"""Constrained Ansible-over-SSH acquisition for explicitly named files."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from detection_goggles.errors import AcquisitionError, ContractError
from detection_goggles.evidence import (
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_TOTAL_SIZE,
    EvidenceBundle,
    LocalEvidenceWorkspace,
    bounded_issues,
    replace_manifest,
    validate_acquisition_limits,
)
from detection_goggles.schema import validate

MAX_REMOTE_PATH_LENGTH = 3500
MAX_STATUS_BYTES = 4096
HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class SshOptions:
    host: str
    user: str
    port: int = 22
    identity: Path | None = None
    ask_pass: bool = False
    become: bool = False
    ask_become_pass: bool = False
    host_key_policy: str = "strict"
    connection_timeout: int = 30
    acquisition_timeout: int = 600


def _validate_host(value: str) -> str:
    if not value or value != value.strip() or len(value) > 253:
        raise ContractError("SSH host must be a hostname or IP address of at most 253 characters")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    hostname = value[:-1] if value.endswith(".") else value
    if not hostname or any(not HOSTNAME_LABEL.fullmatch(label) for label in hostname.split(".")):
        raise ContractError(f"Invalid SSH hostname: {value!r}")
    return value


def _validate_options(options: SshOptions) -> SshOptions:
    _validate_host(options.host)
    if not USERNAME.fullmatch(options.user):
        raise ContractError("SSH user may contain only letters, numbers, dot, underscore, and dash")
    if not 1 <= options.port <= 65535:
        raise ContractError("SSH port must be between 1 and 65535")
    if options.host_key_policy not in {"strict", "accept-new"}:
        raise ContractError("SSH host-key policy must be 'strict' or 'accept-new'")
    if not 1 <= options.connection_timeout <= 300:
        raise ContractError("SSH connection timeout must be between 1 and 300 seconds")
    if not 1 <= options.acquisition_timeout <= 3600:
        raise ContractError("SSH acquisition timeout must be between 1 and 3600 seconds")
    if options.ask_become_pass and not options.become:
        raise ContractError("--ask-become-pass requires --become")
    if options.identity is not None:
        identity = options.identity.expanduser()
        try:
            metadata = identity.stat()
        except OSError as exc:
            raise ContractError(f"Cannot access SSH identity file {identity}: {exc}") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"SSH identity must be a regular file: {identity}")
    return options


def _validate_remote_paths(paths: tuple[str, ...], max_files: int) -> None:
    if not paths:
        raise ContractError("At least one --remote-file is required")
    if max_files < 1:
        raise ContractError("Maximum file count must be positive")
    if len(paths) > max_files:
        raise ContractError(
            f"Requested {len(paths)} remote files, exceeding the configured limit {max_files}"
        )
    if len(set(paths)) != len(paths):
        raise ContractError("Duplicate remote file paths are not allowed")
    for path in paths:
        if not path or len(path) > MAX_REMOTE_PATH_LENGTH:
            raise ContractError(
                f"Remote paths must contain between 1 and {MAX_REMOTE_PATH_LENGTH} characters"
            )
        if any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise ContractError("Remote file paths may not contain control characters")
        if not path.startswith("/"):
            raise ContractError(f"Remote file path must be an absolute POSIX path: {path!r}")


def _write_private(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def _write_private_json(path: Path, value: Any) -> None:
    _write_private(path, json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n")


def _ansible_environment(config: Path, local_tmp: Path) -> dict[str, str]:
    environment = {
        "ANSIBLE_CONFIG": str(config),
        "ANSIBLE_HOST_KEY_CHECKING": "True",
        "ANSIBLE_LOCAL_TEMP": str(local_tmp),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_RETRY_FILES_ENABLED": "False",
        "HOME": os.environ.get("HOME", str(Path.home())),
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONUNBUFFERED": "1",
    }
    for name in ("LANG", "LC_ALL", "LOGNAME", "SSH_AUTH_SOCK", "TERM", "USER"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    return environment


def _target_label(host: str, port: int) -> str:
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{rendered_host}:{port}"


def _read_status(path: Path) -> dict[str, Any] | None:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return None
        if metadata.st_size > MAX_STATUS_BYTES:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    required = {"exists", "is_regular", "is_link", "failed", "size", "modified_ns"}
    if not isinstance(value, dict) or set(value) != required:
        return None
    numeric = {"size", "modified_ns"}
    if any(not isinstance(value[name], bool) for name in required - numeric):
        return None
    for name in ("size", "modified_ns"):
        if not isinstance(value[name], int) or isinstance(value[name], bool) or value[name] < 0:
            return None
    return value


def _read_fetch_status(path: Path) -> dict[str, bool] | None:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return None
        if metadata.st_size > MAX_STATUS_BYTES:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or set(value) != {"failed"}:
        return None
    if not isinstance(value["failed"], bool):
        return None
    return value


def _issue(path: str, code: str, message: str) -> dict[str, str]:
    return {"path": path, "code": code, "message": message[:1000]}


def _invoke_ansible(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
) -> int:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            start_new_session=(os.name == "posix"),
        )
    except OSError as exc:
        raise AcquisitionError(f"Could not start ansible-playbook: {exc}") from exc
    try:
        return process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.wait()
        raise AcquisitionError(
            f"Ansible SSH acquisition timed out after {timeout_seconds} seconds"
        ) from exc
    except BaseException:
        if process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait()
        raise


class SshEvidenceWorkspace(AbstractContextManager[EvidenceBundle]):
    """Fetch explicit remote paths, then convert them to a normal local evidence bundle."""

    def __init__(
        self,
        paths: tuple[str, ...],
        options: SshOptions,
        *,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
        max_files: int = DEFAULT_MAX_FILES,
    ) -> None:
        self.paths = paths
        self.options = options
        self.max_file_size = max_file_size
        self.max_total_size = max_total_size
        self.max_files = max_files
        self._stack: ExitStack | None = None

    def __enter__(self) -> EvidenceBundle:
        _validate_options(self.options)
        _validate_remote_paths(self.paths, self.max_files)
        validate_acquisition_limits(
            max_file_size=self.max_file_size,
            max_total_size=self.max_total_size,
            max_files=self.max_files,
        )

        executable = shutil.which("ansible-playbook")
        if executable is None:
            raise AcquisitionError(
                "SSH acquisition requires ansible-playbook; install the optional dependency "
                "with: pip install 'detection-goggles[ssh]'"
            )

        stack = ExitStack()
        self._stack = stack
        try:
            temporary = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="dac-ssh-")))
            temporary.chmod(0o700)
            fetched = temporary / "fetched"
            statuses = temporary / "statuses"
            ansible_tmp = temporary / "ansible-tmp"
            control_path = temporary / "control-path"
            for directory in (fetched, statuses, ansible_tmp, control_path):
                directory.mkdir(mode=0o700)

            inventory_path = temporary / "inventory.json"
            variables_path = temporary / "variables.json"
            config_path = temporary / "ansible.cfg"
            host_variables: dict[str, Any] = {
                "ansible_connection": "ssh",
                "ansible_host": self.options.host,
                "ansible_port": self.options.port,
                "ansible_user": self.options.user,
            }
            if self.options.host_key_policy == "accept-new":
                host_variables["ansible_ssh_common_args"] = "-o StrictHostKeyChecking=accept-new"
            inventory = {"all": {"hosts": {"dac_target": host_variables}}}
            remote_files = [
                {"id": f"remote-{index:04d}", "path": path}
                for index, path in enumerate(self.paths, start=1)
            ]
            variables = {
                "dac_become": self.options.become,
                "dac_local_staging": str(fetched),
                "dac_max_file_size": self.max_file_size,
                "dac_max_total_size": self.max_total_size,
                "dac_remote_files": remote_files,
                "dac_status_staging": str(statuses),
            }
            _write_private_json(inventory_path, inventory)
            _write_private_json(variables_path, variables)
            _write_private(
                config_path,
                "[defaults]\n"
                "host_key_checking = True\n"
                "retry_files_enabled = False\n"
                f"local_tmp = {ansible_tmp}\n"
                "[ssh_connection]\n"
                f"control_path_dir = {control_path}\n"
                "pipelining = True\n",
            )

            playbook = Path(__file__).with_name("ansible") / "fetch_files.yml"
            if not playbook.is_file():
                raise ContractError(f"Core Ansible playbook is missing: {playbook}")
            command = [
                executable,
                "--inventory",
                str(inventory_path),
                "--limit",
                "dac_target",
                "--extra-vars",
                f"@{variables_path}",
                "--timeout",
                str(self.options.connection_timeout),
            ]
            if self.options.identity is not None:
                command.extend(["--private-key", str(self.options.identity.expanduser().resolve())])
            if self.options.ask_pass:
                command.append("--ask-pass")
            if self.options.ask_become_pass:
                command.append("--ask-become-pass")
            command.append(str(playbook))

            return_code = _invoke_ansible(
                command,
                cwd=temporary,
                environment=_ansible_environment(config_path, ansible_tmp),
                timeout_seconds=self.options.acquisition_timeout,
            )
            if return_code != 0:
                raise AcquisitionError(
                    f"Ansible SSH acquisition failed with exit status {return_code}"
                )

            selected_bytes = 0
            selected: list[tuple[Path, str, int]] = []
            remote_issues: list[dict[str, str]] = []
            for item in remote_files:
                remote_path = item["path"]
                status_value = _read_status(statuses / f"{item['id']}.json")
                if status_value is None:
                    remote_issues.append(
                        _issue(remote_path, "io_error", "Remote file metadata was unavailable")
                    )
                    continue
                if status_value["failed"]:
                    remote_issues.append(
                        _issue(remote_path, "io_error", "Remote path could not be inspected")
                    )
                    continue
                if not status_value["exists"]:
                    remote_issues.append(
                        _issue(remote_path, "not_found", "Remote path does not exist")
                    )
                    continue
                if status_value["is_link"]:
                    remote_issues.append(
                        _issue(
                            remote_path,
                            "symlink_rejected",
                            "Remote symbolic links are not followed",
                        )
                    )
                    continue
                if not status_value["is_regular"]:
                    remote_issues.append(
                        _issue(remote_path, "not_regular", "Remote path is not a regular file")
                    )
                    continue
                remote_size = status_value["size"]
                if remote_size > self.max_file_size:
                    remote_issues.append(
                        _issue(
                            remote_path,
                            "size_limit",
                            f"Remote file size {remote_size} exceeds limit "
                            f"{self.max_file_size} bytes",
                        )
                    )
                    continue
                if selected_bytes + remote_size > self.max_total_size:
                    remote_issues.append(
                        _issue(
                            remote_path,
                            "size_limit",
                            "Total acquisition size limit would be exceeded",
                        )
                    )
                    continue
                selected_bytes += remote_size
                fetch_status = _read_fetch_status(statuses / f"{item['id']}.fetch.json")
                if fetch_status is None:
                    remote_issues.append(
                        _issue(remote_path, "io_error", "Remote file fetch outcome was unavailable")
                    )
                    continue
                if fetch_status["failed"]:
                    remote_issues.append(
                        _issue(remote_path, "io_error", "Remote file fetch failed integrity checks")
                    )
                    continue
                fetched_path = fetched / item["id"]
                if not fetched_path.is_file() or fetched_path.is_symlink():
                    remote_issues.append(
                        _issue(remote_path, "io_error", "Remote regular file was not fetched")
                    )
                    continue
                selected.append((fetched_path, remote_path, status_value["modified_ns"]))

            local_workspace = LocalEvidenceWorkspace(
                (path for path, _, _ in selected),
                max_file_size=self.max_file_size,
                max_total_size=self.max_total_size,
                max_files=self.max_files,
            )
            local_bundle = stack.enter_context(local_workspace)
            staged_to_remote = {str(path): remote for path, remote, _ in selected}
            staged_to_modified = {str(path): modified_ns for path, _, modified_ns in selected}
            target = _target_label(self.options.host, self.options.port)
            manifest = dict(local_bundle.manifest)
            manifest["source"] = {
                "type": "ssh",
                "target": target,
                "inputs": list(self.paths),
            }
            for artifact in manifest["artifacts"]:
                staged_path = artifact["display_path"]
                remote_path = staged_to_remote.get(staged_path, staged_path)
                artifact["display_path"] = f"{target}:{remote_path}"
                artifact["modified_ns"] = staged_to_modified.get(
                    staged_path, artifact["modified_ns"]
                )
                artifact["acquisition"]["source"] = "ssh"
            local_issues = []
            for issue in manifest["acquisition_issues"]:
                copied = dict(issue)
                copied["path"] = staged_to_remote.get(copied["path"], copied["path"])
                local_issues.append(copied)
            manifest["acquisition_issues"] = bounded_issues(remote_issues + local_issues)
            validate(manifest, "evidence-bundle.schema.json", label="SSH evidence")
            replace_manifest(local_bundle.root, manifest)
            bundle = EvidenceBundle(root=local_bundle.root, manifest=manifest)
            bundle.verify(
                max_file_size=self.max_file_size,
                max_total_size=self.max_total_size,
                max_files=self.max_files,
            )
            return bundle
        except BaseException:
            stack.close()
            self._stack = None
            raise

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        if self._stack is not None:
            self._stack.close()
            self._stack = None
