"""Host orchestration. Evidence parsing and detector execution belong to workers."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from detection_goggles.errors import DacError
from detection_goggles.podman import Mount, Podman

NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
RUN_ID = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
VOLUME = re.compile(r"^dac-[a-z]+-[a-f0-9]{32}$")
MAX_REPORT_BYTES = 10 * 1024**2


def _private_directory(path: Path) -> Path:
    if path.is_symlink():
        raise DacError(f"State or output directory may not be a symbolic link: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise DacError(f"Expected a directory: {path}")
    return path


def _state_root() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
    root = _private_directory(base / "detection-goggles/controller")
    if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise DacError(f"Controller state must be private and owned by the current user: {root}")
    return root


def _record_path(kind: str, identifier: str) -> Path:
    pattern = NAME if kind == "targets" else RUN_ID
    if pattern.fullmatch(identifier) is None:
        raise DacError(f"Invalid {kind} identifier: {identifier!r}")
    return _private_directory(_state_root() / kind) / f"{identifier}.json"


def _read_record(kind: str, identifier: str) -> dict[str, Any]:
    path = _record_path(kind, identifier)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise DacError(f"No {kind} entry named {identifier!r}") from exc
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16384:
            raise DacError("Invalid controller state file")
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise DacError("Controller state is not private")
        value = json.load(handle)
    if not isinstance(value, dict) or not VOLUME.fullmatch(str(value.get("volume", ""))):
        raise DacError("Invalid managed volume reference")
    return value


def _write_record(kind: str, identifier: str, value: dict[str, Any]) -> None:
    path = _record_path(kind, identifier)
    with tempfile.TemporaryDirectory(prefix=".record-", dir=path.parent) as temporary:
        staged = Path(temporary) / "record.json"
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        # Publish a complete record atomically without replacing an existing one.
        os.link(staged, path)


def _result(result: dict[str, Any], *, allow_partial: bool = False) -> dict[str, Any]:
    code = result.get("exit_code")
    if code not in {0, 1, 2}:
        raise DacError("Container returned an invalid application exit code")
    if code == 2 and not (allow_partial and result.get("artifact_count", 0) > 0):
        raise DacError(str(result.get("error", "Container operation failed")))
    return result


class Resources(AbstractContextManager["Resources"]):
    def __init__(self, runtime: Podman) -> None:
        self.runtime = runtime
        self.volumes: list[str] = []

    def volume(self, purpose: str) -> str:
        name = f"dac-{purpose}-{uuid.uuid4().hex}"
        self.runtime.volume_create(name)
        self.volumes.append(name)
        return name

    def retain(self, name: str) -> None:
        self.volumes.remove(name)

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        failures = []
        for name in reversed(self.volumes):
            try:
                self.runtime.volume_remove(name)
            except (DacError, OSError) as exc:
                failures.append(f"{name}: {exc}")
        if failures:
            message = "Could not remove managed temporary volumes: " + "; ".join(failures)
            if exc_type is None:
                raise DacError(message)
            print(f"error: {message}", file=sys.stderr)


def _input(path: Path, destination: str, *, follow: bool = False) -> Mount:
    path = path.expanduser().absolute()
    if path.is_symlink() and not follow:
        raise DacError(f"Symbolic-link input requires --follow-symlinks: {path}")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() and not resolved.is_dir():
        raise DacError(f"Input must be a regular file or directory: {path}")
    forbidden = {Path("/"), Path.home().resolve(), Path(__file__).resolve().parents[2]}
    if resolved in forbidden:
        raise DacError(f"Select a specific evidence or pack directory instead of {resolved}")
    sensitive = [
        Path.home() / ".ssh",
        Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "containers",
        Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "containers",
        Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "podman",
    ]
    agent_socket = os.environ.get("SSH_AUTH_SOCK")
    if agent_socket and Path(agent_socket).is_absolute():
        sensitive.append(Path(agent_socket).resolve().parent)
    if resolved.is_dir() and any(
        resolved.is_relative_to(root.resolve()) or root.resolve().is_relative_to(resolved)
        for root in sensitive
    ):
        raise DacError("SSH and container-runtime directories may not be mounted")
    return Mount(str(resolved), destination, read_only=True, kind="bind")


def _pack_context(arguments: argparse.Namespace, runtime: Podman) -> tuple[list[str], list[Mount]]:
    runtime.volume_create("dac-installed-packs")
    mounts = [Mount("dac-installed-packs", "/installed-packs")]
    roots = []
    extra = list(arguments.pack_root)
    extra.extend(Path(p) for p in os.environ.get("DAC_PACK_PATH", "").split(os.pathsep) if p)
    for index, path in enumerate(extra):
        target = f"/inputs/pack-root-{index}"
        mounts.append(_input(path, target))
        roots.append(target)
    roots.extend(["/installed-packs", "/packs"])
    return roots, mounts


def _pack_reference(reference: str, mounts: list[Mount]) -> str:
    candidate = Path(reference).expanduser()
    if candidate.exists():
        if candidate.is_file() and candidate.name == "pack.yml":
            candidate = candidate.parent
        target = "/inputs/selected-pack"
        mounts.append(_input(candidate, target))
        return target
    return reference


def _limits(arguments: argparse.Namespace) -> dict[str, int]:
    limits = {
        key: getattr(arguments, key) for key in ("max_file_size", "max_total_size", "max_files")
    }
    for key, maximum in (
        ("max_file_size", 1024**3),
        ("max_total_size", 4 * 1024**3),
        ("max_files", 5000),
    ):
        if not 1 <= limits[key] <= maximum:
            raise DacError(f"{key} must be between 1 and {maximum}")
    if not 1 <= arguments.timeout <= 30:
        raise DacError("Detector timeout must be between 1 and 30 seconds")
    return limits


def _export_files(destination: Path, files: dict[str, Any], *, reports: bool) -> None:
    if not isinstance(files, dict) or not files:
        raise DacError("Container exported no files")
    root = _private_directory(destination.expanduser())
    with tempfile.TemporaryDirectory(prefix=".dac-export-", dir=root) as temporary:
        staged = Path(temporary)
        for name, payload in files.items():
            if reports:
                if name not in {"report.json", "report.md"} or not isinstance(payload, str):
                    raise DacError("Invalid report export")
                data = payload.encode("utf-8")
                maximum = MAX_REPORT_BYTES
            else:
                if not re.fullmatch(r"[A-Za-z0-9_.-]+\.tar\.gz", name):
                    raise DacError("Invalid pack archive export name")
                data = base64.b64decode(payload, validate=True)
                maximum = 64 * 1024**2
            if len(data) > maximum:
                raise DacError(f"Export exceeds the size limit: {name}")
            descriptor = os.open(staged / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
        for name in files:
            if (root / name).exists() or (root / name).is_symlink():
                raise DacError(f"Refusing to overwrite {root / name}")
        for name in files:
            os.link(staged / name, root / name)


def _run(arguments: argparse.Namespace, runtime: Podman, resources: Resources) -> int:
    limits = _limits(arguments)
    pack_roots, pack_mounts = _pack_context(arguments, runtime)
    pack = _pack_reference(arguments.pack, pack_mounts)
    # Validate the pack before acquiring evidence or opening an SSH session.
    _result(
        runtime.run(
            "manage",
            {"op": "pack", "action": "validate", "pack": pack, "pack_roots": pack_roots},
            pack_mounts,
        )
    )
    evidence_volume = resources.volume("evidence")
    output_mount = Mount(evidence_volume, "/output", read_only=False)
    source = arguments.run_source
    if source == "files":
        mounts = [output_mount]
        inputs = []
        admission_issues = []
        for index, path in enumerate(arguments.paths):
            target = f"/inputs/{index}"
            expanded = path.expanduser()
            code = None
            message = None
            try:
                metadata = expanded.lstat()
                if stat.S_ISLNK(metadata.st_mode) and not arguments.follow_symlinks:
                    code, message = "symlink_rejected", "Symbolic links are not followed by default"
                elif expanded.is_dir() and not arguments.recursive:
                    code, message = (
                        "directory_requires_recursive",
                        "Directory input requires --recursive",
                    )
                elif not expanded.is_file() and not expanded.is_dir():
                    code, message = "not_regular", "Input is not a regular file"
                else:
                    mount = _input(path, target, follow=arguments.follow_symlinks)
            except FileNotFoundError:
                code, message = "not_found", "Input does not exist"
            except PermissionError:
                code, message = "permission_denied", "Permission denied while inspecting input"
            except OSError:
                code, message = "io_error", "Cannot inspect selected input"
            if code:
                admission_issues.append({"path": str(path), "code": code, "message": message})
                continue
            mounts.append(mount)
            inputs.append({"path": target, "display_path": str(path)})
        acquired = runtime.run(
            "import",
            {
                "op": "import_files",
                "inputs": inputs,
                "recursive": arguments.recursive,
                "follow_symlinks": arguments.follow_symlinks,
                "admission_issues": admission_issues,
                "source_inputs": [str(p) for p in arguments.paths],
                "limits": limits,
            },
            mounts,
        )
    elif source == "evidence":
        if bool(arguments.bundle) == bool(arguments.run_id):
            raise DacError("Choose either an evidence bundle path or --run-id")
        if arguments.run_id:
            record = _read_record("evidence", arguments.run_id)
            selected = Mount(record["volume"], "/inputs/bundle")
            bundle = "/inputs/bundle/evidence"
        else:
            path = arguments.bundle
            if path.name == "manifest.json" and path.is_file():
                path = path.parent
            selected = _input(path, "/inputs/bundle")
            bundle = "/inputs/bundle"
        acquired = runtime.run(
            "import",
            {"op": "import_evidence", "bundle": bundle, "limits": limits},
            [selected, output_mount],
        )
    else:
        target = _read_record("targets", arguments.target)
        mounts = [output_mount, Mount(target["volume"], "/identity")]
        identity = None
        if arguments.identity:
            imported = resources.volume("identity")
            _result(
                runtime.run(
                    "import",
                    {"op": "identity_import", "source": "/inputs/key"},
                    [
                        _input(arguments.identity, "/inputs/key"),
                        Mount(imported, "/output", read_only=False),
                    ],
                )
            )
            mounts.append(Mount(imported, "/imports"))
            identity = "/imports/id_ed25519"
        request = {
            "op": "acquire",
            "target": target,
            "remote_files": arguments.remote_files,
            "user": arguments.user,
            "identity": identity,
            "ask_pass": arguments.ask_pass,
            "become": arguments.become,
            "ask_become_pass": arguments.ask_become_pass,
            "connection_timeout": arguments.connection_timeout,
            "acquisition_timeout": arguments.acquisition_timeout,
            "limits": limits,
        }
        with runtime.acquisition_pod(target) as pod:
            acquired = runtime.run("acquire", request, mounts, pod=pod, interactive=True)
    _result(acquired, allow_partial=True)
    reports_volume = resources.volume("reports")
    result = runtime.run(
        "analyse",
        {
            "op": "analyse",
            "pack": pack,
            "pack_roots": pack_roots,
            "bundle": "/evidence/evidence",
            "replay": source == "evidence",
            "limits": limits,
            "timeout": arguments.timeout,
        },
        pack_mounts
        + [Mount(evidence_volume, "/evidence"), Mount(reports_volume, "/output", read_only=False)],
    )
    # Operational detector outcomes still have useful reports and must be exported.
    if result.get("exit_code") not in {0, 1, 2} or not RUN_ID.fullmatch(
        str(result.get("run_id", ""))
    ):
        raise DacError(str(result.get("error", "Analysis did not produce a valid run")))
    run_id = result["run_id"]
    exported = _result(
        runtime.run(
            "export",
            {"op": "export_reports", "run_id": run_id, "formats": result["formats"]},
            [Mount(reports_volume, "/reports")],
        )
    )
    output_root = _private_directory(arguments.output.expanduser())
    destination = output_root / run_id
    destination.mkdir(mode=0o700)
    _export_files(destination, exported["files"], reports=True)
    if arguments.retain_evidence:
        _write_record(
            "evidence",
            run_id,
            {
                "volume": evidence_volume,
                "run_id": run_id,
                "evidence_run_id": acquired.get("run_id"),
                "pack": arguments.pack,
            },
        )
        resources.retain(evidence_volume)
    print(f"Report: {destination}")
    print(f"Findings: {result.get('summary', {}).get('finding_count', 0)}")
    if arguments.retain_evidence:
        print(f"Retained evidence: {run_id}")
    return int(result["exit_code"])


def _registry(source: str, runtime: Podman, resources: Resources) -> tuple[str, list[Mount]]:
    if not urlparse(source).scheme:
        return "/inputs/registry.yml", [_input(Path(source), "/inputs/registry.yml")]
    volume = resources.volume("download")
    _result(
        runtime.run(
            "download",
            {"op": "download", "url": source, "limit": 1024**2},
            [Mount(volume, "/output", read_only=False)],
        )
    )
    return "/registry-download/download", [Mount(volume, "/registry-download")]


def _pack(arguments: argparse.Namespace, runtime: Podman, resources: Resources) -> int:
    roots, mounts = _pack_context(arguments, runtime)
    action = arguments.pack_action
    request: dict[str, Any] = {"op": "pack", "action": action, "pack_roots": roots}
    if action in {"validate", "build"}:
        request["pack"] = _pack_reference(arguments.pack, mounts)
    if action in {"available", "verify"}:
        registry, registry_mounts = _registry(arguments.registry, runtime, resources)
        mounts.extend(registry_mounts)
        request["registry"] = registry
    if action == "verify":
        mounts.append(_input(arguments.archive, "/inputs/archive.tar.gz"))
        # Registry verification selects by archive basename, so preserve it.
        mounts[-1] = _input(arguments.archive, f"/inputs/{arguments.archive.name}")
        request["archive"] = mounts[-1].target
    if action == "install":
        if arguments.destination_root is not None:
            raise DacError(
                "Packs are installed into managed container storage; omit --destination-root"
            )
        request["destination_root"] = "/installed-packs"
        mounts[0] = Mount("dac-installed-packs", "/installed-packs", read_only=False)
        local = Path(arguments.reference).expanduser()
        if local.exists():
            if not arguments.sha256:
                raise DacError("Installing a local archive requires --sha256")
            mounts.append(_input(local, "/inputs/archive.tar.gz"))
            request.update(reference="/inputs/archive.tar.gz", sha256=arguments.sha256)
        else:
            if (
                arguments.sha256
                or "/" in arguments.reference
                or arguments.reference.endswith(".tar.gz")
            ):
                raise DacError(
                    "Local archive does not exist, or --sha256 was used with a registry ID"
                )
            registry, registry_mounts = _registry(arguments.registry, runtime, resources)
            resolved = _result(
                runtime.run(
                    "manage",
                    {
                        "op": "pack",
                        "action": "resolve_registry",
                        "reference": arguments.reference,
                        "registry": registry,
                    },
                    registry_mounts,
                )
            )
            entry = resolved["entry"]
            volume = resources.volume("download")
            _result(
                runtime.run(
                    "download",
                    {"op": "download", "url": entry["url"], "limit": 64 * 1024**2},
                    [Mount(volume, "/output", read_only=False)],
                )
            )
            mounts.append(Mount(volume, "/downloads"))
            request.update(
                reference="/downloads/download",
                sha256=entry["sha256"],
                expected_id=entry["id"],
                expected_version=entry["version"],
            )
    if action == "build":
        volume = resources.volume("build")
        mounts.append(Mount(volume, "/output", read_only=False))
    result = _result(runtime.run("manage", request, mounts))
    if action == "build":
        exported = _result(
            runtime.run(
                "export",
                {"op": "export_archive", "archive": result["archive"]},
                [Mount(volume, "/reports")],
            )
        )
        _export_files(
            arguments.output, {exported["archive"]: exported["data_base64"]}, reports=False
        )
        print(f"Built: {arguments.output / result['archive']}")
        print(f"SHA256: {result['sha256']}")
    elif "packs" in result:
        for pack in result["packs"]:
            print(f"{pack['id']:<38} {pack['version']}")
    else:
        print(result.get("message", f"Pack {action} completed"))
    return int(result["exit_code"])


def _target(arguments: argparse.Namespace, runtime: Podman, resources: Resources) -> int:
    action = arguments.target_action
    if action in {"list", "remove"}:
        return _records("targets", action, getattr(arguments, "name", None), runtime)
    path = _record_path("targets", arguments.name)
    if path.exists():
        raise DacError("Target already exists; remove it before changing its identity")
    address = ipaddress.ip_address(arguments.host)
    if (
        address.version != 4
        or address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
    ):
        raise DacError("Target must be a non-loopback, non-link-local unicast IPv4 address")
    if not 1 <= arguments.port <= 65535:
        raise DacError("SSH port must be between 1 and 65535")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", arguments.host_key_fingerprint):
        raise DacError("Expected an OpenSSH SHA256 host-key fingerprint")
    volume = resources.volume("target")
    target = {
        "name": arguments.name,
        "host": str(address),
        "port": arguments.port,
        "fingerprint": arguments.host_key_fingerprint,
        "volume": volume,
    }
    with runtime.acquisition_pod(target) as pod:
        result = _result(
            runtime.run(
                "target",
                {"op": "target_init", "target": target},
                [Mount(volume, "/identity", read_only=False)],
                pod=pod,
                interactive=True,
            )
        )
    _write_record("targets", arguments.name, target)
    resources.retain(volume)
    print("Register this public key on the dedicated target account:")
    print(result["public_key"])
    return 0


def _records(kind: str, action: str, identifier: str | None, runtime: Podman) -> int:
    if action == "remove":
        assert identifier is not None
        record = _read_record(kind, identifier)
        runtime.volume_remove(record["volume"])
        _record_path(kind, identifier).unlink()
        print(
            f"Removed {kind} entry {identifier} and its managed volume; recovery is not provided."
        )
        if kind == "targets":
            print("Revoke the registered public key on the target account.")
        return 0
    directory = _private_directory(_state_root() / kind)
    for path in sorted(directory.glob("*.json")):
        record = _read_record(kind, path.stem)
        detail = f"{record['host']}:{record['port']}" if kind == "targets" else record["pack"]
        print(f"{path.stem}  {detail}")
    return 0


def dispatch(arguments: argparse.Namespace) -> int:
    runtime = Podman()
    runtime.preflight()
    if arguments.command == "runtime":
        print("Rootless Podman, pinned images and required host controls are available.")
        return 0
    with Resources(runtime) as resources:
        if arguments.command == "target":
            return _target(arguments, runtime, resources)
        if arguments.command == "evidence":
            return _records(
                "evidence", arguments.evidence_action, getattr(arguments, "run_id", None), runtime
            )
        if arguments.command == "pack":
            return _pack(arguments, runtime, resources)
        if arguments.command == "run":
            return _run(arguments, runtime, resources)
    raise DacError("Unsupported command")
