"""The sole host-side boundary for starting Detection Goggles workloads.

No method falls back to executing a workload on the host. Podman itself is always
invoked locally and rootlessly; network permission belongs to a sealed namespace,
not to a request supplied by a detector.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import platform
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import termios
import time
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from detection_goggles.errors import DacError

OWNER_LABEL = "io.detection-goggles.managed"
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
RESOURCE_NAME = re.compile(r"dac-[a-zA-Z0-9][a-zA-Z0-9_.-]{0,110}")
MAX_RESULT_BYTES = 96 * 1024 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
MAX_ERROR_BYTES = 1024 * 1024
MEMORY_BYTES = 4 * 1024**3
PID_LIMIT = 128
OFFLINE_ROLES = frozenset({"import", "analyse", "export", "manage", "test"})
TARGET_ROLES = frozenset({"acquire", "target"})
MOUNT_ROOTS = frozenset(
    {
        "input",
        "inputs",
        "output",
        "reports",
        "evidence",
        "identity",
        "packs",
        "keys",
        "state",
        "imports",
        "installed-packs",
        "downloads",
        "registry-download",
        "scratch-source",
        "credentials",
    }
)


@dataclass(frozen=True)
class Mount:
    source: str
    target: str
    read_only: bool = True
    kind: str = "volume"


def _environment() -> dict[str, str]:
    # Do not inherit remote-engine selectors, host SSH agents, loader overrides,
    # or arbitrary container defaults from a caller's environment.
    allowed = {
        "PATH",
        "HOME",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "LANG",
        "LC_ALL",
        "TERM",
        "DBUS_SESSION_BUS_ADDRESS",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}


def _target(values: dict[str, Any]) -> dict[str, Any]:
    try:
        if not isinstance(values["host"], str):
            raise ValueError("target addresses must be literal strings")
        address = ipaddress.ip_address(values["host"])
        port = values["port"]
        fingerprint = values["fingerprint"]
    except (KeyError, TypeError, ValueError) as error:
        raise DacError(
            "A literal IPv4 target, SSH port and pinned fingerprint are required"
        ) from error
    if (
        address.version != 4
        or address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or str(address) == "255.255.255.255"
    ):
        raise DacError("The SSH target must be a unicast IPv4 address outside local helper ranges")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise DacError("The SSH target port must be between 1 and 65535")
    if (
        not isinstance(fingerprint, str)
        or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) is None
    ):
        raise DacError("The SSH host fingerprint must use OpenSSH SHA256 format")
    return {"host": str(address), "port": port, "fingerprint": fingerprint}


@contextlib.contextmanager
def _quiet_terminal(interactive: bool) -> Iterator[None]:
    """Protect prompted secrets without allocating a merged-output container TTY."""
    descriptor = None
    original = None
    if interactive and sys.stdin.isatty():
        try:
            descriptor = sys.stdin.fileno()
            original = termios.tcgetattr(descriptor)
            selected = original.copy()
            selected[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(descriptor, termios.TCSANOW, selected)
        except (OSError, termios.error) as error:
            raise DacError(
                "Cannot disable terminal echo for the container credential prompt"
            ) from error
    try:
        yield
    finally:
        if original is not None and descriptor is not None:
            termios.tcsetattr(descriptor, termios.TCSANOW, original)


class Podman:
    """Manage fixed-policy ephemeral containers and labelled persistent volumes."""

    def __init__(self, *, images_path: Path | None = None) -> None:
        config = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        self.images_path = images_path or config / "detection-goggles" / "images.json"
        self.images: dict[str, str] = {}
        self._checked = False
        self._seals: dict[str, dict[str, Any]] = {}

    def _command(self, arguments: Sequence[str], *, timeout: int = 30) -> str:
        try:
            result = subprocess.run(
                ["podman", "--remote=false", *arguments],
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=_environment(),
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DacError(f"Local Podman operation failed: {error}") from error
        if len(result.stdout) > MAX_ERROR_BYTES or len(result.stderr) > MAX_ERROR_BYTES:
            raise DacError("Podman management output exceeded its size limit")
        if result.returncode:
            detail = result.stderr.decode("utf-8", "replace").strip()[-4000:]
            raise DacError(f"Podman {' '.join(arguments[:2])} failed: {detail}")
        return result.stdout.decode("utf-8", "strict")

    def _json(self, arguments: Sequence[str]) -> Any:
        try:
            return json.loads(self._command(arguments))
        except (ValueError, UnicodeError) as error:
            raise DacError("Podman returned malformed management JSON") from error

    def preflight(self) -> None:
        if self._checked:
            return
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise DacError("The supported container controller requires native Linux x86_64")
        if os.geteuid() == 0:
            raise DacError("Run Detection Goggles with rootless Podman, not as root")
        if shutil.which("podman") is None:
            raise DacError("Rootless Podman is required; no host-execution fallback is available")
        info = self._json(["info", "--format", "json"])
        host = info.get("host", {})
        if re.fullmatch(r"5\.8\.[0-9]+", info.get("version", {}).get("Version", "")) is None:
            raise DacError("The supported Podman release series is 5.8.x")
        if host.get("security", {}).get("rootless") is not True:
            raise DacError("Podman must operate rootlessly")
        if host.get("cgroupVersion") != "v2":
            raise DacError("Rootless Podman requires cgroup v2 with delegated CPU, memory and PIDs")
        if not {"cpu", "memory", "pids"} <= set(host.get("cgroupControllers", [])):
            raise DacError("CPU, memory and PID controllers are not delegated to rootless Podman")
        if host.get("networkBackend") != "netavark":
            raise DacError("The supported rootless network backend is Netavark with pasta")
        if host.get("serviceIsRemote") or host.get("rootlessNetworkCmd") != "pasta":
            raise DacError("A local rootless Podman engine with pasta is required")
        if host.get("security", {}).get("seccompEnabled") is not True:
            raise DacError("The supported Podman engine must enforce seccomp")
        try:
            if self.images_path.is_symlink() or not self.images_path.is_file():
                raise ValueError("image manifest is missing or is a link")
            metadata = self.images_path.stat()
            if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
                raise ValueError(
                    "image manifest must be owned by this user and not publicly writable"
                )
            if metadata.st_size > 65536:
                raise ValueError("image manifest is oversized")
            manifest = json.loads(self.images_path.read_text(encoding="utf-8"))
            if manifest.get("schema_version") != 1:
                raise ValueError("unsupported image manifest version")
            images = manifest.get("images", manifest)
            self.images = {name: images[name] for name in ("runtime", "network", "test")}
            for identifier in self.images.values():
                if not isinstance(identifier, str) or IMAGE_ID.fullmatch(identifier) is None:
                    raise ValueError("image references must be immutable SHA-256 IDs")
                inspected = self._json(["image", "inspect", identifier])
                if len(inspected) != 1 or (
                    str(inspected[0].get("Id", "")).removeprefix("sha256:")
                    != identifier.removeprefix("sha256:")
                ):
                    raise ValueError("pinned image is unavailable or its identity differs")
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise DacError(
                f"Run scripts/container-build to prepare pinned images: {error}"
            ) from error
        self._checked = True

    def image(self, kind: str = "runtime") -> str:
        self.preflight()
        try:
            return self.images[kind]
        except KeyError as error:
            raise DacError(f"Unknown controller image kind: {kind}") from error

    @staticmethod
    def _name(name: str) -> None:
        if RESOURCE_NAME.fullmatch(name) is None:
            raise DacError("Invalid Detection Goggles resource name")

    def volume_create(self, name: str) -> str:
        self.preflight()
        self._name(name)
        existing = self._json(
            ["volume", "ls", "--filter", f"name=^{re.escape(name)}$", "--format", "json"]
        )
        if existing:
            details = self._json(["volume", "inspect", name])[0]
            if details.get("Labels", {}).get(OWNER_LABEL) != "true":
                raise DacError(
                    f"Refusing an existing volume not owned by Detection Goggles: {name}"
                )
            return name
        self._command(["volume", "create", "--label", f"{OWNER_LABEL}=true", name])
        return name

    def volume_remove(self, name: str) -> None:
        self.preflight()
        self._name(name)
        details = self._json(["volume", "inspect", name])[0]
        if details.get("Labels", {}).get(OWNER_LABEL) != "true":
            raise DacError(f"Refusing to remove a volume not owned by Detection Goggles: {name}")
        self._command(["volume", "rm", name])

    def _mount(self, mount: Mount) -> str:
        target = Path(mount.target)
        if (
            not target.is_absolute()
            or ".." in target.parts
            or len(target.parts) < 2
            or target.parts[1] not in MOUNT_ROOTS
            or any(character in mount.source + mount.target for character in ",\n\r\x00")
        ):
            raise DacError("Unsafe container mount source or destination")
        if mount.kind == "volume":
            self._name(mount.source)
            metadata = self._json(["volume", "inspect", mount.source])[0]
            if metadata.get("Labels", {}).get(OWNER_LABEL) != "true":
                raise DacError("Only managed Detection Goggles volumes may be mounted")
        elif mount.kind == "bind":
            path = Path(mount.source)
            if not mount.read_only or path.is_symlink() or not path.is_absolute():
                raise DacError("Host inputs must use explicit read-only, non-link paths")
            forbidden = {
                Path("/"),
                Path.home().resolve(),
                (Path.home() / ".ssh").resolve(),
                Path("/home"),
                Path("/etc"),
                Path("/usr"),
                Path("/var"),
                Path("/run"),
                Path("/proc"),
                Path("/sys"),
                Path("/dev"),
                Path("/tmp"),
            }
            if (Path.cwd() / ".git").exists():
                forbidden.add(Path.cwd().resolve())
            if path.resolve() in forbidden or not (path.is_file() or path.is_dir()):
                raise DacError("Broad host directories and non-regular inputs cannot be mounted")
            data_root = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
            config_root = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
            runtime_root = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
            sensitive = [
                Path.home() / ".ssh",
                data_root / "containers",
                config_root / "containers",
                runtime_root / "podman",
            ]
            if os.environ.get("SSH_AUTH_SOCK"):
                sensitive.append(Path(os.environ["SSH_AUTH_SOCK"]).resolve().parent)
            resolved = path.resolve()
            if path.is_dir() and any(
                resolved.is_relative_to(root.resolve()) or root.resolve().is_relative_to(resolved)
                for root in sensitive
            ):
                raise DacError("SSH and container-engine storage directories cannot be mounted")
        else:
            raise DacError("Unsupported container mount kind")
        mode = "ro=true" if mount.read_only else "rw=true"
        return f"type={mount.kind},src={mount.source},dst={mount.target},{mode}"

    def _inspect_workload(
        self,
        identifier: str,
        network: str,
        pod: str | None,
        image: str,
    ) -> None:
        result = self._json(["container", "inspect", identifier])
        if not isinstance(result, list) or len(result) != 1:
            raise DacError("Container inspection did not identify exactly one workload")
        details = result[0]
        host = details.get("HostConfig", {})
        config = details.get("Config", {})
        if str(details.get("Image", "")).removeprefix("sha256:") != image.removeprefix("sha256:"):
            raise DacError("The workload image differs from its pinned identity")
        security = host.get("SecurityOpt", [])
        dropped = {str(cap).upper().removeprefix("CAP_") for cap in host.get("CapDrop", [])}
        if (
            host.get("ReadonlyRootfs") is not True
            or host.get("Privileged")
            or config.get("User") != "10001:10001"
            or not any(str(value).startswith("no-new-privileges") for value in security)
            or host.get("Memory") != MEMORY_BYTES
            or host.get("PidsLimit") != PID_LIMIT
            or host.get("CpuQuota", 0) <= 0
            or host.get("CpuPeriod", 0) <= 0
            or host["CpuQuota"] > 2 * host["CpuPeriod"]
            or host.get("CapAdd")
        ):
            raise DacError(
                "Podman did not apply the required workload isolation and resource limits"
            )
        if "ALL" not in dropped and details.get("EffectiveCaps"):
            raise DacError("The workload retained Linux capabilities")
        if network == "none" and host.get("NetworkMode") != "none":
            raise DacError("An offline workload unexpectedly has networking")
        if network == "registry" and not str(host.get("NetworkMode", "")).startswith("pasta"):
            raise DacError("The registry worker did not receive private rootless networking")
        if pod is not None and details.get("Pod") != pod:
            raise DacError("The workload did not join the sealed acquisition pod")
        if host.get("PidMode") != "private" or host.get("IpcMode") != "private":
            raise DacError("The workload must have private process and IPC namespaces")

    def _stream(self, identifier: str, *, interactive: bool, timeout: int = 3600) -> dict:
        with _quiet_terminal(interactive):
            return self._stream_attached(identifier, interactive=interactive, timeout=timeout)

    def _stream_attached(self, identifier: str, *, interactive: bool, timeout: int) -> dict:
        arguments = ["podman", "--remote=false", "start", "--attach"]
        if interactive:
            arguments.append("--interactive")
        arguments.append(identifier)
        process = subprocess.Popen(
            arguments,
            stdin=None if interactive else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_environment(),
        )
        assert process.stdout is not None and process.stderr is not None
        output = bytearray()
        errors = bytearray()
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    if time.monotonic() > deadline:
                        raise DacError("Container execution exceeded its time limit")
                    for key, _ in selector.select(timeout=0.25):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if key.data == "stdout":
                            output.extend(chunk)
                            if len(output) > MAX_RESULT_BYTES:
                                raise DacError("Container result exceeded its size limit")
                        else:
                            errors.extend(chunk)
                            if len(errors) > MAX_ERROR_BYTES:
                                raise DacError("Container diagnostics exceeded their size limit")
                            sys.stderr.write(chunk.decode("utf-8", "replace"))
                            sys.stderr.flush()
            return_code = process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
        try:
            result = json.loads(output)
        except (ValueError, UnicodeError) as error:
            detail = errors.decode("utf-8", "replace").strip()[-4000:]
            raise DacError(
                f"Container worker did not return exactly one UTF-8 JSON result "
                f"(exit {return_code}): {detail}"
            ) from error
        if not isinstance(result, dict):
            raise DacError("Container worker result must be a JSON object")
        if return_code and (return_code not in {1, 2} or result.get("exit_code") != return_code):
            raise DacError(f"Container worker failed unexpectedly (exit {return_code})")
        return result

    def _pod_state(self, pod: str) -> dict[str, Any]:
        details = self._json(["pod", "inspect", pod])
        if isinstance(details, list):
            details = details[0]
        infra = details.get("InfraContainerID")
        if not infra:
            raise DacError("The acquisition network namespace has no infrastructure container")
        state = self._json(["container", "inspect", infra])[0]
        pid = state.get("State", {}).get("Pid", 0)
        if not state.get("State", {}).get("Running") or not pid:
            raise DacError("The sealed acquisition network namespace is no longer running")
        try:
            namespace = os.readlink(f"/proc/{pid}/ns/net")
        except OSError as error:
            raise DacError("Cannot verify the acquisition network namespace") from error
        return {
            "infra": infra,
            "namespace": namespace,
            "started": state["State"].get("StartedAt"),
        }

    @contextlib.contextmanager
    def acquisition_pod(self, target: dict) -> Iterator[str]:
        self.preflight()
        selected = _target(target)
        # Do not copy the host's primary address into the guest: that makes an
        # explicitly approved service on that address route back to the guest.
        subnet = (
            "10.0.3"
            if ipaddress.ip_address(selected["host"]) in ipaddress.ip_network("10.0.2.0/24")
            else "10.0.2"
        )
        networking = f"pasta:--ipv4-only,-a,{subnet}.100,-n,24,-g,{subnet}.2"
        name = "dac-acquire-" + uuid.uuid4().hex
        pod = self._command(
            [
                "pod",
                "create",
                "--name",
                name,
                "--label",
                f"{OWNER_LABEL}=true",
                "--share=net",
                "--userns=keep-id:uid=10001,gid=10001",
                f"--network={networking}",
                "--no-hosts",
                "--infra=true",
                "--exit-policy=continue",
            ]
        ).strip()
        try:
            self._command(["pod", "start", pod])
            state = self._pod_state(pod)
            self._network_helper(pod, selected)
            if self._pod_state(pod) != state:
                raise DacError("Acquisition namespace changed during network sealing")
            self._seals[pod] = {"target": selected, "state": state}
            yield pod
        finally:
            self._seals.pop(pod, None)
            self._command(["pod", "rm", "--force", pod])

    def _network_helper(self, pod: str, target: dict) -> None:
        identifier = ""
        with tempfile.TemporaryDirectory(prefix="dac-net-policy-") as temporary:
            root = Path(temporary)
            # This policy contains no credentials. The setup UID is namespace
            # root, while the host UID maps to 10001; no DAC override is granted.
            root.chmod(0o755)
            policy = {"target": target, "pod": pod}
            path = root / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            path.chmod(0o444)
            try:
                identifier = self._command(
                    [
                        "create",
                        "--name",
                        "dac-net-init-" + uuid.uuid4().hex,
                        "--pod",
                        pod,
                        "--user=0:0",
                        "--read-only",
                        "--cap-drop=ALL",
                        "--cap-add=NET_ADMIN",
                        "--security-opt=no-new-privileges",
                        "--restart=no",
                        "--memory=128m",
                        "--pids-limit=16",
                        "--cpus=0.5",
                        "--mount",
                        f"type=bind,src={root},dst=/run/dac,ro=true",
                        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
                        "--pull=never",
                        self.images["network"],
                    ]
                ).strip()
                details = self._json(["container", "inspect", identifier])[0]
                host = details.get("HostConfig", {})
                added = {str(cap).removeprefix("CAP_") for cap in host.get("CapAdd", [])}
                if host.get("Privileged") or added != {"NET_ADMIN"} or details.get("Pod") != pod:
                    raise DacError(
                        "Network setup privileges exceed the isolated namespace contract"
                    )
                result = self._stream(identifier, interactive=False, timeout=60)
                if result != {"sealed": True, "target": target}:
                    raise DacError("Network helper did not verify the declared target policy")
            finally:
                if identifier:
                    self._command(["rm", "--force", identifier])

    def run(
        self,
        role: str,
        request: dict,
        mounts: list[Mount],
        *,
        pod: str | None = None,
        interactive: bool = False,
        image_kind: str = "runtime",
    ) -> dict:
        self.preflight()
        if role not in OFFLINE_ROLES | TARGET_ROLES | {"download"}:
            raise DacError(f"Unknown container worker role: {role}")
        if image_kind not in {"runtime", "test"} or (role == "test" and image_kind != "test"):
            raise DacError("The selected image is not permitted for this workload")
        network = "none"
        target = None
        if role in TARGET_ROLES:
            if pod not in self._seals:
                raise DacError("SSH operations require a newly sealed acquisition namespace")
            seal = self._seals[pod]
            if self._pod_state(pod) != seal["state"]:
                raise DacError("The acquisition namespace restarted after it was sealed")
            network, target = "target", seal["target"]
            if "target" in request and _target(request["target"]) != target:
                raise DacError("The requested SSH target differs from the sealed namespace")
        elif pod is not None:
            raise DacError("Only acquisition and target-key operations may join an SSH namespace")
        elif role == "download":
            network = "registry"
        policy: dict[str, Any] = {
            "role": role,
            "image": self.images[image_kind],
            "rootless": True,
            "network": network,
        }
        if target is not None:
            policy["target"] = target
        allowed_writable = {
            "import": {"/output"},
            "acquire": {"/output"},
            "analyse": {"/output"},
            "target": {"/identity"},
            "manage": {"/output", "/installed-packs"},
            "download": {"/output"},
            "export": set(),
            "test": set(),
        }
        for mount in mounts:
            if not mount.read_only and mount.target not in allowed_writable[role]:
                raise DacError(f"The {role} role cannot write the requested mount")
            parts = Path(mount.target).parts
            if role in {"analyse", "export", "download", "test"} and (
                len(parts) > 1 and parts[1] in {"identity", "credentials", "keys", "imports"}
            ):
                raise DacError(f"The {role} role cannot receive target credentials")
        payload = json.dumps(request, ensure_ascii=True).encode("utf-8")
        if len(payload) > MAX_REQUEST_BYTES:
            raise DacError("Container request exceeded its size limit")
        mount_options = [self._mount(mount) for mount in mounts]
        destinations = [mount.target for mount in mounts]
        if len(set(destinations)) != len(destinations):
            raise DacError("Duplicate container mount destinations are forbidden")
        identifier = ""
        with tempfile.TemporaryDirectory(prefix="dac-request-") as temporary:
            directory = Path(temporary)
            for filename, data in (
                ("request.json", payload),
                ("policy.json", json.dumps(policy).encode("utf-8")),
            ):
                path = directory / filename
                path.write_bytes(data)
                path.chmod(0o444)
            arguments = [
                "create",
                "--name",
                "dac-" + role + "-" + uuid.uuid4().hex,
                "--label",
                f"{OWNER_LABEL}=true",
                "--read-only",
                "--user=10001:10001",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--restart=no",
                "--cpus=2",
                f"--memory={MEMORY_BYTES}",
                f"--memory-swap={MEMORY_BYTES}",
                f"--pids-limit={PID_LIMIT}",
                "--ulimit=nofile=1024:1024",
                "--ulimit=fsize=1073741824:1073741824",
                "--ipc=private",
                "--pid=private",
                "--uts=private",
                "--init",
                "--http-proxy=false",
                "--unsetenv-all",
                "--env=HOME=/home/dac",
                "--env=PATH=/opt/dac/venv/bin:/usr/local/bin:/usr/bin:/bin",
                "--env=TMPDIR=/tmp",
                "--env=XDG_CACHE_HOME=/tmp/cache",
                "--env=XDG_DATA_HOME=/tmp/data",
                "--env=PYTHONDONTWRITEBYTECODE=1",
                "--env=LANG=C.UTF-8",
                "--workdir=/work",
                "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=1g,mode=1777",
                "--tmpfs=/run:rw,nosuid,nodev,noexec,size=16m,mode=755",
                "--tmpfs=/run/dac-auth:rw,nosuid,nodev,noexec,size=1m,mode=1777",
                "--tmpfs=/work:rw,nosuid,nodev,noexec,size=64m,mode=1777",
                "--mount",
                f"type=bind,src={directory},dst=/run/dac,ro=true",
                "--pull=never",
            ]
            if pod is not None:
                arguments.extend(["--pod", pod])
            else:
                arguments.extend(["--userns=keep-id:uid=10001,gid=10001", "--no-hosts"])
                arguments.append(
                    "--network=none" if network == "none" else "--network=pasta:--ipv4-only"
                )
            if interactive:
                arguments.append("--interactive")
            for mount in mount_options:
                arguments.extend(["--mount", mount])
            arguments.append(self.images[image_kind])
            try:
                identifier = self._command(arguments).strip()
                self._inspect_workload(identifier, network, pod, self.images[image_kind])
                if pod is not None and self._pod_state(pod) != self._seals[pod]["state"]:
                    raise DacError("The acquisition namespace changed before workload start")
                return self._stream(identifier, interactive=interactive)
            finally:
                if identifier:
                    self._command(["rm", "--force", identifier])
