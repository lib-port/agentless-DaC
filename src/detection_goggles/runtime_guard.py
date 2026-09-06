"""Fail closed unless the worker is inside the required restricted Linux runtime.

The policy describes the launcher's intended role. Kernel state is checked independently;
the policy is not an authentication token and cannot constrain the owner of the host.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from detection_goggles.errors import ContractError

POLICY_PATH = Path("/run/dac/policy.json")
MAX_POLICY_BYTES = 16 * 1024
OFFLINE_ROLES = frozenset({"import", "analyse", "export", "manage", "test"})
ROLE_NETWORKS = {
    **dict.fromkeys(OFFLINE_ROLES, "none"),
    "acquire": "target",
    "target": "target",
    "download": "registry",
}


def _deny(reason: str) -> None:
    raise ContractError(
        f"A verified rootless Podman runtime is required: {reason}. Use the host dacctl launcher."
    )


def _read_text(path: Path, *, limit: int = 256 * 1024) -> str:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        _deny(f"runtime metadata exceeds its limit ({path})")
    return raw.decode("utf-8")


def _mounts() -> list[tuple[Path, set[str]]]:
    mounts = []
    for line in _read_text(Path("/proc/self/mountinfo")).splitlines():
        fields = line.split()
        if len(fields) < 7 or " - " not in line:
            _deny("malformed mount metadata")
        mount_path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
        mounts.append((Path(mount_path), set(fields[5].split(","))))
    return mounts


def _readonly(path: Path, mounts: list[tuple[Path, set[str]]]) -> bool:
    applicable = [(mount, flags) for mount, flags in mounts if path.is_relative_to(mount)]
    return bool(applicable and "ro" in max(applicable, key=lambda item: len(item[0].parts))[1])


def _policy(mounts: list[tuple[Path, set[str]]]) -> dict[str, Any]:
    if not _readonly(POLICY_PATH, mounts):
        _deny("the launch policy is not mounted read-only")
    descriptor = os.open(POLICY_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            _deny("the launch policy is not a single regular file")
        if metadata.st_mode & 0o222:
            _deny("the launch policy has writable permission bits")
        raw = os.read(descriptor, MAX_POLICY_BYTES + 1)
        if len(raw) > MAX_POLICY_BYTES:
            _deny("the launch policy exceeds its size limit")
        policy = json.loads(raw.decode("utf-8"))
    finally:
        os.close(descriptor)
    if not isinstance(policy, dict) or policy.get("rootless") is not True:
        _deny("missing rootless launch policy")
    role = policy.get("role")
    if role not in ROLE_NETWORKS or policy.get("network") != ROLE_NETWORKS[role]:
        _deny("invalid role or network policy")
    if not isinstance(policy.get("image"), str) or not re.fullmatch(
        r"(?:[^\s]+@)?sha256:[a-f0-9]{64}", policy["image"]
    ):
        _deny("the image is not identified by an immutable SHA-256 digest")
    if role in {"acquire", "target"}:
        target = policy.get("target")
        if not isinstance(target, dict):
            _deny("the target role has no sealed target")
        ipaddress.ip_address(target.get("host", ""))
        port = target.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            _deny("the sealed target port is invalid")
        if role == "acquire" and not re.fullmatch(
            r"SHA256:[A-Za-z0-9+/]{43}", str(target.get("fingerprint", ""))
        ):
            _deny("the acquisition target has no pinned SSH fingerprint")
    return policy


def _effective_limit(name: str) -> int:
    root = Path("/sys/fs/cgroup")
    cgroups = _read_text(Path("/proc/self/cgroup"), limit=16 * 1024).splitlines()
    paths = [line[3:] for line in cgroups if line.startswith("0::")]
    if len(paths) != 1 or not paths[0].startswith("/") or ".." in Path(paths[0]).parts:
        _deny("a private cgroup v2 hierarchy is required")
    current = root / paths[0].lstrip("/")
    limits = []
    while current.is_relative_to(root):
        candidate = current / name
        if candidate.is_file():
            value = _read_text(candidate, limit=128).strip()
            if value != "max":
                parsed = int(value)
                if parsed <= 0:
                    _deny(f"invalid {name} cgroup limit")
                limits.append(parsed)
        if current == root:
            break
        current = current.parent
    if not limits:
        _deny(f"no effective finite {name} cgroup limit")
    return min(limits)


def _cpu_limit() -> float:
    root = Path("/sys/fs/cgroup")
    entries = _read_text(Path("/proc/self/cgroup"), limit=16 * 1024).splitlines()
    path = next(line[3:] for line in entries if line.startswith("0::"))
    current = root / path.lstrip("/")
    limits = []
    while current.is_relative_to(root):
        candidate = current / "cpu.max"
        if candidate.is_file():
            quota, period = _read_text(candidate, limit=128).split()
            if quota != "max":
                if int(quota) <= 0 or int(period) <= 0:
                    _deny("invalid CPU cgroup limit")
                limits.append(int(quota) / int(period))
        if current == root:
            break
        current = current.parent
    if not limits:
        _deny("no effective finite CPU cgroup limit")
    return min(limits)


def require_container(*roles: str) -> dict[str, Any]:
    """Check every execution boundary without caching mutable runtime observations."""

    try:
        if os.name != "posix" or not Path("/proc/self/status").is_file():
            _deny("Linux kernel runtime metadata is unavailable")
        if os.geteuid() == 0 or os.getuid() == 0:
            _deny("the worker must run as a non-root user")
        mappings = [
            tuple(int(value) for value in line.split())
            for line in _read_text(Path("/proc/self/uid_map"), limit=4096).splitlines()
        ]
        if not mappings or any(len(mapping) != 3 for mapping in mappings):
            _deny("invalid user namespace mappings")
        if not any(inside != outside for inside, outside, _ in mappings):
            _deny("an unprivileged user namespace is required")
        mounts = _mounts()
        if not _readonly(Path("/"), mounts):
            _deny("the container root filesystem is writable")
        status = dict(
            line.split(":", 1)
            for line in _read_text(Path("/proc/self/status")).splitlines()
            if ":" in line
        )
        if any(int(status.get(name, "-1"), 16) != 0 for name in ("CapEff", "CapBnd")):
            _deny("capabilities have not been completely dropped")
        if status.get("NoNewPrivs", "").strip() != "1":
            _deny("no-new-privileges is not enabled")
        if status.get("Seccomp", "").strip() != "2":
            _deny("a seccomp filter is required")
        if _effective_limit("memory.max") > 4 * 1024**3:
            _deny("the memory limit exceeds 4 GiB")
        if _effective_limit("pids.max") > 128:
            _deny("the process limit exceeds 128")
        if _cpu_limit() > 2:
            _deny("the CPU limit exceeds two CPUs")
        policy = _policy(mounts)
        if roles and policy["role"] not in roles:
            _deny(f"operation is forbidden in the {policy['role']!r} runtime role")
        if policy["network"] == "none":
            interfaces = {
                line.split(":", 1)[0].strip()
                for line in _read_text(Path("/proc/net/dev"), limit=16 * 1024).splitlines()
                if ":" in line
            }
            if interfaces - {"lo"}:
                _deny("the offline role has a non-loopback network interface")
        return policy
    except ContractError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        _deny(f"runtime verification failed ({type(exc).__name__})")
    raise AssertionError("unreachable")
