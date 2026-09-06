"""Container-only SSH identity provisioning and short-lived local agents."""

from __future__ import annotations

import getpass
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from detection_goggles.errors import DacError


def _guard(roles: set[str]) -> None:
    from detection_goggles.runtime_guard import require_container

    require_container(*roles)


def _environment() -> dict[str, str]:
    return {"PATH": os.defpath, "HOME": "/tmp", "LANG": "C.UTF-8"}


def _passphrase(prompt: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    # The host launcher disables terminal echo before forwarding interactive
    # input. Pipes have no terminal echo; keep stdout reserved for the response.
    print(prompt, end="", file=sys.stderr, flush=True)
    # Do not read ahead: Ansible may consume a subsequent become-password line
    # from this same descriptor after the dedicated key has been unlocked.
    raw = bytearray()
    while len(raw) <= 4096:
        character = os.read(sys.stdin.fileno(), 1)
        if not character:
            break
        raw.extend(character)
        if character == b"\n":
            break
    value = raw.decode("utf-8")
    if not value or len(value) > 4096:
        raise DacError("Passphrase input is missing or exceeds its limit")
    return value.rstrip("\r\n")


def _check_phrase(phrase: str) -> None:
    # OpenSSH's askpass reader has a 1024-byte C buffer. Reject values that
    # would be silently truncated or interpreted as a different passphrase.
    if any(character in phrase for character in "\x00\r\n") or len(phrase.encode("utf-8")) > 1023:
        raise DacError("Passphrases must fit 1023 UTF-8 bytes and contain no NUL or line breaks")


@contextmanager
def _askpass(directory: Path, phrase: str, *, consume: bool = False) -> Iterator[dict[str, str]]:
    _check_phrase(phrase)
    secret = directory / "passphrase"
    descriptor = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(phrase + "\n")
        executable = Path(sys.executable).with_name("dac-askpass")
        yield {
            "SSH_ASKPASS": str(executable),
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": "dac",
            "DAC_PASSPHRASE_FILE": str(secret),
            "DAC_ASKPASS_ONCE": "1" if consume else "0",
        }
    finally:
        secret.unlink(missing_ok=True)


def askpass() -> int:
    """OpenSSH helper; the passphrase itself is never an argument or environment value."""
    try:
        _guard({"target", "acquire"})
        path = Path(os.environ.get("DAC_PASSPHRASE_FILE", ""))
        if not path.is_absolute() or not path.is_relative_to("/run/dac-auth"):
            raise DacError("Invalid passphrase location")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o077
                or metadata.st_size > 8192
            ):
                raise DacError("Unsafe passphrase file")
            phrase = handle.read(8192)
        if os.environ.get("DAC_ASKPASS_ONCE") == "1":
            # A wrong phrase must fail once, not make ssh-add repeatedly invoke
            # the helper with the same wrong value until its timeout expires.
            path.unlink()
        sys.stdout.buffer.write(phrase)
        return 0
    except (DacError, OSError):
        return 2


def _auth_root() -> Path:
    root = Path("/run/dac-auth")
    root.mkdir(mode=0o700, exist_ok=True)
    return root


def _host_key(target: dict[str, Any], directory: Path) -> bytes:
    scan = subprocess.run(
        ["ssh-keyscan", "-T", "10", "-p", str(target["port"]), target["host"]],
        check=False,
        capture_output=True,
        timeout=30,
        env=_environment(),
    )
    candidate = directory / "host.pub"
    for line in scan.stdout.splitlines():
        if not line or line.startswith(b"#") or len(line) > 16384:
            continue
        candidate.write_bytes(line + b"\n")
        fingerprint = subprocess.run(
            ["ssh-keygen", "-E", "sha256", "-lf", str(candidate)],
            check=False,
            capture_output=True,
            timeout=10,
            env=_environment(),
        )
        fields = fingerprint.stdout.decode("utf-8", errors="replace").split()
        if fingerprint.returncode == 0 and len(fields) > 1 and fields[1] == target["fingerprint"]:
            return line + b"\n"
    raise DacError("Target host key did not match the independently obtained fingerprint")


def import_identity(request: dict[str, Any]) -> dict[str, Any]:
    _guard({"import"})
    source = Path(request["source"])
    if source != Path("/inputs/key"):
        raise DacError("Identity import requires the explicitly selected input file")
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as incoming:
        metadata = os.fstat(incoming.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024**2:
            raise DacError("SSH identity must be a regular file smaller than 1 MiB")
        output = os.open("/output/id_ed25519", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(output, "wb") as outgoing:
            data = incoming.read(1024**2 + 1)
            if len(data) > 1024**2:
                raise DacError("SSH identity grew beyond the import limit")
            outgoing.write(data)
    return {"exit_code": 0}


def handle(request: dict[str, Any]) -> dict[str, Any]:
    if request["op"] == "identity_import":
        return import_identity(request)
    _guard({"target"})
    if request["op"] in {"verify-network", "verify_network"}:
        return verify_network(request)
    target = request["target"]
    # The driver seals this exact destination before this worker is created.
    from detection_goggles.runtime_guard import require_container

    policy = require_container("target")
    for field in ("host", "port", "fingerprint"):
        if policy["target"][field] != target[field]:
            raise DacError("Target differs from the sealed namespace")
    key = Path("/identity/id_ed25519")
    if key.exists() or key.is_symlink():
        raise DacError("Refusing to overwrite a target identity")
    with tempfile.TemporaryDirectory(prefix="key-", dir=_auth_root()) as temporary:
        directory = Path(temporary)
        matched = _host_key(target, directory)
        descriptor = os.open("/identity/known_hosts", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(matched)
        phrase = _passphrase("Passphrase for the new dedicated SSH key: ")
        confirmation = _passphrase("Repeat the passphrase: ")
        if not phrase or phrase != confirmation or "\n" in phrase or len(phrase) > 4096:
            raise DacError("A matching, non-empty passphrase is required")
        with _askpass(directory, phrase) as extra:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-a",
                    "100",
                    "-f",
                    str(key),
                    "-C",
                    f"dac-{target['name']}",
                ],
                stdin=subprocess.DEVNULL,
                env={**_environment(), **extra},
                timeout=120,
                check=False,
            )
        if result.returncode != 0:
            raise DacError("Dedicated SSH key generation failed")
        unencrypted = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(key)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_environment(),
            timeout=10,
            check=False,
        )
        if unencrypted.returncode == 0:
            raise DacError("The generated SSH key is not encrypted; refusing to retain it")
    key.chmod(0o600)
    return {
        "exit_code": 0,
        "public_key": key.with_suffix(".pub").read_text(encoding="ascii").strip(),
    }


def verify_network(request: dict[str, Any]) -> dict[str, Any]:
    from detection_goggles.runtime_guard import require_container

    policy = require_container("target")
    target = policy["target"]
    with socket.create_connection((target["host"], target["port"]), timeout=5):
        pass
    with tempfile.TemporaryDirectory(prefix="verify-key-", dir=_auth_root()) as temporary:
        _host_key(target, Path(temporary))
    probes = [
        (target["host"], 1 if target["port"] == 65535 else target["port"] + 1),
        ("1.1.1.1", 443),
        ("169.254.1.2", 22),
        ("127.0.0.1", 22),
        ("::1", 22),
    ]
    for host, port in probes:
        try:
            with socket.create_connection((host, port), timeout=1):
                raise DacError(f"Forbidden network probe succeeded: {host}:{port}")
        except OSError:
            pass
    return {"exit_code": 0, "message": "Approved target reachable; forbidden probes failed"}


@contextmanager
def unlocked_identity(identity: Path) -> Iterator[str]:
    """Load only the selected key into an agent that dies with this acquisition."""
    _guard({"acquire"})
    if identity.is_symlink() or not identity.is_file():
        raise DacError("Selected SSH identity is unavailable")
    with tempfile.TemporaryDirectory(prefix="agent-", dir=_auth_root()) as temporary:
        directory = Path(temporary)
        socket = directory / "agent.sock"
        agent = subprocess.Popen(
            ["ssh-agent", "-D", "-a", str(socket)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_environment(),
        )
        try:
            deadline = time.monotonic() + 5
            while not socket.exists():
                if agent.poll() is not None or time.monotonic() >= deadline:
                    raise DacError("Could not start the acquisition SSH agent")
                time.sleep(0.02)
            check = subprocess.run(
                ["ssh-keygen", "-y", "-P", "", "-f", str(identity)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_environment(),
                check=False,
                timeout=10,
            )
            phrase = "" if check.returncode == 0 else _passphrase("SSH key passphrase: ")
            with _askpass(directory, phrase, consume=True) as extra:
                result = subprocess.run(
                    ["ssh-add", str(identity)],
                    stdin=subprocess.DEVNULL,
                    env={**_environment(), **extra, "SSH_AUTH_SOCK": str(socket)},
                    check=False,
                    timeout=120,
                )
            if result.returncode != 0:
                raise DacError("Could not unlock the selected SSH identity")
            yield str(socket)
        finally:
            agent.terminate()
            try:
                agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                agent.kill()
                agent.wait()
