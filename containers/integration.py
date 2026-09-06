#!/usr/bin/env python3
"""Live acceptance against a disposable SSH service and inert synthetic samples.

Run after container-build. Only the host launcher is invoked here; detectors run
in the mandatory restricted runtime. No existing target or evidence is reused.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
PACK = "htb-malevolent-modmaker"


def command(
    arguments: list[str], *, expected: int = 0, input_text: str | None = None, timeout: int = 300
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPOSITORY / "src")
    result = subprocess.run(
        arguments,
        input=input_text,
        text=True,
        capture_output=True,
        env=environment,
        timeout=timeout,
        check=False,
    )
    if result.returncode != expected:
        raise RuntimeError(
            f"Command {arguments[:4]} exited {result.returncode}, expected {expected}:\n"
            f"{result.stdout[-4000:]}\n{result.stderr[-4000:]}"
        )
    return result


def cli(arguments: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    print("Checking: " + " ".join(arguments[:3]), flush=True)
    return command([sys.executable, "-m", "detection_goggles", *arguments], **kwargs)


def pe(markers: bytes) -> bytes:
    data = bytearray(132)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 128)
    data[128:132] = b"PE\0\0"
    return bytes(data) + markers


def report(root: Path) -> dict:
    paths = list(root.glob("*/report.json"))
    if len(paths) != 1:
        raise RuntimeError("Expected exactly one exported JSON report")
    return json.loads(paths[0].read_text())


def main() -> None:
    cli(["runtime", "doctor"])
    run_token = uuid.uuid4().hex[:12]
    target_name = f"integration-{run_token}"
    server_name = f"dac-integration-{run_token}"
    retained = None
    created_target = False
    created_server = False
    with tempfile.TemporaryDirectory(prefix="dac-integration-") as temporary:
        root = Path(temporary)
        keys, samples = root / "keys", root / "samples"
        keys.mkdir(mode=0o755)
        samples.mkdir(mode=0o755)
        ransomware = pe(b"Go build ID: crypto/aes cipher.NewGCM os.ReadFile os.WriteFile")
        loader = pe(b"Go build ID: net/http os/exec https://example.invalid/payload")
        (samples / "ransomware.bin").write_bytes(ransomware)
        (samples / "loader.bin").write_bytes(loader)
        for path in samples.iterdir():
            path.chmod(0o644)
        # Fixture keys contain no user identity and live only for this test.
        for filename in ("host_key", "import_key"):
            command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keys / filename)])
        authorised = keys / "authorized_keys"
        authorised.write_bytes((keys / "import_key.pub").read_bytes())
        authorised.chmod(0o644)
        fingerprint = command(
            ["ssh-keygen", "-E", "sha256", "-lf", str(keys / "host_key.pub")]
        ).stdout.split()[1]
        build_root = root / "build"
        build_root.mkdir()
        shutil.copyfile(
            REPOSITORY / "containers/ssh-test.Containerfile", build_root / "Containerfile"
        )
        command(
            [
                "podman",
                "--remote=false",
                "build",
                "--layers",
                "--tag",
                "localhost/dac-ssh-test:acceptance",
                str(build_root),
            ],
            timeout=900,
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            host = probe.getsockname()[0]
        forbidden_listener = socket.socket()
        for _ in range(20):
            with socket.socket() as available:
                available.bind(("0.0.0.0", 0))
                port = available.getsockname()[1]
            try:
                forbidden_listener.bind((host, 1 if port == 65535 else port + 1))
                forbidden_listener.listen(8)
                break
            except OSError:
                continue
        else:
            forbidden_listener.close()
            raise RuntimeError("Could not reserve the denied-port positive-control listener")
        try:
            command(
                [
                    "podman",
                    "--remote=false",
                    "run",
                    "--detach",
                    "--name",
                    server_name,
                    "--label",
                    "io.detection-goggles.integration=true",
                    "--network=pasta",
                    "--publish",
                    f"{host}:{port}:2222",
                    "--volume",
                    f"{keys / 'host_key'}:/keys/host_key:ro",
                    "--volume",
                    f"{authorised}:/keys/authorized_keys:ro",
                    "--volume",
                    f"{samples}:/samples:ro",
                    "localhost/dac-ssh-test:acceptance",
                ]
            )
            created_server = True
            deadline = time.monotonic() + 15
            while True:
                try:
                    with socket.create_connection((host, port), timeout=1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("Disposable SSH service did not start") from None
                    time.sleep(0.1)
            init = cli(
                [
                    "target",
                    "init",
                    target_name,
                    "--host",
                    host,
                    "--port",
                    str(port),
                    "--host-key-fingerprint",
                    fingerprint,
                ],
                input_text="test-only-passphrase\ntest-only-passphrase\n",
            )
            created_target = True
            public_keys = [
                line for line in init.stdout.splitlines() if line.startswith("ssh-ed25519 ")
            ]
            if len(public_keys) != 1:
                raise RuntimeError("Target initialisation did not return one public key")
            with authorised.open("a") as handle:
                handle.write(public_keys[0] + "\n")

            local_output = root / "local"
            cli(
                [
                    "run",
                    "files",
                    PACK,
                    str(samples),
                    "--recursive",
                    "--retain-evidence",
                    "--output",
                    str(local_output),
                ],
                expected=1,
            )
            local = report(local_output)
            retained = local["run"]["id"]
            if {finding["rule_id"] for finding in local["findings"]} != {
                "MMM-001",
                "MMM-002",
                "MMM-003",
            }:
                raise RuntimeError("Synthetic chain did not produce all three detections")
            replay_output = root / "replay"
            cli(
                ["run", "evidence", PACK, "--run-id", retained, "--output", str(replay_output)],
                expected=1,
            )
            replay = report(replay_output)
            if (
                replay["run"]["mode"] != "replay"
                or replay["run"]["evidence_run_id"] != local["run"]["evidence_run_id"]
            ):
                raise RuntimeError("Replay identity or mode was not preserved")
            if (samples / "ransomware.bin").read_bytes() != ransomware or (
                samples / "loader.bin"
            ).read_bytes() != loader:
                raise RuntimeError("Source evidence was modified")

            clean = root / "clean.txt"
            clean.write_text("An inert clean text fixture.\n")
            cli(["run", "files", PACK, str(clean), "--output", str(root / "clean")])
            if report(root / "clean")["summary"]["finding_count"] != 0:
                raise RuntimeError("Clean text unexpectedly produced a detection")
            linked = root / "linked"
            linked.mkdir()
            (linked / "loader.bin").write_bytes(loader)
            (linked / "outside").symlink_to(samples, target_is_directory=True)
            cli(
                [
                    "run",
                    "files",
                    PACK,
                    str(linked),
                    "--recursive",
                    "--follow-symlinks",
                    "--output",
                    str(root / "link-result"),
                ],
                expected=2,
            )
            if report(root / "link-result")["summary"]["acquisition_issue_count"] != 1:
                raise RuntimeError("Out-of-selection symbolic link was not rejected")

            ssh_args = [
                "run",
                "ssh",
                PACK,
                "--target",
                target_name,
                "--user",
                "analyst",
                "--remote-file",
                "/samples/ransomware.bin",
                "--remote-file",
                "/samples/loader.bin",
            ]
            ssh_output = root / "ssh"
            cli(
                [*ssh_args, "--output", str(root / "wrong-passphrase")],
                expected=2,
                input_text="deliberately-wrong-passphrase\n",
            )
            if (root / "wrong-passphrase").exists():
                raise RuntimeError("A wrong key passphrase reached report export")
            cli(
                [*ssh_args, "--output", str(ssh_output)],
                expected=1,
                input_text="test-only-passphrase\n",
            )
            ssh_report = report(ssh_output)
            if ssh_report["run"]["source"] != "ssh" or ssh_report["run"]["mode"] != "acquisition":
                raise RuntimeError("Fresh SSH acquisition was mislabelled as replay")
            if ssh_report["summary"]["finding_count"] != local["summary"]["finding_count"]:
                raise RuntimeError("SSH and local analysis disagree")
            cli(
                [
                    *ssh_args,
                    "--become",
                    "--ask-become-pass",
                    "--output",
                    str(root / "key-become"),
                ],
                expected=1,
                input_text="test-only-passphrase\ndac-test-password\n",
            )
            cli(
                [
                    *ssh_args,
                    "--identity",
                    str(keys / "import_key"),
                    "--output",
                    str(root / "imported-key"),
                ],
                expected=1,
            )
            cli(
                [*ssh_args, "--ask-pass", "--output", str(root / "password")],
                expected=1,
                input_text="dac-test-password\n",
            )
            cli(
                [
                    *ssh_args,
                    "--ask-pass",
                    "--become",
                    "--ask-become-pass",
                    "--output",
                    str(root / "become"),
                ],
                expected=1,
                input_text="dac-test-password\ndac-test-password\n",
            )
            cli(
                [
                    "run",
                    "files",
                    PACK,
                    str(samples / "loader.bin"),
                    str(root / "missing"),
                    "--output",
                    str(root / "partial"),
                ],
                expected=2,
            )
            if report(root / "partial")["summary"]["acquisition_issue_count"] != 1:
                raise RuntimeError("Partial local acquisition was not reported")
            cli(
                [
                    *ssh_args,
                    "--remote-file",
                    "/samples/missing",
                    "--identity",
                    str(keys / "import_key"),
                    "--output",
                    str(root / "ssh-partial"),
                ],
                expected=2,
            )
            if report(root / "ssh-partial")["summary"]["acquisition_issue_count"] != 1:
                raise RuntimeError("Partial SSH acquisition was not reported")
            verification = [
                sys.executable,
                str(REPOSITORY / "containers/check.py"),
                "verify",
                "--target-ip",
                host,
                "--target-port",
                str(port),
                "--host-key-fingerprint",
            ]
            # The forbidden adjacent port is known to be listening, so failure
            # inside the acquisition namespace is evidence of the allowlist.
            with socket.create_connection(forbidden_listener.getsockname(), timeout=2):
                pass
            command([*verification, fingerprint])
            wrong_fingerprint = command(
                ["ssh-keygen", "-E", "sha256", "-lf", str(keys / "import_key.pub")]
            ).stdout.split()[1]
            command([*verification, wrong_fingerprint], expected=2)
            cli(["pack", "build", PACK, "--output", str(root / "archives")])
            archive = next((root / "archives").glob("*.tar.gz"))
            import hashlib

            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            cli(
                [
                    "pack",
                    "verify",
                    str(archive),
                    "--registry",
                    str(REPOSITORY / "registry/packs.yml"),
                ]
            )
            cli(["pack", "install", str(archive), "--sha256", digest])
            for path in root.glob("*/*/report.json"):
                if {member.name for member in path.parent.iterdir()} != {
                    "report.json",
                    "report.md",
                }:
                    raise RuntimeError("Report export included unexpected files or raw evidence")
                for member in path.parent.iterdir():
                    exported = member.read_text()
                    if any(
                        secret in exported
                        for secret in ("test-only-passphrase", "dac-test-password", "PRIVATE KEY")
                    ):
                        raise RuntimeError("A report contained fixture credentials")
        finally:
            failures = []
            if retained:
                try:
                    cli(["evidence", "remove", retained])
                except (RuntimeError, subprocess.SubprocessError) as error:
                    failures.append(str(error))
            if created_target:
                try:
                    cli(["target", "remove", target_name])
                except (RuntimeError, subprocess.SubprocessError) as error:
                    failures.append(str(error))
            if created_server:
                try:
                    command(["podman", "--remote=false", "rm", "--force", server_name])
                except (RuntimeError, subprocess.SubprocessError) as error:
                    failures.append(str(error))
            forbidden_listener.close()
            if failures:
                raise RuntimeError("Acceptance cleanup failed: " + "; ".join(failures))
        print(
            "PASS: real SSH, generated encrypted and imported keys, all detections, replay, "
            "partial acquisition, network allowlist, wrong-fingerprint rejection, "
            "pack build/install and cleanup",
            flush=True,
        )


if __name__ == "__main__":
    main()
