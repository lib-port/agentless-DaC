"""Lightweight host CLI: substantive work is delegated to Podman."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from detection_goggles import __version__
from detection_goggles.errors import DacError

DEFAULT_REGISTRY = (
    "https://raw.githubusercontent.com/lib-port/agentless-DaC/main/registry/packs.yml"
)


def _size(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)(B|KiB|MiB|GiB)?", value, re.IGNORECASE)
    if not match:
        raise argparse.ArgumentTypeError("use a positive byte count, for example 128MiB")
    return (
        int(match[1])
        * {"b": 1, "kib": 1024, "mib": 1024**2, "gib": 1024**3}[(match[2] or "B").lower()]
    )


def _positive(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def _sha256(value: str) -> str:
    if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise argparse.ArgumentTypeError("SHA-256 must contain 64 hexadecimal characters")
    return value.lower()


def _run_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-file-size", type=_size, default=128 * 1024**2)
    parser.add_argument("--max-total-size", type=_size, default=512 * 1024**2)
    parser.add_argument("--max-files", type=_positive, default=1000)
    parser.add_argument("--timeout", type=_positive, default=10)
    parser.add_argument("--output", type=Path, default=Path("reports"))
    parser.add_argument("--retain-evidence", action="store_true")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dacctl", description="Run Detection Packs in compulsory rootless Podman containers."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--pack-root", action="append", type=Path, default=[])
    commands = parser.add_subparsers(dest="command", required=True)

    runtime = commands.add_parser("runtime", help="inspect the container runtime")
    runtime.add_subparsers(dest="runtime_action", required=True).add_parser("doctor")

    targets = commands.add_parser("target", help="manage pinned SSH targets and dedicated keys")
    target_actions = targets.add_subparsers(dest="target_action", required=True)
    target_actions.add_parser("list")
    target_remove = target_actions.add_parser("remove")
    target_remove.add_argument("name")
    target_init = target_actions.add_parser("init")
    target_init.add_argument("name")
    target_init.add_argument("--host", required=True, help="literal unicast IPv4 address")
    target_init.add_argument("--port", type=_positive, default=22)
    target_init.add_argument("--host-key-fingerprint", required=True)

    evidence = commands.add_parser("evidence", help="manage retained evidence")
    evidence_actions = evidence.add_subparsers(dest="evidence_action", required=True)
    evidence_actions.add_parser("list")
    evidence_remove = evidence_actions.add_parser("remove")
    evidence_remove.add_argument("run_id")

    packs = commands.add_parser("pack", help="inspect, build and install Detection Packs")
    actions = packs.add_subparsers(dest="pack_action", required=True)
    actions.add_parser("list")
    available = actions.add_parser("available")
    available.add_argument("--registry", default=DEFAULT_REGISTRY)
    validate = actions.add_parser("validate")
    validate.add_argument("pack")
    build = actions.add_parser("build")
    build.add_argument("pack")
    build.add_argument("--output", type=Path, default=Path("dist"))
    verify = actions.add_parser("verify")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--registry", default=DEFAULT_REGISTRY)
    install = actions.add_parser("install")
    install.add_argument("reference")
    install.add_argument("--sha256", type=_sha256)
    install.add_argument("--registry", default=DEFAULT_REGISTRY)
    install.add_argument("--destination-root", type=Path, help=argparse.SUPPRESS)

    run = commands.add_parser("run", help="analyse explicitly selected evidence")
    sources = run.add_subparsers(dest="run_source", required=True)
    files = sources.add_parser("files")
    files.add_argument("pack")
    files.add_argument("paths", nargs="+", type=Path)
    files.add_argument("--recursive", action="store_true")
    files.add_argument("--follow-symlinks", action="store_true")
    _run_options(files)
    replay = sources.add_parser("evidence")
    replay.add_argument("pack")
    replay.add_argument("bundle", nargs="?", type=Path)
    replay.add_argument("--run-id")
    _run_options(replay)
    ssh = sources.add_parser("ssh", aliases=["host"])
    ssh.add_argument("pack")
    ssh.add_argument("--target", required=True)
    ssh.add_argument("--user", required=True)
    ssh.add_argument("--remote-file", action="append", required=True, dest="remote_files")
    ssh.add_argument("--identity", type=Path)
    ssh.add_argument("--ask-pass", action="store_true")
    ssh.add_argument("--become", action="store_true")
    ssh.add_argument("--ask-become-pass", action="store_true")
    ssh.add_argument("--connection-timeout", type=_positive, default=30)
    ssh.add_argument("--acquisition-timeout", type=_positive, default=600)
    _run_options(ssh)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        from detection_goggles.launcher import dispatch

        return dispatch(arguments)
    except (DacError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted; disposable resources are being removed", file=sys.stderr)
        return 2
