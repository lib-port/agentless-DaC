"""The dacctl command-line interface."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from detection_goggles import __version__
from detection_goggles.errors import DacError
from detection_goggles.evidence import (
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_TOTAL_SIZE,
    HARD_MAX_FILE_SIZE,
    HARD_MAX_FILES,
    HARD_MAX_TOTAL_SIZE,
)
from detection_goggles.package_archive import build_pack_archive, install_pack_archive
from detection_goggles.packs import default_pack_roots, discover_packs, resolve_pack
from detection_goggles.registry import (
    DEFAULT_REGISTRY,
    install_registry_pack,
    load_registry,
    verify_registry_archive,
)
from detection_goggles.runner import CompletedRun, run_evidence, run_files, run_ssh
from detection_goggles.ssh_source import SshOptions

SIZE_PATTERN = re.compile(r"^(?P<number>[1-9][0-9]*)(?P<unit>B|KiB|MiB|GiB)?$", re.IGNORECASE)
SIZE_MULTIPLIERS = {"b": 1, "kib": 1024, "mib": 1024**2, "gib": 1024**3}


def _size(value: str) -> int:
    match = SIZE_PATTERN.fullmatch(value)
    if not match:
        raise argparse.ArgumentTypeError("use a positive byte count such as 1048576 or 128MiB")
    unit = (match.group("unit") or "B").lower()
    return int(match.group("number")) * SIZE_MULTIPLIERS[unit]


def _file_size(value: str) -> int:
    size = _size(value)
    if size > HARD_MAX_FILE_SIZE:
        raise argparse.ArgumentTypeError(
            f"file size limit may not exceed {HARD_MAX_FILE_SIZE} bytes"
        )
    return size


def _total_size(value: str) -> int:
    size = _size(value)
    if size > HARD_MAX_TOTAL_SIZE:
        raise argparse.ArgumentTypeError(
            f"total size limit may not exceed {HARD_MAX_TOTAL_SIZE} bytes"
        )
    return size


def _file_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("file count must be an integer") from exc
    if not 1 <= count <= HARD_MAX_FILES:
        raise argparse.ArgumentTypeError(f"file count must be between 1 and {HARD_MAX_FILES}")
    return count


def _positive_timeout(value: str) -> int:
    try:
        timeout = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be an integer") from exc
    if not 1 <= timeout <= 30:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 30 seconds")
    return timeout


def _connection_timeout(value: str) -> int:
    try:
        timeout = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be an integer") from exc
    if not 1 <= timeout <= 300:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 300 seconds")
    return timeout


def _acquisition_timeout(value: str) -> int:
    try:
        timeout = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be an integer") from exc
    if not 1 <= timeout <= 3600:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 3600 seconds")
    return timeout


def _sha256(value: str) -> str:
    lowered = value.lower()
    if not re.fullmatch(r"[a-f0-9]{64}", lowered):
        raise argparse.ArgumentTypeError("SHA-256 must be exactly 64 hexadecimal characters")
    return lowered


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dacctl",
        description="Run first-party Detection Packs against explicit evidence sources.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--pack-root",
        action="append",
        default=[],
        type=Path,
        help="additional Detection Pack search root (repeatable)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    pack_command = commands.add_parser("pack", help="inspect, build, and install packs")
    pack_actions = pack_command.add_subparsers(dest="pack_action", required=True)
    pack_actions.add_parser("list", help="list discoverable packs")

    available_command = pack_actions.add_parser(
        "available", help="list packs in a distribution registry"
    )
    available_command.add_argument("--registry", default=DEFAULT_REGISTRY)

    validate_command = pack_actions.add_parser("validate", help="validate a pack contract")
    validate_command.add_argument("pack")

    build_command = pack_actions.add_parser("build", help="build a reproducible pack archive")
    build_command.add_argument("pack")
    build_command.add_argument("--output", type=Path, default=Path("dist"))

    verify_command = pack_actions.add_parser(
        "verify", help="verify an archive against a distribution registry"
    )
    verify_command.add_argument("archive", type=Path)
    verify_command.add_argument("--registry", default=DEFAULT_REGISTRY)

    install_command = pack_actions.add_parser(
        "install", help="install a local archive or a pack from the registry"
    )
    install_command.add_argument("reference")
    install_command.add_argument("--destination-root", type=Path)
    install_command.add_argument("--registry", default=DEFAULT_REGISTRY)
    install_command.add_argument(
        "--sha256",
        type=_sha256,
        help="required digest to verify when installing a local archive",
    )

    run_command = commands.add_parser("run", help="run detections")
    run_sources = run_command.add_subparsers(dest="run_source", required=True)

    files_command = run_sources.add_parser("files", help="scan explicitly selected local files")
    files_command.add_argument("pack")
    files_command.add_argument("paths", nargs="+", type=Path)
    files_command.add_argument(
        "--recursive",
        action="store_true",
        help="permit directory inputs and scan them recursively",
    )
    files_command.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="follow symbolic links (disabled by default)",
    )
    files_command.add_argument(
        "--max-file-size", type=_file_size, default=DEFAULT_MAX_FILE_SIZE, metavar="SIZE"
    )
    files_command.add_argument(
        "--max-total-size", type=_total_size, default=DEFAULT_MAX_TOTAL_SIZE, metavar="SIZE"
    )
    files_command.add_argument("--max-files", type=_file_count, default=DEFAULT_MAX_FILES)
    files_command.add_argument("--timeout", type=_positive_timeout, default=10)
    files_command.add_argument("--output", type=Path, default=Path("reports"))
    files_command.add_argument(
        "--retain-evidence",
        action="store_true",
        help="retain owner-only file snapshots beside the report",
    )

    evidence_command = run_sources.add_parser("evidence", help="replay a saved evidence bundle")
    evidence_command.add_argument("pack")
    evidence_command.add_argument("bundle", type=Path)
    evidence_command.add_argument(
        "--max-file-size", type=_file_size, default=DEFAULT_MAX_FILE_SIZE, metavar="SIZE"
    )
    evidence_command.add_argument(
        "--max-total-size", type=_total_size, default=DEFAULT_MAX_TOTAL_SIZE, metavar="SIZE"
    )
    evidence_command.add_argument("--max-files", type=_file_count, default=DEFAULT_MAX_FILES)
    evidence_command.add_argument("--timeout", type=_positive_timeout, default=10)
    evidence_command.add_argument("--output", type=Path, default=Path("reports"))
    evidence_command.add_argument("--retain-evidence", action="store_true")

    ssh_command = run_sources.add_parser(
        "ssh",
        aliases=["host"],
        help="fetch explicitly selected remote files over SSH, then scan locally",
    )
    ssh_command.add_argument("pack")
    ssh_command.add_argument("--host", required=True)
    ssh_command.add_argument("--user", required=True)
    ssh_command.add_argument(
        "--remote-file",
        action="append",
        required=True,
        dest="remote_files",
        metavar="PATH",
        help="absolute remote file path (repeatable)",
    )
    ssh_command.add_argument("--port", type=int, default=22)
    ssh_command.add_argument("--identity", type=Path)
    ssh_command.add_argument(
        "--ask-pass",
        action="store_true",
        help="let Ansible prompt interactively for the SSH password",
    )
    ssh_command.add_argument("--become", action="store_true")
    ssh_command.add_argument("--ask-become-pass", action="store_true")
    ssh_command.add_argument(
        "--host-key-policy",
        choices=("strict", "accept-new"),
        default="strict",
        help="verify known hosts strictly (default) or trust a first-seen key",
    )
    ssh_command.add_argument(
        "--connection-timeout", type=_connection_timeout, default=30, metavar="SECONDS"
    )
    ssh_command.add_argument(
        "--acquisition-timeout", type=_acquisition_timeout, default=600, metavar="SECONDS"
    )
    ssh_command.add_argument(
        "--max-file-size", type=_file_size, default=DEFAULT_MAX_FILE_SIZE, metavar="SIZE"
    )
    ssh_command.add_argument(
        "--max-total-size", type=_total_size, default=DEFAULT_MAX_TOTAL_SIZE, metavar="SIZE"
    )
    ssh_command.add_argument("--max-files", type=_file_count, default=DEFAULT_MAX_FILES)
    ssh_command.add_argument("--timeout", type=_positive_timeout, default=10)
    ssh_command.add_argument("--output", type=Path, default=Path("reports"))
    ssh_command.add_argument("--retain-evidence", action="store_true")
    return parser


def _print_run(completed: CompletedRun) -> None:
    report = completed.report
    print("Detection Goggles")
    print(f"Pack:      {report['pack']['id']} {report['pack']['version']}")
    print(f"Artifacts: {report['summary']['artifact_count']}")
    print()
    for evaluation in report["evaluations"]:
        subjects = ",".join(evaluation["subject_ids"]) or "bundle"
        print(f"{evaluation['rule_id']:<12} {evaluation['status'].upper():<15} {subjects}")
    print()
    print(f"Findings:  {report['summary']['finding_count']}")
    preferred_report = completed.report_directory / "report.md"
    if not preferred_report.is_file():
        preferred_report = completed.report_directory / "report.json"
    print(f"Report:    {preferred_report}")
    if report["summary"]["acquisition_issue_count"]:
        print(f"Warning:   {report['summary']['acquisition_issue_count']} acquisition issue(s)")


def _roots(arguments: argparse.Namespace) -> tuple[Path, ...]:
    return default_pack_roots(arguments.pack_root)


def _dispatch(arguments: argparse.Namespace) -> int:
    roots = _roots(arguments)
    if arguments.command == "pack":
        if arguments.pack_action == "list":
            packs = discover_packs(roots)
            if not packs:
                print("No Detection Packs found.")
                return 0
            print(f"{'PACK':<38} {'VERSION':<12} {'SOURCES':<20} PATH")
            for pack in packs:
                sources = ",".join(pack.manifest["capabilities"]["sources"])
                print(f"{pack.id:<38} {pack.version:<12} {sources:<20} {pack.path}")
            return 0
        if arguments.pack_action == "available":
            registry = load_registry(arguments.registry)
            print(f"{'PACK':<38} {'VERSION':<12} PLATFORM")
            for entry in registry["packs"]:
                print(f"{entry['id']:<38} {entry['version']:<12} {entry['platform']}")
            return 0
        if arguments.pack_action == "validate":
            pack = resolve_pack(arguments.pack, roots)
            print(f"Valid: {pack.id} {pack.version} ({len(pack.rules)} detections)")
            return 0
        if arguments.pack_action == "build":
            pack = resolve_pack(arguments.pack, roots)
            archive, digest = build_pack_archive(pack, arguments.output)
            print(f"Built:  {archive}")
            print(f"SHA256: {digest}")
            return 0
        if arguments.pack_action == "verify":
            registry = load_registry(arguments.registry)
            entry = verify_registry_archive(arguments.archive, registry)
            print(f"Verified: {entry['id']} {entry['version']} ({entry['sha256']})")
            return 0
        if arguments.pack_action == "install":
            local_archive = Path(arguments.reference).expanduser()
            if local_archive.exists():
                if arguments.sha256 is None:
                    raise DacError(
                        "Installing a local pack archive requires --sha256; "
                        "use `dacctl pack build` to obtain its digest"
                    )
                pack = install_pack_archive(
                    local_archive,
                    arguments.destination_root,
                    expected_sha256=arguments.sha256,
                )
            else:
                if arguments.sha256 is not None:
                    raise DacError("--sha256 applies only to a local archive")
                if "/" in arguments.reference or arguments.reference.endswith(".tar.gz"):
                    raise DacError(f"Local pack archive does not exist: {local_archive}")
                pack = install_registry_pack(
                    arguments.reference,
                    registry_source=arguments.registry,
                    destination_root=arguments.destination_root,
                )
            print(f"Installed: {pack.id} {pack.version} at {pack.path}")
            return 0

    if arguments.command == "run":
        pack = resolve_pack(arguments.pack, roots)
        if arguments.run_source == "files":
            completed = run_files(
                pack,
                arguments.paths,
                output_root=arguments.output,
                recursive=arguments.recursive,
                follow_symlinks=arguments.follow_symlinks,
                max_file_size=arguments.max_file_size,
                max_total_size=arguments.max_total_size,
                max_files=arguments.max_files,
                timeout_seconds=arguments.timeout,
                retain_evidence=arguments.retain_evidence,
            )
        elif arguments.run_source == "evidence":
            completed = run_evidence(
                pack,
                arguments.bundle,
                output_root=arguments.output,
                max_file_size=arguments.max_file_size,
                max_total_size=arguments.max_total_size,
                max_files=arguments.max_files,
                timeout_seconds=arguments.timeout,
                retain_evidence=arguments.retain_evidence,
            )
        elif arguments.run_source in {"ssh", "host"}:
            completed = run_ssh(
                pack,
                arguments.remote_files,
                SshOptions(
                    host=arguments.host,
                    user=arguments.user,
                    port=arguments.port,
                    identity=arguments.identity,
                    ask_pass=arguments.ask_pass,
                    become=arguments.become,
                    ask_become_pass=arguments.ask_become_pass,
                    host_key_policy=arguments.host_key_policy,
                    connection_timeout=arguments.connection_timeout,
                    acquisition_timeout=arguments.acquisition_timeout,
                ),
                output_root=arguments.output,
                max_file_size=arguments.max_file_size,
                max_total_size=arguments.max_total_size,
                max_files=arguments.max_files,
                timeout_seconds=arguments.timeout,
                retain_evidence=arguments.retain_evidence,
            )
        else:
            raise DacError(f"Unsupported run source: {arguments.run_source}")
        _print_run(completed)
        return completed.exit_code

    raise DacError("Unsupported command")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        return _dispatch(arguments)
    except DacError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: operating-system failure: {exc}", file=sys.stderr)
        return 2
