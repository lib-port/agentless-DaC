"""High-level orchestration shared by the CLI and tests."""

from __future__ import annotations

import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from detection_goggles.engine import DEFAULT_TIMEOUT_SECONDS, evaluate
from detection_goggles.errors import AcquisitionError, DacError
from detection_goggles.evidence import (
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_TOTAL_SIZE,
    LocalEvidenceWorkspace,
    load_evidence_bundle,
)
from detection_goggles.evidence import (
    retain_evidence as snapshot_evidence,
)
from detection_goggles.models import DetectionRun, Pack
from detection_goggles.packs import ensure_source_supported
from detection_goggles.reporting import build_report, write_report
from detection_goggles.runtime_guard import require_container
from detection_goggles.ssh_source import SshOptions


@dataclass(frozen=True)
class CompletedRun:
    report: dict[str, Any]
    report_directory: Path
    detection_run: DetectionRun

    @property
    def exit_code(self) -> int:
        has_operational_problem = bool(self.report["acquisition_issues"]) or any(
            evaluation["status"] in {"error", "unknown"}
            for evaluation in self.detection_run.evaluations
        )
        if has_operational_problem:
            return 2
        if self.detection_run.findings:
            return 1
        return 0


def run_files(
    pack: Pack,
    paths: Iterable[Path],
    *,
    output_root: Path,
    recursive: bool = False,
    follow_symlinks: bool = False,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    retain_evidence: bool = False,
) -> CompletedRun:
    require_container("analyse", "test")
    ensure_source_supported(pack, "files")
    with LocalEvidenceWorkspace(
        paths,
        recursive=recursive,
        follow_symlinks=follow_symlinks,
        max_file_size=max_file_size,
        max_total_size=max_total_size,
        max_files=max_files,
    ) as bundle:
        if not bundle.manifest["artifacts"]:
            raise AcquisitionError("No regular file artifacts were acquired")
        detection_run = evaluate(pack, bundle, timeout_cap=timeout_seconds)
        report = build_report(pack, bundle, detection_run)
        report_directory = write_report(
            report,
            output_root,
            formats=pack.manifest["reporting"]["formats"],
            bundle=bundle,
            retain=retain_evidence,
        )
    return CompletedRun(report, report_directory, detection_run)


def run_ssh(
    pack: Pack,
    remote_paths: Iterable[str],
    options: SshOptions,
    *,
    output_root: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    retain_evidence: bool = False,
) -> CompletedRun:
    """Reject the former combined network-acquisition and detection API."""

    raise DacError(
        "SSH acquisition and detection require separate Podman roles; "
        "use `dacctl run ssh` through the host launcher"
    )


def run_evidence(
    pack: Pack,
    evidence_path: Path,
    *,
    output_root: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    retain_evidence: bool = False,
) -> CompletedRun:
    require_container("analyse", "test")
    ensure_source_supported(pack, "evidence")
    bundle = load_evidence_bundle(
        evidence_path,
        max_file_size=max_file_size,
        max_total_size=max_total_size,
        max_files=max_files,
    )
    if not bundle.manifest["artifacts"]:
        raise AcquisitionError("Evidence bundle contains no file artifacts")
    with tempfile.TemporaryDirectory(prefix="dac-replay-") as temporary:
        staging_root = Path(temporary)
        staging_root.chmod(0o700)
        staged_path = snapshot_evidence(
            bundle,
            staging_root,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            max_files=max_files,
        )
        staged_bundle = load_evidence_bundle(
            staged_path,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            max_files=max_files,
        )
        detection_run = evaluate(pack, staged_bundle, timeout_cap=timeout_seconds, replay=True)
        report = build_report(pack, staged_bundle, detection_run)
        report_directory = write_report(
            report,
            output_root,
            formats=pack.manifest["reporting"]["formats"],
            bundle=staged_bundle,
            retain=retain_evidence,
        )
    return CompletedRun(report, report_directory, detection_run)
