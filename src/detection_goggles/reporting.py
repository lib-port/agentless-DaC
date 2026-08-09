"""Minimal JSON and Markdown reporting."""

from __future__ import annotations

import html
import json
import os
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from detection_goggles.errors import ContractError
from detection_goggles.evidence import EvidenceBundle, retain_evidence, utc_now
from detection_goggles.models import DetectionRun, Pack
from detection_goggles.schema import validate


def build_report(pack: Pack, bundle: EvidenceBundle, run: DetectionRun) -> dict[str, Any]:
    statuses = Counter(evaluation["status"] for evaluation in run.evaluations)
    run_metadata = {
        "id": run.run_id,
        "evidence_run_id": run.evidence_run_id,
        "evaluated_at": utc_now(),
        "source": bundle.manifest["source"]["type"],
    }
    if bundle.manifest["source"].get("target"):
        run_metadata["target"] = bundle.manifest["source"]["target"]
    report = {
        "schema_version": 1,
        "run": {
            **run_metadata,
            "mode": "replay" if run.run_id != run.evidence_run_id else "acquisition",
        },
        "pack": {
            "id": pack.id,
            "name": pack.name,
            "version": pack.version,
        },
        "summary": {
            "artifact_count": len(bundle.manifest["artifacts"]),
            "evaluation_count": len(run.evaluations),
            "finding_count": len(run.findings),
            "acquisition_issue_count": len(bundle.manifest["acquisition_issues"]),
            "statuses": dict(sorted(statuses.items())),
        },
        "artifacts": [
            {
                key: artifact[key]
                for key in ("id", "kind", "display_path", "size", "sha256", "media_type")
            }
            for artifact in bundle.manifest["artifacts"]
        ],
        "acquisition_issues": bundle.manifest["acquisition_issues"],
        "evaluations": list(run.evaluations),
        "findings": list(run.findings),
    }
    validate(report, "report.schema.json", label="generated report")
    return report


def _safe(value: Any) -> str:
    return (
        html.escape(str(value), quote=True)
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("|", "&#124;")
        .replace("`", "&#96;")
    )


def _markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    pack = report["pack"]
    run = report["run"]
    lines = [
        "# Detection Goggles report",
        "",
        f"- Run: `{_safe(run['id'])}`",
        f"- Evidence run: `{_safe(run['evidence_run_id'])}`",
        f"- Pack: `{_safe(pack['id'])}` {_safe(pack['version'])}",
        f"- Source: `{_safe(run['source'])}`",
        f"- Mode: `{_safe(run['mode'])}`",
        f"- Artifacts: {summary['artifact_count']}",
        f"- Findings: {summary['finding_count']}",
        f"- Acquisition issues: {summary['acquisition_issue_count']}",
        "",
        "## Evaluations",
        "",
        "| Rule | Status | Subjects | Duration |",
        "| --- | --- | --- | ---: |",
    ]
    if run.get("target"):
        lines.insert(6, f"- Target: `{_safe(run['target'])}`")
    for evaluation in report["evaluations"]:
        subjects = ", ".join(evaluation["subject_ids"]) or "—"
        lines.append(
            f"| `{_safe(evaluation['rule_id'])}` | `{_safe(evaluation['status'])}` | "
            f"{_safe(subjects)} | {evaluation['duration_ms']} ms |"
        )
        if evaluation.get("reason"):
            lines.extend(["", f"> {_safe(evaluation['reason'])}", ""])

    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.extend(["No detections matched.", ""])
    else:
        artifact_paths = {item["id"]: item["display_path"] for item in report["artifacts"]}
        for finding in report["findings"]:
            subjects = ", ".join(
                f"`{_safe(artifact_paths.get(item['artifact_id'], item['artifact_id']))}`"
                for item in finding["subjects"]
            )
            lines.extend(
                [
                    f"### {_safe(finding['rule_id'])}: {_safe(finding['title'])}",
                    "",
                    f"- Severity: `{_safe(finding['severity'])}`",
                    f"- Confidence: `{_safe(finding['confidence'])}`",
                    f"- Subjects: {subjects}",
                    "",
                    _safe(finding["summary"]),
                    "",
                ]
            )
            if finding["evidence"]:
                lines.extend(["Evidence:", ""])
                for item in finding["evidence"]:
                    lines.append(
                        f"- `{_safe(item['artifact_id'])}` {_safe(item['type'])}: "
                        f"`{_safe(item['value'])}`"
                    )
                lines.append("")

    if report["acquisition_issues"]:
        lines.extend(["## Acquisition issues", ""])
        for issue in report["acquisition_issues"]:
            lines.append(
                f"- `{_safe(issue['code'])}` `{_safe(issue['path'])}`: {_safe(issue['message'])}"
            )
        lines.append("")
    return "\n".join(lines)


def _exclusive_text(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def write_report(
    report: dict[str, Any],
    output_root: Path,
    *,
    formats: Iterable[str] = ("json", "markdown"),
    bundle: EvidenceBundle | None = None,
    retain: bool = False,
) -> Path:
    selected_formats = tuple(dict.fromkeys(formats))
    unsupported = set(selected_formats) - {"json", "markdown"}
    if not selected_formats or unsupported:
        rendered = ", ".join(sorted(unsupported)) or "<none>"
        raise ContractError(f"Unsupported or empty report format selection: {rendered}")
    validate(report, "report.schema.json", label="report output")

    output_root = output_root.expanduser()
    if output_root.is_symlink():
        raise ContractError(f"Output root may not be a symbolic link: {output_root}")
    try:
        output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise ContractError(f"Cannot prepare report output root {output_root}: {exc}") from exc
    run_directory = output_root / report["run"]["id"]
    try:
        run_directory.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ContractError(
            f"Refusing to overwrite existing report directory: {run_directory}"
        ) from exc

    try:
        if "json" in selected_formats:
            _exclusive_text(
                run_directory / "report.json",
                json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            )
        if "markdown" in selected_formats:
            _exclusive_text(run_directory / "report.md", _markdown(report))
        if retain:
            if bundle is None:
                raise ContractError("Cannot retain evidence without an evidence bundle")
            retain_evidence(bundle, run_directory)
    except Exception:
        # Leave any partial, owner-only report directory for forensic troubleshooting.
        raise
    return run_directory
