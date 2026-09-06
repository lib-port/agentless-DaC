"""Isolated Detection Pack execution."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any

from detection_goggles.errors import ContractError
from detection_goggles.evidence import EvidenceBundle, new_run_id
from detection_goggles.models import DetectionRun, Pack, Rule
from detection_goggles.runtime_guard import require_container
from detection_goggles.schema import validate

ALLOWED_STATUSES = {"detected", "not_detected", "unknown", "not_applicable"}
DEFAULT_TIMEOUT_SECONDS = 10
MAX_OUTPUT_BYTES = 1024 * 1024


def _identifier(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _resource_limits(timeout_seconds: int) -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (timeout_seconds + 1, timeout_seconds + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES * 2, MAX_OUTPUT_BYTES * 2))
        address_space = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    except (ImportError, OSError, ValueError):
        return


def _detector_environment(scratch: Path) -> dict[str, str]:
    environment = {
        "HOME": str(scratch),
        "TMPDIR": str(scratch),
        "TEMP": str(scratch),
        "TMP": str(scratch),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    for name in ("SystemRoot", "WINDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    process.wait()


def _terminate_remaining_group(process: subprocess.Popen[bytes]) -> None:
    if os.name != "posix":
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _read_limited(handle: Any, limit: int) -> bytes:
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size > limit:
        raise ContractError(f"Detector output exceeded {limit} bytes")
    handle.seek(0)
    return handle.read(limit + 1)


def _run_subprocess(
    script: Path,
    request: dict[str, Any],
    *,
    timeout_seconds: int,
) -> tuple[dict[str, Any], int]:
    require_container("analyse", "test")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="dac-detector-") as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o700)
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                [sys.executable, "-I", str(script)],
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
                cwd=scratch,
                env=_detector_environment(scratch),
                start_new_session=(os.name == "posix"),
                preexec_fn=(
                    (lambda: _resource_limits(timeout_seconds)) if os.name == "posix" else None
                ),
            )
            payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
            try:
                process.communicate(input=payload, timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                _terminate(process)
                raise ContractError(f"Detector timed out after {timeout_seconds} seconds") from exc
            except BaseException:
                _terminate(process)
                raise
            _terminate_remaining_group(process)

            duration_ms = max(0, round((time.monotonic() - started) * 1000))
            if process.returncode != 0:
                raise ContractError(f"Detector exited with status {process.returncode}")

            raw = _read_limited(stdout, MAX_OUTPUT_BYTES)
            try:
                result = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                raise ContractError("Detector did not return one valid UTF-8 JSON object") from exc
            validate(result, "detector-output.schema.json", label=f"output from {script}")
            return result, duration_ms


def _artifact_request(
    bundle: EvidenceBundle, artifacts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    request_artifacts: list[dict[str, Any]] = []
    for artifact in artifacts:
        request_artifacts.append(
            {
                "id": artifact["id"],
                "kind": artifact["kind"],
                "display_path": artifact["display_path"],
                "size": artifact["size"],
                "sha256": artifact["sha256"],
                "media_type": artifact["media_type"],
                "content_path": str(bundle.artifact_path(artifact)),
            }
        )
    return request_artifacts


def _finding(rule: Rule, match: dict[str, Any], allowed_ids: set[str]) -> dict[str, Any]:
    subject_ids = match["subject_ids"]
    referenced = set(subject_ids)
    referenced.update(item["artifact_id"] for item in match["evidence"])
    referenced.update(item["artifact_id"] for item in match.get("locations", []))
    unknown = referenced - allowed_ids
    if unknown:
        rendered_unknown = ", ".join(sorted(unknown))
        raise ContractError(
            f"Detector {rule.id} referenced artifacts outside its input: {rendered_unknown}"
        )
    finding = {
        "id": _identifier("finding"),
        "rule_id": rule.id,
        "title": rule.metadata["title"],
        "severity": rule.metadata["severity"],
        "confidence": rule.metadata["confidence"],
        "subjects": [{"kind": "file", "artifact_id": item} for item in subject_ids],
        "summary": match["summary"],
        "evidence": match["evidence"],
        "locations": match.get("locations", []),
        "mitre_attack": rule.metadata.get("mitre_attack", {}),
    }
    validate(finding, "finding.schema.json", label=f"finding from {rule.id}")
    return finding


def _evaluate_once(
    rule: Rule,
    bundle: EvidenceBundle,
    artifacts: list[dict[str, Any]],
    *,
    timeout_cap: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    evaluation_id = _identifier("eval")
    input_ids = [artifact["id"] for artifact in artifacts]
    started = time.monotonic()

    try:
        entrypoint = rule.path / rule.implementation["entrypoint"]
        timeout = min(
            int(rule.implementation.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)), timeout_cap
        )
        request = {
            "protocol_version": 1,
            "rule": {"id": rule.id},
            "artifacts": _artifact_request(bundle, artifacts),
        }
        output, duration_ms = _run_subprocess(entrypoint, request, timeout_seconds=timeout)
        status = output["status"]
        if status not in ALLOWED_STATUSES:
            raise ContractError(f"Detector returned unsupported status: {status}")
        findings = [_finding(rule, match, set(input_ids)) for match in output["matches"]]
        subject_ids = (
            sorted({subject for match in output["matches"] for subject in match["subject_ids"]})
            or input_ids
        )
        evaluation: dict[str, Any] = {
            "id": evaluation_id,
            "rule_id": rule.id,
            "status": status,
            "subject_ids": subject_ids,
            "finding_ids": [finding["id"] for finding in findings],
            "duration_ms": duration_ms,
        }
        if output.get("reason"):
            evaluation["reason"] = output["reason"]
    except ContractError as exc:
        duration_ms = max(0, round((time.monotonic() - started) * 1000))
        findings = []
        evaluation = {
            "id": evaluation_id,
            "rule_id": rule.id,
            "status": "error",
            "subject_ids": input_ids,
            "finding_ids": [],
            "duration_ms": duration_ms,
            "reason": str(exc)[:1000],
        }
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        duration_ms = max(0, round((time.monotonic() - started) * 1000))
        findings = []
        evaluation = {
            "id": evaluation_id,
            "rule_id": rule.id,
            "status": "error",
            "subject_ids": input_ids,
            "finding_ids": [],
            "duration_ms": duration_ms,
            "reason": f"Detector execution failed: {type(exc).__name__}",
        }

    validate(evaluation, "evaluation.schema.json", label=f"evaluation for {rule.id}")
    return evaluation, findings


def evaluate(
    pack: Pack,
    bundle: EvidenceBundle,
    *,
    timeout_cap: int = DEFAULT_TIMEOUT_SECONDS,
    replay: bool = False,
) -> DetectionRun:
    require_container("analyse", "test")
    if timeout_cap < 1:
        raise ContractError("Detector timeout cap must be positive")
    bundle.verify()
    evaluations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = bundle.manifest["artifacts"]

    for rule in pack.rules:
        scope = rule.implementation["scope"]
        if not artifacts:
            evaluation = {
                "id": _identifier("eval"),
                "rule_id": rule.id,
                "status": "not_applicable",
                "subject_ids": [],
                "finding_ids": [],
                "duration_ms": 0,
                "reason": "No acquired file artifacts were available",
            }
            validate(evaluation, "evaluation.schema.json")
            evaluations.append(evaluation)
            continue

        batches = [[artifact] for artifact in artifacts] if scope == "artifact" else [artifacts]
        for batch in batches:
            evaluation, new_findings = _evaluate_once(
                rule,
                bundle,
                batch,
                timeout_cap=timeout_cap,
            )
            evaluations.append(evaluation)
            findings.extend(new_findings)

    return DetectionRun(
        run_id=new_run_id("eval") if replay else bundle.manifest["run_id"],
        evidence_run_id=bundle.manifest["run_id"],
        evaluations=tuple(evaluations),
        findings=tuple(findings),
    )
