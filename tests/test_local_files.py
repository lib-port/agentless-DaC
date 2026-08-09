from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import detection_goggles.evidence as evidence_module
from detection_goggles.errors import AcquisitionError, ContractError
from detection_goggles.evidence import load_evidence_bundle
from detection_goggles.packs import default_pack_roots, resolve_pack
from detection_goggles.runner import run_evidence, run_files
from tests.helpers import malevolent_profile_files


@pytest.fixture
def pack():
    return resolve_pack("htb-malevolent-modmaker", default_pack_roots())


def test_clean_file_has_no_findings(pack, tmp_path: Path) -> None:
    clean = tmp_path / "clean.txt"
    clean.write_text("ordinary configuration content\n", encoding="utf-8")

    completed = run_files(pack, [clean], output_root=tmp_path / "reports")

    assert completed.exit_code == 0
    assert not completed.detection_run.findings
    assert {item["status"] for item in completed.detection_run.evaluations} == {"not_detected"}
    assert (completed.report_directory / "report.json").is_file()
    assert (completed.report_directory / "report.md").is_file()
    assert not (completed.report_directory / "evidence").exists()


def test_synthetic_chain_triggers_all_three_rules_without_modifying_inputs(
    pack, tmp_path: Path
) -> None:
    ransomware, loader = malevolent_profile_files(tmp_path)
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (ransomware, loader)}

    completed = run_files(
        pack,
        [ransomware, loader],
        output_root=tmp_path / "reports",
        retain_evidence=True,
    )

    assert completed.exit_code == 1
    assert {finding["rule_id"] for finding in completed.detection_run.findings} == {
        "MMM-001",
        "MMM-002",
        "MMM-003",
    }
    assert before == {
        path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (ransomware, loader)
    }
    evidence = completed.report_directory / "evidence"
    assert (evidence / "manifest.json").is_file()
    assert len(list((evidence / "artifacts").iterdir())) == 2


def test_retained_evidence_can_be_replayed(pack, tmp_path: Path) -> None:
    ransomware, loader = malevolent_profile_files(tmp_path)
    first = run_files(
        pack,
        [ransomware, loader],
        output_root=tmp_path / "first",
        retain_evidence=True,
    )

    replay = run_evidence(
        pack,
        first.report_directory / "evidence",
        output_root=tmp_path / "replay",
    )

    assert replay.exit_code == 1
    assert replay.detection_run.run_id != replay.detection_run.evidence_run_id
    assert replay.report["run"]["mode"] == "replay"
    assert {finding["rule_id"] for finding in replay.detection_run.findings} == {
        "MMM-001",
        "MMM-002",
        "MMM-003",
    }


def test_rejected_symlink_is_an_explicit_partial_run(pack, tmp_path: Path) -> None:
    clean = tmp_path / "clean.txt"
    clean.write_text("clean", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(clean)

    completed = run_files(pack, [clean, link], output_root=tmp_path / "reports")

    assert completed.exit_code == 2
    assert completed.report["acquisition_issues"][0]["code"] == "symlink_rejected"


def test_no_acquired_artifacts_is_an_operational_error(pack, tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"

    with pytest.raises(AcquisitionError, match="No regular file artifacts"):
        run_files(pack, [missing], output_root=tmp_path / "reports")


def test_tampered_retained_artifact_is_rejected(pack, tmp_path: Path) -> None:
    ransomware, _ = malevolent_profile_files(tmp_path)
    completed = run_files(
        pack,
        [ransomware],
        output_root=tmp_path / "reports",
        retain_evidence=True,
    )
    evidence = completed.report_directory / "evidence"
    artifact = next((evidence / "artifacts").iterdir())
    artifact.chmod(0o600)
    artifact.write_bytes(b"tampered")

    with pytest.raises(ContractError, match="integrity check failed"):
        load_evidence_bundle(evidence)


def test_replay_rejects_actual_size_mismatch_before_reading(
    pack, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ransomware, _ = malevolent_profile_files(tmp_path)
    completed = run_files(
        pack,
        [ransomware],
        output_root=tmp_path / "reports",
        retain_evidence=True,
    )
    evidence = completed.report_directory / "evidence"
    manifest_path = evidence / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["size"] = 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def unexpected_read(*args: object, **kwargs: object) -> bytes:
        pytest.fail("artifact content was read after the size mismatch")

    monkeypatch.setattr(evidence_module.os, "read", unexpected_read)
    with pytest.raises(ContractError, match="integrity check failed"):
        load_evidence_bundle(evidence)


def test_replay_enforces_operator_file_count_limit(pack, tmp_path: Path) -> None:
    ransomware, loader = malevolent_profile_files(tmp_path)
    completed = run_files(
        pack,
        [ransomware, loader],
        output_root=tmp_path / "reports",
        retain_evidence=True,
    )

    with pytest.raises(ContractError, match="contains 2 artifacts; limit is 1"):
        run_evidence(
            pack,
            completed.report_directory / "evidence",
            output_root=tmp_path / "replay",
            max_files=1,
        )
