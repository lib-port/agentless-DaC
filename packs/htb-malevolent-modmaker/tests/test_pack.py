"""Self-contained contract tests shipped with the Detection Pack."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from detection_goggles.errors import ContractError
from detection_goggles.packs import load_pack
from detection_goggles.runner import run_files
from detection_goggles.runtime_guard import require_container

PACK_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _verified_test_runtime():
    try:
        require_container("test")
    except ContractError:
        pytest.skip("Run pack tests inside the verified Podman test image")


def _pe_shaped_bytes(*markers: bytes) -> bytes:
    """Return inert test bytes with PE headers and searchable marker strings."""

    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    return bytes(data) + b"\0".join(markers)


def test_clean_fixture_does_not_match(tmp_path: Path) -> None:
    pack = load_pack(PACK_ROOT)

    completed = run_files(
        pack,
        [PACK_ROOT / "tests" / "fixtures" / "clean.txt"],
        output_root=tmp_path / "reports",
    )

    assert completed.exit_code == 0
    assert not completed.detection_run.findings


def test_synthetic_behavior_chain_matches_all_rules(tmp_path: Path) -> None:
    pack = load_pack(PACK_ROOT)
    ransomware = tmp_path / "synthetic-ransomware-profile.bin"
    ransomware.write_bytes(
        _pe_shaped_bytes(
            b"Go build ID:",
            b"runtime.goexit",
            b"crypto/aes",
            b"cipher.NewGCM",
            b"os.ReadFile",
            b"os.WriteFile",
            b"filepath.Walk",
        )
    )
    loader = tmp_path / "synthetic-loader-profile.bin"
    loader.write_bytes(
        _pe_shaped_bytes(
            b"Go build ID:",
            b"net/http",
            b"https://download.invalid/payload",
            b"os/exec",
            b"exec.Command",
        )
    )

    completed = run_files(
        pack,
        [ransomware, loader],
        output_root=tmp_path / "reports",
    )

    assert completed.exit_code == 1
    assert {finding["rule_id"] for finding in completed.detection_run.findings} == {
        "MMM-001",
        "MMM-002",
        "MMM-003",
    }
    loader_finding = next(
        finding for finding in completed.detection_run.findings if finding["rule_id"] == "MMM-002"
    )
    rendered_evidence = " ".join(item["value"] for item in loader_finding["evidence"])
    assert "https://download.invalid" in rendered_evidence
    assert "/payload" not in rendered_evidence


def test_correlation_requires_distinct_artifacts(tmp_path: Path) -> None:
    pack = load_pack(PACK_ROOT)
    combined = tmp_path / "combined-profile.bin"
    combined.write_bytes(
        _pe_shaped_bytes(
            b"Go build ID:",
            b"crypto/aes",
            b"cipher.NewGCM",
            b"os.ReadFile",
            b"os.WriteFile",
            b"net/http",
            b"os/exec",
        )
    )

    completed = run_files(pack, [combined], output_root=tmp_path / "reports")

    assert {finding["rule_id"] for finding in completed.detection_run.findings} == {
        "MMM-001",
        "MMM-002",
    }


def test_correlation_uses_the_same_loader_profile_as_component_rule(tmp_path: Path) -> None:
    pack = load_pack(PACK_ROOT)
    ransomware = tmp_path / "ransomware.bin"
    ransomware.write_bytes(
        _pe_shaped_bytes(
            b"Go build ID:",
            b"crypto/aes",
            b"cipher.NewGCM",
            b"os.ReadFile",
            b"os.WriteFile",
        )
    )
    loader = tmp_path / "loader.bin"
    loader.write_bytes(_pe_shaped_bytes(b"net/http", b"os/exec", b"AmsiScanBuffer"))

    completed = run_files(pack, [ransomware, loader], output_root=tmp_path / "reports")

    assert {finding["rule_id"] for finding in completed.detection_run.findings} == {
        "MMM-001",
        "MMM-002",
        "MMM-003",
    }


def test_contained_file_operation_name_is_counted_once(tmp_path: Path) -> None:
    pack = load_pack(PACK_ROOT)
    sample = tmp_path / "single-operation.bin"
    sample.write_bytes(
        _pe_shaped_bytes(b"Go build ID:", b"crypto/aes", b"cipher.NewGCM", b"os.RemoveAll")
    )

    completed = run_files(pack, [sample], output_root=tmp_path / "reports")

    assert "MMM-001" not in {finding["rule_id"] for finding in completed.detection_run.findings}
