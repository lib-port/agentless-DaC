"""The former host dispatch tests now exercise the guarded worker protocol."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from detection_goggles import worker
from detection_goggles.errors import ContractError
from detection_goggles.packs import default_pack_roots, resolve_pack

pytestmark = pytest.mark.container


@pytest.fixture
def worker_paths(monkeypatch, tmp_path):
    source = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    inputs = tmp_path / "inputs"
    output = tmp_path / "output"
    inputs.mkdir()
    output.mkdir()
    monkeypatch.setattr(worker, "INPUT_ROOT", inputs)
    monkeypatch.setattr(worker, "OUTPUT_ROOT", output)
    monkeypatch.setattr(worker, "PACK_ROOT", source.path.parent)
    monkeypatch.setattr(worker, "INSTALLED_PACK_ROOT", tmp_path / "installed")
    return inputs, output


def test_pack_list(worker_paths):
    result = worker.handle({"op": "pack", "action": "list"})
    assert result["exit_code"] == 0
    assert [pack["id"] for pack in result["packs"]] == ["htb-malevolent-modmaker"]


def test_pack_available_from_local_registry(worker_paths):
    inputs, _ = worker_paths
    registry = inputs / "registry.yml"
    registry.write_bytes(Path("registry/packs.yml").read_bytes())
    result = worker.handle({"op": "pack", "action": "available", "registry": str(registry)})
    assert result["exit_code"] == 0
    assert result["packs"][0]["id"] == "htb-malevolent-modmaker"


def test_local_pack_install_requires_a_digest(worker_paths):
    inputs, _ = worker_paths
    archive = inputs / "pack.tar.gz"
    archive.write_bytes(b"placeholder")
    with pytest.raises(ContractError, match="expected SHA-256"):
        worker.handle({"op": "pack", "action": "install", "archive": str(archive)})


def test_import_preserves_original_display_path(worker_paths):
    inputs, output = worker_paths
    clean = inputs / "0"
    clean.write_text("clean", encoding="utf-8")
    result = worker.handle(
        {
            "op": "import_files",
            "inputs": [{"path": str(clean), "display_path": "case/clean.txt"}],
        }
    )
    manifest = json.loads((output / "evidence" / "manifest.json").read_text())
    assert result["exit_code"] == 0
    assert manifest["artifacts"][0]["display_path"] == "case/clean.txt"
    assert manifest["source"]["inputs"] == ["case/clean.txt"]


def test_import_refuses_unmounted_host_paths(worker_paths):
    with pytest.raises(ContractError, match="outside the operation"):
        worker.handle(
            {
                "op": "import_files",
                "inputs": [{"path": "/etc/passwd", "display_path": "bad"}],
            }
        )


def test_worker_has_no_arbitrary_attribute_dispatch():
    with pytest.raises(ContractError, match="Unsupported worker operation"):
        worker.handle({"op": "__import__", "module": "os"})


def test_input_symlink_cannot_expand_the_selected_boundary(worker_paths):
    inputs, output = worker_paths
    selected = inputs / "chosen"
    selected.mkdir()
    (selected / "clean.txt").write_text("clean")
    outside = inputs / "not-selected.txt"
    outside.write_text("not selected")
    (selected / "escape.txt").symlink_to(outside)
    result = worker.handle(
        {
            "op": "import_files",
            "recursive": True,
            "follow_symlinks": True,
            "inputs": [{"path": str(selected), "display_path": "chosen"}],
        }
    )
    assert result["exit_code"] == 2
    assert result["artifact_count"] == 1
    assert result["acquisition_issues"][0]["code"] == "symlink_rejected"
    assert len(list((output / "evidence" / "artifacts").iterdir())) == 1


def test_report_export_rejects_links_and_traversal(monkeypatch, tmp_path):
    root = tmp_path / "reports"
    run = root / "run-12345678"
    run.mkdir(parents=True)
    outside = tmp_path / "secret"
    outside.write_text("secret")
    (run / "report.json").symlink_to(outside)
    monkeypatch.setattr(worker, "REPORT_ROOT", root)
    with pytest.raises(OSError):
        worker.handle({"op": "export_reports", "run_id": run.name, "formats": ["json"]})
    with pytest.raises(ContractError, match="Invalid report run ID"):
        worker.handle({"op": "export_reports", "run_id": "../secret", "formats": ["json"]})
    with pytest.raises(ContractError, match="Only JSON and Markdown"):
        worker.handle({"op": "export_reports", "run_id": run.name, "formats": ["evidence"]})


def test_report_export_returns_only_selected_rendered_files(monkeypatch, tmp_path):
    root = tmp_path / "reports"
    run = root / "run-12345678"
    run.mkdir(parents=True)
    (run / "report.json").write_text('{"value": "safe"}\n')
    monkeypatch.setattr(worker, "REPORT_ROOT", root)
    assert worker.handle({"op": "export_reports", "run_id": run.name, "formats": ["json"]}) == {
        "exit_code": 0,
        "files": {"report.json": '{"value": "safe"}\n'},
    }


def test_fifo_report_is_rejected_without_waiting_for_a_writer(tmp_path):
    root = tmp_path / "reports"
    run = root / "run-12345678"
    run.mkdir(parents=True)
    os.mkfifo(run / "report.json")
    script = f"""
from pathlib import Path
from detection_goggles import worker
from detection_goggles.errors import ContractError
worker.REPORT_ROOT = Path({str(root)!r})
try:
    worker.handle({{'op': 'export_reports', 'run_id': {run.name!r}, 'formats': ['json']}})
except ContractError as error:
    print(error)
    raise SystemExit(0)
raise SystemExit(1)
"""
    process = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert process.returncode == 0
    assert "regular file" in process.stdout


@pytest.mark.parametrize("extra", ("extra.txt", "evidence", "report.md"))
def test_report_export_rejects_unexpected_files_and_directories(monkeypatch, tmp_path, extra):
    root = tmp_path / "reports"
    run = root / "run-12345678"
    run.mkdir(parents=True)
    (run / "report.json").write_text("{}")
    if extra == "evidence":
        (run / extra).mkdir()
    else:
        (run / extra).write_text("unexpected")
    monkeypatch.setattr(worker, "REPORT_ROOT", root)
    with pytest.raises(ContractError, match="unexpected entries"):
        worker.handle({"op": "export_reports", "run_id": run.name, "formats": ["json"]})


def test_report_export_rejects_preexisting_hard_links(monkeypatch, tmp_path):
    root = tmp_path / "reports"
    run = root / "run-12345678"
    run.mkdir(parents=True)
    report = run / "report.json"
    report.write_text("{}")
    os.link(report, tmp_path / "second-name")
    monkeypatch.setattr(worker, "REPORT_ROOT", root)
    with pytest.raises(ContractError, match="exactly one hard link"):
        worker.handle({"op": "export_reports", "run_id": run.name, "formats": ["json"]})


@pytest.mark.parametrize("mutation", ("link", "permissions"))
def test_report_export_rejects_metadata_changes_during_read(monkeypatch, tmp_path, mutation):
    root = tmp_path / "reports"
    run = root / "run-12345678"
    run.mkdir(parents=True)
    report = run / "report.json"
    report.write_text("{}")
    monkeypatch.setattr(worker, "REPORT_ROOT", root)
    original_read = worker.os.read
    changed = False

    def read_and_change(descriptor, size):
        nonlocal changed
        data = original_read(descriptor, size)
        if not changed and Path(f"/proc/self/fd/{descriptor}").resolve() == report.resolve():
            changed = True
            if mutation == "link":
                os.link(report, tmp_path / "second-name")
            else:
                report.chmod(0o400)
        return data

    monkeypatch.setattr(worker.os, "read", read_and_change)
    with pytest.raises(ContractError, match="changed while it was exported"):
        worker.handle({"op": "export_reports", "run_id": run.name, "formats": ["json"]})
    assert changed
