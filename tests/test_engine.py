from __future__ import annotations

import copy
from pathlib import Path

import pytest

from detection_goggles.models import Pack, Rule
from detection_goggles.packs import default_pack_roots, resolve_pack
from detection_goggles.runner import run_files

pytestmark = pytest.mark.container


def _pack_with_script(tmp_path: Path, source: str) -> Pack:
    original = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    rule_directory = tmp_path / "rule"
    rule_directory.mkdir()
    (rule_directory / "detect.py").write_text(source, encoding="utf-8")
    metadata = copy.deepcopy(original.rules[0].metadata)
    metadata["implementation"]["timeout_seconds"] = 1
    return Pack(
        path=tmp_path,
        manifest=copy.deepcopy(original.manifest),
        rules=(Rule(path=rule_directory, metadata=metadata),),
    )


def test_detector_timeout_becomes_an_error_evaluation(tmp_path: Path) -> None:
    pack = _pack_with_script(
        tmp_path,
        "import time\ntime.sleep(5)\n",
    )
    sample = tmp_path / "sample.txt"
    sample.write_text("safe", encoding="utf-8")

    completed = run_files(pack, [sample], output_root=tmp_path / "reports", timeout_seconds=1)

    evaluation = completed.detection_run.evaluations[0]
    assert completed.exit_code == 2
    assert evaluation["status"] == "error"
    assert "timed out" in evaluation["reason"]


def test_caller_environment_is_not_inherited_by_detector(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DAC_TEST_SECRET", "must-not-reach-detector")
    pack = _pack_with_script(
        tmp_path,
        """
import json
import os
import sys

if os.environ.get("DAC_TEST_SECRET"):
    raise SystemExit(9)
json.dump({"status": "not_detected", "matches": []}, sys.stdout)
""",
    )
    sample = tmp_path / "sample.txt"
    sample.write_text("safe", encoding="utf-8")

    completed = run_files(pack, [sample], output_root=tmp_path / "reports")

    assert completed.exit_code == 0
    assert completed.detection_run.evaluations[0]["status"] == "not_detected"


def test_detector_stderr_is_not_copied_into_report(tmp_path: Path) -> None:
    secret = "synthetic-secret-that-must-not-be-reported"
    pack = _pack_with_script(
        tmp_path,
        f"import sys\nsys.stderr.write({secret!r})\nraise SystemExit(3)\n",
    )
    sample = tmp_path / "sample.txt"
    sample.write_text("safe", encoding="utf-8")

    completed = run_files(pack, [sample], output_root=tmp_path / "reports")

    assert completed.exit_code == 2
    assert secret not in (completed.report_directory / "report.json").read_text(encoding="utf-8")


def test_pack_report_format_declaration_controls_output(tmp_path: Path) -> None:
    pack = _pack_with_script(
        tmp_path,
        "import json, sys\njson.dump({'status': 'not_detected', 'matches': []}, sys.stdout)\n",
    )
    pack.manifest["reporting"]["formats"] = ["json"]
    sample = tmp_path / "sample.txt"
    sample.write_text("safe", encoding="utf-8")

    completed = run_files(pack, [sample], output_root=tmp_path / "reports")

    assert (completed.report_directory / "report.json").is_file()
    assert not (completed.report_directory / "report.md").exists()
