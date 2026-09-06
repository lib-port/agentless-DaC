"""Host orchestration tests do not execute detectors or parse evidence."""

from __future__ import annotations

import json
from contextlib import contextmanager

import pytest

from detection_goggles import cli, launcher
from detection_goggles.errors import DacError


class FakePodman:
    def __init__(self):
        self.events = []
        self.existing = set()
        self.result_code = 0

    def preflight(self):
        self.events.append(("preflight",))

    def volume_create(self, name):
        self.existing.add(name)

    def volume_remove(self, name):
        self.events.append(("remove", name))
        self.existing.discard(name)

    @contextmanager
    def acquisition_pod(self, target):
        self.events.append(("seal", target))
        try:
            yield "sealed-pod"
        finally:
            self.events.append(("unseal",))

    def run(self, role, request, mounts, **kwargs):
        self.events.append((role, request, mounts, kwargs))
        if request["op"].startswith("import_") or request["op"] == "acquire":
            return {"exit_code": 0, "artifact_count": 1, "run_id": "run-original-evidence"}
        if request["op"] == "analyse":
            return {
                "exit_code": self.result_code,
                "run_id": "run-test-12345678",
                "formats": ["json", "markdown"],
                "summary": {"finding_count": 1},
            }
        if request["op"] == "export_reports":
            return {"exit_code": 0, "files": {"report.json": "{}\n", "report.md": "Report\n"}}
        if request["op"] == "target_init":
            return {"exit_code": 0, "public_key": "ssh-ed25519 synthetic-public-key"}
        return {"exit_code": 0, "message": "OK"}


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    fake = FakePodman()
    monkeypatch.setattr(launcher, "Podman", lambda: fake)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("DAC_PACK_PATH", raising=False)
    return fake


def test_launcher_refuses_missing_runtime_without_host_fallback(monkeypatch, capsys):
    class Missing:
        def preflight(self):
            raise DacError("Rootless Podman is required")

    monkeypatch.setattr(launcher, "Podman", Missing)
    assert cli.main(["pack", "list"]) == 2
    assert "Rootless Podman" in capsys.readouterr().err


def test_files_are_imported_before_offline_analysis_and_reports_exported(runtime, tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("inert fixture")
    output = tmp_path / "reports"
    runtime.result_code = 1
    assert cli.main(["run", "files", "example-pack", str(sample), "--output", str(output)]) == 1
    roles = [item[0] for item in runtime.events]
    assert roles[:5] == ["preflight", "manage", "import", "analyse", "export"]
    analysis = next(item for item in runtime.events if item[0] == "analyse")
    assert all(m.kind == "volume" for m in analysis[2])
    assert next(m for m in analysis[2] if m.target == "/evidence").read_only
    assert (output / "run-test-12345678/report.md").is_file()
    assert runtime.existing == {"dac-installed-packs"}


def test_ssh_credentials_and_pod_are_absent_from_analysis(runtime, tmp_path):
    target_volume = "dac-target-" + "a" * 32
    launcher._write_record(
        "targets",
        "lab",
        {
            "volume": target_volume,
            "host": "192.0.2.10",
            "port": 22,
            "fingerprint": "SHA256:" + "A" * 43,
        },
    )
    args = [
        "run",
        "ssh",
        "example-pack",
        "--target",
        "lab",
        "--user",
        "analyst",
        "--remote-file",
        "/sample",
        "--output",
        str(tmp_path / "reports"),
    ]
    assert cli.main(args) == 0
    roles = [item[0] for item in runtime.events]
    assert roles.index("acquire") < roles.index("unseal") < roles.index("analyse")
    analysis = next(item for item in runtime.events if item[0] == "analyse")
    assert all(m.source != target_volume for m in analysis[2])
    assert not analysis[3].get("pod")
    assert analysis[1]["replay"] is False


def test_retained_evidence_uses_managed_storage(runtime, tmp_path):
    sample = tmp_path / "sample"
    sample.write_text("inert")
    assert (
        cli.main(
            [
                "run",
                "files",
                "example-pack",
                str(sample),
                "--retain-evidence",
                "--output",
                str(tmp_path / "reports"),
            ]
        )
        == 0
    )
    record = launcher._read_record("evidence", "run-test-12345678")
    assert record["volume"] in runtime.existing
    assert not (tmp_path / "reports/run-test-12345678/evidence").exists()
    runtime.events.clear()
    assert (
        cli.main(
            [
                "run",
                "evidence",
                "example-pack",
                "--run-id",
                "run-test-12345678",
                "--output",
                str(tmp_path / "replayed"),
            ]
        )
        == 0
    )
    analysis = next(item for item in runtime.events if item[0] == "analyse")
    assert analysis[1]["replay"] is True


def test_operational_detection_errors_still_export_reports(runtime, tmp_path):
    runtime.result_code = 2
    sample = tmp_path / "sample"
    sample.write_text("inert")
    assert (
        cli.main(
            ["run", "files", "example-pack", str(sample), "--output", str(tmp_path / "reports")]
        )
        == 2
    )
    assert (tmp_path / "reports/run-test-12345678/report.json").is_file()


def test_report_export_rejects_traversal_and_existing_files(tmp_path):
    with pytest.raises(DacError, match="Invalid report"):
        launcher._export_files(tmp_path, {"../escape": "bad"}, reports=True)
    existing = tmp_path / "report.json"
    existing.write_text("keep")
    with pytest.raises(DacError, match="overwrite"):
        launcher._export_files(tmp_path, {"report.json": "replace"}, reports=True)
    assert existing.read_text() == "keep"


def test_evidence_removal_rejects_corrupted_volume_reference(runtime):
    path = launcher._record_path("evidence", "run-test-12345678")
    path.write_text(json.dumps({"volume": "unrelated-user-volume"}))
    path.chmod(0o600)
    assert cli.main(["evidence", "remove", "run-test-12345678"]) == 2
    assert not any(item[0] == "remove" for item in runtime.events)
