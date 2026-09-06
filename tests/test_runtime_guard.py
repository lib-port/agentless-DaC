"""Host denial and kernel-policy regression checks; no detector runs on the host."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from detection_goggles import engine, runner
from detection_goggles.errors import ContractError
from detection_goggles.runtime_guard import require_container


@pytest.mark.host_only
def test_environment_marker_cannot_enable_host_execution(monkeypatch):
    monkeypatch.setenv("DAC_IN_CONTAINER", "1")
    monkeypatch.setenv("container", "podman")
    with pytest.raises(ContractError, match="verified rootless Podman runtime"):
        require_container("analyse")


@pytest.mark.host_only
def test_worker_on_host_returns_one_clean_error_object():
    process = subprocess.run(
        [sys.executable, "-m", "detection_goggles.worker"],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
    )
    assert process.returncode == 2
    result = json.loads(process.stdout)
    assert result["exit_code"] == 2
    assert "Podman runtime" in result["error"]
    assert "Traceback" not in process.stderr


@pytest.mark.host_only
def test_direct_runner_and_engine_fail_before_accessing_evidence(tmp_path):
    for operation in (
        lambda: runner.run_files(None, [], output_root=tmp_path),
        lambda: runner.run_evidence(None, tmp_path, output_root=tmp_path),
        lambda: engine.evaluate(None, None),
        lambda: engine._run_subprocess(tmp_path / "absent.py", {}, timeout_seconds=1),
    ):
        with pytest.raises(ContractError, match="verified rootless Podman runtime"):
            operation()
    assert not list(tmp_path.iterdir())


@pytest.mark.host_only
@pytest.mark.parametrize("rule_id", ("MMM-001", "MMM-002", "MMM-003"))
def test_shipped_rule_entrypoint_rejects_host_before_reading_stdin(rule_id):
    script = (
        Path(__file__).resolve().parents[1]
        / "packs"
        / "htb-malevolent-modmaker"
        / "detections"
        / rule_id
        / "detect.py"
    )
    specification = importlib.util.spec_from_file_location("guarded_rule", script)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    with pytest.raises(ContractError, match="verified rootless Podman runtime"):
        module.main()


@pytest.mark.container
def test_test_runtime_has_real_kernel_limits_and_no_network():
    policy = require_container("test")
    assert policy["network"] == "none"
    assert policy["rootless"] is True


@pytest.mark.container
def test_test_runtime_cannot_execute_network_worker_roles():
    for role in ("acquire", "download", "target"):
        with pytest.raises(ContractError, match="operation is forbidden"):
            require_container(role)
