from __future__ import annotations

import json
from pathlib import Path

import pytest

import detection_goggles.ssh_source as ssh_source
from detection_goggles.errors import AcquisitionError, ContractError
from detection_goggles.packs import default_pack_roots, resolve_pack
from detection_goggles.runner import run_ssh
from detection_goggles.ssh_source import SshOptions
from tests.helpers import malevolent_profile_files


@pytest.fixture
def pack():
    return resolve_pack("htb-malevolent-modmaker", default_pack_roots())


def _fake_ansible(
    monkeypatch: pytest.MonkeyPatch,
    payloads: dict[str, bytes | None],
    captured: dict[str, object] | None = None,
    *,
    fetch_failures: set[str] | None = None,
) -> None:
    monkeypatch.setattr(ssh_source.shutil, "which", lambda _: "/test/ansible-playbook")

    def invoke(
        command: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> int:
        variables_reference = command[command.index("--extra-vars") + 1]
        variables = json.loads(Path(variables_reference.removeprefix("@")).read_text())
        inventory_path = Path(command[command.index("--inventory") + 1])
        inventory = json.loads(inventory_path.read_text())
        if captured is not None:
            captured.update(
                {
                    "command": command,
                    "environment": environment,
                    "inventory": inventory,
                    "acquisition_timeout": timeout_seconds,
                }
            )

        fetched = Path(variables["dac_local_staging"])
        statuses = Path(variables["dac_status_staging"])
        for item in variables["dac_remote_files"]:
            payload = payloads.get(item["path"])
            status = {
                "exists": payload is not None,
                "is_regular": payload is not None,
                "is_link": False,
                "failed": False,
                "size": len(payload) if payload is not None else 0,
                "modified_ns": 1_700_000_000_000_000_000,
            }
            (statuses / f"{item['id']}.json").write_text(json.dumps(status), encoding="utf-8")
            if payload is not None:
                (fetched / item["id"]).write_bytes(payload)
                fetch_status = {"failed": item["path"] in (fetch_failures or set())}
                (statuses / f"{item['id']}.fetch.json").write_text(
                    json.dumps(fetch_status), encoding="utf-8"
                )
        return 0

    monkeypatch.setattr(ssh_source, "_invoke_ansible", invoke)


def test_ssh_fetches_named_files_then_detects_locally(
    pack, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ransomware, loader = malevolent_profile_files(tmp_path)
    remote_payloads = {
        "/opt/lab/ransomware.bin": ransomware.read_bytes(),
        "/opt/lab/loader.bin": loader.read_bytes(),
    }
    captured: dict[str, object] = {}
    _fake_ansible(monkeypatch, remote_payloads, captured)

    completed = run_ssh(
        pack,
        remote_payloads,
        SshOptions(host="10.10.10.10", user="htb"),
        output_root=tmp_path / "reports",
        retain_evidence=True,
    )

    assert completed.exit_code == 1
    assert completed.report["run"]["source"] == "ssh"
    assert completed.report["run"]["target"] == "10.10.10.10:22"
    retained_manifest = json.loads(
        (completed.report_directory / "evidence" / "manifest.json").read_text()
    )
    assert retained_manifest["source"]["type"] == "ssh"
    assert {finding["rule_id"] for finding in completed.detection_run.findings} == {
        "MMM-001",
        "MMM-002",
        "MMM-003",
    }
    assert all(
        artifact["display_path"].startswith("10.10.10.10:22:/opt/lab/")
        for artifact in completed.report["artifacts"]
    )
    host_vars = captured["inventory"]["all"]["hosts"]["dac_target"]  # type: ignore[index]
    assert "ansible_password" not in host_vars
    assert "ansible_ssh_common_args" not in host_vars
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert not any(name.startswith("ANSIBLE_PASSWORD") for name in environment)
    assert captured["command"].count("--timeout") == 1  # type: ignore[union-attr]
    assert captured["acquisition_timeout"] == 600


def test_ssh_missing_remote_file_makes_a_partial_run(
    pack, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}
    _fake_ansible(
        monkeypatch,
        {"/opt/lab/clean.txt": b"clean", "/missing.bin": None},
        captured,
    )

    completed = run_ssh(
        pack,
        ["/opt/lab/clean.txt", "/missing.bin"],
        SshOptions(host="lab.example", user="analyst", host_key_policy="accept-new"),
        output_root=tmp_path / "reports",
    )

    assert completed.exit_code == 2
    assert completed.report["acquisition_issues"] == [
        {
            "path": "/missing.bin",
            "code": "not_found",
            "message": "Remote path does not exist",
        }
    ]
    host_vars = captured["inventory"]["all"]["hosts"]["dac_target"]  # type: ignore[index]
    assert host_vars["ansible_ssh_common_args"] == "-o StrictHostKeyChecking=accept-new"


def test_ssh_requires_optional_ansible_dependency(
    pack, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ssh_source.shutil, "which", lambda _: None)

    with pytest.raises(AcquisitionError, match="optional dependency"):
        run_ssh(
            pack,
            ["/opt/lab/sample.bin"],
            SshOptions(host="10.10.10.10", user="htb"),
            output_root=tmp_path / "reports",
        )


def test_ssh_rejects_relative_and_duplicate_paths(pack, tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="absolute"):
        run_ssh(
            pack,
            ["relative.bin"],
            SshOptions(host="10.10.10.10", user="htb"),
            output_root=tmp_path / "reports",
        )

    with pytest.raises(ContractError, match="Duplicate"):
        run_ssh(
            pack,
            ["/sample.bin", "/sample.bin"],
            SshOptions(host="10.10.10.10", user="htb"),
            output_root=tmp_path / "reports",
        )


def test_failed_fetch_is_not_accepted_when_a_residual_file_exists(
    pack, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _fake_ansible(
        monkeypatch,
        {"/opt/lab/good.txt": b"clean", "/opt/lab/changed.bin": b"partial"},
        fetch_failures={"/opt/lab/changed.bin"},
    )

    completed = run_ssh(
        pack,
        ["/opt/lab/good.txt", "/opt/lab/changed.bin"],
        SshOptions(host="lab.example", user="analyst"),
        output_root=tmp_path / "reports",
    )

    assert completed.exit_code == 2
    assert completed.report["summary"]["artifact_count"] == 1
    assert completed.report["acquisition_issues"] == [
        {
            "path": "/opt/lab/changed.bin",
            "code": "io_error",
            "message": "Remote file fetch failed integrity checks",
        }
    ]


def test_ansible_process_group_is_terminated_at_acquisition_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class TimedOutProcess:
        pid = 424242

        def __init__(self) -> None:
            self.waits = 0

        def wait(self, timeout: int | None = None) -> int:
            if self.waits == 0:
                self.waits += 1
                raise ssh_source.subprocess.TimeoutExpired(["ansible-playbook"], timeout)
            return -9

        def poll(self) -> None:
            return None

    process = TimedOutProcess()
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(ssh_source.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        ssh_source.os,
        "killpg",
        lambda process_id, signal_number: killed.append((process_id, signal_number)),
    )

    with pytest.raises(AcquisitionError, match="timed out after 17 seconds"):
        ssh_source._invoke_ansible(
            ["ansible-playbook"],
            cwd=tmp_path,
            environment={},
            timeout_seconds=17,
        )

    assert killed == [(process.pid, ssh_source.signal.SIGKILL)]
