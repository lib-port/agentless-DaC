from __future__ import annotations

import json
import runpy
import termios
from pathlib import Path

import pytest

from detection_goggles.errors import DacError
from detection_goggles.podman import Mount, Podman, _quiet_terminal, _target


def test_build_snapshot_excludes_arbitrary_root_files_and_evidence(tmp_path: Path) -> None:
    stage = runpy.run_path(str(Path(__file__).parents[1] / "containers" / "build.py"))["stage"]
    source = tmp_path / "repository"
    destination = tmp_path / "staged"
    source.mkdir()
    destination.mkdir()
    names = ["pyproject.toml", "src/module.py", "private-key", "evidence/secret", ".vagrant/key"]
    for name in names:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture", encoding="utf-8")
    stage.__globals__["ROOT"] = source
    stage.__globals__["command"] = lambda args: (
        "\x00".join(names) + "\x00" if "ls-files" in args else "fixture-commit"
    )
    result = stage(destination)
    assert result["file_count"] == 2
    assert {
        str(path.relative_to(destination)) for path in destination.rglob("*") if path.is_file()
    } == {
        "pyproject.toml",
        "src/module.py",
    }


def _firewall_fixture() -> list[dict]:
    entries = [{"table": {"family": "inet", "name": "dac_filter"}}]
    for name in ("input", "output", "forward"):
        entries.append(
            {
                "chain": {
                    "family": "inet",
                    "table": "dac_filter",
                    "name": name,
                    "type": "filter",
                    "hook": name,
                    "prio": 0,
                    "policy": "drop",
                }
            }
        )
    for name, prefix, states in (
        ("input", "s", "established"),
        ("output", "d", ["new", "established"]),
    ):
        expressions = [
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": protocol, "field": field}},
                    "right": value,
                }
            }
            for protocol, field, value in (
                ("ip", prefix + "addr", "192.0.2.10"),
                ("tcp", prefix + "port", 22),
            )
        ]
        expressions.extend(
            [
                {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": states}},
                {"accept": None},
            ]
        )
        entries.append(
            {
                "rule": {
                    "family": "inet",
                    "table": "dac_filter",
                    "chain": name,
                    "expr": expressions,
                }
            }
        )
    return entries


@pytest.mark.parametrize("mutation", ["extra-state", "wrong-operator", "missing-ct", "wrong-table"])
def test_firewall_readback_rejects_weakened_state_rules(mutation: str) -> None:
    verify = runpy.run_path(str(Path(__file__).parents[1] / "containers" / "network_init.py"))[
        "verify_ruleset"
    ]
    rules = _firewall_fixture()
    verify(rules, "192.0.2.10", 22)
    inbound = rules[4]["rule"]
    state = inbound["expr"][2]["match"]
    if mutation == "extra-state":
        state["right"] = ["established", "new"]
    elif mutation == "wrong-operator":
        state["op"] = "!="
    elif mutation == "missing-ct":
        state["left"] = {"ct": {"key": "mark"}}
    else:
        inbound["table"] = "other_table"
    with pytest.raises(RuntimeError):
        verify(rules, "192.0.2.10", 22)


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.1.2", "::1", "0.0.0.0", "224.0.0.1"])
def test_target_policy_rejects_local_helpers_and_non_unicast_addresses(
    address: str,
) -> None:
    with pytest.raises(DacError):
        _target({"host": address, "port": 22, "fingerprint": "SHA256:" + "A" * 43})


def test_target_policy_rejects_boolean_ports() -> None:
    with pytest.raises(DacError):
        _target({"host": "192.0.2.10", "port": True, "fingerprint": "SHA256:" + "A" * 43})


def test_failed_network_initialisation_cannot_yield_a_collector_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = Podman()
    commands = []
    monkeypatch.setattr(driver, "preflight", lambda: None)
    monkeypatch.setattr(driver, "_command", lambda args: commands.append(args) or "pod-id")
    monkeypatch.setattr(driver, "_pod_state", lambda pod: {"namespace": "original"})

    def fail_setup(pod: str, target: dict) -> None:
        raise DacError("Injected policy installation failure")

    monkeypatch.setattr(driver, "_network_helper", fail_setup)
    with (
        pytest.raises(DacError, match="installation failure"),
        driver.acquisition_pod(
            {"host": "192.0.2.10", "port": 22, "fingerprint": "SHA256:" + "A" * 43}
        ),
    ):
        pytest.fail("The collector was authorised after failed setup")
    assert commands[-1] == ["pod", "rm", "--force", "pod-id"]
    assert not driver._seals


def test_restarted_namespace_invalidates_existing_seal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = Podman()
    driver._seals["pod-id"] = {
        "state": {"namespace": "original"},
        "target": {"host": "192.0.2.10", "port": 22},
    }
    monkeypatch.setattr(driver, "preflight", lambda: None)
    monkeypatch.setattr(driver, "_pod_state", lambda pod: {"namespace": "replacement"})
    with pytest.raises(DacError, match="restarted"):
        driver.run("acquire", {}, [], pod="pod-id")


def test_acquisition_without_a_sealed_namespace_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = Podman()
    monkeypatch.setattr(driver, "preflight", lambda: None)
    with pytest.raises(DacError, match="newly sealed"):
        driver.run("acquire", {}, [])


def test_analysis_cannot_join_an_acquisition_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = Podman()
    monkeypatch.setattr(driver, "preflight", lambda: None)
    with pytest.raises(DacError, match="Only acquisition"):
        driver.run("analyse", {}, [], pod="pod-id")


def test_host_mounts_are_readonly_and_explicit(tmp_path: Path) -> None:
    source = tmp_path / "sample"
    source.write_text("artifact", encoding="utf-8")
    driver = Podman()
    with pytest.raises(DacError, match="read-only"):
        driver._mount(Mount(str(source), "/inputs/sample", read_only=False, kind="bind"))
    with pytest.raises(DacError, match="Unsafe"):
        driver._mount(Mount(str(source), "/run/dac/policy.json", kind="bind"))
    assert "ro=true" in driver._mount(Mount(str(source), "/inputs/sample", kind="bind"))


def test_host_agent_socket_directory_and_ancestors_cannot_be_mounted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_directory = tmp_path / "agent" / "private"
    socket_directory.mkdir(parents=True)
    monkeypatch.setenv("SSH_AUTH_SOCK", str(socket_directory / "agent.socket"))
    driver = Podman()
    for source in (tmp_path, socket_directory.parent, socket_directory):
        with pytest.raises(DacError, match="storage directories"):
            driver._mount(Mount(str(source), "/inputs/0", kind="bind"))
    explicit_file = socket_directory / "selected-key"
    explicit_file.write_text("fixture-only selected key", encoding="utf-8")
    assert "ro=true" in driver._mount(Mount(str(explicit_file), "/inputs/0", kind="bind"))


def test_existing_foreign_volumes_cannot_be_adopted_or_deleted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = Podman()
    monkeypatch.setattr(driver, "preflight", lambda: None)
    monkeypatch.setattr(driver, "_json", lambda args: [{"Labels": {}}])
    with pytest.raises(DacError, match="not owned"):
        driver.volume_create("dac-existing")
    with pytest.raises(DacError, match="not owned"):
        driver.volume_remove("dac-existing")


def test_driver_rejects_multiple_management_json_documents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = Podman()
    monkeypatch.setattr(driver, "_command", lambda args: json.dumps({}) + json.dumps({}))
    with pytest.raises(DacError, match="malformed"):
        driver._json(["info"])


def test_terminal_echo_is_restored_after_an_interrupted_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import detection_goggles.podman as module

    class Terminal:
        def isatty(self) -> bool:
            return True

        def fileno(self) -> int:
            return 7

    original = [
        0,
        0,
        0,
        termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG,
        0,
        0,
        [],
    ]
    changes = []
    monkeypatch.setattr(module.sys, "stdin", Terminal())
    monkeypatch.setattr(module.termios, "tcgetattr", lambda descriptor: original)
    monkeypatch.setattr(module.termios, "tcsetattr", lambda fd, when, value: changes.append(value))
    with pytest.raises(KeyboardInterrupt), _quiet_terminal(True):
        assert changes[-1][3] & (termios.ECHO | termios.ECHONL) == 0
        assert changes[-1][3] & (termios.ICANON | termios.ISIG) == termios.ICANON | termios.ISIG
        raise KeyboardInterrupt
    assert changes[-1] == original
