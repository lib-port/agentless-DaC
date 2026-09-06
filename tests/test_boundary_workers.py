"""Host-safe boundary tests: all transport and worker operations are mocked."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from detection_goggles import download_worker, launcher, target_worker
from detection_goggles.errors import DacError


@pytest.mark.parametrize(
    "url",
    ("http://example.invalid/file", "file:///etc/passwd", "https://user:password@example.invalid/"),
)
def test_downloads_refuse_unsafe_schemes_and_url_credentials(url):
    with pytest.raises(DacError, match="credential-free HTTPS"):
        download_worker._url(url)


def test_https_redirect_cannot_downgrade_or_add_credentials():
    request = urllib.request.Request("https://example.invalid/pack")
    handler = download_worker._Redirect()
    for location in ("http://example.invalid/pack", "https://user:secret@example.invalid/pack"):
        with pytest.raises(DacError, match="credential-free HTTPS"):
            handler.redirect_request(request, None, 302, "Found", {}, location)


def test_askpass_secret_is_private_not_in_environment_and_removed_on_failure(tmp_path):
    phrase = "synthetic test passphrase"
    with (
        pytest.raises(RuntimeError, match="simulated failure"),
        target_worker._askpass(tmp_path, phrase) as environment,
    ):
        secret = Path(environment["DAC_PASSPHRASE_FILE"])
        assert secret.read_text() == phrase + "\n"
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600
        assert phrase not in environment.values()
        raise RuntimeError("simulated failure")
    assert not (tmp_path / "passphrase").exists()


@pytest.mark.parametrize("failure", (None, "rejected", "timeout"))
def test_local_agent_and_temporary_passphrase_are_removed_for_every_outcome(
    monkeypatch,
    tmp_path,
    failure,
):
    """No SSH process is started; the fake process records lifecycle and arguments."""
    identity = tmp_path / "identity"
    identity.write_text("inert identity placeholder")
    monkeypatch.setattr(target_worker, "_guard", lambda roles: None)
    monkeypatch.setattr(target_worker, "_auth_root", lambda: tmp_path)
    phrase = "synthetic unlock phrase"
    monkeypatch.setattr(target_worker, "_passphrase", lambda prompt: phrase)
    calls = []

    class Agent:
        terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

    agent = Agent()

    def start(arguments, **kwargs):
        assert arguments[:2] == ["ssh-agent", "-D"]
        Path(arguments[arguments.index("-a") + 1]).touch()
        return agent

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        assert phrase not in arguments
        assert phrase not in kwargs["env"].values()
        if arguments[0] == "ssh-keygen":
            return SimpleNamespace(returncode=1)
        secret = Path(kwargs["env"]["DAC_PASSPHRASE_FILE"])
        assert secret.read_text() == phrase + "\n"
        assert kwargs["env"]["DAC_ASKPASS_ONCE"] == "1"
        if failure == "timeout":
            raise subprocess.TimeoutExpired(arguments, 120)
        return SimpleNamespace(returncode=1 if failure == "rejected" else 0)

    monkeypatch.setattr(target_worker.subprocess, "Popen", start)
    monkeypatch.setattr(target_worker.subprocess, "run", run)
    if failure is None:
        with target_worker.unlocked_identity(identity) as socket:
            assert Path(socket).exists()
            assert not agent.terminated
    else:
        expected = DacError if failure == "rejected" else subprocess.TimeoutExpired
        with pytest.raises(expected), target_worker.unlocked_identity(identity):
            pytest.fail("unlock failure must not yield an agent")
    assert agent.terminated
    assert [arguments[0] for arguments, _ in calls] == ["ssh-keygen", "ssh-add"]
    assert list(tmp_path.iterdir()) == [identity]


def test_host_key_pin_mismatch_fails_without_accepting_scanned_key(monkeypatch, tmp_path):
    calls = []

    def run(arguments, **kwargs):
        calls.append(arguments)
        if arguments[0] == "ssh-keyscan":
            return SimpleNamespace(returncode=0, stdout=b"192.0.2.7 ssh-ed25519 AAAA\n")
        return SimpleNamespace(returncode=0, stdout=b"256 SHA256:wrong host (ED25519)\n")

    monkeypatch.setattr(target_worker.subprocess, "run", run)
    with pytest.raises(DacError, match="independently obtained fingerprint"):
        target_worker._host_key(
            {"host": "192.0.2.7", "port": 22, "fingerprint": "SHA256:expected"},
            tmp_path,
        )
    assert [arguments[0] for arguments in calls] == ["ssh-keyscan", "ssh-keygen"]


@contextmanager
def _pipe_input(monkeypatch, data):
    read_descriptor, write_descriptor = os.pipe()
    try:
        os.write(write_descriptor, data)
    finally:
        os.close(write_descriptor)
    with os.fdopen(read_descriptor, "r", encoding="utf-8") as stream:
        monkeypatch.setattr(target_worker.sys, "stdin", stream)
        yield read_descriptor


def test_non_tty_passphrase_reader_rejects_missing_and_oversized_input(monkeypatch):
    for data in (b"", b"x" * 4097):
        with _pipe_input(monkeypatch, data), pytest.raises(DacError):
            target_worker._passphrase("Test prompt: ")


def test_unlock_prompt_does_not_prefetch_a_later_become_password(monkeypatch):
    with _pipe_input(monkeypatch, b"unlock phrase\nbecome password\n") as descriptor:
        assert target_worker._passphrase("Test prompt: ") == "unlock phrase"
        assert os.read(descriptor, 100) == b"become password\n"


@pytest.mark.parametrize("phrase", ("\x00", "bad\rphrase", "bad\nphrase", "é" * 512))
def test_askpass_rejects_values_openssh_would_truncate(tmp_path, phrase):
    with pytest.raises(DacError), target_worker._askpass(tmp_path, phrase):
        pytest.fail("The truncated passphrase must not reach OpenSSH")
    assert not list(tmp_path.iterdir())


def test_failed_state_write_leaves_no_partial_record(monkeypatch, tmp_path):
    final = tmp_path / "record.json"
    monkeypatch.setattr(launcher, "_record_path", lambda kind, identifier: final)

    def fail_write(value, handle, **kwargs):
        handle.write('{"volume":')
        raise OSError("synthetic write failure")

    monkeypatch.setattr(launcher.json, "dump", fail_write)
    with pytest.raises(OSError, match="synthetic write failure"):
        launcher._write_record("targets", "lab", {"volume": "example"})
    assert not list(tmp_path.iterdir())


def test_atomic_state_publish_never_replaces_an_existing_record(monkeypatch, tmp_path):
    final = tmp_path / "record.json"
    final.write_text('{"existing": true}')
    monkeypatch.setattr(launcher, "_record_path", lambda kind, identifier: final)
    with pytest.raises(FileExistsError):
        launcher._write_record("targets", "lab", {"replacement": True})
    assert final.read_text() == '{"existing": true}'
    assert list(tmp_path.iterdir()) == [final]


@pytest.mark.container
def test_unlock_askpass_consumes_the_phrase_once(monkeypatch, capfd):
    """Use only an inert phrase in the test container's private authentication tmpfs."""
    monkeypatch.setattr(target_worker, "_guard", lambda roles: None)
    with (
        tempfile.TemporaryDirectory(prefix="askpass-test-", dir="/run/dac-auth") as temporary,
        target_worker._askpass(Path(temporary), "inert test phrase", consume=True) as environment,
    ):
        for name, value in environment.items():
            monkeypatch.setenv(name, value)
        assert target_worker.askpass() == 0
        assert capfd.readouterr().out == "inert test phrase\n"
        assert not Path(environment["DAC_PASSPHRASE_FILE"]).exists()
        assert target_worker.askpass() == 2
        assert capfd.readouterr().out == ""


@pytest.mark.parametrize(
    "exception",
    ("subprocess.TimeoutExpired(['ssh-keyscan'], 30)", "HTTPException('invalid response')"),
)
def test_worker_normalises_subprocess_and_http_failures_into_one_json_object(tmp_path, exception):
    """A mocked handler only raises; it cannot acquire files or execute detections."""
    request = tmp_path / "request.json"
    request.write_text("{}")
    script = f"""
import subprocess
from http.client import HTTPException
from pathlib import Path
from detection_goggles import worker
worker.require_container = lambda: {{}}
worker.REQUEST_PATH = Path({str(request)!r})
def fail(_request):
    raise {exception}
worker.handle = fail
raise SystemExit(worker.main())
"""
    process = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
    )
    assert process.returncode == 2
    result = json.loads(process.stdout)
    assert result["exit_code"] == 2
    assert "Worker operation failed" in result["error"]
    assert "Traceback" not in process.stderr
