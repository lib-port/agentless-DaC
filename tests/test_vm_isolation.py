from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOST_SCRIPTS = tuple(sorted((ROOT / "scripts").glob("vm-*")))
GUEST_SCRIPTS = (
    ROOT / "vm" / "guest" / "dac-key-init",
    ROOT / "vm" / "provision" / "bootstrap.sh",
)


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _load_guest_exporter() -> ModuleType:
    path = ROOT / "vm" / "guest" / "dac_export_report.py"
    specification = importlib.util.spec_from_file_location("dac_export_report_test", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _load_vm_locks() -> ModuleType:
    path = ROOT / "scripts" / "vm_locks.py"
    specification = importlib.util.spec_from_file_location("vm_locks_test", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write_test_wheel(directory: Path, filename: str, project_name: str, version: str) -> Path:
    path = directory / filename
    metadata_root = f"{project_name.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr(
            f"{metadata_root}/METADATA",
            f"Metadata-Version: 2.1\nName: {project_name}\nVersion: {version}\n",
        )
        archive.writestr(f"{metadata_root}/WHEEL", "Wheel-Version: 1.0\n")
    return path


@pytest.mark.parametrize("script", (*HOST_SCRIPTS, *GUEST_SCRIPTS))
def test_vm_bash_scripts_are_syntactically_valid_and_executable(script: Path) -> None:
    assert os.access(script, os.X_OK)
    subprocess.run(["bash", "-n", str(script)], check=True)


def test_posix_dacctl_wrapper_is_syntactically_valid_and_executable() -> None:
    wrapper = ROOT / "vm" / "guest" / "dacctl"
    assert os.access(wrapper, os.X_OK)
    subprocess.run(["sh", "-n", str(wrapper)], check=True)


def test_vagrantfile_has_required_isolation_controls() -> None:
    vagrantfile = _text("Vagrantfile")
    assert 'controller.vm.box = "debian/bookworm64"' in vagrantfile
    assert 'controller.vm.box_version = "12.20260519.1"' in vagrantfile
    assert 'controller.vm.synced_folder ".", "/vagrant", disabled: true' in vagrantfile
    assert "controller.ssh.forward_agent = false" in vagrantfile
    assert "controller.ssh.forward_x11 = false" in vagrantfile
    assert 'libvirt.driver = "kvm"' in vagrantfile
    assert 'libvirt.system_uri = "qemu:///system"' in vagrantfile
    assert 'libvirt.management_network_mode = "nat"' in vagrantfile
    assert 'libvirt.management_network_guest_ipv6 = "no"' in vagrantfile
    assert 'libvirt.graphics_type = "none"' in vagrantfile
    assert 'controller.vm.network "public_network"' not in vagrantfile
    assert 'controller.vm.network "forwarded_port"' not in vagrantfile


def test_box_pin_is_consistent_and_checksum_is_exact() -> None:
    vagrantfile = _text("Vagrantfile")
    initializer = _text("scripts/vm-init")
    version = re.search(r'readonly BOX_VERSION="([^"]+)"', initializer)
    digest = re.search(r'readonly BOX_SHA256="([0-9a-f]+)"', initializer)
    assert version is not None
    assert digest is not None and len(digest.group(1)) == 64
    assert f'controller.vm.box_version = "{version.group(1)}"' in vagrantfile
    assert 'readonly VAGRANT_LIBVIRT_VERSION="0.12.2"' in initializer
    assert initializer.index("vagrant validate") < initializer.index("vagrant up controller")


def test_vagrant_and_host_baseline_are_exactly_enforced() -> None:
    vagrantfile = _text("Vagrantfile")
    initializer = _text("scripts/vm-init")
    assert 'Vagrant.require_version "= 2.3.4"' in vagrantfile
    assert 'readonly VAGRANT_VERSION="2.3.4"' in initializer
    assert 'installed_vagrant_version" == "$VAGRANT_VERSION' in initializer
    assert 'values.get("ID") != "debian"' in initializer
    assert 'values.get("VERSION_ID") != "12"' in initializer
    assert "systemd-detect-virt --quiet" in initializer
    assert "CPython 3.11 is required on the Debian 12 host" in initializer
    assert initializer.index("vagrant reload controller") < initializer.index(
        '"${SCRIPT_DIR}/vm-verify"'
    )


def test_vagrantfile_has_valid_ruby_syntax_when_ruby_is_available() -> None:
    ruby = shutil.which("ruby")
    if ruby is None:
        pytest.skip("Ruby is not installed")
    subprocess.run([ruby, "-c", str(ROOT / "Vagrantfile")], check=True)


@pytest.mark.parametrize("lock_name", ("vm.lock", "vm-runtime.lock"))
def test_vm_lock_is_fully_pinned_and_hashed(lock_name: str) -> None:
    lock_lines = _text(f"requirements/{lock_name}").splitlines()
    requirements = [
        line for line in lock_lines if line and not line[0].isspace() and line[0] != "#"
    ]
    assert requirements
    assert all(re.match(r"^[A-Za-z0-9_.-]+==[^ ]+ \\$", line) for line in requirements)

    hashes = [line.strip() for line in lock_lines if line.strip().startswith("--hash=")]
    assert len(hashes) == len(requirements)
    assert all(re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", line) for line in hashes)


def test_runtime_lock_excludes_validation_tooling() -> None:
    runtime_lock = _text("requirements/vm-runtime.lock").lower()
    for package in ("build==", "pytest==", "ruff==", "setuptools=="):
        assert package not in runtime_lock


def test_committed_vm_locks_satisfy_the_shared_contract() -> None:
    helper = _load_vm_locks()
    helper.validate_lock_contract(
        ROOT / "requirements" / "vm.lock",
        ROOT / "requirements" / "vm-runtime.lock",
    )


def test_vm_lock_roots_follow_project_extras() -> None:
    helper = _load_vm_locks()
    runtime = helper.project_roots(ROOT / "pyproject.toml", "runtime")
    validation = helper.project_roots(ROOT / "pyproject.toml", "validation")
    assert "ansible-core>=2.19,<2.22" in runtime
    assert not any(requirement.startswith("pytest") for requirement in runtime)
    assert set(runtime) < set(validation)
    assert any(requirement.startswith("pytest") for requirement in validation)
    assert any(requirement.startswith("ruff") for requirement in validation)


def test_vm_lock_generation_is_sorted_deterministic_and_hashes_wheels(tmp_path: Path) -> None:
    helper = _load_vm_locks()
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    zulu = _write_test_wheel(wheels, "zulu_pkg-2.0-py3-none-any.whl", "Zulu.Pkg", "2.0")
    alpha = _write_test_wheel(wheels, "alpha_pkg-1.0-py3-none-any.whl", "alpha_pkg", "1.0")
    first = tmp_path / "first.lock"
    second = tmp_path / "second.lock"

    helper.generate_lock(wheels, first, "runtime")
    helper.generate_lock(wheels, second, "runtime")

    assert first.read_bytes() == second.read_bytes()
    content = first.read_text(encoding="utf-8")
    assert content.index("alpha_pkg==1.0") < content.index("Zulu.Pkg==2.0")
    assert hashlib.sha256(alpha.read_bytes()).hexdigest() in content
    assert hashlib.sha256(zulu.read_bytes()).hexdigest() in content
    assert helper.read_lock(first) == ["alpha-pkg", "zulu-pkg"]


def test_vm_lock_generation_rejects_non_wheels_and_duplicate_projects(tmp_path: Path) -> None:
    helper = _load_vm_locks()
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    (wheels / "source.tar.gz").write_bytes(b"not a wheel")
    with pytest.raises(helper.LockError, match="non-wheel"):
        helper.generate_lock(wheels, tmp_path / "bad.lock", "runtime")

    (wheels / "source.tar.gz").unlink()
    _write_test_wheel(wheels, "one-1.0-py3-none-any.whl", "same-name", "1.0")
    _write_test_wheel(wheels, "two-1.0-py3-none-any.whl", "same_name", "1.0")
    with pytest.raises(helper.LockError, match="duplicate wheels"):
        helper.generate_lock(wheels, tmp_path / "duplicate.lock", "runtime")


def test_vm_lock_contract_rejects_malformed_hash(tmp_path: Path) -> None:
    helper = _load_vm_locks()
    lock = tmp_path / "bad.lock"
    lock.write_text("example==1.0 \\\n    --hash=sha256:not-a-digest\n", encoding="utf-8")
    with pytest.raises(helper.LockError, match="malformed wheel hash"):
        helper.read_lock(lock)


def test_vm_lock_contract_requires_identical_shared_pins(tmp_path: Path) -> None:
    helper = _load_vm_locks()
    validation = tmp_path / "validation.lock"
    runtime = tmp_path / "runtime.lock"
    validation.write_text(
        f"core==1.0 \\\n    --hash=sha256:{'a' * 64}\n"
        f"pytest==9.0 \\\n    --hash=sha256:{'b' * 64}\n",
        encoding="utf-8",
    )
    runtime.write_text(
        f"core==1.0 \\\n    --hash=sha256:{'c' * 64}\n",
        encoding="utf-8",
    )
    with pytest.raises(helper.LockError, match="disagree on shared pins"):
        helper.validate_lock_contract(validation, runtime)


def test_vm_lock_build_inputs_are_staged_without_repository_state(tmp_path: Path) -> None:
    helper = _load_vm_locks()
    staged = tmp_path / "staged"
    helper.copy_project_source(ROOT, staged)
    assert (staged / "pyproject.toml").read_bytes() == (ROOT / "pyproject.toml").read_bytes()
    assert (staged / "src" / "detection_goggles" / "cli.py").is_file()
    assert not list((staged / "src").glob("*.egg-info"))
    assert not list(staged.rglob("__pycache__"))
    assert not (staged / ".git").exists()
    assert not (staged / ".venv").exists()
    assert not (staged / "reports").exists()


def test_vm_lock_build_input_staging_rejects_links(tmp_path: Path) -> None:
    helper = _load_vm_locks()
    source = tmp_path / "source"
    source.mkdir()
    for filename in ("pyproject.toml", "README.md", "LICENSE"):
        (source / filename).write_text("placeholder", encoding="utf-8")
    (source / "src").mkdir()
    (source / "src" / "unsafe").symlink_to(source / "README.md")
    with pytest.raises(helper.LockError, match="contains a link"):
        helper.copy_project_source(source, tmp_path / "staged")


def test_vm_locks_failure_cleans_temporary_workspace(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    temporary_root = tmp_path / "temporary"
    fake_bin.mkdir()
    temporary_root.mkdir()
    fake_python = fake_bin / "python3"
    fake_python.write_text(
        "#!/bin/sh\nif [ \"${1:-}\" = -c ]; then printf '3.11\\n'; exit 0; fi\nexit 9\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    environment["TMPDIR"] = str(temporary_root)

    completed = subprocess.run(
        [str(ROOT / "scripts" / "vm-locks"), "update"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "could not read dependency roots" in completed.stderr
    assert list(temporary_root.iterdir()) == []


def test_vm_lock_command_uses_canonical_binary_only_index() -> None:
    script = _text("scripts/vm-locks")
    assert 'readonly PYPI_INDEX="https://pypi.org/simple"' in script
    assert "--isolated" in script
    assert "--only-binary=:all:" in script
    assert "--require-hashes" in script
    assert "trap cleanup EXIT" in script


def test_guest_firewall_is_default_deny_and_target_allowlisted() -> None:
    bootstrap = _text("vm/provision/bootstrap.sh")
    assert bootstrap.count("policy drop;") == 3
    assert "ip daddr ${TARGET_IP} tcp dport ${TARGET_PORT} accept" in bootstrap
    assert "systemctl enable --now nftables" in bootstrap
    assert "AllowAgentForwarding no" in bootstrap
    assert "AllowTcpForwarding no" in bootstrap
    assert "vagrant still has unrestricted passwordless sudo" in bootstrap
    assert "VALIDATION_VENV=/tmp/dac-validation-venv" in bootstrap
    assert "vm-runtime.lock" in bootstrap
    assert "pip uninstall --yes setuptools" in bootstrap
    assert '--pack-root "${APP_ROOT}/packs"' in bootstrap
    assert "host SSH-agent forwarding must remain disabled" in bootstrap
    assert "a host-sharing filesystem is mounted" in bootstrap


def test_vm_verify_checks_post_reboot_isolation_and_runtime_contracts() -> None:
    verifier = _text("scripts/vm-verify")
    for required in (
        "vagrant status controller --machine-readable",
        'VAGRANT_VERSION="2.3.4"',
        'VAGRANT_LIBVIRT_VERSION="0.12.2"',
        "/etc/detection-goggles/commit",
        "a host-sharing filesystem is mounted",
        "an SSH agent was forwarded",
        "/tmp/dac-validation-venv",
        "systemctl is-active --quiet nftables",
        "dac unexpectedly has passwordless root access",
        "dacctl pack validate htb-malevolent-modmaker",
        "ansible-playbook --syntax-check",
    ):
        assert required in verifier
    assert "vagrant up" not in verifier
    assert "vagrant destroy" not in verifier


def test_vm_runbooks_cover_supported_host_verification_and_recovery() -> None:
    playbook = _text("docs/operations/vagrant-controller.md")
    troubleshooting = _text("docs/operations/troubleshooting.md")
    ssh_playbook = _text("docs/operations/ssh-acquisition.md")
    assert "bare-metal Debian 12 amd64" in playbook
    assert 'test "$(vagrant --version)" = "Vagrant 2.3.4"' in playbook
    assert "scripts/vm-verify" in playbook
    assert "scripts/vm-locks update" in playbook
    assert "## Physical-host release validation" in playbook
    assert "## Disposable controller VM" in troubleshooting
    assert "Do not bypass a failed" in troubleshooting
    assert "Never delete `.vagrant` manually" in troubleshooting
    assert "physical host's agent" in ssh_playbook


def test_report_export_rejects_traversal_before_accessing_vm_state() -> None:
    completed = subprocess.run(
        [str(ROOT / "scripts" / "vm-pull-report"), "../evidence"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert "invalid run ID" in completed.stderr


def test_report_export_allowlists_only_rendered_reports() -> None:
    exporter = _text("scripts/vm-pull-report")
    assert "for report_name in report.json report.md" in exporter
    assert "evidence" not in exporter
    assert "MAX_REPORT_SIZE" in exporter
    assert "/usr/local/bin/dac-export-report" in exporter


def test_guest_report_export_uses_descriptor_based_safety_checks() -> None:
    assert os.access(ROOT / "vm" / "guest" / "dac_export_report.py", os.X_OK)
    exporter = _text("vm/guest/dac_export_report.py")
    assert "os.O_NOFOLLOW" in exporter
    assert "metadata.st_nlink != 1" in exporter
    assert 'REPORT_NAMES = frozenset({"report.json", "report.md"})' in exporter
    assert "report changed while it was exported" in exporter


def test_guest_report_export_streams_only_a_regular_allowlisted_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    exporter = _load_guest_exporter()
    report_directory = tmp_path / "run-12345678"
    report_directory.mkdir()
    (report_directory / "report.json").write_bytes(b'{"safe": true}\n')
    monkeypatch.setattr(exporter, "REPORT_ROOT", str(tmp_path))

    assert exporter.main([report_directory.name, "report.json"]) == 0
    output, error = capfd.readouterr()
    assert output == '{"safe": true}\n'
    assert error == ""


def test_guest_report_export_rejects_links_and_non_report_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    exporter = _load_guest_exporter()
    report_directory = tmp_path / "run-12345678"
    report_directory.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    (report_directory / "report.json").symlink_to(outside)
    monkeypatch.setattr(exporter, "REPORT_ROOT", str(tmp_path))

    assert exporter.main([report_directory.name, "report.json"]) == 1
    output, error = capfd.readouterr()
    assert output == ""
    assert "report export failed" in error
    assert exporter.main([report_directory.name, "evidence"]) == 2


def test_vm_runtime_state_is_gitignored() -> None:
    ignored = _text(".gitignore").splitlines()
    assert ".vagrant/" in ignored
