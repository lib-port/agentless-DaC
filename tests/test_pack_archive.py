import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

import detection_goggles.package_archive as package_archive
from detection_goggles.errors import ContractError
from detection_goggles.package_archive import build_pack_archive, install_pack_archive
from detection_goggles.packs import default_pack_roots, resolve_pack
from detection_goggles.registry import load_registry, resolve_registry_entry

pytestmark = pytest.mark.container


def test_pack_archive_is_reproducible_and_installable(tmp_path: Path) -> None:
    pack = resolve_pack("htb-malevolent-modmaker", default_pack_roots())

    first_archive, first_digest = build_pack_archive(pack, tmp_path / "first")
    second_archive, second_digest = build_pack_archive(pack, tmp_path / "second")

    assert first_digest == second_digest
    assert first_archive.read_bytes() == second_archive.read_bytes()

    installed = install_pack_archive(first_archive, tmp_path / "installed")
    assert installed.id == pack.id
    assert installed.version == pack.version
    assert [rule.id for rule in installed.rules] == ["MMM-001", "MMM-002", "MMM-003"]


def test_source_registry_matches_reproducible_archive(tmp_path: Path) -> None:
    pack = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    _, digest = build_pack_archive(pack, tmp_path / "dist")
    registry = load_registry(Path("registry/packs.yml"))
    entry = resolve_registry_entry(pack.id, registry)

    assert entry["version"] == pack.version
    assert entry["sha256"] == digest


def test_local_install_fails_closed_on_digest_mismatch(tmp_path: Path) -> None:
    pack = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    archive, _ = build_pack_archive(pack, tmp_path / "dist")

    with pytest.raises(ContractError, match="digest mismatch"):
        install_pack_archive(
            archive,
            tmp_path / "installed",
            expected_sha256="0" * 64,
        )

    assert not list((tmp_path / "installed").glob("*/*"))


def test_install_rejects_a_symlinked_pack_directory(tmp_path: Path) -> None:
    pack = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    archive, digest = build_pack_archive(pack, tmp_path / "dist")
    installation_root = tmp_path / "installed"
    installation_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (installation_root / pack.id).symlink_to(outside, target_is_directory=True)

    with pytest.raises(ContractError, match="installation directory is unsafe"):
        install_pack_archive(
            archive,
            installation_root,
            expected_sha256=digest,
        )

    assert not (outside / pack.version).exists()


def test_archive_path_traversal_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "malicious.tar.gz"
    payload = b"must not escape"
    with tarfile.open(archive, "w:gz") as tar:
        member = tarfile.TarInfo("pack/../../escape")
        member.size = len(payload)
        tar.addfile(member, io.BytesIO(payload))

    with pytest.raises(ContractError, match="Unsafe archive path"):
        install_pack_archive(archive, tmp_path / "installed")

    assert not (tmp_path / "escape").exists()


def test_windows_style_archive_traversal_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "malicious-windows.tar.gz"
    payload = b"must not escape"
    with tarfile.open(archive, "w:gz") as tar:
        member = tarfile.TarInfo(r"pack\..\escape")
        member.size = len(payload)
        tar.addfile(member, io.BytesIO(payload))

    with pytest.raises(ContractError, match="Unsafe archive path"):
        install_pack_archive(archive, tmp_path / "installed")


def test_malformed_archive_is_a_clean_contract_error(tmp_path: Path) -> None:
    archive = tmp_path / "broken.tar.gz"
    archive.write_bytes(b"not a tar archive")

    with pytest.raises(ContractError, match="valid gzip-compressed tar"):
        install_pack_archive(archive, tmp_path / "installed")


def test_builder_rejects_source_that_installer_could_not_accept(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pack = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    monkeypatch.setattr(package_archive, "MAX_ARCHIVE_FILES", 2)

    with pytest.raises(ContractError, match="more than 2 archive entries"):
        build_pack_archive(pack, tmp_path / "dist")


def test_failed_build_leaves_no_partial_final_archive(tmp_path: Path) -> None:
    pack = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    output = tmp_path / "dist"
    archive = output / f"{pack.id}-{pack.version}.tar.gz"

    def fail_copy(source, destination, *args, **kwargs):
        destination.write(source.read(32))
        raise OSError("synthetic compression failure")

    with (
        patch("detection_goggles.package_archive.shutil.copyfileobj", fail_copy),
        pytest.raises(OSError, match="synthetic compression failure"),
    ):
        build_pack_archive(pack, output)

    assert not archive.exists()
    rebuilt, _ = build_pack_archive(pack, output)
    assert rebuilt == archive
