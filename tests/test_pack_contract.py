import shutil
from pathlib import Path

import pytest

from detection_goggles.errors import ContractError
from detection_goggles.packs import default_pack_roots, discover_packs, load_pack, resolve_pack


def test_only_first_party_pack_is_discoverable() -> None:
    packs = discover_packs(default_pack_roots())

    assert [(pack.id, pack.version) for pack in packs] == [("htb-malevolent-modmaker", "0.1.1")]
    assert packs[0].manifest["pack"]["first_party"] is True
    assert packs[0].manifest["capabilities"]["remote_execution"] is False
    assert set(packs[0].manifest["capabilities"]["sources"]) == {"files", "evidence", "ssh"}


def test_pack_can_be_resolved_by_id_and_path() -> None:
    roots = default_pack_roots()
    by_id = resolve_pack("htb-malevolent-modmaker", roots)
    by_path = resolve_pack(str(Path("packs/htb-malevolent-modmaker")), roots)

    assert by_id.path == by_path.path
    assert [rule.id for rule in by_id.rules] == ["MMM-001", "MMM-002", "MMM-003"]


def test_current_directory_is_not_an_implicit_pack_root(monkeypatch, tmp_path: Path) -> None:
    source_pack = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    shadow_root = tmp_path / "packs"
    shadow_root.mkdir()
    shutil.copytree(source_pack.path, shadow_root / source_pack.id)
    monkeypatch.chdir(tmp_path)

    roots = default_pack_roots()
    resolved = resolve_pack("htb-malevolent-modmaker@0.1.1", roots)

    assert shadow_root not in roots
    assert resolved.path == source_pack.path


def test_duplicate_pack_identity_across_explicit_roots_is_rejected(tmp_path: Path) -> None:
    source_pack = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    shutil.copytree(source_pack.path, first / source_pack.id)
    shutil.copytree(source_pack.path, second / source_pack.id)

    with pytest.raises(ContractError, match="present in multiple roots"):
        discover_packs([first, second])


def test_noncanonical_pack_version_is_rejected_during_load(tmp_path: Path) -> None:
    source_pack = resolve_pack("htb-malevolent-modmaker", default_pack_roots())
    invalid = tmp_path / "invalid"
    shutil.copytree(source_pack.path, invalid)
    manifest = invalid / "pack.yml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("version: 0.1.1", "version: 1.0.0-."),
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="pack.version"):
        load_pack(invalid)
