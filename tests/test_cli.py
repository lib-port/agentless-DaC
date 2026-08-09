from pathlib import Path

import detection_goggles.ssh_source as ssh_source
from detection_goggles.cli import main


def test_pack_list(capsys) -> None:
    assert main(["pack", "list"]) == 0
    assert "htb-malevolent-modmaker" in capsys.readouterr().out


def test_pack_available_from_local_registry(capsys) -> None:
    assert main(["pack", "available", "--registry", "registry/packs.yml"]) == 0
    assert "htb-malevolent-modmaker" in capsys.readouterr().out


def test_local_pack_install_requires_a_digest(tmp_path: Path, capsys) -> None:
    archive = tmp_path / "pack.tar.gz"
    archive.write_bytes(b"placeholder")

    assert main(["pack", "install", str(archive)]) == 2
    assert "requires --sha256" in capsys.readouterr().err


def test_clean_file_exit_code(tmp_path: Path) -> None:
    clean = tmp_path / "clean.txt"
    clean.write_text("clean", encoding="utf-8")

    result = main(
        [
            "run",
            "files",
            "htb-malevolent-modmaker",
            str(clean),
            "--output",
            str(tmp_path / "reports"),
        ]
    )

    assert result == 0


def test_output_root_file_is_a_clean_operational_error(tmp_path: Path, capsys) -> None:
    clean = tmp_path / "clean.txt"
    clean.write_text("clean", encoding="utf-8")
    output_file = tmp_path / "not-a-directory"
    output_file.write_text("occupied", encoding="utf-8")

    result = main(
        [
            "run",
            "files",
            "htb-malevolent-modmaker",
            str(clean),
            "--output",
            str(output_file),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert "Cannot prepare report output root" in captured.err
    assert "Traceback" not in captured.err


def test_ssh_cli_reports_missing_optional_dependency(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ssh_source.shutil, "which", lambda _: None)

    result = main(
        [
            "run",
            "ssh",
            "htb-malevolent-modmaker",
            "--host",
            "10.10.10.10",
            "--user",
            "htb",
            "--remote-file",
            "/opt/evidence/sample.bin",
        ]
    )

    assert result == 2
    assert "optional dependency" in capsys.readouterr().err
