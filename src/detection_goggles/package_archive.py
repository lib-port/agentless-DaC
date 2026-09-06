"""Reproducible pack archives and safe local installation."""

from __future__ import annotations

import gzip
import hashlib
import os
import shutil
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath

from detection_goggles.errors import ContractError
from detection_goggles.models import Pack
from detection_goggles.packs import load_pack, user_pack_root
from detection_goggles.runtime_guard import require_container

MAX_ARCHIVE_FILES = 5000
MAX_ARCHIVE_EXPANDED_SIZE = 256 * 1024 * 1024


def _archive_paths(pack: Pack) -> list[Path]:
    paths: list[Path] = []
    expanded_size = 0
    for path in pack.path.rglob("*"):
        relative = path.relative_to(pack.path)
        if "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            raise ContractError(
                f"Detection Pack archives may not contain symbolic links: {relative}"
            )
        if not (path.is_dir() or path.is_file()):
            raise ContractError(f"Detection Pack contains a non-regular entry: {relative}")
        paths.append(path)
        if path.is_file():
            expanded_size += path.stat().st_size
            if expanded_size > MAX_ARCHIVE_EXPANDED_SIZE:
                raise ContractError(
                    f"Detection Pack expands beyond {MAX_ARCHIVE_EXPANDED_SIZE} bytes"
                )
        if len(paths) + 1 > MAX_ARCHIVE_FILES:
            raise ContractError(
                f"Detection Pack contains more than {MAX_ARCHIVE_FILES} archive entries"
            )
    return sorted(paths, key=lambda item: item.relative_to(pack.path).as_posix())


def _tar_info(name: str, *, directory: bool, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o755 if directory else 0o644
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    info.size = 0 if directory else size
    return info


def build_pack_archive(pack: Pack, output_directory: Path) -> tuple[Path, str]:
    require_container("manage", "test")
    output_directory = output_directory.expanduser()
    if output_directory.is_symlink():
        raise ContractError(f"Output directory may not be a symbolic link: {output_directory}")
    try:
        output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise ContractError(
            f"Cannot prepare pack output directory {output_directory}: {exc}"
        ) from exc
    archive = output_directory / f"{pack.id}-{pack.version}.tar.gz"
    if archive.exists():
        raise ContractError(f"Refusing to overwrite existing archive: {archive}")

    root_name = f"{pack.id}-{pack.version}"
    with tempfile.TemporaryDirectory(prefix="dac-build-") as temporary:
        uncompressed = Path(temporary) / "pack.tar"
        with tarfile.open(uncompressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
            tar.addfile(_tar_info(root_name, directory=True))
            for path in _archive_paths(pack):
                relative = path.relative_to(pack.path).as_posix()
                name = f"{root_name}/{relative}"
                _safe_member_path(name)
                if path.is_dir():
                    tar.addfile(_tar_info(name, directory=True))
                else:
                    info = _tar_info(name, directory=False, size=path.stat().st_size)
                    with path.open("rb") as handle:
                        tar.addfile(info, handle)

        temporary_archive = output_directory / f".{archive.name}.{uuid.uuid4().hex}.tmp"
        try:
            descriptor = os.open(temporary_archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output_handle:
                with (
                    gzip.GzipFile(
                        filename="", mode="wb", fileobj=output_handle, mtime=0
                    ) as compressed,
                    uncompressed.open("rb") as input_handle,
                ):
                    shutil.copyfileobj(input_handle, compressed)
                output_handle.flush()
                os.fsync(output_handle.fileno())

            digest = hashlib.sha256()
            with temporary_archive.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            try:
                os.link(temporary_archive, archive)
            except FileExistsError as exc:
                raise ContractError(f"Refusing to overwrite existing archive: {archive}") from exc
            except OSError as exc:
                raise ContractError(f"Cannot finalize pack archive {archive}: {exc}") from exc
        finally:
            temporary_archive.unlink(missing_ok=True)

    return archive, digest.hexdigest()


def _safe_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or not path.parts
        or "\\" in name
        or ":" in name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ContractError(f"Unsafe archive path: {name!r}")
    return path


def _extract_pack_archive(archive: Path, staging: Path) -> Path:
    seen: set[PurePosixPath] = set()
    top_levels: set[str] = set()
    expanded_size = 0
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            members: list[tarfile.TarInfo] = []
            for member in tar:
                if len(members) >= MAX_ARCHIVE_FILES:
                    raise ContractError(f"Archive contains more than {MAX_ARCHIVE_FILES} entries")
                members.append(member)
                path = _safe_member_path(member.name)
                if path in seen:
                    raise ContractError(f"Archive contains a duplicate path: {member.name}")
                seen.add(path)
                top_levels.add(path.parts[0])
                if not (member.isdir() or member.isfile()):
                    raise ContractError(
                        f"Archive entry is not a regular file or directory: {member.name}"
                    )
                expanded_size += member.size
                if expanded_size > MAX_ARCHIVE_EXPANDED_SIZE:
                    raise ContractError(f"Archive expands beyond {MAX_ARCHIVE_EXPANDED_SIZE} bytes")

            if len(top_levels) != 1:
                raise ContractError("Pack archive must contain exactly one top-level directory")

            for member in sorted(
                members, key=lambda item: (len(PurePosixPath(item.name).parts), item.name)
            ):
                relative = _safe_member_path(member.name)
                target = staging.joinpath(*relative.parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if member.isdir():
                    target.mkdir(mode=0o700, exist_ok=True)
                    continue
                source = tar.extractfile(member)
                if source is None:
                    raise ContractError(f"Cannot read archive member: {member.name}")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with source, os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(source, output)
    except (tarfile.TarError, EOFError) as exc:
        raise ContractError(
            f"Pack archive is not a valid gzip-compressed tar file: {archive}"
        ) from exc
    return staging / next(iter(top_levels))


def install_pack_archive(
    archive: Path,
    destination_root: Path | None = None,
    *,
    expected_sha256: str | None = None,
    expected_id: str | None = None,
    expected_version: str | None = None,
) -> Pack:
    require_container("manage", "test")
    archive = archive.expanduser()
    if archive.is_symlink() or not archive.is_file():
        raise ContractError(f"Pack archive must be a regular, non-symlink file: {archive}")
    if expected_sha256 is not None:
        digest = hashlib.sha256()
        with archive.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        actual_sha256 = digest.hexdigest()
        if actual_sha256 != expected_sha256.lower():
            raise ContractError(
                f"Pack archive digest mismatch: expected {expected_sha256.lower()}, "
                f"received {actual_sha256}"
            )
    destination_root = (destination_root or user_pack_root()).expanduser()
    if destination_root.is_symlink():
        raise ContractError(f"Pack root may not be a symbolic link: {destination_root}")
    destination_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".install-", dir=destination_root) as temporary:
        staging = Path(temporary)
        extracted = _extract_pack_archive(archive, staging)
        pack = load_pack(extracted)
        if expected_id is not None and pack.id != expected_id:
            raise ContractError(
                f"Pack identity mismatch: expected {expected_id}, archive contains {pack.id}"
            )
        if expected_version is not None and pack.version != expected_version:
            raise ContractError(
                f"Pack version mismatch: expected {expected_version}, "
                f"archive contains {pack.version}"
            )
        pack_root = destination_root / pack.id
        if pack_root.is_symlink() or (pack_root.exists() and not pack_root.is_dir()):
            raise ContractError(f"Pack installation directory is unsafe: {pack_root}")
        pack_root.mkdir(mode=0o700, exist_ok=True)
        destination = pack_root / pack.version
        if destination.exists():
            raise ContractError(
                f"Pack {pack.id} {pack.version} is already installed at {destination}"
            )
        extracted.rename(destination)
        return load_pack(destination)
