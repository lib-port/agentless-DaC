"""Secure local-file acquisition and evidence-bundle replay."""

from __future__ import annotations

import errno
import hashlib
import json
import mimetypes
import os
import stat
import tempfile
import uuid
from collections.abc import Iterable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from detection_goggles.errors import ContractError
from detection_goggles.schema import validate

DEFAULT_MAX_FILE_SIZE = 128 * 1024 * 1024
DEFAULT_MAX_TOTAL_SIZE = 512 * 1024 * 1024
DEFAULT_MAX_FILES = 1000
HARD_MAX_FILE_SIZE = 1024 * 1024 * 1024
HARD_MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024
HARD_MAX_FILES = 5000
MAX_ACQUISITION_ISSUES = 10000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


class _FileIssue(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_run_id(prefix: str = "run") -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{timestamp}-{uuid.uuid4().hex[:8]}"


def _write_json(path: Path, value: Any) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)


def replace_manifest(root: Path, manifest: dict[str, Any]) -> None:
    """Atomically replace a bundle manifest inside its private workspace."""

    temporary = root / f".manifest-{uuid.uuid4().hex}.json"
    _write_json(temporary, manifest)
    try:
        os.replace(temporary, root / "manifest.json")
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _media_type(path: Path, head: bytes) -> str:
    if len(head) >= 64 and head[:2] == b"MZ":
        offset = int.from_bytes(head[0x3C:0x40], "little")
        if offset >= 64 and offset + 4 <= len(head) and head[offset : offset + 4] == b"PE\0\0":
            return "application/vnd.microsoft.portable-executable"
    if head.startswith(b"PK\x03\x04"):
        return "application/zip"
    guessed, _ = mimetypes.guess_type(path.name)
    return guessed or "application/octet-stream"


def _issue(path: Path | str, code: str, message: str) -> dict[str, str]:
    return {"path": str(path), "code": code, "message": message[:1000]}


def bounded_issues(issues: list[dict[str, str]]) -> list[dict[str, str]]:
    if len(issues) <= MAX_ACQUISITION_ISSUES:
        return issues
    omitted = len(issues) - (MAX_ACQUISITION_ISSUES - 1)
    return issues[: MAX_ACQUISITION_ISSUES - 1] + [
        _issue(
            "<acquisition>",
            "io_error",
            f"{omitted} additional acquisition issues were omitted at the hard limit",
        )
    ]


def validate_acquisition_limits(*, max_file_size: int, max_total_size: int, max_files: int) -> None:
    if not 1 <= max_file_size <= HARD_MAX_FILE_SIZE:
        raise ContractError(f"Per-file limit must be between 1 and {HARD_MAX_FILE_SIZE} bytes")
    if not 1 <= max_total_size <= HARD_MAX_TOTAL_SIZE:
        raise ContractError(f"Total-size limit must be between 1 and {HARD_MAX_TOTAL_SIZE} bytes")
    if not 1 <= max_files <= HARD_MAX_FILES:
        raise ContractError(f"File-count limit must be between 1 and {HARD_MAX_FILES}")


def _expand_inputs(
    inputs: Iterable[Path],
    *,
    recursive: bool,
    follow_symlinks: bool,
    max_files: int,
) -> tuple[list[tuple[Path, str]], list[dict[str, str]]]:
    files: list[tuple[Path, str]] = []
    issues: list[dict[str, str]] = []

    for supplied in inputs:
        display = str(supplied)
        if len(files) >= max_files:
            issues.append(_issue(display, "file_limit", f"File limit {max_files} reached"))
            break
        try:
            metadata = supplied.stat() if follow_symlinks else supplied.lstat()
        except FileNotFoundError:
            issues.append(_issue(display, "not_found", "Input path does not exist"))
            continue
        except PermissionError:
            issues.append(
                _issue(display, "permission_denied", "Permission denied while inspecting input")
            )
            continue
        except OSError as exc:
            issues.append(
                _issue(display, "io_error", f"Cannot inspect input: {exc.strerror or exc}")
            )
            continue

        if stat.S_ISLNK(metadata.st_mode) and not follow_symlinks:
            issues.append(
                _issue(display, "symlink_rejected", "Symbolic links are not followed by default")
            )
            continue
        if stat.S_ISREG(metadata.st_mode):
            files.append((supplied, display))
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            issues.append(_issue(display, "not_regular", "Input is not a regular file"))
            continue
        if not recursive:
            issues.append(
                _issue(
                    display, "directory_requires_recursive", "Directory input requires --recursive"
                )
            )
            continue

        def on_error(error: OSError, display_path: str = display) -> None:
            code = "permission_denied" if isinstance(error, PermissionError) else "io_error"
            issues.append(_issue(error.filename or display_path, code, str(error)))

        visited_directories: set[tuple[int, int]] = set()
        limit_reached = False
        for directory, directory_names, file_names in os.walk(
            supplied, followlinks=follow_symlinks, onerror=on_error
        ):
            directory_names.sort()
            file_names.sort()
            try:
                directory_metadata = Path(directory).stat()
                directory_key = (directory_metadata.st_dev, directory_metadata.st_ino)
            except OSError as exc:
                directory_names.clear()
                on_error(exc)
                continue
            if directory_key in visited_directories:
                directory_names.clear()
                issues.append(
                    _issue(
                        directory, "symlink_rejected", "Directory cycle skipped during recursion"
                    )
                )
                continue
            visited_directories.add(directory_key)

            retained_directories: list[str] = []
            for name in directory_names:
                child_directory = Path(directory) / name
                if child_directory.is_symlink() and not follow_symlinks:
                    issues.append(
                        _issue(
                            child_directory,
                            "symlink_rejected",
                            "Symbolic-link directory skipped during recursion",
                        )
                    )
                    continue
                retained_directories.append(name)
            directory_names[:] = retained_directories

            for name in file_names:
                if len(files) >= max_files:
                    issues.append(
                        _issue(
                            Path(directory) / name,
                            "file_limit",
                            f"File limit {max_files} reached",
                        )
                    )
                    directory_names.clear()
                    limit_reached = True
                    break
                child = Path(directory) / name
                child_display = str(child)
                if child.is_symlink() and not follow_symlinks:
                    issues.append(
                        _issue(
                            child_display,
                            "symlink_rejected",
                            "Symbolic link skipped during recursion",
                        )
                    )
                    continue
                files.append((child, child_display))
            if limit_reached:
                break

        if limit_reached:
            break

    return files, issues


def _copy_regular_file(
    source: Path,
    destination: Path,
    *,
    follow_symlinks: bool,
    max_file_size: int,
    remaining_size: int,
) -> tuple[int, int, str, bytes]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if not follow_symlinks and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    source_descriptor = os.open(source, flags)
    try:
        metadata = os.fstat(source_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _FileIssue("not_regular", "Input changed or is not a regular file")
        if metadata.st_size > max_file_size:
            raise _FileIssue(
                "size_limit", f"File size {metadata.st_size} exceeds limit {max_file_size} bytes"
            )
        if metadata.st_size > remaining_size:
            raise _FileIssue("size_limit", "Total acquisition size limit would be exceeded")

        digest = hashlib.sha256()
        head = b""
        copied = 0
        try:
            destination_descriptor = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400
            )
            with os.fdopen(destination_descriptor, "wb") as destination_handle:
                while True:
                    block = os.read(source_descriptor, 1024 * 1024)
                    if not block:
                        break
                    if not head:
                        head = block[:4096]
                    copied += len(block)
                    if copied > max_file_size or copied > remaining_size:
                        raise _FileIssue(
                            "size_limit", "Input grew beyond the configured size limit"
                        )
                    digest.update(block)
                    destination_handle.write(block)
                final_metadata = os.fstat(source_descriptor)
                stable_fields = (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                )
                final_fields = (
                    final_metadata.st_dev,
                    final_metadata.st_ino,
                    final_metadata.st_size,
                    final_metadata.st_mtime_ns,
                )
                if stable_fields != final_fields or copied != final_metadata.st_size:
                    raise _FileIssue("io_error", "Input changed while it was being snapshotted")
                destination_handle.flush()
                os.fsync(destination_handle.fileno())
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return copied, metadata.st_mtime_ns, digest.hexdigest(), head
    finally:
        os.close(source_descriptor)


@dataclass(frozen=True)
class EvidenceBundle:
    root: Path
    manifest: dict[str, Any]

    def artifact_path(self, artifact: dict[str, Any]) -> Path:
        root = self.root.resolve(strict=True)
        candidate = self.root / artifact["content_ref"]
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise ContractError(
                f"Artifact {artifact.get('id', '<unknown>')} has an unsafe content_ref"
            ) from exc
        if candidate.is_symlink() or not resolved.is_file():
            raise ContractError(f"Artifact {artifact['id']} is not a regular, non-symlink file")
        return resolved

    def verify(
        self,
        *,
        max_file_size: int | None = None,
        max_total_size: int | None = None,
        max_files: int | None = None,
    ) -> None:
        validate(
            self.manifest, "evidence-bundle.schema.json", label=str(self.root / "manifest.json")
        )
        effective_file_size = max_file_size if max_file_size is not None else HARD_MAX_FILE_SIZE
        effective_total_size = max_total_size if max_total_size is not None else HARD_MAX_TOTAL_SIZE
        effective_files = max_files if max_files is not None else HARD_MAX_FILES
        validate_acquisition_limits(
            max_file_size=effective_file_size,
            max_total_size=effective_total_size,
            max_files=effective_files,
        )
        if len(self.manifest["artifacts"]) > effective_files:
            raise ContractError(
                f"Evidence bundle contains {len(self.manifest['artifacts'])} artifacts; "
                f"limit is {effective_files}"
            )
        seen: set[str] = set()
        seen_content_refs: set[str] = set()
        declared_total = 0
        for artifact in self.manifest["artifacts"]:
            validate(artifact, "artifact.schema.json", label=f"artifact {artifact.get('id')}")
            if artifact["id"] in seen:
                raise ContractError(f"Duplicate artifact ID: {artifact['id']}")
            seen.add(artifact["id"])
            expected_ref = f"artifacts/{artifact['id']}"
            if artifact["content_ref"] != expected_ref:
                raise ContractError(
                    f"Artifact {artifact['id']} must use content_ref {expected_ref!r}"
                )
            if artifact["content_ref"] in seen_content_refs:
                raise ContractError(f"Duplicate artifact content_ref: {artifact['content_ref']}")
            seen_content_refs.add(artifact["content_ref"])
            if artifact["size"] > effective_file_size:
                raise ContractError(
                    f"Artifact {artifact['id']} size {artifact['size']} exceeds replay limit "
                    f"{effective_file_size} bytes"
                )
            declared_total += artifact["size"]
            if declared_total > effective_total_size:
                raise ContractError(
                    f"Evidence bundle declared size exceeds replay limit "
                    f"{effective_total_size} bytes"
                )
            path = self.artifact_path(artifact)
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags)
            except OSError as exc:
                raise ContractError(f"Cannot open artifact {artifact['id']}: {exc}") from exc
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != artifact["size"]:
                    raise ContractError(f"Artifact integrity check failed: {artifact['id']}")
                initial_fields = (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                )
                digest = hashlib.sha256()
                size = 0
                while size <= artifact["size"]:
                    block = os.read(descriptor, min(1024 * 1024, artifact["size"] - size + 1))
                    if not block:
                        break
                    size += len(block)
                    if size > artifact["size"]:
                        raise ContractError(f"Artifact integrity check failed: {artifact['id']}")
                    digest.update(block)
                final_metadata = os.fstat(descriptor)
                final_fields = (
                    final_metadata.st_dev,
                    final_metadata.st_ino,
                    final_metadata.st_size,
                    final_metadata.st_mtime_ns,
                )
                if (
                    initial_fields != final_fields
                    or size != artifact["size"]
                    or digest.hexdigest() != artifact["sha256"]
                ):
                    raise ContractError(f"Artifact integrity check failed: {artifact['id']}")
            finally:
                os.close(descriptor)


class LocalEvidenceWorkspace(AbstractContextManager[EvidenceBundle]):
    def __init__(
        self,
        inputs: Iterable[Path],
        *,
        recursive: bool = False,
        follow_symlinks: bool = False,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
        max_files: int = DEFAULT_MAX_FILES,
    ) -> None:
        self.inputs = tuple(inputs)
        self.recursive = recursive
        self.follow_symlinks = follow_symlinks
        self.max_file_size = max_file_size
        self.max_total_size = max_total_size
        self.max_files = max_files
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.bundle: EvidenceBundle | None = None

    def __enter__(self) -> EvidenceBundle:
        validate_acquisition_limits(
            max_file_size=self.max_file_size,
            max_total_size=self.max_total_size,
            max_files=self.max_files,
        )
        if len(self.inputs) > HARD_MAX_FILES:
            raise ContractError(f"No more than {HARD_MAX_FILES} local input paths are permitted")
        self._temporary = tempfile.TemporaryDirectory(prefix="dac-evidence-")
        root = Path(self._temporary.name)
        root.chmod(0o700)
        artifacts_dir = root / "artifacts"
        artifacts_dir.mkdir(mode=0o700)

        expanded, issues = _expand_inputs(
            self.inputs,
            recursive=self.recursive,
            follow_symlinks=self.follow_symlinks,
            max_files=self.max_files,
        )
        artifacts: list[dict[str, Any]] = []
        total_size = 0

        for source, display in expanded:
            if len(artifacts) >= self.max_files:
                issues.append(_issue(display, "file_limit", f"File limit {self.max_files} reached"))
                continue
            artifact_id = f"file-{len(artifacts) + 1:04d}"
            destination = artifacts_dir / artifact_id
            try:
                size, modified_ns, sha256, head = _copy_regular_file(
                    source,
                    destination,
                    follow_symlinks=self.follow_symlinks,
                    max_file_size=self.max_file_size,
                    remaining_size=self.max_total_size - total_size,
                )
            except FileNotFoundError:
                issues.append(_issue(display, "not_found", "Input disappeared during acquisition"))
                continue
            except PermissionError:
                issues.append(
                    _issue(display, "permission_denied", "Permission denied while reading input")
                )
                continue
            except OSError as exc:
                code = "symlink_rejected" if exc.errno == errno.ELOOP else "io_error"
                issues.append(_issue(display, code, f"Cannot acquire input: {exc.strerror or exc}"))
                continue
            except _FileIssue as exc:
                issues.append(_issue(display, exc.code, str(exc)))
                continue

            total_size += size
            artifacts.append(
                {
                    "id": artifact_id,
                    "kind": "file",
                    "display_path": display,
                    "size": size,
                    "sha256": sha256,
                    "media_type": _media_type(source, head),
                    "modified_ns": modified_ns,
                    "content_ref": f"artifacts/{artifact_id}",
                    "acquisition": {"status": "complete", "source": "local_files"},
                }
            )

        manifest: dict[str, Any] = {
            "schema_version": 1,
            "run_id": new_run_id(),
            "created_at": utc_now(),
            "source": {"type": "local_files", "inputs": [str(path) for path in self.inputs]},
            "artifacts": artifacts,
            "acquisition_issues": bounded_issues(issues),
        }
        validate(manifest, "evidence-bundle.schema.json", label="acquired evidence")
        _write_json(root / "manifest.json", manifest)
        self.bundle = EvidenceBundle(root=root, manifest=manifest)
        return self.bundle

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()


def load_evidence_bundle(
    path: Path,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
) -> EvidenceBundle:
    validate_acquisition_limits(
        max_file_size=max_file_size,
        max_total_size=max_total_size,
        max_files=max_files,
    )
    root = path.expanduser()
    manifest_path = root if root.is_file() else root / "manifest.json"
    if manifest_path.name != "manifest.json" or manifest_path.is_symlink():
        raise ContractError("Evidence input must be a bundle directory or a regular manifest.json")
    try:
        metadata = manifest_path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError("Evidence manifest must be a regular file")
        if metadata.st_size > MAX_MANIFEST_BYTES:
            raise ContractError(f"Evidence manifest exceeds {MAX_MANIFEST_BYTES} bytes")
        raw = manifest_path.read_bytes()
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ContractError(f"Evidence manifest exceeds {MAX_MANIFEST_BYTES} bytes")
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"Cannot load evidence manifest {manifest_path}: {exc}") from exc
    bundle = EvidenceBundle(root=manifest_path.parent, manifest=manifest)
    bundle.verify(
        max_file_size=max_file_size,
        max_total_size=max_total_size,
        max_files=max_files,
    )
    return bundle


def retain_evidence(
    bundle: EvidenceBundle,
    destination: Path,
    *,
    max_file_size: int | None = None,
    max_total_size: int | None = None,
    max_files: int | None = None,
) -> Path:
    target = destination / "evidence"
    if target.exists():
        raise ContractError(f"Refusing to overwrite retained evidence: {target}")
    bundle.verify(
        max_file_size=max_file_size,
        max_total_size=max_total_size,
        max_files=max_files,
    )
    target.mkdir(mode=0o700)
    artifacts_directory = target / "artifacts"
    artifacts_directory.mkdir(mode=0o700)
    _write_json(target / "manifest.json", bundle.manifest)
    for artifact in bundle.manifest["artifacts"]:
        source = bundle.artifact_path(artifact)
        copied, _, sha256, _ = _copy_regular_file(
            source,
            target / artifact["content_ref"],
            follow_symlinks=False,
            max_file_size=artifact["size"],
            remaining_size=artifact["size"],
        )
        if copied != artifact["size"] or sha256 != artifact["sha256"]:
            raise ContractError(f"Artifact changed while retaining evidence: {artifact['id']}")
    return target
