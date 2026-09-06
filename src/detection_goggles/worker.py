"""Internal, role-restricted container worker; never a host execution entrypoint."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from http.client import HTTPException
from pathlib import Path
from typing import Any

from detection_goggles.errors import AcquisitionError, ContractError, DacError
from detection_goggles.runtime_guard import require_container

REQUEST_PATH = Path("/run/dac/request.json")
OUTPUT_ROOT = Path("/output")
REPORT_ROOT = Path("/reports")
PACK_ROOT = Path("/packs")
INSTALLED_PACK_ROOT = Path("/installed-packs")
INPUT_ROOT = Path("/inputs")
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_EXPORT_BYTES = 20 * 1024 * 1024
RUN_ID = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
FORMATS = {"json": "report.json", "markdown": "report.md"}
OP_ROLES = {
    "import_files": ("import", "test"),
    "import_evidence": ("import", "test"),
    "acquire": ("acquire", "test"),
    "analyse": ("analyse", "test"),
    "export_reports": ("export", "test"),
    "export_archive": ("export", "test"),
    "pack": ("manage", "test"),
    "download": ("download",),
    "target_init": ("target",),
    "identity_import": ("import",),
    "test": ("test",),
    "verify": ("manage", "test"),
    "verify-network": ("target",),
    "verify_network": ("target",),
}


def _string(value: Any, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ContractError(f"Invalid {label}")
    return value


def _flag(request: dict[str, Any], name: str) -> bool:
    value = request.get(name, False)
    if type(value) is not bool:
        raise ContractError(f"{name} must be a boolean")
    return value


def _path(value: Any, label: str, roots: tuple[str | Path, ...]) -> Path:
    path = Path(_string(value, label))
    if not path.is_absolute() or ".." in path.parts:
        raise ContractError(f"{label} must be an absolute contained container path")
    if not any(path == Path(root) or path.is_relative_to(root) for root in roots):
        raise ContractError(f"{label} is outside the operation's mounted inputs")
    return path


def _limits(request: dict[str, Any]) -> dict[str, int]:
    from detection_goggles.evidence import (
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_MAX_FILES,
        DEFAULT_MAX_TOTAL_SIZE,
        validate_acquisition_limits,
    )

    supplied = request.get("limits", {})
    if not isinstance(supplied, dict):
        raise ContractError("limits must be an object")
    defaults = {
        "max_file_size": DEFAULT_MAX_FILE_SIZE,
        "max_total_size": DEFAULT_MAX_TOTAL_SIZE,
        "max_files": DEFAULT_MAX_FILES,
    }
    limits = {
        name: supplied.get(name, request.get(name, value)) for name, value in defaults.items()
    }
    if any(type(value) is not int for value in limits.values()):
        raise ContractError("Acquisition limits must be integers")
    validate_acquisition_limits(**limits)
    return limits


def _pack_roots(request: dict[str, Any]) -> tuple[Path, ...]:
    supplied = request.get("pack_roots", [])
    if not isinstance(supplied, list) or len(supplied) > 100:
        raise ContractError("pack_roots must be a bounded list")
    extra = tuple(
        _path(value, "pack root", (INPUT_ROOT, PACK_ROOT, INSTALLED_PACK_ROOT))
        for value in supplied
    )
    return tuple(dict.fromkeys((*extra, PACK_ROOT, INSTALLED_PACK_ROOT)))


def _pack_reference(request: dict[str, Any]) -> str:
    reference = _string(request.get("pack"), "pack reference")
    if "/" in reference:
        _path(reference, "pack reference", (INPUT_ROOT, PACK_ROOT, INSTALLED_PACK_ROOT))
    return reference


def _acquired(bundle: Any, limits: dict[str, int]) -> dict[str, Any]:
    from detection_goggles.evidence import retain_evidence

    if not bundle.manifest["artifacts"]:
        raise AcquisitionError("No regular file artefacts were acquired")
    retain_evidence(bundle, OUTPUT_ROOT, **limits)
    issues = bundle.manifest["acquisition_issues"]
    return {
        "exit_code": 2 if issues else 0,
        "run_id": bundle.manifest["run_id"],
        "artifact_count": len(bundle.manifest["artifacts"]),
        "acquisition_issues": issues,
    }


def _import_files(request: dict[str, Any]) -> dict[str, Any]:
    from detection_goggles.evidence import (
        EvidenceBundle,
        LocalEvidenceWorkspace,
        bounded_issues,
        replace_manifest,
    )

    limits = _limits(request)
    inputs = request.get("inputs")
    if not isinstance(inputs, list) or len(inputs) > 5000:
        raise ContractError("inputs must be a bounded list")
    admission_issues = request.get("admission_issues", [])
    if (
        not isinstance(admission_issues, list)
        or len(admission_issues) > 10000
        or not all(
            isinstance(item, dict)
            and set(item) == {"path", "code", "message"}
            and all(isinstance(value, str) for value in item.values())
            for item in admission_issues
        )
    ):
        raise ContractError("Invalid input admission issues")
    selected = []
    display_paths = {}
    for item in inputs:
        if not isinstance(item, dict):
            raise ContractError("Each input must have path and display_path fields")
        path = _path(item.get("path"), "input path", (INPUT_ROOT,))
        display = _string(item.get("display_path"), "input display path")
        if path in display_paths:
            raise ContractError("Duplicate mapped input path")
        selected.append(path)
        display_paths[path] = display

    def original(value: str) -> str:
        path = Path(value)
        for mounted in sorted(display_paths, key=lambda item: len(item.parts), reverse=True):
            if path == mounted:
                return display_paths[mounted]
            if path.is_relative_to(mounted):
                return str(Path(display_paths[mounted]) / path.relative_to(mounted))
        return value

    with LocalEvidenceWorkspace(
        selected,
        recursive=_flag(request, "recursive"),
        follow_symlinks=_flag(request, "follow_symlinks"),
        input_boundaries=selected,
        **limits,
    ) as bundle:
        manifest = copy.deepcopy(bundle.manifest)
        source_inputs = request.get("source_inputs", [display_paths[path] for path in selected])
        if (
            not isinstance(source_inputs, list)
            or len(source_inputs) > 5000
            or not all(isinstance(value, str) and len(value) <= 4096 for value in source_inputs)
        ):
            raise ContractError("Invalid source input labels")
        manifest["source"]["inputs"] = source_inputs
        for artifact in manifest["artifacts"]:
            artifact["display_path"] = original(artifact["display_path"])
        for issue in manifest["acquisition_issues"]:
            issue["path"] = original(issue["path"])
        manifest["acquisition_issues"] = bounded_issues(
            [*admission_issues, *manifest["acquisition_issues"]]
        )
        replace_manifest(bundle.root, manifest)
        return _acquired(EvidenceBundle(bundle.root, manifest), limits)


def _import_evidence(request: dict[str, Any]) -> dict[str, Any]:
    from detection_goggles.evidence import load_evidence_bundle

    limits = _limits(request)
    path = _path(request.get("bundle"), "evidence bundle", (INPUT_ROOT, "/evidence"))
    bundle = load_evidence_bundle(path, **limits)
    return _acquired(bundle, limits)


def _acquire(request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    from detection_goggles.ssh_source import SshEvidenceWorkspace, SshOptions
    from detection_goggles.target_worker import unlocked_identity

    target = request.get("target")
    if not isinstance(target, dict) or any(
        target.get(field) != policy.get("target", {}).get(field)
        for field in ("host", "port", "fingerprint")
    ):
        raise ContractError("Acquisition request does not match the sealed target")
    paths = request.get("remote_files")
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        raise ContractError("remote_files must be a list of absolute remote paths")
    ask_pass = _flag(request, "ask_pass")
    identity = request.get("identity") or (None if ask_pass else "/identity/id_ed25519")
    identity_path = _path(identity, "SSH identity", ("/identity", "/imports")) if identity else None
    known_hosts = _path(
        request.get("known_hosts", "/identity/known_hosts"), "pinned known hosts", ("/identity",)
    )
    options = SshOptions(
        host=target["host"],
        port=target["port"],
        fingerprint=target["fingerprint"],
        user=_string(request.get("user"), "SSH user", maximum=128),
        identity=identity_path,
        known_hosts=known_hosts,
        ask_pass=ask_pass,
        become=_flag(request, "become"),
        ask_become_pass=_flag(request, "ask_become_pass"),
        host_key_policy=request.get("host_key_policy", "strict"),
        connection_timeout=request.get("connection_timeout", 30),
        acquisition_timeout=request.get("acquisition_timeout", 600),
    )
    limits = _limits(request)
    if identity_path is not None:
        from dataclasses import replace

        with unlocked_identity(identity_path) as socket:
            options = replace(options, agent_socket=socket)
            with SshEvidenceWorkspace(tuple(paths), options, **limits) as bundle:
                return _acquired(bundle, limits)
    with SshEvidenceWorkspace(tuple(paths), options, **limits) as bundle:
        return _acquired(bundle, limits)


def _analyse(request: dict[str, Any]) -> dict[str, Any]:
    from detection_goggles.engine import evaluate
    from detection_goggles.evidence import load_evidence_bundle
    from detection_goggles.packs import ensure_source_supported, resolve_pack
    from detection_goggles.reporting import build_report, write_report
    from detection_goggles.runner import CompletedRun

    pack = resolve_pack(_pack_reference(request), _pack_roots(request))
    bundle_path = _path(request.get("bundle", "/evidence"), "evidence bundle", ("/evidence",))
    bundle = load_evidence_bundle(bundle_path, **_limits(request))
    if not bundle.manifest["artifacts"]:
        raise AcquisitionError("Evidence bundle contains no file artefacts")
    replay = _flag(request, "replay")
    source = "evidence" if replay else bundle.manifest["source"]["type"]
    ensure_source_supported(pack, "files" if source == "local_files" else source)
    timeout = request.get("timeout", 10)
    if type(timeout) is not int or not 1 <= timeout <= 30:
        raise ContractError("Detector timeout must be between 1 and 30 seconds")
    run = evaluate(pack, bundle, timeout_cap=timeout, replay=replay)
    report = build_report(pack, bundle, run)
    formats = list(pack.manifest["reporting"]["formats"])
    directory = write_report(report, OUTPUT_ROOT, formats=formats)
    completed = CompletedRun(report, directory, run)
    return {
        "exit_code": completed.exit_code,
        "run_id": run.run_id,
        "formats": formats,
        "pack": report["pack"],
        "summary": report["summary"],
        "evaluations": report["evaluations"],
    }


def _open_export_directory(directory: str | None) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    root_descriptor = os.open(REPORT_ROOT, flags | os.O_DIRECTORY)
    try:
        return (
            os.open(directory, flags | os.O_DIRECTORY, dir_fd=root_descriptor)
            if directory is not None
            else os.dup(root_descriptor)
        )
    finally:
        os.close(root_descriptor)


def _read_export_file(parent: int, filename: str, limit: int) -> bytes:
    # O_NONBLOCK prevents a substituted FIFO from blocking before fstat can reject it.
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(filename, flags, dir_fd=parent)
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise ContractError("Export must be a regular file with exactly one hard link")
        if initial.st_size > limit:
            raise ContractError(f"Export exceeds the {limit}-byte size limit")
        chunks = []
        total = 0
        while chunk := os.read(descriptor, min(64 * 1024, limit - total + 1)):
            total += len(chunk)
            if total > limit:
                raise ContractError("Export grew beyond its size limit")
            chunks.append(chunk)
        final = os.fstat(descriptor)
        if total != initial.st_size or any(
            getattr(initial, field) != getattr(final, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        ):
            raise ContractError("File changed while it was exported")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_export(directory: str | None, filename: str, limit: int) -> bytes:
    parent = _open_export_directory(directory)
    try:
        return _read_export_file(parent, filename, limit)
    finally:
        os.close(parent)


def _export_reports(request: dict[str, Any]) -> dict[str, Any]:
    run_id = _string(request.get("run_id"), "run ID", maximum=80)
    if not RUN_ID.fullmatch(run_id):
        raise ContractError("Invalid report run ID")
    formats = request.get("formats", ["json", "markdown"])
    if not isinstance(formats, list) or not formats or any(item not in FORMATS for item in formats):
        raise ContractError("Only JSON and Markdown reports may be exported")
    expected_names = tuple(FORMATS[item] for item in dict.fromkeys(formats))
    parent = _open_export_directory(run_id)
    try:
        initial = os.fstat(parent)
        names = set()
        with os.scandir(parent) as entries:
            for entry in entries:
                if len(names) >= 2 or entry.name not in expected_names:
                    raise ContractError("Report directory contains unexpected entries")
                names.add(entry.name)
        if names != set(expected_names):
            raise ContractError("Report directory is missing a declared report format")
        files = {
            name: _read_export_file(parent, name, MAX_REPORT_BYTES).decode("utf-8")
            for name in expected_names
        }
        final = os.fstat(parent)
        if any(
            getattr(initial, field) != getattr(final, field)
            for field in ("st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        ):
            raise ContractError("Report directory changed while it was exported")
    finally:
        os.close(parent)
    return {"exit_code": 0, "files": files}


def _export_archive(request: dict[str, Any]) -> dict[str, Any]:
    filename = _string(request.get("archive"), "archive filename", maximum=200)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*\.tar\.gz", filename):
        raise ContractError("Invalid archive filename")
    raw = _read_export(None, filename, MAX_ARCHIVE_EXPORT_BYTES)
    return {
        "exit_code": 0,
        "archive": filename,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "data_base64": base64.b64encode(raw).decode("ascii"),
    }


def _pack(request: dict[str, Any]) -> dict[str, Any]:
    from detection_goggles.package_archive import build_pack_archive, install_pack_archive
    from detection_goggles.packs import discover_packs, resolve_pack
    from detection_goggles.registry import (
        load_registry,
        resolve_registry_entry,
        verify_registry_archive,
    )

    action = request.get("action")
    roots = _pack_roots(request)
    if action == "list":
        return {
            "exit_code": 0,
            "packs": [
                {
                    "id": pack.id,
                    "version": pack.version,
                    "name": pack.name,
                    "path": str(pack.path),
                    "sources": pack.manifest["capabilities"]["sources"],
                }
                for pack in discover_packs(roots)
            ],
        }
    if action in {"validate", "build"}:
        pack = resolve_pack(_pack_reference(request), roots)
        result = {
            "exit_code": 0,
            "id": pack.id,
            "version": pack.version,
            "path": str(pack.path),
            "rule_count": len(pack.rules),
        }
        if action == "build":
            archive, digest = build_pack_archive(pack, OUTPUT_ROOT)
            result.update(archive=archive.name, sha256=digest)
        return result
    if action in {"available", "resolve_registry", "verify"}:
        registry_path = _path(
            request.get("registry"),
            "registry",
            (INPUT_ROOT, "/downloads", "/registry", "/registry-download"),
        )
        registry = load_registry(registry_path)
        if action == "available":
            return {"exit_code": 0, "packs": registry["packs"]}
        if action == "resolve_registry":
            entry = resolve_registry_entry(
                _string(request.get("reference"), "pack reference"), registry
            )
        else:
            archive = _path(request.get("archive"), "archive", (INPUT_ROOT, "/downloads"))
            entry = verify_registry_archive(archive, registry)
        return {"exit_code": 0, "entry": entry}
    if action == "install":
        archive = _path(
            request.get("archive", request.get("reference")), "archive", (INPUT_ROOT, "/downloads")
        )
        digest = request.get("expected_sha256", request.get("sha256"))
        if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise ContractError("Installing an archive requires its expected SHA-256 digest")
        destination = _path(
            request.get("destination_root", str(INSTALLED_PACK_ROOT)),
            "installation destination",
            (INSTALLED_PACK_ROOT,),
        )
        with tempfile.TemporaryDirectory(prefix="dac-pack-check-") as temporary:
            checked = install_pack_archive(
                archive,
                Path(temporary),
                expected_sha256=digest,
                expected_id=request.get("expected_id"),
                expected_version=request.get("expected_version"),
            )
            for builtin in discover_packs((PACK_ROOT,)):
                if builtin.id == checked.id and builtin.version == checked.version:
                    _, builtin_digest = build_pack_archive(builtin, Path(temporary) / "builtin")
                    if builtin_digest != digest.lower():
                        raise ContractError(
                            "The archive has the same identity as a built-in pack "
                            "but different content"
                        )
                    return {
                        "exit_code": 0,
                        "id": builtin.id,
                        "version": builtin.version,
                        "path": str(builtin.path),
                        "sha256": builtin_digest,
                        "already_available": True,
                        "message": f"Pack {builtin.id} {builtin.version} is already in the image",
                    }
        pack = install_pack_archive(
            archive,
            destination,
            expected_sha256=digest,
            expected_id=request.get("expected_id"),
            expected_version=request.get("expected_version"),
        )
        return {
            "exit_code": 0,
            "id": pack.id,
            "version": pack.version,
            "path": str(pack.path),
            "sha256": digest.lower(),
        }
    raise ContractError("Unsupported pack worker action")


def handle(request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ContractError("Worker request must be an object")
    operation = request.get("op", request.get("operation"))
    if not isinstance(operation, str) or operation not in OP_ROLES:
        raise ContractError("Unsupported worker operation")
    policy = require_container(*OP_ROLES[operation])
    request = {**request, "op": operation}
    if operation == "import_files":
        return _import_files(request)
    if operation == "import_evidence":
        return _import_evidence(request)
    if operation == "acquire":
        return _acquire(request, policy)
    if operation == "analyse":
        return _analyse(request)
    if operation == "export_reports":
        return _export_reports(request)
    if operation == "export_archive":
        return _export_archive(request)
    if operation == "pack":
        return _pack(request)
    if operation == "download":
        from detection_goggles.download_worker import handle as download

        return download(request)
    if operation in {"target_init", "identity_import", "verify-network", "verify_network"}:
        from detection_goggles.target_worker import handle as target_init

        return target_init(request)
    if operation == "test":
        arguments = request.get("args", [])
        if (
            not isinstance(arguments, list)
            or len(arguments) > 100
            or not all(
                isinstance(item, str) and len(item) <= 4096 and "\x00" not in item
                for item in arguments
            )
        ):
            raise ContractError("Invalid test arguments")
        process = subprocess.run(
            [
                "/opt/dac/validation/bin/python",
                "-m",
                "pytest",
                "-p",
                "no:cacheprovider",
                *arguments,
            ],
            cwd="/opt/dac/source",
            check=False,
            timeout=1200,
        )
        return {
            "exit_code": 0 if process.returncode == 0 else 2,
            "pytest_exit_code": process.returncode,
        }
    if operation == "verify":
        from detection_goggles import __version__

        result = _pack({"action": "list"})
        return {**result, "version": __version__, "runtime_verified": True}
    raise AssertionError("unreachable")


def main() -> int:
    # Keep only the parent process's private descriptor for the JSON response. All
    # ordinary Python output and inherited subprocess fd 1 go to diagnostic stderr.
    sys.stdout.flush()
    response_descriptor = os.dup(sys.stdout.fileno())
    os.set_inheritable(response_descriptor, False)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    try:
        try:
            require_container()
            descriptor = os.open(REQUEST_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ContractError("Worker request must be a regular file")
                raw = os.read(descriptor, MAX_REQUEST_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(raw) > MAX_REQUEST_BYTES:
                raise ContractError("Worker request exceeds its size limit")
            result = handle(json.loads(raw.decode("utf-8")))
        except DacError as exc:
            result = {"exit_code": 2, "error": str(exc)}
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            RecursionError,
            subprocess.SubprocessError,
            HTTPException,
        ) as exc:
            result = {"exit_code": 2, "error": f"Worker operation failed: {type(exc).__name__}"}
        payload = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_RESPONSE_BYTES:
            result = {"exit_code": 2, "error": "Worker response exceeds the 32 MiB size limit"}
            payload = json.dumps(result).encode("utf-8")
        remaining = memoryview(payload + b"\n")
        while remaining:
            written = os.write(response_descriptor, remaining)
            remaining = remaining[written:]
        return int(result["exit_code"])
    finally:
        os.close(response_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
