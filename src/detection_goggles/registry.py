"""Read the first-party pack registry and perform digest-verified downloads."""

from __future__ import annotations

import hashlib
import os
import ssl
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from yaml.tokens import AliasToken

from detection_goggles import __version__
from detection_goggles.errors import ContractError, PackNotFoundError
from detection_goggles.models import Pack
from detection_goggles.package_archive import install_pack_archive
from detection_goggles.runtime_guard import require_container
from detection_goggles.schema import validate

DEFAULT_REGISTRY = (
    "https://raw.githubusercontent.com/lib-port/agentless-DaC/main/registry/packs.yml"
)
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024


def _https_bytes(url: str, *, limit: int) -> bytes:
    require_container("download")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ContractError(f"Registry network URLs must use credential-free HTTPS: {url}")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"detection-goggles/{__version__}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - URL scheme is restricted above.
            request,
            timeout=15,
            context=ssl.create_default_context(),
        ) as response:
            final_url = urlparse(response.geturl())
            if (
                final_url.scheme != "https"
                or not final_url.netloc
                or final_url.username
                or final_url.password
            ):
                raise ContractError("Registry request redirected to an unsafe URL")
            announced = response.headers.get("Content-Length")
            if announced is not None:
                try:
                    announced_size = int(announced)
                except ValueError as exc:
                    raise ContractError("Network response has an invalid Content-Length") from exc
                if announced_size < 0:
                    raise ContractError("Network response has an invalid Content-Length")
                if announced_size > limit:
                    raise ContractError(f"Network response exceeds {limit} bytes")
            data = response.read(limit + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ContractError(f"Network request failed for {url}: {exc}") from exc
    if len(data) > limit:
        raise ContractError(f"Network response exceeds {limit} bytes")
    return data


def load_registry(source: str | Path = DEFAULT_REGISTRY) -> dict[str, Any]:
    require_container("manage", "test")
    if isinstance(source, Path) or urlparse(str(source)).scheme == "":
        path = Path(source).expanduser()
        if path.is_symlink() or not path.is_file():
            raise ContractError(f"Registry must be a regular, non-symlink file: {path}")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ContractError(f"Cannot read registry {path}: {exc}") from exc
        if len(raw) > MAX_REGISTRY_BYTES:
            raise ContractError(f"Registry exceeds {MAX_REGISTRY_BYTES} bytes")
        label = str(path)
    else:
        raise ContractError(
            "Registry downloads and parsing require separate Podman roles; use the host launcher"
        )
    try:
        decoded = raw.decode("utf-8")
        if any(isinstance(token, AliasToken) for token in yaml.scan(decoded)):
            raise ContractError(f"YAML aliases are not permitted in registry {label}")
        registry = yaml.safe_load(decoded)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ContractError(f"Registry {label} is not valid UTF-8 YAML: {exc}") from exc
    validate(registry, "registry.schema.json", label=label)

    identities: set[tuple[str, str]] = set()
    for entry in registry["packs"]:
        try:
            parsed_version = Version(entry["version"])
        except InvalidVersion as exc:
            raise ContractError(
                f"Registry contains an invalid version for {entry['id']}: {entry['version']}"
            ) from exc
        if str(parsed_version) != entry["version"]:
            raise ContractError(
                f"Registry version for {entry['id']} must use canonical X.Y.Z form: "
                f"{entry['version']}"
            )
        identity = (entry["id"], entry["version"])
        if identity in identities:
            raise ContractError(
                f"Registry contains duplicate pack version: {entry['id']} {entry['version']}"
            )
        identities.add(identity)
        parsed_url = urlparse(entry["url"])
        if parsed_url.scheme != "https" or parsed_url.username or parsed_url.password:
            raise ContractError(f"Pack URL must use credential-free HTTPS: {entry['url']}")
    return registry


def resolve_registry_entry(
    reference: str,
    registry: dict[str, Any],
) -> dict[str, Any]:
    pack_id, separator, requested_version = reference.partition("@")
    matches = [entry for entry in registry["packs"] if entry["id"] == pack_id]
    if separator:
        try:
            parsed_version = Version(requested_version)
        except InvalidVersion as exc:
            raise PackNotFoundError(f"Invalid requested pack version: {requested_version}") from exc
        matches = [entry for entry in matches if Version(entry["version"]) == parsed_version]

    compatible: list[dict[str, Any]] = []
    for entry in matches:
        try:
            specification = SpecifierSet(entry["core"])
        except InvalidSpecifier as exc:
            raise ContractError(f"Registry has an invalid core range for {entry['id']}") from exc
        if Version(__version__) in specification:
            compatible.append(entry)
    if not compatible:
        raise PackNotFoundError(
            f"No compatible registry entry found for {reference!r} and core {__version__}"
        )
    return max(compatible, key=lambda entry: Version(entry["version"]))


def verify_registry_archive(
    archive: Path,
    registry: dict[str, Any],
) -> dict[str, Any]:
    archive = archive.expanduser()
    if archive.is_symlink() or not archive.is_file():
        raise ContractError(f"Pack archive must be a regular, non-symlink file: {archive}")
    matches = [entry for entry in registry["packs"] if entry["archive"] == archive.name]
    if len(matches) != 1:
        raise PackNotFoundError(
            f"Registry does not contain exactly one entry for archive {archive.name!r}"
        )
    digest = hashlib.sha256()
    with archive.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    actual = digest.hexdigest()
    if actual != matches[0]["sha256"]:
        raise ContractError(
            f"Pack archive digest mismatch: expected {matches[0]['sha256']}, received {actual}"
        )
    return matches[0]


def install_registry_pack(
    reference: str,
    *,
    registry_source: str | Path = DEFAULT_REGISTRY,
    destination_root: Path | None = None,
) -> Pack:
    registry = load_registry(registry_source)
    entry = resolve_registry_entry(reference, registry)
    expected = entry["sha256"]

    with tempfile.TemporaryDirectory(prefix="dac-download-") as temporary:
        archive = Path(temporary) / entry["archive"]
        payload = _https_bytes(entry["url"], limit=MAX_DOWNLOAD_BYTES)
        actual = hashlib.sha256(payload).hexdigest()
        if actual != expected:
            raise ContractError(
                f"Downloaded pack digest mismatch: expected {expected}, received {actual}"
            )
        descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        pack = install_pack_archive(
            archive,
            destination_root,
            expected_sha256=expected,
            expected_id=entry["id"],
            expected_version=entry["version"],
        )

    if pack.id != entry["id"] or pack.version != entry["version"]:
        raise ContractError("Installed pack identity does not match its registry metadata")
    return pack
