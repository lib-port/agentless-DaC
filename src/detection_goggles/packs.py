"""Detection Pack discovery and contract validation."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from yaml.tokens import AliasToken

from detection_goggles import __version__
from detection_goggles.errors import ContractError, PackNotFoundError
from detection_goggles.models import Pack, Rule
from detection_goggles.schema import validate

MAX_PACK_YAML_BYTES = 1024 * 1024


def user_pack_root() -> Path:
    data_home = os.environ.get("XDG_DATA_HOME")
    base = Path(data_home).expanduser() if data_home else Path.home() / ".local" / "share"
    return base / "detection-goggles" / "packs"


def default_pack_roots(extra_roots: Iterable[Path] = ()) -> tuple[Path, ...]:
    candidates: list[Path] = [Path(path).expanduser() for path in extra_roots]
    configured = os.environ.get("DAC_PACK_PATH")
    if configured:
        candidates.extend(Path(path).expanduser() for path in configured.split(os.pathsep) if path)

    # An implicit current-working-directory root lets an unrelated checkout shadow a
    # trusted installed pack. Only add the repository pack root when the package is
    # actually running from a source checkout; all other custom roots must be explicit.
    source_root = Path(__file__).resolve().parents[2]
    if (source_root / "pyproject.toml").is_file() and (source_root / "packs").is_dir():
        candidates.append(source_root / "packs")
    candidates.append(user_pack_root())

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate.resolve(strict=False))
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return tuple(unique)


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        metadata = path.stat()
        if metadata.st_size > MAX_PACK_YAML_BYTES:
            raise ContractError(f"{path} exceeds {MAX_PACK_YAML_BYTES} bytes")
        encoded = path.read_bytes()
        if len(encoded) > MAX_PACK_YAML_BYTES:
            raise ContractError(f"{path} exceeds {MAX_PACK_YAML_BYTES} bytes")
        raw = encoded.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ContractError(f"Cannot read {path}: {exc}") from exc
    try:
        if any(isinstance(token, AliasToken) for token in yaml.scan(raw)):
            raise ContractError(f"YAML aliases are not permitted in {path}")
        value = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ContractError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{path} must contain a YAML object")
    return value


def _contained_regular_file(root: Path, relative: str, *, label: str) -> Path:
    candidate = root / relative
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise ContractError(
            f"{label} escapes the Detection Pack or does not exist: {relative}"
        ) from exc
    if candidate.is_symlink() or not resolved.is_file():
        raise ContractError(f"{label} must be a regular, non-symlink file: {relative}")
    return resolved


def load_pack(path: Path) -> Pack:
    root = path.expanduser().resolve(strict=False)
    if root.is_file() and root.name == "pack.yml":
        root = root.parent
    manifest_path = root / "pack.yml"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ContractError(f"Detection Pack has no regular pack.yml: {root}")

    manifest = _read_yaml(manifest_path)
    validate(manifest, "pack.schema.json", label=str(manifest_path))

    try:
        parsed_pack_version = Version(str(manifest["pack"]["version"]))
    except InvalidVersion as exc:
        raise ContractError(f"Invalid pack version in {manifest_path}: {exc}") from exc
    if str(parsed_pack_version) != manifest["pack"]["version"]:
        raise ContractError(
            f"Pack version in {manifest_path} must use canonical X.Y.Z form: "
            f"{manifest['pack']['version']}"
        )

    try:
        required_core = SpecifierSet(str(manifest["compatibility"]["core"]))
    except InvalidSpecifier as exc:
        raise ContractError(f"Invalid core compatibility range in {manifest_path}: {exc}") from exc
    if Version(__version__) not in required_core:
        raise ContractError(
            f"Pack {manifest['pack']['id']} {manifest['pack']['version']} requires core "
            f"{required_core}; installed core is {__version__}"
        )

    rule_ids: list[str] = manifest["detections"]
    rules: list[Rule] = []
    for rule_id in rule_ids:
        rule_dir = root / "detections" / rule_id
        rule_path = _contained_regular_file(root, f"detections/{rule_id}/rule.yml", label="Rule")
        metadata = _read_yaml(rule_path)
        validate(metadata, "rule.schema.json", label=str(rule_path))
        if metadata["id"] != rule_id:
            raise ContractError(
                f"Rule directory/list ID {rule_id!r} does not match rule.yml ID {metadata['id']!r}"
            )
        entrypoint = str(metadata["implementation"]["entrypoint"])
        _contained_regular_file(rule_dir, entrypoint, label=f"Entrypoint for {rule_id}")
        rules.append(Rule(path=rule_dir, metadata=metadata))

    declared = set(rule_ids)
    detection_root = root / "detections"
    if detection_root.is_dir():
        undeclared = sorted(
            child.name
            for child in detection_root.iterdir()
            if child.is_dir() and (child / "rule.yml").is_file() and child.name not in declared
        )
        if undeclared:
            raise ContractError(
                f"Undeclared detection directories in {root}: {', '.join(undeclared)}"
            )

    return Pack(path=root, manifest=manifest, rules=tuple(rules))


def _manifest_candidates(root: Path) -> Iterable[Path]:
    if not root.is_dir():
        return ()
    direct = list(root.glob("*/pack.yml"))
    versioned = list(root.glob("*/*/pack.yml"))
    return sorted({path.parent for path in direct + versioned})


def discover_packs(roots: Iterable[Path]) -> tuple[Pack, ...]:
    packs: dict[tuple[str, str], Pack] = {}
    for root in roots:
        for path in _manifest_candidates(root):
            pack = load_pack(path)
            identity = (pack.id, pack.version)
            existing = packs.get(identity)
            if existing is not None and existing.path != pack.path:
                raise ContractError(
                    f"Detection Pack {pack.id} {pack.version} is present in multiple roots: "
                    f"{existing.path}, {pack.path}"
                )
            packs[identity] = pack
    return tuple(
        sorted(packs.values(), key=lambda pack: (pack.id, Version(pack.version)), reverse=False)
    )


def resolve_pack(reference: str, roots: Iterable[Path]) -> Pack:
    candidate = Path(reference).expanduser()
    if candidate.exists():
        return load_pack(candidate)

    pack_id, separator, requested_version = reference.partition("@")
    parsed_version: Version | None = None
    if separator:
        try:
            parsed_version = Version(requested_version)
        except InvalidVersion as exc:
            raise PackNotFoundError(f"Invalid requested pack version: {requested_version}") from exc

    roots = tuple(roots)
    packs_by_root: list[list[Pack]] = []
    identities: dict[tuple[str, str], Pack] = {}
    for root in roots:
        root_packs = [load_pack(path) for path in _manifest_candidates(root)]
        packs_by_root.append(root_packs)
        for pack in root_packs:
            identity = (pack.id, pack.version)
            existing = identities.get(identity)
            if existing is not None and existing.path != pack.path:
                raise ContractError(
                    f"Detection Pack {pack.id} {pack.version} is present in multiple roots: "
                    f"{existing.path}, {pack.path}"
                )
            identities[identity] = pack

    for root_packs in packs_by_root:
        matches = [pack for pack in root_packs if pack.id == pack_id]
        if parsed_version is not None:
            matches = [pack for pack in matches if Version(pack.version) == parsed_version]
        if matches:
            return max(matches, key=lambda pack: Version(pack.version))

    roots_text = ", ".join(str(root) for root in roots)
    raise PackNotFoundError(f"Detection Pack {reference!r} was not found in: {roots_text}")


def ensure_source_supported(pack: Pack, source: str) -> None:
    supported = set(pack.manifest["capabilities"]["sources"])
    if source not in supported:
        raise ContractError(
            f"Pack {pack.id} does not support the {source!r} input source; "
            f"supported sources: {', '.join(sorted(supported))}"
        )
