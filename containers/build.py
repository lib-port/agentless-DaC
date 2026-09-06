"""Build pinned controller images from a bounded, recorded source snapshot."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_IMAGE = (
    "docker.io/library/debian:bookworm-slim@"
    "sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867"
)
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
SOURCE_DIRECTORIES = frozenset(
    {"src", "packs", "containers", "requirements", "scripts", "tests", "docs", "registry"}
)
SOURCE_METADATA = frozenset(
    {"LICENSE", "README.md", "SECURITY.md", "DEVELOPMENT.md", "pyproject.toml", "MANIFEST.in"}
)


def command(arguments: list[str], *, capture: bool = True) -> str:
    environment = os.environ.copy()
    for name in (
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
        "DOCKER_HOST",
        "SSH_AUTH_SOCK",
    ):
        environment.pop(name, None)
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        check=True,
        env=environment,
        stdout=subprocess.PIPE if capture else None,
        text=True,
    )
    return result.stdout or ""


def stage(destination: Path) -> dict:
    names = command(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    paths = sorted(set(names.rstrip("\x00").split("\x00")))
    if len(paths) > 10000:
        raise ValueError("Source snapshot exceeds 10,000 files")
    digest = hashlib.sha256()
    size = 0
    count = 0
    for name in paths:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe Git source path")
        # Do not copy arbitrary untracked root files, local evidence, keys or
        # legacy VM state into an image merely because Git does not ignore them.
        if name not in SOURCE_METADATA and (
            len(relative.parts) < 2 or relative.parts[0] not in SOURCE_DIRECTORIES
        ):
            continue
        source = ROOT / relative
        if source.is_symlink() or source.resolve() != source:
            raise ValueError(f"Source snapshot cannot contain links: {name}")
        if not source.exists():
            continue  # An explicitly deleted tracked file is absent from this snapshot.
        if not source.is_file():
            raise ValueError(f"Non-regular source input: {name}")
        if any(part in {".git", ".venv", "__pycache__", ".vagrant"} for part in relative.parts):
            continue
        size += source.stat().st_size
        if size > 128 * 1024 * 1024:
            raise ValueError("Source snapshot exceeds 128 MiB")
        data = source.read_bytes()
        digest.update(name.encode("utf-8") + b"\x00" + len(data).to_bytes(8, "big") + data)
        staged = destination / relative
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(data)
        staged.chmod(0o755 if os.access(source, os.X_OK) else 0o644)
        count += 1
    return {
        "commit": command(["git", "rev-parse", "HEAD"]).strip(),
        "source_sha256": digest.hexdigest(),
        "dirty": bool(command(["git", "status", "--porcelain=v1", "--untracked-files=all"])),
        "file_count": count,
        "base_image": BASE_IMAGE,
    }


def main() -> int:
    if len(sys.argv) != 1:
        print("Usage: scripts/container-build", file=sys.stderr)
        return 2
    if os.geteuid() == 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Build using rootless Podman on native Linux x86_64")
    if shutil.which("podman") is None:
        raise ValueError("Podman is required; install the supported rootless prerequisites")
    info = json.loads(command(["podman", "--remote=false", "info", "--format", "json"]))
    if (
        not info["host"]["security"]["rootless"]
        or info["host"]["serviceIsRemote"]
        or info["host"]["cgroupVersion"] != "v2"
        or re.fullmatch(r"5\.8\.[0-9]+", info["version"]["Version"]) is None
    ):
        raise ValueError("The supported build profile is local rootless Podman 5.8.x and cgroup v2")
    images: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="dac-build-") as temporary:
        staging = Path(temporary) / "source"
        staging.mkdir(mode=0o700)
        provenance = stage(staging)
        (staging / "containers" / "source.json").write_text(
            json.dumps(provenance, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        # The small firewall image is built first so network acceptance can be
        # diagnosed independently of the Python dependency build.
        for kind in ("network", "runtime", "test"):
            image_file = Path(temporary) / f"{kind}-image-id"
            command(
                [
                    "podman",
                    "--remote=false",
                    "build",
                    "--jobs=1",
                    "--layers",
                    "--memory=1g",
                    "--memory-swap=1500m",
                    "--cpu-period=100000",
                    "--cpu-quota=200000",
                    "--pull=missing",
                    "--target",
                    kind,
                    "--iidfile",
                    str(image_file),
                    "--label",
                    "io.detection-goggles.managed=true",
                    "--label",
                    f"org.opencontainers.image.revision={provenance['commit']}",
                    "--label",
                    f"io.detection-goggles.source-sha256={provenance['source_sha256']}",
                    "--file",
                    str(staging / "containers" / "Containerfile"),
                    str(staging),
                ],
                capture=False,
            )
            identifier = image_file.read_text(encoding="utf-8").strip()
            if IMAGE_ID.fullmatch(identifier) is None:
                raise ValueError("The image builder did not return an immutable image ID")
            images[kind] = identifier
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    destination = config_root / "detection-goggles"
    if destination.is_symlink():
        raise ValueError("The image configuration directory cannot be a symbolic link")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = destination / "images.json"
    if output.is_symlink():
        raise ValueError("The image manifest cannot be a symbolic link")
    manifest = {"schema_version": 1, "images": images, "source": provenance}
    descriptor, temporary_name = tempfile.mkstemp(prefix=".images-", dir=destination)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, output)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    print(f"Pinned controller images recorded in {output}")
    print(f"Source snapshot: {provenance['source_sha256']} (dirty={provenance['dirty']})")
    print("Next: scripts/container-test and scripts/container-verify")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"container-build: {error}", file=sys.stderr)
        raise SystemExit(1) from error
