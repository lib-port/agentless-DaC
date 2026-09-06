"""Detect a Go PE containing AES-GCM and ransomware-style file operations."""

import importlib.util
import json
import sys
from pathlib import Path

from detection_goggles.runtime_guard import require_container


def load_profiles():
    path = Path(__file__).resolve().parents[1] / "profiles.py"
    spec = importlib.util.spec_from_file_location("malevolent_modmaker_profiles", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load shared detection profiles: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    require_container("analyse", "test")
    profiles = load_profiles()
    request = json.load(sys.stdin)
    matches = []
    for artifact in request["artifacts"]:
        data = Path(artifact["content_path"]).read_bytes()
        profile = profiles.ransomware_profile(data)
        if not profile["matched"]:
            continue
        go_hits = profile["go_hits"]
        aes_hits = profile["aes_hits"]
        gcm_hits = profile["gcm_hits"]
        file_hits = profile["file_hits"]
        matches.append(
            {
                "subject_ids": [artifact["id"]],
                "summary": (
                    "Windows Go executable contains AES-GCM primitives and a clustered set "
                    "of file transformation operations consistent with ransomware capability."
                ),
                "evidence": [
                    {
                        "artifact_id": artifact["id"],
                        "type": "static.go-markers",
                        "value": ", ".join(go_hits[:4]),
                    },
                    {
                        "artifact_id": artifact["id"],
                        "type": "static.crypto-markers",
                        "value": ", ".join((aes_hits + gcm_hits)[:6]),
                    },
                    {
                        "artifact_id": artifact["id"],
                        "type": "static.file-operation-markers",
                        "value": ", ".join(file_hits[:6]),
                    },
                ],
                "locations": [],
            }
        )
    json.dump({"status": "detected" if matches else "not_detected", "matches": matches}, sys.stdout)


if __name__ == "__main__":
    main()
