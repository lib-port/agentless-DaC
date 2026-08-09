"""Correlate loader and ransomware profiles across a bundle."""

import importlib.util
import json
import sys
from pathlib import Path


def load_profiles():
    path = Path(__file__).resolve().parents[1] / "profiles.py"
    spec = importlib.util.spec_from_file_location("malevolent_modmaker_profiles", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load shared detection profiles: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    profiles = load_profiles()
    request = json.load(sys.stdin)
    ransomware_ids = []
    loader_ids = []
    for artifact in request["artifacts"]:
        data = Path(artifact["content_path"]).read_bytes()
        if profiles.ransomware_profile(data)["matched"]:
            ransomware_ids.append(artifact["id"])
        if profiles.loader_profile(data)["matched"]:
            loader_ids.append(artifact["id"])

    correlated_ransomware_ids = [
        artifact_id
        for artifact_id in ransomware_ids
        if any(loader_id != artifact_id for loader_id in loader_ids)
    ]
    correlated_loader_ids = [
        artifact_id
        for artifact_id in loader_ids
        if any(ransomware_id != artifact_id for ransomware_id in ransomware_ids)
    ]
    if not correlated_ransomware_ids or not correlated_loader_ids:
        json.dump({"status": "not_detected", "matches": []}, sys.stdout)
        return

    subjects = sorted(set(correlated_ransomware_ids + correlated_loader_ids))
    evidence = []
    for artifact_id in correlated_ransomware_ids:
        evidence.append(
            {
                "artifact_id": artifact_id,
                "type": "correlation.role",
                "value": "Go AES-GCM file transformation component",
            }
        )
    for artifact_id in correlated_loader_ids:
        evidence.append(
            {
                "artifact_id": artifact_id,
                "type": "correlation.role",
                "value": "network retrieval and process execution component",
            }
        )
    json.dump(
        {
            "status": "detected",
            "matches": [
                {
                    "subject_ids": subjects,
                    "summary": (
                        "The evidence set contains both a loader profile and a Go AES-GCM "
                        "ransomware profile consistent with the lab's multi-stage behavior."
                    ),
                    "evidence": evidence,
                    "locations": [],
                }
            ],
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
