"""Detect a PE with downloader and process-execution traits."""

import importlib.util
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from detection_goggles.runtime_guard import require_container

URL_PATTERN = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{3,300}", re.IGNORECASE)


def load_profiles():
    path = Path(__file__).resolve().parents[1] / "profiles.py"
    spec = importlib.util.spec_from_file_location("malevolent_modmaker_profiles", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load shared detection profiles: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe_url(value):
    parsed = urlsplit(value.decode("ascii", errors="replace"))
    if not parsed.hostname:
        return None
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None:
        host = f"{host}:{port}"
    return f"{parsed.scheme.lower()}://{host}"[:300]


def main():
    require_container("analyse", "test")
    profiles = load_profiles()
    request = json.load(sys.stdin)
    matches = []
    for artifact in request["artifacts"]:
        data = Path(artifact["content_path"]).read_bytes()
        profile = profiles.loader_profile(data)
        if not profile["matched"]:
            continue
        network_hits = profile["network_hits"]
        execution_hits = profile["execution_hits"]
        support_hits = profile["support_hits"]
        urls = [url for match in URL_PATTERN.findall(data)[:3] if (url := safe_url(match))]
        evidence = [
            {
                "artifact_id": artifact["id"],
                "type": "static.network-markers",
                "value": ", ".join(network_hits[:6]),
            },
            {
                "artifact_id": artifact["id"],
                "type": "static.execution-markers",
                "value": ", ".join(execution_hits[:6]),
            },
            {
                "artifact_id": artifact["id"],
                "type": "static.supporting-markers",
                "value": ", ".join(support_hits[:6]),
            },
        ]
        if urls:
            evidence.append(
                {
                    "artifact_id": artifact["id"],
                    "type": "static.embedded-urls",
                    "value": ", ".join(urls),
                }
            )
        matches.append(
            {
                "subject_ids": [artifact["id"]],
                "summary": (
                    "Windows executable combines network retrieval and child-process execution "
                    "traits with Go, elevation, or defense-evasion indicators."
                ),
                "evidence": evidence,
                "locations": [],
            }
        )
    json.dump({"status": "detected" if matches else "not_detected", "matches": matches}, sys.stdout)


if __name__ == "__main__":
    main()
