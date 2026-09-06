"""Run verification inside the same mandatory boundary used operationally."""

from __future__ import annotations

import argparse
import json
import sys

from detection_goggles.errors import DacError
from detection_goggles.podman import Podman


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("test", "verify"))
    parser.add_argument("--target-ip")
    parser.add_argument("--target-port", type=int)
    parser.add_argument("--host-key-fingerprint")
    arguments, additional = parser.parse_known_args()
    driver = Podman()
    driver.preflight()
    if arguments.mode == "test":
        result = driver.run(
            "test", {"operation": "test", "args": additional}, [], image_kind="test"
        )
    else:
        if additional:
            parser.error("unrecognised arguments: " + " ".join(additional))
        result = driver.run("manage", {"operation": "verify"}, [])
        target_arguments = (
            arguments.target_ip,
            arguments.target_port,
            arguments.host_key_fingerprint,
        )
        if any(value is not None for value in target_arguments):
            if not all(value is not None for value in target_arguments):
                parser.error("all three target options are required for SSH network verification")
            target = {
                "host": arguments.target_ip,
                "port": arguments.target_port,
                "fingerprint": arguments.host_key_fingerprint,
            }
            with driver.acquisition_pod(target) as pod:
                network = driver.run(
                    "target", {"op": "verify_network", "target": target}, [], pod=pod
                )
            result["network"] = network
            result["exit_code"] = max(
                int(result.get("exit_code", 0)), int(network.get("exit_code", 2))
            )
        else:
            result["network"] = (
                "not tested: supply the three target options for live SSH acceptance"
            )
    print(json.dumps(result, sort_keys=True, indent=2))
    return int(result.get("exit_code", 0))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DacError as error:
        print(f"container-{sys.argv[1]}: {error}", file=sys.stderr)
        raise SystemExit(2) from error
