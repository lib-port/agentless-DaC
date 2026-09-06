"""Install a target-only firewall before a collector joins this namespace."""

from __future__ import annotations

import ipaddress
import json
import subprocess
from pathlib import Path


def verify_ruleset(actual: list[dict], address: str, port: int) -> None:
    tables = [entry["table"] for entry in actual if "table" in entry]
    chains = [entry["chain"] for entry in actual if "chain" in entry]
    actual_rules = [entry["rule"] for entry in actual if "rule" in entry]
    if (
        len(tables) != 1
        or tables[0].get("family") != "inet"
        or tables[0].get("name") != "dac_filter"
        or len(chains) != 3
        or {chain.get("name") for chain in chains} != {"input", "output", "forward"}
        or len(actual_rules) != 2
        or {rule.get("chain") for rule in actual_rules} != {"input", "output"}
    ):
        raise RuntimeError("Unexpected active firewall shape")
    for chain in chains:
        if (
            chain.get("family") != "inet"
            or chain.get("table") != "dac_filter"
            or chain.get("policy") != "drop"
            or chain.get("type") != "filter"
            or chain.get("prio") != 0
            or chain.get("name") != chain.get("hook")
        ):
            raise RuntimeError("Default-deny policy was not installed")
    for rule in actual_rules:
        expressions = rule.get("expr", [])
        matches = [entry["match"] for entry in expressions if "match" in entry]
        chain = rule["chain"]
        expected_field = "daddr" if chain == "output" else "saddr"
        expected_port = "dport" if chain == "output" else "sport"
        if (
            rule.get("family") != "inet"
            or rule.get("table") != "dac_filter"
            or len(expressions) != 4
            or len(matches) != 3
            or expressions[-1] != {"accept": None}
        ):
            raise RuntimeError("Unexpected firewall rule")
        for field, protocol, value in (
            (expected_field, "ip", address),
            (expected_port, "tcp", port),
        ):
            if not any(
                match.get("op") == "=="
                and match.get("left") == {"payload": {"protocol": protocol, "field": field}}
                and match.get("right") == value
                for match in matches
            ):
                raise RuntimeError("The active firewall target differs from its sealed policy")
        states = [match for match in matches if match.get("left") == {"ct": {"key": "state"}}]
        if len(states) != 1 or states[0].get("op") != "in":
            raise RuntimeError("The active firewall connection-state restriction is missing")
        values = states[0].get("right")
        if isinstance(values, dict) and set(values) == {"set"}:
            values = values["set"]
        if isinstance(values, str):
            values = [values]
        expected_states = {"new", "established"} if chain == "output" else {"established"}
        if (
            not isinstance(values, list)
            or not all(isinstance(value, str) for value in values)
            or set(values) != expected_states
        ):
            raise RuntimeError("The active firewall connection states differ from its policy")


def main() -> None:
    policy = json.loads(Path("/run/dac/policy.json").read_text(encoding="utf-8"))
    target = policy["target"]
    address = ipaddress.ip_address(target["host"])
    port = target["port"]
    if (
        address.version != 4
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
        or isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise ValueError("Invalid target policy")
    # One transaction; no detector or credential-bearing process exists yet.
    rules = f"""flush ruleset
table inet dac_filter {{
  chain input {{
    type filter hook input priority filter; policy drop;
    ip saddr {address} tcp sport {port} ct state established accept
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
  }}
  chain output {{
    type filter hook output priority filter; policy drop;
    ip daddr {address} tcp dport {port} ct state new,established accept
  }}
}}
"""
    subprocess.run(["nft", "--check", "--file", "-"], input=rules, text=True, check=True)
    subprocess.run(["nft", "--file", "-"], input=rules, text=True, check=True)
    result = subprocess.run(
        ["nft", "--json", "list", "ruleset"],
        check=True,
        capture_output=True,
        text=True,
    )
    verify_ruleset(json.loads(result.stdout)["nftables"], str(address), port)
    print(json.dumps({"sealed": True, "target": target}, sort_keys=True))


if __name__ == "__main__":
    main()
