"""Small immutable models used across the core."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Rule:
    path: Path
    metadata: dict[str, Any]

    @property
    def id(self) -> str:
        return str(self.metadata["id"])

    @property
    def implementation(self) -> dict[str, Any]:
        return self.metadata["implementation"]


@dataclass(frozen=True)
class Pack:
    path: Path
    manifest: dict[str, Any]
    rules: tuple[Rule, ...]

    @property
    def id(self) -> str:
        return str(self.manifest["pack"]["id"])

    @property
    def name(self) -> str:
        return str(self.manifest["pack"]["name"])

    @property
    def version(self) -> str:
        return str(self.manifest["pack"]["version"])


@dataclass(frozen=True)
class DetectionRun:
    run_id: str
    evidence_run_id: str
    evaluations: tuple[dict[str, Any], ...]
    findings: tuple[dict[str, Any], ...]
