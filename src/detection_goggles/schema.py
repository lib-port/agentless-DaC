"""JSON Schema loading and validation."""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from detection_goggles.errors import ContractError


@cache
def _validator(schema_name: str) -> Draft202012Validator:
    schema_path = files("detection_goggles").joinpath("schemas", schema_name)
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContractError(f"Unknown schema: {schema_name}") from exc
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate(instance: Any, schema_name: str, *, label: str | None = None) -> None:
    errors = sorted(
        _validator(schema_name).iter_errors(instance), key=lambda error: list(error.path)
    )
    if not errors:
        return

    rendered: list[str] = []
    for error in errors[:10]:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        rendered.append(f"{location}: {error.message}")
    if len(errors) > 10:
        rendered.append(f"... and {len(errors) - 10} more validation errors")
    subject = label or schema_name
    raise ContractError(f"{subject} is invalid:\n  " + "\n  ".join(rendered))
