"""Strict JSON Lines ingestion with physical-line error locations."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import AuthEvent


class ValidationError(ValueError):
    """An input event failed validation before detection started."""

    def __init__(self, source: str, line_number: int, message: str) -> None:
        self.source = source
        self.line_number = line_number
        self.message = message
        super().__init__(f"{source}:{line_number}: {message}")


_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d"
    r"(?:\.\d{1,6})?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON value {value!r}")


def _parse_lines(lines: Iterable[str], source: str) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        def fail(message: str) -> ValidationError:
            return ValidationError(source, line_number, message)

        try:
            record = json.loads(
                line,
                object_pairs_hook=_no_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (ValueError, RecursionError) as exc:
            raise fail(f"invalid JSON: {exc}") from exc
        if not isinstance(record, dict):
            raise fail("event must be a JSON object")

        fields = ("timestamp", "event_type", "source_ip", "username", "host")
        for name in fields:
            if name not in record:
                raise fail(f"missing required field {name!r}")
            value = record[name]
            if not isinstance(value, str) or not value.strip():
                raise fail(f"field {name!r} must be a non-empty string")
            if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                raise fail(f"field {name!r} must contain valid Unicode scalar values")
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise fail(f"field {name!r} must not contain control characters")

        timestamp_text = record["timestamp"]
        if not _TIMESTAMP.fullmatch(timestamp_text):
            raise fail("timestamp must be ISO-8601 with seconds and a timezone (Z or +/-HH:MM)")
        try:
            timestamp = datetime.fromisoformat(timestamp_text.upper().replace("Z", "+00:00"))
            timestamp = timestamp.astimezone(timezone.utc)
        except (ValueError, OverflowError) as exc:
            raise fail(f"invalid timestamp: {exc}") from exc
        if record["event_type"] not in {"auth_failure", "auth_success"}:
            raise fail("event_type must be 'auth_failure' or 'auth_success'")
        try:
            if "%" in record["source_ip"]:
                raise ValueError("scoped IPv6 addresses are not supported")
            source_ip = str(ipaddress.ip_address(record["source_ip"]))
        except ValueError as exc:
            raise fail(f"invalid source_ip: {exc}") from exc

        events.append(
            AuthEvent(
                timestamp=timestamp,
                event_type=record["event_type"],
                source_ip=source_ip,
                username=record["username"],
                host=record["host"],
                line_number=line_number,
                source=source,
            )
        )
    return events


def parse_jsonl(text: str, *, source: str = "input") -> list[AuthEvent]:
    """Parse JSONL text atomically; errors identify the first malformed line."""
    return _parse_lines(text.removeprefix("\ufeff").splitlines(), source)


def load_events(path: str | Path) -> list[AuthEvent]:
    """Read UTF-8 JSONL, retaining filename and line references as evidence."""
    input_path = Path(path)
    with input_path.open("r", encoding="utf-8-sig") as handle:
        return _parse_lines(handle, str(input_path))
