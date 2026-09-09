"""Strict JSON Lines ingestion with physical-line error locations."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone, tzinfo
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

# RFC 3164 syslog prefix emitted by common Linux rsyslog configurations.  The
# year and timezone are not present in this format, so ``parse_openssh`` makes
# both explicit parameters (with stable, documented defaults).
_OPENSSH_PREFIX = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.+)$"
)
_OPENSSH_FAILURE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<username>\S+)"
    r" from (?P<source_ip>\S+)\s+port\s+\d+(?:\s+.*)?$"
)
_OPENSSH_SUCCESS = re.compile(
    r"^Accepted password for (?P<username>\S+)"
    r" from (?P<source_ip>\S+)\s+port\s+\d+(?:\s+.*)?$"
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


def parse_openssh(
    text: str,
    *,
    source: str = "input",
    year: int | None = None,
    timezone_info: tzinfo = timezone.utc,
) -> list[AuthEvent]:
    """Adapt common RFC 3164 ``sshd`` authentication lines.

    The adapter recognizes ``Failed password`` and ``Accepted password``
    messages such as ``Sep  9 12:34:56 host sshd[123]: Failed password for
    invalid user admin from 203.0.113.10 port 22 ssh2``.  RFC 3164 omits a
    year and timezone; callers analyzing an archived log should pass ``year``
    (the current UTC year is used when omitted) and may provide the collector's
    local timezone via ``timezone_info``.  Physical line numbers include blank
    and unrelated lines.  Lines that do not match the supported ``sshd``
    messages are ignored so a full auth.log can be supplied directly.

    ``ValidationError`` is raised when a line has a supported message shape but
    contains an invalid timestamp or source address; this prevents silently
    dropping evidence that appeared to be an authentication event.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    parse_year = datetime.now(timezone.utc).year if year is None else year
    if isinstance(parse_year, bool) or not isinstance(parse_year, int):
        raise ValueError("year must be an integer")
    if not isinstance(timezone_info, tzinfo):
        raise TypeError("timezone_info must be a datetime tzinfo")

    events: list[AuthEvent] = []
    for line_number, line in enumerate(text.removeprefix("\ufeff").splitlines(), start=1):
        if not line.strip():
            continue
        prefix = _OPENSSH_PREFIX.fullmatch(line)
        if prefix is None:
            continue
        message = prefix.group("message")
        failure = _OPENSSH_FAILURE.fullmatch(message)
        success = _OPENSSH_SUCCESS.fullmatch(message)
        if failure is None and success is None:
            continue

        def fail(detail: str) -> ValidationError:
            return ValidationError(source, line_number, detail)

        try:
            local_timestamp = datetime.strptime(
                f"{parse_year} {prefix.group('month')} {prefix.group('day')} {prefix.group('clock')}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=timezone_info)
            timestamp = local_timestamp.astimezone(timezone.utc)
        except (ValueError, OverflowError) as exc:
            raise fail(f"invalid RFC 3164 timestamp: {exc}") from exc

        match = failure or success
        assert match is not None
        try:
            if "%" in match.group("source_ip"):
                raise ValueError("scoped IPv6 addresses are not supported")
            source_ip = str(ipaddress.ip_address(match.group("source_ip")))
        except ValueError as exc:
            raise fail(f"invalid source_ip: {exc}") from exc
        events.append(
            AuthEvent(
                timestamp=timestamp,
                event_type="auth_failure" if failure else "auth_success",
                source_ip=source_ip,
                username=match.group("username"),
                host=prefix.group("host"),
                line_number=line_number,
                source=source,
            )
        )
    return events


def load_openssh(
    path: str | Path,
    *,
    year: int | None = None,
    timezone_info: tzinfo = timezone.utc,
) -> list[AuthEvent]:
    """Read a UTF-8 OpenSSH/RFC 3164 log while retaining its filename source."""
    input_path = Path(path)
    with input_path.open("r", encoding="utf-8-sig") as handle:
        return parse_openssh(
            handle.read(), source=str(input_path), year=year, timezone_info=timezone_info
        )
