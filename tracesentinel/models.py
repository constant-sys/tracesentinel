"""Typed authentication events and evidence-backed detection results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def format_timestamp(value: datetime) -> str:
    """Return a stable UTC ISO-8601 representation."""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    event_type: str
    source_ip: str
    username: str
    host: str
    line_number: int
    source: str = "input"

    @property
    def event_id(self) -> str:
        """Identify the original physical input line, including skipped blank lines."""
        return f"{self.source}:{self.line_number}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": format_timestamp(self.timestamp),
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "username": self.username,
            "host": self.host,
            "source": self.source,
            "line_number": self.line_number,
        }


@dataclass(frozen=True)
class Alert:
    alert_id: str
    rule_id: str
    severity: str
    title: str
    source_ip: str
    host: str
    username: str | None
    start: datetime
    end: datetime
    evidence: tuple[AuthEvent, ...]
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "source_ip": self.source_ip,
            "host": self.host,
            "username": self.username,
            "start": format_timestamp(self.start),
            "end": format_timestamp(self.end),
            "evidence": [event.to_dict() for event in self.evidence],
            "details": dict(self.details),
        }


# Short aliases are convenient when writing integrations.
Event = AuthEvent
