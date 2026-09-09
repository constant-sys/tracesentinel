"""Deterministic, host-aware authentication detections over sliding windows."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from typing import Iterable

from .models import Alert, AuthEvent


BRUTE_FORCE = "TS-AUTH-001"
PASSWORD_SPRAY = "TS-AUTH-002"
SUCCESS_AFTER_FAILURES = "TS-AUTH-003"


@dataclass(frozen=True)
class EngineConfig:
    window_seconds: int = 300
    brute_force_threshold: int = 5
    password_spray_threshold: int = 5
    success_after_failures_threshold: int = 5

    def __post_init__(self) -> None:
        for name in (
            "window_seconds",
            "brute_force_threshold",
            "password_spray_threshold",
            "success_after_failures_threshold",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


DetectionConfig = EngineConfig


def _event_order(event: AuthEvent) -> tuple[datetime, str, int]:
    return event.timestamp, event.source, event.line_number


def _alert(
    rule_id: str,
    severity: str,
    title: str,
    evidence: Iterable[AuthEvent],
    username: str | None,
    details: dict,
) -> Alert:
    events = tuple(evidence)
    identity = json.dumps(
        [rule_id, [event.to_dict() for event in events]],
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return Alert(
        alert_id=sha256(identity.encode("utf-8")).hexdigest()[:16],
        rule_id=rule_id,
        severity=severity,
        title=title,
        source_ip=events[-1].source_ip,
        host=events[-1].host,
        username=username,
        start=events[0].timestamp,
        end=events[-1].timestamp,
        evidence=events,
        details=details,
    )


def detect(events: Iterable[AuthEvent], config: EngineConfig | None = None) -> list[Alert]:
    """Detect bursts in any input order using an inclusive time window.

    Burst alerts fire when a group first crosses the threshold. They re-arm
    after the active window falls below the threshold. Evidence is the window
    at firing time. A repeated success with no intervening failure produces no
    additional success-after-failures alert. Equal timestamps follow physical
    source-line order, so a success only correlates with preceding failures.
    """
    settings = config or EngineConfig()
    user_failures: dict[tuple[str, str, str], deque[AuthEvent]] = {}
    host_failures: dict[tuple[str, str], deque[AuthEvent]] = {}
    host_users: dict[tuple[str, str], Counter[str]] = {}
    brute_active: set[tuple[str, str, str]] = set()
    spray_active: set[tuple[str, str]] = set()
    success_last_failure: dict[tuple[str, str, str], str] = {}
    alerts: list[Alert] = []

    for event in sorted(events, key=_event_order):
        if event.timestamp.tzinfo is None or event.timestamp.utcoffset() is None:
            raise ValueError("event timestamp must include a timezone")
        if event.event_type not in {"auth_failure", "auth_success"}:
            raise ValueError("event_type must be 'auth_failure' or 'auth_success'")
        user_key = (event.source_ip, event.username, event.host)
        host_key = (event.source_ip, event.host)
        failures = user_failures.setdefault(user_key, deque())
        while failures and (event.timestamp - failures[0].timestamp).total_seconds() > settings.window_seconds:
            failures.popleft()
        if len(failures) < settings.brute_force_threshold:
            brute_active.discard(user_key)

        if event.event_type == "auth_success":
            if len(failures) >= settings.success_after_failures_threshold:
                last_failure_id = failures[-1].event_id
                if success_last_failure.get(user_key) != last_failure_id:
                    alerts.append(
                        _alert(
                            SUCCESS_AFTER_FAILURES,
                            "high",
                            "Successful authentication after repeated failures",
                            [*failures, event],
                            event.username,
                            {
                                "failure_count": len(failures),
                                "threshold": settings.success_after_failures_threshold,
                                "window_seconds": settings.window_seconds,
                                "interpretation": "Suspicious authentication sequence; compromise is not confirmed.",
                            },
                        )
                    )
                    success_last_failure[user_key] = last_failure_id
            continue

        failures.append(event)
        if len(failures) >= settings.brute_force_threshold and user_key not in brute_active:
            alerts.append(
                _alert(
                    BRUTE_FORCE,
                    "medium",
                    "Repeated authentication failures against one account",
                    failures,
                    event.username,
                    {
                        "failure_count": len(failures),
                        "threshold": settings.brute_force_threshold,
                        "window_seconds": settings.window_seconds,
                    },
                )
            )
            brute_active.add(user_key)

        host_queue = host_failures.setdefault(host_key, deque())
        counts = host_users.setdefault(host_key, Counter())
        while host_queue and (event.timestamp - host_queue[0].timestamp).total_seconds() > settings.window_seconds:
            expired = host_queue.popleft()
            counts[expired.username] -= 1
            if counts[expired.username] == 0:
                del counts[expired.username]
        if len(counts) < settings.password_spray_threshold:
            spray_active.discard(host_key)
        host_queue.append(event)
        counts[event.username] += 1
        if len(counts) >= settings.password_spray_threshold and host_key not in spray_active:
            alerts.append(
                _alert(
                    PASSWORD_SPRAY,
                    "medium",
                    "Authentication failures across multiple accounts",
                    host_queue,
                    None,
                    {
                        "failure_count": len(host_queue),
                        "distinct_users": len(counts),
                        "usernames": sorted(counts),
                        "threshold": settings.password_spray_threshold,
                        "window_seconds": settings.window_seconds,
                    },
                )
            )
            spray_active.add(host_key)

    return sorted(alerts, key=lambda item: (item.end, item.rule_id, item.alert_id))


class DetectionEngine:
    """A reusable configuration wrapper; each run has independent state."""

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config or EngineConfig()

    def detect(self, events: Iterable[AuthEvent]) -> list[Alert]:
        return detect(events, self.config)
