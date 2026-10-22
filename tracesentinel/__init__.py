"""TraceSentinel: explainable authentication-log detection for blue teams."""

from .engine import DetectionConfig, DetectionEngine, EngineConfig, detect
from .ingest import (
    OpenSSHParseResult,
    ValidationError,
    load_events,
    load_openssh,
    load_openssh_result,
    parse_jsonl,
    parse_openssh,
    parse_openssh_result,
)
from .models import Alert, AuthEvent, Event

__version__ = "0.3.1"

__all__ = [
    "Alert",
    "AuthEvent",
    "DetectionConfig",
    "DetectionEngine",
    "EngineConfig",
    "Event",
    "OpenSSHParseResult",
    "ValidationError",
    "detect",
    "load_events",
    "load_openssh",
    "load_openssh_result",
    "parse_jsonl",
    "parse_openssh",
    "parse_openssh_result",
]
