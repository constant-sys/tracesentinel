"""TraceSentinel: explainable authentication-log detection for blue teams."""

from .engine import DetectionConfig, DetectionEngine, EngineConfig, detect
from .ingest import ValidationError, load_events, parse_jsonl
from .models import Alert, AuthEvent, Event

__version__ = "0.1.0"

__all__ = [
    "Alert",
    "AuthEvent",
    "DetectionConfig",
    "DetectionEngine",
    "EngineConfig",
    "Event",
    "ValidationError",
    "detect",
    "load_events",
    "parse_jsonl",
]
