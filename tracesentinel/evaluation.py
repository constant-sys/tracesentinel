"""Strict, reproducible evaluation of labeled synthetic authentication scenarios.

The evaluation unit is one scenario/rule pair. All three known rules are
evaluated for each scenario. Metrics describe only this synthetic dataset,
not production precision or recall.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any
import unicodedata

from . import __version__
from .engine import BRUTE_FORCE, PASSWORD_SPRAY, SUCCESS_AFTER_FAILURES, EngineConfig, detect
from .ingest import parse_jsonl
from .models import AuthEvent


RULE_IDS = (BRUTE_FORCE, PASSWORD_SPRAY, SUCCESS_AFTER_FAILURES)
_SLUG = re.compile(r"[a-z0-9]+(?:[-_][a-z0-9]+)*")
_SUITE_FIELDS = {"schema_version", "dataset_id", "synthetic", "description", "scenarios"}
_SCENARIO_FIELDS = {"id", "description", "expected_rules", "events"}
_EVENT_FIELDS = {"timestamp", "event_type", "source_ip", "username", "host"}


class DatasetValidationError(ValueError):
    """A dataset failed validation before any detections were evaluated."""


@dataclass(frozen=True)
class _Scenario:
    id: str
    description: str
    expected_rules: tuple[str, ...]
    events: list[AuthEvent]


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DatasetValidationError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise DatasetValidationError(f"non-standard JSON value {value!r}")


def _fields(value: Any, required: set[str], location: str) -> None:
    if not isinstance(value, dict):
        raise DatasetValidationError(f"{location}: must be a JSON object")
    missing = required - value.keys()
    unknown = value.keys() - required
    if missing:
        raise DatasetValidationError(f"{location}: missing required fields {sorted(missing)!r}")
    if unknown:
        raise DatasetValidationError(f"{location}: unknown fields {sorted(unknown)!r}")


def _text(value: Any, location: str, *, slug: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DatasetValidationError(f"{location}: must be a non-empty string")
    if any(unicodedata.category(char) in {"Cc", "Cs"} for char in value):
        raise DatasetValidationError(f"{location}: must not contain control characters or Unicode surrogates")
    if slug and not _SLUG.fullmatch(value):
        raise DatasetValidationError(f"{location}: must be a lowercase ASCII slug")
    return value


def _validate(raw: bytes) -> tuple[dict[str, Any], list[_Scenario]]:
    try:
        document = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, RecursionError) as exc:
        raise DatasetValidationError(f"invalid evaluation JSON: {exc}") from exc
    _fields(document, _SUITE_FIELDS, "dataset")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise DatasetValidationError("schema_version: must be the integer 1")
    dataset_id = _text(document["dataset_id"], "dataset_id", slug=True)
    _text(document["description"], "description")
    if document["synthetic"] is not True:
        raise DatasetValidationError("synthetic: must be true; evaluation datasets must contain synthetic data")
    if not isinstance(document["scenarios"], list) or not document["scenarios"]:
        raise DatasetValidationError("scenarios: must be a non-empty array")

    seen: set[str] = set()
    scenarios: list[_Scenario] = []
    for index, value in enumerate(document["scenarios"], start=1):
        location = f"scenarios[{index}]"
        _fields(value, _SCENARIO_FIELDS, location)
        scenario_id = _text(value["id"], f"{location}.id", slug=True)
        if scenario_id in seen:
            raise DatasetValidationError(f"{location}.id: duplicate scenario ID {scenario_id!r}")
        seen.add(scenario_id)
        description = _text(value["description"], f"{location}.description")
        expected = value["expected_rules"]
        if not isinstance(expected, list):
            raise DatasetValidationError(f"{location}.expected_rules: must be an array")
        if any(not isinstance(rule_id, str) or rule_id not in RULE_IDS for rule_id in expected):
            raise DatasetValidationError(f"{location}.expected_rules: must contain only known rules in {RULE_IDS!r}")
        if len(set(expected)) != len(expected):
            raise DatasetValidationError(f"{location}.expected_rules: duplicate rule IDs")
        if not isinstance(value["events"], list) or not value["events"]:
            raise DatasetValidationError(f"{location}.events: must be a non-empty array")
        for event_index, event in enumerate(value["events"], start=1):
            _fields(event, _EVENT_FIELDS, f"{location}.events[{event_index}]")
        # ASCII escaping keeps embedded line separators on a single virtual
        # JSONL line. Each evidence line denotes the event's array position.
        lines = "\n".join(json.dumps(event, ensure_ascii=True) for event in value["events"])
        try:
            events = parse_jsonl(lines, source=f"{dataset_id}/{scenario_id}")
        except ValueError as exc:
            raise DatasetValidationError(str(exc)) from exc
        scenarios.append(_Scenario(scenario_id, description, tuple(sorted(expected)), events))
    return document, sorted(scenarios, key=lambda item: item.id)


def _metrics(counts: Counter[str]) -> dict[str, Any]:
    tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
    }


def evaluate_dataset(path: str | Path, config: EngineConfig | None = None) -> dict[str, Any]:
    """Read and evaluate a complete synthetic dataset atomically.

    Scenario order and JSON object key order cannot change classifications or
    evidence. Their byte changes do change the input SHA-256. Event array order
    is preserved as evidence line order and resolves equal-timestamp ties.
    No output contains a wall clock or a machine-dependent absolute path.
    """
    if config is not None and not isinstance(config, EngineConfig):
        raise TypeError("config must be an EngineConfig or None")
    settings = config if config is not None else EngineConfig()
    raw = Path(path).read_bytes()
    document, scenarios = _validate(raw)
    totals: Counter[str] = Counter()
    rule_counts: dict[str, Counter[str]] = {rule_id: Counter() for rule_id in RULE_IDS}
    results: list[dict[str, Any]] = []
    alert_count = 0

    for scenario in scenarios:
        alerts = detect(scenario.events, settings)
        predicted = {alert.rule_id for alert in alerts}
        expected = set(scenario.expected_rules)
        for rule_id in RULE_IDS:
            if rule_id in expected:
                outcome = "tp" if rule_id in predicted else "fn"
            else:
                outcome = "fp" if rule_id in predicted else "tn"
            totals[outcome] += 1
            rule_counts[rule_id][outcome] += 1
        alert_count += len(alerts)
        results.append({
            "id": scenario.id,
            "description": scenario.description,
            "event_count": len(scenario.events),
            "expected_rules": list(scenario.expected_rules),
            "predicted_rules": sorted(predicted),
            "false_positive_rules": sorted(predicted - expected),
            "false_negative_rules": sorted(expected - predicted),
            "alerts": [alert.to_dict() for alert in alerts],
        })

    return {
        "schema_version": "1.0",
        "tool_version": __version__,
        "dataset": {
            "id": document["dataset_id"],
            "description": document["description"],
            "synthetic": True,
            "sha256": sha256(raw).hexdigest(),
        },
        "config": asdict(settings),
        "methodology": {
            "unit": "scenario_rule_binary",
            "rules": list(RULE_IDS),
            "aggregation": "micro",
            "prediction": "Each scenario/rule pair is positive when at least one alert matches that rule; repeated alerts count once.",
            "scope": "Each scenario is isolated. All three known rules are evaluated for every scenario.",
            "labels": "expected_rules lists ground-truth malicious behavior labels authored independently of detector output.",
            "evidence": "Evidence line_number is the 1-based event array index, not the physical dataset JSON line.",
            "undefined_metrics": "A metric with a zero denominator is null, including F1 = 2TP / (2TP + FP + FN).",
            "limitations": "Synthetic regression scenarios only; these scores do not estimate production precision or recall.",
        },
        "summary": {
            "scenarios": len(scenarios),
            "events": sum(len(scenario.events) for scenario in scenarios),
            "alerts": alert_count,
            "evaluated_pairs": len(scenarios) * len(RULE_IDS),
        },
        "metrics": _metrics(totals),
        "by_rule": {rule_id: _metrics(rule_counts[rule_id]) for rule_id in RULE_IDS},
        "scenarios": results,
    }
