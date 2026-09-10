from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tracesentinel import EngineConfig, __version__
from tracesentinel.engine import BRUTE_FORCE, PASSWORD_SPRAY, SUCCESS_AFTER_FAILURES
from tracesentinel.evaluation import DatasetValidationError, RULE_IDS, evaluate_dataset


def event(second=0, *, username="alice", event_type="auth_failure", host="lab-01"):
    return {
        "timestamp": (datetime(2026, 9, 9, tzinfo=timezone.utc) + timedelta(seconds=second)).isoformat(),
        "event_type": event_type,
        "source_ip": "192.0.2.1",
        "username": username,
        "host": host,
    }


def scenario(name="benign", expected_rules=(), events=None):
    return {
        "id": name,
        "description": f"Synthetic scenario {name}",
        "expected_rules": list(expected_rules),
        "events": [event(event_type="auth_success")] if events is None else events,
    }


def dataset(*scenarios):
    return {
        "schema_version": 1,
        "dataset_id": "auth-v1",
        "synthetic": True,
        "description": "Synthetic evaluation 数据集",
        "scenarios": list(scenarios) if scenarios else [scenario()],
    }


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "dataset.json"

    def evaluate(self, document, config=None):
        self.path.write_text(json.dumps(document, ensure_ascii=True, indent=2), encoding="utf-8")
        return evaluate_dataset(self.path, config)

    def test_known_confusion_matrix_micro_and_rule_metrics(self):
        report = self.evaluate(dataset(
            scenario("attack", [BRUTE_FORCE, SUCCESS_AFTER_FAILURES],
                     [*(event(i) for i in range(5)), event(5, event_type="auth_success")]),
            scenario("benign-retries", [], [event(i) for i in range(5)]),
            scenario("missed-spray", [PASSWORD_SPRAY], [event(i, username=f"user-{i}") for i in range(4)]),
            scenario(),
        ))
        self.assertEqual(report["metrics"], {
            "tp": 2, "fp": 1, "fn": 1, "tn": 8,
            "precision": 2 / 3, "recall": 2 / 3, "f1": 2 / 3,
        })
        self.assertEqual(report["summary"], {"scenarios": 4, "events": 16, "alerts": 3, "evaluated_pairs": 12})
        self.assertEqual(report["by_rule"][BRUTE_FORCE], {
            "tp": 1, "fp": 1, "fn": 0, "tn": 2, "precision": 0.5, "recall": 1.0, "f1": 2 / 3,
        })
        self.assertEqual(report["by_rule"][PASSWORD_SPRAY], {
            "tp": 0, "fp": 0, "fn": 1, "tn": 3, "precision": None, "recall": 0.0, "f1": 0.0,
        })
        by_id = {item["id"]: item for item in report["scenarios"]}
        self.assertEqual(by_id["benign-retries"]["false_positive_rules"], [BRUTE_FORCE])
        self.assertEqual(by_id["missed-spray"]["false_negative_rules"], [PASSWORD_SPRAY])

    def test_undefined_metrics_are_null_and_json_is_standard(self):
        report = self.evaluate(dataset())
        self.assertEqual(report["metrics"], {
            "tp": 0, "fp": 0, "fn": 0, "tn": 3, "precision": None, "recall": None, "f1": None,
        })
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)

    def test_false_positive_only_has_zero_precision_f1_but_null_recall(self):
        metrics = self.evaluate(dataset(scenario(events=[event(i) for i in range(5)])))["metrics"]
        self.assertEqual(metrics["precision"], 0.0)
        self.assertIsNone(metrics["recall"])
        self.assertEqual(metrics["f1"], 0.0)

    def test_repeated_alerts_count_once_but_all_evidence_is_retained(self):
        report = self.evaluate(dataset(scenario("bursts", [BRUTE_FORCE],
                                               [event(i) for i in [*range(5), *range(700, 705)]])))
        self.assertEqual(report["metrics"]["tp"], 1)
        self.assertEqual(report["metrics"]["tn"], 2)
        self.assertEqual(report["summary"]["alerts"], 2)
        self.assertEqual(report["scenarios"][0]["predicted_rules"], [BRUTE_FORCE])
        self.assertEqual(len(report["scenarios"][0]["alerts"]), 2)

    def test_scenarios_cannot_share_engine_state(self):
        report = self.evaluate(dataset(
            scenario("first", events=[event(i) for i in range(4)]),
            scenario("second", events=[event(4)]),
        ))
        self.assertEqual(report["summary"]["alerts"], 0)
        self.assertEqual(report["metrics"]["tn"], 6)

    def test_configuration_changes_predictions_but_preserves_ground_truth(self):
        document = dataset(scenario("weak", [BRUTE_FORCE], [event(i) for i in range(3)]))
        default = self.evaluate(document)
        configured = self.evaluate(document, EngineConfig(brute_force_threshold=3))
        self.assertEqual(default["metrics"]["fn"], 1)
        self.assertEqual(configured["metrics"]["tp"], 1)
        self.assertEqual(configured["config"]["brute_force_threshold"], 3)
        self.assertEqual(default["scenarios"][0]["expected_rules"], configured["scenarios"][0]["expected_rules"])
        with self.assertRaises(TypeError):
            evaluate_dataset(self.path, {})

    def test_evidence_uses_array_index_and_stable_virtual_source(self):
        report = self.evaluate(dataset(scenario("burst", [BRUTE_FORCE], [event(i) for i in range(5)])))
        evidence = report["scenarios"][0]["alerts"][0]["evidence"]
        self.assertEqual([item["line_number"] for item in evidence], [1, 2, 3, 4, 5])
        self.assertEqual(evidence[0]["event_id"], "auth-v1/burst:1")
        self.assertTrue(all(item["source"] == "auth-v1/burst" for item in evidence))
        self.assertNotIn(str(self.path), json.dumps(report))

    def test_hashes_actual_bytes_including_bom_and_is_repeatable(self):
        raw = ("\ufeff" + json.dumps(dataset(), ensure_ascii=False, indent=2) + "\r\n").encode("utf-8")
        self.path.write_bytes(raw)
        report = evaluate_dataset(self.path)
        self.assertEqual(report["dataset"]["sha256"], sha256(raw).hexdigest())
        self.assertEqual(report["tool_version"], __version__)
        self.assertEqual(report, evaluate_dataset(str(self.path)))
        self.assertEqual(report["methodology"]["unit"], "scenario_rule_binary")
        self.assertEqual(report["methodology"]["rules"], list(RULE_IDS))

    def test_scenario_key_and_label_permutations_only_change_byte_hash(self):
        document = dataset(
            scenario("z-last", [SUCCESS_AFTER_FAILURES, BRUTE_FORCE],
                     [*(event(i) for i in range(5)), event(5, event_type="auth_success")]),
            scenario("a-first"),
        )
        normal = self.evaluate(document)
        document["scenarios"].reverse()
        for item in document["scenarios"]:
            item["expected_rules"].reverse()
        self.path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        permuted = evaluate_dataset(self.path)
        self.assertNotEqual(normal["dataset"].pop("sha256"), permuted["dataset"].pop("sha256"))
        self.assertEqual(normal, permuted)
        self.assertEqual([item["id"] for item in normal["scenarios"]], ["a-first", "z-last"])

    def test_distinct_timestamp_event_permutation_preserves_metrics_not_line_indices(self):
        records = [*(event(i) for i in range(5)), event(5, event_type="auth_success")]
        normal = self.evaluate(dataset(scenario("burst", [BRUTE_FORCE, SUCCESS_AFTER_FAILURES], records)))
        reverse = self.evaluate(dataset(scenario("burst", [BRUTE_FORCE, SUCCESS_AFTER_FAILURES], records[::-1])))
        self.assertEqual(normal["metrics"], reverse["metrics"])
        self.assertEqual(normal["summary"], reverse["summary"])
        self.assertNotEqual(normal["scenarios"][0]["alerts"], reverse["scenarios"][0]["alerts"])

    def test_equal_timestamp_array_order_is_intentional_tie_breaker(self):
        failures = [event() for _ in range(5)]
        success = event(event_type="auth_success")
        before = self.evaluate(dataset(scenario("burst", [BRUTE_FORCE], [success, *failures])))
        after = self.evaluate(dataset(scenario("burst", [BRUTE_FORCE, SUCCESS_AFTER_FAILURES], [*failures, success])))
        self.assertEqual(before["scenarios"][0]["predicted_rules"], [BRUTE_FORCE])
        self.assertEqual(after["scenarios"][0]["predicted_rules"], [BRUTE_FORCE, SUCCESS_AFTER_FAILURES])

    def test_bad_later_scenario_is_validated_before_any_detection(self):
        document = dataset(scenario("valid", [BRUTE_FORCE], [event(i) for i in range(5)]), scenario("bad"))
        document["scenarios"][1]["events"][0]["source_ip"] = "invalid"
        with patch("tracesentinel.evaluation.detect") as mocked:
            with self.assertRaisesRegex(DatasetValidationError, "auth-v1/bad:1.*invalid source_ip"):
                self.evaluate(document)
        mocked.assert_not_called()

    def test_unknown_and_missing_keys_at_every_level_are_rejected(self):
        for level in ("dataset", "scenario", "event"):
            for operation in ("unknown", "missing"):
                document = dataset()
                target = document if level == "dataset" else document["scenarios"][0]
                if level == "event":
                    target = target["events"][0]
                if operation == "unknown":
                    target["unexpected"] = "ignored?"
                else:
                    del target[next(iter(target))]
                with self.subTest(level=level, operation=operation), self.assertRaises(DatasetValidationError):
                    self.evaluate(document)

    def test_duplicate_json_keys_at_every_level_are_rejected(self):
        text = json.dumps(dataset())
        for key, value in (("dataset_id", "auth-v1"), ("id", "benign"), ("host", "lab-01")):
            token = json.dumps(key) + ": " + json.dumps(value)
            self.path.write_text(text.replace(token, token + ", " + token, 1), encoding="utf-8")
            with self.subTest(key=key), self.assertRaisesRegex(DatasetValidationError, "duplicate JSON field"):
                evaluate_dataset(self.path)

    def test_invalid_json_constants_document_type_utf8_and_depth_are_rejected(self):
        invalid = [b"\xff", b"{", b"[]", b"null", b"true", b"{} {}", b"NaN", b"Infinity", b"-Infinity",
                   b"[" * 1500 + b"]" * 1500]
        for raw in invalid:
            self.path.write_bytes(raw)
            with self.subTest(raw=raw[:20]), self.assertRaises(DatasetValidationError):
                evaluate_dataset(self.path)
        self.path.write_text(json.dumps(dataset()).replace('"schema_version": 1', '"schema_version": NaN'), encoding="utf-8")
        with self.assertRaisesRegex(DatasetValidationError, "non-standard JSON"):
            evaluate_dataset(self.path)

    def test_schema_version_and_synthetic_have_exact_types(self):
        for field, invalid_values in (("schema_version", [True, False, 1.0, "1", 2, None]),
                                      ("synthetic", [False, 1, "true", None, []])):
            for value in invalid_values:
                document = dataset()
                document[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(DatasetValidationError):
                    self.evaluate(document)

    def test_nonempty_arrays_and_scenario_objects_are_required(self):
        for invalid in ([], {}, "", None, True):
            document = dataset()
            document["scenarios"] = invalid
            with self.subTest(scenarios=invalid), self.assertRaises(DatasetValidationError):
                self.evaluate(document)
            document = dataset()
            document["scenarios"][0]["events"] = invalid
            with self.subTest(events=invalid), self.assertRaises(DatasetValidationError):
                self.evaluate(document)
        for invalid in ([], "", None, True):
            for field in ("scenarios", "events"):
                document = dataset()
                target = document if field == "scenarios" else document["scenarios"][0]
                target[field] = [invalid]
                with self.subTest(field=field, value=invalid), self.assertRaises(DatasetValidationError):
                    self.evaluate(document)

    def test_rule_labels_must_be_unique_known_rule_ids(self):
        for invalid in (None, {}, BRUTE_FORCE, [BRUTE_FORCE, BRUTE_FORCE], ["TS-AUTH-999"], [True], [[]]):
            document = dataset()
            document["scenarios"][0]["expected_rules"] = invalid
            with self.subTest(value=invalid), self.assertRaises(DatasetValidationError):
                self.evaluate(document)

    def test_duplicate_scenario_ids_are_rejected(self):
        with self.assertRaisesRegex(DatasetValidationError, "duplicate scenario ID"):
            self.evaluate(dataset(scenario(), scenario()))

    def test_metadata_rejects_controls_surrogates_invalid_types_and_unsafe_ids(self):
        for field in ("dataset_id", "description", "scenario_id", "scenario_description"):
            for invalid in (None, True, 1, [], "", "  ", "bad\ntext", "bad\x7ftext", "bad\x85text", "bad\ud800"):
                document = dataset()
                target = document["scenarios"][0] if field.startswith("scenario_") else document
                key = field.removeprefix("scenario_")
                target[key] = invalid
                with self.subTest(field=field, value=repr(invalid)), self.assertRaises(DatasetValidationError):
                    self.evaluate(document)
        for invalid in ("../data", "upperCase", "a/b", "a:b", "-first", "last-", "a b", "名字"):
            document = dataset()
            document["dataset_id"] = invalid
            with self.subTest(slug=invalid), self.assertRaises(DatasetValidationError):
                self.evaluate(document)

    def test_normalized_event_validation_is_reused_without_silent_skips(self):
        replacements = {
            "timestamp": ["2026-09-09T00:00:00", "2026-02-30T00:00:00Z"],
            "event_type": ["logout"], "source_ip": ["192.0.2.1/24", "not-an-ip"],
            "username": ["", "bad\nname", "bad\udfff"], "host": [None, []],
        }
        for field, values in replacements.items():
            for value in values:
                document = dataset()
                document["scenarios"][0]["events"][0][field] = value
                with self.subTest(field=field, value=repr(value)), self.assertRaises(DatasetValidationError):
                    self.evaluate(document)

    def test_unicode_and_timestamp_normalization_reach_evidence(self):
        records = [event(i, username="研究员-🛡") for i in range(5)]
        records[0]["timestamp"] = "2026-09-09T08:00:00+08:00"
        for item in records:
            item["source_ip"] = "2001:0db8:0000::1"
        report = self.evaluate(dataset(scenario("unicode", [BRUTE_FORCE], records)))
        evidence = report["scenarios"][0]["alerts"][0]["evidence"]
        self.assertEqual(evidence[0]["timestamp"], "2026-09-09T00:00:00Z")
        self.assertEqual(evidence[0]["source_ip"], "2001:db8::1")
        self.assertEqual(evidence[0]["username"], "研究员-🛡")


if __name__ == "__main__":
    unittest.main()
