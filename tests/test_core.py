from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from tracesentinel import EngineConfig, ValidationError, detect, load_events, parse_jsonl
from tracesentinel.engine import BRUTE_FORCE, PASSWORD_SPRAY, SUCCESS_AFTER_FAILURES


BASE = datetime(2026, 9, 9, tzinfo=timezone.utc)


def record(second=0, *, username="alice", host="lab-01", source_ip="192.0.2.10", event_type="auth_failure"):
    return {
        "timestamp": (BASE + timedelta(seconds=second)).isoformat(),
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "host": host,
    }


def events(*records):
    return parse_jsonl("\n".join(json.dumps(item) for item in records), source="fixture.jsonl")


def only(alerts, rule_id):
    return [alert for alert in alerts if alert.rule_id == rule_id]


class IngestionTests(unittest.TestCase):
    def test_line_numbers_survive_blank_lines_and_bom(self):
        parsed = parse_jsonl("\ufeff\n" + json.dumps(record()) + "\n\n" + json.dumps(record(1)), source="auth.jsonl")
        self.assertEqual([event.line_number for event in parsed], [2, 4])
        self.assertEqual(parsed[1].event_id, "auth.jsonl:4")

    def test_timezone_offsets_are_normalized_to_utc(self):
        item = record()
        item["timestamp"] = "2026-09-09T08:00:00+08:00"
        parsed = events(item)[0]
        self.assertEqual(parsed.timestamp, BASE)
        self.assertEqual(parsed.to_dict()["timestamp"], "2026-09-09T00:00:00Z")

    def test_ipv6_is_canonicalized(self):
        self.assertEqual(events(record(source_ip="2001:0db8:0000::1"))[0].source_ip, "2001:db8::1")

    def test_malformed_json_has_physical_line_context(self):
        with self.assertRaises(ValidationError) as caught:
            parse_jsonl(json.dumps(record()) + "\n\n{broken", source="bad.jsonl")
        self.assertEqual(caught.exception.line_number, 3)
        self.assertIn("bad.jsonl:3", str(caught.exception))

    def test_required_fields_and_value_types(self):
        for field in record():
            for invalid in [None, 7, False, [], "", "   "]:
                with self.subTest(field=field, invalid=invalid):
                    item = record()
                    item[field] = invalid
                    with self.assertRaises(ValidationError):
                        events(item)
            item = record()
            del item[field]
            with self.subTest(field=field, missing=True), self.assertRaises(ValidationError):
                events(item)

    def test_rejects_bad_timestamp_and_timezone(self):
        invalid = [
            "2026-09-09T00:00:00", "2026-09-09", "2026-02-30T00:00:00Z",
            "2026-09-09T24:00:00Z", "2026-09-09T00:00:00+24:00",
            "2026-09-09T00:00:00+00:60", "2026-09-09T00:00:00+08:00 ",
        ]
        for value in invalid:
            with self.subTest(value=value):
                item = record()
                item["timestamp"] = value
                with self.assertRaises(ValidationError):
                    events(item)

    def test_rejects_invalid_ip_and_unsupported_events(self):
        for ip in ["example.com", "999.1.2.3", "192.0.2.1/24", "fe80::1%eth0"]:
            with self.subTest(ip=ip), self.assertRaises(ValidationError):
                events(record(source_ip=ip))
        with self.assertRaises(ValidationError):
            events(record(event_type="logout"))

    def test_rejects_non_objects_duplicate_fields_and_nonstandard_json(self):
        for text in ["[]", '"text"', "null", '{"host":"one","host":"two"}', '{"extra":NaN}']:
            with self.subTest(text=text), self.assertRaises(ValidationError):
                parse_jsonl(text)

    def test_rejects_control_characters(self):
        with self.assertRaises(ValidationError):
            events(record(username="alice\nadmin"))

    def test_rejects_escaped_lone_surrogates_before_report_serialization(self):
        for field in record():
            for surrogate in [chr(0xD800), chr(0xDFFF)]:
                with self.subTest(field=field, surrogate=repr(surrogate)):
                    item = record()
                    item[field] = surrogate
                    with self.assertRaisesRegex(ValidationError, "valid Unicode scalar values"):
                        events(item)

    def test_accepts_valid_surrogate_pairs_as_unicode_characters(self):
        parsed = events(record(username="analyst-\U0001f6e1"))[0]
        self.assertEqual(parsed.username, "analyst-\U0001f6e1")
        parsed.username.encode("utf-8")

    def test_file_loader_reads_utf8_bom_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.jsonl"
            path.write_text(json.dumps(record(username="研究员")), encoding="utf-8-sig")
            parsed = load_events(path)
        self.assertEqual(parsed[0].source, str(path))
        self.assertEqual(parsed[0].username, "研究员")


class DetectionTests(unittest.TestCase):
    def test_empty_and_benign_input(self):
        self.assertEqual(detect([]), [])
        self.assertEqual(detect(events(*(record(i) for i in range(4)))), [])

    def test_brute_force_at_threshold_with_evidence(self):
        alerts = detect(events(*(record(i) for i in range(5))))
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, BRUTE_FORCE)
        self.assertEqual(alert.username, "alice")
        self.assertEqual(alert.details["failure_count"], 5)
        self.assertEqual([item.line_number for item in alert.evidence], [1, 2, 3, 4, 5])
        self.assertEqual(alert.to_dict()["evidence"][0]["event_id"], "fixture.jsonl:1")

    def test_window_includes_exact_five_minute_boundary(self):
        data = events(*(record(i) for i in [0, 10, 20, 30, 300]))
        self.assertEqual(len(only(detect(data), BRUTE_FORCE)), 1)

    def test_window_excludes_events_one_microsecond_too_old(self):
        data = events(*(record(i) for i in [0, 10, 20, 30, 300.000001]))
        self.assertEqual(detect(data), [])

    def test_sliding_window_crosses_fixed_clock_boundary(self):
        data = events(*(record(i) for i in [298, 299, 300, 301, 302]))
        self.assertEqual(len(only(detect(data), BRUTE_FORCE)), 1)

    def test_one_alert_per_sustained_burst_and_rearm_after_gap(self):
        data = events(*(record(i) for i in [*range(12), *range(700, 705)]))
        self.assertEqual(len(only(detect(data), BRUTE_FORCE)), 2)

    def test_password_spray_counts_distinct_users(self):
        data = events(*(record(i, username=f"user-{i}") for i in range(5)))
        alerts = detect(data)
        self.assertEqual([item.rule_id for item in alerts], [PASSWORD_SPRAY])
        self.assertIsNone(alerts[0].username)
        self.assertEqual(alerts[0].details["distinct_users"], 5)

    def test_repeated_attempts_against_four_users_are_not_spray(self):
        data = events(*(record(i, username=f"user-{i % 4}") for i in range(8)))
        self.assertEqual(only(detect(data), PASSWORD_SPRAY), [])

    def test_spray_expiry_removes_only_last_event_for_a_user(self):
        data = events(
            record(0, username="a"), record(299, username="a"),
            record(300, username="b"), record(301, username="c"),
            record(302, username="d"), record(303, username="e"),
        )
        alerts = only(detect(data), PASSWORD_SPRAY)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].details["distinct_users"], 5)
        self.assertEqual(alerts[0].start, BASE + timedelta(seconds=299))

    def test_success_after_failures_correlates_all_evidence(self):
        data = events(*(record(i) for i in range(5)), record(5, event_type="auth_success"))
        alerts = only(detect(data), SUCCESS_AFTER_FAILURES)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "high")
        self.assertEqual(len(alerts[0].evidence), 6)
        self.assertEqual(alerts[0].evidence[-1].event_type, "auth_success")

    def test_success_rule_excludes_old_failures(self):
        data = events(*(record(i) for i in range(5)), record(305, event_type="auth_success"))
        self.assertEqual(only(detect(data), SUCCESS_AFTER_FAILURES), [])

    def test_success_does_not_correlate_other_identity_host_or_source(self):
        for changes in [dict(username="bob"), dict(host="lab-02"), dict(source_ip="192.0.2.11")]:
            with self.subTest(changes=changes):
                data = events(*(record(i) for i in range(5)), record(5, event_type="auth_success", **changes))
                self.assertEqual(only(detect(data), SUCCESS_AFTER_FAILURES), [])

    def test_repeated_success_without_new_failure_is_deduplicated(self):
        data = events(*(record(i) for i in range(5)), record(5, event_type="auth_success"), record(6, event_type="auth_success"))
        self.assertEqual(len(only(detect(data), SUCCESS_AFTER_FAILURES)), 1)

    def test_hosts_and_sources_cannot_be_combined_for_threshold(self):
        for field, alternate in [("host", "lab-02"), ("source_ip", "192.0.2.11")]:
            with self.subTest(field=field):
                data = events(*(record(i) for i in range(4)), record(4, **{field: alternate}))
                self.assertEqual(detect(data), [])

    def test_unsorted_input_is_deterministic(self):
        data = events(*(record(i) for i in range(5)), record(5, event_type="auth_success"))
        normal = [item.to_dict() for item in detect(data)]
        reverse = [item.to_dict() for item in detect(reversed(data))]
        self.assertEqual(normal, reverse)

    def test_success_cannot_use_future_failures_at_equal_timestamp(self):
        data = events(record(event_type="auth_success"), *(record() for _ in range(5)))
        self.assertEqual(only(detect(reversed(data)), SUCCESS_AFTER_FAILURES), [])

    def test_configuration_changes_threshold_and_window(self):
        config = EngineConfig(window_seconds=10, brute_force_threshold=3)
        self.assertEqual(len(only(detect(events(record(0), record(5), record(10)), config), BRUTE_FORCE)), 1)
        self.assertEqual(detect(events(record(0), record(5), record(11)), config), [])

    def test_invalid_configuration_is_rejected(self):
        for field in ["window_seconds", "brute_force_threshold", "password_spray_threshold", "success_after_failures_threshold"]:
            for value in [0, -1, True, 1.5, "5"]:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    EngineConfig(**{field: value})

    def test_earliest_supported_timestamp_does_not_underflow(self):
        data = events(*(record(i) for i in range(5)))
        early = [replace(event, timestamp=event.timestamp.replace(year=1, month=1, day=1)) for event in data]
        self.assertEqual(len(only(detect(early), BRUTE_FORCE)), 1)

    def test_alert_is_json_serializable(self):
        data = events(*(record(i) for i in range(5)))
        self.assertEqual(json.loads(json.dumps(detect(data)[0].to_dict()))["rule_id"], BRUTE_FORCE)


if __name__ == "__main__":
    unittest.main()
