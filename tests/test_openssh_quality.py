from datetime import timedelta, timezone
import unittest

import tracesentinel
from tracesentinel.ingest import (
    ValidationError,
    parse_openssh,
    parse_openssh_result,
)


class OpenSSHParseQualityTests(unittest.TestCase):
    def test_quality_api_is_exported(self):
        self.assertIs(tracesentinel.parse_openssh_result, parse_openssh_result)
        self.assertIs(tracesentinel.OpenSSHParseResult, type(parse_openssh_result("", year=2026)))

    def test_result_accounts_for_blank_unmatched_and_events(self):
        text = "\n".join(
            [
                "",
                "Sep  9 12:00:00 edge systemd[1]: Started ssh.service",
                "Sep  9 12:00:01 edge sshd[1]: Failed publickey for alice from 203.0.113.8 port 22 ssh2",
                "Sep  9 12:00:02 edge sshd[2]: Accepted publickey for alice from 2001:db8::8 port 22 ssh2",
                "Sep  9 12:00:03 edge sshd[3]: Invalid user guest from 192.0.2.9 port 22",
            ]
        )
        result = parse_openssh_result(text, source="auth.log", year=2026)
        self.assertEqual(result.total_lines, 5)
        self.assertEqual(result.blank_lines, 1)
        self.assertEqual(result.unmatched_lines, 1)
        self.assertEqual(result.malformed_auth_lines, 0)
        self.assertEqual([event.event_type for event in result.events], ["auth_failure", "auth_success", "auth_failure"])
        self.assertEqual(result.events[2].username, "guest")

    def test_malformed_auth_line_is_counted_with_warning(self):
        result = parse_openssh_result(
            "Sep  9 12:00:00 edge sshd: Failed password for alice from not-an-ip port 22 ssh2",
            source="auth.log",
            year=2026,
        )
        self.assertEqual(result.total_lines, 1)
        self.assertEqual(result.malformed_auth_lines, 1)
        self.assertEqual(result.events, [])
        self.assertRegex(result.warnings[0], r"auth\.log:1: invalid source_ip")

    def test_malformed_auth_line_remains_strict_for_legacy_api(self):
        with self.assertRaisesRegex(ValidationError, r"auth\.log:1: invalid source_ip"):
            parse_openssh(
                "Sep  9 12:00:00 edge sshd: Failed password for alice from not-an-ip port 22 ssh2",
                source="auth.log",
                year=2026,
            )

    def test_unsupported_auth_method_is_not_silently_unmatched(self):
        result = parse_openssh_result(
            "Sep  9 12:00:00 edge sshd: Failed keyboard-interactive/pam for alice from 192.0.2.10 port 22 ssh2",
            source="auth.log",
            year=2026,
        )
        self.assertEqual(result.malformed_auth_lines, 1)
        self.assertEqual(result.unmatched_lines, 0)
        self.assertIn("unsupported or malformed", result.warnings[0])

    def test_invalid_rfc3164_date_is_counted(self):
        result = parse_openssh_result(
            "Feb 30 12:00:00 edge sshd: Accepted password for alice from 192.0.2.10 port 22 ssh2",
            source="auth.log",
            year=2026,
        )
        self.assertEqual(result.malformed_auth_lines, 1)
        self.assertRegex(result.warnings[0], r"invalid RFC 3164 timestamp")

    def test_result_applies_timezone(self):
        result = parse_openssh_result(
            "Sep  9 12:00:00 edge sshd: Accepted password for alice from 192.0.2.10 port 22 ssh2",
            year=2026,
            timezone_info=timezone(timedelta(hours=8)),
        )
        self.assertEqual(result.events[0].timestamp.isoformat(), "2026-09-09T04:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
