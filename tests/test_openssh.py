from datetime import timedelta, timezone
import unittest

from tracesentinel import ValidationError, parse_openssh


class OpenSSHAdapterTests(unittest.TestCase):
    def test_failed_and_accepted_password_lines_are_normalized(self):
        text = "\n".join(
            [
                "Sep  9 12:34:55 edge-01 sshd[100]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2",
                "Sep  9 12:35:02 edge-01 sshd[101]: Accepted password for alice from 2001:0db8::10 port 22 ssh2",
            ]
        )
        events = parse_openssh(text, source="auth.log", year=2026)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, "auth_failure")
        self.assertEqual(events[0].username, "admin")
        self.assertEqual(events[0].source_ip, "203.0.113.10")
        self.assertEqual(events[0].host, "edge-01")
        self.assertEqual(events[0].line_number, 1)
        self.assertEqual(events[0].source, "auth.log")
        self.assertEqual(events[1].event_type, "auth_success")
        self.assertEqual(events[1].source_ip, "2001:db8::10")
        self.assertEqual(events[1].timestamp.isoformat(), "2026-09-09T12:35:02+00:00")

    def test_unmatched_lines_are_ignored_but_line_numbers_are_physical(self):
        text = "\n".join(
            [
                "Sep  9 12:00:00 edge-01 systemd[1]: Started ssh.service",
                "",
                "Sep  9 12:00:01 edge-01 sshd[1]: Failed publickey for alice from 203.0.113.8 port 22 ssh2",
                "Sep  9 12:00:02 edge-01 sshd[2]: Failed password for bob from 203.0.113.9 port 22 ssh2",
            ]
        )
        events = parse_openssh(text, source="/var/log/auth.log", year=2026)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].line_number, 4)
        self.assertEqual(events[0].event_id, "/var/log/auth.log:4")

    def test_timezone_is_applied_to_rfc3164_timestamp(self):
        events = parse_openssh(
            "Sep  9 12:00:00 edge sshd: Accepted password for alice from 192.0.2.4 port 22 ssh2",
            source="fixture",
            year=2026,
            timezone_info=timezone(timedelta(hours=8)),
        )
        self.assertEqual(events[0].timestamp.isoformat(), "2026-09-09T04:00:00+00:00")

    def test_invalid_ip_in_supported_message_is_reported_with_line(self):
        with self.assertRaisesRegex(ValidationError, r"auth.log:3: invalid source_ip"):
            parse_openssh(
                "\n\nSep  9 12:00:00 edge sshd: Failed password for alice from not-an-ip port 22 ssh2",
                source="auth.log",
                year=2026,
            )


if __name__ == "__main__":
    unittest.main()
