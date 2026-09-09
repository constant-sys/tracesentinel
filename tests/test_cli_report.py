"""Exercise the public CLI and untrusted content crossing into HTML reports."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tracesentinel.cli import main
from tracesentinel.engine import EngineConfig, detect
from tracesentinel.ingest import parse_jsonl
from tracesentinel.report import build_report, render_html


PROJECT = Path(__file__).resolve().parents[1]


def fixture(*, username="研究员", host="lab-01"):
    records = []
    for second in range(6):
        records.append({
            "timestamp": f"2026-09-09T00:00:0{second}Z",
            "event_type": "auth_failure" if second < 5 else "auth_success",
            "source_ip": "192.0.2.10",
            "username": username,
            "host": host,
        })
    return "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n"


class ParsedHTML(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)


class CLIReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "auth.jsonl"
        self.output = self.root / "results"

    def run_cli(self, *extra, source=None, output=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main([
                "analyze", str(source or self.source),
                "--output", str(output or self.output), *extra,
            ])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_module_cli_writes_usable_reports_with_source_evidence(self):
        self.source.write_text(fixture(), encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, "-m", "tracesentinel", "analyze", str(self.source),
             "--output", str(self.output)],
            cwd=PROJECT, capture_output=True, text=True, encoding="utf-8", check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Analyzed 6 events; found 2 alerts.", completed.stdout)
        report = json.loads((self.output / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["events"], 6)
        self.assertEqual(report["summary"]["by_rule"], {"TS-AUTH-001": 1, "TS-AUTH-003": 1})
        self.assertEqual(report["alerts"][-1]["evidence"][-1]["event_id"], "auth.jsonl:6")
        self.assertEqual(report["alerts"][0]["username"], "研究员")
        page = (self.output / "report.html").read_text(encoding="utf-8")
        self.assertIn("研究员", page)
        self.assertIn(report["alerts"][0]["alert_id"], page)

    def test_output_is_byte_identical_and_hash_identifies_original_bytes(self):
        raw = b"\xef\xbb\xbf" + fixture().replace("\n", "\r\n").encode("utf-8")
        self.source.write_bytes(raw)
        self.assertEqual(self.run_cli()[0], 0)
        first = {path.name: path.read_bytes() for path in self.output.iterdir()}
        self.assertEqual(self.run_cli()[0], 0)
        second = {path.name: path.read_bytes() for path in self.output.iterdir()}
        self.assertEqual(first, second)
        report = json.loads(first["report.json"])
        self.assertEqual(report["source_sha256"], sha256(raw).hexdigest())
        self.assertNotEqual(report["source_sha256"], sha256(fixture().encode("utf-8")).hexdigest())
        self.assertEqual(self.source.read_bytes(), raw)

    def test_invalid_input_never_creates_output(self):
        surrogate_record = fixture().replace("研究员", "\\ud800").encode("utf-8")
        for raw in [b"{broken\n", b"\xff\xfe", b'{}\n', fixture().encode() + b'{broken\n', surrogate_record]:
            with self.subTest(raw=raw[:20]):
                self.source.write_bytes(raw)
                code, stdout, stderr = self.run_cli()
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertIn("error:", stderr)
                self.assertFalse(self.output.exists())
                self.assertEqual(self.source.read_bytes(), raw)

    def test_invalid_input_preserves_existing_reports(self):
        self.output.mkdir()
        for name in ["report.json", "report.html"]:
            (self.output / name).write_bytes(b"previous report")
        self.source.write_bytes(b"not json")
        self.assertEqual(self.run_cli()[0], 2)
        for name in ["report.json", "report.html"]:
            self.assertEqual((self.output / name).read_bytes(), b"previous report")

    def test_missing_input_and_invalid_config_do_not_create_output(self):
        self.assertEqual(self.run_cli()[0], 2)
        self.assertFalse(self.output.exists())
        self.source.write_text(fixture(), encoding="utf-8")
        for option in ["--window", "--threshold"]:
            with self.subTest(option=option):
                self.assertEqual(self.run_cli(option, "0")[0], 2)
                self.assertFalse(self.output.exists())

    def test_direct_input_output_collision_is_rejected(self):
        for name in ["report.json", "report.html"]:
            with self.subTest(name=name):
                directory = self.root / name.replace(".", "-")
                directory.mkdir()
                source = directory / name
                raw = fixture().encode("utf-8")
                source.write_bytes(raw)
                code, _, stderr = self.run_cli(source=source, output=directory)
                self.assertEqual(code, 2)
                self.assertIn("overwrite the input", stderr)
                self.assertEqual(source.read_bytes(), raw)
                self.assertEqual(list(directory.iterdir()), [source])

    def test_hard_link_to_input_is_not_overwritten(self):
        raw = fixture().encode("utf-8")
        self.source.write_bytes(raw)
        self.output.mkdir()
        target = self.output / "report.json"
        try:
            os.link(self.source, target)
        except OSError as exc:
            self.skipTest(f"Hard links are unavailable: {exc}")
        code, _, stderr = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("overwrite the input", stderr)
        self.assertEqual(self.source.read_bytes(), raw)
        self.assertFalse((self.output / "report.html").exists())

    def test_empty_input_produces_explicit_no_findings_report(self):
        self.source.write_bytes(b"\n\n")
        self.assertEqual(self.run_cli()[0], 0)
        report = json.loads((self.output / "report.json").read_bytes())
        self.assertEqual(report["summary"], {"events": 0, "alerts": 0, "by_rule": {}})
        page = (self.output / "report.html").read_text(encoding="utf-8")
        self.assertIn("No rules triggered", page)
        self.assertIn("does not establish that the input is safe", page)


class HTMLSafetyTests(unittest.TestCase):
    def test_log_fields_are_visible_text_and_never_active_html(self):
        attack = '<img src="https://invalid.example/x" onerror="alert(1)"><script>alert(2)</script>&\''
        events = parse_jsonl(fixture(username=attack, host=attack), source=attack)
        config = EngineConfig()
        report = build_report(events, detect(events, config), config, source=attack, source_sha256="a" * 64)
        # Exercise the escaping boundary even for strings supplied by future rule plugins.
        report["alerts"][0]["title"] = attack
        report["alerts"][0]["details"]["interpretation"] = attack
        page = render_html(report)
        parsed = ParsedHTML(page)
        tags = [tag for tag, _ in parsed.tags]
        self.assertNotIn("script", tags)
        self.assertNotIn("img", tags)
        self.assertIn(attack, "".join(parsed.text))
        self.assertIn("&lt;script&gt;", page)
        for _, attrs in parsed.tags:
            self.assertFalse(any(name.startswith("on") for name in attrs))

    def test_report_is_self_contained_and_has_restrictive_csp(self):
        config = EngineConfig()
        report = build_report([], [], config, source="empty.jsonl", source_sha256="b" * 64)
        page = render_html(report)
        parsed = ParsedHTML(page)
        for tag, attrs in parsed.tags:
            self.assertNotIn(tag, {"script", "iframe", "object", "embed", "link", "form"})
            self.assertFalse({"src", "srcset", "href", "action"} & attrs.keys())
        csp = next(attrs["content"] for tag, attrs in parsed.tags
                   if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("base-uri 'none'", csp)
        self.assertIn("form-action 'none'", csp)
        self.assertNotIn("@import", page.lower())
        self.assertNotIn("url(", page.lower())


if __name__ == "__main__":
    unittest.main()
