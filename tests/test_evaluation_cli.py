"""Public evaluation workflow: fixed ground truth, changing thresholds, safe output."""
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tracesentinel.cli import main

PROJECT = Path(__file__).resolve().parents[1]
DATASET = PROJECT / "examples/evaluation/auth-synthetic-v1.json"


class EvaluationCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "results"

    def run_cli(self, *extra, source=DATASET, output=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["evaluate", str(source), "--output", str(output or self.output), *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def read_report(self):
        return json.loads((self.output / "evaluation.json").read_bytes())

    def test_fixed_ground_truth_catches_known_false_positives_and_misses(self):
        completed = subprocess.run(
            [sys.executable, "-m", "tracesentinel", "evaluate", str(DATASET), "--output", str(self.output)],
            cwd=PROJECT, capture_output=True, text=True, encoding="utf-8", check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("TP=6 FP=4 FN=2 TN=24", completed.stdout)
        report = self.read_report()
        self.assertEqual(report["summary"], {"scenarios": 12, "events": 64, "alerts": 11, "evaluated_pairs": 36})
        self.assertEqual(report["dataset"]["sha256"], sha256(DATASET.read_bytes()).hexdigest())
        self.assertEqual(report["metrics"]["precision"], .6)
        self.assertEqual(report["metrics"]["recall"], .75)
        self.assertAlmostEqual(report["metrics"]["f1"], 2 / 3)
        cases = {case["id"]: case for case in report["scenarios"]}
        self.assertEqual(cases["slow-guessing"]["false_negative_rules"], ["TS-AUTH-001"])
        self.assertEqual(cases["distributed-spray"]["false_negative_rules"], ["TS-AUTH-002"])
        self.assertEqual(cases["benign-shared-nat"]["false_positive_rules"], ["TS-AUTH-002"])
        self.assertEqual(len(cases["two-guessing-bursts"]["alerts"]), 2)
        self.assertEqual(cases["two-guessing-bursts"]["predicted_rules"], ["TS-AUTH-001"])

    def test_raising_threshold_reduces_false_positives_but_misses_more_labels(self):
        self.assertEqual(self.run_cli("--threshold", "6")[0], 0)
        report = self.read_report()
        counts = {name: report["metrics"][name] for name in ("tp", "fp", "fn", "tn")}
        self.assertEqual(counts, {"tp": 2, "fp": 0, "fn": 6, "tn": 28})
        self.assertEqual(report["metrics"]["recall"], .25)
        self.assertEqual(report["config"]["brute_force_threshold"], 6)

    def test_longer_window_recovers_slow_guessing_without_changing_labels(self):
        self.assertEqual(self.run_cli("--window", "600")[0], 0)
        report = self.read_report()
        self.assertEqual(report["metrics"]["tp"], 7)
        self.assertEqual(report["metrics"]["fn"], 1)
        self.assertEqual(report["metrics"]["fp"], 4)

    def test_output_is_deterministic_and_markdown_records_methodology(self):
        self.assertEqual(self.run_cli()[0], 0)
        first = {p.name: p.read_bytes() for p in self.output.iterdir()}
        self.assertEqual(self.run_cli()[0], 0)
        self.assertEqual(first, {p.name: p.read_bytes() for p in self.output.iterdir()})
        markdown = first["evaluation.md"].decode()
        for phrase in ("60.0%", "75.0%", "scenario-rule", "production accuracy", "two&#45;guessing&#45;bursts"):
            self.assertIn(phrase, markdown)

    def test_invalid_input_or_configuration_does_not_touch_prior_reports(self):
        self.assertEqual(self.run_cli()[0], 0)
        first = {p.name: p.read_bytes() for p in self.output.iterdir()}
        source = self.root / "bad.json"
        source.write_bytes(b'{"scenarios":[]}')
        self.assertEqual(self.run_cli(source=source)[0], 2)
        self.assertEqual(first, {p.name: p.read_bytes() for p in self.output.iterdir()})
        for option in ("--window", "--threshold"):
            self.assertEqual(self.run_cli(option, "0")[0], 2)
        self.assertEqual(first, {p.name: p.read_bytes() for p in self.output.iterdir()})
        self.assertEqual(self.run_cli(source=self.root / "missing.json", output=self.root / "absent")[0], 2)
        self.assertFalse((self.root / "absent").exists())

    def test_dataset_cannot_be_overwritten_by_output_or_hard_link(self):
        self.output.mkdir()
        source = self.output / "evaluation.json"
        raw = DATASET.read_bytes()
        source.write_bytes(raw)
        self.assertEqual(self.run_cli(source=source)[0], 2)
        self.assertEqual(source.read_bytes(), raw)
        other_output = self.root / "linked"
        other_output.mkdir()
        try:
            os.link(source, other_output / "evaluation.md")
        except OSError as exc:
            self.skipTest(f"Hard links unavailable: {exc}")
        self.assertEqual(self.run_cli(source=source, output=other_output)[0], 2)
        self.assertEqual(source.read_bytes(), raw)
        self.assertFalse((other_output / "evaluation.json").exists())

    def test_untrusted_description_is_literal_in_markdown(self):
        dataset = json.loads(DATASET.read_bytes())
        attack = '<img src=x onerror=alert(1)>[link](https://example.com) | **text**'
        dataset["description"] = attack
        dataset["scenarios"][0]["description"] = attack
        source = self.root / "text.json"
        source.write_text(json.dumps(dataset), encoding="utf-8")
        self.assertEqual(self.run_cli(source=source)[0], 0)
        markdown = (self.output / "evaluation.md").read_text(encoding="utf-8")
        self.assertNotIn(attack, markdown)
        self.assertNotIn("<img", markdown)
        self.assertNotIn("[link]", markdown)
        self.assertIn("&#60;img", markdown)
        self.assertEqual(self.read_report()["dataset"]["description"], attack)


if __name__ == "__main__":
    unittest.main()
