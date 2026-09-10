"""Command-line entry point with repeatable, offline output."""
import argparse
from hashlib import sha256
from pathlib import Path
import sys

from . import __version__
from .engine import EngineConfig, detect
from .evaluation import evaluate_dataset
from .evaluation_report import render_evaluation_markdown
from .ingest import parse_jsonl, parse_openssh
from .report import build_report, render_html, render_json


def main(argv=None):
    parser = argparse.ArgumentParser(description="Investigate authentication logs and evaluate detection scenarios locally.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Detect suspicious authentication sequences")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--output", type=Path, default=Path("output"))
    analyze.add_argument("--window", type=int, default=300, help="Inclusive window in seconds")
    analyze.add_argument("--threshold", type=int, default=5, help="Failure/distinct-account threshold")
    analyze.add_argument("--format", choices=("jsonl", "openssh"), default="jsonl",
                         help="Input format (default: jsonl)")
    analyze.add_argument("--year", type=int, help="Year for OpenSSH RFC 3164 timestamps")
    evaluate = commands.add_parser("evaluate", help="Evaluate a labeled synthetic JSON scenario dataset")
    evaluate.add_argument("input", type=Path)
    evaluate.add_argument("--output", type=Path, default=Path("output/evaluation"))
    evaluate.add_argument("--window", type=int, default=300, help="Inclusive window in seconds")
    evaluate.add_argument("--threshold", type=int, default=5, help="Failure/distinct-account threshold")
    args = parser.parse_args(argv)
    try:
        config = EngineConfig(window_seconds=args.window, brute_force_threshold=args.threshold,
                              password_spray_threshold=args.threshold,
                              success_after_failures_threshold=args.threshold)
        if args.command == "evaluate":
            report = evaluate_dataset(args.input, config)
            targets = [args.output / "evaluation.json", args.output / "evaluation.md"]
            rendered = [render_json(report), render_evaluation_markdown(report)]
            _write_reports(args.input, args.output, targets, rendered)
            metrics = report["metrics"]
            print(f"Evaluated {report['summary']['scenarios']} scenarios "
                  f"({report['summary']['evaluated_pairs']} scenario-rule pairs).")
            print(f"TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} TN={metrics['tn']}")
            print(f"Reports: {targets[0]} and {targets[1]}")
            return 0
        # Hash and parse the same bytes so evidence identifies exactly the analyzed input.
        raw = args.input.read_bytes()
        decoded = raw.decode("utf-8-sig")
        if args.format == "openssh":
            events = parse_openssh(decoded, source=args.input.name, year=args.year)
        else:
            events = parse_jsonl(decoded, source=args.input.name)
        alerts = detect(events, config)
        report = build_report(events, alerts, config, source=args.input.name,
                              source_sha256=sha256(raw).hexdigest())
        targets = [args.output / "report.json", args.output / "report.html"]
        _write_reports(args.input, args.output, targets, [render_json(report), render_html(report)])
        print(f"Analyzed {len(events)} events; found {len(alerts)} alerts.")
        print(f"Reports: {args.output / 'report.json'} and {args.output / 'report.html'}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _write_reports(source, output, targets, contents):
    if any(target.resolve() == source.resolve()
           or (target.exists() and target.samefile(source)) for target in targets):
        raise ValueError("output must not overwrite the input file")
    # Finish rendering and encoding before touching previous reports.
    rendered = [content.encode("utf-8") for content in contents]
    output.mkdir(parents=True, exist_ok=True)
    for target, content in zip(targets, rendered):
        target.write_bytes(content)
