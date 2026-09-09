"""Command-line entry point with repeatable, offline output."""
import argparse
from hashlib import sha256
from pathlib import Path
import sys

from . import __version__
from .engine import EngineConfig, detect
from .ingest import parse_jsonl
from .report import build_report, render_html, render_json


def main(argv=None):
    parser = argparse.ArgumentParser(description="Investigate normalized authentication JSONL locally.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Detect suspicious authentication sequences")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--output", type=Path, default=Path("output"))
    analyze.add_argument("--window", type=int, default=300, help="Inclusive window in seconds")
    analyze.add_argument("--threshold", type=int, default=5, help="Failure/distinct-account threshold")
    args = parser.parse_args(argv)
    try:
        config = EngineConfig(window_seconds=args.window, brute_force_threshold=args.threshold,
                              password_spray_threshold=args.threshold,
                              success_after_failures_threshold=args.threshold)
        # Hash and parse the same bytes so evidence identifies exactly the analyzed input.
        raw = args.input.read_bytes()
        events = parse_jsonl(raw.decode("utf-8-sig"), source=args.input.name)
        alerts = detect(events, config)
        report = build_report(events, alerts, config, source=args.input.name,
                              source_sha256=sha256(raw).hexdigest())
        targets = [args.output / "report.json", args.output / "report.html"]
        if any(target.resolve() == args.input.resolve()
               or (target.exists() and target.samefile(args.input)) for target in targets):
            raise ValueError("output must not overwrite the input file")
        # Complete encoding before creating output, too: a rendering error must
        # not leave behind a directory or a truncated previous report.
        rendered = [render_json(report).encode("utf-8"), render_html(report).encode("utf-8")]
        args.output.mkdir(parents=True, exist_ok=True)
        for target, content in zip(targets, rendered):
            target.write_bytes(content)
        print(f"Analyzed {len(events)} events; found {len(alerts)} alerts.")
        print(f"Reports: {args.output / 'report.json'} and {args.output / 'report.html'}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
