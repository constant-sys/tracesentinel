# Changelog

## 0.3.1 — 2026-10-22

- Add OpenSSH parser accounting for total, blank, unmatched and malformed authentication lines.
- Add `parse_openssh_result` / `load_openssh_result` with publickey, `Invalid user` and line-specific warnings.
- Include parser statistics in JSON and offline HTML reports; surface malformed-line counts on the CLI.
- Preserve the strict legacy `parse_openssh` contract and add regression coverage for parser quality and report output.

## 0.3.0 — 2026-09-10

- Add `evaluate` with strict, self-contained synthetic datasets and scenario-rule binary metrics.
- Report TP/FP/FN/TN, precision, recall and F1 by rule and overall, with explicit undefined values.
- Retain input hash, actual configuration, scenario labels and complete alert evidence in deterministic JSON/Markdown reports.
- Add 12 authored scenarios exposing both false positives and false negatives, and threshold/window comparisons.
- Document the OpenSSH adapter from the preceding iteration and its remaining skipped-line/timezone limitations. That iteration was not separately versioned as a package release.

## 0.1.0 — 2026-09-09

- Add strict, timezone-aware normalized authentication JSONL ingestion.
- Detect single-account failures, multi-account failure bursts and success after failures.
- Export deterministic JSON and offline HTML with input hashes and source-line evidence.
- Include reproducible synthetic fixtures, automated tests and CI.
- Document detection limits, architecture, roadmap and learning exercises.
