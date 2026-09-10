"""Portable, deterministic evaluation summary with literal untrusted labels."""


def _literal(value):
    # Numeric entities preserve visible text without activating Markdown or HTML.
    return "".join(char if char.isalnum() or char == " " else f"&#{ord(char)};"
                   for char in str(value))


def _percent(value):
    return "N/A" if value is None else f"{value:.1%}"


def render_evaluation_markdown(report):
    dataset, summary = report["dataset"], report["summary"]
    lines = [
        "# TraceSentinel · Detection evaluation", "",
        f"Dataset: **{_literal(dataset['id'])}** · tool version {_literal(report['tool_version'])}", "",
        _literal(dataset["description"]), "",
        "**Synthetic regression scenarios. These results do not estimate production accuracy.**", "",
        f"{summary['scenarios']} scenarios · {summary['events']} events · "
        f"{summary['evaluated_pairs']} scenario-rule pairs · {summary['alerts']} raw alerts", "",
        f"Input SHA-256: `{dataset['sha256']}`", "",
        "## Measurement", "",
        "Each scenario runs independently. For each of the three rules, at least one alert means "
        "a positive prediction. Repeated alerts count once per scenario-rule pair. Labels express "
        "authored scenario intent and are independent of the configured threshold. "
        "All raw alerts and their event indices remain in evaluation.json.", "",
        "A matching rule anywhere in a scenario counts as a hit; identity, timing and evidence "
        "accuracy are not scored here. N/A means a zero denominator. Overall metrics sum the "
        "counts from all rules before dividing (micro aggregation).", "",
        "| Rule | TP | FP | FN | TN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, metrics in [("Overall", report["metrics"]), *sorted(report["by_rule"].items())]:
        lines.append(f"| {name} | {metrics['tp']} | {metrics['fp']} | {metrics['fn']} | {metrics['tn']} | "
                     f"{_percent(metrics['precision'])} | {_percent(metrics['recall'])} | {_percent(metrics['f1'])} |")
    lines += ["", "## Configuration", "", "| Parameter | Value |", "|---|---:|"]
    lines += [f"| {_literal(key)} | {value} |" for key, value in sorted(report["config"].items())]
    lines += ["", "## Scenario results", "",
              "| Scenario | Expected rules | Predicted rules | False positives | False negatives |",
              "|---|---|---|---|---|"]
    for item in report["scenarios"]:
        def names(key):
            return ", ".join(item[key]) or "—"
        lines.append(f"| {_literal(item['id'])} | {names('expected_rules')} | {names('predicted_rules')} | "
                     f"{names('false_positive_rules')} | {names('false_negative_rules')} |")
    lines += ["", "## Scenario intent", ""]
    lines += [f"- **{_literal(item['id'])}**: {_literal(item['description'])}" for item in report["scenarios"]]
    lines += ["", "## Limits", "",
              "This hand-authored corpus is small, intentionally includes known failure cases, "
              "and is neither a representative sample nor a held-out test set. Its benign/malicious "
              "labels include contextual knowledge unavailable to the detector. Do not tune and "
              "claim general accuracy on the same cases. It evaluates normalized-event rule behavior; "
              "OpenSSH parsing, ingestion loss, incident matching and production false-positive rates "
              "require separate evaluation.", ""]
    return "\n".join(lines)
