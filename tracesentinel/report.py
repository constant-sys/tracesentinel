"""Portable reports. Event content is untrusted and always HTML-escaped."""
from collections import Counter
from dataclasses import asdict
from html import escape
import json

from . import __version__


def build_report(events, alerts, config, *, source, source_sha256, parser=None):
    report = {
        "schema_version": "1.0", "tool_version": __version__,
        "source": source, "source_sha256": source_sha256,
        "config": asdict(config),
        "summary": {"events": len(events), "alerts": len(alerts),
                    "by_rule": dict(sorted(Counter(a.rule_id for a in alerts).items()))},
        "alerts": [alert.to_dict() for alert in alerts],
    }
    if parser is not None:
        report["parser"] = parser
    return report


def render_json(report):
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"


def render_html(report):
    def e(value):
        return escape(str(value), quote=True)

    cards = []
    for alert in report["alerts"]:
        rows = "".join(
            f'<tr><td>{e(item["line_number"])}</td><td>{e(item["timestamp"])}</td>'
            f'<td>{e(item["event_type"])}</td><td>{e(item["username"])}</td></tr>'
            for item in alert["evidence"]
        )
        details = e(json.dumps(alert["details"], ensure_ascii=False, indent=2))
        cards.append(f'''<article data-severity="{e(alert['severity'])}">
<div class="tag">{e(alert['rule_id'])} · {e(alert['severity']).upper()}</div>
<h2>{e(alert['title'])}</h2><p>{e(alert['source_ip'])} → {e(alert['host'])}
 · Account: {e(alert['username'] or 'multiple')}</p>
<p class="muted">{e(alert['start'])} — {e(alert['end'])} · ID {e(alert['alert_id'])}</p>
<details open><summary>Evidence · {len(alert['evidence'])} events</summary>
<div class="scroll"><table><thead><tr><th>Input line</th><th>Time (UTC)</th><th>Event</th><th>Account</th></tr></thead>
<tbody>{rows}</tbody></table></div></details>
<details><summary>Detection parameters & interpretation</summary><pre>{details}</pre></details></article>''')
    cards_html = "\n".join(cards) or '<article><h2>No rules triggered</h2><p>This does not establish that the input is safe.</p></article>'
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>TraceSentinel · Investigation report</title>
<style>
:root{{color-scheme:dark;--bg:#0b1220;--panel:#121f33;--line:#2b3b53;--fg:#e7edf7;--muted:#9dadc6;--accent:#58ddc0}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,sans-serif}}
main{{max-width:1100px;margin:auto;padding:48px 24px}}header{{border-top:4px solid var(--accent);padding-top:24px}}
.eyebrow,.tag{{font-size:12px;letter-spacing:.12em;color:var(--accent);font-weight:700}}
h1{{font-size:clamp(30px,5vw,48px);letter-spacing:-.04em;margin:8px 0}}h2{{font-size:21px;margin:8px 0}}
.muted{{color:var(--muted);overflow-wrap:anywhere}}.metrics{{display:flex;gap:16px;margin:24px 0;flex-wrap:wrap}}
.metric,article{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px}}
.metric{{flex:1;min-width:180px}}.metric strong{{display:block;font-size:36px;line-height:1.2}}
article{{margin:18px 0;overflow-wrap:anywhere}}article[data-severity=high]{{border-left:4px solid #f8a16c}}
.scroll{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;text-align:left;margin-top:12px;white-space:nowrap}}
td,th{{padding:10px 12px;border-bottom:1px solid var(--line)}}th{{color:var(--muted);font-size:12px}}
summary{{cursor:pointer;color:var(--accent);padding:12px 0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
footer{{font-size:13px;color:var(--muted);padding-top:16px}}code{{overflow-wrap:anywhere}}
</style></head><body><main><header><div class="eyebrow">TRACESENTINEL / AUTHENTICATION TELEMETRY</div>
<h1>From login traces to evidence.</h1><p class="muted">Offline investigation report · v{e(report['tool_version'])}</p></header>
<div class="metrics"><div class="metric"><strong>{report['summary']['events']}</strong>events analyzed</div>
<div class="metric"><strong>{report['summary']['alerts']}</strong>findings to investigate</div>
<div class="metric"><strong>{report['config']['window_seconds']}s</strong>inclusive detection window</div></div>
<p class="muted">Source: {e(report['source'])}<br>SHA-256: <code>{e(report['source_sha256'])}</code></p>
{_render_parser_summary(report, e)}
{cards_html}<article><h2>Investigation checklist</h2><p>Validate expected user activity and source ownership.
Correlate with MFA, endpoint and subsequent session events. Check shared egress and automation before escalating.
Preserve the original log and compare its SHA-256 with this report.</p></article>
<footer>Heuristic findings are leads, not confirmation of compromise. Multiple rules may describe one sequence.
Password values are not available: a multi-account burst only suggests spraying.
Generated locally; this report contains no scripts, remote fonts or analytics.</footer></main></body></html>\n'''


def _render_parser_summary(report, escape_value):
    parser = report.get("parser")
    if not parser:
        return ""
    rows = "".join(
        f"<tr><th>{escape_value(key)}</th><td>{escape_value(value)}</td></tr>"
        for key, value in parser.items()
        if key != "warnings"
    )
    warnings = parser.get("warnings", [])
    warning_html = ""
    if warnings:
        items = "".join(f"<li>{escape_value(item)}</li>" for item in warnings)
        warning_html = f"<details><summary>Parser warnings · {len(warnings)}</summary><ul>{items}</ul></details>"
    return (
        '<article><h2>Input parser accounting</h2>'
        '<p class="muted">These counts explain which physical lines became normalized events.</p>'
        f'<div class="scroll"><table><tbody>{rows}</tbody></table></div>{warning_html}</article>'
    )
