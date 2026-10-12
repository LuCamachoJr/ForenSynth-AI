"""Render deterministic evidence and separately identified AI interpretations."""

import csv
import html
from collections import Counter

from .evidence import stable_id


def baseline_findings(detections):
    # Keep source-backed facts modest: rule matches do not establish malicious intent.
    groups = {}
    for d in detections:
        groups.setdefault((d["rule_id"], d["rule_name"]), []).append(d)
    return [
        {
            "id": stable_id("finding", [key, [d["id"] for d in group]]),
            "statement": f"Rule '{key[1]}' matched {len(group)} detection record(s).",
            "evidence_refs": [d["id"] for d in group],
            "classification": "observed",
            "confidence": "high",
            "confidence_rationale": "Count calculated from retained detections.",
            "alternative_explanations": [
                "A rule match may represent authorized or benign activity."
            ],
            "review_status": "pending",
            "origin": "deterministic",
        }
        for key, group in sorted(groups.items(), key=lambda item: str(item[0]))
    ]


def markdown(doc):
    coverage = doc["run"]["coverage"]
    timestamps = sorted(e["timestamp_utc"] for e in doc["events"] if e["timestamp_utc"])
    hosts = sorted({e["host"] for e in doc["events"] if e["host"]})
    lines = [
        "# ForenSynth AI v2.4 — Evidence Review",
        "",
        f"Case: {doc['case']['id']} | Environment: {doc['case']['environment']}",
        f"Generated: {doc['run']['generated_at']}",
        "",
        "## Scope and coverage",
        "",
        f"- Input records: {coverage['raw_records']}; parsed: {coverage['parsed_records']}; rejected: {coverage['rejected_records']}",
        f"- Detection matches: {len(doc['detections'])}; unique retained events: {len(doc['events'])}",
        f"- AI selected: {len(coverage['selected_detection_ids'])}; processed: {len(coverage['ai_processed_detection_ids'])}; skipped: {len(coverage['ai_skipped_detection_ids'])}",
        f"- Omitted from AI selection: {len(coverage['omitted_detection_ids'])}; evidence exports retain all parsed records.",
        f"- Observed hosts: {', '.join(hosts) or 'Unavailable'}",
        f"- Event time range: {timestamps[0] + ' to ' + timestamps[-1] if timestamps else 'Unavailable'}",
        "",
        "A detection match is not proof of compromise. No remediation is executed. AI findings remain pending analyst review.",
        "Evidence references establish traceability, not semantic correctness. Missing telemetry limits scope conclusions.",
        "",
        "## Findings",
        "",
    ]
    for finding in doc["findings"]:
        lines.extend(
            [
                f"### {finding['id']}",
                finding["statement"],
                "",
                f"Classification: {finding['classification']} | Origin: {finding['origin']} | Review: {finding['review_status']}",
                f"Confidence: {finding['confidence']} — {finding['confidence_rationale']}",
                "Evidence: " + ", ".join(finding["evidence_refs"]),
                "Alternatives: " + "; ".join(finding["alternative_explanations"]),
                "",
            ]
        )
    if not doc["findings"]:
        lines.extend(
            ["No detection matches; this does not establish absence of malicious activity.", ""]
        )
    lines.extend(
        [
            "## ATT&CK mappings",
            "",
            "Mappings are supplied Sigma tags, not confirmed adversary behavior.",
            "",
        ]
    )
    counts = Counter(t for d in doc["detections"] for t in d["technique_ids"])
    lines.extend(
        f"- {technique}: {count} detection matches" for technique, count in sorted(counts.items())
    )
    lines.extend(["", "## Warnings", ""] + [f"- {w}" for w in doc["run"]["warnings"]])
    ai = doc["run"]["ai"]
    lines.extend(
        [
            "",
            "## AI usage",
            "",
            f"Mode: {ai.get('mode', 'off')}",
            f"Successful-response token usage: {ai.get('usage', {})}",
            f"Estimated cost (configured rates): {ai.get('estimated_cost_usd', 'unknown')}",
            "Provider billing may differ, including calls without returned usage.",
            "",
        ]
    )
    return "\n".join(lines)


def html_report(doc, md):
    # Escape all telemetry and AI text; no untrusted data is inserted into scripts.
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>ForenSynth Evidence Review</title><style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#f6f8fc;color:#17243a}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:2rem;border:1px solid #dde4ef;border-radius:12px}</style><body><pre>'
        + html.escape(md)
        + "</pre></body></html>"
    )


def csv_cell(value):
    text = str(value or "")
    # Spreadsheet formula injection mitigation; original values remain in evidence.json.
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def write_csv(path, doc):
    events = {e["id"]: e for e in doc["events"]}
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "detection_id",
                "event_ref",
                "timestamp_utc",
                "host",
                "provider",
                "channel",
                "event_id",
                "record_id",
                "rule",
                "severity",
                "techniques",
                "artifact_ref",
            ]
        )
        for d in doc["detections"]:
            for ref in d["event_refs"]:
                e = events[ref]
                writer.writerow(
                    [
                        csv_cell(x)
                        for x in (
                            d["id"],
                            ref,
                            e["timestamp_utc"],
                            e["host"],
                            e["provider"],
                            e["channel"],
                            e["event_id"],
                            e["record_id"],
                            d["rule_name"],
                            d["severity"],
                            ";".join(d["technique_ids"]),
                            e["artifact_ref"],
                        )
                    ]
                )
