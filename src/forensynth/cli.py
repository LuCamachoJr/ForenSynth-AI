"""v2.4 command line: deterministic reports by default, explicitly opt-in cloud AI."""

from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .evidence import load_detections, normalize, select_detections, sha256, stable_id
from .integrity import verify_run
from .report import baseline_findings, html_report, markdown, write_csv
from .stix_export import build_bundle
from .validation import validate_document


def parser():
    p = argparse.ArgumentParser(description="ForenSynth AI v2.4 evidence review beta")
    source = p.add_mutually_exclusive_group(required=False)
    source.add_argument("--input", type=Path, help="Existing Chainsaw detection JSON or JSONL")
    source.add_argument(
        "--evtx-root", type=Path, help="EVTX file or directory to hunt with Chainsaw"
    )
    source.add_argument("--verify-run", type=Path, help="Verify a completed run's SHA-256 manifest")
    p.add_argument("--rules", type=Path, help="Sigma rules file/directory (EVTX mode)")
    p.add_argument("--mapping", type=Path, help="Chainsaw mapping file (EVTX mode)")
    p.add_argument("--chainsaw", default="chainsaw", help="Chainsaw executable")
    p.add_argument("--chainsaw-timeout", type=int, default=600)
    p.add_argument("--outdir", type=Path, default=Path("reports"))
    p.add_argument("--case-id", default="unassigned")
    p.add_argument(
        "--environment", choices=["unknown", "production", "lab", "simulation"], default="unknown"
    )
    p.add_argument("--authorized-test", action="store_true", default=None)
    p.add_argument("--scope", default="Supplied detection export / EVTX sources only")
    p.add_argument(
        "--allow-rejected", action="store_true", help="Continue with explicit rejected-record audit"
    )
    p.add_argument("--html", "--make-html", action="store_true", dest="html")
    p.add_argument("--export-evidence-csv", action="store_true")
    p.add_argument("--export-stix", action="store_true")
    p.add_argument(
        "--indicator-reviews", type=Path, help="Analyst-reviewed observable assessments JSON"
    )
    p.add_argument("--attack-data", type=Path, help="Pinned local ATT&CK STIX bundle")
    p.add_argument("--attack-version", help="Dataset version; required with --attack-data")
    p.add_argument(
        "--limit-detections",
        type=int,
        default=0,
        help="AI-only limit; all high/critical matches retained",
    )
    p.add_argument(
        "--ai",
        choices=["off", "cloud"],
        default="off",
        help="cloud explicitly authorizes sending selected evidence fields to OpenAI",
    )
    p.add_argument("--model", default="gpt-5-mini")
    p.add_argument("--max-input-tokens", type=int, default=16000)
    p.add_argument("--max-output-tokens", type=int, default=4096)
    p.add_argument("--max-total-tokens", type=int, default=100000)
    p.add_argument("--max-requests", type=int, default=20)
    p.add_argument("--llm-timeout", type=int, default=90)
    p.add_argument("--input-rate", type=float, help="Configured USD per million input tokens")
    p.add_argument("--output-rate", type=float, help="Configured USD per million output tokens")
    p.add_argument("--version", action="version", version=__version__)
    return p


def _git_commit(path):
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _artifact(path, kind, now, parent_ref=None):
    digest = sha256(path)
    return {
        "id": stable_id("artifact", [kind, digest]),
        "kind": kind,
        "path": str(path),
        "sha256": digest,
        "size_bytes": path.stat().st_size,
        "collected_at": now,
        "parent_ref": parent_ref,
    }


def run(args):
    if not args.input and not args.evtx_root:
        raise ValueError("Supply --input or --evtx-root")
    if args.limit_detections < 0:
        raise ValueError("--limit-detections must be nonnegative")
    for key in (
        "max_input_tokens",
        "max_output_tokens",
        "max_total_tokens",
        "max_requests",
        "llm_timeout",
        "chainsaw_timeout",
    ):
        if getattr(args, key) <= 0:
            raise ValueError(f"{key} must be positive")
    if bool(args.attack_data) != bool(args.attack_version):
        raise ValueError("--attack-data and --attack-version must be supplied together")
    if args.indicator_reviews and not args.export_stix:
        raise ValueError("--indicator-reviews requires --export-stix")
    if (args.input_rate is None) != (args.output_rate is None):
        raise ValueError("Supply both --input-rate and --output-rate, or neither")
    if any(
        value is not None and (value < 0 or not math.isfinite(value))
        for value in (args.input_rate, args.output_rate)
    ):
        raise ValueError("Pricing rates must be finite and nonnegative")
    if args.input and not args.input.is_file():
        raise ValueError("--input must be an existing file")
    if args.evtx_root and (
        not args.evtx_root.exists()
        or not args.rules
        or not args.mapping
        or not args.rules.exists()
        or not args.mapping.is_file()
    ):
        raise ValueError("EVTX mode requires existing --evtx-root, --rules and --mapping")
    args.outdir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    output = Path(
        tempfile.mkdtemp(
            prefix=datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%SZ_"), dir=args.outdir
        )
    ).resolve()
    artifacts = []
    warnings = []
    if args.evtx_root:
        evtx_files = (
            sorted(args.evtx_root.rglob("*.evtx")) if args.evtx_root.is_dir() else [args.evtx_root]
        )
        if not evtx_files:
            raise ValueError("No .evtx files found")
        for path in evtx_files:
            item = _artifact(path.resolve(), "evtx", now)
            if not any(a["id"] == item["id"] for a in artifacts):
                artifacts.append(item)
        chainsaw_out = output / "chainsaw.json"
        command = [
            args.chainsaw,
            "hunt",
            str(args.evtx_root.resolve()),
            "-s",
            str(args.rules.resolve()),
            "--mapping",
            str(args.mapping.resolve()),
            "--json",
            "--output",
            str(chainsaw_out),
        ]
        subprocess.run(command, check=True, timeout=args.chainsaw_timeout)
        if not chainsaw_out.is_file():
            raise ValueError("Chainsaw did not produce its JSON output file")
        for item in artifacts:
            if sha256(Path(item["path"])) != item["sha256"]:
                raise ValueError(
                    "EVTX source changed during collection; repeat with stable evidence"
                )
        source = chainsaw_out
    else:
        source = args.input
    # Preserve original bytes before parsing; no destructive source modification.
    snapshot = output / "input.original"
    shutil.copyfile(source, snapshot)
    input_artifact = _artifact(snapshot, "input", now)
    artifacts.append(input_artifact)
    detections, coverage = load_detections(snapshot, args.allow_rejected)
    canonical = output / "detections.json"
    canonical.write_text(
        json.dumps({"detections": detections}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    parsed_artifact = _artifact(canonical, "parsed_detections", now, input_artifact["id"])
    artifacts.append(parsed_artifact)
    events, matches, observables, issues = normalize(detections, parsed_artifact["id"])
    warnings.extend(issues)
    if coverage["rejected_records"]:
        warnings.append(
            "Some input records were rejected; source bytes and rejection locations are retained."
        )
    selected, selection = select_detections(matches, events, args.limit_detections)
    coverage.update(selection | {"ai_processed_detection_ids": [], "ai_skipped_detection_ids": []})
    if selection["limit_exceeded_for_protected"]:
        warnings.append(
            "AI selection limit exceeded to preserve all high/critical detections; request/token budgets still apply."
        )
    if selection["omitted_detection_ids"]:
        warnings.append(
            "AI input is sampled; conclusions cannot establish absence of omitted behavior."
        )
    doc = {
        "schema_version": "1.0.0",
        "case": {
            "id": args.case_id,
            "environment": args.environment,
            "authorized_test": args.authorized_test,
            "scope": args.scope,
        },
        "artifacts": artifacts,
        "events": events,
        "detections": matches,
        "observables": observables,
        "findings": baseline_findings(matches),
        "run": {
            "id": str(uuid.uuid4()),
            "generated_at": now,
            "version": __version__,
            "code_commit": _git_commit(Path(__file__).resolve().parents[2]),
            "ruleset_commit": _git_commit(args.rules.parent) if args.rules else None,
            "mapping_sha256": sha256(args.mapping) if args.mapping else None,
            "coverage": coverage,
            "warnings": warnings,
            "ai": {"mode": "off", "usage": {}, "estimated_cost_usd": None},
            "attack_dataset_version": args.attack_version,
        },
    }
    # Persist a recoverable deterministic result before any optional cloud operation.
    validate_document(doc)
    evidence_path = output / "evidence.json"
    evidence_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.ai == "cloud" and selected:
        from .llm import synthesize

        config = {
            "model": args.model,
            "max_input_tokens": args.max_input_tokens,
            "max_output_tokens": args.max_output_tokens,
            "max_total_tokens": args.max_total_tokens,
            "max_requests": args.max_requests,
            "timeout": args.llm_timeout,
            "input_rate": args.input_rate,
            "output_rate": args.output_rate,
        }
        try:
            findings, processed, skipped, meta, ai_warnings = synthesize(doc, selected, config)
            # Deduplicate identical AI findings without discarding evidence.
            doc["findings"].extend({f["id"]: f for f in findings}.values())
            coverage["ai_processed_detection_ids"] = processed
            coverage["ai_skipped_detection_ids"] = skipped
            doc["run"]["ai"] = meta
            warnings.extend(ai_warnings)
        except (ImportError, ValueError) as exc:
            warnings.append(f"Cloud synthesis unavailable: {exc}; deterministic report retained.")
            coverage["ai_skipped_detection_ids"] = [d["id"] for d in selected]
            doc["run"]["ai"] = {"mode": "cloud_failed", "usage": {}, "estimated_cost_usd": None}
    if args.export_stix:
        reviews = (
            json.loads(args.indicator_reviews.read_text(encoding="utf-8"))
            if args.indicator_reviews
            else []
        )
        if not isinstance(reviews, list):
            raise ValueError("Indicator reviews must be a JSON array")
        attack = (
            json.loads(args.attack_data.read_text(encoding="utf-8")) if args.attack_data else None
        )
        bundle, stix_warnings = build_bundle(doc, reviews, attack)
        warnings.extend(stix_warnings)
        (output / "stix_bundle.json").write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    validate_document(doc)
    evidence_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md = markdown(doc)
    (output / "report.md").write_text(md, encoding="utf-8")
    if args.html:
        (output / "report.html").write_text(html_report(doc, md), encoding="utf-8")
    if args.export_evidence_csv:
        write_csv(output / "evidence.csv", doc)
    # A manifest detects later changes; this is not a signed chain-of-custody system.
    manifest = {p.name: sha256(p) for p in output.iterdir() if p.is_file()}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return output, doc


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.verify_run:
            count = verify_run(args.verify_run)
            print(f"SHA-256 matches for {count} files; manifest is unsigned.")
            return 0
        output, doc = run(args)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"ForenSynth error: {exc}", file=sys.stderr)
        return 2
    print(f"Report: {output / 'report.md'}")
    print(f"Evidence: {len(doc['detections'])} matches / {len(doc['events'])} unique events")
    print(f"Warnings: {len(doc['run']['warnings'])}; review evidence.json for details")
    return 0
