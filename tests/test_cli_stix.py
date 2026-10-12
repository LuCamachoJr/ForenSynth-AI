import json
from pathlib import Path

import pytest
from stix2validator import ValidationOptions, validate_string

from forensynth.cli import main, parser, run
from forensynth.evidence import sha256
from forensynth.report import csv_cell, html_report
from forensynth.stix_export import build_bundle, validate_bundle_refs


def test_offline_cli_preserves_bytes_and_all_evidence(input_path, tmp_path):
    original = input_path.read_bytes()
    output, doc = run(
        parser().parse_args(
            [
                "--input",
                str(input_path),
                "--outdir",
                str(tmp_path / "out"),
                "--html",
                "--export-evidence-csv",
                "--export-stix",
                "--limit-detections",
                "1",
            ]
        )
    )
    assert (output / "input.original").read_bytes() == original == input_path.read_bytes()
    assert len(doc["detections"]) == 3 and len(doc["events"]) == 3
    assert len(doc["run"]["coverage"]["selected_detection_ids"]) == 1
    assert doc["run"]["ai"]["mode"] == "off"
    manifest = json.loads((output / "manifest.json").read_text())
    assert all(sha256(output / name) == digest for name, digest in manifest.items())
    bundle = json.loads((output / "stix_bundle.json").read_text())
    assert not any(o["type"] == "indicator" for o in bundle["objects"])
    validate_bundle_refs(bundle)
    assert validate_string(json.dumps(bundle), ValidationOptions(version="2.1")).is_valid


def test_same_day_runs_do_not_overwrite(input_path, tmp_path):
    args = parser().parse_args(["--input", str(input_path), "--outdir", str(tmp_path)])
    a, _ = run(args)
    b, _ = run(args)
    assert a != b and a.exists() and b.exists()


def test_stix_indicators_only_from_reviewed_observables(document):
    observable = next(o for o in document["observables"] if o["type"] == "url")
    review = {
        "observable_ref": observable["id"],
        "assessment": "malicious",
        "reviewer": "Fixture analyst",
        "rationale": "Synthetic test only",
        "confidence": 80,
    }
    bundle, _ = build_bundle(document, [review])
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert "\\'" in indicator["pattern"]
    assert any(o["type"] == "relationship" for o in bundle["objects"])
    assert validate_string(json.dumps(bundle), ValidationOptions(version="2.1")).is_valid


@pytest.mark.parametrize(
    "mutation",
    [
        {"assessment": "suspicious"},
        {"reviewer": ""},
        {"observable_ref": "unknown"},
        {"confidence": 101},
    ],
)
def test_invalid_indicator_review_rejected(document, mutation):
    review = {
        "observable_ref": document["observables"][0]["id"],
        "assessment": "malicious",
        "reviewer": "Analyst",
        "rationale": "Verified",
        "confidence": 80,
    } | mutation
    with pytest.raises(ValueError):
        build_bundle(document, [review])


def test_no_observation_timestamp_invented(document):
    for event in document["events"]:
        event["timestamp_utc"] = None
    bundle, warnings = build_bundle(document)
    assert not any(o["type"] == "observed-data" for o in bundle["objects"])
    assert warnings


def test_html_injection_escaped(document):
    result = html_report(document, "</pre><script>alert(1)</script>")
    assert "<script>alert" not in result
    assert "&lt;script&gt;" in result


@pytest.mark.parametrize("value", ["=1+1", " +SUM(A1)", "-1", "@x"])
def test_csv_formula_injection(value):
    assert csv_cell(value).startswith("'")


def test_missing_input_returns_error(tmp_path):
    assert main(["--input", str(tmp_path / "missing")]) == 2


def test_cloud_missing_key_retains_report(input_path, tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    output, doc = run(
        parser().parse_args(
            ["--input", str(input_path), "--outdir", str(tmp_path), "--ai", "cloud"]
        )
    )
    assert (output / "report.md").exists()
    assert doc["run"]["ai"]["mode"] == "cloud_failed"
    assert len(doc["run"]["coverage"]["ai_skipped_detection_ids"]) == 3


def test_published_dataset_aggregate_regression(tmp_path):
    path = Path(__file__).resolve().parents[1] / "examples/2025-11-2-polish-run/detections.json"
    if not path.is_file():
        pytest.skip("Historical dataset not available")
    _, doc = run(parser().parse_args(["--input", str(path), "--outdir", str(tmp_path)]))
    aggregates = [d for d in doc["detections"] if d["rule_name"] == "Rare Service Installations"]
    events = {e["id"]: e for e in doc["events"]}
    assert aggregates
    assert all(events[ref]["event_id"] == "7045" for d in aggregates for ref in d["event_refs"])


def test_pinned_attack_import_includes_dependencies(document):
    import stix2

    creator = stix2.Identity(name="MITRE fixture", identity_class="organization")
    technique = stix2.AttackPattern(
        name="PowerShell fixture",
        created_by_ref=creator.id,
        external_references=[{"source_name": "mitre-attack", "external_id": "T1059.001"}],
    )
    attack_bundle = json.loads(stix2.Bundle(objects=[creator, technique]).serialize())
    bundle, _ = build_bundle(document, attack_bundle=attack_bundle)
    assert {creator.id, technique.id} <= {o["id"] for o in bundle["objects"]}
    validate_bundle_refs(bundle)
    assert validate_string(json.dumps(bundle), ValidationOptions(version="2.1")).is_valid


def test_chainsaw_invocation_uses_file_output_without_shell(tmp_path, detections, monkeypatch):
    import forensynth.cli as cli

    evtx = tmp_path / "fixture.evtx"
    evtx.write_bytes(b"synthetic placeholder")
    rules = tmp_path / "rules"
    rules.mkdir()
    mapping = tmp_path / "mapping.yml"
    mapping.write_text("fixture")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        target = Path(command[command.index("--output") + 1])
        assert target.suffix == ".json" and not target.exists()
        target.write_text(json.dumps(detections))

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(cli, "_git_commit", lambda path: None)
    _, doc = run(
        parser().parse_args(
            [
                "--evtx-root",
                str(evtx),
                "--rules",
                str(rules),
                "--mapping",
                str(mapping),
                "--outdir",
                str(tmp_path / "reports"),
            ]
        )
    )
    assert len(calls) == 1 and not calls[0][1].get("shell", False)
    assert any(a["kind"] == "evtx" for a in doc["artifacts"])
