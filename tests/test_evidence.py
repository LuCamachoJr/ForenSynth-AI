import copy

import pytest

from forensynth.evidence import load_detections, normalize, select_detections, utc_timestamp
from forensynth.validation import validate_ai_findings, validate_document


def test_aggregate_and_duplicate_event(detections):
    events, matches, _, _ = normalize(detections, "artifact-test")
    assert len(events) == 3
    assert len(matches) == 3
    assert len(matches[-1]["event_refs"]) == 2
    assert matches[0]["event_refs"] == matches[1]["event_refs"]
    assert events[0]["host"] == "LAB01"
    assert events[1]["event_id"] == "7045"
    assert matches[-1]["tactics"] == ["persistence", "privilege_escalation"]


def test_provider_channel_distinguish_event_identity(detections):
    other = copy.deepcopy(detections[0])
    other["document"]["data"]["Event"]["System"]["Provider_attributes"]["Name"] = "AnotherProvider"
    events, _, _, _ = normalize([detections[0], other], "artifact")
    assert len(events) == 2


def test_every_high_critical_survives_selection(detections):
    detections[-1]["level"] = "critical"
    events, matches, _, _ = normalize(detections, "artifact-test")
    selected, coverage = select_detections(matches, events, 1)
    assert {d["severity"] for d in selected} == {"high", "critical"}
    assert coverage["limit_exceeded_for_protected"]
    assert len(coverage["omitted_detection_ids"]) == 1


def test_round_robin_selection_reproducible(detections):
    events, matches, _, _ = normalize(detections, "artifact-test")
    assert select_detections(matches, events, 2) == select_detections(matches, events, 2)


@pytest.mark.parametrize("value", ["bad", "2026-10-12T04:00:00", None])
def test_no_assumed_timestamps(value):
    assert utc_timestamp(value)[0] is None


def test_timezone_normalized():
    assert utc_timestamp("2026-10-12T00:00:00-04:00")[0] == "2026-10-12T04:00:00Z"


def test_rejected_jsonl_requires_explicit_opt_in(tmp_path):
    path = tmp_path / "input.jsonl"
    path.write_text('{"name":"valid"}\n{broken}\n42\n')
    with pytest.raises(ValueError, match="Rejected 2"):
        load_detections(path)
    valid, audit = load_detections(path, True)
    assert len(valid) == 1
    assert audit["raw_records"] == 3
    assert audit["rejected_records"] == 2


def test_malformed_array_not_reinterpreted_as_jsonl(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('[\n{"name":"valid"}\n')
    with pytest.raises(ValueError, match="Malformed JSON array"):
        load_detections(path, True)


def test_minimal_adapter_shape():
    events, matches, _, _ = normalize(
        [{"ruleTitle": "Test", "host": "LAB01", "timestamp": "2026-10-12T04:00:00Z"}], "artifact"
    )
    assert matches[0]["rule_name"] == "Test"
    assert events[0]["host"] == "LAB01"
    assert events[0]["missing_reasons"]["event_id"] == "not provided"


def test_observables_unassessed(detections):
    _, _, observables, _ = normalize(detections, "artifact")
    assert {o["type"] for o in observables} == {"ipv4-addr", "domain-name", "sha256", "url"}
    assert all(o["assessment"] == "unassessed" for o in observables)


def test_unknown_references_fail(document):
    document["findings"][0]["evidence_refs"] = ["invented-id"]
    with pytest.raises(ValueError, match="Unknown finding"):
        validate_document(document)


def test_coverage_mismatch_fails(document):
    document["run"]["coverage"]["parsed_records"] += 1
    with pytest.raises(ValueError, match="coverage"):
        validate_document(document)


def test_ai_cannot_cite_outside_prompt():
    item = {
        "statement": "Possible persistence",
        "evidence_refs": ["invented"],
        "classification": "inferred",
        "confidence": "low",
        "confidence_rationale": "Unverified",
        "alternative_explanations": ["Authorized administration"],
    }
    with pytest.raises(ValueError, match="outside"):
        validate_ai_findings({"findings": [item]}, ["real"])


def test_empty_array_supported(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("[]")
    valid, audit = load_detections(path)
    assert valid == [] and audit["raw_records"] == 0
