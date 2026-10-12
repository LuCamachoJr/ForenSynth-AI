"""Schema and referential validation; references are necessary, not proof of a claim."""

import json
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker, ValidationError


def schema(name):
    return json.loads(files("forensynth").joinpath(f"schemas/{name}.json").read_text())


def validate_document(document):
    try:
        Draft202012Validator(schema("evidence-v1"), format_checker=FormatChecker()).validate(
            document
        )
    except ValidationError as exc:
        raise ValueError(f"Evidence schema violation at {list(exc.path)}: {exc.message}") from exc
    events = {e["id"] for e in document["events"]}
    artifacts = {a["id"] for a in document["artifacts"]}
    detections = {d["id"] for d in document["detections"]}
    for key in ("events", "detections", "observables", "findings", "artifacts"):
        ids = [item["id"] for item in document[key]]
        if len(ids) != len(set(ids)):
            raise ValueError(f"Duplicate IDs in {key}")
    for event in document["events"]:
        if event["artifact_ref"] not in artifacts:
            raise ValueError("Unknown artifact reference")
    for artifact in document["artifacts"]:
        if artifact["parent_ref"] is not None and artifact["parent_ref"] not in artifacts:
            raise ValueError("Unknown parent artifact reference")
    for item in document["detections"] + document["observables"]:
        if not set(item["event_refs"]) <= events:
            raise ValueError("Unknown event reference")
    for finding in document["findings"]:
        if not set(finding["evidence_refs"]) <= detections:
            raise ValueError("Unknown finding evidence reference")
    coverage = document["run"]["coverage"]
    if coverage["raw_records"] != coverage["parsed_records"] + coverage["rejected_records"]:
        raise ValueError("Input coverage does not reconcile")
    if coverage["parsed_records"] != len(detections):
        raise ValueError("Detection count does not reconcile")
    selected, omitted = (
        set(coverage["selected_detection_ids"]),
        set(coverage["omitted_detection_ids"]),
    )
    if selected & omitted or selected | omitted != detections:
        raise ValueError("Selection coverage does not reconcile")
    processed = set(coverage["ai_processed_detection_ids"])
    if not processed <= selected:
        raise ValueError("AI coverage includes unselected records")


def validate_ai_findings(payload, allowed_refs):
    Draft202012Validator(schema("ai-findings"), format_checker=FormatChecker()).validate(payload)
    for item in payload["findings"]:
        if not set(item["evidence_refs"]) <= set(allowed_refs):
            raise ValueError("AI cited evidence outside its supplied input")
        if item["classification"] == "observed":
            raise ValueError("AI interpretations must be inferred or hypotheses")
    return payload["findings"]
