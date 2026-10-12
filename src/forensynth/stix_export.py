"""Minimal STIX 2.1: observations and behavior notes; indicators require analyst review."""

from __future__ import annotations

import json

import stix2
from stix2patterns.validator import run_validator


def _references(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith("_ref") and isinstance(item, str):
                yield item
            elif key.endswith("_refs") and isinstance(item, list):
                yield from (ref for ref in item if isinstance(ref, str))
            else:
                yield from _references(item)
    elif isinstance(value, list):
        for item in value:
            yield from _references(item)


def _sco(observable):
    kind, value = observable["type"], observable["value"]
    if kind == "ipv4-addr":
        return stix2.IPv4Address(value=value)
    if kind == "ipv6-addr":
        return stix2.IPv6Address(value=value)
    if kind == "domain-name":
        return stix2.DomainName(value=value)
    if kind == "url":
        return stix2.URL(value=value)
    return stix2.File(hashes={{"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}[kind]: value})


def _pattern(observable):
    value = observable["value"].replace("\\", "\\\\").replace("'", "\\'")
    kind = observable["type"]
    if kind in ("sha256", "sha1", "md5"):
        algo = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}[kind]
        return f"[file:hashes.'{algo}' = '{value}']"
    return f"[{kind}:value = '{value}']"


def build_bundle(doc, reviews=None, attack_bundle=None):
    now = doc["run"]["generated_at"]
    creator = stix2.Identity(
        name="ForenSynth AI", identity_class="system", created=now, modified=now
    )
    objects = {creator.id: creator}
    sco_by_observable, refs_by_event, observed_by_event = {}, {}, {}
    warnings = []
    for observable in doc["observables"]:
        sco = _sco(observable)
        objects[sco.id] = sco
        sco_by_observable[observable["id"]] = sco.id
        for ref in observable["event_refs"]:
            refs_by_event.setdefault(ref, []).append(sco.id)
    for event in doc["events"]:
        process = event["process"]
        if process.get("CommandLine") or process.get("ProcessId") or process.get("Image"):
            properties = {}
            if process.get("CommandLine"):
                properties["command_line"] = process["CommandLine"]
            if process.get("ProcessId", "").isdigit():
                properties["pid"] = int(process["ProcessId"])
            if process.get("Image"):
                # Use name only; source path remains available in normalized evidence.
                image = stix2.File(name=process["Image"].replace("\\", "/").rsplit("/", 1)[-1])
                objects[image.id] = image
                properties["image_ref"] = image.id
                refs_by_event.setdefault(event["id"], []).append(image.id)
            if properties:
                proc = stix2.Process(**properties)
                objects[proc.id] = proc
                refs_by_event.setdefault(event["id"], []).append(proc.id)
        refs = sorted(set(refs_by_event.get(event["id"], [])))
        if refs and event["timestamp_utc"]:
            observed = stix2.ObservedData(
                created=now,
                modified=now,
                created_by_ref=creator.id,
                first_observed=event["timestamp_utc"],
                last_observed=event["timestamp_utc"],
                number_observed=1,
                object_refs=refs,
            )
            objects[observed.id] = observed
            observed_by_event[event["id"]] = observed.id
    attacks = {}
    dataset_objects = {}
    if attack_bundle is not None:
        if not isinstance(attack_bundle, dict) or not isinstance(
            attack_bundle.get("objects"), list
        ):
            raise ValueError("ATT&CK input must be a STIX bundle with objects")
        dataset_objects = {
            o["id"]: o for o in attack_bundle["objects"] if isinstance(o, dict) and "id" in o
        }
        # Only import supplied official-style attack-pattern objects with matching external IDs.
        for raw in attack_bundle.get("objects", []):
            if (
                raw.get("type") != "attack-pattern"
                or raw.get("revoked")
                or raw.get("x_mitre_deprecated")
            ):
                continue
            for reference in raw.get("external_references", []):
                if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
                    attacks[reference["external_id"]] = raw

    def import_attack(raw):
        if raw["id"] in objects:
            return
        attack = stix2.parse(raw, allow_custom=True)
        objects[attack.id] = attack
        for ref in _references(raw):
            if ref not in objects:
                if ref not in dataset_objects:
                    raise ValueError(f"ATT&CK dataset lacks referenced object: {ref}")
                import_attack(dataset_objects[ref])

    detections = {d["id"]: d for d in doc["detections"]}
    for finding in doc["findings"]:
        refs = {creator.id}
        techniques = set()
        for ref in finding["evidence_refs"]:
            d = detections[ref]
            techniques.update(d["technique_ids"])
            refs.update(observed_by_event[e] for e in d["event_refs"] if e in observed_by_event)
        for technique in techniques:
            if technique in attacks:
                import_attack(attacks[technique])
                refs.add(attacks[technique]["id"])
        content = json.dumps(
            {
                "case_id": doc["case"]["id"],
                "environment": doc["case"]["environment"],
                "finding": finding,
                "sigma_technique_tags": sorted(techniques),
                "limitation": "Sigma mappings are not confirmed behavior. Evidence references do not prove AI claims.",
            },
            ensure_ascii=False,
        )
        note = stix2.Note(
            created=now,
            modified=now,
            created_by_ref=creator.id,
            abstract=f"{finding['classification']} / {finding['review_status']}",
            content=content,
            object_refs=sorted(refs),
        )
        objects[note.id] = note
    observables = {o["id"]: o for o in doc["observables"]}
    for review in reviews or []:
        required = {"observable_ref", "assessment", "reviewer", "rationale", "confidence"}
        if not isinstance(review, dict) or not required <= review.keys():
            raise ValueError(
                "Indicator reviews require observable_ref, assessment, reviewer, rationale, confidence"
            )
        if review["assessment"] != "malicious" or not review["reviewer"] or not review["rationale"]:
            raise ValueError(
                "Indicators require an explicit malicious assessment and named reviewer/rationale"
            )
        if (
            not isinstance(review["confidence"], int)
            or isinstance(review["confidence"], bool)
            or not 0 <= review["confidence"] <= 100
        ):
            raise ValueError("Indicator confidence must be an integer from 0 to 100")
        observable = observables.get(review["observable_ref"])
        if observable is None:
            raise ValueError("Indicator review references unknown observable")
        pattern = _pattern(observable)
        errors = run_validator(pattern, stix_version="2.1")
        if errors:
            raise ValueError(f"Invalid STIX pattern: {errors}")
        indicator = stix2.Indicator(
            created=now,
            modified=now,
            created_by_ref=creator.id,
            name=f"Reviewed {observable['type']} indicator",
            pattern_type="stix",
            pattern=pattern,
            valid_from=now,
            confidence=review["confidence"],
            description=f"Environment: {doc['case']['environment']}. Reviewer: {review['reviewer']}. {review['rationale']}",
        )
        objects[indicator.id] = indicator
        supporting = sorted(
            {observed_by_event[e] for e in observable["event_refs"] if e in observed_by_event}
        )
        for ref in supporting:
            relation = stix2.Relationship(
                created=now,
                modified=now,
                created_by_ref=creator.id,
                relationship_type="based-on",
                source_ref=indicator.id,
                target_ref=ref,
            )
            objects[relation.id] = relation
    if doc["observables"] and not observed_by_event:
        warnings.append(
            "Observables exported without observation timestamps; no observed-data was invented."
        )
    if not attacks and any(d["technique_ids"] for d in doc["detections"]):
        warnings.append(
            "No ATT&CK dataset supplied: technique tags remain in notes; no attack-pattern objects invented."
        )
    bundle = json.loads(stix2.Bundle(objects=list(objects.values())).serialize())
    validate_bundle_refs(bundle)
    return bundle, warnings


def validate_bundle_refs(bundle):
    stix2.parse(bundle, allow_custom=True)
    ids = {o["id"] for o in bundle["objects"]}
    if len(ids) != len(bundle["objects"]):
        raise ValueError("Duplicate STIX object IDs")
    for obj in bundle["objects"]:
        if any(ref not in ids for ref in _references(obj)):
            raise ValueError(f"Unresolved STIX reference in {obj['id']}")
