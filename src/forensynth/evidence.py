"""Loss-aware ingestion and deterministic normalization of Chainsaw detections."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
TACTICS = {
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
}
SEVERITY = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def stable_id(prefix: str, value: Any) -> str:
    body = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return prefix + "-" + hashlib.sha256(body.encode()).hexdigest()[:24]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def utc_timestamp(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value:
        return None, "missing timestamp"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None, "timestamp has no timezone; UTC was not assumed"
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), None
    except ValueError:
        return None, "invalid timestamp"


def load_detections(path: Path, allow_rejected: bool = False) -> tuple[list[dict], dict]:
    # Snapshot bytes are parsed strictly. Never silently discard malformed input.
    text = path.read_text(encoding="utf-8")
    rejected = []
    raw_count = 0
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # A malformed array/envelope is not reinterpreted as JSONL.
        if text.lstrip().startswith("["):
            raise ValueError("Malformed JSON array") from None
        lines = [item for item in enumerate(text.splitlines(), 1) if item[1].strip()]
        data = []
        for line, body in lines:
            raw_count += 1
            try:
                data.append(json.loads(body))
            except json.JSONDecodeError as exc:
                rejected.append({"location": f"line:{line}", "reason": exc.msg})
        if not data:
            raise ValueError("Input is neither valid JSON nor valid detection JSONL")
    if isinstance(data, dict):
        if not isinstance(data.get("detections"), list):
            raise ValueError("JSON envelope must contain a detections array")
        data = data["detections"]
    if not isinstance(data, list):
        raise ValueError("Input must be a detection array, envelope, or JSONL")
    if not raw_count:
        raw_count = len(data)
    valid = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            rejected.append({"location": f"record:{index}", "reason": "not an object"})
        elif not any(item.get(key) for key in ("name", "ruleTitle", "rule")):
            rejected.append({"location": f"record:{index}", "reason": "missing rule title"})
        elif "documents" in item and (
            not isinstance(item["documents"], list)
            or not all(isinstance(d, dict) for d in item["documents"])
        ):
            rejected.append({"location": f"record:{index}", "reason": "invalid documents array"})
        elif "document" in item and not isinstance(item["document"], dict):
            rejected.append({"location": f"record:{index}", "reason": "invalid document"})
        else:
            valid.append(item)
    if rejected and not allow_rejected:
        raise ValueError(
            f"Rejected {len(rejected)} input records; use --allow-rejected to retain audit details"
        )
    return valid, {
        "raw_records": raw_count,
        "parsed_records": len(valid),
        "rejected_records": len(rejected),
        "rejections": rejected,
    }


def _scalar(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("#text", value.get("value"))
    return (
        str(value) if isinstance(value, (str, int, float)) and str(value) not in ("", "-") else None
    )


def _tags(det: dict) -> list[str]:
    tags = det.get("tags", [])
    if isinstance(tags, str):
        tags = [tags]
    return (
        sorted({str(t).lower() for t in tags if isinstance(t, str)})
        if isinstance(tags, list)
        else []
    )


def normalize(
    detections: list[dict], artifact_id: str
) -> tuple[list[dict], list[dict], list[dict], list[str]]:
    events, matches, observables, warnings = {}, [], {}, []
    seen = Counter()
    for index, det in enumerate(detections):
        tags = _tags(det)
        rule = det.get("rule") if isinstance(det.get("rule"), dict) else {}
        name = str(det.get("name") or det.get("ruleTitle") or rule.get("title"))
        refs = []
        documents = det.get("documents") if "documents" in det else [det.get("document", {})]
        if not documents:
            documents = [{}]
        for doc_index, doc in enumerate(documents):
            data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
            ev = data.get("Event") if isinstance(data.get("Event"), dict) else {}
            system = ev.get("System") if isinstance(ev.get("System"), dict) else {}
            ed = ev.get("EventData") if isinstance(ev.get("EventData"), dict) else {}
            # Minimal fixture/adapter fields are also supported.
            if not ev:
                ed = det.get("event_data") if isinstance(det.get("event_data"), dict) else {}
            provider_data = system.get("Provider_attributes", system.get("Provider", {}))
            provider = (
                _scalar(provider_data.get("Name"))
                if isinstance(provider_data, dict)
                else _scalar(provider_data)
            )
            timestamp, issue = utc_timestamp(
                system.get("TimeCreated_attributes", {}).get("SystemTime")
                if isinstance(system.get("TimeCreated_attributes"), dict)
                and system["TimeCreated_attributes"].get("SystemTime")
                else det.get("timestamp")
            )
            host = _scalar(system.get("Computer") or det.get("host"))
            channel = _scalar(system.get("Channel") or det.get("channel"))
            record = _scalar(system.get("EventRecordID") or det.get("record_id"))
            eid = _scalar(system.get("EventID") or det.get("event_id"))
            source_path = _scalar(doc.get("path"))
            # Rule identity is excluded from event identity: one event may match many rules.
            identity = {
                "path": source_path,
                "host": host,
                "channel": channel,
                "provider": provider,
                "record": record,
                "timestamp": timestamp,
                "event_id": eid,
                "data": ed,
            }
            if not ev and not ed:
                identity["adapter_record"] = {
                    k: v
                    for k, v in det.items()
                    if k not in ("name", "rule", "ruleTitle", "tags", "id", "level")
                }
                if not record:
                    identity["unresolved_index"] = index
            event_ref = stable_id("event", identity)
            location = (
                f"/detections/{index}/documents/{doc_index}"
                if "documents" in det
                else f"/detections/{index}/document"
            )
            if event_ref not in events:
                process = {
                    k: _scalar(ed.get(k))
                    for k in (
                        "Image",
                        "CommandLine",
                        "ParentImage",
                        "ParentCommandLine",
                        "ProcessGuid",
                        "ProcessId",
                        "ParentProcessGuid",
                        "ParentProcessId",
                        "ScriptBlockText",
                        "TargetFilename",
                        "TargetObject",
                        "TaskName",
                        "TaskContent",
                        "ServiceName",
                        "ImagePath",
                    )
                    if _scalar(ed.get(k))
                }
                users = {
                    k: _scalar(ed.get(k))
                    for k in (
                        "User",
                        "SubjectUserName",
                        "TargetUserName",
                        "SubjectUserSid",
                        "TargetUserSid",
                        "SubjectLogonId",
                        "TargetLogonId",
                    )
                    if _scalar(ed.get(k))
                }
                events[event_ref] = {
                    "id": event_ref,
                    "artifact_ref": artifact_id,
                    "source_path": source_path,
                    "raw_refs": [location],
                    "record_id": record,
                    "provider": provider,
                    "channel": channel,
                    "event_id": eid,
                    "timestamp_utc": timestamp,
                    "host": host,
                    "users": users,
                    "process": process,
                    "event_data": ed,
                    "missing_reasons": {},
                }
                for field in (
                    "record_id",
                    "provider",
                    "channel",
                    "event_id",
                    "timestamp_utc",
                    "host",
                ):
                    if events[event_ref][field] is None:
                        events[event_ref]["missing_reasons"][field] = (
                            issue if field == "timestamp_utc" else "not provided"
                        )
                if issue:
                    warnings.append(f"{event_ref}: {issue}")
                for kind, value, role in extract_observables(ed):
                    key = (kind, value)
                    oid = stable_id("observable", key)
                    obj = observables.setdefault(
                        key,
                        {
                            "id": oid,
                            "type": kind,
                            "value": value,
                            "roles": [],
                            "event_refs": [],
                            "assessment": "unassessed",
                        },
                    )
                    if event_ref not in obj["event_refs"]:
                        obj["event_refs"].append(event_ref)
                    if role not in obj["roles"]:
                        obj["roles"].append(role)
            elif location not in events[event_ref]["raw_refs"]:
                events[event_ref]["raw_refs"].append(location)
            if event_ref not in refs:
                refs.append(event_ref)
        # Distinguish repeated identical matches without losing their input record locations.
        key = stable_id("detection", {"rule": det.get("id") or name, "events": refs})
        seen[key] += 1
        matches.append(
            {
                "id": f"{key}-{seen[key]}",
                "rule_id": _scalar(det.get("id") or rule.get("id")),
                "rule_name": name,
                "rule_status": _scalar(det.get("status")),
                "severity": SEVERITY.get(str(det.get("level", "")).lower(), "unknown"),
                "event_refs": refs,
                "tags": tags,
                "technique_ids": sorted(
                    {m.group(1).upper() for t in tags if (m := TECHNIQUE.fullmatch(t))}
                ),
                "tactics": sorted(
                    {
                        t.split(".", 1)[1]
                        for t in tags
                        if t.startswith("attack.") and t.split(".", 1)[1] in TACTICS
                    }
                ),
                "mapping_source": "sigma_tags",
                "raw_ref": f"/detections/{index}",
                "false_positives": det.get("falsepositives", [])
                if isinstance(det.get("falsepositives", []), list)
                else [],
            }
        )
    return list(events.values()), matches, list(observables.values()), warnings


def extract_observables(ed: dict) -> list[tuple[str, str, str]]:
    """Extract explicit typed fields, not arbitrary strings/rule-title guesses."""
    out = []
    for field in ("SourceIp", "DestinationIp", "IpAddress", "SourceAddress", "DestinationAddress"):
        value = _scalar(ed.get(field))
        if value:
            try:
                ip = ipaddress.ip_address(value)
                out.append(("ipv4-addr" if ip.version == 4 else "ipv6-addr", str(ip), field))
            except ValueError:
                pass
    for field in ("QueryName", "DestinationHostname"):
        value = _scalar(ed.get(field))
        if value and re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
            out.append(("domain-name", value.lower(), field))
    for field in ("Url", "URL"):
        value = _scalar(ed.get(field))
        if value and value.startswith(("http://", "https://")):
            out.append(("url", value, field))
    for field in ("SHA256", "Sha256"):
        value = _scalar(ed.get(field))
        if value and re.fullmatch(r"[a-fA-F0-9]{64}", value):
            out.append(("sha256", value.lower(), field))
    hashes = _scalar(ed.get("Hashes")) or ""
    for algorithm, value in re.findall(
        r"(?:^|[,;])\s*(SHA256|SHA1|MD5)=([a-fA-F0-9]+)", hashes, re.I
    ):
        length = {"SHA256": 64, "SHA1": 40, "MD5": 32}[algorithm.upper()]
        if len(value) == length:
            out.append((algorithm.lower(), value.lower(), "Hashes"))
    return out


def select_detections(
    matches: list[dict], events: list[dict], limit: int = 0
) -> tuple[list[dict], dict]:
    """Keep all high/critical matches; select deterministic round-robin strata for the rest."""
    from collections import defaultdict

    by_id = {e["id"]: e for e in events}
    protected = [d for d in matches if d["severity"] in ("high", "critical")]
    protected_ids = {d["id"] for d in protected}
    selected = list(protected)
    groups = defaultdict(list)
    for d in matches:
        if d["id"] not in protected_ids:
            host = by_id[d["event_refs"][0]]["host"] or "unknown"
            day = (by_id[d["event_refs"][0]]["timestamp_utc"] or "unknown")[:10]
            groups[(host, d["rule_id"] or d["rule_name"], day)].append(d)
    target = len(matches) if limit == 0 else max(limit, len(protected))
    while groups and len(selected) < target:
        for key in sorted(list(groups)):
            if len(selected) >= target:
                break
            selected.append(groups[key].pop(0))
            if not groups[key]:
                del groups[key]
    ids = {d["id"] for d in selected}
    return selected, {
        "selected_detection_ids": sorted(ids),
        "omitted_detection_ids": [d["id"] for d in matches if d["id"] not in ids],
        "protected_count": len(protected),
        "requested_limit": limit,
        "limit_exceeded_for_protected": bool(limit and len(protected) > limit),
    }
