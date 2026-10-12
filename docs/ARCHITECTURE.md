# ForenSynth AI v2.4 beta architecture

## Evidence pipeline

The active package is `src/forensynth`; historical version snapshots are preserved.
The `forensynth` command and `src/v2.4/forensynth_ai_v2_4.py` use the same CLI.

1. Accept existing JSON/JSONL detections, or call Chainsaw on collected EVTX.
2. Preserve original input bytes and hash the source and canonical parsed envelope.
3. Normalize individual `document` and aggregate `documents` records into events
   independently of Sigma rule identity. Retain multiple matches against one event.
4. Compute full evidence counts and findings deterministically.
5. Optionally select AI input across host/rule/day strata; retain every high/critical
   detection. Selection never removes records from evidence exports.
6. Group cloud input by host, ProcessGuid (rule fallback), and hour. Split within an
   estimated per-call budget. Cloud findings must satisfy a strict schema and cite
   only supplied detection IDs. Invalid or incomplete outputs are rejected.
7. Render a deterministic report containing observed counts and separate pending
   AI interpretations; export CSV and minimal STIX from the same evidence model.
8. Validate schema/references/coverage and write a hash manifest.

## Modules

| Module | Responsibility |
| --- | --- |
| `evidence.py` | Strict ingestion, normalization, observables, IDs, timestamps, selection |
| `validation.py` | JSON Schema, evidence references, coverage reconciliation |
| `llm.py` | Explicit cloud processing, structured findings, token/request reservations, usage |
| `report.py` | Deterministic findings, readable reports, escaped exports |
| `stix_export.py` | STIX objects, reviewed indicators, ATT&CK imports, reference/pattern validation |
| `cli.py` | Source preservation, optional Chainsaw execution, artifacts and run orchestration |

## Evidence contract

Schema version `1.0.0` is independent of application version `2.4.0b1`.
`schemas/evidence-v1.json` defines case, artifact, event, detection, observable,
finding, and run records. `schemas/ai-findings.json` defines model outputs.

An event points to the hashed canonical `detections.json` artifact. `raw_refs` are
JSON pointers into its `detections` envelope. The canonical artifact points to the
byte-preserved original input artifact. Rejected JSONL locations are recorded
against original input; use `--allow-rejected` only when partial ingestion is acceptable.
Events without reliable identifying telemetry remain separate unresolved records.
Event IDs must be interpreted alongside provider and channel.

Missing fields are null with reasons. Timestamps without timezone information are
not assumed to be UTC. Event data is preserved without snippet truncation; only
optional cloud prompt fields are capped and explicitly flagged.

Findings distinguish `observed`, `inferred`, and `hypothesis`. Deterministic findings
only establish rule-match counts. AI cannot declare `observed` findings and cannot
approve itself. Confidence is an explained assessment, not a calibrated probability.

Coverage distinguishes raw, parsed, rejected, selected, omitted, AI-processed,
and AI-skipped records. An offline run has zero AI-processed records. The report
always covers all parsed evidence through deterministic counts and references.

## STIX contract

Typed explicit telemetry fields yield SCOs, not automatic IOCs. Timestamped events
with supported SCOs yield `observed-data`, with one observation per deduplicated event.
Process command lines, process IDs, and image names are represented where available.
Behavior findings are notes with Sigma technique tags and source references. A pinned
local ATT&CK bundle enables importing matching attack-patterns and their dependencies.

Only a supplied analyst review asserting a malicious observable creates an indicator.
The pattern is exact-value, not a generated Sigma translation. Bundles are checked
with the `stix2` parser, internal reference checks, and pattern validation; CI also
uses the independent STIX validator. No synthetic observation timestamps are created.

## Limitations and deferred work

- Beta: no verified production deployment, effectiveness benchmark, or independent analyst evaluation yet.
- No signed custody, analyst authentication, automatic anonymization, or local-model adapter.
- No guaranteed resistance to model hallucinations or prompt injection; human review is required.
- No final generative merge, concurrent cloud workers, retries, or hosted service in this beta.
- HTML favors an escaped readable evidence report; historical charts are not migrated.
- No ATT&CK mapping from keywords; tags remain mappings, not maliciousness determinations.
- Hashes/revisions improve reproducibility but do not guarantee identical future model output.
- Real Chainsaw EVTX processing and live API integration require environment-specific validation.
