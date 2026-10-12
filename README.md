# ForenSynth AI — Evidence-linked DFIR reporting

ForenSynth AI converts Chainsaw/Sigma detections into reviewable Windows DFIR reports.
**v2.4.0 beta** adds a versioned evidence model, source hashes, explicit coverage,
optional structured AI findings, and minimal STIX 2.1 export.

Detection matches are investigation leads. They do not establish compromise,
malicious intent, exfiltration, or affected-system scope on their own.

## Quickstart (offline; no API key)

Requires Python 3.11 or later. From the repository root:

```sh
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
python -m pip install .
forensynth --input examples/v2.4/synthetic_detections.json --outdir reports --case-id demo --environment simulation --authorized-test --html --export-evidence-csv --export-stix
```

Outputs are placed in a unique run directory:

- `input.original`: unchanged input bytes.
- `detections.json`: canonical parsed envelope; rejected input records are excluded only with explicit opt-in.
- `evidence.json`: validated normalized events, detections, observables, findings, provenance, and coverage.
- `report.md` and optional `report.html`.
- Optional `evidence.csv` and `stix_bundle.json`.
- `manifest.json`: SHA-256 hashes of run-level files (excluding itself).

Original evidence remains local. The hash manifest detects later changes; it is not
an independently signed chain-of-custody system. Keep source files and backups.

## Desktop GUI (Windows / Linux)

Run `forensynth-gui` after installing the package. On Linux, install `python3-tk`
if Tkinter is absent. Browse to evidence, select exports, and create a report.
Offline processing is the default. See [desktop setup and checksums](docs/DESKTOP.md)
for source installation, packaged beta builds, and verification.

## Hunt EVTX with Chainsaw

Install [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) separately and
obtain a Sigma ruleset and compatible mapping. Use stable collected EVTX files:

```sh
forensynth --evtx-root /path/to/evtx --rules /path/to/sigma/rules --mapping /path/to/sigma-event-logs-all.yml --outdir reports --case-id case-001 --html --export-stix
```

Chainsaw is called without a shell, using JSON file output. EVTX hashes are checked
before and after the hunt. Ruleset Git revision and mapping hash are recorded when
available. Real EVTX/binary integration still needs testing in your investigation environment.

## Optional cloud AI

```sh
python -m pip install '.[llm]'
# Set OPENAI_API_KEY in your environment; do not commit it.
forensynth --input /path/to/detections.json --ai cloud --model gpt-5-mini --limit-detections 1000 --max-requests 20 --max-total-tokens 100000 --html
```

`--ai cloud` explicitly enables sending selected rule metadata, host/account fields,
and process/script fields to OpenAI. Review your data-sharing authorization first.
Raw event data and source file paths are excluded, but selected fields may still
contain sensitive information. v2.4 does not promise anonymization or automatic redaction.

Offline mode is the default. AI is a structured interpretation stage; there is no
unvalidated prose merge. Each finding must cite IDs from that call's input and is
marked `pending` analyst review. Referencing evidence is not proof that a statement
is correct. Prompts treat telemetry as untrusted data, but this is not a guarantee
against prompt injection. No containment, account changes, or other remediation is executed.

Limits apply only to AI input. Full parsed evidence and deterministic counts are
retained. All high/critical matches survive selection even if this exceeds the
selection limit; request and token budgets still cap cloud calls. Remaining input
is selected across host/rule/day strata. Process-field prompt values are truncated
at 2,000 characters with explicit flags; oversized records may be skipped with audit details.
Token budgeting includes schema/prompt overhead and reserved output allowance.
It is an estimate, not a provider billing guarantee. Calls are sequential with no
SDK retries; failed calls do not produce unchecked findings. Successful response
usage is accumulated, including rejected outputs. Unknown pricing is reported as
unknown. Optional `--input-rate` and `--output-rate` are USD per million tokens.

## STIX and ATT&CK

`--export-stix` writes Cyber-observable Objects, timestamped `observed-data`, and
behavior/finding notes. Sigma ATT&CK tags are not independently confirmed behavior.
Optionally provide `--attack-data /path/to/enterprise-attack.json --attack-version VERSION`
to include corresponding ATT&CK attack-pattern objects and referenced dependencies.
No ATT&CK objects are fabricated when the dataset is absent.

Indicators are never generated automatically from observed values. Supply a reviewed
JSON array using `--indicator-reviews reviews.json --export-stix`:

```json
[
  {
    "observable_ref": "observable-ID_FROM_EVIDENCE_JSON",
    "assessment": "malicious",
    "reviewer": "Named analyst",
    "rationale": "Evidence supporting the malicious assessment",
    "confidence": 80
  }
]
```

The review file is an analyst assertion, not authentication of reviewer identity.
Exact-value patterns are generated, validated, and linked to supporting observations
when timestamps exist. Simulation context is included in notes and indicator descriptions.

## Validation and contributing

```sh
python -m pip install -e '.[llm,dev]'
python -m pytest -q
ruff check src/forensynth src/v2.4 tests
ruff format --check src/forensynth src/v2.4 tests
```

Active v2.4 CI checks are blocking. Tests cover aggregate records, deduplicated
events, protected selection, malformed input, missing timestamps, reference checks,
bounded AI mocks, escaped HTML/CSV, and STIX validation. They do not establish
real-world detection accuracy or clinical/legal forensic admissibility.

[Architecture](docs/ARCHITECTURE.md) · [v2.4 review notes](docs/releases/v2.4.md) ·
[Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## Historical versions

v1.x through v2.3.4 are retained as historical snapshots. Their CLI and evidence
formats differ from v2.4. Earlier screenshots and reports are demonstrations,
including simulated activity, and are not verified production incident findings.
See [v2.3.4 release notes](docs/releases/v2.3.4.md).

Licensed under Apache-2.0. Third-party tools, rules, and datasets retain their own licenses.
