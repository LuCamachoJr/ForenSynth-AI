# ForenSynth AI – Architecture

> Chainsaw detections in → DFIR-shaped, AI-assisted reports out.

This document describes how ForenSynth AI is wired together as of v2.3.4.

At a high level:

1. Chainsaw hunts Windows Event Logs (EVTX/EVT) with Sigma rules.
2. The resulting detections JSON is loaded, optionally sampled, and grouped.
3. The tool generates micro-summaries in parallel using an LLM.
4. A final LLM pass merges those micro summaries into an executive DFIR report.
5. The report is rendered as Markdown + HTML, with charts, donuts, and appendices.
6. A normalized evidence appendix (JSON + CSV) is emitted for further analysis.

---

## 1. High-Level Flow

EVTX/EVT directory  
        │  
        ▼  
   [Chainsaw]  
  rules + hunt  
        │  detections.json  
        ▼  
  [Detections Loader]  
        │  
  (optional sampling)  
        │  
        ▼  
 [Phase Mapper + Clustering]  
        │  
        ▼  
   [Micro Engine]  
  (parallel LLM calls)  
        │  
        ▼  
   [Final Engine]  
  (single LLM merge)  
        │  
        ▼  
  [Renderers + Export]  
Markdown | HTML | evidence.json | evidence.csv  

### 1.1 Components at a Glance

- Chainsaw runner  
  - Invokes Chainsaw with a Sigma ruleset against the EVTX/EVT directory.  
  - Writes detections.json (and optionally other artifacts) into a Reports/<timestamp>/ folder.

- Detection loader + sampler (v2.3.4)  
  - Loads raw detections.json.  
  - Optional sampling governor:
    - --limit-detections N → cap the number of detections fed to AI.
    - --sample-step S → keep every S-th detection (stratified sampling).
  - Prints a clear banner such as:  
    ⚙ Sampling applied: 2705 → 902 (step=3, limit=1000)

- Phase / MITRE mapper  
  - Maps detections into high-level phases:
    - Execution  
    - Persistence  
    - Credential / Account  
    - Discovery / Lateral  
    - Defense Evasion  
    - Unmapped / Multiple  
  - Uses Sigma metadata, rule names, and keywords to infer MITRE ATT&CK techniques.

- Micro engine  
  - Splits the (sampled) detections into blocks (“micro clusters”).  
  - Calls an LLM in parallel to summarize each block.  
  - Respects:
    - --micro-workers → parallel worker count.  
    - --rpm → soft rate limiting (requests per minute).  
    - --chunk-size → size of each micro block.  
    - --integrity on|off → conservative vs cheaper prompts.

- Final engine  
  - Takes the micro summaries as input.  
  - Optionally runs a two-pass merge:
    - --two-pass:
      - Pass 1: outline + structure.
      - Pass 2: polished narrative built from the outline.
  - Produces a single executive DFIR report with:
    - Executive summary  
    - Observed activity by phase  
    - MITRE TTPs  
    - Risk assessment  
    - Recommendations (with quick wins)  
    - Limitations / uncertainties  
    - Evidence appendix  

- Renderers & exports  
  - Markdown:
    - forensynth_summary_YYYY-MM-DD.md  
  - HTML:
    - forensynth_report_YYYY-MM-DD.html  
    - Optional branding & table of contents.  
    - Visuals: heatmap + phase donuts.  
  - Evidence JSON:
    - evidence.json – normalized view over key fields (rules, event IDs, phases, etc.).  
  - Evidence CSV:
    - evidence.csv when --export-evidence-csv is used.

---

## 2. Data Artifacts and Layout

Default lab layout (example):

DFIR-Labs/  
  ForenSynth/  
    Reports/  
      2025-11-02_153010Z/  
        detections.json           # raw Chainsaw detections  
        evidence.json             # normalized evidence  
        evidence.csv              # flattened evidence (optional)  
        forensynth_summary_*.md   # Markdown DFIR report  
        forensynth_report_*.html  # HTML DFIR report (visuals)  
        *.png / *.jpg             # screenshots / lab artifacts (optional)  

Key files:

- detections.json  
  - Raw Chainsaw output.  
  - An array of detection objects (rules, event IDs, timestamps, etc.).

- evidence.json (v2.3.4)  
  - Normalized shape extracted from detections:
    - rule_name  
    - event_id  
    - phase  
    - timestamp  
    - host/user (if available)

- evidence.csv (v2.3.4)  
  - CSV flattening of evidence.json for:
    - Excel / spreadsheets  
    - SIEM / BI / Jupyter pivoting

- Summary markdown/HTML  
  - Human-readable report for:
    - GitHub examples  
    - DFIR case notes  
    - Attachments in tickets / emails  

---

## 3. CLI Surface (v2.3.4)

The current CLI exposes options roughly along these lines:

- Core:
  - --evtx-dir PATH (or auto-discover latest directory in a lab path)  
  - --two-pass  
  - --integrity on|off  
  - --max-input-tokens N (guardrail against over-large prompts)

- Parallelism & latency:
  - --micro-workers N  
  - --rpm N  
  - --chunk-size N  
  - --llm-timeout SECONDS  
  - --llm-retries N  

- Sampling (v2.3.4):
  - --limit-detections N  
  - --sample-step N  

- Rendering:
  - --make-html  
  - --toc on|off  
  - --branding on|off  
  - --chart-style bar|donut|both  
  - --export-evidence-csv  

Not every flag is required in every run; defaults are tuned for small/mid-sized lab hunts.

For large hunts (2k–3k detections), a typical combination is:

- --limit-detections 1000  
- --sample-step 3  
- --micro-workers 3  

to keep latency and cost predictable.

---

## 4. Visual Layer (HTML)

As of v2.3.4, the HTML report includes:

1. Detection heatmap  
   - X-axis: days or time buckets.  
   - Y-axis: key Event IDs (1, 11, 13, 4104, 4688, 4720, 4728, etc.).  
   - Color intensity: detection count.  
   - Caption: short narrative of notable bursts.  
   - Footnote:  
     EventID 1 = Sysmon ProcessCreate; 11 = File create; 13 = Registry; 4104 = PowerShell ScriptBlock; etc.

2. Donut charts  
   - Main donut: detections by phase:
     - Execution  
     - Persistence  
     - Credential / Account  
     - Discovery / Lateral  
     - Defense Evasion  
     - Unmapped / Multiple  
   - Consistent color palette across donuts and heatmap.  
   - Legends show counts + percentages.

3. “At a glance” section  
   - Compact stats block near the top:
     - Total detections (raw)  
     - Sampled detections used by AI  
     - Number of micro blocks  
     - Time range  
     - Top Event IDs and top rules  

---

## 5. LLM & Cost Handling

ForenSynth AI uses OpenAI models via the official Python client.

### 5.1 API Key Handling

- Uses python-dotenv when available.  
- Secure resolution logic:
  - Looks for .env in:
    - Current working directory  
    - User home directory  
  - Enforces “not world-readable / world-writable” for .env.  
- Reads OPENAI_API_KEY from the environment:
  - Fails fast with a clear error if not set.

### 5.2 Models and Costs

- Typical configuration:
  - Micro passes: gpt-5-mini (or similar “mini” tier).  
  - Final pass: gpt-5.  

As of v2.3.4:

- Reads actual token usage from the API response.  
- Prints a cost breakdown per model and total, for example:

- gpt-5-mini: in=90,399, out=29,430 → $0.08146  
- gpt-5:      in=29,912, out=2,281  → $0.06020  
- Total cost: $0.14166  

This makes it easier to discuss feasibility of AI-assisted DFIR.

---

## 6. Versioning & Source Layout

Source layout in this repo:

src/  
  v2.0/  
  v2.1/  
  v2.3.1/  
  v2.3.2/  
  v2.3.3/  
  v2.3.4/  

docs/  
  ARCHITECTURE.md  
  CHANGELOG.md  
  releases/  
    v2.3.4.md  

examples/  
  ...  

- Each vX.Y.Z folder contains a snapshot of that version’s script(s).  
- v2.3.4 is the current polished iteration:
  - forensynth_ai_v2_3_4_polish.py is the primary entry point for DFIR reports.

---

## 7. Extensibility Notes

Areas designed to be pluggable:

- Upstream detector:
  - Chainsaw is the default EVTX engine.  
  - Other sources (e.g., EDR exports, Zeek logs) can be adapted by converting into a detections.json-like structure.

- Phase / MITRE mapping:
  - Current mapping is heuristic.  
  - Can be extended with:
    - Explicit rule metadata  
    - External ATT&CK knowledge bases  

- Output formats:
  - Current: Markdown, HTML, JSON, CSV.  
  - Future:
    - STIX 2.1 bundles  
    - Direct SIEM / ticket system exports  

ForenSynth AI is intentionally built as a thin orchestration layer:

- Upstream: detectors (Chainsaw).  
- Middle: summarization logic (micro + final).  
- Downstream: formats that humans and systems can consume.

The goal is human-led, AI-assisted DFIR:  
models help surface patterns; analysts still make the call.
