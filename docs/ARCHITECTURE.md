\# ForenSynth AI – Architecture



> Chainsaw detections in → DFIR-shaped, AI-assisted reports out.



This document describes how ForenSynth AI is wired together as of v2.3.4.



At a high level:



1\. Chainsaw hunts Windows Event Logs (EVTX/EVT) with Sigma rules.

2\. The resulting detections JSON is loaded, optionally sampled, and grouped.

3\. The tool generates micro-summaries in parallel using an LLM.

4\. A final LLM pass merges those micro summaries into an executive DFIR report.

5\. The report is rendered as Markdown + HTML, with charts, donuts, and appendices.

6\. A normalized evidence appendix (JSON + CSV) is emitted for further analysis.



---



\## 1. High-Level Flow



EVTX/EVT directory  

&nbsp;       │  

&nbsp;       ▼  

&nbsp;  \[Chainsaw]  

&nbsp; rules + hunt  

&nbsp;       │  detections.json  

&nbsp;       ▼  

&nbsp; \[Detections Loader]  

&nbsp;       │  

&nbsp; (optional sampling)  

&nbsp;       │  

&nbsp;       ▼  

&nbsp;\[Phase Mapper + Clustering]  

&nbsp;       │  

&nbsp;       ▼  

&nbsp;  \[Micro Engine]  

&nbsp; (parallel LLM calls)  

&nbsp;       │  

&nbsp;       ▼  

&nbsp;  \[Final Engine]  

&nbsp; (single LLM merge)  

&nbsp;       │  

&nbsp;       ▼  

&nbsp; \[Renderers + Export]  

Markdown | HTML | evidence.json | evidence.csv  



\### 1.1 Components at a Glance



\- Chainsaw runner  

&nbsp; - Invokes Chainsaw with a Sigma ruleset against the EVTX/EVT directory.  

&nbsp; - Writes detections.json (and optionally other artifacts) into a Reports/<timestamp>/ folder.



\- Detection loader + sampler (v2.3.4)  

&nbsp; - Loads raw detections.json.  

&nbsp; - Optional sampling governor:

&nbsp;   - --limit-detections N → cap the number of detections fed to AI.

&nbsp;   - --sample-step S → keep every S-th detection (stratified sampling).

&nbsp; - Prints a clear banner such as:  

&nbsp;   ⚙ Sampling applied: 2705 → 902 (step=3, limit=1000)



\- Phase / MITRE mapper  

&nbsp; - Maps detections into high-level phases:

&nbsp;   - Execution  

&nbsp;   - Persistence  

&nbsp;   - Credential / Account  

&nbsp;   - Discovery / Lateral  

&nbsp;   - Defense Evasion  

&nbsp;   - Unmapped / Multiple  

&nbsp; - Uses Sigma metadata, rule names, and keywords to infer MITRE ATT\&CK techniques.



\- Micro engine  

&nbsp; - Splits the (sampled) detections into blocks (“micro clusters”).  

&nbsp; - Calls an LLM in parallel to summarize each block.  

&nbsp; - Respects:

&nbsp;   - --micro-workers → parallel worker count.  

&nbsp;   - --rpm → soft rate limiting (requests per minute).  

&nbsp;   - --chunk-size → size of each micro block.  

&nbsp;   - --integrity on|off → conservative vs cheaper prompts.



\- Final engine  

&nbsp; - Takes the micro summaries as input.  

&nbsp; - Optionally runs a two-pass merge:

&nbsp;   - --two-pass:

&nbsp;     - Pass 1: outline + structure.

&nbsp;     - Pass 2: polished narrative built from the outline.

&nbsp; - Produces a single executive DFIR report with:

&nbsp;   - Executive summary  

&nbsp;   - Observed activity by phase  

&nbsp;   - MITRE TTPs  

&nbsp;   - Risk assessment  

&nbsp;   - Recommendations (with quick wins)  

&nbsp;   - Limitations / uncertainties  

&nbsp;   - Evidence appendix  



\- Renderers \& exports  

&nbsp; - Markdown:

&nbsp;   - forensynth\_summary\_YYYY-MM-DD.md  

&nbsp; - HTML:

&nbsp;   - forensynth\_report\_YYYY-MM-DD.html  

&nbsp;   - Optional branding \& table of contents.  

&nbsp;   - Visuals: heatmap + phase donuts.  

&nbsp; - Evidence JSON:

&nbsp;   - evidence.json – normalized view over key fields (rules, event IDs, phases, etc.).  

&nbsp; - Evidence CSV:

&nbsp;   - evidence.csv when --export-evidence-csv is used.



---



\## 2. Data Artifacts and Layout



Default lab layout (example):



DFIR-Labs/  

&nbsp; ForenSynth/  

&nbsp;   Reports/  

&nbsp;     2025-11-02\_153010Z/  

&nbsp;       detections.json           # raw Chainsaw detections  

&nbsp;       evidence.json             # normalized evidence  

&nbsp;       evidence.csv              # flattened evidence (optional)  

&nbsp;       forensynth\_summary\_\*.md   # Markdown DFIR report  

&nbsp;       forensynth\_report\_\*.html  # HTML DFIR report (visuals)  

&nbsp;       \*.png / \*.jpg             # screenshots / lab artifacts (optional)  



Key files:



\- detections.json  

&nbsp; - Raw Chainsaw output.  

&nbsp; - An array of detection objects (rules, event IDs, timestamps, etc.).



\- evidence.json (v2.3.4)  

&nbsp; - Normalized shape extracted from detections:

&nbsp;   - rule\_name  

&nbsp;   - event\_id  

&nbsp;   - phase  

&nbsp;   - timestamp  

&nbsp;   - host/user (if available)



\- evidence.csv (v2.3.4)  

&nbsp; - CSV flattening of evidence.json for:

&nbsp;   - Excel / spreadsheets  

&nbsp;   - SIEM / BI / Jupyter pivoting



\- Summary markdown/HTML  

&nbsp; - Human-readable report for:

&nbsp;   - GitHub examples  

&nbsp;   - DFIR case notes  

&nbsp;   - Attachments in tickets / emails  



---



\## 3. CLI Surface (v2.3.4)



The current CLI exposes options roughly along these lines:



\- Core:

&nbsp; - --evtx-dir PATH (or auto-discover latest directory in a lab path)  

&nbsp; - --two-pass  

&nbsp; - --integrity on|off  

&nbsp; - --max-input-tokens N (guardrail against over-large prompts)



\- Parallelism \& latency:

&nbsp; - --micro-workers N  

&nbsp; - --rpm N  

&nbsp; - --chunk-size N  

&nbsp; - --llm-timeout SECONDS  

&nbsp; - --llm-retries N  



\- Sampling (v2.3.4):

&nbsp; - --limit-detections N  

&nbsp; - --sample-step N  



\- Rendering:

&nbsp; - --make-html  

&nbsp; - --toc on|off  

&nbsp; - --branding on|off  

&nbsp; - --chart-style bar|donut|both  

&nbsp; - --export-evidence-csv  



Not every flag is required in every run; defaults are tuned for small/mid-sized lab hunts.



For large hunts (2k–3k detections), a typical combination is:



\- --limit-detections 1000  

\- --sample-step 3  

\- --micro-workers 3  



to keep latency and cost predictable.



---



\## 4. Visual Layer (HTML)



As of v2.3.4, the HTML report includes:



1\. Detection heatmap  

&nbsp;  - X-axis: days or time buckets.  

&nbsp;  - Y-axis: key Event IDs (1, 11, 13, 4104, 4688, 4720, 4728, etc.).  

&nbsp;  - Color intensity: detection count.  

&nbsp;  - Caption: short narrative of notable bursts.  

&nbsp;  - Footnote:  

&nbsp;    EventID 1 = Sysmon ProcessCreate; 11 = File create; 13 = Registry; 4104 = PowerShell ScriptBlock; etc.



2\. Donut charts  

&nbsp;  - Main donut: detections by phase:

&nbsp;    - Execution  

&nbsp;    - Persistence  

&nbsp;    - Credential / Account  

&nbsp;    - Discovery / Lateral  

&nbsp;    - Defense Evasion  

&nbsp;    - Unmapped / Multiple  

&nbsp;  - Consistent color palette across donuts and heatmap.  

&nbsp;  - Legends show counts + percentages.



3\. “At a glance” section  

&nbsp;  - Compact stats block near the top:

&nbsp;    - Total detections (raw)  

&nbsp;    - Sampled detections used by AI  

&nbsp;    - Number of micro blocks  

&nbsp;    - Time range  

&nbsp;    - Top Event IDs and top rules  



---



\## 5. LLM \& Cost Handling



ForenSynth AI uses OpenAI models via the official Python client.



\### 5.1 API Key Handling



\- Uses python-dotenv when available.  

\- Secure resolution logic:

&nbsp; - Looks for .env in:

&nbsp;   - Current working directory  

&nbsp;   - User home directory  

&nbsp; - Enforces “not world-readable / world-writable” for .env.  

\- Reads OPENAI\_API\_KEY from the environment:

&nbsp; - Fails fast with a clear error if not set.



\### 5.2 Models and Costs



\- Typical configuration:

&nbsp; - Micro passes: gpt-5-mini (or similar “mini” tier).  

&nbsp; - Final pass: gpt-5.  



As of v2.3.4:



\- Reads actual token usage from the API response.  

\- Prints a cost breakdown per model and total, for example:



\- gpt-5-mini: in=90,399, out=29,430 → $0.08146  

\- gpt-5:      in=29,912, out=2,281  → $0.06020  

\- Total cost: $0.14166  



This makes it easier to discuss feasibility of AI-assisted DFIR.



---



\## 6. Versioning \& Source Layout



Source layout in this repo:



src/  

&nbsp; v2.0/  

&nbsp; v2.1/  

&nbsp; v2.3.1/  

&nbsp; v2.3.2/  

&nbsp; v2.3.3/  

&nbsp; v2.3.4/  



docs/  

&nbsp; ARCHITECTURE.md  

&nbsp; CHANGELOG.md  

&nbsp; releases/  

&nbsp;   v2.3.4.md  



examples/  

&nbsp; ...  



\- Each vX.Y.Z folder contains a snapshot of that version’s script(s).  

\- v2.3.4 is the current polished iteration:

&nbsp; - forensynth\_ai\_v2\_3\_4\_polish.py is the primary entry point for DFIR reports.



---



\## 7. Extensibility Notes



Areas designed to be pluggable:



\- Upstream detector:

&nbsp; - Chainsaw is the default EVTX engine.  

&nbsp; - Other sources (e.g., EDR exports, Zeek logs) can be adapted by converting into a detections.json-like structure.



\- Phase / MITRE mapping:

&nbsp; - Current mapping is heuristic.  

&nbsp; - Can be extended with:

&nbsp;   - Explicit rule metadata  

&nbsp;   - External ATT\&CK knowledge bases  



\- Output formats:

&nbsp; - Current: Markdown, HTML, JSON, CSV.  

&nbsp; - Future:

&nbsp;   - STIX 2.1 bundles  

&nbsp;   - Direct SIEM / ticket system exports  



ForenSynth AI is intentionally built as a thin orchestration layer:



\- Upstream: detectors (Chainsaw).  

\- Middle: summarization logic (micro + final).  

\- Downstream: formats that humans and systems can consume.



The goal is human-led, AI-assisted DFIR:  

models help surface patterns; analysts still make the call.



