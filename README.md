# ForenSynth AI — DFIR Report Synthesizer

ForenSynth AI is a DFIR-focused log summarization engine that ingests **Chainsaw/Sigma detections**, groups them, and produces:

- Executive summary mapped to **MITRE ATT&CK**
- Micro-cluster summaries
- HTML visual report (heatmap + MITRE-phase donuts)
- CSV evidence appendix
- Actual OpenAI usage & cost summary
- Integrity metadata, timelines, and breakdowns

---

# Versions (tags)

- **v1.0.0** — Chainsaw Summarizer (static + 3.5)
- **v2.0.0** — First “ForenSynth AI”
- **v2.1.0** — Resilience & retries
- **v2.2.0** — Dev-stream visuals (heatmap)
- **v2.3.2** — Max Fidelity (deterministic two-pass)
- **v2.3.3** — Visual Release (KPI cards + heatmap)
- **v2.3.4** — **Polish: donuts + heatmap, sampling governor, CSV export, real cost calculations (current)**

---

# Quickstart (v2.3.3 Visual)

> v2.3.3 is kept as a “pure visuals” baseline.  
> For the *latest* visuals + sampling + CSV, use **v2.3.4 Polish** (see below).

## Setup

Create a virtual environment and install dependencies:

    python -m venv venv
    venv\Scripts\activate  # Windows
    pip install -r requirements.txt

## Run (v2.3.3 Visual)

    python .\src\v2.3.3\forensynth_ai_v2_3_3_visual.py ^
      --input "E:\Case\detections.json" ^
      --outdir "E:\Case\report" ^
      --html ^
      --integrity

### Outputs (v2.3.3)

- HTML report
- Markdown summary
- Integrity meta
- Evidence snapshot

---

# v2.3.4 Polish (current)

`src/v2.3.4/forensynth_ai_v2_3_4_polish.py` is the newest iteration.

## What’s new in v2.3.4

**MITRE-mapped donut charts**

- Donuts by phase:
  - Execution
  - Persistence
  - Discovery
  - Lateral Movement
  - Defense Evasion
  - Unmapped / Multiple

**Heatmap polish**

- Caption under the heatmap
- EventID footnote (e.g., 1 = Process Create, 13 = Registry, 4104 = ScriptBlock)
- Consistent color palette with the donuts

**Sampling Governor**

Designed for **2k–3k detections** so you can still get a clean, readable report:

- `--limit-detections N`  
- `--sample-step N` (stratified sampling)

Example:  
2705 detections → step 3 → 902 summarized detections → much better runtime and cost.

**CSV Evidence Appendix**

`--export-evidence-csv` produces a CSV with:

- Rule → count → ATT&CK phase
- Entities (users, accounts, tasks, etc.)
- Key timestamps

This is meant as a pivot table for analysts.

**Real OpenAI cost**

- Uses real `response.usage` token counts instead of estimates
- Cost section now matches the OpenAI dashboard for the run

**Micro-cap governor**

- Caps number of micro-summaries by both detection count and token budget
- Keeps final merge latency + cost under control while preserving coverage

**Meta improvements**

- “Selected micros: X / Y blocks” shown in the report
- EventID explanation footnote near the visuals
- More readable legends
- Cleaner HTML structure

---

# Running v2.3.4 Polish

Typical usage on Windows:

    python .\src\v2.3.4\forensynth_ai_v2_3_4_polish.py ^
      --input "E:\Case\detections.json" ^
      --outdir "E:\Case\polish-report" ^
      --html ^
      --integrity ^
      --export-evidence-csv ^
      --chart-style both ^
      --limit-detections 1000 ^
      --sample-step 3

Outputs:

- `forensynth_report_YYYY-MM-DD.html`
- `forensynth_summary_YYYY-MM-DD.md`
- `evidence.csv`
- `meta.txt`
- `detections.json` (input copy or reference)

---

# Sampling Notes (POC)

Example production-style POC run:

- Raw detections: **2705**
- Sampling: `step=3`, `limit-detections=1000` → **902** used for micro summaries
- Runtime: **~5 minutes** on a Kali VM
- Cost: **~$0.07** (gpt-5-mini + gpt-5 combo)

This makes it feasible to:

- Run repeatedly on lab data
- Show to hiring managers / mentors
- Use in HTB/DFIR write-ups without breaking the bank

---

# Examples

Example folder structure:

    examples/
      2025-11-02-polish-run/
        forensynth_summary_2025-11-02.md
        forensynth_report_2025-11-02.html
        evidence.csv
        detections.json

These artifacts can be used for:

- Portfolio / GitHub “Featured” items
- LinkedIn posts
- Walk-through blog posts
- DFIR demos and training

---

# CLI Differences (v2.3.4 vs v2.3.3)

New or important flags in **v2.3.4**:

- `--chart-style {bar,donuts,both}`  
  Controls visuals: classic bar heatmap, MITRE donuts, or both.

- `--export-evidence-csv`  
  Writes an `evidence.csv` appendix for further analysis.

- `--limit-detections N`  
  Hard cap on total detections fed into micro summaries.

- `--sample-step N`  
  Stratified down-sampling of detections (e.g., every 3rd).

- `--max-input-tokens N`  
  Safety guard for very large runs (protects against out-of-control token usage).

View full CLI help:

    python .\src\v2.3.4\forensynth_ai_v2_3_4_polish.py --help

---

# Project Vision

ForenSynth AI started as a “vibe-coded” idea coming out of a Windows Event Logs & Finding Evil lab (HTB-style) and evolved into a working DFIR assistant:

- Uses Chainsaw + Sigma as the telemetry engine
- Uses an LLM to compress noisy detections into:
  - Executive report
  - Micro-cluster summaries
  - Visual MITRE overview
- Wraps it in:
  - Sampling guards (cost + time)
  - Evidence exports (CSV)
  - Real cost transparency

The project reflects a modern approach to DFIR where:

- **Analyst** designs the workflow and interpretation
- **AI** helps with pattern recognition and summarization
- **Tools** like Chainsaw, Sysmon, and Sigma remain the primary telemetry sources

ForenSynth AI is not a “push-button forensics solution.”  
It is a **DFIR co-pilot**: it accelerates triage and reporting, but **the human analyst still makes the call.**
