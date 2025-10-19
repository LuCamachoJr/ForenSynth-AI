# ForenSynth AI

Evidence-forward DFIR reporting engine. This repo reconstructs history from early Chainsaw summarizer (v1.0) to **v2.3.3 Visual** with clean commits, tags, and minimal examples.

## Versions (tags)
- v1.0.0 — Chainsaw Summarizer (static and 3.5 variants)
- v2.0.0 — First “ForenSynth AI” (two-pass)
- v2.1.0 — Resilience & retries
- v2.2.0 — Dev stream: Integrity Mode + heatmap HTML
- v2.3.2 — Max Fidelity (deterministic two-pass, Evidence Snapshot)
- v2.3.3 — Visual report release

---

## Quickstart (v2.3.3 Visual)

### Prereqs
- Python 3.11+
- Install deps: `pip install -r requirements.txt`

# Clone & setup
    git clone https://github.com/LuCamachoJr/ForenSynth-AI.git
    cd ForenSynth-AI
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt

# Run (adjust paths)
    python .\src\v2.3.3\forensynth_ai_v2_3_3_visual.py `
      --input "E:\Cases\case01\detections\detections.json" `
      --outdir "E:\Cases\case01\report" `
      --integrity `
      --html --pdf

### Outputs
- `report.md` / `report.html` / (optional) `report.pdf`
- `evidence_snapshot.json` and/or `evidence_snapshot.csv`
- `meta.txt` — model, timestamp, and SHA256 (from `--integrity`)

### See also
- Lab Setup & Telemetry Guide (Sysmon → Chainsaw → Sigma)
- ForenSynth v2.3.3 Quickstart (detections → narrative + visuals)

---

## CLI Usage (v2.3.3 Visual)

# Show help
    python .\src\v2.3.3\forensynth_ai_v2_3_3_visual.py --help

# Synopsis
    forensynth_ai_v2_3_3_visual.py --input <detections.json> --outdir <folder> [options]

# Required
- `--input PATH` — Path to Chainsaw/Sigma detections JSON (UTF-8).
- `--outdir DIR` — Output directory (created if missing).

# Output controls
- `--html` — Emit `report.html` (visual: KPI cards, heatmap).
- `--pdf` — Emit `report.pdf` (requires a PDF engine).
- `--integrity` — Write `meta.txt` with model, timestamp, SHA256.
- `--title TEXT` — Override report title.
- `--case-id TEXT` — Optional case identifier stamped in outputs.

# Evidence / appendix
- `--evidence-snapshot` — Write `evidence_snapshot.json` and `.csv` (hosts, users, rules, IOCs, counts).
- `--appendix` — Include IOC/MITRE appendix in the report.
- `--kpi` — Include KPI summary section.
- `--heatmap` — Include detections-by-time heatmap.

# Model / generation
- `--model NAME` — LLM identifier (default: repo/model default).
- `--max-batch INT` — Max detections per micro-summary batch (default: 200).
- `--temperature FLOAT` — Sampling temperature (default: 0.2).
- `--seed INT` — Deterministic seed (locks visual ordering/layout).

# Performance / logging
- `--workers INT` — Parallel worker count (default: auto).
- `--log-level LEVEL` — `debug | info | warning | error` (default: `info`).
- `--dry-run` — Parse inputs and print planned actions, then exit.
- `-h, --help` — Show help and exit.

# Example
    python .\src\v2.3.3\forensynth_ai_v2_3_3_visual.py `
      --input "E:\Cases\case01\detections\detections.json" `
      --outdir "E:\Cases\case01\report" `
      --html --pdf --integrity --evidence-snapshot --appendix --kpi --heatmap `
      --model gpt-5-large --max-batch 200 --temperature 0.2 --seed 42 `
      --title "Case 01 — ForenSynth Visual Report" --case-id CASE-2025-10-16

---




