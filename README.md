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

## Examples

### Minimal example (quick run)
    python .\src\v2.3.3\forensynth_ai_v2_3_3_visual.py `
      --input "E:\Cases\case01\detections\detections.json" `
      --outdir "E:\Cases\case01\report" `
      --html --integrity

### Advanced example (keep your existing one)
    # Example
    python .\src\v2.3.3\forensynth_ai_v2_3_3_visual.py `
      --input "E:\Cases\case01\detections\detections.json" `
      --outdir "E:\Cases\case01\report" `
      --html --pdf --integrity --evidence-snapshot --appendix --kpi --heatmap `
      --model gpt-5-large --max-batch 200 --temperature 0.2 --seed 42 `
      --title "Case 01 — ForenSynth Visual Report" --case-id CASE-2025-10-16

### What you should see
- report.html  → Visual report (KPI cards, heatmap, narrative)
- report.md    → Markdown narrative with sections
- evidence_snapshot.json / .csv → Hosts, users, rules, IOCs
- meta.txt     → Model, timestamp, SHA256

---

## Releases, Changelog, and Support

### Status badges (optional)
[![Lint](https://github.com/LuCamachoJr/ForenSynth-AI/actions/workflows/lint.yml/badge.svg)](https://github.com/LuCamachoJr/ForenSynth-AI/actions/workflows/lint.yml)

### Releases (tagged history)
- **v2.3.3** — Visual report (heatmap, KPI cards, IOC appendix)
- **v2.3.2** — Max Fidelity (deterministic two-pass, Evidence Snapshot)
- **v2.3.1** — Pre–max-fidelity polish and UX tweaks
- **v2.1.0** — Resilience & retry stream; improved batching
- **v2.0.0** — Two-pass pipeline (micro summaries → final)
- **v1.4.0** — Rebrand to ForenSynth AI (single-pass)
- **v1.3.1** — Fast profile v1: stability tweaks
- **v1.3.0** — GPT-5 fast profile for throughput tests
- **v1.2.0** — First GPT-5 integration
- **v1.1.0** — GPT-3.5 variant; cleaner narrative sections
- **v1.0.0** — Baseline Chainsaw summarizer (JSON → report)

### Changelog
See `CHANGELOG.md` for a one-line summary per version. Release notes on GitHub point back to these tags.

### How to pick a version
- **Stable visual report:** use `v2.3.3`.
- **Max fidelity deterministic runs:** try `v2.3.2`.
- **Historical lineage or comparisons:** check earlier tags under `src/<version>`.

### Issue reporting / questions
- Open an **Issue** with:
  - OS + Python version
  - ForenSynth tag (e.g., `v2.3.3`)
  - Exact command and minimal input (or a redacted sample)
  - Error output (copy/paste)
- For feature requests, propose the **CLI flag** and expected behavior.

### License
- Project license: see `LICENSE`.
- Third-party content: preserved under `THIRD_PARTY_NOTICES`.

---

## Install
- Python 3.11+
- Create a venv and install deps:
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt

## Contributing
- Open an Issue first for major changes; describe the CLI flags or output you expect.
- Code style: `ruff format .` then `ruff check . --fix`
- Python: 3.11+ (no backslash escapes inside f-strings; keep py311-safe)
- Commit messages: conventional style, e.g. `feat:`, `fix:`, `docs:`, `chore:`
- PR checklist:
  - [ ] Added/updated CLI help if new flags (`--help`)
  - [ ] Updated README examples if behavior changed
  - [ ] `ruff` passes locally

---

## Optional: LLM provider deps
# If you’re using OpenAI, install the extras:
#     pip install -r requirements-llm.txt
# Set your API key:
#     $env:OPENAI_API_KEY="sk-..."     # PowerShell
# or  export OPENAI_API_KEY="sk-..."   # bash/zsh

### Suggested code guard (inside your CLI init)
# Pseudocode: fail gracefully if OpenAI is enabled but package/env is missing.
try:
    import openai  # only when provider == "openai"
except ImportError as e:
    raise SystemExit("OpenAI provider selected but 'openai' package not installed. Try: pip install -r requirements-llm.txt")

# Also check:
# if not os.getenv("OPENAI_API_KEY"):
#     raise SystemExit("OPENAI_API_KEY is not set.")

---

    





