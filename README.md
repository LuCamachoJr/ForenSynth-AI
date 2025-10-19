\# ForenSynth AI

Evidence-forward DFIR reporting engine. This repo reconstructs history from early Chainsaw summarizer (v1.0) to \*\*v2.3.3 Visual\*\* with clean commits, tags, and minimal examples.



\## Versions (tags)

\- v1.0.0 — Chainsaw Summarizer (static and 3.5 variants)

\- v2.0.0 — First “ForenSynth AI” (two-pass)

\- v2.1.0 — Resilience \& retries

\- v2.2.0 — Dev stream: Integrity Mode + heatmap HTML

\- v2.3.2 — Max Fidelity (deterministic two-pass, Evidence Snapshot)

\- v2.3.3 — Visual report release



\## Quickstart (v2.3.3 Visual)



\### Prereqs

\- Python 3.11+

\- `pip install -r requirements.txt`



&nbsp;   # Clone \& setup

&nbsp;   git clone https://github.com/LuCamachoJr/ForenSynth-AI.git

&nbsp;   cd ForenSynth-AI

&nbsp;   python -m venv venv

&nbsp;   venv\\Scripts\\activate

&nbsp;   pip install -r requirements.txt



&nbsp;   # Run (adjust paths)

&nbsp;   python .\\src\\v2.3.3\\forensynth\_ai\_v2\_3\_3\_visual.py `

&nbsp;     --input "E:\\Cases\\case01\\detections\\detections.json" `

&nbsp;     --outdir "E:\\Cases\\case01\\report" `

&nbsp;     --integrity `

&nbsp;     --html --pdf



\### Outputs

\- `report.md` / `report.html` / \*(optional)\* `report.pdf`

\- `evidence\_snapshot.json` and/or `evidence\_snapshot.csv`

\- `meta.txt` — model, timestamp, and SHA256 (from `--integrity`)



\### See also

\- Lab Setup \& Telemetry Guide (Sysmon → Chainsaw → Sigma)

\- ForenSynth v2.3.3 Quickstart (detections → narrative + visuals)



\## CLI Usage (v2.3.3 Visual)



\# Show help

python .\\src\\v2.3.3\\forensynth\_ai\_v2\_3\_3\_visual.py --help



\# Synopsis

forensynth\_ai\_v2\_3\_3\_visual.py --input <detections.json> --outdir <folder> \[options]



\# Required

&nbsp; --input PATH            Path to Chainsaw/Sigma detections JSON (UTF-8).

&nbsp; --outdir DIR            Output directory (created if missing).



\# Output controls

&nbsp; --html                  Emit report.html (visual: KPI cards, heatmap).

&nbsp; --pdf                   Emit report.pdf (requires a PDF engine).

&nbsp; --integrity             Write meta.txt with model, timestamp, SHA256.

&nbsp; --title TEXT            Override report title.

&nbsp; --case-id TEXT          Optional case identifier to stamp in outputs.



\# Evidence / appendix

&nbsp; --evidence-snapshot     Write evidence\_snapshot.json and .csv (hosts, users,

&nbsp;                         rules, IOCs, counts).

&nbsp; --appendix              Include IOC/MITRE appendix in the report.

&nbsp; --kpi                   Include KPI summary section in the report.

&nbsp; --heatmap               Include detections-by-time heatmap.



\# Model / generation

&nbsp; --model NAME            LLM identifier (default: gpt-5-large or repo default).

&nbsp; --max-batch INT         Max detections per micro-summary batch (default: 200).

&nbsp; --temperature FLOAT     Sampling temperature (default: 0.2).

&nbsp; --seed INT              Deterministic seed (locks visual ordering/layout).



\# Performance / logging

&nbsp; --workers INT           Parallel worker count (default: auto).

&nbsp; --log-level LEVEL       debug | info | warning | error (default: info).

&nbsp; --dry-run               Parse inputs and print planned actions, then exit.

&nbsp; -h, --help              Show this help and exit.



\# Example

python .\\src\\v2.3.3\\forensynth\_ai\_v2\_3\_3\_visual.py `

&nbsp; --input "E:\\Cases\\case01\\detections\\detections.json" `

&nbsp; --outdir "E:\\Cases\\case01\\report" `

&nbsp; --html --pdf --integrity --evidence-snapshot --appendix --kpi --heatmap `

&nbsp; --model gpt-5-large --max-batch 200 --temperature 0.2 --seed 42 `

&nbsp; --title "Case 01 — ForenSynth Visual Report" --case-id CASE-2025-10-16





