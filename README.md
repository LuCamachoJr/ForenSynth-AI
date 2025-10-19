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



