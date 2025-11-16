# Changelog

All notable changes to **ForenSynth AI** will be documented in this file.

Dates are approximate lab milestones, not formal release dates.

---

## [2.3.4] — 2025-11-02 — “Polish”

### Added
- **Sampling governor** for large hunts:
  - `--limit-detections` to cap detections after sampling.
  - `--sample-step` to keep every N-th detection.
  - Runtime banner showing original vs sampled counts, e.g.:
    - `⚙ Sampling applied: 2705 → 902 (step=3, limit=1000)`
- **Evidence Appendix** section in HTML:
  - Top Sigma rules and counts.
  - Event ID distribution.
  - Persistence artifact overview (Scheduled Tasks, Run keys, services/COM).
  - Sampling banner clarifying scope of the summarized slice.
- **Evidence CSV export**:
  - `--export-evidence-csv` writes `evidence.csv` alongside `evidence.json`.
  - Flattened evidence rows for quick pivoting in Excel / SIEM / BI tools.
- **Donut charts** with MITRE-mapped phases:
  - Primary donut: detections by phase
    - Execution
    - Persistence
    - Credential / Account
    - Discovery / Lateral
    - Defense Evasion
    - Unmapped / Multiple
  - Optional donuts for Event IDs and rule/behavior categories.
  - Controlled by `--chart-style donut` or `--chart-style both`.
- **Improved cost breakdown** (LLM usage):
  - Read actual input/output token usage from the OpenAI API.
  - Print approximate dollar figure per model and total.
- **Event ID footnote and captions**:
  - Short explanation of common Event IDs (1, 11, 13, 4104, 4688, 4720, 4728…).
  - Heatmap caption calling out notable bursts by date/time.

### Changed
- HTML report layout refined:
  - Legends now surface **counts + percentages**.
  - Slight font/spacing improvements for readability in lab VMs.
  - Footer explicitly documents:
    - Original vs sampled detections.
    - That micro-summaries reflect the sampled subset, not raw EVTX.
- Micro/final prompts:
  - Re-tuned for more structured DFIR narrative:
    - Clearer risk section.
    - Actionable recommendations with quick wins.
    - Explicit “Uncertainties / Limitations” call-out.
- Documentation:
  - `ARCHITECTURE.md` updated to describe sampling, donuts, evidence CSV.
  - `docs/releases/v2.3.4.md` added for this release.

### Fixed
- Ensured non-ASCII banners / stray characters do not break linting/CI.
- Minor robustness fixes:
  - More defensive JSON loading and sampling.
  - Better guardrails around max input token usage.

---

## [2.3.3] — 2025-10-14 — “Visual Refresh”

### Added
- **HTML visualizations**:
  - Detection bar chart by Event ID / day.
  - Detection heatmap (Event IDs vs days) with intensity based on count.
- **Branding block**:
  - Optional “Trace & Triage / RunQuiet”-style header.
  - Controlled via `--branding on|off`.
- **Table of contents**:
  - In-page TOC for HTML output.
  - Enabled via `--toc on`.
- **Runtime summary footer**:
  - Shows detections, runtime, models used, and cost estimate.

### Changed
- HTML layout:
  - Cleaner separation of **Executive Summary**, **TTPs**, **Risk**, and **Appendix**.
  - Responsive-ish layout inside a single static HTML file (no external CSS).
- Log messages:
  - Nicer CLI banners (ASCII) and step labels for:
    - Chainsaw run.
    - Evidence load.
    - Micro phase.
    - Final merge.

### Fixed
- Minor issues with Markdown → HTML conversion that could truncate long lines.
- Corrected some event labeling in at-a-glance statistics.

---

## [2.3.2] — 2025-10-13 — “Max Fidelity”

### Added
- **Max fidelity mode**:
  - `--max-fidelity` toggles more conservative summarization:
    - Larger micro chunks but stricter prompts.
    - Emphasis on preserving counts, timelines, and caveats.
- **Stricter retry / timeout handling**:
  - Global `--llm-timeout` and `--llm-retries` applied to both micro and final phases.
  - Better error messages for “LLM retries exceeded / request timed out”.
- **Two-pass final merge**:
  - `--two-pass`:
    - Pass 1: structure & outline.
    - Pass 2: polished final narrative based on the outline.

### Changed
- Executive summary structure:
  - Standardized sections:
    - “What happened”
    - “Scope at a glance”
    - “Likely intent”
    - “Business risk”
- Micro cluster output:
  - More consistent “Executive bullets / Key TTPs / IOCs / Actions” pattern.

### Fixed
- Cost estimates:
  - Adjusted token math so estimated costs better match OpenAI dashboard.
- Handled odd edge cases:
  - Empty or very small detection sets no longer generate awkward summaries.

---

## [2.3.1] — 2025-10-12 — “Parallel Micro”

### Added
- **Micro-summaries in parallel**:
  - Introduced micro chunking and workers:
    - `--micro-workers` for concurrency.
    - `--rpm` (requests per minute) as a soft throttle.
    - `--chunk-size` for micro block size.
- **Integrity flag**:
  - Early version of `--integrity on|off` to favor accuracy vs cost.
- **Basic metrics**:
  - Printed counts of:
    - Detections.
    - Micro blocks.
    - Approx token usage.

### Changed
- From “single giant prompt” to **micro + merge** pipeline:
  - Greatly improved scalability for 1k+ detections.
- Prompting:
  - Shifted from purely log-line-driven to **cluster-driven** summaries:
    - Multi-event time windows.
    - Phase-based grouping (execution, persistence, etc.).

### Fixed
- Eliminated occasional “wall of text” summaries by forcing a sectioned layout in the final merge.
- Improved handling of weird timestamps and partial fields.

---

## [2.1.0] — 2025-10-01 — “Structured DFIR”

### Added
- **DFIR-shaped report template**:
  - Sections:
    - Executive summary.
    - Observed activity (by phase).
    - Key TTPs (MITRE).
    - Risk assessment.
    - Recommendations.
- **MITRE ATT&CK mapping (v1)**:
  - Initial mapping from rule tags / keywords to ATT&CK technique IDs.
  - Basic table in the Markdown output.

### Changed
- Switched from “just a paragraph summary” to **multi-section** markdown reports.
- Better syslog/Sigma wording in the prompts so reports sound like incident notes, not generic AI text.

### Fixed
- Several edge cases where missing fields (e.g., no username) caused prompt formatting errors.
- More resilient timestamp parsing for Chainsaw output.

---

## [2.0.0] — 2025-09-20 — “Chainsaw Integration”

### Added
- **First integrated Chainsaw → LLM pipeline**:
  - Invokes Chainsaw with a ruleset against EVTX/EVT.
  - Consumes the resulting `detections.json` as primary input.
- **Markdown report generation**:
  - Writes `forensynth_summary_YYYY-MM-DD.md`.
  - Basic sections for:
    - Overview.
    - Notable detections.
    - High-level recommendations.
- **Basic CLI**:
  - Core options for:
    - EVTX directory path.
    - Model selection (`gpt-4` → later upgraded to `gpt-5` family).
    - Temperature and basic timeout.

### Changed
- Transitioned from “single file EVTX experiments” to **directory-based lab runs**.
- Aligned naming and folder structure with DFIR lab conventions:
  - `DFIR-Labs/ForenSynth/Reports/<timestamp>/`.

### Fixed
- Early JSON parsing bugs for detections containing nested fields or unusual Unicode.

---

## [1.4.0]

- Rebrand to ForenSynth AI (single-pass)

---

## [1.3.1]

- Fast profile v1: stability tweaks

---

## [1.3.0]

- GPT-5 fast profile for throughput tests

---

## [1.2.0]

- First GPT-5 integration

---

## [1.1.0]

- GPT-3.5 variant; cleaner narrative sections

---

## Legend

- **Added** — new features.
- **Changed** — behavior or interface changes (not necessarily breaking).
- **Fixed** — bug fixes or robustness improvements.

Older experiments and throwaway scripts prior to **v1.1.0** are not tracked here; they were ad-hoc prototypes and lab notebooks rather than part of the maintained tool.
