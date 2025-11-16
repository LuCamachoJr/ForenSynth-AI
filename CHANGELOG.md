\# Changelog



All notable changes to \*\*ForenSynth AI\*\* will be documented in this file.



Dates are approximate lab milestones, not formal release dates.



---



\## \[2.3.4] — 2025-11-02 — “Polish”



\### Added

\- \*\*Sampling governor\*\* for large hunts:

&nbsp; - `--limit-detections` to cap detections after sampling.

&nbsp; - `--sample-step` to keep every N-th detection.

&nbsp; - Runtime banner showing original vs sampled counts, e.g.:

&nbsp;   - `⚙ Sampling applied: 2705 → 902 (step=3, limit=1000)`

\- \*\*Evidence Appendix\*\* section in HTML:

&nbsp; - Top Sigma rules and counts.

&nbsp; - Event ID distribution.

&nbsp; - Persistence artifact overview (Scheduled Tasks, Run keys, services/COM).

&nbsp; - Sampling banner clarifying scope of the summarized slice.

\- \*\*Evidence CSV export\*\*:

&nbsp; - `--export-evidence-csv` writes `evidence.csv` alongside `evidence.json`.

&nbsp; - Flattened evidence rows for quick pivoting in Excel / SIEM / BI tools.

\- \*\*Donut charts\*\* with MITRE-mapped phases:

&nbsp; - Primary donut: detections by phase

&nbsp;   - Execution

&nbsp;   - Persistence

&nbsp;   - Credential / Account

&nbsp;   - Discovery / Lateral

&nbsp;   - Defense Evasion

&nbsp;   - Unmapped / Multiple

&nbsp; - Optional donuts for Event IDs and rule/behavior categories.

&nbsp; - Controlled by `--chart-style donut` or `--chart-style both`.

\- \*\*Improved cost breakdown\*\* (LLM usage):

&nbsp; - Read actual input/output token usage from the OpenAI API.

&nbsp; - Print approximate dollar figure per model and total.

\- \*\*Event ID footnote and captions\*\*:

&nbsp; - Short explanation of common Event IDs (1, 11, 13, 4104, 4688, 4720, 4728…).

&nbsp; - Heatmap caption calling out notable bursts by date/time.



\### Changed

\- HTML report layout refined:

&nbsp; - Legends now surface \*\*counts + percentages\*\*.

&nbsp; - Slight font/spacing improvements for readability in lab VMs.

&nbsp; - Footer explicitly documents:

&nbsp;   - Original vs sampled detections.

&nbsp;   - That micro-summaries reflect the sampled subset, not raw EVTX.

\- Micro/final prompts:

&nbsp; - Re-tuned for more structured DFIR narrative:

&nbsp;   - Clearer risk section.

&nbsp;   - Actionable recommendations with quick wins.

&nbsp;   - Explicit “Uncertainties / Limitations” call-out.

\- Documentation:

&nbsp; - `ARCHITECTURE.md` updated to describe sampling, donuts, evidence CSV.

&nbsp; - `docs/releases/v2.3.4.md` added for this release.



\### Fixed

\- Ensured non-ASCII banners / stray characters do not break linting/CI.

\- Minor robustness fixes:

&nbsp; - More defensive JSON loading and sampling.

&nbsp; - Better guardrails around max input token usage.



---



\## \[2.3.3] — 2025-10-14 — “Visual Refresh”



\### Added

\- \*\*HTML visualizations\*\*:

&nbsp; - Detection bar chart by Event ID / day.

&nbsp; - Detection heatmap (Event IDs vs days) with intensity based on count.

\- \*\*Branding block\*\*:

&nbsp; - Optional “Trace \& Triage / RunQuiet”-style header.

&nbsp; - Controlled via `--branding on|off`.

\- \*\*Table of contents\*\*:

&nbsp; - In-page TOC for HTML output.

&nbsp; - Enabled via `--toc on`.

\- \*\*Runtime summary footer\*\*:

&nbsp; - Shows detections, runtime, models used, and cost estimate.



\### Changed

\- HTML layout:

&nbsp; - Cleaner separation of \*\*Executive Summary\*\*, \*\*TTPs\*\*, \*\*Risk\*\*, and \*\*Appendix\*\*.

&nbsp; - Responsive-ish layout inside a single static HTML file (no external CSS).

\- Log messages:

&nbsp; - Nicer CLI banners (ASCII) and step labels for:

&nbsp;   - Chainsaw run.

&nbsp;   - Evidence load.

&nbsp;   - Micro phase.

&nbsp;   - Final merge.



\### Fixed

\- Minor issues with Markdown → HTML conversion that could truncate long lines.

\- Corrected some event labeling in at-a-glance statistics.



---



\## \[2.3.2] — 2025-10-13 — “Max Fidelity”



\### Added

\- \*\*Max fidelity mode\*\*:

&nbsp; - `--max-fidelity` toggles more conservative summarization:

&nbsp;   - Larger micro chunks but stricter prompts.

&nbsp;   - Emphasis on preserving counts, timelines, and caveats.

\- \*\*Stricter retry / timeout handling\*\*:

&nbsp; - Global `--llm-timeout` and `--llm-retries` applied to both micro and final phases.

&nbsp; - Better error messages for “LLM retries exceeded / request timed out”.

\- \*\*Two-pass final merge\*\*:

&nbsp; - `--two-pass`:

&nbsp;   - Pass 1: structure \& outline.

&nbsp;   - Pass 2: polished final narrative based on the outline.



\### Changed

\- Executive summary structure:

&nbsp; - Standardized sections:

&nbsp;   - “What happened”

&nbsp;   - “Scope at a glance”

&nbsp;   - “Likely intent”

&nbsp;   - “Business risk”

\- Micro cluster output:

&nbsp; - More consistent “Executive bullets / Key TTPs / IOCs / Actions” pattern.



\### Fixed

\- Cost estimates:

&nbsp; - Adjusted token math so estimated costs better match OpenAI dashboard.

\- Handled odd edge cases:

&nbsp; - Empty or very small detection sets no longer generate awkward summaries.



---



\## \[2.3.1] — 2025-10-12 — “Parallel Micro”



\### Added

\- \*\*Micro-summaries in parallel\*\*:

&nbsp; - Introduced micro chunking and workers:

&nbsp;   - `--micro-workers` for concurrency.

&nbsp;   - `--rpm` (requests per minute) as a soft throttle.

&nbsp;   - `--chunk-size` for micro block size.

\- \*\*Integrity flag\*\*:

&nbsp; - Early version of `--integrity on|off` to favor accuracy vs cost.

\- \*\*Basic metrics\*\*:

&nbsp; - Printed counts of:

&nbsp;   - Detections.

&nbsp;   - Micro blocks.

&nbsp;   - Approx token usage.



\### Changed

\- From “single giant prompt” to \*\*micro + merge\*\* pipeline:

&nbsp; - Greatly improved scalability for 1k+ detections.

\- Prompting:

&nbsp; - Shifted from purely log-line-driven to \*\*cluster-driven\*\* summaries:

&nbsp;   - Multi-event time windows.

&nbsp;   - Phase-based grouping (execution, persistence, etc.).



\### Fixed

\- Eliminated occasional “wall of text” summaries by forcing a sectioned layout in the final merge.

\- Improved handling of weird timestamps and partial fields.



---



\## \[2.1.0] — 2025-10-01 — “Structured DFIR”



\### Added

\- \*\*DFIR-shaped report template\*\*:

&nbsp; - Sections:

&nbsp;   - Executive summary.

&nbsp;   - Observed activity (by phase).

&nbsp;   - Key TTPs (MITRE).

&nbsp;   - Risk assessment.

&nbsp;   - Recommendations.

\- \*\*MITRE ATT\&CK mapping (v1)\*\*:

&nbsp; - Initial mapping from rule tags / keywords to ATT\&CK technique IDs.

&nbsp; - Basic table in the Markdown output.



\### Changed

\- Switched from “just a paragraph summary” to \*\*multi-section\*\* markdown reports.

\- Better syslog/Sigma wording in the prompts so reports sound like incident notes, not generic AI text.



\### Fixed

\- Several edge cases where missing fields (e.g., no username) caused prompt formatting errors.

\- More resilient timestamp parsing for Chainsaw output.



---



\## \[2.0.0] — 2025-09-20 — “Chainsaw Integration”



\### Added

\- \*\*First integrated Chainsaw → LLM pipeline\*\*:

&nbsp; - Invokes Chainsaw with a ruleset against EVTX/EVT.

&nbsp; - Consumes the resulting `detections.json` as primary input.

\- \*\*Markdown report generation\*\*:

&nbsp; - Writes `forensynth\_summary\_YYYY-MM-DD.md`.

&nbsp; - Basic sections for:

&nbsp;   - Overview.

&nbsp;   - Notable detections.

&nbsp;   - High-level recommendations.

\- \*\*Basic CLI\*\*:

&nbsp; - Core options for:

&nbsp;   - EVTX directory path.

&nbsp;   - Model selection (`gpt-4` → later upgraded to `gpt-5` family).

&nbsp;   - Temperature and basic timeout.



\### Changed

\- Transitioned from “single file EVTX experiments” to \*\*directory-based lab runs\*\*.

\- Aligned naming and folder structure with DFIR lab conventions:

&nbsp; - `DFIR-Labs/ForenSynth/Reports/<timestamp>/`.



\### Fixed

\- Early JSON parsing bugs for detections containing nested fields or unusual Unicode.



---



\## \[1.4.0]



\- Rebrand to ForenSynth AI (single-pass)



---



\## \[1.3.1]



\- Fast profile v1: stability tweaks



---



\## \[1.3.0]



\- GPT-5 fast profile for throughput tests



---



\## \[1.2.0]



\- First GPT-5 integration



---



\## \[1.1.0]



\- GPT-3.5 variant; cleaner narrative sections



---



\## Legend



\- \*\*Added\*\* — new features.

\- \*\*Changed\*\* — behavior or interface changes (not necessarily breaking).

\- \*\*Fixed\*\* — bug fixes or robustness improvements.



Older experiments and throwaway scripts prior to \*\*v1.1.0\*\* are not tracked here; they were ad-hoc prototypes and lab notebooks rather than part of the maintained tool.



