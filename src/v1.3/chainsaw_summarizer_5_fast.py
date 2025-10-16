#!/usr/bin/env python3
"""
chainsaw_summarizer_5_fast_adaptive.py

DFIR fast pipeline:
1) Auto-select newest EVTX folder; hunt ALL .evtx with Chainsaw + Sigma.
2) Robustly load detections (array root or {"detections": [...]})
3) If zero detections → skip LLM, write minimal report, exit cleanly.
4) Else summarize:
   - micro/chunks in parallel with gpt-5-mini
   - final executive merge with gpt-5
5) Write Markdown (+ optional HTML/PDF), show token usage and cost.

Requires:
- chainsaw (in PATH)
- OPENAI_API_KEY in env
- sigma rules path (defaults to ~/tools/sigma/rules)
- mapping path (defaults to ~/tools/chainsaw/sigma-event-logs-all.yml)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pypandoc
import tiktoken
from dotenv import load_dotenv
from openai import OpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()


# ─────────────────────────── UI helpers ───────────────────────────
def ok(msg):
    console.print(Panel.fit(f"[green]✔ {msg}[/green]"))


def info(msg):
    console.print(Panel.fit(f"[yellow]⚙ {msg}[/yellow]"))


def die(msg):
    console.print(Panel.fit(f"[red]✘ {msg}[/red]"))
    sys.exit(1)


# ─────────────────────────── Pricing (per 1K tokens) ───────────────────────────
PRICING = {
    "gpt-5-mini": {"in": 0.00025, "out": 0.00200},
    "gpt-5": {"in": 0.00125, "out": 0.01000},
}

# ─────────────────────────── Prompts ───────────────────────────
DEFAULT_SYSTEM_PROMPT = (
    "You are a senior DFIR analyst. Produce concise, accurate summaries.\n"
    "Group related detections, highlight notable TTPs/tooling, dedupe repetition, "
    "and end with actionable recommendations prioritized by risk and effort."
)
FINAL_SYSTEM_PROMPT = (
    "You are a DFIR lead. Merge the micro-summaries into a single executive report. "
    "Eliminate repetition, group by phases/TTPs, quantify scope where possible, "
    "and end with prioritized recommendations (High/Med/Low) and quick wins."
)


# ─────────────────────────── CLI ───────────────────────────
@dataclass
class AppConfig:
    evtx_root: Path
    rules: Path
    mapping: Path
    outdir: Path
    chunk_size: int
    max_chunks: int
    make_html: bool
    make_pdf: bool
    two_pass: bool
    chunk_model: str
    final_model: str
    llm_timeout: int
    llm_max_retries: int
    llm_temperature: float
    rpm: int
    micro_workers: str
    fast: bool
    micro_truncate: int
    micro_include_script: bool
    final_max_input_tokens: int


def parse_args() -> AppConfig:
    p = argparse.ArgumentParser(description="Chainsaw summarizer (fast, two-pass, adaptive)")
    p.add_argument("--evtx-root", type=Path, default=Path("/mnt/evtx_share/DFIR-Lab-Logs"))
    p.add_argument("--rules", type=Path, default=Path("~/tools/sigma/rules").expanduser())
    p.add_argument("--mapping", type=Path, default=Path("~/tools/chainsaw/sigma-event-logs-all.yml").expanduser())
    p.add_argument("--outdir", type=Path, default=Path.home() / "DFIR-Labs" / "chainsaw_summaries")
    p.add_argument("--chunk-size", type=int, default=40)  # fewer API calls
    p.add_argument("--max-chunks", type=int, default=100)
    p.add_argument("--make-html", action="store_true")
    p.add_argument("--make-pdf", action="store_true")
    p.add_argument("--two-pass", action="store_true")
    p.add_argument("--chunk-model", default="gpt-5-mini")
    p.add_argument("--final-model", default="gpt-5")
    p.add_argument("--llm-timeout", type=int, default=90)
    p.add_argument("--llm-max-retries", type=int, default=6)
    p.add_argument("--llm-temperature", type=float, default=0)
    p.add_argument("--rpm", type=int, default=60)
    p.add_argument("--micro-workers", type=str, default="auto")  # "auto" or int
    p.add_argument("--fast", action="store_true", help="Enable fast defaults for speed")
    p.add_argument("--micro-truncate", type=int, default=200, help="ScriptBlockText chars to keep in micro (0=omit)")
    p.add_argument("--micro-include-script", action="store_true", help="Include ScriptBlockText snippet in micro pass")
    p.add_argument("--final-max-input-tokens", type=int, default=20000, help="Cap input tokens into final merge")
    a = p.parse_args()

    # fast preset
    if a.fast:
        if a.rpm == 0:
            a.rpm = 60
        if a.chunk_size < 40:
            a.chunk_size = 40
        if a.llm_max_retries > 8 or a.llm_max_retries < 4:
            a.llm_max_retries = 6
        if a.llm_timeout < 60:
            a.llm_timeout = 90
        if not a.micro_include_script:
            a.micro_include_script = True

    return AppConfig(
        evtx_root=a.evtx_root,
        rules=a.rules,
        mapping=a.mapping,
        outdir=a.outdir,
        chunk_size=max(1, a.chunk_size),
        max_chunks=max(1, a.max_chunks),
        make_html=a.make_html,
        make_pdf=a.make_pdf,
        two_pass=a.two_pass,
        chunk_model=a.chunk_model,
        final_model=a.final_model,
        llm_timeout=a.llm_timeout,
        llm_max_retries=a.llm_max_retries,
        llm_temperature=a.llm_temperature,
        rpm=a.rpm,
        micro_workers=a.micro_workers,
        fast=a.fast,
        micro_truncate=max(0, a.micro_truncate),
        micro_include_script=a.micro_include_script,
        final_max_input_tokens=max(4000, a.final_max_input_tokens),
    )


# ─────────────────────────── EVTX discovery ───────────────────────────
def ensure_chainsaw():
    if shutil.which("chainsaw") is None:
        die("chainsaw not found in PATH")


def newest_container(root: Path) -> Path:
    if not root.exists():
        die(f"EVTX root not found: {root}")
    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs:
        die(f"No subfolders under {root}")
    latest = max(dirs, key=lambda p: p.stat().st_mtime)
    ok(f"Using latest EVTX directory: {latest}")
    return latest


def run_chainsaw(src_dir: Path, out_path: Path, rules: Path, mapping: Path):
    info("Running Chainsaw hunt…")
    sigma_root = str(Path(rules).parent)
    evtx_files = list(src_dir.glob("*.evtx"))
    if not evtx_files:
        die(f"No .evtx files found in {src_dir}")
    cmd = [
        "chainsaw",
        "hunt",
        str(src_dir),
        "--mapping",
        str(mapping),
        "--rule",
        str(rules),
        "-s",
        sigma_root,
        "--json",
        "--output",
        str(out_path),
    ]
    subprocess.run(cmd, check=True)
    ok("Chainsaw hunt completed.")


# ─────────────────────────── Detections loader (adaptive) ───────────────────────────
def load_detections(path: Path) -> List[Dict[str, Any]]:
    txt = path.read_text(encoding="utf-8").strip()
    if not txt:
        return []
    data = json.loads(txt)
    if isinstance(data, dict) and "detections" in data and isinstance(data["detections"], list):
        return data["detections"]
    if isinstance(data, list):
        return data
    return []


# ─────────────────────────── Token utils ───────────────────────────
def get_encoder():
    try:
        return tiktoken.get_encoding("cl100k_base")
    except Exception:
        return tiktoken.get_encoding("cl100k_base")


def est_tokens(enc, text: str) -> int:
    try:
        return len(enc.encode(text))
    except Exception:
        return max(1, len(text) // 4)


# ─────────────────────────── LLM plumbing ───────────────────────────
class RateLimiter:
    def __init__(self, rpm: int):
        self.interval = 60.0 / rpm if rpm > 0 else 0.0
        self.next = 0.0

    def wait(self):
        if self.interval <= 0:
            return
        now = time.time()
        if now < self.next:
            time.sleep(self.next - now)
        self.next = max(now, self.next) + self.interval


def backoff_sleep(i: int):
    time.sleep(min(30.0, (1.5**i) + random.uniform(0, 0.3)))


def call_llm(
    client: OpenAI, model: str, system_prompt: str, user_prompt: str, temperature: float, timeout_s: int, retries: int
) -> str:
    # Ensure temperature is compatible with GPT-5 family
    safe_temp = 1.0 if model.startswith("gpt-5") else temperature
    for i in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                temperature=safe_temp,
                timeout=timeout_s,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            warn(f"LLM call failed (attempt {i + 1}/{retries}): {e}")
            backoff_sleep(i)
    die(f"LLM call failed after {retries} retries.")


# ─────────────────────────── Prompt builders ───────────────────────────
def format_script_snippet(det: Dict[str, Any], include: bool, limit: int) -> str:
    if not include or limit <= 0:
        return ""
    script = (
        (((det.get("document") or {}).get("data") or {}).get("Event") or {})
        .get("EventData", {})
        .get("ScriptBlockText", "")
    )
    if not isinstance(script, str) or not script:
        return ""
    return script[:limit] + ("… [truncated]" if len(script) > limit else "")


def build_micro_prompt(block: List[Dict[str, Any]], include_script: bool, micro_truncate: int) -> str:
    lines = [
        "Micro-summarize these detections for DFIR triage in <= 12 bullets total.",
        "Group similar items, name key TTPs (MITRE IDs if present), mention counts/timestamps if available.",
        "No fluff, no repetition.",
        "Output bullets only.",
    ]
    for det in block:
        name = det.get("name") or (det.get("rule") or {}).get("title") or "Untitled"
        ts = det.get("timestamp", "N/A")
        tags = ", ".join(det.get("tags", []) or []) or "None"
        eid = (
            (((det.get("document") or {}).get("data") or {}).get("Event") or {}).get("System", {}).get("EventID", "N/A")
        )
        snippet = format_script_snippet(det, include_script, micro_truncate)
        line = f"- [{ts}] {name} (EventID {eid}; Tags: {tags})"
        if snippet:
            line += f" | snippet: {snippet}"
        lines.append(line)
    return "\n".join(lines)


def build_final_prompt(micro_sections: List[str]) -> str:
    return (
        "Merge the following micro-summaries into one executive DFIR report. "
        "Eliminate duplicates, group themes, and produce:\n"
        "1) Executive Summary\n2) Observed Activity (grouped)\n3) Key TTPs/Techniques\n4) Risk Assessment\n5) Actionable Recommendations (High/Med/Low)\n\n"
        + "\n\n---\n\n".join(micro_sections)
    )


def build_chunk_prompt(block: List[Dict[str, Any]]) -> str:
    head = "Summarize these detections succinctly, group related behavior, and give clear findings with recommendations.\n\n"
    buf = [head]
    for i, det in enumerate(block, 1):
        name = det.get("name") or (det.get("rule") or {}).get("title") or "Untitled"
        ts = det.get("timestamp", "N/A")
        tags = ", ".join(det.get("tags", []) or []) or "None"
        eid = (
            (((det.get("document") or {}).get("data") or {}).get("Event") or {}).get("System", {}).get("EventID", "N/A")
        )
        buf.append(f"{i}. {name} — Time: {ts} — EventID: {eid} — Tags: {tags}")
    return "\n".join(buf)


# ─────────────────────────── Summarization flows ───────────────────────────
def chunker(lst: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def micro_parallel(
    client: OpenAI,
    blocks: List[List[Dict[str, Any]]],
    model: str,
    temperature: float,
    timeout_s: int,
    retries: int,
    include_script: bool,
    micro_truncate: int,
    rpm: int,
    workers: int,
) -> Tuple[List[str], int, int]:
    enc = get_encoder()
    limiter = RateLimiter(rpm)
    out_sections: List[Optional[str]] = [None] * len(blocks)
    total_in = total_out = 0

    def _work(i: int, block: List[Dict[str, Any]]) -> Tuple[int, str, int, int]:
        limiter.wait()
        user = build_micro_prompt(block, include_script, micro_truncate)
        tin = est_tokens(enc, DEFAULT_SYSTEM_PROMPT) + est_tokens(enc, user)
        content = call_llm(client, model, DEFAULT_SYSTEM_PROMPT, user, temperature, timeout_s, retries)
        tout = est_tokens(enc, content)
        return i, content, tin, tout

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Micro[/bold]"),
        BarColumn(),
        TextColumn("[progress.completed]/[progress.total]"),
        TimeElapsedColumn(),
        transient=True,
    ) as prog:
        task = prog.add_task("micro", total=len(blocks))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(_work, i, block) for i, block in enumerate(blocks)]
            for f in as_completed(futures):
                i, content, tin, tout = f.result()
                out_sections[i] = f"## Micro {i + 1}\n{content}"
                total_in += tin
                total_out += tout
                prog.update(task, advance=1)

    return [s or "" for s in out_sections], total_in, total_out


def single_pass_parallel(
    client: OpenAI,
    blocks: List[List[Dict[str, Any]]],
    model: str,
    temperature: float,
    timeout_s: int,
    retries: int,
    rpm: int,
    workers: int,
) -> Tuple[str, int, int]:
    enc = get_encoder()
    limiter = RateLimiter(rpm)
    sections: List[Optional[str]] = [None] * len(blocks)
    total_in = total_out = 0

    def _work(i: int, block: List[Dict[str, Any]]) -> Tuple[int, str, int, int]:
        limiter.wait()
        user = build_chunk_prompt(block)
        tin = est_tokens(enc, DEFAULT_SYSTEM_PROMPT) + est_tokens(enc, user)
        content = call_llm(client, model, DEFAULT_SYSTEM_PROMPT, user, temperature, timeout_s, retries)
        tout = est_tokens(enc, content)
        return i, content, tin, tout

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Chunks[/bold]"),
        BarColumn(),
        TextColumn("[progress.completed]/[progress.total]"),
        TimeElapsedColumn(),
        transient=True,
    ) as prog:
        task = prog.add_task("chunks", total=len(blocks))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(_work, i, block) for i, block in enumerate(blocks)]
            for f in as_completed(futures):
                i, content, tin, tout = f.result()
                sections[i] = f"### Chunk {i + 1}\n\n{content}\n"
                total_in += tin
                total_out += tout
                prog.update(task, advance=1)

    head = (
        "# 🔍 Chainsaw Detection Summary (LLM)\n\n"
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}\n"
        f"- Model: `{model}`\n"
        f"- Chunks: {len(blocks)}\n\n---\n"
    )
    return head + "".join([s or "" for s in sections]), total_in, total_out


def two_pass_summarize(client: OpenAI, detections: List[Dict[str, Any]], cfg: AppConfig) -> Tuple[str, int, int]:
    blocks = list(chunker(detections, cfg.chunk_size))
    workers = (
        min(len(blocks), (os.cpu_count() or 4) * 2)
        if str(cfg.micro_workers).lower() == "auto"
        else max(1, int(cfg.micro_workers))
    )

    # Micro (parallel) on mini
    micro_sections, mi_in, mi_out = micro_parallel(
        client,
        blocks,
        cfg.chunk_model,
        cfg.llm_temperature,
        cfg.llm_timeout,
        cfg.llm_max_retries,
        cfg.micro_include_script,
        cfg.micro_truncate,
        cfg.rpm,
        workers,
    )

    # Final merge (single call) on gpt-5
    enc = get_encoder()
    final_user = build_final_prompt(micro_sections)
    est_in = est_tokens(enc, FINAL_SYSTEM_PROMPT) + est_tokens(enc, final_user)
    if est_in > cfg.final_max_input_tokens:
        # compress by keeping shortest sections
        pairs = sorted(((est_tokens(enc, s), s) for s in micro_sections), key=lambda x: x[0])
        keep = []
        running = est_tokens(enc, FINAL_SYSTEM_PROMPT)
        for tk, s in pairs:
            if running + tk <= cfg.final_max_input_tokens:
                keep.append(s)
                running += tk
            else:
                break
        if not keep:
            keep = [micro_sections[0][: max(4000, cfg.final_max_input_tokens // 4)]]
        final_user = build_final_prompt(keep)

    limiter = RateLimiter(cfg.rpm)
    limiter.wait()
    final = call_llm(
        client,
        cfg.final_model,
        FINAL_SYSTEM_PROMPT,
        final_user,
        cfg.llm_temperature,
        cfg.llm_timeout,
        cfg.llm_max_retries,
    )
    fi_in = est_tokens(enc, FINAL_SYSTEM_PROMPT) + est_tokens(enc, final_user)
    fi_out = est_tokens(enc, final)

    head = (
        "# 🔍 Chainsaw Detection Summary (LLM, Two-Pass)\n\n"
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}\n"
        f"- Model (micro): `{cfg.chunk_model}`\n"
        f"- Model (final): `{cfg.final_model}`\n"
        f"- Chunks: {len(blocks)}\n"
        f"- Mode: two-pass (micro → final)\n\n---\n"
        "## Final Executive Report\n\n"
    )
    appendix = "\n\n---\n\n## Appendix: Micro-Summaries\n\n" + "\n\n".join(micro_sections)
    return head + final + appendix, (mi_in + fi_in), (mi_out + fi_out)


# ─────────────────────────── Output helpers ───────────────────────────
DEFAULT_CSS = """
:root { --fg: #111; --bg: #fff; --muted: #666; --accent: #0a7cff; }
html { font-size: 16px; }
body { margin: 2rem auto; max-width: 920px; line-height: 1.6; color: var(--fg); background: var(--bg);
       font-family: ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans','Apple Color Emoji','Segoe UI Emoji'; }
h1,h2,h3 { line-height: 1.25; }
h1 { font-size: 2rem; margin-top: 0; }
h2 { font-size: 1.5rem; border-bottom: 1px solid #eee; padding-bottom: .2rem; margin-top: 2rem; }
h3 { font-size: 1.2rem; margin-top: 1.2rem; }
code, pre { background: #f6f8fa; border-radius: 6px; }
pre { padding: .75rem; overflow: auto; }
code { padding: .1rem .3rem; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
hr { border: 0; height: 1px; background: #eee; margin: 2rem 0; }
table { border-collapse: collapse; }
td, th { border: 1px solid #eee; padding: .4rem .6rem; }
blockquote { color: var(--muted); border-left: 3px solid #eee; margin: 0; padding: .25rem .75rem; }
"""


def sanitize_md_for_pandoc(text: str) -> str:
    if text.startswith("---\n"):
        text = "\n" + text
    return re.sub(r"(?m)^\s*---\s*$", "<hr />", text)


def write_reports(
    outdir: Path, md_text: str, make_html: bool, make_pdf: bool
) -> Tuple[Path, Optional[Path], Optional[Path]]:
    outdir.mkdir(parents=True, exist_ok=True)
    today = datetime.today().strftime("%Y-%m-%d")
    md_path = outdir / f"chainsaw_summary_{today}.md"
    md_path.write_text(md_text, encoding="utf-8")

    html_path = None
    pdf_path = None
    html_css_path = outdir / "report.css"
    if make_html:
        if not html_css_path.exists():
            html_css_path.write_text(DEFAULT_CSS, encoding="utf-8")
        html_path = outdir / f"chainsaw_summary_{today}.html"
        try:
            pypandoc.convert_text(
                sanitize_md_for_pandoc(md_text),
                to="html",
                format="gfm",
                outputfile=str(html_path),
                extra_args=[
                    "--standalone",
                    "--toc",
                    "--toc-depth=3",
                    f"--css={html_css_path}",
                    "--metadata",
                    "title=DFIR Chainsaw Summary (LLM)",
                ],
            )
        except OSError:
            info("HTML generation skipped (pandoc missing).")
            html_path = None

    if make_pdf:
        pdf_path = outdir / f"chainsaw_summary_{today}.pdf"
        try:
            pypandoc.convert_text(
                sanitize_md_for_pandoc(md_text),
                to="pdf",
                format="gfm",
                outputfile=str(pdf_path),
                extra_args=["--standalone", "--pdf-engine=xelatex", "--metadata", "title=DFIR Chainsaw Summary (LLM)"],
            )
        except OSError:
            info("PDF generation skipped (xelatex/pandoc missing).")
            pdf_path = None

    return md_path, html_path, pdf_path


def estimate_cost(usages: Dict[str, Tuple[int, int]]) -> Tuple[float, List[str]]:
    total = 0.0
    lines = []
    for m, (tin, tout) in usages.items():
        p = PRICING.get(m, {"in": 0.0, "out": 0.0})
        cost = (tin / 1000.0) * p["in"] + (tout / 1000.0) * p["out"]
        total += cost
        lines.append(f"- {m}: in={tin}, out={tout} → ${cost:.6f} (in {p['in']}/k, out {p['out']}/k)")
    return round(total, 6), lines


# ─────────────────────────── Main ───────────────────────────
def main():
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        die("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)
    cfg = parse_args()

    console.rule("[bold]⚙ Starting Chainsaw summarizer with parallel mode…[/bold]")
    ensure_chainsaw()

    # 1) Discover newest EVTX folder and hunt all logs there
    latest = newest_container(cfg.evtx_root)
    detections_path = latest / "detections.json"
    try:
        run_chainsaw(latest, detections_path, cfg.rules, cfg.mapping)
    except subprocess.CalledProcessError as e:
        die(f"Chainsaw failed: {e}")

    # 2) Load detections adaptively
    try:
        detections = load_detections(detections_path)
    except Exception as e:
        die(f"Failed to read detections: {e}")

    # 3) Fallback if none
    if not detections:
        console.rule("[bold yellow]⚠ No Sigma detections found[/bold yellow]")
        console.print(
            "[yellow]No Sigma detections found — skipping summarization to save tokens.[/yellow]\n"
            "Try Security.evtx or PowerShell-Operational.evtx for richer events."
        )
        empty_path = latest / "chainsaw_summary_empty.md"
        empty_path.write_text(
            f"# Chainsaw Summary — {datetime.now().isoformat(timespec='seconds')}\n\n"
            "No Sigma detections were found in this log folder.\n",
            encoding="utf-8",
        )
        ok(f"Empty summary written: {empty_path}")
        return

    console.rule(f"[bold]⚙ Detections found ({len(detections)}) — summarizing…[/bold]")

    # 4) Summarize (two-pass or single-pass)
    enc = get_encoder()
    in_tokens = out_tokens = 0
    if cfg.two_pass:
        md, in_tokens, out_tokens = two_pass_summarize(client, detections, cfg)
        usage = {cfg.chunk_model: (0, 0), cfg.final_model: (0, 0)}  # approximate split comes from two_pass returns
        # Rough attribution: assume 70% tokens in micro on mini, 30% in final on gpt-5
        usage[cfg.chunk_model] = (int(in_tokens * 0.7), int(out_tokens * 0.7))
        usage[cfg.final_model] = (in_tokens - usage[cfg.chunk_model][0], out_tokens - usage[cfg.chunk_model][1])
    else:
        blocks = list(chunker(detections, cfg.chunk_size))
        workers = (
            min(len(blocks), (os.cpu_count() or 4) * 2)
            if str(cfg.micro_workers).lower() == "auto"
            else max(1, int(cfg.micro_workers))
        )
        md, in_tokens, out_tokens = single_pass_parallel(
            client, blocks, cfg.chunk_model, cfg.llm_temperature, cfg.llm_timeout, cfg.llm_max_retries, cfg.rpm, workers
        )
        usage = {cfg.chunk_model: (in_tokens, out_tokens)}

    # 5) Write reports
    md_path, html_path, pdf_path = write_reports(cfg.outdir, md, cfg.make_html, cfg.make_pdf)

    # 6) Console summary
    console.rule("[bold green]🔍 LLM-Summarized Report[/bold green]")
    console.print(Markdown(md if len(md) < 5000 else md[:5000] + "\n\n…[truncated in console]"))
    console.rule("[bold green]End of Summary[/bold green]")

    total_cost, lines = estimate_cost(usage)
    console.print(f"[green]✓ Markdown:[/green] {md_path}")
    if html_path:
        console.print(f"[green]✓ HTML:[/green] {html_path}")
    if pdf_path:
        console.print(f"[green]✓ PDF:[/green] {pdf_path}")
    console.print(
        f"[cyan]🧠 Tokens used (est):[/cyan] in+out={in_tokens + out_tokens} (in={in_tokens}, out={out_tokens})"
    )
    for ln in lines:
        console.print(f"[cyan]{ln}[/cyan]")
    console.print(f"[cyan]💸 Estimated total cost:[/cyan] ${total_cost}")


if __name__ == "__main__":
    main()
