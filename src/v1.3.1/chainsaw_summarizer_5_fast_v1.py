# File: chainsaw_summarizer_5_pro.py
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pypandoc
import tiktoken
from dotenv import load_dotenv
from openai import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    BadRequestError,
    OpenAI,
    RateLimitError,
)
from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

# ─────────────────────────── Console & Defaults ───────────────────────────
console = Console()

CHUNK_MODEL = os.getenv("CHUNK_MODEL", "gpt-5-mini")
FINAL_MODEL = os.getenv("FINAL_MODEL", "gpt-5")

MAX_LLM_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "8"))
REQ_TIMEOUT_S = int(os.getenv("LLM_TIMEOUT", "30"))
TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "1"))

PRICING = {
    "gpt-5-mini": {"in": 0.00025, "out": 0.00200},
    "gpt-5": {"in": 0.00125, "out": 0.01000},
    "gpt-3.5-turbo": {"in": 0.0005, "out": 0.0015},
}

DEFAULT_SYSTEM_PROMPT = (
    "You are a senior DFIR analyst. Produce concise, accurate summaries. "
    "Group related detections, highlight notable TTPs/tooling, dedupe repetition, "
    "and end with actionable recommendations prioritized by risk and effort."
)

DEFAULT_FINAL_SYSTEM = (
    "You are a DFIR lead. Merge the provided micro-summaries into a coherent executive report. "
    "Eliminate repetition; group by phases/TTPs; quantify scope where possible; "
    "end with prioritized, actionable recommendations (High/Med/Low) and quick wins."
)

DEFAULT_CSS = """
:root { --fg:#111; --bg:#fff; --muted:#666; --accent:#0a7cff; }
html { font-size: 16px; }
body { margin: 2rem auto; max-width: 980px; line-height: 1.6; color: var(--fg); background: var(--bg);
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


# ───────────────────────────── Config Model ───────────────────────────────
@dataclass
class AppConfig:
    # IO / chainsaw
    evtx_root: Path
    prefer_logs: List[str]
    outdir: Path
    rules_dir: Path
    mapping_path: Path
    sigma_root: Optional[Path]
    make_pdf: bool
    make_html: bool
    # parsing/limits
    max_detections: int
    chunk_size: int
    max_chunks: int
    max_input_tokens: int
    parse_format: str
    # LLM
    two_pass: bool
    chunk_model: str
    final_model: str
    llm_timeout: int
    llm_max_retries: int
    llm_temperature: float
    # perf
    fast: bool
    micro_workers: int
    rpm: int
    # pricing/cost
    pricing_json: Optional[str]
    # extras
    css_path: Optional[Path]
    csv_summary: Path
    archive: bool
    # prompting controls
    no_script: bool
    truncate_script: int
    micro_include_script: bool
    micro_truncate: int
    final_max_input_tokens: int


# ───────────────────────────── Helpers ────────────────────────────────────
class LoaderError(Exception):
    pass


def die(msg: str, code: int = 1) -> None:
    console.print(Panel.fit(f"[red]✘ {msg}[/red]", box=box.ROUNDED))
    sys.exit(code)


def ok(msg: str) -> None:
    console.print(Panel.fit(f"[green]✔ {msg}[/green]", box=box.ROUNDED))


def info(msg: str) -> None:
    console.print(Panel.fit(f"[yellow]⚙ {msg}[/yellow]", box=box.ROUNDED))


def parse_args() -> AppConfig:
    p = argparse.ArgumentParser(description="Chainsaw → Sigma → GPT (mini→5) DFIR summarizer (pro)")
    p.add_argument("--evtx-root", type=Path, default=Path("/mnt/evtx_share/DFIR-Lab-Logs"))
    p.add_argument("--prefer-logs", type=str, default="PowerShell-Operational.evtx,Security.evtx")
    p.add_argument("--outdir", type=Path, default=Path.home() / "DFIR-Labs" / "chainsaw_summaries")
    p.add_argument("--rules", type=Path, default=Path("/home/kali/tools/sigma/rules"))
    p.add_argument(
        "--mapping", type=Path, default=Path("/home/kali/tools/chainsaw/sigma-event-logs-all.yml")
    )
    p.add_argument("--sigma-root", type=Path, default=Path("/home/kali/tools/sigma"))
    p.add_argument("--make-pdf", action="store_true")
    p.add_argument("--make-html", action="store_true")
    p.add_argument("--max-detections", type=int, default=1000)
    p.add_argument("--chunk-size", type=int, default=25)
    p.add_argument("--max-chunks", type=int, default=100)
    p.add_argument("--max-input-tokens", type=int, default=120_000)
    p.add_argument("--format", choices=["auto", "json", "jsonl"], default="auto")
    p.add_argument("--two-pass", action="store_true")
    p.add_argument("--chunk-model", default=CHUNK_MODEL)
    p.add_argument("--final-model", default=FINAL_MODEL)
    p.add_argument("--llm-timeout", type=int, default=REQ_TIMEOUT_S)
    p.add_argument("--llm-max-retries", type=int, default=MAX_LLM_RETRIES)
    p.add_argument("--llm-temperature", type=float, default=TEMPERATURE)
    p.add_argument("--fast", action="store_true", help="Parallelize micro summaries")
    p.add_argument("--micro-workers", type=str, default="auto")
    p.add_argument("--rpm", type=int, default=0)
    p.add_argument("--pricing-json", type=str, default=None)
    p.add_argument("--css", type=Path, default=None)
    p.add_argument(
        "--csv-summary",
        type=Path,
        default=Path.home() / "DFIR-Labs" / "chainsaw_summaries" / "summary.csv",
    )
    p.add_argument(
        "--archive",
        action="store_true",
        help="Archive previous dated runs into archive/YYYY-MM-DD/",
    )
    # prompt size controls
    p.add_argument("--no-script", action="store_true")
    p.add_argument("--truncate-script", type=int, default=0)
    p.add_argument("--micro-include-script", action="store_true")
    p.add_argument("--micro-truncate", type=int, default=200)
    p.add_argument("--final-max-input-tokens", type=int, default=20_000)
    a = p.parse_args()

    # workers
    if str(a.micro_workers).lower() == "auto":
        cpu = os.cpu_count() or 2
        workers = max(2, min(8, cpu * 2)) if a.fast else 1
    else:
        workers = max(1, int(a.micro_workers))

    prefer_logs = [s.strip() for s in a.prefer_logs.split(",") if s.strip()]
    return AppConfig(
        evtx_root=a.evtx_root,
        prefer_logs=prefer_logs,
        outdir=a.outdir,
        rules_dir=a.rules,
        mapping_path=a.mapping,
        sigma_root=a.sigma_root,
        make_pdf=a.make_pdf,
        make_html=a.make_html,
        max_detections=max(0, a.max_detections),
        chunk_size=max(1, a.chunk_size),
        max_chunks=max(1, a.max_chunks),
        max_input_tokens=max(1000, a.max_input_tokens),
        parse_format=a.format,
        two_pass=a.two_pass,
        chunk_model=a.chunk_model,
        final_model=a.final_model,
        llm_timeout=a.llm_timeout,
        llm_max_retries=a.llm_max_retries,
        llm_temperature=a.llm_temperature,
        fast=a.fast,
        micro_workers=workers,
        rpm=max(0, a.rpm),
        pricing_json=a.pricing_json,
        css_path=a.css,
        csv_summary=a.csv_summary,
        archive=a.archive,
        no_script=a.no_script,
        truncate_script=max(0, a.truncate_script),
        micro_include_script=a.micro_include_script,
        micro_truncate=max(0, a.micro_truncate),
        final_max_input_tokens=max(4000, a.final_max_input_tokens),
    )


# ───────────────────────── Chainsaw / Source ──────────────────────────────
def ensure_chainsaw_available() -> None:
    if shutil.which("chainsaw") is None:
        die("chainsaw not found in PATH.")


def find_latest_container(root: Path) -> Path:
    if not root.exists():
        die(f"EVTX root not found: {root}")
    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs:
        die(f"No subfolders under {root}")
    return max(dirs, key=lambda p: p.stat().st_mtime)


def print_source_banners(latest_dir: Path, rules: Path, mapping: Path, sigma_root: Optional[Path]):
    console.print(Panel.fit(f"[green]✔ Hunting directory:[/green] {latest_dir}", box=box.ROUNDED))
    console.print(Panel.fit(f"[green]✔ Using Chainsaw rules:[/green] {rules}", box=box.ROUNDED))
    console.print(Panel.fit(f"[green]✔ Using Chainsaw mapping:[/green] {mapping}", box=box.ROUNDED))
    if sigma_root:
        console.print(
            Panel.fit(f"[green]✔ Using Sigma root:[/green] {sigma_root}", box=box.ROUNDED)
        )


def run_chainsaw(
    src: Path, out_path: Path, rules: Path, mapping: Path, sigma_root: Optional[Path]
) -> None:
    info("Running Chainsaw hunt…")
    cmd = ["chainsaw", "hunt", str(src), "--mapping", str(mapping), "--rule", str(rules)]
    if sigma_root:
        cmd += ["-s", str(sigma_root)]
    cmd += ["--json", "--output", str(out_path)]
    subprocess.run(cmd, check=True)
    ok("Chainsaw hunt completed (json)")


# ───────────────────────── Detection Loading ──────────────────────────────
def _looks_json(path: Path) -> bool:
    try:
        t = path.read_text(encoding="utf-8").lstrip()
        return len(t) > 1 and t[0] in "{["
    except Exception:
        return False


def _read_text(path: Path) -> str:
    if not path.exists():
        raise LoaderError(f"detections file not found: {path}")
    if path.stat().st_size == 0:
        raise LoaderError(f"detections file is empty: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8-sig")


def _parse_json_text(text: str) -> Any:
    return json.loads(text)


def _parse_jsonl_text(text: str) -> List[Any]:
    out: List[Any] = []
    for ln in (ln.strip() for ln in text.splitlines() if ln.strip()):
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


def _normalize_to_list(obj: Any) -> List[Dict[str, Any]]:
    if isinstance(obj, dict) and "detections" in obj and isinstance(obj["detections"], list):
        return obj["detections"]
    if isinstance(obj, list):
        return obj
    raise LoaderError("Unexpected JSON shape. Expect list or dict with 'detections'.")


def load_detections(json_path: Path, mode: str, max_items: int) -> List[Dict[str, Any]]:
    text = _read_text(json_path)
    dets: List[Dict[str, Any]] = []
    if mode == "json":
        try:
            dets = _normalize_to_list(_parse_json_text(text))
        except json.JSONDecodeError as e:
            raise LoaderError(f"JSON parse error: {e}") from e
    elif mode == "jsonl":
        items = _parse_jsonl_text(text)
        if not items:
            raise LoaderError("No valid JSON lines found in JSONL file.")
        flat: List[Dict[str, Any]] = []
        for it in items:
            if isinstance(it, dict) and "detections" in it and isinstance(it["detections"], list):
                flat.extend(it["detections"])
            elif isinstance(it, dict):
                flat.append(it)
            elif isinstance(it, list):
                flat.extend(it)
        if not flat:
            raise LoaderError("JSONL parsed, but no detections found.")
        dets = flat
    else:
        try:
            dets = _normalize_to_list(_parse_json_text(text))
        except Exception:
            items = _parse_jsonl_text(text)
            if not items:
                preview = text[:200].replace("\n", "\\n")
                raise LoaderError(
                    "Failed to parse detections as JSON or JSONL. Preview: " + preview
                )
            flat: List[Dict[str, Any]] = []
            for it in items:
                if (
                    isinstance(it, dict)
                    and "detections" in it
                    and isinstance(it["detections"], list)
                ):
                    flat.extend(it["detections"])
                elif isinstance(it, dict):
                    flat.append(it)
                elif isinstance(it, list):
                    flat.extend(it)
            dets = flat
    if max_items > 0:
        dets = dets[:max_items]
    return dets


# ───────────────────────── Markdown builders ──────────────────────────────
def chunk(lst: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def _fmt_script(script: str, no_script: bool, trunc: int) -> str:
    if no_script:
        return "(omitted)"
    if trunc > 0 and script:
        return "```\n" + script[:trunc] + ("… [truncated]" if len(script) > trunc else "") + "\n```"
    return "```\n" + (script or "") + "\n```"


def build_chunk_prompt(
    block: List[Dict[str, Any]], *, no_script: bool, truncate_script: int
) -> str:
    header = (
        "You are a senior DFIR analyst. Summarize these Windows detection events succinctly. "
        "Group related items, highlight notable TTPs/tooling, and provide an executive summary plus actionable recommendations.\n\n"
    )
    parts = []
    for i, det in enumerate(block, 1):
        ts = det.get("timestamp", "N/A")
        rule = det.get("name", "N/A")
        doc = ((det.get("document") or {}).get("data") or {}).get("Event") or {}
        event_id = (doc.get("System") or {}).get("EventID") or "N/A"
        script_raw = (doc.get("EventData") or {}).get("ScriptBlockText") or ""
        script = _fmt_script(script_raw, no_script, truncate_script)
        mitre_tags = ", ".join(det.get("tags", []) or []) or "None"
        category = (det.get("logsource") or {}).get("category", "N/A")
        references = "\n".join(det.get("references", []) or []) or "None"
        parts.append(
            f"## 🕵️ Detection {i}\n- Time: {ts}\n- Rule: {rule}\n- Event ID: {event_id}\n"
            f"- MITRE Tags: {mitre_tags}\n- Category: {category}\n\nScript Block:\n{script}\n\nReferences:\n{references}\n"
        )
    return header + "\n".join(parts)


def build_micro_prompt(
    block: List[Dict[str, Any]], include_script: bool, micro_truncate: int
) -> str:
    header = (
        "Micro-summarize these detections for DFIR triage in <= 12 bullets total. "
        "Group similar items, name key TTPs (MITRE IDs if present), mention counts/timestamps if available. "
        "No fluff, no repetition. Output:\n"
        "• Executive bullets\n• Key TTPs\n• Notable IOCs (if any)\n"
    )
    parts = []
    for det in block:
        ts = det.get("timestamp", "N/A")
        rule = det.get("name", "N/A")
        tags = ", ".join(det.get("tags", []) or []) or "None"
        doc = ((det.get("document") or {}).get("data") or {}).get("Event") or {}
        eid = (doc.get("System") or {}).get("EventID") or "N/A"
        script = (doc.get("EventData") or {}).get("ScriptBlockText") or ""
        snippet = ""
        if include_script and micro_truncate > 0 and isinstance(script, str) and script:
            snippet = script[:micro_truncate] + (
                "… [truncated]" if len(script) > micro_truncate else ""
            )
        line = f"- [{ts}] {rule} (EventID {eid}; Tags: {tags})"
        if snippet:
            line += f"  | snippet: {snippet}"
        parts.append(line)
    return header + "\n" + "\n".join(parts)


def build_final_merge_prompt(micro_sections: List[str]) -> str:
    header = (
        "Merge the following micro-summaries into one executive DFIR report. "
        "Eliminate duplicates, group themes, and produce:\n"
        "1) Executive Summary\n2) Observed Activity (grouped)\n3) Key TTPs/Techniques\n4) Risk Assessment\n5) Actionable Recommendations (High/Med/Low)\n"
    )
    return header + "\n\n" + "\n\n---\n\n".join(micro_sections)


# ───────────────────────── Token / Cost utils ─────────────────────────────
def get_encoder() -> tiktoken.Encoding:
    try:
        return tiktoken.get_encoding("cl100k_base")
    except Exception:
        return tiktoken.get_encoding("cl100k_base")


def estimate_tokens(enc: tiktoken.Encoding, text: str) -> int:
    try:
        return len(enc.encode(text))
    except Exception:
        return math.ceil(len(text) / 4)


def estimate_cost(
    usages: Dict[str, Tuple[int, int]], pricing: Dict[str, Dict[str, float]]
) -> Tuple[float, List[str]]:
    total = 0.0
    lines = []
    for m, (tin, tout) in usages.items():
        p = pricing.get(m, {"in": 0.0, "out": 0.0})
        cost = (tin / 1000.0) * p["in"] + (tout / 1000.0) * p["out"]
        total += cost
        lines.append(
            f"- {m}: in={tin}, out={tout} → ${cost:.6f} (in {p['in']}/k, out {p['out']}/k)"
        )
    return round(total, 6), lines


# ───────────────────────── LLM Calls ──────────────────────────────────────
def backoff_sleep(i: int):
    time.sleep(min(30.0, (1.5**i) + random.uniform(0, 0.3)))


def call_llm(
    client: OpenAI,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    timeout_s: int,
    retries: int,
) -> str:
    # Some GPT-5 variants only support default 1.0 temperature
    safe_temp = 1.0 if model.startswith("gpt-5") else temperature
    for i in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=safe_temp,
                timeout=timeout_s,
            )
            return resp.choices[0].message.content or ""
        except (RateLimitError, APITimeoutError, APIConnectionError, APIError):
            backoff_sleep(i)
            continue
        except BadRequestError as e:
            # Strip temperature if rejected
            if "temperature" in str(e):
                safe_temp = 1.0
                continue
            raise
    raise RuntimeError("LLM retries exceeded.")


# ───────────────────────── Micro (parallel) ───────────────────────────────
class RateLimiter:
    def __init__(self, rpm: int):
        self.rpm = max(0, rpm)
        self.lock = threading.Lock()
        self.next_time = 0.0
        self.dt = 60.0 / self.rpm if self.rpm > 0 else 0.0

    def wait(self):
        if self.rpm <= 0:
            return
        with self.lock:
            now = time.time()
            if now < self.next_time:
                time.sleep(self.next_time - now)
            self.next_time = max(now, self.next_time) + self.dt


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
    sections = [None] * len(blocks)  # type: ignore
    mi_in = mi_out = 0

    def _one(i: int, b: List[Dict[str, Any]]):
        nonlocal mi_in, mi_out
        user = build_micro_prompt(b, include_script, micro_truncate)
        mi_in += estimate_tokens(enc, DEFAULT_SYSTEM_PROMPT) + estimate_tokens(enc, user)
        limiter.wait()
        content = call_llm(
            client, model, DEFAULT_SYSTEM_PROMPT, user, temperature, timeout_s, retries
        )
        mi_out += estimate_tokens(enc, content)
        return i, f"## Micro {i + 1}\n{content}"

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Micro[/bold]"),
        BarColumn(),
        TextColumn("chunk [progress.completed]/[progress.total]"),
        TimeElapsedColumn(),
        transient=True,
    ) as prog:
        task = prog.add_task("micro", total=len(blocks))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_one, i, b): i for i, b in enumerate(blocks)}
            for f in as_completed(futs):
                i, sec = f.result()
                sections[i] = sec
                prog.update(task, advance=1)
    return [s or "" for s in sections], mi_in, mi_out


# ───────────────────────── Two-pass flow ──────────────────────────────────
def guardrail_estimate_or_die(
    chunks: List[List[Dict[str, Any]]],
    system_prompt: str,
    max_chunks: int,
    max_input_tokens: int,
    *,
    no_script: bool,
    truncate_script: int,
) -> Tuple[int, List[int]]:
    if len(chunks) > max_chunks:
        die(f"Chunk guardrail exceeded: {len(chunks)} > --max-chunks {max_chunks}")
    enc = get_encoder()
    per, total = [], 0
    for ch in chunks:
        prompt = build_chunk_prompt(ch, no_script=no_script, truncate_script=truncate_script)
        t = estimate_tokens(enc, system_prompt) + estimate_tokens(enc, prompt)
        per.append(t)
        total += t
    if total > max_input_tokens:
        die(
            f"Estimated input tokens {total} exceed --max-input-tokens {max_input_tokens}. "
            "Tune chunk size / truncate options."
        )
    return total, per


def two_pass_summarize(
    client: OpenAI, detections: List[Dict[str, Any]], cfg: AppConfig
) -> Tuple[str, int, int, Dict[str, Tuple[int, int]]]:
    enc = get_encoder()
    usage: Dict[str, Tuple[int, int]] = {}
    blocks = list(chunk(detections, cfg.chunk_size))

    # Pass 1: micro
    start = time.perf_counter()
    if cfg.fast and cfg.micro_workers > 1:
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
            cfg.micro_workers,
        )
    else:
        micro_sections = []
        mi_in = mi_out = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]Micro[/bold]"),
            BarColumn(),
            TextColumn("chunk [progress.completed]/[progress.total]"),
            TimeElapsedColumn(),
            transient=True,
        ) as prog:
            task = prog.add_task("micro", total=len(blocks))
            for i, b in enumerate(blocks):
                user = build_micro_prompt(b, cfg.micro_include_script, cfg.micro_truncate)
                mi_in += estimate_tokens(enc, DEFAULT_SYSTEM_PROMPT) + estimate_tokens(enc, user)
                content = call_llm(
                    client,
                    cfg.chunk_model,
                    DEFAULT_SYSTEM_PROMPT,
                    user,
                    cfg.llm_temperature,
                    cfg.llm_timeout,
                    cfg.llm_max_retries,
                )
                mi_out += estimate_tokens(enc, content)
                micro_sections.append(f"## Micro {i + 1}\n{content}")
                prog.update(task, advance=1)
    t_micro = time.perf_counter() - start
    usage[cfg.chunk_model] = (mi_in, mi_out)

    # Pass 2: final merge
    info("Two-pass: merging micro-summaries...")
    start = time.perf_counter()
    final_user = build_final_merge_prompt(micro_sections)
    est_final_in = estimate_tokens(enc, DEFAULT_FINAL_SYSTEM) + estimate_tokens(enc, final_user)
    if est_final_in > cfg.final_max_input_tokens:
        # compress: keep shortest sections until cap
        pairs = sorted(((estimate_tokens(enc, s), s) for s in micro_sections), key=lambda x: x[0])
        keep, running = [], estimate_tokens(enc, DEFAULT_FINAL_SYSTEM)
        for tok, s in pairs:
            if running + tok <= cfg.final_max_input_tokens:
                keep.append(s)
                running += tok
            else:
                break
        if not keep:
            keep = [micro_sections[0][: max(5000, cfg.final_max_input_tokens // 4)]]
        final_user = build_final_merge_prompt(keep)

    final_content = call_llm(
        client,
        cfg.final_model,
        DEFAULT_FINAL_SYSTEM,
        final_user,
        cfg.llm_temperature,
        cfg.llm_timeout,
        cfg.llm_max_retries,
    )
    fin_in = estimate_tokens(enc, DEFAULT_FINAL_SYSTEM) + estimate_tokens(enc, final_user)
    fin_out = estimate_tokens(enc, final_content)
    t_merge = time.perf_counter() - start
    usage[cfg.final_model] = (
        usage.get(cfg.final_model, (0, 0))[0] + fin_in,
        usage.get(cfg.final_model, (0, 0))[1] + fin_out,
    )

    # Head
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
    return (
        head + final_content + appendix,
        (mi_in + fin_in),
        (mi_out + fin_out),
        usage,
        t_micro,
        t_merge,
    )


# ───────────────────────── IOC Extraction ─────────────────────────────────
RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}\b")
RE_DOM = re.compile(
    r"\b(?!(?:localhost|localdomain)\b)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_iocs(dets: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    ips, doms, md5, sha1, sha256 = set(), set(), set(), set(), set()

    def scan(text: str):
        if not text:
            return
        ips.update(RE_IP.findall(text))
        doms.update(RE_DOM.findall(text))
        md5.update(RE_MD5.findall(text))
        sha1.update(RE_SHA1.findall(text))
        sha256.update(RE_SHA256.findall(text))

    for d in dets:
        scan(d.get("name", ""))
        for k in ("tags", "references", "authors", "falsepositives"):
            v = d.get(k)
            if isinstance(v, list):
                scan(" ".join([str(x) for x in v]))
        doc = ((d.get("document") or {}).get("data") or {}).get("Event") or {}
        evd = doc.get("EventData") or {}
        for k in (
            "ScriptBlockText",
            "CommandLine",
            "ParentCommandLine",
            "TargetFilename",
            "Image",
            "DestinationHostname",
            "DestinationIp",
        ):
            v = evd.get(k)
            if isinstance(v, str):
                scan(v)
    return {
        "ips": sorted(ips),
        "domains": sorted(doms),
        "md5": sorted(md5),
        "sha1": sorted(sha1),
        "sha256": sorted(sha256),
    }


def format_iocs_md(iocs: Dict[str, List[str]]) -> str:
    blocks = []
    for label in ("ips", "domains", "md5", "sha1", "sha256"):
        vals = iocs.get(label, [])
        if not vals:
            continue
        blocks.append(f"### {label.upper()}\n" + "\n".join(f"- `{v}`" for v in vals))
    if not blocks:
        return "No IOCs were extracted from the provided detections."
    return "\n\n".join(blocks)


# ───────────────────────── Output helpers ─────────────────────────────────
def ensure_css(base_dir: Path, css_path: Optional[Path]) -> Path:
    if css_path and css_path.exists():
        return css_path
    out = base_dir / "report.css"
    if not out.exists():
        out.write_text(DEFAULT_CSS, encoding="utf-8")
    return out


def sanitize_md_for_pandoc(text: str) -> str:
    # Disable accidental YAML header and horizontal-rule confusion
    if text.startswith("---\n"):
        text = "\n" + text
    text = re.sub(r"(?m)^\s*---\s*$", "<hr />", text)
    return text


def write_reports(
    base_dir: Path, llm_md: str, make_pdf: bool, make_html: bool, css_path: Optional[Path]
) -> Tuple[Optional[Path], Optional[Path]]:
    base_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.today().strftime("%Y-%m-%d")
    md_path = base_dir / f"chainsaw_summary_{today}.md"
    html_path = base_dir / f"chainsaw_summary_{today}.html"
    pdf_path = base_dir / f"chainsaw_summary_{today}.pdf"

    md_path.write_text(llm_md, encoding="utf-8")
    html_out = None
    pdf_out = None

    if make_html:
        css_out = ensure_css(base_dir, css_path)
        # Disable TeX math parsing to avoid LaTeX warnings
        pypandoc.convert_text(
            sanitize_md_for_pandoc(llm_md),
            to="html",
            format="gfm-tex_math_dollars-tex_math_single_backslash",
            outputfile=str(html_path),
            extra_args=[
                "--standalone",
                "--toc",
                "--toc-depth=3",
                f"--css={css_out}",
                "--metadata",
                "title=DFIR Chainsaw Summary (LLM)",
            ],
        )
        html_out = html_path

    if make_pdf:
        try:
            # Try Markdown → HTML → PDF via wkhtmltopdf (robust with code blocks)
            if shutil.which("wkhtmltopdf") and html_out:
                subprocess.run(["wkhtmltopdf", str(html_out), str(pdf_path)], check=True)
                pdf_out = pdf_path
            else:
                # Fallback to pandoc PDF with TeX-math disabled
                pypandoc.convert_text(
                    sanitize_md_for_pandoc(llm_md),
                    to="pdf",
                    format="gfm-tex_math_dollars-tex_math_single_backslash",
                    outputfile=str(pdf_path),
                    extra_args=[
                        "--standalone",
                        "--pdf-engine=xelatex",
                        "--metadata",
                        "title=DFIR Chainsaw Summary (LLM)",
                    ],
                )
                pdf_out = pdf_path
        except Exception as e:
            info(f"PDF generation skipped: {e}")
            pdf_out = None

    return html_out, pdf_out


def write_raw_md(base_dir: Path, detections: List[Dict[str, Any]], chunk_size: int) -> Path:
    head = "# 🔍 Chainsaw Detection Summary (Raw)\n\nThis section lists detections prior to LLM summarization.\n\n"
    bod = []
    for block in chunk(detections, chunk_size):
        for d in block:
            title = d.get("name", "Untitled")
            ts = d.get("timestamp", "N/A")
            rule_id = d.get("id", "N/A")
            sev = str(d.get("level", "unknown")).capitalize()
            product = (d.get("logsource") or {}).get("product", "N/A")
            bod.append(
                f"### 🛡️ {title}\n**Severity:** {sev}  \n**Timestamp:** `{ts}`  \n**Rule ID:** `{rule_id}`  \n**Product:** `{product}`\n\n---\n"
            )
    today = datetime.today().strftime("%Y-%m-%d")
    path = base_dir / f"chainsaw_report_raw_{today}.md"
    path.write_text(head + "".join(bod), encoding="utf-8")
    return path


def write_iocs(base_dir: Path, iocs: Dict[str, List[str]]) -> Path:
    today = datetime.today().strftime("%Y-%m-%d")
    path = base_dir / f"iocs_{today}.txt"
    lines = []
    for k in ("ips", "domains", "md5", "sha1", "sha256"):
        vals = iocs.get(k, [])
        if not vals:
            continue
        lines.append(k.upper() + ":")
        lines.extend(vals)
        lines.append("")
    path.write_text("\n".join(lines) if lines else "No IOCs.", encoding="utf-8")
    return path


def append_csv_summary(
    csv_path: Path,
    *,
    date: str,
    detections: int,
    chunks: int,
    micro_model: str,
    final_model: str,
    runtime_s: float,
    micro_s: float,
    merge_s: float,
    cost: float,
    in_tokens: int,
    out_tokens: int,
):
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not csv_path.exists()
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(
                [
                    "date",
                    "detections",
                    "chunks",
                    "micro_model",
                    "final_model",
                    "runtime_s",
                    "micro_s",
                    "merge_s",
                    "cost_usd",
                    "in_tokens",
                    "out_tokens",
                ]
            )
        w.writerow(
            [
                date,
                detections,
                chunks,
                micro_model,
                final_model,
                f"{runtime_s:.2f}",
                f"{micro_s:.2f}",
                f"{merge_s:.2f}",
                f"{cost:.6f}",
                in_tokens,
                out_tokens,
            ]
        )


def move_old_runs_to_archive(outdir: Path, today_str: str):
    # Move any sibling dated dirs (YYYY-MM-DD) except today into archive/YYYY-MM-DD
    archive_root = outdir / "archive"
    outdir.mkdir(parents=True, exist_ok=True)
    archive_root.mkdir(parents=True, exist_ok=True)
    for p in outdir.iterdir():
        if not p.is_dir():
            continue
        name = p.name
        if name == "archive":
            continue
        if name == today_str:
            continue
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", name):
            dest = archive_root / name
            if dest.exists():
                continue
            shutil.move(str(p), str(dest))


# ───────────────────────────────── Main ───────────────────────────────────
def main() -> None:
    t0 = time.perf_counter()
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        die("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)
    cfg = parse_args()

    # Select latest EVTX container
    latest = find_latest_container(cfg.evtx_root)
    ok(f"Using EVTX directory: {latest.name}")
    print_source_banners(latest, cfg.rules_dir, cfg.mapping_path, cfg.sigma_root)

    # Ensure chainsaw
    ensure_chainsaw_available()

    # Run chainsaw against dir (to match your 3.5 flow)
    detections_json = latest / "detections.json"
    t_hunt0 = time.perf_counter()
    run_chainsaw(latest, detections_json, cfg.rules_dir, cfg.mapping_path, cfg.sigma_root)
    t_hunt = time.perf_counter() - t_hunt0

    # Load detections
    t_load0 = time.perf_counter()
    if not _looks_json(detections_json):
        die(f"Chainsaw output not JSON: {detections_json}")
    detections = load_detections(detections_json, cfg.parse_format, cfg.max_detections)
    ok(f"Loaded {len(detections)} detections")
    t_load = time.perf_counter() - t_load0

    # Short-circuit when empty
    if not detections:
        console.rule("[bold yellow]⚠ No Sigma detections found[/bold yellow]")
        console.print("No Sigma detections found — skipping summarization to save tokens.")
        empty = latest / "chainsaw_summary_empty.md"
        empty.write_text(
            "# No Sigma detections\n\nChainsaw produced no Sigma hits for this run.\n",
            encoding="utf-8",
        )
        return

    # Prepare chunks & guardrail (single-pass guard)
    chunks = list(chunk(detections, cfg.chunk_size))
    _ = guardrail_estimate_or_die(
        chunks,
        DEFAULT_SYSTEM_PROMPT,
        cfg.max_chunks,
        cfg.max_input_tokens,
        no_script=cfg.no_script,
        truncate_script=cfg.truncate_script,
    )

    # Summarize (two-pass only, per your usage)
    t_micro = t_merge = 0.0
    t_llm0 = time.perf_counter()
    md, in_tokens, out_tokens, usage, t_micro, t_merge = two_pass_summarize(client, detections, cfg)
    t_llm = time.perf_counter() - t_llm0

    # IOC extraction
    iocs = extract_iocs(detections)
    ioc_md = "\n\n---\n\n## Indicators of Compromise\n\n" + format_iocs_md(iocs)
    md += ioc_md

    # Outputs (dated folder)
    today = datetime.today().strftime("%Y-%m-%d")
    target = cfg.outdir / today
    target.mkdir(parents=True, exist_ok=True)

    raw_md_path = write_raw_md(target, detections, cfg.chunk_size)
    html_path, pdf_path = write_reports(target, md, cfg.make_pdf, cfg.make_html, cfg.css_path)
    ioc_path = write_iocs(target, iocs)

    # Archive previous runs (optional)
    if cfg.archive:
        move_old_runs_to_archive(cfg.outdir, today)

    # Cost
    pricing = PRICING if not cfg.pricing_json else {**PRICING, **json.loads(cfg.pricing_json)}
    est_cost, cost_lines = estimate_cost(usage, pricing)

    # CSV summary
    append_csv_summary(
        cfg.csv_summary,
        date=today,
        detections=len(detections),
        chunks=len(chunks),
        micro_model=cfg.chunk_model,
        final_model=cfg.final_model,
        runtime_s=(time.perf_counter() - t0),
        micro_s=t_micro,
        merge_s=t_merge,
        cost=est_cost,
        in_tokens=in_tokens,
        out_tokens=out_tokens,
    )

    # Console output (rich)
    console.rule("[bold green]🔍 LLM-Summarized Report[/bold green]")
    console.print(Markdown(md[:8000] + ("\n\n…[truncated in console]" if len(md) > 8000 else "")))
    console.rule("[bold green]End of Summary[/bold green]")

    console.print(f"[green]✓ Raw Markdown:[/green] {raw_md_path}")
    if html_path:
        console.print(f"[green]✓ HTML:[/green] {html_path}")
    if pdf_path:
        console.print(f"[green]✓ PDF:[/green]  {pdf_path}")
    console.print(f"[green]✓ IOCs:[/green] {ioc_path}")

    console.print(
        f"[cyan]🧠 Tokens used (est): in+out={in_tokens + out_tokens} (in={in_tokens}, out={out_tokens})[/cyan]"
    )
    for ln in cost_lines:
        console.print(f"[cyan]{ln}[/cyan]")
    console.print(f"[cyan]💸 Estimated total cost:[/cyan] ${est_cost:.6f}")

    # Phase runtime footer
    console.rule("[bold]⏱ Runtime by phase[/bold]")
    console.print(f"- Chainsaw hunt: {t_hunt:.2f}s")
    console.print(f"- Load detections: {t_load:.2f}s")
    console.print(f"- Micro summaries: {t_micro:.2f}s")
    console.print(f"- Merge (final):   {t_merge:.2f}s")
    console.print(f"- LLM total:       {t_llm:.2f}s")
    console.print(f"- End-to-end:      {time.perf_counter() - t0:.2f}s")
    console.print(f"[green]✓ CSV summary:[/green] {cfg.csv_summary}")
    if html_path and not cfg.css_path:
        console.print(f"[green]✓ CSS:[/green] {target / 'report.css'}")


if __name__ == "__main__":
    main()
