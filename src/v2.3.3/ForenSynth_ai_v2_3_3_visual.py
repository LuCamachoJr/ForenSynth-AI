#!/usr/bin/env python3
# File: forensynth_ai_v2_3_3_visual.py
"""
ForenSynth AI v2.3.3 (Visual Refresh)
DFIR Intelligence Engine — Two-pass Sigma/EVTX summarization with:
 - Parallel micro-summaries (auto workers, RPM throttle thread-safe)
 - Scoring for chunk selection (technique/tags/event rarity/diversity)
 - Final executive merge under strict token guard (tiktoken if available)
 - Integrity Mode (forces gpt-5-mini + gpt-5)
 - Progress bars incl. final-merge bar + runtime footer
 - Self-contained HTML (escaped; heatmap + donut charts + tiny legends; no external JS)
 - TOC toggle, optional branding
 - CSV run log + recent runs table
 - Evidence JSON (+ optional CSV exports)
 - Built-in tests (token guard & HTML escape)

Quick example:
  python3 forensynth_ai_v2_3_3_visual.py --two-pass --micro-workers 6 --rpm 50 \
    --chunk-size 30 --llm-timeout 120 --llm-retries 8 \
    --make-html --toc on --branding on --chart-style both --export-evidence-csv
"""

from __future__ import annotations

import argparse
import csv
import html as _html
import json
import math
import os
import random
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# Optional libs
try:
    import tiktoken  # type: ignore
except Exception:
    tiktoken = None
try:
    import pypandoc  # type: ignore
except Exception:
    pypandoc = None

# OpenAI SDK
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
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

# ────────────────────────────────────────────────────────────────────────────
# Config & Defaults
# ────────────────────────────────────────────────────────────────────────────
console = Console()
DFIR_BLUE = "#0a69ff"

DEFAULT_CHUNK_MODEL = os.getenv("CHUNK_MODEL", "gpt-5-mini")
DEFAULT_FINAL_MODEL = os.getenv("FINAL_MODEL", "gpt-5")

PRICING = {
    "gpt-5-mini": {"in": 0.00025, "out": 0.00200},
    "gpt-5": {"in": 0.00125, "out": 0.01000},
    "gpt-3.5-turbo": {"in": 0.0005, "out": 0.0015},
}

SYSTEM_MICRO = (
    "You are a senior DFIR analyst. Produce concise, accurate summaries. "
    "Group related detections, highlight notable TTPs (MITRE), dedupe repetition, "
    "and end with prioritized recommendations by risk and effort."
)
SYSTEM_FINAL = (
    "You are a DFIR lead. Merge micro-summaries into a coherent executive report. "
    "Eliminate repetition; group by phases/TTPs; quantify scope; "
    "end with prioritized, actionable recommendations (High/Med/Low) and quick wins."
)
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

EVENT_WEIGHTS = {  # interesting EIDs
    "1": 1.2,
    "3": 1.3,
    "7": 1.1,
    "8": 1.1,
    "10": 1.4,
    "11": 1.1,
    "4624": 1.1,
    "4625": 1.1,
    "4688": 1.6,
    "4697": 1.4,
    "4720": 1.5,
    "4728": 1.3,
    "4732": 1.3,
    "7045": 1.5,
}
SEVERITY_TAG_BOOSTS = {
    "critical": 2.0,
    "high": 1.6,
    "medium": 1.3,
    "suspicious": 1.2,
    "credential": 1.3,
    "persistence": 1.4,
    "lateral": 1.4,
    "exfil": 1.6,
    "ransom": 1.8,
}


# ────────────────────────────────────────────────────────────────────────────
# CLI & App State
# ────────────────────────────────────────────────────────────────────────────
@dataclass
class AppConfig:
    evtx_root: Path
    scope: str
    prefer: List[str]
    rules: Path
    mapping: Path
    sigma_root: Optional[Path]
    outdir: Path

    two_pass: bool
    make_html: bool
    make_pdf: bool
    toc: bool
    branding: bool
    fast: bool
    stream: bool
    integrity: bool
    run_tests: bool
    max_fidelity: bool

    chunk_model: str
    final_model: str
    llm_timeout: int
    llm_retries: int
    temperature: float
    max_input_tokens: int
    chunk_size: int
    max_chunks: int

    micro_workers: int
    rpm: int
    limit_detections: int
    sample_step: int

    export_evidence_csv: bool
    chart_style: str  # 'heatmap' | 'pies' | 'both' | 'off'


def parse_args() -> AppConfig:
    p = argparse.ArgumentParser(description="ForenSynth AI v2.3.3 (Visual Refresh)")
    p.add_argument("--evtx-root", type=Path, default=Path("/mnt/evtx_share/DFIR-Lab-Logs"))
    p.add_argument("--scope", choices=["dir", "file"], default="dir")
    p.add_argument("--prefer", default="PowerShell-Operational.evtx,Security.evtx")
    p.add_argument("--rules", type=Path, default=Path.home() / "tools" / "sigma" / "rules")
    p.add_argument(
        "--mapping",
        type=Path,
        default=Path.home() / "tools" / "chainsaw" / "sigma-event-logs-all.yml",
    )
    p.add_argument("--sigma-root", type=Path, default=None)
    p.add_argument(
        "--outdir", type=Path, default=Path.home() / "DFIR-Labs" / "ForenSynth" / "Reports"
    )

    p.add_argument("--two-pass", action="store_true")
    p.add_argument("--make-html", action="store_true")
    p.add_argument("--make-pdf", action="store_true")
    p.add_argument("--toc", choices=["on", "off"], default="off")
    p.add_argument("--branding", choices=["on", "off"], default="on")
    p.add_argument("--fast", action="store_true")
    p.add_argument("--stream", choices=["on", "off"], default="off")
    p.add_argument("--integrity", choices=["on", "off"], default="off")
    p.add_argument("--run-tests", action="store_true")
    p.add_argument("--max-fidelity", action="store_true")

    p.add_argument("--chunk-model", default=DEFAULT_CHUNK_MODEL)
    p.add_argument("--final-model", default=DEFAULT_FINAL_MODEL)
    p.add_argument("--llm-timeout", type=int, default=60)
    p.add_argument("--llm-retries", type=int, default=6)
    p.add_argument("--temperature", type=float, default=1.0)
    p.add_argument("--max-input-tokens", type=int, default=120_000)
    p.add_argument("--chunk-size", type=int, default=25)
    p.add_argument("--max-chunks", type=int, default=120)

    p.add_argument("--micro-workers", type=int, default=0, help="0=auto")
    p.add_argument("--rpm", type=int, default=0)

    p.add_argument("--export-evidence-csv", action="store_true")
    p.add_argument("--chart-style", choices=["heatmap", "pies", "both", "off"], default="both")
    p.add_argument("--limit-detections", type=int, default=0,
                   help="If > 0, limit the number of detections processed after loading (applied post-                  Chainsaw).")
    p.add_argument("--sample-step", type=int, default=0,
                   help="If > 1, keep every Nth detection before applying the limit (simple stratified     sample).")

    a = p.parse_args()
    prefer = [s.strip() for s in a.prefer.split(",") if s.strip()]

    workers = a.micro_workers
    if workers <= 0:
        cpu = os.cpu_count() or 2
        workers = min(max(2, cpu), 8) if a.fast else max(1, min(cpu, 4))

    chunk_model = a.chunk_model
    final_model = a.final_model
    if a.integrity == "on":
        chunk_model = "gpt-5-mini"
        final_model = "gpt-5"

    return AppConfig(
        evtx_root=a.evtx_root,
        scope=a.scope,
        prefer=prefer,
        rules=a.rules,
        mapping=a.mapping,
        sigma_root=a.sigma_root,
        outdir=a.outdir,
        two_pass=a.two_pass,
        make_html=a.make_html,
        make_pdf=a.make_pdf,
        toc=(a.toc == "on"),
        branding=(a.branding == "on"),
        fast=a.fast,
        stream=(a.stream == "on"),
        integrity=(a.integrity == "on"),
        run_tests=a.run_tests,
        max_fidelity=a.max_fidelity,
        chunk_model=chunk_model,
        final_model=final_model,
        llm_timeout=a.llm_timeout,
        llm_retries=a.llm_retries,
        temperature=a.temperature,
        max_input_tokens=max(4000, a.max_input_tokens),
        chunk_size=max(1, a.chunk_size),
        max_chunks=max(1, a.max_chunks),
        micro_workers=workers,
        rpm=max(0, a.rpm),
        export_evidence_csv=a.export_evidence_csv,
        chart_style=a.chart_style,
        limit_detections=a.limit_detections,
        sample_step=a.sample_step
    )


# ────────────────────────────────────────────────────────────────────────────
# Console helpers
# ────────────────────────────────────────────────────────────────────────────
def ok(msg: str):
    console.print(Panel.fit(f"[green]✔ {msg}[/green]", box=box.ROUNDED))


def info(msg: str):
    console.print(Panel.fit(f"[yellow]⚙ {msg}[/yellow]", box=box.ROUNDED))


def warn(msg: str):
    console.print(Panel.fit(f"[yellow]⚠ {msg}[/yellow]", box=box.ROUNDED))


def die(msg: str):
    console.print(Panel.fit(f"[red]✘ {msg}[/red]", box=box.ROUNDED))
    sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────
# Chainsaw integration
# ────────────────────────────────────────────────────────────────────────────
def latest_container(root: Path) -> Path:
    if not root.exists():
        die(f"EVTX root not found: {root}")
    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs:
        die(f"No subfolders under {root}")
    return max(dirs, key=lambda p: p.stat().st_mtime)


def select_source(root: Path, scope: str, prefer: List[str]) -> Tuple[str, Path]:
    folder = latest_container(root)
    console.print(
        Panel.fit(f"[cyan]✔ Using latest EVTX directory:[/cyan] {folder}", box=box.ROUNDED)
    )
    if scope == "dir":
        return "dir", folder
    for name in prefer:
        p = folder / name
        if p.exists():
            ok(f"Selected log file: {p.name}")
            return "file", p
    any_evtx = sorted(folder.glob("*.evtx"))
    if any_evtx:
        ok(f"Selected log file (fallback): {any_evtx[0].name}")
        return "file", any_evtx[0]
    die("No .evtx files found in latest directory")


def ensure_chainsaw():
    if shutil.which("chainsaw") is None:
        die("chainsaw not found in PATH")


def ensure_paths(rules: Path, mapping: Path):
    if not rules.exists():
        die(f"Sigma rules path not found: {rules}")
    if not mapping.exists():
        die(f"Chainsaw mapping not found: {mapping}")


def run_chainsaw(kind: str, src: Path, rules: Path, mapping: Path, outdir: Path) -> Path:
    info("Running Chainsaw hunt…")
    console.print("\n[italic]🪓 Chainsaw Module Active — Sigma Hunt in Progress…[/italic]\n")
    out_path = outdir / "detections.json"
    outdir.mkdir(parents=True, exist_ok=True)

    sigma_root = str((rules.parent if rules.name.lower() == "rules" else rules).resolve())
    cmd = [
        "chainsaw",
        "hunt",
        str(src),
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
    with Progress(
        SpinnerColumn(), TextColumn("[bold]Hunting[/bold]"), BarColumn(), TimeElapsedColumn()
    ) as prog:
        task = prog.add_task("hunt", total=None)
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            die(f"Chainsaw failed: {e}")
        finally:
            prog.update(task, completed=True)
    ok("Chainsaw hunt completed. Parsing detections…")
    (outdir / "chainsaw_cmd.txt").write_text(" ".join(cmd), encoding="utf-8")
    return out_path


# ────────────────────────────────────────────────────────────────────────────
# Detections load/normalize
# ────────────────────────────────────────────────────────────────────────────
def load_detections(path: Path, cap: int = 0) -> List[Dict[str, Any]]:
    if not path.exists():
        die(f"Detections file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for ln in text.splitlines():
            ln = ln.strip()
            if ln:
                try:
                    data.append(json.loads(ln))
                except json.JSONDecodeError:
                    pass
    if isinstance(data, dict) and "detections" in data:
        detections = data["detections"]
    elif isinstance(data, list):
        detections = data
    else:
        die("Unexpected detections JSON shape")
    if cap > 0:
        detections = detections[:cap]
    return detections


# ────────────────────────────────────────────────────────────────────────────
# Token estimation
# ────────────────────────────────────────────────────────────────────────────
def est_tokens(s: str, model_hint: str = "gpt-4o") -> int:
    if tiktoken:
        try:
            enc = tiktoken.encoding_for_model(model_hint)
        except Exception:
            enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(s))
    return max(1, math.ceil(len(s) / 4))


# ────────────────────────────────────────────────────────────────────────────
# Scoring (smarter selection)
# ────────────────────────────────────────────────────────────────────────────
def _extract_event_id(det: Dict[str, Any]) -> str:
    try:
        return str(
            (((det.get("document") or {}).get("data") or {}).get("Event") or {})
            .get("System", {})
            .get("EventID", "")
        )
    except Exception:
        return ""


def _extract_tags(det: Dict[str, Any]) -> List[str]:
    tags = det.get("tags", []) or []
    if isinstance(tags, str):
        tags = [tags]
    return [t.lower() for t in tags]


def score_detection(det: Dict[str, Any], rule_freq: Dict[str, int]) -> float:
    rule = det.get("name") or (det.get("rule", {}) or {}).get("title") or ""
    tags = _extract_tags(det)
    eid = _extract_event_id(det)

    mitres = MITRE_RE.findall(rule + " " + " ".join(tags))
    mitre_bonus = 1.0 + (0.2 * min(3, len(mitres)))

    sev = 1.0
    for t in tags:
        for k, mult in SEVERITY_TAG_BOOSTS.items():
            if k in t:
                sev = max(sev, mult)

    eid_w = EVENT_WEIGHTS.get(str(eid), 1.0)
    freq = rule_freq.get(rule, 1)
    rarity = 1.0 + min(0.8, 1.0 / math.sqrt(freq))

    script = (
        (((det.get("document") or {}).get("data") or {}).get("Event") or {}).get("EventData") or {}
    ).get("ScriptBlockText", "")
    script_bonus = 1.0 + min(0.5, len(script) / 2000.0)

    return mitre_bonus * sev * eid_w * rarity * script_bonus


def score_micro_block(block: List[Dict[str, Any]], rule_freq: Dict[str, int]) -> float:
    if not block:
        return 0.0
    scores = sorted((score_detection(d, rule_freq) for d in block), reverse=True)
    base = sum(scores[: min(5, len(scores))])
    uniq_rules = len({d.get("name") or (d.get("rule", {}) or {}).get("title") for d in block})
    diversity = 1.0 + min(0.5, (uniq_rules / max(1, len(block))) * 0.5)
    return base * diversity


# ────────────────────────────────────────────────────────────────────────────
# Prompt builders
# ────────────────────────────────────────────────────────────────────────────
def fmt_micro_line(det: Dict[str, Any], include_snip: bool = True, snip_len: int = 160) -> str:
    ts = det.get("timestamp", "N/A")
    rule = det.get("name", (det.get("rule", {}) or {}).get("title", "N/A"))
    tags = ", ".join(_extract_tags(det)) or "None"
    eid = _extract_event_id(det) or "N/A"
    script = (
        (((det.get("document") or {}).get("data") or {}).get("Event") or {}).get("EventData") or {}
    ).get("ScriptBlockText", "")
    snip = (
        (script[:snip_len] + ("…" if len(script) > snip_len else ""))
        if (include_snip and script)
        else ""
    )
    line = f"- [{ts}] {rule} (EventID {eid}; Tags: {tags})"
    if snip:
        line += f" | snippet: {snip}"
    return line


def build_micro_prompt(block: List[Dict[str, Any]]) -> str:
    hdr = (
        "Micro-summarize these detections for DFIR triage in <= 12 bullets total. "
        "Group similar items, cite key TTPs (MITRE IDs if present), mention counts/timestamps. "
        "No fluff. Output sections:\n"
        "• Executive bullets\n• Key TTPs\n• Notable IOCs (if any)\n"
    )
    body = "\n".join(fmt_micro_line(d) for d in block)
    return hdr + "\n" + body


def build_final_prompt(micros: List[str]) -> str:
    hdr = (
        "Merge the following micro-summaries into one executive DFIR report. "
        "Eliminate duplicates, group themes, and produce:\n"
        "1) Executive Summary\n2) Observed Activity (grouped)\n3) Key TTPs/Techniques\n4) Risk Assessment\n5) Actionable Recommendations (High/Med/Low)\n"
    )
    return hdr + "\n\n" + "\n\n---\n\n".join(micros)


# ────────────────────────────────────────────────────────────────────────────
# LLM call with robust fallback
# ────────────────────────────────────────────────────────────────────────────
def backoff_sleep(i: int):
    time.sleep(min(30.0, (1.6**i) + random.uniform(0, 0.25)))


def call_llm(
    client: OpenAI,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    timeout_s: int,
    retries: int,
    stream: bool = False,
) -> str:
    send_temp = (
        None if abs(temperature - 1.0) < 1e-6 or model.startswith("gpt-5") else float(temperature)
    )
    last_err = None
    for i in range(retries):
        try:
            payload: Dict[str, Any] = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
            if send_temp is not None:
                payload["temperature"] = send_temp
            if stream:
                payload["stream"] = True
                chunks = client.chat.completions.create(**payload, timeout=timeout_s)
                out: List[str] = []
                for ev in chunks:
                    delta = getattr(ev.choices[0].delta, "content", None)
                    if delta:
                        out.append(delta)
                return "".join(out)
            else:
                resp = client.chat.completions.create(**payload, timeout=timeout_s)
                return resp.choices[0].message.content or ""
        except BadRequestError as e:
            msg = str(e).lower()
            if "stream" in msg:
                stream = False
                last_err = e
                continue
            if "temperature" in msg:
                send_temp = None
                last_err = e
                continue
            raise
        except (RateLimitError, APITimeoutError, APIConnectionError, APIError) as e:
            last_err = e
            backoff_sleep(i)
            continue
    raise RuntimeError(f"LLM retries exceeded: {last_err}")


# ────────────────────────────────────────────────────────────────────────────
# Chunking / batching under token guard
# ────────────────────────────────────────────────────────────────────────────
def chunk(lst: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def dynamic_chunks(
    dets: List[Dict[str, Any]], base_size: int, max_input_tokens: int
) -> List[List[Dict[str, Any]]]:
    size = max(1, base_size)
    while True:
        blocks = list(chunk(dets, size))
        sys_t = est_tokens(SYSTEM_MICRO)
        total_est = 0
        for b in blocks:
            total_est += sys_t + est_tokens(build_micro_prompt(b))
            if total_est > max_input_tokens:
                break
        if total_est <= max_input_tokens or size == 1:
            return blocks
        size = max(1, size - 2)


# ────────────────────────────────────────────────────────────────────────────
# Parallel micro + scoring-aware final selection
# ────────────────────────────────────────────────────────────────────────────
def micro_parallel(
    client: OpenAI, blocks: List[List[Dict[str, Any]]], cfg: AppConfig
) -> Tuple[List[str], Tuple[int, int]]:
    usage_in = usage_out = 0
    micros: List[str] = [""] * len(blocks)

    import threading

    last_call = [0.0]
    lock = threading.Lock()

    def throttle():
        if cfg.rpm > 0:
            min_gap = 60.0 / float(cfg.rpm)
            with lock:
                wait = max(0.0, min_gap - (time.time() - last_call[0]))
                if wait > 0:
                    time.sleep(wait)
                last_call[0] = time.time()

    def work(i: int, b: List[Dict[str, Any]]) -> Tuple[int, str, int, int]:
        user = build_micro_prompt(b)
        tin = est_tokens(SYSTEM_MICRO) + est_tokens(user)
        throttle()
        out = call_llm(
            client,
            cfg.chunk_model,
            SYSTEM_MICRO,
            user,
            cfg.temperature,
            cfg.llm_timeout,
            cfg.llm_retries,
            stream=False,
        )
        tout = est_tokens(out)
        return i, out, tin, tout

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Micro[/bold]"),
        BarColumn(),
        TextColumn("[progress.completed]/[progress.total]"),
        TimeElapsedColumn(),
    ) as prog:
        task = prog.add_task("micro", total=len(blocks))
        with ThreadPoolExecutor(max_workers=cfg.micro_workers) as ex:
            futs = [ex.submit(work, i, b) for i, b in enumerate(blocks)]
            for f in as_completed(futs):
                i, out, tin, tout = f.result()
                micros[i] = f"## Micro {i + 1}: Cluster Summary\n\n" + out
                usage_in += tin
                usage_out += tout
                prog.update(task, advance=1)
    return micros, (usage_in, usage_out)


def select_best_micros(
    blocks: List[List[Dict[str, Any]]], micros: List[str], max_tokens: int
) -> List[str]:
    rule_freq: Dict[str, int] = {}
    for b in blocks:
        for d in b:
            r = d.get("name") or (d.get("rule", {}) or {}).get("title") or ""
            rule_freq[r] = rule_freq.get(r, 0) + 1

    scored: List[Tuple[float, str]] = []
    for b, m in zip(blocks, micros):
        scored.append((score_micro_block(b, rule_freq), m))
    scored.sort(key=lambda x: x[0], reverse=True)

    selected: List[str] = []
    budget = est_tokens(SYSTEM_FINAL)
    for s, m in scored:
        cost = est_tokens(m)
        if budget + cost <= max_tokens:
            selected.append(m)
            budget += cost
    if not selected and micros:
        m0 = micros[0]
        allowed = max(1000, max_tokens - est_tokens(SYSTEM_FINAL))
        selected = [m0[: allowed * 4]]
    return selected


def two_pass(
    client: OpenAI, dets: List[Dict[str, Any]], cfg: AppConfig
) -> Tuple[str, Dict[str, Tuple[int, int]]]:
    blocks = dynamic_chunks(dets, cfg.chunk_size, cfg.max_input_tokens)
    if not blocks:
        return "# No detections — nothing to summarize.", {}

    console.print(
        Panel.fit(
            f"[yellow]⚙ Detections found ({len(dets)}) — generating micro-summaries…[/yellow]",
            box=box.ROUNDED,
        )
    )
    micros, (mi_in, mi_out) = micro_parallel(client, blocks, cfg)

    console.print(
        Panel.fit(
            "[yellow]⚙ Compiling executive summary with final model…[/yellow]", box=box.ROUNDED
        )
    )
    selected = select_best_micros(blocks, micros, cfg.max_input_tokens)
    final_user = build_final_prompt(selected)

    final_text = ""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Final Merge[/bold]"),
        BarColumn(bar_width=None),
        TimeElapsedColumn(),
    ) as prog:
        task = prog.add_task("final", total=None)
        if cfg.rpm > 0:
            time.sleep(max(0.0, 60.0 / float(cfg.rpm)))
        try:
            final_text = call_llm(
                client,
                cfg.final_model,
                SYSTEM_FINAL,
                final_user,
                cfg.temperature,
                cfg.llm_timeout,
                cfg.llm_retries,
                stream=False if cfg.max_fidelity else cfg.stream,
            )
        except RuntimeError as e:
            if "stream" in str(e).lower():
                final_text = call_llm(
                    client,
                    cfg.final_model,
                    SYSTEM_FINAL,
                    final_user,
                    cfg.temperature,
                    cfg.llm_timeout,
                    cfg.llm_retries,
                    stream=False,
                )
            else:
                raise
        prog.update(task, completed=True)

    usage = {
        cfg.chunk_model: (mi_in, mi_out),
        cfg.final_model: (
            est_tokens(SYSTEM_FINAL) + est_tokens(final_user),
            est_tokens(final_text),
        ),
    }

    header = (
        "# 🔒 ForenSynth AI — DFIR Summary (Two-Pass, Max Fidelity)\n\n"
        f"- Generated: {datetime.now(timezone.utc).isoformat()}\n"
        f"- Micro model: `{cfg.chunk_model}`\n"
        f"- Final model: `{cfg.final_model}`\n"
        f"- Chunks: {len(blocks)}\n"
        f"- Integrity: {'ON' if cfg.integrity else 'OFF'} | Max Fidelity: {'ON' if cfg.max_fidelity else 'OFF'}\n"
        "\n---\n\n## Final Executive Report\n\n"
    )
    appendix = "\n\n---\n\n## Micro Cluster Summaries\n\n" + "\n\n".join(micros)
    return header + final_text + appendix, usage


# ────────────────────────────────────────────────────────────────────────────
# Evidence CSV export (optional)
# ────────────────────────────────────────────────────────────────────────────
def _write_csv(path: Path, headers: List[str], rows: List[Tuple[Any, ...]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for r in rows:
            writer.writerow(
                [
                    x if not isinstance(x, (list, dict)) else json.dumps(x, ensure_ascii=False)
                    for x in r
                ]
            )


def write_evidence_csvs(evd: Dict[str, Any], outdir: Path):
    base = outdir / "evidence_csv"
    top = evd.get("top", {}) if isinstance(evd, dict) else {}
    counts = evd.get("counts", {}) if isinstance(evd, dict) else {}
    timeframe = evd.get("timeframe", {}) if isinstance(evd, dict) else {}
    iocs = evd.get("iocs", {}) if isinstance(evd, dict) else {}

    _write_csv(
        base / "summary.csv",
        [
            "detections",
            "first_ts",
            "last_ts",
            "unique_rules",
            "unique_event_ids",
            "unique_hosts",
            "unique_users",
            "unique_tags",
        ],
        [
            (
                evd.get("detections"),
                timeframe.get("first"),
                timeframe.get("last"),
                counts.get("unique_rules"),
                counts.get("unique_event_ids"),
                counts.get("unique_hosts"),
                counts.get("unique_users"),
                counts.get("unique_tags"),
            )
        ],
    )

    def write_top(name: str, pairs: List[List[Any]]):
        _write_csv(
            base / f"top_{name}.csv",
            [name[:-1] if name.endswith("s") else name, "count"],
            pairs or [],
        )

    write_top("rules", top.get("rules", []))
    write_top("event_ids", top.get("event_ids", []))
    write_top("hosts", top.get("hosts", []))
    write_top("users", top.get("users", []))

    def write_ioc(name: str, items: List[str]):
        _write_csv(base / f"iocs_{name}.csv", [name], [(x,) for x in (items or [])])

    write_ioc("ipv4", iocs.get("ipv4", []))
    write_ioc("domains", iocs.get("domains", []))
    write_ioc("urls", iocs.get("urls", []))
    write_ioc("emails", iocs.get("emails", []))
    write_ioc("sha256", iocs.get("sha256", []))
    write_ioc("sha1", iocs.get("sha1", []))
    write_ioc("md5", iocs.get("md5", []))
    write_ioc("paths", iocs.get("paths", []))
 
# ────────────────────────────────────────────────────────────────────────────
# Sampling Helper
# ────────────────────────────────────────────────────────────────────────────
def apply_sampling(dets: List[Dict[str, Any]], limit: int = 0, step: int = 0, sort_time: bool = False) -> List[Dict[str, Any]]:
    """
    Optionally sub-sample and/or cap detections before the LLM phases.
    - step > 1  → keep every Nth record (0, N, 2N, ...)
    - limit > 0 → truncate to first `limit` items after step filter
    - sort_time → if True, attempt chronological sort by .timestamp before sampling
    """
    original = len(dets)
    if sort_time:
        try:
            dets = sorted(dets, key=lambda d: (d.get("timestamp") or ""))
        except Exception:
            # keep original order if timestamp sort fails
            pass

    if step and step > 1:
        dets = [v for i, v in enumerate(dets) if i % step == 0]

    if limit and limit > 0:
        dets = dets[:limit]

    if len(dets) != original:
        info(f"Sampling applied: {original} → {len(dets)} (step={step or 1}, limit={limit or 'none'})")
    return dets

# ────────────────────────────────────────────────────────────────────────────
# Heatmap & Donut helpers + HTML
# ────────────────────────────────────────────────────────────────────────────
def build_heatmap_counts(dets: List[Dict[str, Any]]) -> List[int]:
    buckets = [0] * 24
    for d in dets:
        ts = d.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00") if ts.endswith("Z") else ts)
            hr = dt.astimezone(timezone.utc).hour
            buckets[hr] += 1
        except Exception:
            continue
    return buckets


def counts_by_day(dets: List[Dict[str, Any]]) -> List[Tuple[str, int]]:
    c = Counter()
    for d in dets:
        ts = d.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00") if ts.endswith("Z") else ts)
            day = dt.date().isoformat()
            c[day] += 1
        except Exception:
            continue
    return sorted(c.items())


def phase_buckets_from_evidence(evd: Dict[str, Any]) -> Dict[str, int]:
    tag_counts = dict(evd.get("top", {}).get("tags", [])) if isinstance(evd, dict) else {}
    buckets = defaultdict(int)
    phase_map = {
        "execution": "Execution",
        "powershell": "Execution",
        "wmic": "Execution",
        "encoded": "Execution",
        "persistence": "Persistence",
        "schtask": "Persistence",
        "registry": "Persistence",
        "runkey": "Persistence",
        "service": "Persistence",
        "com": "Persistence",
        "credential": "Accounts/Creds",
        "account": "Accounts/Creds",
        "user": "Accounts/Creds",
        "group": "Accounts/Creds",
        "discovery": "Discovery/Lateral",
        "lateral": "Discovery/Lateral",
        "smb": "Discovery/Lateral",
        "wmi": "Discovery/Lateral",
        "exfil": "Impact/Exfil",
        "ransom": "Impact/Exfil",
        "evasion": "Evasion",
        "obfuscation": "Evasion",
        "log": "Evasion",
        "sysmon": "Evasion",
    }
    for tag, ct in tag_counts.items():
        tag_l = str(tag).lower()
        bucket = "Other"
        for k, name in phase_map.items():
            if k in tag_l:
                bucket = name
                break
        buckets[bucket] += int(ct)
    return dict(buckets)


INLINE_CSS = f"""
:root {{ --fg:#0e1628; --muted:#66728a; --bg:#ffffff; --edge:#eef2f8; --accent:{DFIR_BLUE}; }}
html,body {{ margin:0; padding:0; }}
body {{ color:var(--fg); background:var(--bg); font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial; }}
.header {{ padding:24px 24px 8px; border-bottom:1px solid var(--edge); }}
.h1 {{ font-size:28px; font-weight:800; margin:0 0 4px; }}
.sub {{ color:var(--muted); font-size:14px; }}
.container {{ max-width:min(1200px, 96vw); margin:0 auto; padding:0 clamp(12px,2vw,24px) 48px; }}
.toc {{ margin:16px 0 24px; padding:12px; background:#f6f9ff; border:1px solid var(--edge); border-radius:8px; overflow:auto; }}
.section h2 {{ font-size:20px; margin-top:28px; border-bottom:1px solid var(--edge); padding-bottom:4px; }}
pre, code {{ background:#f7f9fc; border:1px solid var(--edge); border-radius:6px; }}
pre {{ padding:12px; overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; }}
.footer {{ margin-top:36px; padding:16px; border-top:1px solid var(--edge); font-size:13px; color:var(--muted);
           display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap; }}
.brand {{ opacity:0.85; }}
.strip {{ margin-top:18px; height:8px; background: linear-gradient(90deg, #d6e6ff 0%, {DFIR_BLUE} 50%, #001A72 100%); border-radius:4px; }}
.kpis {{ display:grid; grid-template-columns: repeat(6, minmax(0,1fr)); gap:12px; margin:16px 0; }}
.kpi {{ background:#f7faff; border:1px solid var(--edge); border-radius:10px; padding:12px; }}
.kpi .label {{ color:var(--muted); font-size:12px; }}
.kpi .value {{ font-size:18px; font-weight:700; }}
.canvas-wrap {{ margin:12px 0 0; border:1px solid var(--edge); border-radius:8px; padding:8px; }}
.note {{ color:var(--muted); font-size:12px; margin-top:6px; }}
.charts {{ display:grid; grid-template-columns: repeat(3, minmax(240px,1fr)); gap:16px; align-items:center; }}
.chart {{ background:#f7faff; border:1px solid var(--edge); border-radius:12px; padding:12px; display:flex; flex-direction:column; gap:8px; }}
.chart h3 {{ margin:0; font-size:16px; }}
canvas.resp {{ width:100%; height:auto; display:block; }}
.legend {{ display:grid; grid-template-columns: 1fr; gap:6px; margin-top:6px; font-size:12px; color:#334155; }}
.legend-item {{ display:flex; align-items:center; gap:8px; }}
.legend-swatch {{ width:10px; height:10px; border-radius:2px; border:1px solid rgba(0,0,0,0.08); }}
.legend-label {{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
@media (max-width: 960px) {{
  .kpis {{ grid-template-columns: repeat(3, minmax(0,1fr)); }}
  .charts {{ grid-template-columns: 1fr; }}
}}
"""

HEATMAP_JS = r"""
function renderHeatmap(canvasId, counts) {
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  const cols = 24, rows = 1, pad = 8;
  const cw = (w - pad*2) / cols;
  const ch = (h - pad*2) / rows;
  const max = Math.max(1, ...counts);

  ctx.clearRect(0,0,w,h);
  ctx.font = '12px system-ui, -apple-system, Segoe UI, Roboto, Arial';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';

  for (let c=0; c<cols; c++) {
    const val = counts[c] || 0;
    const t = Math.sqrt(val / max);
    const r = Math.floor(214 - 120*t);
    const g = Math.floor(230 - 110*t);
    const b = Math.floor(255 - 140*t);
    ctx.fillStyle = `rgb(${r},${g},${b})`;
    const x = pad + c*cw;
    const y = pad;
    ctx.fillRect(x, y, cw-2, ch);

    if (c % 3 === 0) {
      ctx.fillStyle = '#66728a';
      ctx.fillText(String(c).padStart(2,'0'), x+cw/2, y+ch+2);
    }
  }

  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left - pad;
    if (mx < 0 || mx > (w-pad*2)) { canvas.title=''; return; }
    const c = Math.min(23, Math.max(0, Math.floor(mx / ((w-pad*2)/cols))));
    canvas.title = `${String(c).padStart(2,'0')}:00 — ${counts[c]||0} detections`;
  });
}
"""

DONUT_JS = r"""
function fitCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width  = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(rect.width * 0.66 * dpr);
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr,0,0,dpr,0,0);
  return ctx;
}
function palette(i){
  const base = [[214,230,255],[77,136,255],[0,26,114],[138,180,248],[66,133,244],[23,78,166],[178,208,255],[99,155,255]];
  const p = base[i % base.length];
  return `rgb(${p[0]},${p[1]},${p[2]})`;
}
function drawDonut(canvasId, dataPairs, title, legendId) {
  const canvas = document.getElementById(canvasId);
  const ctx = fitCanvas(canvas);
  const w = canvas.clientWidth, h = canvas.clientHeight;
  const cx = w/2, cy = h/2, r = Math.min(w,h)*0.35, ir = r*0.62;
  const total = dataPairs.reduce((a,b)=>a + (b[1]||0), 0) || 1;
  let start = -Math.PI/2;
  ctx.clearRect(0,0,w,h);
  ctx.font = '14px system-ui,-apple-system,Segoe UI,Roboto,Arial';
  ctx.textAlign = 'center';
  ctx.fillStyle = '#111';
  ctx.fillText(title, cx, 18);
  dataPairs.forEach(([label, val], i) => {
    const frac = (val||0)/total;
    const end = start + frac * Math.PI*2;
    ctx.beginPath(); ctx.moveTo(cx,cy);
    ctx.arc(cx,cy,r,start,end); ctx.closePath();
    ctx.fillStyle = palette(i); ctx.fill();
    const mid = (start+end)/2, pct = Math.round(frac*100);
    if (pct >= 6) {
      const lx = cx + Math.cos(mid)* (r*0.8);
      const ly = cy + Math.sin(mid)* (r*0.8);
      ctx.fillStyle = '#111'; ctx.fillText(`${pct}%`, lx, ly);
    }
    start = end;
  });
  ctx.globalCompositeOperation = 'destination-out';
  ctx.beginPath(); ctx.arc(cx,cy,ir,0,Math.PI*2); ctx.fill();
  ctx.globalCompositeOperation = 'source-over';
  if (legendId) {
    const el = document.getElementById(legendId);
    if (el) {
      el.innerHTML = "";
      dataPairs.slice(0,8).forEach(([label, val], i)=>{
        const row = document.createElement('div'); row.className='legend-item';
        const sw = document.createElement('div'); sw.className='legend-swatch'; sw.style.background = palette(i);
        const txt = document.createElement('div'); txt.className='legend-label'; txt.textContent = `${label} (${val})`;
        row.appendChild(sw); row.appendChild(txt); el.appendChild(row);
      });
    }
  }
}
window.addEventListener('resize', ()=>{
  document.querySelectorAll('canvas.resp').forEach(c=>{
    const t = c.getAttribute('data-type');
    if (t==='donut' && c.__redraw) c.__redraw();
  });
});
"""


def build_html(
    md_final: str,
    dets: List[Dict[str, Any]],
    cfg: AppConfig,
    outname: str,
    evd: Dict[str, Any] = None,
) -> str:
    counts = build_heatmap_counts(dets)
    by_day = counts_by_day(dets)
    phase_buckets = phase_buckets_from_evidence(evd or {"top": {"tags": []}})
    top_eids = (evd or {}).get("top", {}).get("event_ids", [])[:6]

    toc_html = (
        """
    <div class="toc">
      <strong>Contents</strong>
      <ul>
        <li><a href="#kpis">Key Metrics</a></li>
        <li><a href="#heat">Detection Heatmap</a></li>
        <li><a href="#charts">At-a-Glance</a></li>
        <li><a href="#exec">Executive Report</a></li>
      </ul>
    </div>
    """
        if cfg.toc
        else ""
    )

    branding = (
        '<div class="brand">Powered by <strong>ForenSynth AI\u2122</strong></div>'
        if cfg.branding
        else "<div></div>"
    )
    body_html = _html.escape(md_final)

    heat_html = (
        """
    <div id="heat" class="section">
      <h2>Detection Heatmap (UTC, per hour)</h2>
      <div class="canvas-wrap">
        <canvas id="heatmap" class="resp"></canvas>
      </div>
      <div class="note">Hover cells to see exact hour & count</div>
    </div>
    """
        if cfg.chart_style in ("heatmap", "both")
        else ""
    )

    charts_html = (
        """
    <div id="charts" class="section">
      <h2>At-a-Glance</h2>
      <div class="charts">
        <div class="chart">
          <h3>By Phase</h3>
          <canvas id="donut_phase" class="resp" data-type="donut"></canvas>
          <div id="legend_phase" class="legend"></div>
        </div>
        <div class="chart">
          <h3>Top Event IDs</h3>
          <canvas id="donut_eid" class="resp" data-type="donut"></canvas>
          <div id="legend_eid" class="legend"></div>
        </div>
        <div class="chart">
          <h3>By Day</h3>
          <canvas id="donut_day" class="resp" data-type="donut"></canvas>
          <div id="legend_day" class="legend"></div>
        </div>
      </div>
      <div class="note">Percentages shown for larger slices; legend capped to top 8 per chart.</div>
    </div>
    """
        if cfg.chart_style in ("pies", "both")
        else ""
    )

    # Build the main HTML (no inline f-string JS to avoid brace parsing)
    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>ForenSynth AI — DFIR Report</title>
<style>{INLINE_CSS}</style>
</head>
<body>
  <div class="header">
    <div class="h1">ForenSynth AI — DFIR Report</div>
    <div class="sub">Generated {datetime.now(timezone.utc).isoformat()} | Integrity Mode: {"ON" if cfg.integrity else "OFF"}</div>
    <div class="strip"></div>
  </div>
  <div class="container">
    {toc_html}
    <div id="kpis" class="kpis">
      <div class="kpi"><div class="label">Detections</div><div class="value">{len(dets)}</div></div>
      <div class="kpi"><div class="label">Chunk Model</div><div class="value">{_html.escape(cfg.chunk_model)}</div></div>
      <div class="kpi"><div class="label">Final Model</div><div class="value">{_html.escape(cfg.final_model)}</div></div>
      <div class="kpi"><div class="label">Two-Pass</div><div class="value">{"Yes" if cfg.two_pass else "No"}</div></div>
      <div class="kpi"><div class="label">Integrity</div><div class="value">{"ON" if cfg.integrity else "OFF"}</div></div>
      <div class="kpi"><div class="label">Max Fidelity</div><div class="value">{"ON" if cfg.max_fidelity else "OFF"}</div></div>
    </div>

    {heat_html}
    {charts_html}

    <div id="exec" class="section">
      <h2>Executive & Findings</h2>
      <pre>{body_html}</pre>
    </div>

    <div class="footer">
      {branding}
      <div>{_html.escape(outname)}</div>
    </div>
  </div>
"""

    # Build JS safely outside f-string to avoid `{}` parsing issues
    script_data = (
        "  // datasets from Python\n"
        + f"  const COUNTS = {json.dumps(counts)};\n"
        + f"  const PHASE_DATA = {json.dumps(sorted(phase_buckets.items(), key=lambda x: -x[1]))};\n"
        + f"  const EID_DATA   = {json.dumps(top_eids)};\n"
        + f"  const DAY_DATA   = {json.dumps(by_day)};\n"
    )
    script_tail = """
  // heatmap (responsive)
  (function(){
    const c = document.getElementById('heatmap');
    if (!c) return;
    const ctx = c.getContext('2d');
    function draw(){
      const dpr = window.devicePixelRatio || 1;
      const rect = c.getBoundingClientRect();
      c.width = Math.floor(rect.width * dpr);
      c.height = Math.floor(rect.width * 0.085 * dpr);
      ctx.setTransform(dpr,0,0,dpr,0,0);
      renderHeatmap('heatmap', COUNTS);
    }
    window.addEventListener('resize', draw); draw();
  })();

  // donuts + legends
  (function(){
    function asPairs(x){ return x || []; }
    const d1 = document.getElementById('donut_phase');
    if (d1) { d1.__redraw = ()=> drawDonut('donut_phase', asPairs(PHASE_DATA), 'By Phase', 'legend_phase'); d1.__redraw(); }
    const d2 = document.getElementById('donut_eid');
    if (d2) { d2.__redraw = ()=> drawDonut('donut_eid', asPairs(EID_DATA), 'Event IDs', 'legend_eid'); d2.__redraw(); }
    const d3 = document.getElementById('donut_day');
    if (d3) { d3.__redraw = ()=> drawDonut('donut_day', asPairs(DAY_DATA), 'Detections per Day', 'legend_day'); d3.__redraw(); }
  })();
"""
    script_block = (
        "<script>\n"
        + HEATMAP_JS
        + "\n"
        + DONUT_JS
        + "\n"
        + script_data
        + script_tail
        + "\n</script>\n"
    )

    html += script_block + "</body>\n</html>\n"
    return html


# ────────────────────────────────────────────────────────────────────────────
# Cost & Logging & Archiving
# ────────────────────────────────────────────────────────────────────────────
def cost_breakdown(usage: Dict[str, Tuple[int, int]]) -> Tuple[float, List[str]]:
    total = 0.0
    lines: List[str] = []
    for m, (ti, to) in usage.items():
        p = PRICING.get(m, {"in": 0.0, "out": 0.0})
        c = (ti / 1000.0) * p["in"] + (to / 1000.0) * p["out"]
        total += c
        lines.append(f"- {m}: in={ti}, out={to} → ${c:.6f} (in {p['in']}/k, out {p['out']}/k)")
    return round(total, 6), lines


def write_run_log(csv_path: Path, row: Dict[str, Any]):
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []
    if csv_path.exists():
        with csv_path.open("r", newline="", encoding="utf-8") as f:
            rows.extend(csv.DictReader(f))
    rows.append(row)
    rows.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "detections",
                "runtime_sec",
                "cost_usd",
                "integrity",
                "chunk_model",
                "final_model",
            ],
        )
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    tbl = Table(title="Recent ForenSynth Runs (latest 5)", box=box.SIMPLE_HEAVY)
    for h in [
        "timestamp",
        "detections",
        "runtime_sec",
        "cost_usd",
        "integrity",
        "chunk_model",
        "final_model",
    ]:
        tbl.add_column(h)
    for r in rows[:5]:
        tbl.add_row(
            r.get("timestamp", ""),
            str(r.get("detections", "")),
            str(r.get("runtime_sec", "")),
            str(r.get("cost_usd", "")),
            r.get("integrity", ""),
            r.get("chunk_model", ""),
            r.get("final_model", ""),
        )
    console.print(tbl)


def archive_old_reports(base_dir: Path, keep_day: str):
    archive_dir = base_dir / "archive" / keep_day
    archive_dir.mkdir(parents=True, exist_ok=True)
    for p in list(base_dir.iterdir()):
        if p.name == "archive":
            continue
        if p.is_dir() and p.name.startswith(keep_day):
            continue
        if p.is_dir():
            shutil.move(str(p), archive_dir / p.name)
        elif p.is_file() and (p.suffix in {".html", ".md", ".pdf"}):
            shutil.move(str(p), archive_dir / p.name)


# ────────────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────────────
def main():
    cfg = parse_args()
    if cfg.run_tests:
        return _run_tests()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        die("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)

    if cfg.integrity:
        console.print(
            Panel.fit(
                "🧠 Integrity Mode Active — prioritizing detection accuracy over cost.",
                box=box.ROUNDED,
            )
        )

    console.rule(
        "[bold cyan]🧠 ForenSynth AI — DFIR Intelligence Engine v2.3.3 (Visual Refresh)[/bold cyan]"
    )
    if not cfg.branding:
        console.print(Panel.fit("Clean Report Mode — no branding footer added.", box=box.ROUNDED))

    start = time.time()

    # Prepare run folder
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%SZ")
    outdir = cfg.outdir / stamp
    outdir.mkdir(parents=True, exist_ok=True)

    # Resolve source & run Chainsaw
    kind, src = select_source(cfg.evtx_root, cfg.scope, cfg.prefer)
    ensure_chainsaw()
    ensure_paths(cfg.rules, cfg.mapping)
    det_json = run_chainsaw(kind, src, cfg.rules, cfg.mapping, outdir)

    # Load detections
    dets = load_detections(det_json)
    count = len(dets)
    ok(f"Detections loaded: {count}")

    # Optional post-hunt sampling to bound time/cost for PoC runs
    dets = apply_sampling(dets, limit=cfg.limit_detections, step=cfg.sample_step, sort_time=False)

    # Build simple evidence from detections
    evd = {
        "detections": count,
        "timeframe": {
            "first": next((d.get("timestamp") for d in dets if d.get("timestamp")), None),
            "last": next((d.get("timestamp") for d in reversed(dets) if d.get("timestamp")), None),
        },
        "top": {
            "event_ids": [],
            "tags": [],
        },
        "counts": {},
        "iocs": {},
    }
    eid_ctr = Counter()
    tag_ctr = Counter()
    for d in dets:
        eid = _extract_event_id(d)
        if eid:
            eid_ctr[eid] += 1
        for t in _extract_tags(d):
            tag_ctr[t] += 1
    evd["top"]["event_ids"] = [[k, v] for k, v in eid_ctr.most_common(10)]
    evd["top"]["tags"] = [[k, v] for k, v in tag_ctr.most_common(20)]

    (outdir / "evidence.json").write_text(json.dumps(evd, indent=2), encoding="utf-8")
    ok("Evidence written: evidence.json")
    if cfg.export_evidence_csv:
        write_evidence_csvs(evd, outdir)
        ok("Evidence CSVs written: evidence_csv/*.csv")

    if count == 0:
        warn("No Sigma detections found — skipping summarization to save tokens.")
        md_path = outdir / f"forensynth_summary_{stamp.split('_')[0]}.md"
        md_path.write_text("# No detections — nothing to summarize.\n", encoding="utf-8")
        if cfg.make_html:
            html = build_html(
                "# No detections — nothing to summarize.\n", [], cfg, md_path.name, evd=evd
            )
            html_path = outdir / f"forensynth_report_{stamp.split('_')[0]}.html"
            html_path.write_text(html, encoding="utf-8")
            ok(f"Report written: {html_path}")
        write_run_log(
            cfg.outdir / "run_log.csv",
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "detections": 0,
                "runtime_sec": int(time.time() - start),
                "cost_usd": f"{0.0:.6f}",
                "integrity": "on" if cfg.integrity else "off",
                "chunk_model": cfg.chunk_model,
                "final_model": cfg.final_model,
            },
        )
        archive_old_reports(cfg.outdir, keep_day=stamp.split("_")[0])
        return

    # Summarize
    if cfg.two_pass:
        md_final, usage = two_pass(client, dets, cfg)
    else:
        blocks = dynamic_chunks(dets, cfg.chunk_size, cfg.max_input_tokens)
        flat = [d for b in blocks for d in b]
        user = build_micro_prompt(flat)
        base_in = est_tokens(SYSTEM_FINAL)
        while base_in + est_tokens(user) > cfg.max_input_tokens:
            parts = user.splitlines()
            if len(parts) <= 10:
                break
            user = "\n".join(parts[:-10])
        final_text = ""
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]Final Merge[/bold]"),
            BarColumn(bar_width=None),
            TimeElapsedColumn(),
        ) as prog:
            task = prog.add_task("final", total=None)
            final_text = call_llm(
                client,
                cfg.final_model,
                SYSTEM_FINAL,
                user,
                cfg.temperature,
                cfg.llm_timeout,
                cfg.llm_retries,
                stream=cfg.stream,
            )
            prog.update(task, completed=True)

        usage = {cfg.final_model: (base_in + est_tokens(user), est_tokens(final_text))}
        md_final = (
            "# 🔍 ForenSynth AI — DFIR Summary (Single-Pass)\n\n"
            f"- Generated: {datetime.now(timezone.utc).isoformat()}\n"
            f"- Final model: `{cfg.final_model}`\n\n"
            "## Final Executive Report\n\n" + final_text
        )

    # Output
    md_path = outdir / f"forensynth_summary_{stamp.split('_')[0]}.md"
    md_path.write_text(md_final, encoding="utf-8")
    html_path = None
    if cfg.make_html:
        html = build_html(md_final, dets, cfg, md_path.name, evd=evd)
        html_path = outdir / f"forensynth_report_{stamp.split('_')[0]}.html"
        html_path.write_text(html, encoding="utf-8")
        ok(f"Report written: {html_path}")

    if cfg.make_pdf and pypandoc is not None:
        try:
            pdf_path = outdir / f"forensynth_report_{stamp.split('_')[0]}.pdf"
            pypandoc.convert_text(html, to="pdf", format="html", outputfile=str(pdf_path))  # type: ignore
            ok(f"PDF written: {pdf_path}")
        except Exception as e:
            info(f"PDF generation failed/skipped: {e}")

    archive_old_reports(cfg.outdir, keep_day=stamp.split("_")[0])

    runtime = int(time.time() - start)
    total_cost, lines = cost_breakdown(usage)

    write_run_log(
        cfg.outdir / "run_log.csv",
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detections": count,
            "runtime_sec": runtime,
            "cost_usd": f"{total_cost:.6f}",
            "integrity": "on" if cfg.integrity else "off",
            "chunk_model": cfg.chunk_model,
            "final_model": cfg.final_model,
        },
    )

    console.rule("[bold]Cost Breakdown[/bold]")
    for ln in lines:
        console.print(ln)
    console.print(f"Total cost: ${total_cost:.6f}")

    console.print(
        Panel.fit(
            f"[white on dodger_blue2]  Runtime Summary  [/white on dodger_blue2]\n"
            f"Processed {count} detections in {runtime}s | Output: {md_path.name}"
            + (f" | HTML: {html_path.name}" if html_path else ""),
            box=box.ROUNDED,
        )
    )


# ────────────────────────────────────────────────────────────────────────────
# Basic Tests (unit-style)
# ────────────────────────────────────────────────────────────────────────────
def _fake_det(ts: str, name: str, eid: str, tags: List[str], script: str = "") -> Dict[str, Any]:
    return {
        "timestamp": ts,
        "name": name,
        "tags": tags,
        "document": {
            "data": {
                "Event": {"System": {"EventID": eid}, "EventData": {"ScriptBlockText": script}}
            }
        },
    }


def _run_tests():
    import unittest

    class TokenGuardTests(unittest.TestCase):
        def test_dynamic_chunks_guard(self):
            dets = [
                _fake_det(
                    "2024-01-01T00:00:00Z",
                    f"Rule T1059.{i % 3}",
                    "4688",
                    ["high", "execution"],
                    "A" * 400,
                )
                for i in range(200)
            ]
            blocks = dynamic_chunks(dets, base_size=50, max_input_tokens=6000)
            total = 0
            for b in blocks:
                total += est_tokens(SYSTEM_MICRO) + est_tokens(build_micro_prompt(b))
            self.assertLessEqual(total, 6000)
            self.assertGreater(len(blocks), 1)

    class HtmlEscapeTests(unittest.TestCase):
        def test_html_escape(self):
            malicious = "# Title\n<script>alert('x')</script>"
            html = build_html(
                malicious,
                [],
                AppConfig(
                    evtx_root=Path("."),
                    scope="dir",
                    prefer=[],
                    rules=Path("."),
                    mapping=Path("."),
                    sigma_root=None,
                    outdir=Path("."),
                    two_pass=True,
                    make_html=True,
                    make_pdf=False,
                    toc=False,
                    branding=False,
                    fast=False,
                    stream=False,
                    integrity=False,
                    run_tests=False,
                    max_fidelity=True,
                    chunk_model="gpt-5-mini",
                    final_model="gpt-5",
                    llm_timeout=30,
                    llm_retries=3,
                    temperature=1.0,
                    max_input_tokens=8000,
                    chunk_size=25,
                    max_chunks=20,
                    micro_workers=1,
                    rpm=0,
                    export_evidence_csv=False,
                    chart_style="both",
                ),
                "out.md",
            )
            self.assertNotIn("<script>", html)
            self.assertIn("&lt;script&gt;", html)

    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TokenGuardTests))
    suite.addTest(unittest.makeSuite(HtmlEscapeTests))
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    if not res.wasSuccessful():
        sys.exit(1)
    ok("All tests passed.")


# ────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("Interrupted by user")
