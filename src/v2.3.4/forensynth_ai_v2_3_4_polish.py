#!/usr/bin/env python3
# ForenSynth AI v2.3.4 (Polish)
# DFIR Intelligence Engine — Chainsaw+Sigma -> LLM micro-summaries -> executive report
# Features:
# - Secure .env load + explicit OpenAI(api_key=...)
# - Accurate billing via resp.usage (non-streaming for LLM calls)
# - RPM throttle + micro parallel
# - Sampling flags for POC speed
# - HTML visuals: heatmap + 3 donuts (Phase/EID/Day) + legend/counts + footnotes
# - Billing Summary injected into HTML
# - Optional: Evidence CSV export

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
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Optional vendor libs
try:
    import tiktoken  # type: ignore
except Exception:
    tiktoken = None

try:
    import pypandoc  # type: ignore
except Exception:
    pypandoc = None

# OpenAI SDK
from openai import OpenAI
from openai import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    BadRequestError,
    RateLimitError,
)

# Pretty console (rich)
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

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

EVENT_WEIGHTS = {
    "1": 1.2, "3": 1.3, "7": 1.1, "8": 1.1, "10": 1.4, "11": 1.1, "4624": 1.1, "4625": 1.1,
    "4688": 1.6, "4697": 1.4, "4720": 1.5, "4728": 1.3, "4732": 1.3, "7045": 1.5,
}
SEVERITY_TAG_BOOSTS = {
    "critical": 2.0, "high": 1.6, "medium": 1.3, "suspicious": 1.2,
    "credential": 1.3, "persistence": 1.4, "lateral": 1.4, "exfil": 1.6, "ransom": 1.8,
}

# ─────────────────────────────────────────────────────────────────────────────
# Secure dotenv load
# ─────────────────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv  # type: ignore
except Exception:
    load_dotenv = None  # optional

def _ok_perms(path: Path) -> bool:
    try:
        st = path.stat()
    except Exception:
        return False
    world_writable = bool(st.st_mode & stat.S_IWOTH)
    world_readable = bool(st.st_mode & stat.S_IROTH)
    return not (world_writable or world_readable)

def _safe_load_dotenv():
    if not load_dotenv:
        return
    for p in (Path.cwd() / ".env", Path.home() / ".env"):
        if p.exists() and _ok_perms(p):
            load_dotenv(p, override=False)

_safe_load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# CLI & App State
# ─────────────────────────────────────────────────────────────────────────────
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

def parse_args() -> AppConfig:
    p = argparse.ArgumentParser(description="ForenSynth AI v2.3.4 (Polish)")
    p.add_argument("--evtx-root", type=Path, default=Path("/mnt/evtx_share/DFIR-Lab-Logs"))
    p.add_argument("--scope", choices=["dir", "file"], default="dir")
    p.add_argument("--prefer", default="PowerShell-Operational.evtx,Security.evtx")
    p.add_argument("--rules", type=Path, default=Path.home()/"tools"/"sigma"/"rules")
    p.add_argument("--mapping", type=Path, default=Path.home()/"tools"/"chainsaw"/"sigma-event-logs-all.yml")
    p.add_argument("--sigma-root", type=Path, default=None)
    p.add_argument("--outdir", type=Path, default=Path.home()/"DFIR-Labs"/"ForenSynth"/"Reports")

    p.add_argument("--two-pass", action="store_true")
    p.add_argument("--make-html", action="store_true")
    p.add_argument("--make-pdf", action="store_true")
    p.add_argument("--toc", choices=["on", "off"], default="off")
    p.add_argument("--branding", choices=["on", "off"], default="on")
    p.add_argument("--fast", action="store_true")
    p.add_argument("--stream", choices=["on", "off"], default="off")
    p.add_argument("--integrity", choices=["on", "off"], default="off")
    p.add_argument("--run-tests", action="store_true")

    p.add_argument("--chunk-model", default=DEFAULT_CHUNK_MODEL)
    p.add_argument("--final-model", default=DEFAULT_FINAL_MODEL)
    p.add_argument("--llm-timeout", type=int, default=60)
    p.add_argument("--llm-retries", type=int, default=6)
    p.add_argument("--temperature", type=float, default=1.0)
    p.add_argument("--max-input-tokens", type=int, default=120_000)
    p.add_argument("--chunk-size", type=int, default=25)
    p.add_argument("--max-chunks", type=int, default=120)

    p.add_argument("--micro-workers", type=int, default=0, help="0=auto")
    p.add_argument("--rpm", type=int, default=0, help="Rate limit per-minute across micro jobs (0=off)")

    # POC sampling + CSV
    p.add_argument("--limit-detections", type=int, default=0, help="If >0, cap detections to this many after sampling")
    p.add_argument("--sample-step", type=int, default=0, help="If >0, keep every Nth detection (stratified sample)")
    p.add_argument("--export-evidence-csv", action="store_true")

    a = p.parse_args()
    prefer = [s.strip() for s in a.prefer.split(",") if s.strip()]

    # Auto workers
    workers = a.micro_workers
    if workers <= 0:
        cpu = os.cpu_count() or 2
        workers = min(max(2, cpu), 8) if a.fast else max(1, min(cpu, 4))

    # Integrity → lock models
    chunk_model = a.chunk_model
    final_model = a.final_model
    if a.integrity == "on":
        chunk_model = "gpt-5-mini"
        final_model = "gpt-5"

    return AppConfig(
        evtx_root=a.evtx_root, scope=a.scope, prefer=prefer,
        rules=a.rules, mapping=a.mapping, sigma_root=a.sigma_root, outdir=a.outdir,
        two_pass=a.two_pass, make_html=a.make_html, make_pdf=a.make_pdf,
        toc=(a.toc == "on"), branding=(a.branding == "on"), fast=a.fast,
        stream=(a.stream == "on"), integrity=(a.integrity == "on"), run_tests=a.run_tests,
        chunk_model=chunk_model, final_model=final_model,
        llm_timeout=a.llm_timeout, llm_retries=a.llm_retries, temperature=a.temperature,
        max_input_tokens=max(4000, a.max_input_tokens),
        chunk_size=max(1, a.chunk_size), max_chunks=max(1, a.max_chunks),
        micro_workers=workers, rpm=max(0, a.rpm),
        limit_detections=max(0, a.limit_detections),
        sample_step=max(0, a.sample_step),
        export_evidence_csv=a.export_evidence_csv,
    )

# ─────────────────────────────────────────────────────────────────────────────
# Console helpers
# ─────────────────────────────────────────────────────────────────────────────
def ok(msg: str):   console.print(Panel.fit(f"[green]✔ {msg}[/green]", box=box.ROUNDED))
def info(msg: str): console.print(Panel.fit(f"[yellow]⚙ {msg}[/yellow]", box=box.ROUNDED))
def warn(msg: str): console.print(Panel.fit(f"[yellow]⚠ {msg}[/yellow]", box=box.ROUNDED))
def die(msg: str):
    console.print(Panel.fit(f"[red]✘ {msg}[/red]", box=box.ROUNDED))
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Chainsaw integration
# ─────────────────────────────────────────────────────────────────────────────
def latest_container(root: Path) -> Path:
    if not root.exists(): die(f"EVTX root not found: {root}")
    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs: die(f"No subfolders under {root}")
    return max(dirs, key=lambda p: p.stat().st_mtime)

def select_source(root: Path, scope: str, prefer: List[str]) -> Tuple[str, Path]:
    folder = latest_container(root)
    console.print(Panel.fit(f"[cyan]✔ Using latest EVTX directory:[/cyan] {folder}", box=box.ROUNDED))
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
    if not rules.exists():  die(f"Sigma rules path not found: {rules}")
    if not mapping.exists(): die(f"Chainsaw mapping not found: {mapping}")

def run_chainsaw(kind: str, src: Path, rules: Path, mapping: Path, outdir: Path) -> Path:
    info("Running Chainsaw hunt…")
    console.print("\n[italic]🪓 Chainsaw Module Active — Sigma Hunt in Progress…[/italic]\n")
    out_path = outdir / "detections.json"
    outdir.mkdir(parents=True, exist_ok=True)

    sigma_root = str((rules.parent if rules.name.lower() == "rules" else rules).resolve())
    cmd = [
        "chainsaw", "hunt", str(src),
        "--mapping", str(mapping),
        "--rule", str(rules),
        "-s", sigma_root,
        "--json", "--output", str(out_path)
    ]
    with Progress(SpinnerColumn(), TextColumn("[bold]Hunting[/bold]"), BarColumn(), TimeElapsedColumn()) as prog:
        task = prog.add_task("hunt", total=None)
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            die(f"Chainsaw failed: {e}")
        finally:
            prog.update(task, completed=True)
    ok("Chainsaw hunt completed. Parsing detections…")
    return out_path

# ─────────────────────────────────────────────────────────────────────────────
# Load detections
# ─────────────────────────────────────────────────────────────────────────────
def load_detections(path: Path) -> List[Dict[str, Any]]:
    if not path.exists(): die(f"Detections file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for ln in text.splitlines():
            ln = ln.strip()
            if ln:
                try: data.append(json.loads(ln))
                except json.JSONDecodeError: pass
    if isinstance(data, dict) and "detections" in data:
        detections = data["detections"]
    elif isinstance(data, list):
        detections = data
    else:
        die("Unexpected detections JSON shape")
    return detections

# ─────────────────────────────────────────────────────────────────────────────
# Token estimation
# ─────────────────────────────────────────────────────────────────────────────
def est_tokens(s: str, model_hint: str = "gpt-4o") -> int:
    if tiktoken:
        try:
            enc = tiktoken.encoding_for_model(model_hint)
        except Exception:
            enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(s))
    return max(1, math.ceil(len(s) / 4))

# ─────────────────────────────────────────────────────────────────────────────
# Scoring (smarter selection)
# ─────────────────────────────────────────────────────────────────────────────
def _extract_event_id(det: Dict[str, Any]) -> str:
    try:
        return str((((det.get("document") or {}).get("data") or {}).get("Event") or {}).get("System", {}).get("EventID", ""))
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

    script = ((((det.get("document") or {}).get("data") or {}).get("Event") or {}).get("EventData") or {}).get("ScriptBlockText", "")
    script_bonus = 1.0 + min(0.5, len(script) / 2000.0)

    return 1.0 * mitre_bonus * sev * eid_w * rarity * script_bonus

def score_micro_block(block: List[Dict[str, Any]], rule_freq: Dict[str, int]) -> float:
    if not block:
        return 0.0
    scores = sorted((score_detection(d, rule_freq) for d in block), reverse=True)
    base = sum(scores[:min(5, len(scores))])
    uniq_rules = len({d.get("name") or (d.get("rule", {}) or {}).get("title") for d in block})
    diversity = 1.0 + min(0.5, (uniq_rules / max(1, len(block))) * 0.5)
    return base * diversity

# ─────────────────────────────────────────────────────────────────────────────
# Prompt builders
# ─────────────────────────────────────────────────────────────────────────────
def fmt_micro_line(det: Dict[str, Any], include_snip: bool = True, snip_len: int = 160) -> str:
    ts = det.get("timestamp", "N/A")
    rule = det.get("name", (det.get("rule", {}) or {}).get("title", "N/A"))
    tags = ", ".join(_extract_tags(det)) or "None"
    eid = _extract_event_id(det) or "N/A"
    script = ((((det.get("document") or {}).get("data") or {}).get("Event") or {}).get("EventData") or {}).get("ScriptBlockText", "")
    snip = (script[:snip_len] + ("…" if len(script) > snip_len else "")) if (include_snip and script) else ""
    line = f"- [{ts}] {rule} (EventID {eid}; Tags: {tags})"
    if snip: line += f" | snippet: {snip}"
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

# ─────────────────────────────────────────────────────────────────────────────
# LLM call (accurate billing)
# ─────────────────────────────────────────────────────────────────────────────
def backoff_sleep(i: int):
    time.sleep(min(30.0, (1.6 ** i) + random.uniform(0, 0.25)))

def call_llm(client: OpenAI, model: str, system_prompt: str, user_prompt: str,
             temperature: float, timeout_s: int, retries: int, stream: bool = False) -> Tuple[str, int, int]:
    if stream:
        stream = False  # accurate billing requires usage fields

    send_temp = None if abs(temperature - 1.0) < 1e-6 or model.startswith("gpt-5") else float(temperature)
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

            resp = client.chat.completions.create(**payload, timeout=timeout_s)
            text = resp.choices[0].message.content or ""
            u = getattr(resp, "usage", None)
            ptk = int(getattr(u, "prompt_tokens", 0) or 0)
            ctk = int(getattr(u, "completion_tokens", 0) or 0)
            return text, ptk, ctk

        except BadRequestError as e:
            msg = str(e)
            if "temperature" in msg.lower():
                send_temp = None
                last_err = e
                continue
            raise
        except (RateLimitError, APITimeoutError, APIConnectionError, APIError) as e:
            last_err = e
            backoff_sleep(i)
            continue
    raise RuntimeError(f"LLM retries exceeded: {last_err}")

# ─────────────────────────────────────────────────────────────────────────────
# Chunking / sampling
# ─────────────────────────────────────────────────────────────────────────────
def chunk(lst: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(lst), size):
        yield lst[i : i + size]

def dynamic_chunks(dets: List[Dict[str, Any]], base_size: int, max_input_tokens: int) -> List[List[Dict[str, Any]]]:
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

def apply_sampling(dets: List[Dict[str, Any]], limit: int, step: int) -> List[Dict[str, Any]]:
    if step > 1:
        # take every Nth to stratify
        dets = [v for i, v in enumerate(dets) if i % step == 0]
    if limit > 0 and len(dets) > limit:
        dets = dets[:limit]
    return dets

# ─────────────────────────────────────────────────────────────────────────────
# Micro parallel + selection
# ─────────────────────────────────────────────────────────────────────────────
def micro_parallel(client: OpenAI, blocks: List[List[Dict[str, Any]]], cfg: AppConfig) -> Tuple[List[str], Tuple[int,int]]:
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
        throttle()
        out, ptk, ctk = call_llm(
            client, cfg.chunk_model, SYSTEM_MICRO, user,
            cfg.temperature, cfg.llm_timeout, cfg.llm_retries, stream=False
        )
        return i, out, ptk, ctk

    with Progress(SpinnerColumn(), TextColumn("[bold]Micro[/bold]"), BarColumn(), TextColumn("[progress.completed]/[progress.total]"), TimeElapsedColumn()) as prog:
        task = prog.add_task("micro", total=len(blocks))
        with ThreadPoolExecutor(max_workers=cfg.micro_workers) as ex:
            futs = [ex.submit(work, i, b) for i, b in enumerate(blocks)]
            for f in as_completed(futs):
                i, out, ptk, ctk = f.result()
                micros[i] = f"## Micro {i+1}: Cluster Summary\n\n" + out
                usage_in += ptk
                usage_out += ctk
                prog.update(task, advance=1)
    return micros, (usage_in, usage_out)

def select_best_micros(blocks: List[List[Dict[str, Any]]], micros: List[str], max_tokens: int, cap_count: int = 20) -> List[str]:
    # Rule frequency for rarity/diversity scoring
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
        if len(selected) >= cap_count:
            break
        cost = est_tokens(m)
        if budget + cost <= max_tokens:
            selected.append(m)
            budget += cost
    if not selected and micros:
        allowed = max(1000, max_tokens - est_tokens(SYSTEM_FINAL))
        selected = [micros[0][: allowed * 4]]
    return selected

# ─────────────────────────────────────────────────────────────────────────────
# Visual helpers
# ─────────────────────────────────────────────────────────────────────────────
def build_heatmap_counts(dets: List[Dict[str, Any]]) -> List[int]:
    buckets = [0] * 24
    for d in dets:
        ts = d.get("timestamp")
        if not ts: continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z","+00:00") if ts.endswith("Z") else ts)
            hr = dt.astimezone(timezone.utc).hour
            buckets[hr] += 1
        except Exception:
            continue
    return buckets

def compute_eventid_counts(dets: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    def _eid(d):
        try:
            return str((((d.get("document") or {}).get("data") or {}).get("Event") or {}).get("System", {}).get("EventID", ""))
        except Exception:
            return ""
    for d in dets:
        e = _eid(d) or "?"
        out[e] = out.get(e, 0) + 1
    return out

_PHASE_KEYS = {
    "execution": "Execution",
    "persistence": "Persistence",
    "credential": "Credentials",
    "lateral": "Lateral Movement",
    "discovery": "Discovery",
    "defense": "Defense Evasion",
    "exfil": "Exfiltration",
    "c2": "Command & Control",
}

def compute_phase_counts(dets: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {v: 0 for v in _PHASE_KEYS.values()}
    out["Unmapped/Multiple"] = 0

    def _tags(d):
        t = d.get("tags", []) or []
        if isinstance(t, str): t = [t]
        return [x.lower() for x in t]

    def _name(d):
        return (d.get("name") or (d.get("rule", {}) or {}).get("title") or "").lower()

    for d in dets:
        tags = _tags(d)
        title = _name(d)
        hits = set()
        for k, v in _PHASE_KEYS.items():
            if any(k in s for s in tags) or k in title:
                hits.add(v)
        if not hits or len(hits) > 1:
            out["Unmapped/Multiple"] += 1
        else:
            out[hits.pop()] += 1
    return out

def counts_by_day(dets: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for d in dets:
        ts = d.get("timestamp")
        if not ts: 
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z","+00:00") if ts.endswith("Z") else ts)
            key = dt.astimezone(timezone.utc).strftime("%Y-%m-%d")
            out[key] = out.get(key, 0) + 1
        except Exception:
            continue
    return out

# Inline CSS (base + polish addendum)
INLINE_CSS = f"""
:root {{ --fg:#0e1628; --muted:#66728a; --bg:#ffffff; --edge:#eef2f8; --accent:{DFIR_BLUE}; }}
html,body {{ margin:0; padding:0; }}
body {{ color:var(--fg); background:var(--bg); font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial; }}
.header {{ padding:24px 24px 8px; border-bottom:1px solid var(--edge); }}
.h1 {{ font-size:28px; font-weight:800; margin:0 0 4px; }}
.sub {{ color:var(--muted); font-size:14px; }}
.container {{ max-width:1024px; margin:0 auto; padding:0 24px 48px; }}
.toc {{ margin:16px 0 24px; padding:12px; background:#f6f9ff; border:1px solid var(--edge); border-radius:8px; }}
.section h2 {{ font-size:20px; margin-top:28px; border-bottom:1px solid var(--edge); padding-bottom:4px; }}
pre, code {{ background:#f7f9fc; border:1px solid var(--edge); border-radius:6px; }}
pre {{ padding:12px; overflow:auto; }}
.footer {{ margin-top:36px; padding:16px; border-top:1px solid var(--edge); font-size:13px; color:var(--muted); display:flex; justify-content:space-between; align-items:center; }}
.brand {{ opacity:0.85; }}
.strip {{ margin-top:18px; height:8px; background: linear-gradient(90deg, #d6e6ff 0%, {DFIR_BLUE} 50%, #001A72 100%); border-radius:4px; }}
.kpis {{ display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:12px; margin:16px 0; }}
.kpi {{ background:#f7faff; border:1px solid var(--edge); border-radius:10px; padding:12px; }}
.kpi .label {{ color:var(--muted); font-size:12px; }}
.kpi .value {{ font-size:18px; font-weight:700; }}
.canvas-wrap {{ margin:12px 0 0; border:1px solid var(--edge); border-radius:8px; padding:8px; }}
.note {{ color:var(--muted); font-size:12px; margin-top:6px; }}
"""
INLINE_CSS_POLISH = r"""
.legend { margin-top:10px; display:grid; grid-template-columns:1fr; gap:4px; font-size:13px; color:#333; }
.legend .row { display:flex; align-items:center; gap:8px; }
.legend .swatch { width:10px; height:10px; border-radius:50%; display:inline-block; border:1px solid #ccd; }
.caption { color:#66728a; font-size:12px; margin-top:6px; }
.footnote { color:#66728a; font-size:12px; margin-top:6px; }
.charts { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:16px; margin:16px 0 4px; }
.card { background:#f7faff; border:1px solid #eef2f8; border-radius:10px; padding:12px; }
.card h3 { margin:0 0 8px; font-size:16px; }
"""

# JS helpers as raw strings (avoid f-string brace issues)
HEATMAP_JS = r"""
function renderHeatmap(canvasId, counts) {
  var canvas = document.getElementById(canvasId);
  if(!canvas) return;
  var ctx = canvas.getContext('2d');
  var w = canvas.width, h = canvas.height;
  var cols = 24, rows = 1, pad = 8;
  var cw = (w - pad*2) / cols;
  var ch = (h - pad*2) / rows;
  var max = 1;
  for (var i=0;i<counts.length;i++) if(counts[i]>max) max=counts[i];

  ctx.clearRect(0,0,w,h);
  ctx.font = '12px system-ui, -apple-system, Segoe UI, Roboto, Arial';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';

  for (var c=0; c<cols; c++) {
    var val = counts[c] || 0;
    var t = Math.sqrt(val / max);
    var r = Math.floor(214 - 120*t);
    var g = Math.floor(230 - 110*t);
    var b = Math.floor(255 - 140*t);
    ctx.fillStyle = 'rgb('+r+','+g+','+b+')';
    var x = pad + c*cw;
    var y = pad;
    ctx.fillRect(x, y, cw-2, ch);
    if (c % 3 === 0) {
      ctx.fillStyle = '#66728a';
      ctx.fillText(String(c).padStart(2,'0'), x+cw/2, y+ch+2);
    }
  }

  canvas.addEventListener('mousemove', function(e){
    var rect = canvas.getBoundingClientRect();
    var mx = e.clientX - rect.left - pad;
    if (mx < 0 || mx > (w-pad*2)) { canvas.title=''; return; }
    var c = Math.min(23, Math.max(0, Math.floor(mx / ((w-pad*2)/cols))));
    canvas.title = String(c).padStart(2,'0') + ':00 — ' + (counts[c]||0) + ' detections';
  });
}
"""

DONUT_JS = r"""
function renderDonut(canvasId, data, colors) {
  var canvas = document.getElementById(canvasId);
  if(!canvas) return;
  var ctx = canvas.getContext('2d');
  var w = canvas.width, h = canvas.height;
  var cx = w/2, cy = h/2, r = Math.min(w,h)/2 - 6;
  var total = 0;
  var keys = Object.keys(data);
  for (var i=0;i<keys.length;i++){ total += data[keys[i]]; }
  if (total === 0){
    ctx.clearRect(0,0,w,h);
    ctx.fillStyle = '#66728a';
    ctx.textAlign='center'; ctx.textBaseline='middle';
    ctx.fillText('No data', cx, cy);
    return;
  }
  var start = -Math.PI/2;
  for (var i=0;i<keys.length;i++){
    var k = keys[i], v = data[k];
    var a = (v/total) * Math.PI*2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, start, start+a, false);
    ctx.closePath();
    ctx.fillStyle = colors[i % colors.length];
    ctx.fill();
    start += a;
  }
  ctx.globalCompositeOperation = 'destination-out';
  ctx.beginPath();
  ctx.arc(cx, cy, r*0.55, 0, Math.PI*2, false);
  ctx.fill();
  ctx.globalCompositeOperation = 'source-over';
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# HTML builder + billing injector
# ─────────────────────────────────────────────────────────────────────────────
def build_html(md_final: str, dets: List[Dict[str, Any]], cfg: AppConfig, outname: str) -> str:
    counts_24 = build_heatmap_counts(dets)
    eid_counts = compute_eventid_counts(dets)
    phase_counts = compute_phase_counts(dets)
    day_counts = counts_by_day(dets)

    def topn_items(d: Dict[str,int], n=8):
        return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]

    donut_colors = [
        "#0a69ff","#154cbd","#1e3d8a","#27405e","#5a7bd7","#98b3ff",
        "#3a9ad9","#7bc8f6","#6aabd2","#3e6bb8"
    ]

    body_html = _html.escape(md_final)

    eid_foot = ("EventID 1 = Sysmon Process Create; 13 = Registry value write; "
                "4104 = PowerShell ScriptBlock; 4688 = Process Creation (Security).")
    heat_caption = "Activity by hour (UTC). Hover cells for exact counts."

    css = INLINE_CSS + INLINE_CSS_POLISH

    def legend_html(items):
        rows = []
        for idx,(k,v) in enumerate(items):
            sw = f'<span class="swatch" style="background:{donut_colors[idx % len(donut_colors)]}"></span>'
            rows.append(f'<div class="row">{sw}<span>{_html.escape(str(k))}: <strong>{v}</strong></span></div>')
        return '<div class="legend">' + "".join(rows) + '</div>'

    import json as _json
    js_phase = _json.dumps(phase_counts)
    js_eid   = _json.dumps(dict(topn_items(eid_counts, n=8)))
    js_day   = _json.dumps(day_counts)
    js_counts= _json.dumps(counts_24)
    js_colors= _json.dumps(donut_colors)

    toc_html = (
        '<div class="toc"><strong>Contents</strong><ul>'
        '<li><a href="#kpis">Key Metrics</a></li>'
        '<li><a href="#heat">Detection Heatmap</a></li>'
        '<li><a href="#viz">At a Glance</a></li>'
        '<li><a href="#exec">Executive Report</a></li>'
        '</ul></div>'
    ) if cfg.toc else ""

    branding = '<div class="brand">Powered by <strong>ForenSynth AI\u2122</strong></div>' if cfg.branding else '<div></div>'

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>ForenSynth AI — DFIR Report</title>
<style>{css}</style>
</head>
<body>
  <div class="header">
    <div class="h1">ForenSynth AI — DFIR Report</div>
    <div class="sub">Generated {datetime.now(timezone.utc).isoformat()} | Integrity Mode: {'ON' if cfg.integrity else 'OFF'}</div>
    <div class="strip"></div>
  </div>
  <div class="container">
    {toc_html}
    <div id="kpis" class="kpis">
      <div class="kpi"><div class="label">Detections</div><div class="value">{len(dets)}</div></div>
      <div class="kpi"><div class="label">Chunk Model</div><div class="value">{_html.escape(cfg.chunk_model)}</div></div>
      <div class="kpi"><div class="label">Final Model</div><div class="value">{_html.escape(cfg.final_model)}</div></div>
      <div class="kpi"><div class="label">Two-Pass</div><div class="value">{'Yes' if cfg.two_pass else 'No'}</div></div>
    </div>

    <div id="heat" class="section">
      <h2>Detection Heatmap (UTC, per hour)</h2>
      <div class="canvas-wrap">
        <canvas id="heatmap" width="980" height="84"></canvas>
      </div>
      <div class="caption">{_html.escape(heat_caption)}</div>
      <div class="footnote">{_html.escape(eid_foot)}</div>
    </div>

    <div id="viz" class="section">
      <h2>At a Glance</h2>
      <div class="charts">
        <div class="card">
          <h3>By Phase (MITRE-mapped)</h3>
          <canvas id="donut_phase" width="280" height="180"></canvas>
          {legend_html(topn_items(phase_counts, n=8))}
        </div>
        <div class="card">
          <h3>Top Event IDs</h3>
          <canvas id="donut_eid" width="280" height="180"></canvas>
          {legend_html(topn_items(eid_counts, n=8))}
        </div>
        <div class="card">
          <h3>By Day (UTC)</h3>
          <canvas id="donut_day" width="280" height="180"></canvas>
          {legend_html(topn_items(day_counts, n=8))}
        </div>
      </div>
    </div>

    <div id="exec" class="section">
      <h2>Executive & Findings</h2>
      <pre>{body_html}</pre>
    </div>

    <div class="footer">
      {branding}
      <div>{_html.escape(outname)}</div>
    </div>
  </div>
<script>{HEATMAP_JS}</script>
<script>{DONUT_JS}</script>
<script>
  var COUNTS_24 = {js_counts};
  var DONUT_PHASE = {js_phase};
  var DONUT_EID   = {js_eid};
  var DONUT_DAY   = {js_day};
  var COLORS = {js_colors};
  renderHeatmap('heatmap', COUNTS_24);
  renderDonut('donut_phase', DONUT_PHASE, COLORS);
  renderDonut('donut_eid',   DONUT_EID,   COLORS);
  renderDonut('donut_day',   DONUT_DAY,   COLORS);
</script>
</body>
</html>
"""
    return html

def append_billing_to_html(html_path: Path, lines: List[str]):
    try:
        html = html_path.read_text(encoding="utf-8", errors="ignore")
        billing = "<div class=\"section\"><h2>Billing Summary</h2><ul>" + "".join(
            f"<li>{_html.escape(ln)}</li>" for ln in lines
        ) + "</ul><div class=\"note\">Based on OpenAI usage tokens (prompt/completion) reported by API.</div></div>"
        if "</div>\n</div>\n<script" in html:
            html = html.replace("</div>\n</div>\n<script", billing + "\n</div>\n</div>\n<script", 1)
        else:
            html = html.replace("</body>", billing + "\n</body>", 1)
        html_path.write_text(html, encoding="utf-8")
    except Exception as e:
        info(f"Failed to append billing to HTML: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# Cost & Logging & CSV
# ─────────────────────────────────────────────────────────────────────────────
def cost_breakdown(usage: Dict[str, Tuple[int,int]]) -> Tuple[float, List[str]]:
    total = 0.0
    lines: List[str] = []
    for m, (ti, to) in usage.items():
        p = PRICING.get(m, {"in":0.0, "out":0.0})
        c = (ti/1000.0)*p["in"] + (to/1000.0)*p["out"]
        total += c
        lines.append(f"{m}: prompt={ti} tok, completion={to} tok → ${c:.6f} (in {p['in']}/k, out {p['out']}/k)")
    return round(total,6), lines

def write_run_log(csv_path: Path, row: Dict[str, Any]):
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []
    if csv_path.exists():
        with csv_path.open("r", newline="", encoding="utf-8") as f:
            rows.extend(csv.DictReader(f))
    rows.append(row)
    rows.sort(key=lambda r: r.get("timestamp",""), reverse=True)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp","detections","runtime_sec","cost_usd","integrity","chunk_model","final_model"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    tbl = Table(title="Recent ForenSynth Runs (latest 5)", box=box.SIMPLE_HEAVY)
    for h in ["timestamp","detections","runtime_sec","cost_usd","integrity","chunk_model","final_model"]:
        tbl.add_column(h)
    for r in rows[:5]:
        tbl.add_row(r.get("timestamp",""), str(r.get("detections","")), str(r.get("runtime_sec","")),
                    str(r.get("cost_usd","")), r.get("integrity",""), r.get("chunk_model",""), r.get("final_model",""))
    console.print(tbl)

def export_evidence_csv(evidence_path: Path, dets: List[Dict[str, Any]]):
    try:
        with evidence_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp","rule","event_id","tags","snippet"])
            for d in dets:
                ts = d.get("timestamp","")
                rule = d.get("name") or (d.get("rule",{}) or {}).get("title","")
                eid = _extract_event_id(d)
                tags = ";".join(_extract_tags(d))
                script = ((((d.get("document") or {}).get("data") or {}).get("Event") or {}).get("EventData") or {}).get("ScriptBlockText","")
                snip = (script[:160] + ("…" if len(script) > 160 else "")) if script else ""
                w.writerow([ts, rule, eid, tags, snip])
        ok(f"Evidence CSV written: {evidence_path}")
    except Exception as e:
        warn(f"Evidence CSV write failed: {e}")

def archive_old_reports(base_dir: Path, keep_day: str):
    archive_dir = base_dir/"archive"/keep_day
    archive_dir.mkdir(parents=True, exist_ok=True)
    for p in list(base_dir.iterdir()):
        if p.name == "archive": continue
        if p.is_dir() and p.name.startswith(keep_day):
            continue
        if p.is_dir():
            shutil.move(str(p), archive_dir/p.name)
        elif p.is_file() and (p.suffix in {".html",".md",".pdf"}):
            shutil.move(str(p), archive_dir/p.name)

# ─────────────────────────────────────────────────────────────────────────────
# Two-pass pipeline
# ─────────────────────────────────────────────────────────────────────────────
def two_pass(client: OpenAI, dets: List[Dict[str, Any]], cfg: AppConfig) -> Tuple[str, Dict[str, Tuple[int,int]]]:
    blocks = dynamic_chunks(dets, cfg.chunk_size, cfg.max_input_tokens)
    if not blocks:
        return "# No detections — nothing to summarize.", {}

    console.print(Panel.fit(f"[yellow]⚙ Detections found ({len(dets)}) — generating micro-summaries…[/yellow]", box=box.ROUNDED))
    micros, (mi_in, mi_out) = micro_parallel(client, blocks, cfg)

    console.print(Panel.fit(f"[yellow]⚙ Compiling executive summary with final model…[/yellow]", box=box.ROUNDED))
    selected = select_best_micros(blocks, micros, cfg.max_input_tokens, cap_count=20)
    final_user = build_final_prompt(selected)

    final_text, f_ptk, f_ctk = call_llm(
        client, cfg.final_model, SYSTEM_FINAL, final_user,
        cfg.temperature, cfg.llm_timeout, cfg.llm_retries, stream=False
    )

    usage = {
        cfg.chunk_model: (mi_in, mi_out),
        cfg.final_model: (f_ptk, f_ctk),
    }

    header = (
        "# 🔍 ForenSynth AI — DFIR Summary (Two-Pass)\n\n"
        f"- Generated: {datetime.now(timezone.utc).isoformat()}\n"
        f"- Micro model: `{cfg.chunk_model}`\n"
        f"- Final model: `{cfg.final_model}`\n"
        f"- Chunks: {len(blocks)}\n"
        "\n---\n\n## Final Executive Report\n\n"
    )
    appendix = "\n\n---\n\n## Micro Cluster Summaries\n\n" + "\n\n".join(micros)
    return header + final_text + appendix, usage

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    cfg = parse_args()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        die("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)

    console.rule("[bold cyan]🧠 ForenSynth AI — DFIR Intelligence Engine v2.3.4 (Polish)[/bold cyan]")

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
    dets_full = load_detections(det_json)
    original_count = len(dets_full)

    # Sampling (for POC speed)
    dets = apply_sampling(dets_full, cfg.limit_detections, cfg.sample_step)
    if len(dets) != original_count:
        console.print(Panel.fit(f"[cyan]⚙ Sampling applied: {original_count} → {len(dets)} (step={cfg.sample_step or 1}, limit={cfg.limit_detections or '∞'})[/cyan]", box=box.ROUNDED))

    # Write normalized evidence JSON (what the rest of pipeline uses)
    evidence_json_path = outdir / "evidence.json"
    evidence_json_path.write_text(json.dumps(dets, ensure_ascii=False, indent=2), encoding="utf-8")
    ok("Evidence written: evidence.json")

    count = len(dets)
    if count == 0:
        warn("No Sigma detections found — skipping summarization to save tokens.")
        md_path = outdir / f"forensynth_summary_{stamp.split('_')[0]}.md"
        md_path.write_text("# No detections — nothing to summarize.\n", encoding="utf-8")
        if cfg.make_html:
            html = build_html("# No detections — nothing to summarize.\n", [], cfg, md_path.name)
            html_path = outdir / f"forensynth_report_{stamp.split('_')[0]}.html"
            html_path.write_text(html, encoding="utf-8")
            ok(f"Report written: {html_path}")
        write_run_log(cfg.outdir/"run_log.csv", {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detections": 0,
            "runtime_sec": int(time.time()-start),
            "cost_usd": f"{0.0:.6f}",
            "integrity": "on" if cfg.integrity else "off",
            "chunk_model": cfg.chunk_model,
            "final_model": cfg.final_model,
        })
        archive_old_reports(cfg.outdir, keep_day=stamp.split('_')[0])
        return

    # Summarize (two-pass default when flag present)
    if cfg.two_pass:
        md_final, usage = two_pass(client, dets, cfg)
    else:
        # Single pass: squeeze into final model within budget
        blocks = dynamic_chunks(dets, cfg.chunk_size, cfg.max_input_tokens)
        flat = [d for b in blocks for d in b]
        user = build_micro_prompt(flat)
        base_in = est_tokens(SYSTEM_FINAL)
        while base_in + est_tokens(user) > cfg.max_input_tokens:
            parts = user.splitlines()
            if len(parts) <= 10: break
            user = "\n".join(parts[:-10])
        md_body, ptk, ctk = call_llm(client, cfg.final_model, SYSTEM_FINAL, user, cfg.temperature, cfg.llm_timeout, cfg.llm_retries, stream=False)
        usage = {cfg.final_model: (base_in + ptk, ctk)}
        md_final = (
            "# 🔍 ForenSynth AI — DFIR Summary (Single-Pass)\n\n"
            f"- Generated: {datetime.now(timezone.utc).isoformat()}\n"
            f"- Final model: `{cfg.final_model}`\n\n"
            "## Final Executive Report\n\n" + md_body
        )

    # Output
    md_path = outdir / f"forensynth_summary_{stamp.split('_')[0]}.md"
    md_path.write_text(md_final, encoding="utf-8")
    html_path = None
    if cfg.make_html:
        html = build_html(md_final, dets, cfg, md_path.name)
        html_path = outdir / f"forensynth_report_{stamp.split('_')[0]}.html"
        html_path.write_text(html, encoding="utf-8")
        ok(f"Report written: {html_path}")

    if cfg.export_evidence_csv:
        export_evidence_csv(outdir / f"evidence_{stamp.split('_')[0]}.csv", dets)

    if cfg.make_pdf and pypandoc is not None and html_path is not None:
        try:
            pdf_path = outdir / f"forensynth_report_{stamp.split('_')[0]}.pdf"
            pypandoc.convert_text(html, to="pdf", format="html", outputfile=str(pdf_path))  # type: ignore
            ok(f"PDF written: {pdf_path}")
        except Exception as e:
            info(f"PDF generation failed/skipped: {e}")

    # Runtime + cost
    runtime = int(time.time() - start)
    total_cost, lines = cost_breakdown(usage)

    write_run_log(cfg.outdir/"run_log.csv", {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detections": original_count,  # show original for transparency; visuals reflect sampled set inside HTML
        "runtime_sec": runtime,
        "cost_usd": f"{total_cost:.6f}",
        "integrity": "on" if cfg.integrity else "off",
        "chunk_model": cfg.chunk_model,
        "final_model": cfg.final_model,
    })

    # Append billing to HTML for parity with dashboard
    if html_path is not None:
        append_billing_to_html(html_path, lines)

    console.rule("[bold]Cost Breakdown[/bold]")
    for ln in lines: console.print(ln)
    console.print(f"Total cost: ${total_cost:.6f}")

    console.print(Panel.fit(
        f"[white on dodger_blue2]  Runtime Summary  [/white on dodger_blue2]\n"
        f"Processed {original_count} detections in {runtime}s | Output: {md_path.name}"
        + (f" | HTML: {html_path.name}" if html_path else ""),
        box=box.ROUNDED
    ))

    # Archive prior day reports to keep today's tidy
    archive_old_reports(cfg.outdir, keep_day=stamp.split('_')[0])

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("Interrupted by user")
