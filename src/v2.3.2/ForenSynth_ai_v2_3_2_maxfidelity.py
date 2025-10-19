#!/usr/bin/env python3
# File: forensynth_ai_v2_3_2_maxfidelity.py
"""
ForenSynth AI v2.3.2 (Max Fidelity)
DFIR Intelligence Engine — Evidence-forward, integrity-focused summarization:
 - Integrity Mode hard-lock (gpt-5-mini micro + gpt-5 final)
 - Final prompt enriched with compact Evidence Snapshot (counts/timeframe/top rules/EventIDs)
 - Deterministic-oriented behavior (no streaming final; conservative retries)
 - Parallel micro-summaries (thread-safe RPM throttle)
 - Scoring-aware selection; strict per-block token guard (tiktoken if available)
 - Evidence Appendix (hosts/users/rules/EventIDs/IOCs) built from raw detections (no LLM)
 - Self-contained, escaped HTML with heatmap + KPIs + SHA256 footer
 - Chainsaw command logging; CSV run log; archive housekeeping
 - Includes v2.3.1 fixes (PDF-only path, safer trimming, etc.)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
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
    "gpt-3.5-turbo": {"in": 0.00050, "out": 0.00150},
}

SYSTEM_MICRO = (
    "You are a senior DFIR analyst. Produce concise, accurate summaries. "
    "Group related detections, highlight notable TTPs (MITRE), dedupe repetition, "
    "and end with prioritized recommendations by risk and effort."
)

SYSTEM_FINAL = (
    "You are a DFIR lead. Merge micro-summaries into a coherent executive report. "
    "Eliminate repetition; group by phases/TTPs; quantify scope; "
    "end with prioritized, actionable recommendations (High/Med/Low) and quick wins.\n"
    "Include a brief 'Findings Checklist' with numeric counts if present (detections, unique hosts, users, rules, event IDs, timeframe).\n"
    "If uncertain, state 'Unknown' rather than inferring."
)

MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

EVENT_WEIGHTS = {  # DFIR-interesting IDs
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

# IOC regexes (fast + pragmatic)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN = re.compile(r"\b(?:(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63})\b")
RE_URL = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_PATH = re.compile(r"[A-Za-z]:\\[^\s\"']+|\b/[^ \n\r\t]+")  # Win or *nix


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


def parse_args() -> AppConfig:
    p = argparse.ArgumentParser(description="ForenSynth AI v2.3.2 (Max Fidelity)")
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
    p.add_argument(
        "--max-fidelity",
        action="store_true",
        help="Enable integrity+evidence mode and conservative final call",
    )

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

    a = p.parse_args()
    prefer = [s.strip() for s in a.prefer.split(",") if s.strip()]

    # Auto workers
    workers = a.micro_workers
    if workers <= 0:
        cpu = os.cpu_count() or 2
        workers = min(max(2, cpu), 8) if a.fast else max(1, min(cpu, 4))

    # Integrity + Max Fidelity locks
    integrity = (a.integrity == "on") or a.max_fidelity
    chunk_model = a.chunk_model
    final_model = a.final_model
    if integrity:
        chunk_model = "gpt-5-mini"
        final_model = "gpt-5"

    # In max-fidelity mode we also disable streaming for final call
    stream = (a.stream == "on") and (not a.max_fidelity)

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
        stream=stream,
        integrity=integrity,
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
    (Path(outdir) / "chainsaw_cmd.txt").write_text(" ".join(cmd), encoding="utf-8")

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
def est_tokens(s: str, model_hint: Optional[str] = None) -> int:
    if tiktoken:
        try:
            enc = tiktoken.encoding_for_model(model_hint or DEFAULT_FINAL_MODEL)
        except Exception:
            try:
                enc = tiktoken.encoding_for_model(DEFAULT_CHUNK_MODEL)
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


def _extract_host_user(det: Dict[str, Any]) -> Tuple[str, str]:
    try:
        ev = ((det.get("document") or {}).get("data") or {}).get("Event") or {}
        ed = ev.get("EventData", {}) if isinstance(ev, dict) else {}
        return str(ed.get("Computer", "")), str(ed.get("User", ""))
    except Exception:
        return "", ""


def _extract_script(det: Dict[str, Any]) -> str:
    try:
        return (
            (((det.get("document") or {}).get("data") or {}).get("Event") or {}).get("EventData")
            or {}
        ).get("ScriptBlockText", "") or ""
    except Exception:
        return ""


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
    rarity = 1.0 + min(0.8, 1.0 / max(1.0, math.sqrt(freq)))

    script = _extract_script(det)
    script_bonus = 1.0 + min(0.5, len(str(script)) / 2000.0)

    return mitre_bonus * sev * eid_w * rarity * script_bonus


def score_micro_block(block: List[Dict[str, Any]], rule_freq: Dict[str, int]) -> float:
    if not block:
        return 0.0
    scores = sorted((score_detection(d, rule_freq) for d in block), reverse=True)
    base = sum(scores[: min(5, len(scores))])
    uniq_rules = len({d.get("name") or (d.get("rule", {}) or {}).get("title") for d in block})
    hosts = set()
    users = set()
    for d in block:
        h, u = _extract_host_user(d)
        if h:
            hosts.add(h)
        if u:
            users.add(u)
    diversity = 1.0 + min(
        0.6,
        (0.2 if uniq_rules > 0 else 0.0)
        + (0.2 if len(hosts) > 1 else 0.0)
        + (0.2 if len(users) > 1 else 0.0),
    )
    return base * diversity


# ────────────────────────────────────────────────────────────────────────────
# Evidence extraction (fidelity core)
# ────────────────────────────────────────────────────────────────────────────
def evidence_from_detections(dets: List[Dict[str, Any]]) -> Dict[str, Any]:
    rules: Dict[str, int] = {}
    eids: Dict[str, int] = {}
    hosts: Dict[str, int] = {}
    users: Dict[str, int] = {}
    tags: Dict[str, int] = {}

    first_ts, last_ts = None, None

    iocs = {
        "ipv4": set(),
        "domains": set(),
        "urls": set(),
        "emails": set(),
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
        "paths": set(),
    }

    for d in dets:
        # timeframe
        ts = d.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00") if ts.endswith("Z") else ts)
                if (first_ts is None) or (dt < first_ts):
                    first_ts = dt
                if (last_ts is None) or (dt > last_ts):
                    last_ts = dt
            except Exception:
                pass

        # rule title
        r = d.get("name") or (d.get("rule", {}) or {}).get("title") or ""
        if r:
            rules[r] = rules.get(r, 0) + 1

        # event id
        eid = _extract_event_id(d)
        if eid:
            eids[eid] = eids.get(eid, 0) + 1

        # tags
        for t in _extract_tags(d):
            tags[t] = tags.get(t, 0) + 1

        # host/user
        h, u = _extract_host_user(d)
        if h:
            hosts[h] = hosts.get(h, 0) + 1
        if u:
            users[u] = users.get(u, 0) + 1

        # scan for IOCs in rule+script text
        blob = " ".join([r, _extract_script(d)])
        for m in RE_IPV4.findall(blob):
            iocs["ipv4"].add(m)
        for m in RE_DOMAIN.findall(blob):
            iocs["domains"].add(m)
        for m in RE_URL.findall(blob):
            iocs["urls"].add(m)
        for m in RE_EMAIL.findall(blob):
            iocs["emails"].add(m)
        for m in RE_MD5.findall(blob):
            iocs["md5"].add(m.lower())
        for m in RE_SHA1.findall(blob):
            iocs["sha1"].add(m.lower())
        for m in RE_SHA256.findall(blob):
            iocs["sha256"].add(m.lower())
        for m in RE_PATH.findall(blob):
            iocs["paths"].add(m)

    # sort & limit heavy lists for readability
    def topn(d: Dict[str, int], n=20):
        return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]

    def sortl(s: set, n=50):
        return sorted(list(s))[:n]

    out = {
        "detections": len(dets),
        "timeframe": {
            "first": first_ts.isoformat() if first_ts else None,
            "last": last_ts.isoformat() if last_ts else None,
        },
        "counts": {
            "unique_rules": len(rules),
            "unique_event_ids": len(eids),
            "unique_hosts": len(hosts),
            "unique_users": len(users),
            "unique_tags": len(tags),
        },
        "top": {
            "rules": topn(rules, 25),
            "event_ids": topn(eids, 25),
            "hosts": topn(hosts, 25),
            "users": topn(users, 25),
            "tags": topn(tags, 25),
        },
        "iocs": {k: sortl(v, 100) for k, v in iocs.items()},
    }
    return out


def compact_snapshot_for_prompt(evd: Dict[str, Any]) -> str:
    snap = {
        "detections": evd.get("detections"),
        "timeframe": evd.get("timeframe"),
        "counts": evd.get("counts"),
        "top": {
            "rules": evd.get("top", {}).get("rules", [])[:10],
            "event_ids": evd.get("top", {}).get("event_ids", [])[:10],
        },
    }
    return json.dumps(snap, separators=(",", ":"))


# ────────────────────────────────────────────────────────────────────────────
# Prompt builders
# ────────────────────────────────────────────────────────────────────────────
def fmt_micro_line(det: Dict[str, Any], include_snip: bool = True, snip_len: int = 160) -> str:
    ts = det.get("timestamp", "N/A")
    rule = det.get("name", (det.get("rule", {}) or {}).get("title", "N/A"))
    tags = ", ".join(_extract_tags(det)) or "None"
    eid = _extract_event_id(det) or "N/A"
    script = _extract_script(det)
    snip = (
        (str(script)[:snip_len] + ("…" if len(str(script)) > snip_len else ""))
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


def build_final_prompt(micros: List[str], evidence_snapshot_json: Optional[str] = None) -> str:
    hdr = (
        "Merge the following micro-summaries into one executive DFIR report. "
        "Eliminate duplicates, group themes, and produce:\n"
        "1) Executive Summary\n2) Observed Activity (grouped)\n3) Key TTPs/Techniques\n4) Risk Assessment\n5) Actionable Recommendations (High/Med/Low)\n"
        "At the end, include a short 'Findings Checklist' (counts and timeframe)."
    )
    pieces = [hdr, "\n\n".join(micros)]
    if evidence_snapshot_json:
        pieces.append("\n\n[Evidence Snapshot]\n" + evidence_snapshot_json)
    return "\n\n---\n\n".join(pieces)


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
        None if (abs(temperature - 1.0) < 1e-6 or model.startswith("gpt-5")) else float(temperature)
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
    sys_t = est_tokens(SYSTEM_MICRO)
    while size >= 1:
        blocks = list(chunk(dets, size))
        too_big = any(
            (sys_t + est_tokens(build_micro_prompt(b)) > max_input_tokens) for b in blocks
        )
        if not too_big:
            return blocks
        size = max(1, size - 2)
    return list(chunk(dets, 1))


# ────────────────────────────────────────────────────────────────────────────
# Parallel micro + scoring-aware final selection
# ────────────────────────────────────────────────────────────────────────────
def micro_parallel(
    client: OpenAI, blocks: List[List[Dict[str, Any]]], cfg: AppConfig
) -> Tuple[List[str], Tuple[int, int]]:
    usage_in = usage_out = 0
    micros: List[str] = [""] * len(blocks)

    # Shared RPM throttle (thread-safe)
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
    blocks: List[List[Dict[str, Any]]], micros: List[str], budget_tokens: int, extra_tokens: int = 0
) -> List[str]:
    # Score by block content + diversity; then pack under token budget minus extra
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
    budget = est_tokens(SYSTEM_FINAL) + extra_tokens
    for s, m in scored:
        cost = est_tokens(m)
        if budget + cost <= budget_tokens:
            selected.append(m)
            budget += cost

    if not selected and micros:
        best = scored[0][1]
        lines = best.splitlines()
        while lines and (budget + est_tokens("\n".join(lines)) > budget_tokens):
            lines = lines[:-5] if len(lines) > 5 else lines[:-1]
        selected = ["\n".join(lines)] if lines else [micros[0][:1000]]
    return selected


# ────────────────────────────────────────────────────────────────────────────
# Heatmap + HTML
# ────────────────────────────────────────────────────────────────────────────
def build_heatmap_counts(dets: List[Dict[str, Any]]) -> List[int]:
    from datetime import timezone as _tz

    buckets = [0] * 24
    for d in dets:
        ts = d.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00") if ts.endswith("Z") else ts)
            hr = dt.astimezone(_tz.utc).hour
            buckets[hr] += 1
        except Exception:
            continue
    return buckets


INLINE_CSS = f"""
:root {{ --fg:#0e1628; --muted:#66728a; --bg:#ffffff; --edge:#eef2f8; --accent:{DFIR_BLUE}; }}
html,body {{ margin:0; padding:0; }}
body {{ color:var(--fg); background:var(--bg); font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial; }}
.header {{ padding:24px 24px 8px; border-bottom:1px solid var(--edge); }}
.h1 {{ font-size:28px; font-weight:800; margin:0 0 4px; }}
.sub {{ color:var(--muted); font-size:14px; }}
.container {{ max-width:1100px; margin:0 auto; padding:0 24px 48px; }}
.toc {{ margin:16px 0 24px; padding:12px; background:#f6f9ff; border:1px solid var(--edge); border-radius:8px; }}
.section h2 {{ font-size:20px; margin-top:28px; border-bottom:1px solid var(--edge); padding-bottom:4px; }}
pre, code {{ background:#f7f9fc; border:1px solid var(--edge); border-radius:6px; }}
pre {{ padding:12px; overflow:auto; }}
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
.hash {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; color:#4b5563; word-break:break-all; }}
.table {{ margin-top:10px; border:1px solid var(--edge); border-radius:8px; overflow:auto; }}
.table table {{ width:100%; border-collapse:collapse; }}
.table th, .table td {{ padding:6px 8px; border-bottom:1px solid var(--edge); text-align:left; font-size:13px; }}
"""

HEATMAP_JS = r"""
function renderHeatmap(canvasId, counts) {
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  const cols = 24, pad = 8;
  const cw = (w - pad*2) / cols;
  const ch = (h - pad*2);

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
    ctx.fillRect(x, y, cw-2, ch-16);

    if (c % 3 === 0) {
      ctx.fillStyle = '#66728a';
      ctx.fillText(String(c).padStart(2,'0'), x+cw/2, y+ch-14);
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


def _html_table(headers: List[str], rows: List[Tuple[Any, ...]]) -> str:
    thead = "".join(f"<th>{_html.escape(str(h))}</th>" for h in headers)
    tb = []
    for r in rows:
        tds = "".join(f"<td>{_html.escape(str(x))}</td>" for x in r)
        tb.append(f"<tr>{tds}</tr>")
    return f"<div class='table'><table><thead><tr>{thead}</tr></thead><tbody>{''.join(tb)}</tbody></table></div>"


def build_html(
    md_final: str,
    dets: List[Dict[str, Any]],
    cfg: AppConfig,
    outname: str,
    md_sha256: Optional[str] = None,
    html_sha256: Optional[str] = None,
    evd: Optional[Dict[str, Any]] = None,
) -> str:
    counts = build_heatmap_counts(dets)
    toc_html = (
        """
    <div class="toc">
      <strong>Contents</strong>
      <ul>
        <li><a href="#kpis">Key Metrics</a></li>
        <li><a href="#heat">Detection Heatmap</a></li>
        <li><a href="#exec">Executive Report</a></li>
        <li><a href="#evidence">Evidence Appendix</a></li>
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
    chunk_count = md_final.count("## Micro ")
    body_html = _html.escape(md_final)

    sha_html = ""
    if md_sha256 or html_sha256:
        sha_html = "<div class='hash'>"
        if md_sha256:
            sha_html += f"<div>MD SHA256: {_html.escape(md_sha256)}</div>"
        if html_sha256:
            sha_html += f"<div>HTML SHA256: {_html.escape(html_sha256)}</div>"
        sha_html += "</div>"

    # Evidence tables (if provided)
    evidence_section = ""
    if evd:
        k = evd.get("counts", {})
        tf = evd.get("timeframe", {})
        top = evd.get("top", {})
        iocs = evd.get("iocs", {})
        # Small KPI grid row additions will show via top-level KPIs; here we add tables
        tables = []
        if top.get("rules"):
            tables.append("<h3>Top Rules</h3>" + _html_table(["Rule", "Count"], top["rules"]))
        if top.get("event_ids"):
            tables.append(
                "<h3>Top Event IDs</h3>" + _html_table(["EventID", "Count"], top["event_ids"])
            )
        if top.get("hosts"):
            tables.append("<h3>Top Hosts</h3>" + _html_table(["Host", "Count"], top["hosts"]))
        if top.get("users"):
            tables.append("<h3>Top Users</h3>" + _html_table(["User", "Count"], top["users"]))

        # IOCs (show a few each)
        def ioc_tbl(title: str, key: str):
            items = [(x,) for x in (iocs.get(key) or [])[:50]]
            return f"<h4>{_html.escape(title)}</h4>" + _html_table([title], items) if items else ""

        ioc_blocks = []
        ioc_blocks.append(ioc_tbl("IPv4", "ipv4"))
        ioc_blocks.append(ioc_tbl("Domains", "domains"))
        ioc_blocks.append(ioc_tbl("URLs", "urls"))
        ioc_blocks.append(ioc_tbl("Emails", "emails"))
        ioc_blocks.append(ioc_tbl("SHA256", "sha256"))
        ioc_blocks.append(ioc_tbl("SHA1", "sha1"))
        ioc_blocks.append(ioc_tbl("MD5", "md5"))
        ioc_blocks.append(ioc_tbl("Paths", "paths"))
        evidence_section = (
            f"<div id='evidence' class='section'>"
            f"<h2>Evidence Appendix</h2>"
            f"<p>Detections: {evd.get('detections')} | Timeframe: {tf.get('first')} → {tf.get('last')} | "
            f"Unique: rules {k.get('unique_rules')}, event IDs {k.get('unique_event_ids')}, hosts {k.get('unique_hosts')}, users {k.get('unique_users')}</p>"
            + "".join(tables)
            + "".join(ioc_blocks)
            + "</div>"
        )

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
    <div class="sub">Generated {datetime.now(timezone.utc).isoformat()} | Integrity Mode: {"ON" if cfg.integrity else "OFF"} | Max Fidelity: {"ON" if cfg.max_fidelity else "OFF"}</div>
    <div class="strip"></div>
  </div>
  <div class="container">
    {toc_html}
    <div id="kpis" class="kpis">
      <div class="kpi"><div class="label">Detections</div><div class="value">{len(dets)}</div></div>
      <div class="kpi"><div class="label">Chunks</div><div class="value">{chunk_count}</div></div>
      <div class="kpi"><div class="label">Chunk Model</div><div class="value">{_html.escape(cfg.chunk_model)}</div></div>
      <div class="kpi"><div class="label">Final Model</div><div class="value">{_html.escape(cfg.final_model)}</div></div>
      <div class="kpi"><div class="label">Hosts</div><div class="value">{(evd or {}).get("counts", {}).get("unique_hosts", "~")}</div></div>
      <div class="kpi"><div class="label">Users</div><div class="value">{(evd or {}).get("counts", {}).get("unique_users", "~")}</div></div>
    </div>

    <div id="heat" class="section">
      <h2>Detection Heatmap (UTC, per hour)</h2>
      <div class="canvas-wrap">
        <canvas id="heatmap" width="1050" height="96"></canvas>
      </div>
      <div class="note">Hover cells to see exact hour & count</div>
    </div>

    <div id="exec" class="section">
      <h2>Executive & Findings</h2>
      <pre>{body_html}</pre>
    </div>

    {evidence_section}

    <div class="footer">
      {branding}
      <div>{_html.escape(outname)}</div>
      {sha_html}
    </div>
  </div>
<script>{HEATMAP_JS}
  const COUNTS = {json.dumps(counts)};
  renderHeatmap('heatmap', COUNTS);
</script>
</body>
</html>
"""
    return html


# ────────────────────────────────────────────────────────────────────────────
# Cost & Logging & Archiving & Hash
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
        if p.is_dir() and p.name.startswith(keep_day):  # keep today's run folders
            continue
        if p.is_dir():
            shutil.move(str(p), archive_dir / p.name)
        elif p.is_file() and (p.suffix in {".html", ".md", ".pdf"}):
            shutil.move(str(p), archive_dir / p.name)


def sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ────────────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────────────
def main():
    cfg = parse_args()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        die("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)

    console.rule(
        "[bold cyan]🧠 ForenSynth AI — DFIR Intelligence Engine v2.3.2 (Max Fidelity)[/bold cyan]"
    )
    if cfg.integrity:
        console.print(
            Panel.fit(
                "🧠 Integrity Mode Active — prioritizing detection accuracy over cost.",
                box=box.ROUNDED,
            )
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

    # Load detections & evidence
    dets = load_detections(det_json)
    count = len(dets)
    ok(f"Detections loaded: {count}")

    evd = evidence_from_detections(dets)
    (outdir / "evidence.json").write_text(json.dumps(evd, indent=2), encoding="utf-8")
    ok("Evidence written: evidence.json")

    if count == 0:
        warn(
            "No Sigma detections found — skipping summarization to save tokens.\nTip: verify mapping/rules paths and log sources."
        )
        md_path = outdir / f"forensynth_summary_{stamp.split('_')[0]}.md"
        md_path.write_text("# No detections — nothing to summarize.\n", encoding="utf-8")

        html_path = None
        html_str = None
        if cfg.make_html:
            html_str = build_html(
                "# No detections — nothing to summarize.\n", [], cfg, md_path.name, evd=evd
            )
            html_path = outdir / f"forensynth_report_{stamp.split('_')[0]}.html"
            html_path.write_text(html_str, encoding="utf-8")
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
        # Build micros
        blocks = dynamic_chunks(dets, cfg.chunk_size, cfg.max_input_tokens)
        console.print(
            Panel.fit(
                f"[yellow]⚙ Detections found ({len(dets)}) — generating micro-summaries…[/yellow]",
                box=box.ROUNDED,
            )
        )
        micros, (mi_in, mi_out) = micro_parallel(client, blocks, cfg)

        # Build Evidence Snapshot and pack micros under budget (reserve space for snapshot)
        snapshot = compact_snapshot_for_prompt(evd)
        extra = est_tokens("\n\n[Evidence Snapshot]\n" + snapshot)
        selected = select_best_micros(blocks, micros, cfg.max_input_tokens, extra_tokens=extra)
        final_user = build_final_prompt(selected, evidence_snapshot_json=snapshot)

        # Optional: throttle final under RPM as well
        if cfg.rpm > 0:
            time.sleep(max(0.0, 60.0 / float(cfg.rpm)))

        console.print(
            Panel.fit(
                "[yellow]⚙ Compiling executive summary with final model…[/yellow]", box=box.ROUNDED
            )
        )
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
            f"- Integrity: ON | Max Fidelity: {'ON' if cfg.max_fidelity else 'OFF'}\n"
            "\n---\n\n## Final Executive Report\n\n"
        )
        md_final = (
            header + final_text + "\n\n---\n\n## Micro Cluster Summaries\n\n" + "\n\n".join(micros)
        )

    else:
        # Single-pass (still include Evidence Snapshot for fidelity)
        flat = dets
        user = build_micro_prompt(flat)
        snapshot = compact_snapshot_for_prompt(evd)
        final_user = build_final_prompt([user], evidence_snapshot_json=snapshot)
        md_body = call_llm(
            client,
            cfg.final_model,
            SYSTEM_FINAL,
            final_user,
            cfg.temperature,
            cfg.llm_timeout,
            cfg.llm_retries,
            stream=False if cfg.max_fidelity else cfg.stream,
        )
        usage = {
            cfg.final_model: (
                est_tokens(SYSTEM_FINAL) + est_tokens(final_user),
                est_tokens(md_body),
            )
        }
        md_final = (
            "# 🔒 ForenSynth AI — DFIR Summary (Single-Pass, Max Fidelity)\n\n"
            f"- Generated: {datetime.now(timezone.utc).isoformat()}\n"
            f"- Final model: `{cfg.final_model}`\n"
            f"- Integrity: ON | Max Fidelity: {'ON' if cfg.max_fidelity else 'OFF'}\n\n"
            "## Final Executive Report\n\n" + md_body
        )

    # Output
    md_path = outdir / f"forensynth_summary_{stamp.split('_')[0]}.md"
    md_path.write_text(md_final, encoding="utf-8")
    md_sha = sha256_path(md_path)

    html_path = None
    html_str = None
    if cfg.make_html:
        html_str = build_html(md_final, dets, cfg, md_path.name, md_sha256=md_sha, evd=evd)
        html_path = outdir / f"forensynth_report_{stamp.split('_')[0]}.html"
        html_path.write_text(html_str, encoding="utf-8")
        html_sha = sha256_path(html_path)
        # re-write with html sha included
        html_str = build_html(
            md_final, dets, cfg, md_path.name, md_sha256=md_sha, html_sha256=html_sha, evd=evd
        )
        html_path.write_text(html_str, encoding="utf-8")
        ok(f"Report written: {html_path}")

    if cfg.make_pdf and pypandoc is not None:
        try:
            tmp_html = html_str or build_html(
                md_final, dets, cfg, md_path.name, md_sha256=md_sha, evd=evd
            )
            pdf_path = outdir / f"forensynth_report_{stamp.split('_')[0]}.pdf"
            pypandoc.convert_text(tmp_html, to="pdf", format="html", outputfile=str(pdf_path))  # type: ignore
            ok(f"PDF written: {pdf_path}")
        except Exception as e:
            info(f"PDF generation failed/skipped: {e}")

    # Archive + cost log
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
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("Interrupted by user")
