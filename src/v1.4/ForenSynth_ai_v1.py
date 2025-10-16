# File: forensynth_ai_v1.py
# ForenSynth AI — DFIR Intelligence Engine v1.0
# From raw logs to refined intelligence. Self-contained HTML/CSS reporting.
# Requires: chainsaw, Python 3.9+, openai, tiktoken, python-dotenv, rich
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
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import tiktoken
from dotenv import load_dotenv
from openai import APIConnectionError, APIError, APITimeoutError, BadRequestError, OpenAI, RateLimitError
from rich import box
from rich.console import Console
from rich.panel import Panel

# ───────────────────────────────────────── UI Helpers ─────────────────────────────────────────
console = Console()


def ok(msg: str):
    console.print(Panel.fit(f"[green]✔ {msg}[/green]", box=box.ROUNDED))


def info(msg: str):
    console.print(Panel.fit(f"[yellow]⚙ {msg}[/yellow]", box=box.ROUNDED))


def warn(msg: str):
    console.print(Panel.fit(f"[yellow]⚠ {msg}[/yellow]", box=box.ROUNDED))


def die(msg: str, code: int = 1):
    console.print(Panel.fit(f"[red]✘ {msg}[/red]", box=box.ROUNDED))
    sys.exit(code)


# ───────────────────────────────────────── Defaults ───────────────────────────────────────────
BRAND_NAME = "ForenSynth AI"
VERSION = "v1.0"

DEFAULT_CHUNK_MODEL = os.getenv("CHUNK_MODEL", "gpt-5-mini")
DEFAULT_FINAL_MODEL = os.getenv("FINAL_MODEL", "gpt-5")

PRICING = {  # per 1K tokens
    "gpt-5-nano": {"in": 0.0001, "out": 0.0008},  # example defaults; override with --pricing-json if needed
    "gpt-5-mini": {"in": 0.00025, "out": 0.0020},
    "gpt-5": {"in": 0.00125, "out": 0.0100},
    "gpt-3.5-turbo": {"in": 0.0005, "out": 0.0015},
}

# Embedded CSS (self-contained)
REPORT_CSS = r"""
:root {
  --bg: #0b1220; --fg: #e6eef7; --muted:#9fb0c3; --accent:#6dc0ff; --panel:#101a2e; --card:#0f1a2b; --chip:#132239; --ok:#54d68c; --warn:#f2c14e; --err:#ff6b6b;
  --mono: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
  --sans: ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans","Apple Color Emoji","Segoe UI Emoji";
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.6}
.container{max-width:1100px;margin:2rem auto;padding:0 1rem}
.header{background:linear-gradient(90deg,#0f1a2b,#14243c);border:1px solid #1f2a3a;border-radius:16px;padding:20px 20px;margin-bottom:16px}
.header h1{margin:0 0 6px 0;font-size:28px}
.header .sub{color:var(--muted);font-size:14px}
.badges{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.badge{background:var(--chip);color:var(--fg);border:1px solid #1f2a3a;border-radius:999px;padding:4px 10px;font-size:12px}
.timing{margin-top:6px;color:var(--muted);font-size:13px}

.section{background:var(--panel);border:1px solid #1f2a3a;border-radius:16px;padding:18px;margin:14px 0}
.section h2{margin:0 0 10px 0;font-size:20px;border-bottom:1px dashed #21304d;padding-bottom:6px}
.code{background:#0b162a;border:1px solid #1c2a45;border-radius:10px;padding:10px;font-family:var(--mono);overflow:auto;font-size:13px;white-space:pre-wrap}

.twocol{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width: 900px){.twocol{grid-template-columns:1fr}}

.micro-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width: 900px){.micro-grid{grid-template-columns:1fr}}
.micro-card{background:var(--card);border:1px solid #1f2a3a;border-radius:14px;padding:12px}
.micro-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.micro-title{font-weight:700;font-size:14px}
.micro-meta{color:var(--muted);font-size:12px}
.kv{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px}
.kv span{background:var(--chip);border:1px solid #1f2a3a;border-radius:8px;padding:2px 8px;font-size:12px}

.footer{margin-top:20px;text-align:right;color:var(--muted);font-size:12px;border-top:1px solid #1f2a3a;padding-top:8px}
.footer strong{color:var(--accent)}
"""

# Embedded HTML template with placeholders
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{REPORT_TITLE}}</title>
<style>{{REPORT_CSS}}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>{{REPORT_TITLE}}</h1>
    <div class="sub">{{SUBTITLE}}</div>
    <div class="badges">
      <span class="badge">Detections: {{DETECTION_COUNT}}</span>
      <span class="badge">Integrity: {{INTEGRITY}}</span>
      <span class="badge">Models: micro={{MICRO_MODEL}}, final={{FINAL_MODEL}}</span>
      <span class="badge">Runtime: {{RUNTIME}}</span>
      <span class="badge">Cost: ${{COST}}</span>
    </div>
    <div class="timing">Started {{START_TS}} · Finished {{END_TS}}</div>
  </div>

  <div class="section">
    <h2>Executive Summary</h2>
    <div>{{EXEC_HTML}}</div>
  </div>

  <div class="section">
    <h2>Micro Summaries</h2>
    <div class="micro-grid">
      {{MICRO_CARDS}}
    </div>
  </div>

  <div class="section">
    <h2>Indicators of Compromise</h2>
    <div class="code">{{IOC_BLOCK}}</div>
  </div>

  <div class="section">
    <h2>Environment</h2>
    <div class="code">{{ENV_BLOCK}}</div>
  </div>

  <div class="footer">
    {{FOOTER}}
  </div>
</div>
</body>
</html>
"""


# ───────────────────────────────────────── Config ─────────────────────────────────────────────
@dataclass
class AppConfig:
    hunt: bool
    evtx_root: Path
    outdir: Path
    rules: Path
    mapping: Path
    sigma_root: Optional[Path]
    make_html: bool
    make_pdf: bool
    two_pass: bool
    chunk_size: int
    max_chunks: int
    max_input_tokens: int
    # LLM
    chunk_model: str
    final_model: str
    llm_timeout: int
    llm_retries: int
    llm_temperature: float
    rpm: int
    micro_workers: int
    # Behavior
    branding: str  # "on" | "off"
    integrity: str  # "on" | "off"
    fast: bool
    # Cost override
    pricing_json: Optional[str]


# ───────────────────────────────────────── CLI ───────────────────────────────────────────────
def parse_args() -> AppConfig:
    p = argparse.ArgumentParser(description=f"{BRAND_NAME} — DFIR Intelligence Engine {VERSION}")
    p.add_argument("--hunt", action="store_true", default=True, help="Run Chainsaw hunt (default on)")
    p.add_argument("--evtx-root", type=Path, default=Path("/mnt/evtx_share/DFIR-Lab-Logs"))
    p.add_argument("--outdir", type=Path, default=Path.home() / "DFIR-Labs" / "ForenSynth" / "Reports")
    p.add_argument("--rules", type=Path, default=Path.home() / "tools" / "sigma" / "rules")
    p.add_argument("--mapping", type=Path, default=Path.home() / "tools" / "chainsaw" / "sigma-event-logs-all.yml")
    p.add_argument("--sigma-root", type=Path, default=None)
    p.add_argument("--make-html", action="store_true", help="Write HTML (self-contained)")
    p.add_argument("--make-pdf", action="store_true", help="(Optional) Produce PDF via external tools (not embedded)")
    p.add_argument("--two-pass", action="store_true", help="Use micro (chunk_model) → final (final_model)")
    p.add_argument("--chunk-size", type=int, default=25)
    p.add_argument("--max-chunks", type=int, default=100)
    p.add_argument("--max-input-tokens", type=int, default=120_000)

    p.add_argument("--chunk-model", default=DEFAULT_CHUNK_MODEL)
    p.add_argument("--final-model", default=DEFAULT_FINAL_MODEL)
    p.add_argument("--llm-timeout", type=int, default=60)
    p.add_argument("--llm-max-retries", type=int, default=6)
    p.add_argument("--llm-temperature", type=float, default=1.0)
    p.add_argument("--rpm", type=int, default=0, help="Requests per minute limit (0 = unlimited)")
    p.add_argument("--micro-workers", type=str, default="1", help="'auto' or integer >=1")
    p.add_argument("--branding", choices=["on", "off"], default="off", help="Add 'Powered by ForenSynth AI' footer")
    p.add_argument("--integrity", choices=["on", "off"], default="off", help="Force models to gpt-5-mini/gpt-5")
    p.add_argument("--fast", action="store_true", help="Shortcut: auto micro-workers and conservative chunk sizes")

    p.add_argument(
        "--pricing-json", type=str, default=None, help='Inline JSON map {"model":{"in":x,"out":y}} to override pricing'
    )

    a = p.parse_args()

    # micro-workers resolution
    if a.fast and str(a.micro_workers).lower() == "1":
        # auto in fast
        try:
            cpu = max(1, os.cpu_count() or 1)
        except Exception:
            cpu = 4
        micro_workers = max(2, min(8, 2 * cpu))
    elif str(a.micro_workers).lower() == "auto":
        try:
            cpu = max(1, os.cpu_count() or 1)
        except Exception:
            cpu = 4
        micro_workers = max(2, min(8, 2 * cpu))
    else:
        micro_workers = max(1, int(a.micro_workers))

    # Fast path also tunes chunking
    chunk_size = a.chunk_size
    max_chunks = a.max_chunks
    if a.fast:
        chunk_size = max(15, min(40, a.chunk_size))
        max_chunks = max(200, a.max_chunks)

    return AppConfig(
        hunt=a.hunt,
        evtx_root=a.evtx_root,
        outdir=a.outdir,
        rules=a.rules,
        mapping=a.mapping,
        sigma_root=a.sigma_root,
        make_html=a.make_html,
        make_pdf=a.make_pdf,
        two_pass=a.two_pass,
        chunk_size=chunk_size,
        max_chunks=max_chunks,
        max_input_tokens=max(4000, a.max_input_tokens),
        chunk_model=a.chunk_model,
        final_model=a.final_model,
        llm_timeout=max(20, a.llm_timeout),
        llm_retries=max(1, a.llm_max_retries),
        llm_temperature=a.llm_temperature,
        rpm=max(0, a.rpm),
        micro_workers=micro_workers,
        branding=a.branding,
        integrity=a.integrity,
        fast=a.fast,
        pricing_json=a.pricing_json,
    )


# ───────────────────────────────────────── Chainsaw ──────────────────────────────────────────
def ensure_chainsaw():
    if shutil.which("chainsaw") is None:
        die("chainsaw not found in PATH")


def latest_container(root: Path) -> Path:
    if not root.exists():
        die(f"EVTX root not found: {root}")
    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs:
        die(f"No subfolders under {root}")
    return max(dirs, key=lambda p: p.stat().st_mtime)


def run_chainsaw_hunt(
    container: Path, rules: Path, mapping: Path, sigma_root: Optional[Path], out_json: Path
) -> Tuple[str, List[str]]:
    ensure_chainsaw()
    rules_dir = rules
    sigma = sigma_root or rules_dir.parent
    cmd = [
        "chainsaw",
        "hunt",
        str(container),
        "--mapping",
        str(mapping),
        "--rule",
        str(rules_dir),
        "-s",
        str(sigma),
        "--json",
        "--output",
        str(out_json),
    ]
    info("Running Chainsaw hunt…")
    res = subprocess.run(cmd, capture_output=True, text=True)
    stdout, stderr = res.stdout, res.stderr
    # print chainsaw banner output generously
    console.print(stdout)
    if res.returncode != 0:
        console.print(stderr)
        die("Chainsaw hunt failed")
    # quick detect counts from stdout
    m = re.search(r"\[\+\]\s+(\d+)\s+Detections\s+found", stdout)
    count = m.group(1) if m else "?"
    ok(f"Chainsaw hunt completed. Detections: {count}")
    return "json", cmd


# ───────────────────────────────────────── Detections IO ─────────────────────────────────────
class LoaderError(Exception): ...


def read_text(path: Path) -> str:
    if not path.exists():
        raise LoaderError(f"file not found: {path}")
    if path.stat().st_size == 0:
        raise LoaderError(f"file is empty: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8-sig")


def parse_detections_auto(text: str) -> List[Dict[str, Any]]:
    # Chainsaw outputs a top-level array of detections (each a dict)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise LoaderError(f"JSON parse error: {e}") from e
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and "detections" in obj and isinstance(obj["detections"], list):
        return obj["detections"]
    raise LoaderError("Unexpected detections JSON shape (expect list or dict.detections)")


def load_detections(path: Path, max_items: int) -> List[Dict[str, Any]]:
    t = read_text(path)
    dets = parse_detections_auto(t)
    if max_items > 0:
        dets = dets[:max_items]
    return dets


# ───────────────────────────────────────── Token utils ───────────────────────────────────────
def encoder() -> tiktoken.Encoding:
    try:
        return tiktoken.get_encoding("cl100k_base")
    except Exception:
        return tiktoken.get_encoding("cl100k_base")


def est_tokens(text: str) -> int:
    try:
        return len(encoder().encode(text))
    except Exception:
        return math.ceil(len(text) / 4)


# ───────────────────────────────────────── Prompt builders ───────────────────────────────────
DEFAULT_SYSTEM_PROMPT = (
    "You are a senior DFIR analyst. Produce concise, accurate summaries. "
    "Group related detections, highlight notable TTPs/tooling, dedupe repetition, "
    "and end with prioritized, actionable recommendations."
)
FINAL_SYSTEM_PROMPT = (
    "You are a DFIR lead. Merge the micro-summaries into a crisp executive report. "
    "Eliminate repetition; group by phases/TTPs; quantify scope where feasible; "
    "finish with prioritized recommendations (High/Med/Low)."
)


def fmt_micro_input(block: List[Dict[str, Any]], include_script_chars: int = 160) -> str:
    lines = ["Summarize these events into <= 12 bullets total (executive tone):"]
    for d in block:
        ts = d.get("timestamp", "N/A")
        name = d.get("name", "(untitled)")
        tags = ", ".join(d.get("tags", []) or [])
        doc = ((d.get("document") or {}).get("data") or {}).get("Event") or {}
        eid = (doc.get("System") or {}).get("EventID") or "N/A"
        script = (doc.get("EventData") or {}).get("ScriptBlockText") or ""
        if isinstance(script, str) and include_script_chars > 0 and script:
            script = script[:include_script_chars] + ("… [truncated]" if len(script) > include_script_chars else "")
            # guard backticks in case model tries to format
            script = script.replace("`", "'")
        ln = f"- [{ts}] {name} (EventID {eid}; Tags: {tags})"
        if script:
            ln += f" | snippet: {script}"
        lines.append(ln)
    return "\n".join(lines)


def build_final_prompt(micros: List[str]) -> str:
    return (
        "=== MICRO REPORTS START ===\n\n" + "\n\n---\n\n".join(micros) + "\n\n=== MICRO REPORTS END ===\n\n"
        "Produce the final executive report now."
    )


# ───────────────────────────────────────── OpenAI calls ──────────────────────────────────────
def safe_temperature(model: str, t: float) -> Optional[float]:
    # Most gpt-5* models accept only default=1.0; pass nothing if t==1.0
    if model.startswith("gpt-5"):
        return None if abs(t - 1.0) < 1e-6 else None  # force default
    return t


def call_llm(
    client: OpenAI, model: str, system: str, user: str, timeout_s: int, retries: int, temperature: float
) -> str:
    time.time()
    last_err: Optional[Exception] = None
    for i in range(retries):
        try:
            payload: Dict[str, Any] = {
                "model": model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "timeout": timeout_s,
            }
            tval = safe_temperature(model, temperature)
            if tval is not None:
                payload["temperature"] = tval
            resp = client.chat.completions.create(**payload)
            return resp.choices[0].message.content or ""
        except (RateLimitError, APITimeoutError, APIConnectionError, APIError, BadRequestError) as e:
            last_err = e
            time.sleep(min(30, 1.5**i + random.uniform(0, 0.3)))
    raise RuntimeError(f"LLM retries exceeded after {retries} attempts: {last_err}")


# ───────────────────────────────────────── Chunking / Overflow ───────────────────────────────
def chunk_list(lst: List[Any], n: int) -> List[List[Any]]:
    return [lst[i : i + n] for i in range(0, len(lst), n)]


def ensure_token_budget_or_split(
    blocks: List[List[Dict[str, Any]]], cfg: AppConfig, system_prompt: str
) -> List[List[Dict[str, Any]]]:
    # Estimate total prompt tokens; split further if overflow
    enc = encoder()

    def est_block_tokens(b: List[Dict[str, Any]]) -> int:
        up = fmt_micro_input(b)
        return len(enc.encode(system_prompt)) + len(enc.encode(up))

    total = sum(est_block_tokens(b) for b in blocks)
    if total <= cfg.max_input_tokens:
        return blocks
    # split recursively by halving chunk size until within budget or minimal
    current = blocks
    size = max(1, len(blocks[0]))
    while total > cfg.max_input_tokens and size > 1:
        size = max(1, size // 2)
        flattened = [item for b in current for item in b]
        current = chunk_list(flattened, size)
        total = sum(est_block_tokens(b) for b in current)
    if total > cfg.max_input_tokens:
        warn(f"Token budget still high ({total} > {cfg.max_input_tokens}). Proceeding with best-effort smaller blocks.")
    return current


# ───────────────────────────────────────── IOC Extraction ────────────────────────────────────
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b", re.I)
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.I)


def extract_iocs(detections: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    text_bucket = []
    for d in detections:
        text_bucket.append(d.get("name", ""))
        # flatten likely strings
        doc = d.get("document", {})
        data = doc.get("data") or {}
        ev = data.get("Event") or {}
        evd = ev.get("EventData") or {}
        for k, v in evd.items():
            if isinstance(v, str):
                text_bucket.append(v)
    blob = "\n".join(text_bucket)
    ips = sorted(set(IP_RE.findall(blob)))
    doms = sorted(set(DOMAIN_RE.findall(blob)))
    sha256 = sorted(set(SHA256_RE.findall(blob)))
    md5 = sorted(set(MD5_RE.findall(blob)))
    return {"ips": ips, "domains": doms, "sha256": sha256, "md5": md5}


def render_ioc_block(iocs: Dict[str, List[str]]) -> str:
    lines = []
    for k in ("ips", "domains", "sha256", "md5"):
        vals = iocs.get(k, [])
        lines.append(f"{k}: {', '.join(vals) if vals else '(none)'}")
    return "\n".join(lines)


# ───────────────────────────────────────── HTML Helpers ──────────────────────────────────────
def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def md_to_html_safe(md: str) -> str:
    # very simple safe converter for basic paragraphs and bullets
    md = md.replace("`", "'")  # avoid TeX-like interpretation in consumers
    lines = md.splitlines()
    out = []
    for ln in lines:
        if ln.strip().startswith("- "):
            # bullet list
            out.append(f"<li>{html_escape(ln.strip()[2:])}</li>")
        else:
            if ln.strip():
                out.append(f"<p>{html_escape(ln)}</p>")
    # wrap bullets into <ul> if consecutive <li>
    html = []
    in_ul = False
    for item in out:
        if item.startswith("<li>"):
            if not in_ul:
                html.append("<ul>")
                in_ul = True
            html.append(item)
        else:
            if in_ul:
                html.append("</ul>")
                in_ul = False
            html.append(item)
    if in_ul:
        html.append("</ul>")
    return "\n".join(html)


def micro_cards_html(micro_sections: List[str]) -> str:
    cards = []
    for i, sec in enumerate(micro_sections, start=1):
        # First line as pseudo title if available
        first_line = next((l.strip("- ").strip() for l in sec.splitlines() if l.strip()), f"Micro Cluster #{i}")
        short_title = (first_line[:90] + "…") if len(first_line) > 90 else first_line
        body_html = md_to_html_safe(sec)
        card = f"""
        <div class="micro-card" id="micro-{i}">
          <div class="micro-header">
            <div class="micro-title">Micro Cluster #{i}: {html_escape(short_title)}</div>
            <div class="micro-meta">#{i}</div>
          </div>
          <div class="micro-body">{body_html}</div>
        </div>
        """
        cards.append(card)
    return "\n".join(cards)


# ───────────────────────────────────────── Costs / Logs / Archive ────────────────────────────
def estimate_cost(
    usages: Dict[str, Tuple[int, int]], pricing_map: Dict[str, Dict[str, float]]
) -> Tuple[float, List[str]]:
    total = 0.0
    lines = []
    for m, (tin, tout) in usages.items():
        p = pricing_map.get(m, {"in": 0.0, "out": 0.0})
        c = (tin / 1000.0) * p["in"] + (tout / 1000.0) * p["out"]
        total += c
        lines.append(f"- {m}: in={tin}, out={tout} → ${c:.6f} (in {p['in']}/k, out {p['out']}/k)")
    return round(total, 6), lines


def append_run_log(
    csv_path: Path,
    *,
    ts: str,
    detections: int,
    runtime_s: int,
    cost: float,
    integrity: str,
    chunk_model: str,
    final_model: str,
):
    write_header = not csv_path.exists()
    with csv_path.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(
                ["timestamp", "detections", "runtime_sec", "cost_usd", "integrity", "chunk_model", "final_model"]
            )
        w.writerow([ts, detections, runtime_s, f"{cost:.6f}", integrity, chunk_model, final_model])


def archive_old_reports(report_dir: Path):
    # move previous .html/.md to archive/YYYY-MM-DD (keep today’s files)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    arch = report_dir / "archive" / today
    arch.mkdir(parents=True, exist_ok=True)
    for p in report_dir.glob("*.html"):
        if today not in p.name:
            shutil.move(str(p), arch / p.name)
    for p in report_dir.glob("*.md"):
        if today not in p.name:
            shutil.move(str(p), arch / p.name)


# ───────────────────────────────────────── Pipeline ──────────────────────────────────────────
def main():
    load_dotenv()
    cfg = parse_args()

    console.rule(f"[bold]🧠 {BRAND_NAME} — DFIR Intelligence Engine {VERSION}[/bold]")
    if cfg.branding == "on":
        info("Branding Mode Active — reports will show ForenSynth AI mark.")
    else:
        info("Clean Report Mode — no branding footer added.")
    if cfg.integrity == "on":
        cfg.chunk_model, cfg.final_model = "gpt-5-mini", "gpt-5"
        warn("🧠 Integrity Mode Active — prioritizing detection accuracy over cost.")

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        die("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)

    # Pricing override
    pricing = dict(PRICING)
    if cfg.pricing_json:
        try:
            pricing.update(json.loads(cfg.pricing_json))
        except Exception as e:
            die(f"Bad --pricing-json: {e}")

    # 1) Hunt
    start_ts = datetime.now(UTC)
    t0 = time.time()
    latest = latest_container(cfg.evtx_root)
    ok(f"Using latest EVTX directory: {latest}")
    out_dir_date = cfg.outdir / start_ts.strftime("%Y-%m-%d_%H%M%SZ")
    out_dir_date.mkdir(parents=True, exist_ok=True)
    detections_json = out_dir_date / "detections.json"

    if cfg.hunt:
        run_chainsaw_hunt(latest, cfg.rules, cfg.mapping, cfg.sigma_root, detections_json)
    else:
        info(f"Skipping hunt; using existing {detections_json}")

    # 2) Load detections
    try:
        detections = load_detections(detections_json, max_items=0)
    except LoaderError as e:
        die(f"Failed to load detections: {e}")

    det_count = len(detections)
    if det_count == 0:
        warn("No Sigma detections found — skipping summarization to save tokens.")
        empty_md = "# ForenSynth Report\n\nNo detections were produced by Chainsaw/Sigma for this dataset."
        md_path = out_dir_date / f"forensynth_summary_{start_ts.strftime('%Y-%m-%d')}.md"
        html_path = out_dir_date / f"forensynth_report_{start_ts.strftime('%Y-%m-%d')}.html"
        md_path.write_text(empty_md, encoding="utf-8")
        html = HTML_TEMPLATE.replace("{{REPORT_TITLE}}", f"ForenSynth Report — {start_ts.strftime('%Y-%m-%d')}")
        html = html.replace("{{SUBTITLE}}", "No detections; summarization skipped.")
        html = html.replace("{{DETECTION_COUNT}}", "0")
        html = html.replace("{{INTEGRITY}}", "ON" if cfg.integrity == "on" else "OFF")
        html = html.replace("{{MICRO_MODEL}}", cfg.chunk_model)
        html = html.replace("{{FINAL_MODEL}}", cfg.final_model if cfg.two_pass else cfg.chunk_model)
        html = html.replace("{{RUNTIME}}", "0s")
        html = html.replace("{{COST}}", "0.000000")
        html = html.replace("{{START_TS}}", start_ts.isoformat(timespec="seconds") + "Z")
        html = html.replace("{{END_TS}}", datetime.utcnow().isoformat(timespec="seconds") + "Z")
        html = html.replace("{{EXEC_HTML}}", md_to_html_safe("No activity to summarize."))
        html = html.replace("{{MICRO_CARDS}}", "")
        html = html.replace("{{IOC_BLOCK}}", "(none)")
        html = html.replace(
            "{{ENV_BLOCK}}", f"Rules={cfg.rules}\nMapping={cfg.mapping}\nSigmaRoot={cfg.sigma_root or cfg.rules.parent}"
        )
        html = html.replace("{{REPORT_CSS}}", REPORT_CSS)
        footer = (
            "<p>Powered by <strong>ForenSynth AI™</strong> — Automated DFIR Intelligence Engine</p>"
            if cfg.branding == "on"
            else ""
        )
        html = html.replace("{{FOOTER}}", footer)
        html_path.write_text(html, encoding="utf-8")
        ok(f"Empty report written: {html_path}")
        return

    # Environment blurb
    env_block = (
        f"Rules={cfg.rules}\nMapping={cfg.mapping}\nSigmaRoot={cfg.sigma_root or cfg.rules.parent}\nEVTX={latest}"
    )

    # 3) Micro summaries (parallel if configured) with token overflow protection
    info(f"Detections found ({det_count}) — generating micro-summaries…")
    base_chunk = cfg.chunk_size
    blocks = chunk_list(detections, base_chunk)
    blocks = ensure_token_budget_or_split(blocks, cfg, DEFAULT_SYSTEM_PROMPT)

    micro_texts: List[str] = []
    in_tok = 0
    out_tok = 0
    usages: Dict[str, Tuple[int, int]] = {}

    def do_micro(b: List[Dict[str, Any]]) -> Tuple[str, int, int]:
        user_prompt = fmt_micro_input(b)
        _in = est_tokens(DEFAULT_SYSTEM_PROMPT) + est_tokens(user_prompt)
        txt = call_llm(
            client,
            cfg.chunk_model,
            DEFAULT_SYSTEM_PROMPT,
            user_prompt,
            cfg.llm_timeout,
            cfg.llm_retries,
            cfg.llm_temperature,
        )
        _out = est_tokens(txt)
        return txt, _in, _out

    if cfg.micro_workers > 1:
        with ThreadPoolExecutor(max_workers=cfg.micro_workers) as ex:
            futs = [ex.submit(do_micro, b) for b in blocks]
            for i, f in enumerate(as_completed(futs), start=1):
                try:
                    txt, _in, _out = f.result()
                except Exception as e:
                    txt, _in, _out = (f"**[Micro failure]** {e}", 0, 0)
                micro_texts.append(txt)
                in_tok += _in
                out_tok += _out
    else:
        for b in blocks:
            txt, _in, _out = do_micro(b)
            micro_texts.append(txt)
            in_tok += _in
            out_tok += _out

    usages[cfg.chunk_model] = (in_tok, out_tok)

    # 4) Final executive summary
    exec_html = ""
    final_in = final_out = 0
    if cfg.two_pass:
        info("Compiling executive summary with final model…")
        final_user = build_final_prompt(micro_texts)
        final_in = est_tokens(FINAL_SYSTEM_PROMPT) + est_tokens(final_user)
        final_txt = call_llm(
            client,
            cfg.final_model,
            FINAL_SYSTEM_PROMPT,
            final_user,
            cfg.llm_timeout,
            cfg.llm_retries,
            cfg.llm_temperature,
        )
        final_out = est_tokens(final_txt)
        exec_html = md_to_html_safe(final_txt)
        usages[cfg.final_model] = (
            usages.get(cfg.final_model, (0, 0))[0] + final_in,
            usages.get(cfg.final_model, (0, 0))[1] + final_out,
        )
    else:
        # If not two-pass, use first micro as exec
        exec_html = md_to_html_safe(micro_texts[0] if micro_texts else "No content")

    # 5) Build HTML
    iocs = extract_iocs(detections)
    ioc_block = html_escape(render_ioc_block(iocs))
    micro_cards = micro_cards_html(micro_texts)

    total_cost, lines = estimate_cost(usages, pricing)

    stop_ts = datetime.now(UTC)
    runtime_s = int(time.time() - t0)

    title = f"{BRAND_NAME} Report — {start_ts.strftime('%Y-%m-%d %H:%MZ')}"
    html = (
        HTML_TEMPLATE.replace("{{REPORT_TITLE}}", html_escape(title))
        .replace("{{SUBTITLE}}", "Automated DFIR Intelligence Summary")
        .replace("{{DETECTION_COUNT}}", str(det_count))
        .replace("{{INTEGRITY}}", "ON" if cfg.integrity == "on" else "OFF")
        .replace("{{MICRO_MODEL}}", html_escape(cfg.chunk_model))
        .replace("{{FINAL_MODEL}}", html_escape(cfg.final_model if cfg.two_pass else cfg.chunk_model))
        .replace("{{RUNTIME}}", f"{runtime_s}s")
        .replace("{{COST}}", f"{total_cost:.6f}")
        .replace("{{START_TS}}", start_ts.isoformat(timespec="seconds") + "Z")
        .replace("{{END_TS}}", stop_ts.isoformat(timespec="seconds") + "Z")
        .replace("{{EXEC_HTML}}", exec_html)
        .replace("{{MICRO_CARDS}}", micro_cards)
        .replace("{{IOC_BLOCK}}", ioc_block)
        .replace("{{ENV_BLOCK}}", html_escape(env_block))
        .replace("{{REPORT_CSS}}", REPORT_CSS)
        .replace(
            "{{FOOTER}}",
            "<p>Powered by <strong>ForenSynth AI™</strong> — Automated DFIR Intelligence Engine</p>"
            if cfg.branding == "on"
            else "",
        )
    )

    # 6) Write outputs + archive + run log
    html_path = out_dir_date / f"forensynth_report_{start_ts.strftime('%Y-%m-%d')}.html"
    md_path = out_dir_date / f"forensynth_summary_{start_ts.strftime('%Y-%m-%d')}.md"
    md_path.write_text("## Executive Summary (see HTML for full formatting)\n\n", encoding="utf-8")
    md_path.write_text(md_path.read_text(encoding="utf-8") + re.sub(r"<[^>]+>", "", exec_html), encoding="utf-8")
    html_path.write_text(html, encoding="utf-8")

    ok(f"Report written: {html_path}")
    ok(f"Summary MD:     {md_path}")

    archive_old_reports(out_dir_date.parent)  # archive sibling reports (previous runs in root report dir)
    ok("Archived previous reports into /archive/YYYY-MM-DD/")

    runlog = out_dir_date.parent / "run_log.csv"
    append_run_log(
        runlog,
        ts=start_ts.isoformat(timespec="seconds") + "Z",
        detections=det_count,
        runtime_s=runtime_s,
        cost=total_cost,
        integrity=cfg.integrity,
        chunk_model=cff(cfg.chunk_model),
        final_model=cff(cfg.final_model if cfg.two_pass else cfg.chunk_model),
    )
    ok(f"Run logged: {runlog}")

    # 7) Console cost details
    console.rule("[bold]Cost Breakdown[/bold]")
    for ln in lines:
        console.print(f"[cyan]{ln}[/cyan]")
    console.print(f"[cyan]Total cost: ${total_cost:.6f}[/cyan]")
    console.rule("[bold]Done[/bold]")


def cff(s: str) -> str:
    # compact friendly format
    return s.replace("gpt-5-", "5-").replace("gpt-3.5-", "3.5-")


if __name__ == "__main__":
    main()
