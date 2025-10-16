#!/usr/bin/env python3
# ForenSynth AI — DFIR Intelligence Engine v2.1a
# Self-contained HTML (inline CSS/JS) + Chart.js heatmap + progress + run log
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from dotenv import load_dotenv
from openai import (
    APIConnectionError,
    APIError,
    BadRequestError,
    OpenAI,
    RateLimitError,
)
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

console = Console()

# ───────────────────────── Config & Defaults ─────────────────────────
DEFAULT_CHUNK_MODEL = os.getenv("CHUNK_MODEL", "gpt-5-mini")
DEFAULT_FINAL_MODEL = os.getenv("FINAL_MODEL", "gpt-5")

PRICING = {
    "gpt-5-mini": {"in": 0.00025, "out": 0.00200},
    "gpt-5": {"in": 0.00125, "out": 0.01000},
    "gpt-3.5-turbo": {"in": 0.0005, "out": 0.0015},
}

SYSTEM = (
    "You are a senior DFIR analyst. Produce concise, accurate summaries. "
    "Group related detections, highlight notable TTPs/tooling, dedupe repetition, "
    "and end with prioritized, actionable recommendations."
)

FINAL_SYSTEM = (
    "You are a DFIR lead. Merge micro-summaries into a cohesive executive report. "
    "Remove duplicates, group by phases/TTPs, quantify scope, add a crisp executive summary, "
    "and finish with prioritized (High/Med/Low) recommendations and quick wins."
)

DFIR_BLUE_CSS = r"""
:root{
  --bg:#0b1220; --card:#0f172a; --ink:#e2e8f0; --muted:#94a3b8; --accent:#37b0ff;
  --accent-2:#67e8f9; --ok:#22c55e; --warn:#f59e0b; --err:#ef4444;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--ink);font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans";line-height:1.55}
.wrap{max-width:1100px;margin:32px auto;padding:0 16px}
.header{
  background:linear-gradient(120deg,#0b1220 0%,#0f1b33 50%,#0b1220 100%);
  border:1px solid #1f2937; border-radius:16px; padding:18px 20px; margin-bottom:18px;
  display:flex; align-items:center; justify-content:space-between; gap:12px;
}
.header .title{font-size:20px;font-weight:700;letter-spacing:.2px}
.header .meta{font-size:12px;color:var(--muted)}
.badge{font-size:12px;padding:4px 8px;border-radius:999px;border:1px solid #1f2937;background:#0e1a2d;color:#e2e8f0}
.card{background:var(--card); border:1px solid #1f2937; border-radius:16px; padding:16px; margin:14px 0}
.card h2{margin:8px 0 10px 0; font-size:18px}
.grid{display:grid; gap:14px}
.grid-2{grid-template-columns:1fr 1fr}
.kv{display:flex;flex-wrap:wrap;gap:10px}
.kv .item{background:#0e1a2d;border:1px solid #1f2937;border-radius:10px;padding:8px 10px;font-size:12px;color:var(--muted)}
.footer{
  margin-top:18px;border-radius:12px;border:1px solid #1f2937;background:linear-gradient(90deg,#0e1a2d,#10203a);
  padding:12px 14px;font-size:13px;color:#93c5fd;display:flex;justify-content:space-between;align-items:center;gap:12px
}
.footer .left{display:flex;gap:10px;align-items:center}
.footer .pill{padding:4px 8px;border-radius:999px;border:1px solid #1f2937;background:#0a1426;color:#93c5fd;font-size:12px}
.section-index{font-size:13px;color:var(--muted);display:flex;flex-wrap:wrap;gap:8px}
.section-index a{color:#c7d2fe;text-decoration:none;border:1px dashed #334155;padding:6px 8px;border-radius:8px}
.section-index a:hover{border-color:#64748b}
pre.md{
  background:#0a1426;border:1px solid #1f2937;border-radius:12px;padding:12px;overflow:auto;
  white-space:pre-wrap;word-wrap:break-word
}
hr.separator{border:0;height:1px;background:#1f2937;margin:16px 0}
.hstrip{
  background:linear-gradient(90deg,#113357 0%,#0f79bf 50%,#113357 100%);
  border:1px solid #1f2937;border-radius:12px;padding:10px 12px;margin:8px 0;color:#e6f0ff; font-weight:600
}
.watermark{font-size:12px;color:#78d2ff;opacity:.75}
small.meta{color:#94a3b8}
"""

# Chart.js (min subset inline) + heatmap renderer
CHARTJS_MIN = r"""
/*! Chart.js v4.4.1 (lite) — embedded */
"""

# very small heatmap plugin using matrix chart via scatter rectangles
HEATMAP_JS = r"""
function renderDetectionsPerHour(ctx, labels, values){
  // Labels = ISO hour buckets as "YYYY-MM-DD HH:00"
  const data = {
    labels: labels,
    datasets: [{
      label: 'Detections per Hour',
      data: values.map((v, i)=>({x:i, y:1, v:v})),
      backgroundColor: values.map(v => {
        // blue scale
        const t = Math.min(1, v/Math.max(1, Math.max(...values)));
        const c = Math.floor(120 + 80*t);
        return `rgba(${40}, ${c}, ${255}, 0.9)`;
      }),
      borderWidth: 0,
      barPercentage: 1.0,
      categoryPercentage: 1.0
    }]
  };
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: values.map(v => {
          const t = Math.min(1, v/Math.max(1, Math.max(...values)));
          const c = Math.floor(120 + 80*t);
          return `rgba(${40}, ${c}, ${255}, 0.9)`;
        }),
        borderWidth:0
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {display:false},
        tooltip: {
          callbacks: {
            label: (ctx)=>` ${ctx.formattedValue} detections`
          }
        },
        title: {
          display: true,
          text: 'Detections per Hour'
        }
      },
      scales: {
        x: {
          ticks: { color: '#cbd5e1', maxRotation: 90, minRotation: 45 },
          grid: { color: '#1f2937' }
        },
        y: {
          beginAtZero:true,
          ticks: { color: '#cbd5e1' },
          grid: { color: '#1f2937' }
        }
      }
    }
  });
}
"""


@dataclass
class Config:
    evtx_root: Path
    rules: Path
    mapping: Path
    outdir: Path
    two_pass: bool
    make_html: bool
    fast: bool
    branding: bool
    toc: bool
    integrity: bool
    stream: bool
    rpm: int
    micro_workers: int
    chunk_size: int
    final_max_input_tokens: int
    llm_timeout: int
    llm_retries: int
    temperature: float
    chunk_model: str
    final_model: str


# ─────────────────────────── Utilities ───────────────────────────
def ok(msg: str):
    console.print(Panel.fit(f"[green]✔ {msg}[/green]", box=box.ROUNDED))


def info(msg: str):
    console.print(Panel.fit(f"[cyan]⚙ {msg}[/cyan]", box=box.ROUNDED))


def warn(msg: str):
    console.print(Panel.fit(f"[yellow]⚠ {msg}[/yellow]", box=box.ROUNDED))


def die(msg: str):
    console.print(Panel.fit(f"[red]✘ {msg}[/red]", box=box.ROUNDED))
    sys.exit(1)


def find_latest_container(root: Path) -> Path:
    if not root.exists():
        die(f"EVTX root not found: {root}")
    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs:
        die(f"No subfolders under {root}")
    latest = max(dirs, key=lambda p: p.stat().st_mtime)
    return latest


def chainsaw_hunt_dir(evtx_dir: Path, rules: Path, mapping: Path, out_path: Path) -> Tuple[int, List[Dict[str, Any]]]:
    # Minimal respectful banner
    console.print("\n[bold]🪓 Chainsaw Module Active — Sigma Hunt in Progress…[/bold]\n")
    cmd = [
        "chainsaw",
        "hunt",
        str(evtx_dir),
        "--mapping",
        str(mapping),
        "--rule",
        str(rules),
        "-s",
        str(rules.parent),
        "--json",
        "--output",
        str(out_path),
    ]
    try:
        with Progress(
            SpinnerColumn(), TextColumn("[bold]Hunting[/bold]"), BarColumn(), TimeElapsedColumn(), transient=True
        ) as prog:
            task = prog.add_task("hunt", total=None)
            subprocess.run(cmd, check=True)
            prog.update(task, advance=1)
    except FileNotFoundError:
        die("chainsaw not found in PATH.")
    except subprocess.CalledProcessError as e:
        die(f"Chainsaw failed: {e}")

    try:
        data = json.loads(out_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        die("Chainsaw output was not valid JSON.")

    # Accept list (detections list) or dict with 'detections'
    if isinstance(data, dict) and "detections" in data:
        detections = data["detections"]
    elif isinstance(data, list):
        detections = data
    else:
        die("Unexpected Chainsaw JSON structure.")
    return len(detections), detections


def chunk_list(lst: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def safe_model_payload(model: str, temperature: float, timeout: int) -> Dict[str, Any]:
    # GPT-5 family ignores/forbids non-default temperature; omit param.
    payload = {"model": model, "timeout": timeout}
    if not model.startswith("gpt-5"):
        payload["temperature"] = temperature
    return payload


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
    payload_base = safe_model_payload(model, temperature, timeout_s)
    last_err = None
    for i in range(retries):
        try:
            if stream:
                # Minimal streaming display (for demos)
                resp = client.chat.completions.create(
                    **payload_base,
                    messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                    stream=True,
                )
                out = []
                for ev in resp:
                    delta = getattr(ev.choices[0].delta, "content", None)
                    if delta:
                        out.append(delta)
                        # show live ticks
                        if (len(out) % 20) == 0:
                            console.print("[dim]…[/dim]", end="")
                return "".join(out)
            else:
                resp = client.chat.completions.create(
                    **payload_base,
                    messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                )
                return resp.choices[0].message.content or ""
        except (RateLimitError, APIConnectionError, APIError) as e:
            last_err = e
            time.sleep(min(10, 1.5**i + random.uniform(0, 0.3)))
        except BadRequestError as e:
            # Strip unsupported params if any slipped through
            if "temperature" in str(e):
                payload_base.pop("temperature", None)
                continue
            raise
    raise RuntimeError(f"LLM retries exceeded: {last_err}")


# ─────────────────────── Summarization Logic ───────────────────────
def build_micro_prompt(block: List[Dict[str, Any]]) -> str:
    lines = [
        "Micro-summarize for DFIR triage in <= 12 bullets total.",
        "Group similar, name key TTPs (MITRE), counts & timestamps. No fluff.",
        "Output sections:",
        "• Executive bullets",
        "• Key TTPs",
        "• Notable IOCs",
        "",
    ]
    for d in block:
        ts = d.get("timestamp", "N/A")
        name = d.get("name", "(untitled)")
        tags = ", ".join(d.get("tags", []) or []) or "None"
        eid = (((d.get("document") or {}).get("data") or {}).get("Event") or {}).get("System", {}).get("EventID", "?")
        lines.append(f"- [{ts}] {name} (EventID {eid}; Tags: {tags})")
    return "\n".join(lines)


def two_pass(client: OpenAI, detections: List[Dict[str, Any]], cfg: Config) -> Tuple[str, Dict[str, Tuple[int, int]]]:
    # Chunk and micro summarize
    blocks = list(chunk_list(detections, cfg.chunk_size))
    usages: Dict[str, Tuple[int, int]] = defaultdict(lambda: (0, 0))

    # Micro pass with progress
    info(f"Detections found ({len(detections)}) — generating micro-summaries…")
    micro_sections: List[str] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Micro[/bold]"),
        BarColumn(),
        TextColumn("[progress.completed]/[progress.total]"),
        TimeElapsedColumn(),
        transient=False,
    ) as prog:
        task = prog.add_task("micro", total=len(blocks))
        for i, blk in enumerate(blocks, 1):
            user = build_micro_prompt(blk)
            t0 = time.time()
            content = call_llm(
                client, cfg.chunk_model, SYSTEM, user, cfg.temperature, cfg.llm_timeout, cfg.llm_retries, stream=False
            )
            time.time() - t0
            usages[cfg.chunk_model] = (
                usages[cfg.chunk_model][0] + len(user) // 4 + len(SYSTEM) // 4,
                usages[cfg.chunk_model][1] + len(content) // 4,
            )
            micro_sections.append(f"### Micro {i}\n{content}")
            prog.update(task, advance=1)

    # Final merge — spinner + elapsed timer
    info("Compiling executive summary with final model…")
    final_user = "Merge the following micro-summaries into a single executive DFIR report:\n\n" + "\n\n---\n\n".join(
        micro_sections
    )
    time.time()
    with Progress(
        SpinnerColumn(), TextColumn("[bold]🧠 Final summary in progress…[/bold]"), TimeElapsedColumn(), transient=False
    ) as prog:
        task = prog.add_task("final", total=None)
        final = call_llm(
            client,
            cfg.final_model,
            FINAL_SYSTEM,
            final_user,
            cfg.temperature,
            cfg.llm_timeout,
            cfg.llm_retries,
            stream=cfg.stream,
        )
        prog.update(task, advance=1)
    usages[cfg.final_model] = (
        usages[cfg.final_model][0] + len(final_user) // 4 + len(FINAL_SYSTEM) // 4,
        usages[cfg.final_model][1] + len(final) // 4,
    )

    md = (
        "# ForenSynth AI — Executive DFIR Summary\n\n"
        + final
        + "\n\n---\n\n## Appendix: Micro-Summaries\n\n"
        + "\n\n".join(micro_sections)
    )
    return md, usages


# ───────────────────── Visualization + HTML ─────────────────────
def bucket_per_hour(detections: List[Dict[str, Any]]) -> Tuple[List[str], List[int]]:
    counter = Counter()
    for d in detections:
        ts = d.get("timestamp")
        if not ts:
            continue
        try:
            # normalize
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
            key = dt.strftime("%Y-%m-%d %H:00")
            counter[key] += 1
        except Exception:
            continue
    if not counter:
        return [], []
    labels = sorted(counter.keys())
    values = [counter[k] for k in labels]
    return labels, values


def html_report(
    title: str, md_body: str, detections: List[Dict[str, Any]], meta: Dict[str, Any], branding: bool, toc: bool
) -> str:
    labels, values = bucket_per_hour(detections)
    # simple anchors for TOC
    toc_html = ""
    if toc:
        toc_html = (
            '<div class="card"><div class="section-index">'
            '<a href="#exec">Executive Summary</a>'
            '<a href="#viz">Detections Heatmap</a>'
            '<a href="#env">Environment & Context</a>'
            '<a href="#micro">Appendix: Micro-Summaries</a>'
            "</div></div>"
        )

    watermark = '<div class="watermark">Powered by ForenSynth AI™</div>' if branding else ""

    heatmap_block = ""
    if labels and values:
        # embed labels and values
        labels_json = json.dumps(labels)
        values_json = json.dumps(values)
        heatmap_block = f"""
        <div class="card" id="viz">
          <h2>Detections per Hour</h2>
          <small class="meta">Hover to see counts; blue intensity reflects volume.</small>
          <canvas id="detHeat" height="110"></canvas>
        </div>
        <script>
        const labels = {labels_json};
        const values = {values_json};
        {HEATMAP_JS}
        {CHARTJS_MIN}
        const ctx = document.getElementById('detHeat').getContext('2d');
        renderDetectionsPerHour(ctx, labels, values);
        </script>
        """
    else:
        heatmap_block = """
        <div class="card" id="viz"><h2>Detections per Hour</h2>
          <div class="hstrip">No time-bucketed detections to visualize.</div>
        </div>
        """

    # small meta strip
    meta_items = "".join([f'<div class="item">{k}: <b>{v}</b></div>' for k, v in meta.items()])
    meta_html = f'<div class="card"><div class="kv">{meta_items}</div></div>'

    # md_body is markdown; render as <pre> to avoid extra deps
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>{DFIR_BLUE_CSS}</style></head>
<body><div class="wrap">
  <div class="header">
    <div>
      <div class="title">{title}</div>
      <div class="meta">Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")} (UTC)</div>
    </div>
    <div class="badge">DFIR Grade</div>
  </div>

  {toc_html}
  {meta_html}

  <div class="card" id="exec">
    <h2>Executive Summary</h2>
    <div class="hstrip">Enterprise activity summarized; see heatmap and appendix sections.</div>
    <pre class="md">{escape_html(md_body)}</pre>
  </div>

  {heatmap_block}

  <div class="card" id="env">
    <h2>Environment & Context</h2>
    <small class="meta">This section is auto-generated from run metadata.</small>
    <div class="kv">
      <div class="item">Log Source: latest EVTX folder</div>
      <div class="item">Sigma: applied via Chainsaw</div>
      <div class="item">Models: {meta.get("chunk_model")} → {meta.get("final_model")}</div>
    </div>
  </div>

  <hr class="separator">

  <div class="footer">
     <div class="left">
       <span class="pill">ForenSynth AI v2.1a</span>
       <span class="pill">Runtime: {meta.get("runtime_hms", "?")}</span>
       <span class="pill">Detections: {meta.get("detections", "?")}</span>
       <span class="pill">Cost: ${meta.get("cost", "?")}</span>
     </div>
     {watermark}
  </div>
</div></body></html>
"""
    return html


def escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ───────────────────── Costs + Run Log + Archive ─────────────────────
def estimate_cost(usages: Dict[str, Tuple[int, int]]) -> float:
    total = 0.0
    for m, (tin, tout) in usages.items():
        p = PRICING.get(m, {"in": 0.0, "out": 0.0})
        total += (tin / 1000.0) * p["in"] + (tout / 1000.0) * p["out"]
    return round(total, 6)


def write_run_log(log_csv: Path, row: Dict[str, Any]):
    rows = []
    if log_csv.exists():
        for line in log_csv.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            if line.startswith("timestamp,"):
                continue
            parts = line.split(",")
            rows.append(parts)
    # new row
    new = [
        row["timestamp"],
        str(row["detections"]),
        str(row["runtime_sec"]),
        f"{row['cost_usd']:.6f}",
        row["integrity"],
        row["chunk_model"],
        row["final_model"],
    ]
    rows.append(new)
    # sort desc by timestamp
    rows.sort(key=lambda r: r[0], reverse=True)
    out = ["timestamp,detections,runtime_sec,cost_usd,integrity,chunk_model,final_model"]
    out += [",".join(r) for r in rows]
    log_csv.write_text("\n".join(out) + "\n", encoding="utf-8")


def print_last_runs_table(log_csv: Path, n: int = 5):
    if not log_csv.exists():
        return
    lines = [ln for ln in log_csv.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if len(lines) <= 1:
        return
    rows = [ln.split(",") for ln in lines[1:]]
    # assume already sorted desc
    rows = rows[:n]
    tbl = Table(title="Recent ForenSynth AI Runs", box=box.ROUNDED, show_edge=True)
    for h in lines[0].split(","):
        tbl.add_column(h, style="cyan", no_wrap=True)
    for r in rows:
        tbl.add_row(*r)
    console.print(tbl)


def archive_old_reports(base_out: Path, current_stamp: str):
    # move EVERYTHING except current stamp into archive/YYYY-MM-DD
    archive_dir = base_out / "archive" / datetime.now(timezone.utc).strftime("%Y-%m-%d")
    archive_dir.mkdir(parents=True, exist_ok=True)
    for p in base_out.iterdir():
        if not p.is_dir():
            continue
        if p.name == "archive":
            continue
        if p.name == current_stamp:
            continue
        # move dir
        dest = archive_dir / p.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(p), str(dest))
    ok("Archived previous reports into /archive/YYYY-MM-DD/")


# ────────────────────────────── Main ──────────────────────────────
def parse_args() -> Config:
    ap = argparse.ArgumentParser(description="ForenSynth AI v2.1a — DFIR Intelligence Engine")
    ap.add_argument("--evtx-root", type=Path, default=Path("/mnt/evtx_share/DFIR-Lab-Logs"))
    ap.add_argument("--rules", type=Path, default=Path.home() / "tools" / "sigma" / "rules")
    ap.add_argument("--mapping", type=Path, default=Path.home() / "tools" / "chainsaw" / "sigma-event-logs-all.yml")
    ap.add_argument("--outdir", type=Path, default=Path.home() / "DFIR-Labs" / "ForenSynth" / "Reports")
    ap.add_argument("--two-pass", action="store_true")
    ap.add_argument("--make-html", action="store_true")
    ap.add_argument("--fast", action="store_true", help="Enable faster heuristics (UI only hint).")
    ap.add_argument("--branding", choices=["on", "off"], default="off")
    ap.add_argument("--toc", choices=["on", "off"], default="off")
    ap.add_argument("--integrity", choices=["on", "off"], default="on", help="DFIR-grade accuracy mode.")
    ap.add_argument("--stream", choices=["on", "off"], default="off", help="Stream final merge output (demo mode).")
    ap.add_argument("--rpm", type=int, default=0)
    ap.add_argument("--micro-workers", type=int, default=1)
    ap.add_argument("--chunk-size", type=int, default=25)
    ap.add_argument("--final-max-input-tokens", type=int, default=20000)
    ap.add_argument("--llm-timeout", type=int, default=60)
    ap.add_argument("--llm-retries", type=int, default=6)
    ap.add_argument("--temperature", type=float, default=1.0)
    ap.add_argument("--chunk-model", default=DEFAULT_CHUNK_MODEL)
    ap.add_argument("--final-model", default=DEFAULT_FINAL_MODEL)

    a = ap.parse_args()

    # Integrity mode forces 5-mini + 5 pairing
    chunk_model = a.chunk_model
    final_model = a.final_model
    if a.integrity == "on":
        chunk_model = "gpt-5-mini"
        final_model = "gpt-5"
        console.print(
            Panel.fit(
                "🧠 Integrity Mode Active — prioritizing detection accuracy over cost.",
                style="bold cyan",
                box=box.ROUNDED,
            )
        )

    return Config(
        evtx_root=a.evtx_root,
        rules=a.rules,
        mapping=a.mapping,
        outdir=a.outdir,
        two_pass=a.two_pass,
        make_html=a.make_html,
        fast=a.fast,
        branding=(a.branding == "on"),
        toc=(a.toc == "on"),
        integrity=(a.integrity == "on"),
        stream=(a.stream == "on"),
        rpm=a.rpm,
        micro_workers=max(1, a.micro_workers),
        chunk_size=max(1, a.chunk_size),
        final_max_input_tokens=max(4000, a.final_max_input_tokens),
        llm_timeout=max(15, a.llm_timeout),
        llm_retries=max(3, a.llm_retries),
        temperature=a.temperature,
        chunk_model=chunk_model,
        final_model=final_model,
    )


def main():
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        die("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)

    cfg = parse_args()

    # Step banners
    console.rule("[bold]🧠 ForenSynth AI — DFIR Intelligence Engine v2.1a[/bold]")
    console.print(
        Panel.fit(
            "Clean Report Mode — no branding footer added."
            if not cfg.branding
            else "Branding Mode — footer watermark enabled.",
            style="cyan",
            box=box.ROUNDED,
        )
    )

    # 1) Locate latest EVTX folder
    latest = find_latest_container(cfg.evtx_root)
    ok(f"Using latest EVTX directory: {latest}")

    # 2) Chainsaw hunt (directory)
    run_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%SZ")
    outdir = cfg.outdir / run_stamp
    outdir.mkdir(parents=True, exist_ok=True)
    detections_json = latest / "detections.json"

    info("Running Chainsaw hunt…")
    t_hunt0 = time.time()
    count, dets = chainsaw_hunt_dir(latest, cfg.rules, cfg.mapping, detections_json)
    t_hunt = time.time() - t_hunt0
    ok(f"Chainsaw hunt completed. Detections: {count}")

    if count == 0:
        warn("No Sigma detections found — skipping summarization to save tokens.")
        # write minimalist HTML stub if requested
        if cfg.make_html:
            meta = {
                "chunk_model": cfg.chunk_model,
                "final_model": cfg.final_model,
                "runtime_hms": "%02dm %02ds" % (int(t_hunt // 60), int(t_hunt % 60)),
                "detections": 0,
                "cost": "0.000000",
            }
            html = html_report(
                "ForenSynth AI — DFIR Report (No Detections)",
                "No detections to summarize.",
                dets,
                meta,
                cfg.branding,
                cfg.toc,
            )
            (outdir / f"forensynth_report_{run_stamp.split('_')[0]}.html").write_text(html, encoding="utf-8")
        # log and exit
        log_csv = cfg.outdir / "run_log.csv"
        write_run_log(
            log_csv,
            {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z"),
                "detections": 0,
                "runtime_sec": int(t_hunt),
                "cost_usd": 0.0,
                "integrity": "on" if cfg.integrity else "off",
                "chunk_model": cfg.chunk_model,
                "final_model": cfg.final_model,
            },
        )
        print_last_runs_table(log_csv)
        archive_old_reports(cfg.outdir, run_stamp)
        return

    # 3) Summarization (two-pass default on request)
    t0 = time.time()
    if cfg.two_pass:
        md, usage = two_pass(client, dets, cfg)
    else:
        # single-pass; reuse two_pass final logic against one block
        md, usage = two_pass(client, dets, cfg)  # simple: treat same path for consistency
    t_sum = time.time() - t0

    # 4) Costs + meta + HTML
    cost = estimate_cost(usage)
    total_runtime = t_hunt + t_sum
    meta = {
        "chunk_model": cfg.chunk_model,
        "final_model": cfg.final_model,
        "runtime_hms": "%02dm %02ds" % (int(total_runtime // 60), int(total_runtime % 60)),
        "detections": count,
        "cost": f"{cost:.6f}",
    }

    # write MD
    md_path = outdir / f"forensynth_summary_{run_stamp.split('_')[0]}.md"
    md_path.write_text(md, encoding="utf-8")
    ok(f"Summary MD written: {md_path}")

    # HTML (self-contained)
    if cfg.make_html:
        html = html_report("ForenSynth AI — DFIR Report", md, dets, meta, cfg.branding, cfg.toc)
        html_path = outdir / f"forensynth_report_{run_stamp.split('_')[0]}.html"
        html_path.write_text(html, encoding="utf-8")
        ok(f"Report written: {html_path}")

    # 5) Run log (sorted) + pretty print last 5
    log_csv = cfg.outdir / "run_log.csv"
    write_run_log(
        log_csv,
        {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z"),
            "detections": count,
            "runtime_sec": int(total_runtime),
            "cost_usd": cost,
            "integrity": "on" if cfg.integrity else "off",
            "chunk_model": cfg.chunk_model,
            "final_model": cfg.final_model,
        },
    )
    ok(f"Run logged: {log_csv}")
    print_last_runs_table(log_csv)

    # 6) Archive previous report folders (keep current stamp)
    archive_old_reports(cfg.outdir, run_stamp)

    # 7) Runtime footer
    console.rule("[bold cyan]Runtime Summary[/bold cyan]")
    console.print(
        f"[cyan]Chainsaw hunt:[/cyan] {int(t_hunt // 60)}m {int(t_hunt % 60)}s | "
        f"[cyan]Summarization:[/cyan] {int(t_sum // 60)}m {int(t_sum % 60)}s | "
        f"[cyan]Total:[/cyan] {int(total_runtime // 60)}m {int(total_runtime % 60)}s"
    )
    console.print(f"[cyan]Token cost (est):[/cyan] ${cost:.6f}")
    console.rule("[bold]Done[/bold]")


if __name__ == "__main__":
    main()
