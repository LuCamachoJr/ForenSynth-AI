# File: chainsaw_summarizer_5.py
from __future__ import annotations

import argparse
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
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
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

# Optional YAML for pricing files
try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# ─────────────────────────── Console & Defaults ───────────────────────────
console = Console()

CHUNK_MODEL = os.getenv("CHUNK_MODEL", "gpt-5-mini")
FINAL_MODEL = os.getenv("FINAL_MODEL", "gpt-5")

MAX_LLM_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "8"))
REQ_TIMEOUT_S = int(os.getenv("LLM_TIMEOUT", "30"))  # tighter default
# Default 1.0; many models only accept default. We omit temp when == 1.0.
TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "1"))

# Per-model pricing (per **1K** tokens)
PRICING = {
    "gpt-5-mini": {"in": 0.00025, "out": 0.00200},
    "gpt-5": {"in": 0.00125, "out": 0.01000},
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


# ───────────────────────────── Config Model ───────────────────────────────
@dataclass
class AppConfig:
    hunt: bool
    evtx_root: Path
    evtx_scope: str
    prefer_logs: List[str]
    max_detections: int
    chunk_size: int
    max_chunks: int
    max_input_tokens: int
    outdir: Path
    rules_dir: Path
    mapping_path: Path
    sigma_root: Path
    chainsaw_format: str
    log_chainsaw: Optional[Path]
    make_pdf: bool
    make_html: bool
    timeout: int
    system_prompt: str
    detections_path: Path
    parse_format: str
    css_path: Optional[Path]
    # Prompt size controls
    no_script: bool
    truncate_script: int
    # Two-pass
    two_pass: bool
    micro_truncate: int
    micro_include_script: bool
    final_max_input_tokens: int
    # LLM config
    chunk_model: str
    final_model: str
    llm_max_retries: int
    llm_timeout: int
    llm_temperature: float
    # Pricing overrides
    pricing_file: Optional[Path]
    pricing_json: Optional[str]
    # Sysmon + cost-only
    sysmon_info_path: Path
    cost_only: Optional[Path]
    # Temperature suppression and seed
    force_no_temperature: bool
    llm_seed: Optional[int]
    # Streaming + parallelism
    stream: bool
    micro_workers: int
    # New perf controls
    rpm: int
    micro_max_seconds: int
    abort_after_minutes: int


# ───────────────────────────── Helpers/IO ────────────────────────────────
class LoaderError(Exception):
    pass


def die(msg: str, code: int = 1) -> None:
    console.print(Panel.fit(f"[red]✘ {msg}[/red]", box=box.ROUNDED))
    sys.exit(code)


def ok(msg: str) -> None:
    console.print(Panel.fit(f"[green]✔ {msg}[/green]", box=box.ROUNDED))


def info(msg: str) -> None:
    console.print(Panel.fit(f"[yellow]⚙ {msg}[/yellow]", box=box.ROUNDED))


# ──────────────────────────────── CLI ────────────────────────────────────
def parse_args() -> AppConfig:
    p = argparse.ArgumentParser(description="AI Chainsaw Summary Generator (mini→5 two-pass capable)")
    p.add_argument(
        "--hunt", action="store_true", default=True, help="Run chainsaw hunt before summarizing (default: on)"
    )
    p.add_argument("--evtx-root", type=Path, default=Path("/mnt/evtx_share/DFIR-Lab-Logs"))
    p.add_argument(
        "--evtx-scope", choices=["dir", "file"], default="dir", help="Hunt the latest date directory or a single file."
    )
    p.add_argument(
        "--prefer-logs",
        type=str,
        default="PowerShell-Operational.evtx,Security.evtx",
        help="Comma list to try in file mode.",
    )
    p.add_argument("--max-detections", type=int, default=1000, help="0 = no cap")
    p.add_argument("--chunk-size", type=int, default=25)
    p.add_argument("--max-chunks", type=int, default=100)
    p.add_argument("--max-input-tokens", type=int, default=120_000)
    p.add_argument("--outdir", type=Path, default=Path.home() / "DFIR-Labs" / "chainsaw_summaries")
    p.add_argument("--rules", type=Path, default=Path("chainsaw/rules"))
    p.add_argument("--mapping", type=Path, default=Path("chainsaw/sigma-mapping.yml"))
    p.add_argument(
        "--sigma-root", type=Path, default=None, help="Sigma repo root; defaults to parent of --rules if named 'rules'."
    )
    p.add_argument("--chainsaw-format", choices=["auto", "json", "jsonl"], default="auto")
    p.add_argument("--log-chainsaw", type=Path, default=None)
    p.add_argument("--latex", action="store_true")
    p.add_argument("--html", action="store_true")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--system-prompt", type=str, default=DEFAULT_SYSTEM_PROMPT)
    p.add_argument("--detections", type=Path, default=Path.home() / "chainsaw_output" / "detections.json")
    p.add_argument("--format", choices=["auto", "json", "jsonl"], default="auto")
    p.add_argument("--css", type=Path, default=None)
    # Pricing overrides
    p.add_argument("--pricing-file", type=Path, default=None, help="Path to JSON/YAML pricing file.")
    p.add_argument("--pricing-json", type=str, default=None, help='Inline JSON: {"model":{"in":0.0,"out":0.0}}')
    # Sysmon + cost-only
    p.add_argument("--sysmon-info", type=Path, default=Path.home() / "chainsaw_output" / "sysmon_info.json")
    p.add_argument("--cost-only", type=Path, default=None, help="Path to usage_by_model.json; compute costs and exit.")
    # Prompt size controls
    p.add_argument("--no-script", action="store_true", help="Exclude ScriptBlockText from LLM prompt")
    p.add_argument("--truncate-script", type=int, default=0, help="If >0, keep only first N chars of ScriptBlockText")
    # Two-pass
    p.add_argument("--two-pass", action="store_true", help="Enable micro → final two-pass summarization")
    p.add_argument(
        "--micro-truncate", type=int, default=200, help="Chars of ScriptBlockText to keep in micro pass (0=omit)"
    )
    p.add_argument(
        "--micro-include-script", action="store_true", help="Include truncated ScriptBlockText in micro pass"
    )
    p.add_argument("--final-max-input-tokens", type=int, default=20000, help="Guardrail for final merge input tokens")
    # LLM models & runtime
    p.add_argument("--chunk-model", default=CHUNK_MODEL, help="Model for chunk/micro passes (default: gpt-5-mini)")
    p.add_argument("--final-model", default=FINAL_MODEL, help="Model for final merge (default: gpt-5)")
    p.add_argument("--llm-max-retries", type=int, default=MAX_LLM_RETRIES, help="LLM retry attempts (default: 8)")
    p.add_argument("--llm-timeout", type=int, default=REQ_TIMEOUT_S, help="Per-request LLM timeout (s)")
    p.add_argument("--llm-temperature", type=float, default=TEMPERATURE, help="LLM temperature (default: 1)")
    # Temperature suppression and seed
    p.add_argument("--force-no-temperature", action="store_true", help="Never send 'temperature' to the API.")
    p.add_argument("--llm-seed", type=int, default=None, help="Optional seed for reproducibility (if supported).")
    # Streaming + parallelism + perf
    p.add_argument("--stream", action="store_true", help="Stream model output for responsiveness (serial only).")
    p.add_argument(
        "--micro-workers", type=str, default="1", help="'auto' or integer >=1. Auto = 2*CPU, capped by chunk count."
    )
    p.add_argument("--rpm", type=int, default=0, help="Max requests per minute for micro-pass (0 = unlimited).")
    p.add_argument(
        "--micro-max-seconds", type=int, default=0, help="Skip any micro call exceeding N seconds (0 = no cap)."
    )
    p.add_argument(
        "--abort-after-minutes", type=int, default=0, help="Stop entire run after N minutes; write partials."
    )

    a = p.parse_args()
    sigma_root = a.sigma_root or (a.rules.parent if a.rules.name.lower() == "rules" else a.rules)
    prefer_logs = [s.strip() for s in a.prefer_logs.split(",") if s.strip()]

    # Resolve micro_workers
    if str(a.micro_workers).lower() == "auto":
        try:

            cpu = max(1, os.cpu_count() or 1)  # type: ignore
        except Exception:
            cpu = 2
        micro_workers = max(1, 2 * cpu)
    else:
        micro_workers = max(1, int(a.micro_workers))

    return AppConfig(
        hunt=a.hunt,
        evtx_root=a.evtx_root,
        evtx_scope=a.evtx_scope,
        prefer_logs=prefer_logs,
        max_detections=max(0, a.max_detections),
        chunk_size=max(1, a.chunk_size),
        max_chunks=max(1, a.max_chunks),
        max_input_tokens=max(1000, a.max_input_tokens),
        outdir=a.outdir,
        rules_dir=a.rules,
        mapping_path=a.mapping,
        sigma_root=sigma_root,
        chainsaw_format=a.chainsaw_format,
        log_chainsaw=a.log_chainsaw,
        make_pdf=a.latex,
        make_html=a.html,
        timeout=max(60, a.timeout),
        system_prompt=(a.system_prompt or DEFAULT_SYSTEM_PROMPT).strip(),
        detections_path=a.detections,
        parse_format=a.format,
        css_path=a.css,
        no_script=a.no_script,
        truncate_script=max(0, a.truncate_script),
        two_pass=a.two_pass,
        micro_truncate=max(0, a.micro_truncate),
        micro_include_script=a.micro_include_script,
        final_max_input_tokens=max(4000, a.final_max_input_tokens),
        chunk_model=a.chunk_model,
        final_model=a.final_model,
        llm_max_retries=a.llm_max_retries,
        llm_timeout=a.llm_timeout,
        llm_temperature=a.llm_temperature,
        pricing_file=a.pricing_file,
        pricing_json=a.pricing_json,
        sysmon_info_path=a.sysmon_info,
        cost_only=a.cost_only,
        force_no_temperature=a.force_no_temperature,
        llm_seed=a.llm_seed,
        stream=a.stream,
        micro_workers=micro_workers,
        rpm=max(0, a.rpm),
        micro_max_seconds=max(0, a.micro_max_seconds),
        abort_after_minutes=max(0, a.abort_after_minutes),
    )


# ───────────────────────── Pricing Overrides ─────────────────────────────
def _load_pricing_from_file(path: Path) -> Dict[str, Dict[str, float]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yml", ".yaml"}:
        if yaml is None:
            raise RuntimeError("PyYAML not installed; use JSON or install pyyaml.")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Pricing file must be a mapping model -> {in,out}.")
    return data


def load_pricing(
    defaults: Dict[str, Dict[str, float]], *, file_path: Optional[Path], inline_json: Optional[str]
) -> Dict[str, Dict[str, float]]:
    merged = {**defaults}
    env_json = os.getenv("PRICING_JSON")
    sources: List[Tuple[str, Optional[Dict[str, Any]]]] = []
    if env_json:
        try:
            sources.append(("env:PRICING_JSON", json.loads(env_json)))
        except Exception as e:
            raise RuntimeError(f"Invalid PRICING_JSON: {e}")
    if file_path:
        try:
            sources.append((f"file:{file_path}", _load_pricing_from_file(file_path)))
        except Exception as e:
            raise RuntimeError(f"Failed loading pricing file: {e}")
    if inline_json:
        try:
            sources.append(("cli:--pricing-json", json.loads(inline_json)))
        except Exception as e:
            raise RuntimeError(f"Invalid --pricing-json: {e}")
    for label, data in sources:
        if not data:
            continue
        for model, vals in data.items():
            if not isinstance(vals, dict) or "in" not in vals or "out" not in vals:
                raise RuntimeError(f"Pricing entry for '{model}' in {label} must contain 'in' and 'out'.")
            merged[model] = {"in": float(vals["in"]), "out": float(vals["out"])}
    return merged


def validate_pricing_for_usage(pricing: Dict[str, Dict[str, float]], used_models: List[str]) -> None:
    missing = [m for m in used_models if m not in pricing]
    if missing:
        raise RuntimeError(
            f"Pricing missing for models: {', '.join(missing)}. Add via --pricing-file/--pricing-json/PRICING_JSON."
        )


# ───────────────────────── Sysmon + Environment ───────────────────────────
def load_sysmon_info(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def build_environment_md(sysmon: Optional[Dict[str, Any]]) -> str:
    present = sysmon is not None
    version = (sysmon or {}).get("version") or (sysmon or {}).get("sysmon_version") or "unknown"
    cfg_sha = (sysmon or {}).get("config_sha256") or (sysmon or {}).get("config", {}).get("sha256") or "unknown"
    lines = [
        "### Environment\n",
        f"- Sysmon: {'present' if present else 'not detected'}" + (f" (v{version})" if present else ""),
    ]
    if present:
        lines.append(f"- Sysmon Config Fingerprint: `{cfg_sha}`")
        lines.append("- Lab uses SwiftOnSecurity Sysmon config for high-signal events.")
    return "\n".join(lines) + "\n\n---\n"


# ───────────────────────── Chainsaw Utilities ─────────────────────────────
def ensure_chainsaw_available() -> None:
    if shutil.which("chainsaw") is None:
        die("chainsaw not found in PATH.")


def validate_sigma_root(sigma_root: Path) -> Path:
    sr = sigma_root.resolve()
    if not sr.exists() or not sr.is_dir():
        die(f"Sigma root not found: {sr}\nTip: use --sigma-root /path/to/sigma (parent of 'rules').")
    ok(f"Using Sigma root: {sr}")
    return sr


def resolve_rules_and_mapping(rules_dir: Path, mapping: Path) -> Tuple[Path, Path]:
    home = Path.home()
    script_dir = Path(__file__).resolve().parent

    def uniq(seq: List[Path]) -> List[Path]:
        seen = set()
        out: List[Path] = []
        for p in seq:
            rp = (Path.cwd() / p if not p.is_absolute() else p).resolve()
            if rp not in seen:
                out.append(rp)
                seen.add(rp)
        return out

    rules_candidates = uniq(
        [
            rules_dir,
            script_dir / "chainsaw" / "rules",
            home / "tools" / "sigma" / "rules",
            Path("/usr/share/chainsaw/rules"),
            Path("/usr/local/share/chainsaw/rules"),
        ]
    )

    mapping_candidates = uniq(
        [
            home / "tools" / "chainsaw" / "mappings" / "sigma-windows.yml",
            home / "tools" / "chainsaw" / "sigma-event-logs-all.yml",
            mapping,
            script_dir / "chainsaw" / "sigma-mapping.yml",
            Path("/usr/share/chainsaw/sigma-mapping.yml"),
            Path("/usr/local/share/chainsaw/sigma-mapping.yml"),
            home / "tools" / "chainsaw" / "mapping.yml",
        ]
    )

    rules_found = next((p for p in rules_candidates if p.is_dir()), None)
    mapping_found = next((p for p in mapping_candidates if p.is_file()), None)

    if not rules_found:
        die("Sigma rules directory not found. Tried:\n - " + "\n - ".join(map(str, rules_candidates[:8])))
    if not mapping_found:
        die("Sigma mapping file not found. Tried:\n - " + "\n - ".join(map(str, mapping_candidates[:8])))

    try:
        head = mapping_found.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        die(f"Cannot read mapping file {mapping_found}: {e}")
    if "groups:" not in head:
        die(f"Mapping missing 'groups:' key: {mapping_found}\nTip: use sigma-windows.yml or sigma-event-logs-all.yml.")

    ok(f"Using Chainsaw rules: {rules_found}")
    ok(f"Using Chainsaw mapping: {mapping_found}")
    return rules_found, mapping_found


def find_latest_container(root: Path) -> Path:
    if not root.exists():
        die(f"EVTX root not found: {root}")
    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs:
        die(f"No subfolders under {root}")
    latest = max(dirs, key=lambda p: p.stat().st_mtime)
    return latest


def resolve_evtx_source(root: Path, scope: str, prefer_logs: List[str]) -> Tuple[str, Path]:
    latest = find_latest_container(root)
    if scope == "dir":
        ok(f"Using EVTX directory: {latest.name}")
        console.print(Panel.fit(f"[green]✔ Hunting directory:[/green] {latest}", box=box.ROUNDED))
        return "dir", latest
    for name in prefer_logs:
        p = latest / name
        if p.exists() and p.is_file():
            ok(f"Using EVTX file: {p.name} (dir: {latest.name})")
            return "file", p
    any_evtx = sorted(latest.glob("*.evtx"))
    if any_evtx:
        p = any_evtx[0]
        ok(f"Using EVTX file (fallback): {p.name} (dir: {latest.name})")
        return "file", p
    die(f"No .evtx files found in {latest}")


# ─────────────────────── Chainsaw Execution (JSON) ────────────────────────
def _file_looks_json(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore").lstrip()
    except Exception:
        return False
    if not text:
        return False
    if text[0] in "{[":
        return True
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return False
    starts_ok = sum(1 for ln in lines[:50] if ln and ln[0] in "{[")
    return starts_ok >= max(1, len(lines[:50]) // 2)


def _run(cmd: List[str], timeout: int, log_path: Optional[Path]) -> None:
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "ab") as lf:
            subprocess.run(cmd, check=True, timeout=timeout, stdout=lf, stderr=lf)
    else:
        subprocess.run(cmd, check=True, timeout=timeout)


def run_chainsaw_json(
    src: Path,
    rules_dir: Path,
    mapping: Path,
    sigma_root: Path,
    output_json: Path,
    timeout: int,
    log_path: Optional[Path],
) -> Tuple[str, List[str]]:
    cmd = [
        "chainsaw",
        "hunt",
        str(src),
        "--mapping",
        str(mapping),
        "--rule",
        str(rules_dir),
        "-s",
        str(sigma_root),
        "--json",
        "--output",
        str(output_json),
    ]
    _run(cmd, timeout, log_path)
    return "json", cmd


def run_chainsaw_jsonl(
    src: Path,
    rules_dir: Path,
    mapping: Path,
    sigma_root: Path,
    output_json: Path,
    timeout: int,
    log_path: Optional[Path],
) -> Tuple[str, List[str]]:
    cmd = [
        "chainsaw",
        "hunt",
        str(src),
        "--mapping",
        str(mapping),
        "--rule",
        str(rules_dir),
        "-s",
        str(sigma_root),
        "--jsonl",
        "--output",
        str(output_json),
    ]
    _run(cmd, timeout, log_path)
    return "jsonl", cmd


def run_chainsaw_capture_json_stdout(
    src: Path,
    rules_dir: Path,
    mapping: Path,
    sigma_root: Path,
    output_json: Path,
    timeout: int,
    log_path: Optional[Path],
) -> Tuple[str, List[str]]:
    cmd = [
        "chainsaw",
        "hunt",
        str(src),
        "--mapping",
        str(mapping),
        "--rule",
        str(rules_dir),
        "-s",
        str(sigma_root),
        "--json",
    ]
    result = subprocess.run(cmd, check=True, timeout=timeout, capture_output=True, text=True)
    output_json.write_text(result.stdout, encoding="utf-8")
    if log_path:
        with open(log_path, "ab") as lf:
            lf.write(result.stderr.encode("utf-8", errors="ignore"))
    return "json-stdout", cmd


def run_chainsaw_safely(
    src: Path,
    rules_dir: Path,
    mapping: Path,
    sigma_root: Path,
    output_json: Path,
    timeout: int,
    log_path: Optional[Path],
    preferred: str = "auto",
) -> Tuple[str, List[str]]:
    info("Running chainsaw hunt...")
    output_json.parent.mkdir(parents=True, exist_ok=True)
    attempts = {
        "json": [run_chainsaw_json, run_chainsaw_jsonl, run_chainsaw_capture_json_stdout],
        "jsonl": [run_chainsaw_jsonl, run_chainsaw_json, run_chainsaw_capture_json_stdout],
        "auto": [run_chainsaw_json, run_chainsaw_jsonl, run_chainsaw_capture_json_stdout],
    }[preferred]
    last_err: Optional[Exception] = None
    for fn in attempts:
        try:
            label, cmd = fn(src, rules_dir, mapping, sigma_root, output_json, timeout, log_path)
            if _file_looks_json(output_json):
                ok(f"Chainsaw hunt completed ({label})")
                return label, cmd
            else:
                info(f"Chainsaw produced non-JSON output with mode '{label}'. Trying next...")
        except subprocess.TimeoutExpired:
            die("Chainsaw timed out.")
        except subprocess.CalledProcessError as e:
            last_err = e
            info(f"Chainsaw attempt failed: {e}")
            continue
        except Exception as e:
            last_err = e
            info(f"Chainsaw attempt error: {e}")
            continue
    if last_err:
        die(f"Chainsaw failed after retries: {last_err}")
    die("Chainsaw produced non-JSON output; try --chainsaw-format json or jsonl and recheck mapping/rules.")


# ─────────────────────────── Detection Loading ────────────────────────────
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


def load_detections_strict(json_path: Path, mode: str, max_items: int) -> List[Dict[str, Any]]:
    text = _read_text(json_path)
    if not text.strip():
        raise LoaderError(f"detections file contains only whitespace: {json_path}")
    detections: List[Dict[str, Any]] = []
    if mode == "json":
        try:
            detections = _normalize_to_list(_parse_json_text(text))
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
        detections = flat
    else:
        try:
            detections = _normalize_to_list(_parse_json_text(text))
        except Exception:
            items = _parse_jsonl_text(text)
            if not items:
                preview = text[:200].replace("\n", "\\n")
                raise LoaderError("Failed to parse detections as JSON or JSONL. Preview: " + preview)
            flat: List[Dict[str, Any]] = []
            for it in items:
                if isinstance(it, dict) and "detections" in it and isinstance(it["detections"], list):
                    flat.extend(it["detections"])
                elif isinstance(it, dict):
                    flat.append(it)
                elif isinstance(it, list):
                    flat.extend(it)
            detections = flat
    if not isinstance(detections, list):
        raise LoaderError("Detections is not a list.")
    if max_items > 0:
        detections = detections[:max_items]
    ok(f"Loaded {len(detections)} detections")
    return detections


# ───────────────────────── Markdown Builders ──────────────────────────────
def chunk(lst: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def fmt_detection_md(d: Dict[str, Any]) -> str:
    title = d.get("name", "Untitled")
    ts = d.get("timestamp", "N/A")
    severity = str(d.get("level", "unknown")).capitalize()
    rule_id = d.get("id", "N/A")
    tags = d.get("tags", []) or []
    refs = d.get("references", []) or []
    logsource = d.get("logsource", {}) or {}
    category = logsource.get("category", "N/A")
    product = logsource.get("product", "N/A")
    authors = ", ".join(d.get("authors", []) or []) or "Unknown"
    fps = d.get("falsepositives", []) or []
    return (
        f"### 🛡️ {title}\n"
        f"**Severity:** {severity}  \n"
        f"**Timestamp:** `{ts}`  \n"
        f"**Rule ID:** `{rule_id}`  \n"
        f"**Product:** `{product}`  \n"
        f"**Category:** `{category}`  \n"
        f"**Authors:** {authors}  \n\n"
        f"**Tactics/Techniques:**  \n"
        f"{' • '.join(tags) if tags else 'None'}\n\n"
        f"**False Positives:**  \n"
        f"{(' - ' + '\\n - '.join(fps)) if fps else 'None listed.'}\n\n"
        f"**References:**  \n"
        f"{(' - ' + '\\n - '.join(refs)) if refs else 'None listed.'}\n\n---\n"
    )


def build_raw_md(detections: List[Dict[str, Any]], chunk_size: int) -> str:
    head = "# 🔍 Chainsaw Detection Summary\n\nThis report contains Sigma rule detections from Chainsaw on parsed Windows event logs.\n\n"
    body = []
    for block in chunk(detections, chunk_size):
        for det in block:
            body.append(fmt_detection_md(det))
    return head + "".join(body)


def _format_script(script: str, no_script: bool, truncate_script: int) -> str:
    if no_script:
        return "(omitted)"
    if truncate_script > 0 and script:
        return script[:truncate_script] + ("… [truncated]" if len(script) > truncate_script else "")
    return script or ""


def build_chunk_prompt(chunk_items: List[Dict[str, Any]], *, no_script: bool, truncate_script: int) -> str:
    header = (
        "You are a senior DFIR analyst. Summarize these Windows detection events succinctly. "
        "Group related items, highlight notable TTPs/tooling, and provide an executive summary plus actionable recommendations.\n\n"
    )
    parts = []
    for i, det in enumerate(chunk_items, 1):
        ts = det.get("timestamp", "N/A")
        rule = det.get("name", "N/A")
        doc = ((det.get("document") or {}).get("data") or {}).get("Event") or {}
        event_id = (doc.get("System") or {}).get("EventID") or "N/A"
        script_raw = (doc.get("EventData") or {}).get("ScriptBlockText") or ""
        script = _format_script(script_raw, no_script=no_script, truncate_script=truncate_script)
        mitre_tags = ", ".join(det.get("tags", []) or []) or "None"
        category = (det.get("logsource") or {}).get("category", "N/A")
        definition = (det.get("logsource") or {}).get("definition", "")
        references = "\n".join(det.get("references", []) or []) or "None"
        parts.append(
            f"## 🕵️ Detection {i}\n"
            f"- Time: {ts}\n- Rule: {rule}\n- Event ID: {event_id}\n"
            f"- MITRE Tags: {mitre_tags}\n- Category: {category}\n- Definition: {definition}\n\n"
            f"Script Block:\n{script}\n\nReferences:\n{references}\n"
        )
    return header + "\n".join(parts)


# ───────────────────────────── Token Utils ────────────────────────────────
def get_encoder() -> tiktoken.Encoding:
    try:
        return tiktoken.get_encoding("cl100k_base")
    except Exception:
        return tiktoken.get_encoding("cl100k_base")


def estimate_tokens(encoder: tiktoken.Encoding, text: str) -> int:
    try:
        return len(encoder.encode(text))
    except Exception:
        return math.ceil(len(text) / 4)


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
        die(f"Chunk guardrail exceeded: {len(chunks)} chunks > --max-chunks {max_chunks}.")
    enc = get_encoder()
    per_chunk_inputs: List[int] = []
    total = 0
    for ch in chunks:
        prompt = build_chunk_prompt(ch, no_script=no_script, truncate_script=truncate_script)
        t = estimate_tokens(enc, system_prompt) + estimate_tokens(enc, prompt)
        per_chunk_inputs.append(t)
        total += t
    if total > max_input_tokens:
        die(
            f"Estimated input tokens {total} exceed --max-input-tokens {max_input_tokens}.\n"
            "Tip: increase --chunk-size, use --no-script/--truncate-script, reduce --max-detections, or raise --max-input-tokens."
        )
    return total, per_chunk_inputs


# ───────────────────────────── LLM Calls ──────────────────────────────────
def _sleep_backoff(i: int, base: float = 1.25, cap: float = 30.0):
    delay = min(cap, base**i) + random.uniform(0, 0.2)
    time.sleep(delay)


def call_llm(
    client: OpenAI,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    max_retries: int,
    timeout_s: int,
    *,
    force_no_temperature: bool,
    seed: Optional[int],
    stream: bool,
) -> str:
    last_err = None
    for attempt in range(max_retries):
        try:
            payload: Dict[str, Any] = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "timeout": timeout_s,
            }
            if not force_no_temperature and temperature is not None and float(temperature) != 1.0:
                payload["temperature"] = float(temperature)
            if seed is not None:
                payload["seed"] = int(seed)
            if stream:
                payload["stream"] = True
                chunks = client.chat.completions.create(**payload)
                out = []
                for ev in chunks:
                    delta = getattr(ev.choices[0].delta, "content", None)
                    if delta:
                        out.append(delta)
                return "".join(out)
            else:
                resp = client.chat.completions.create(**payload)
                return resp.choices[0].message.content or ""
        except KeyboardInterrupt:
            raise
        except (RateLimitError, APITimeoutError, APIConnectionError) as e:
            last_err = e
            _sleep_backoff(attempt)
            continue
        except APIError as e:
            last_err = e
            status = getattr(e, "status_code", None)
            if status and 500 <= status < 600:
                _sleep_backoff(attempt)
                continue
            raise
        except BadRequestError as e:
            msg = str(e)
            stripped = False
            if ("temperature" in msg) and ("unsupported" in msg or "does not support" in msg):
                force_no_temperature = True
                stripped = True
            if ("seed" in msg) and ("unsupported" in msg or "does not support" in msg or "unknown parameter" in msg):
                seed = None
                stripped = True
            if stripped:
                try:
                    payload = {
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "timeout": timeout_s,
                    }
                    if not force_no_temperature and temperature is not None and float(temperature) != 1.0:
                        payload["temperature"] = float(temperature)
                    if seed is not None:
                        payload["seed"] = int(seed)
                    if stream:
                        payload["stream"] = True
                        chunks = client.chat.completions.create(**payload)
                        out = []
                        for ev in chunks:
                            delta = getattr(ev.choices[0].delta, "content", None)
                            if delta:
                                out.append(delta)
                        return "".join(out)
                    else:
                        resp = client.chat.completions.create(**payload)
                        return resp.choices[0].message.content or ""
                except KeyboardInterrupt:
                    raise
                except Exception as e2:
                    last_err = e2
                    _sleep_backoff(attempt)
                    continue
            raise
    raise RuntimeError(f"LLM retries exceeded after {max_retries} attempts: {last_err}")


# ─────────────────────────── Rate Limiter ────────────────────────────────
class RateLimiter:
    """Simple cross-thread RPM limiter."""

    def __init__(self, rpm: int):
        self.rpm = max(0, rpm)
        self.lock = threading.Lock()
        self.next_time = 0.0
        self.interval = 60.0 / self.rpm if self.rpm > 0 else 0.0

    def wait(self):
        if self.rpm <= 0:
            return
        with self.lock:
            now = time.time()
            if now < self.next_time:
                time.sleep(self.next_time - now)
            self.next_time = max(now, self.next_time) + self.interval


# ───────────────────────────── Two-Pass Flow ──────────────────────────────
def build_micro_prompt(chunk_items: List[Dict[str, Any]], *, include_script: bool, micro_truncate: int) -> str:
    header = (
        "Micro-summarize these detections for DFIR triage in <= 12 bullets total. "
        "Group similar items, name key TTPs (MITRE IDs if present), mention counts/timestamps if available. "
        "No fluff, no repetition. Output:\n"
        "• Executive bullets\n• Key TTPs\n• Notable IOCs (if any)\n"
    )
    parts = []
    for det in chunk_items:
        ts = det.get("timestamp", "N/A")
        rule = det.get("name", "N/A")
        tags = ", ".join(det.get("tags", []) or []) or "None"
        doc = ((det.get("document") or {}).get("data") or {}).get("Event") or {}
        eid = (doc.get("System") or {}).get("EventID") or "N/A"
        script_raw = (doc.get("EventData") or {}).get("ScriptBlockText") or ""
        snippet = ""
        if include_script and micro_truncate > 0 and script_raw:
            snippet = script_raw[:micro_truncate] + ("… [truncated]" if len(script_raw) > micro_truncate else "")
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


def two_pass_summarize(
    client: OpenAI,
    chunks: List[List[Dict[str, Any]]],
    micro_truncate: int,
    micro_include_script: bool,
    final_max_input_tokens: int,
    *,
    chunk_model: str,
    final_model: str,
    temperature: float,
    max_retries: int,
    timeout_s: int,
    environment_md: str = "",
    force_no_temperature: bool = False,
    seed: Optional[int] = None,
    stream: bool = False,
    micro_workers: int = 1,
    rpm: int = 0,
    micro_max_seconds: int = 0,
    global_deadline_ts: float = 0.0,
) -> Tuple[str, int, int, Dict[str, Tuple[int, int]]]:
    enc = get_encoder()
    total_in = total_out = 0
    usage: Dict[str, Tuple[int, int]] = {}
    limiter = RateLimiter(rpm)

    def check_deadline():
        if global_deadline_ts > 0 and time.time() > global_deadline_ts:
            raise KeyboardInterrupt("Global deadline reached")

    # Pass 1: micro (serial or parallel)
    micro_sections: List[Optional[str]] = [None] * len(chunks)
    info("Two-pass: generating micro-summaries...")
    micro_in = micro_out = 0

    def _work(idx: int, ch: List[Dict[str, Any]]) -> Tuple[int, str, int, int]:
        check_deadline()
        prompt = build_micro_prompt(ch, include_script=micro_include_script, micro_truncate=micro_truncate)
        _in = estimate_tokens(enc, DEFAULT_SYSTEM_PROMPT) + estimate_tokens(enc, prompt)

        def _invoke() -> str:
            limiter.wait()
            return call_llm(
                client,
                chunk_model,
                DEFAULT_SYSTEM_PROMPT,
                prompt,
                temperature,
                max_retries,
                timeout_s,
                force_no_temperature=force_no_temperature,
                seed=seed,
                stream=False,
            )

        if micro_max_seconds > 0:
            with ThreadPoolExecutor(max_workers=1) as ex:
                fut: Future[str] = ex.submit(_invoke)
                try:
                    content = fut.result(timeout=micro_max_seconds)
                except Exception:
                    try:
                        fut.cancel()
                    except Exception:
                        pass
                    content = f"**[Skipped]** micro chunk {idx + 1}: exceeded {micro_max_seconds}s"
        else:
            content = _invoke()

        _out = estimate_tokens(enc, content)
        return idx, content, _in, _out

    if micro_workers > 1:
        if stream:
            info("Streaming disabled for micro-pass due to --micro-workers > 1.")

        max_workers = min(micro_workers, len(chunks))
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]Micro[/bold]"),
            BarColumn(),
            TextColumn("chunk [progress.completed]/[progress.total]"),
            TimeElapsedColumn(),
            transient=True,
        ) as prog:
            task = prog.add_task("micro", total=len(chunks))
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_work, i, ch): i for i, ch in enumerate(chunks)}
                try:
                    for fut in as_completed(futures):
                        i, content, _in, _out = fut.result()
                        micro_sections[i] = f"## Micro {i + 1}\n{content}"
                        micro_in += _in
                        micro_out += _out
                        prog.update(task, advance=1)
                        check_deadline()
                except KeyboardInterrupt:
                    for f in futures:
                        f.cancel()
                    raise
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]Micro[/bold]"),
            BarColumn(),
            TextColumn("chunk [progress.completed]/[progress.total]"),
            TimeElapsedColumn(),
            transient=True,
        ) as prog:
            task = prog.add_task("micro", total=len(chunks))
            for i, ch in enumerate(chunks):
                check_deadline()
                prompt = build_micro_prompt(ch, include_script=micro_include_script, micro_truncate=micro_truncate)
                micro_in += estimate_tokens(enc, DEFAULT_SYSTEM_PROMPT) + estimate_tokens(enc, prompt)
                info(f"Calling LLM (micro chunk {i + 1}/{len(chunks)}; model={chunk_model})")
                limiter.wait()
                content = call_llm(
                    client,
                    chunk_model,
                    DEFAULT_SYSTEM_PROMPT,
                    prompt,
                    temperature,
                    max_retries,
                    timeout_s,
                    force_no_temperature=force_no_temperature,
                    seed=seed,
                    stream=stream,
                )
                micro_out += estimate_tokens(enc, content)
                micro_sections[i] = f"## Micro {i + 1}\n{content}"
                prog.update(task, advance=1)

    usage[chunk_model] = (micro_in, micro_out)
    total_in += micro_in
    total_out += micro_out

    # Pass 2: final merge
    check_deadline()
    final_user = build_final_merge_prompt([s or "" for s in micro_sections])
    est_final_in = estimate_tokens(enc, DEFAULT_FINAL_SYSTEM) + estimate_tokens(enc, final_user)
    if est_final_in > final_max_input_tokens:
        info(f"Final merge prompt too large ({est_final_in} > {final_max_input_tokens}). Compressing micro-sections…")
        pairs = sorted(((estimate_tokens(enc, s or ""), (s or "")) for s in micro_sections), key=lambda x: x[0])
        keep: List[str] = []
        running = estimate_tokens(enc, DEFAULT_FINAL_SYSTEM)
        for tok, s in pairs:
            if running + tok <= final_max_input_tokens:
                keep.append(s)
                running += tok
            else:
                break
        if not keep:
            shortened = (micro_sections[0] or "")[: max(5000, final_max_input_tokens // 4)]
            keep = [shortened]
        final_user = build_final_merge_prompt(keep)

    info("Two-pass: merging micro-summaries...")
    limiter.wait()
    final_content = call_llm(
        client,
        final_model,
        DEFAULT_FINAL_SYSTEM,
        final_user,
        temperature,
        max_retries,
        timeout_s,
        force_no_temperature=force_no_temperature,
        seed=seed,
        stream=stream,
    )
    final_in = estimate_tokens(enc, DEFAULT_FINAL_SYSTEM) + estimate_tokens(enc, final_user)
    final_out = estimate_tokens(enc, final_content)
    usage[final_model] = (usage.get(final_model, (0, 0))[0] + final_in, usage.get(final_model, (0, 0))[1] + final_out)
    total_in += final_in
    total_out += final_out

    head = (
        "# 🔍 Chainsaw Detection Summary (LLM, Two-Pass)\n\n"
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}\n"
        f"- Model (micro): `{chunk_model}`\n"
        f"- Model (final): `{final_model}`\n"
        f"- Chunks: {len(chunks)}\n"
        f"- Mode: two-pass (micro → final)\n\n---\n"
    )
    appendix = "\n\n---\n\n## Appendix: Micro-Summaries\n\n" + "\n\n".join([s or "" for s in micro_sections])
    return (
        head + environment_md + "## Final Executive Report\n\n" + final_content + appendix,
        total_in,
        total_out,
        usage,
    )


# ─────────────────────────── Cost Estimation ──────────────────────────────
def estimate_cost_by_model_with(
    pricing: Dict[str, Dict[str, float]], usages: Dict[str, Tuple[int, int]]
) -> Tuple[float, List[str]]:
    total = 0.0
    lines = []
    for m, (tin, tout) in usages.items():
        p = pricing.get(m, {"in": 0.0, "out": 0.0})
        cost = (tin / 1000.0) * p["in"] + (tout / 1000.0) * p["out"]
        total += cost
        lines.append(f"- {m}: in={tin} out={tout} → ${cost:.6f} (in {p['in']}/k, out {p['out']}/k)")
    return round(total, 6), lines


def estimate_cost_by_model(usages: Dict[str, Tuple[int, int]]) -> Tuple[float, List[str]]:
    return estimate_cost_by_model_with(PRICING, usages)


def write_usage_json(base_dir: Path, usage: Dict[str, Tuple[int, int]]) -> Path:
    out = base_dir / "usage_by_model.json"
    shaped = {m: {"in": tin, "out": tout} for m, (tin, tout) in usage.items()}
    out.write_text(json.dumps(shaped, indent=2), encoding="utf-8")
    return out


def load_usage_json(path: Path) -> Dict[str, Tuple[int, int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    usage: Dict[str, Tuple[int, int]] = {}
    for m, v in data.items():
        if isinstance(v, dict) and "in" in v and "out" in v:
            usage[m] = (int(v["in"]), int(v["out"]))
        elif isinstance(v, (list, tuple)) and len(v) == 2:
            usage[m] = (int(v[0]), int(v[1]))
        else:
            raise RuntimeError(f"Bad usage entry for {m}: {v}")
    return usage


# ───────────────────────────── Output Helpers ─────────────────────────────
def ensure_css(base_dir: Path, css_path: Optional[Path]) -> Path:
    if css_path and css_path.exists():
        return css_path
    out = base_dir / "report.css"
    if not out.exists():
        out.write_text(DEFAULT_CSS, encoding="utf-8")
    return out


def sanitize_md_for_pandoc(text: str) -> str:
    if text.startswith("---\n"):
        text = "\n" + text
    return re.sub(r"(?m)^\s*---\s*$", "<hr />", text)


def write_outputs(
    base_dir: Path,
    raw_md: str,
    llm_md: str,
    make_pdf: bool,
    make_html: bool,
    css_path: Optional[Path],
) -> Tuple[Path, Path, Optional[Path], Optional[Path]]:
    base_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.today().strftime("%Y-%m-%d")
    raw_md_path = base_dir / f"chainsaw_report_raw_{today}.md"
    llm_md_path = base_dir / f"chainsaw_summary_llm_{today}.md"
    raw_md_path.write_text(raw_md, encoding="utf-8")
    llm_md_path.write_text(llm_md, encoding="utf-8")

    llm_md_safe = sanitize_md_for_pandoc(llm_md)
    pdf_path: Optional[Path] = None
    html_path: Optional[Path] = None

    if make_pdf:
        try:
            pdf_path = base_dir / f"chainsaw_summary_{today}.pdf"
            pypandoc.convert_text(
                llm_md_safe,
                to="pdf",
                format="gfm",
                outputfile=str(pdf_path),
                extra_args=["--standalone", "--pdf-engine=xelatex", "--metadata", "title=DFIR Chainsaw Summary (LLM)"],
            )
        except OSError as e:
            info(f"PDF generation skipped: {e}")
            pdf_path = None

    if make_html:
        try:
            css_out = ensure_css(base_dir, css_path)
            html_path = base_dir / f"chainsaw_summary_{today}.html"
            pypandoc.convert_text(
                llm_md_safe,
                to="html",
                format="gfm",
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
        except OSError as e:
            info(f"HTML generation skipped: {e}")
            html_path = None

    return raw_md_path, llm_md_path, pdf_path, html_path


def write_run_meta(
    base_dir: Path,
    *,
    chainsaw_label: Optional[str],
    chainsaw_cmd: Optional[List[str]],
    rules_dir: Path,
    mapping_path: Path,
    sigma_root: Path,
    evtx_kind: str,
    evtx_path: Path,
    cfg: AppConfig,
    sysmon: Optional[Dict[str, Any]],
    usage_by_model: Dict[str, Tuple[int, int]],
) -> Path:
    meta = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "chainsaw": {"mode": chainsaw_label, "cmd": chainsaw_cmd},
        "paths": {
            "rules_dir": str(rules_dir),
            "mapping_path": str(mapping_path),
            "sigma_root": str(sigma_root),
            "evtx": {"kind": evtx_kind, "path": str(evtx_path)},
        },
        "models": {
            "chunk_model": cfg.chunk_model,
            "final_model": cfg.final_model if cfg.two_pass else None,
            "two_pass": cfg.two_pass,
        },
        "llm_runtime": {
            "temperature": None if cfg.force_no_temperature or cfg.llm_temperature == 1.0 else cfg.llm_temperature,
            "force_no_temperature": cfg.force_no_temperature,
            "seed": cfg.llm_seed,
            "timeout_s": cfg.llm_timeout,
            "max_retries": cfg.llm_max_retries,
            "stream": cfg.stream,
            "micro_workers": cfg.micro_workers,
            "rpm": cfg.rpm,
            "micro_max_seconds": cfg.micro_max_seconds,
            "abort_after_minutes": cfg.abort_after_minutes,
        },
        "sysmon": sysmon or {},
        "usage_by_model": {m: {"in": i, "out": o} for m, (i, o) in usage_by_model.items()},
    }
    out = base_dir / "run_meta.json"
    out.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return out


# ───────────────────────────────── Main ───────────────────────────────────
def main() -> None:
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        die("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)

    cfg = parse_args()

    # Load pricing (overrides defaults)
    try:
        pricing = load_pricing(PRICING, file_path=cfg.pricing_file, inline_json=cfg.pricing_json)
    except Exception as e:
        die(f"Pricing configuration error: {e}")

    # Cost-only mode
    if cfg.cost_only:
        usage = load_usage_json(cfg.cost_only)
        est_cost, lines = estimate_cost_by_model_with(pricing, usage)
        console.rule("[bold green]Cost (from usage file)[/bold green]")
        for ln in lines:
            console.print(f"[cyan]{ln}[/cyan]")
        console.print(f"[cyan]💸 Estimated total cost:[/cyan] ${est_cost}")
        return

    # Ensure pricing covers the models used in this run
    models_in_play = [cfg.chunk_model] + ([cfg.final_model] if cfg.two_pass else [])
    try:
        validate_pricing_for_usage(pricing, models_in_play)
    except Exception as e:
        die(str(e))

    # EVTX source
    src_kind, src_path = resolve_evtx_source(cfg.evtx_root, cfg.evtx_scope, cfg.prefer_logs)

    # Resolve rules/mapping & sigma root
    rules_dir_resolved, mapping_resolved = resolve_rules_and_mapping(cfg.rules_dir, cfg.mapping_path)
    if cfg.sigma_root is None or not cfg.sigma_root.exists():
        sigma_guess = rules_dir_resolved.parent if rules_dir_resolved.name.lower() == "rules" else rules_dir_resolved
        sigma_root_resolved = validate_sigma_root(sigma_guess)
    else:
        sigma_root_resolved = validate_sigma_root(cfg.sigma_root)

    # Chainsaw output path
    detections_json = cfg.detections_path
    detections_json.parent.mkdir(parents=True, exist_ok=True)

    chainsaw_label: Optional[str] = None
    chainsaw_cmd: Optional[List[str]] = None

    # Hunt if requested (default: on)
    if cfg.hunt:
        ensure_chainsaw_available()
        chainsaw_label, chainsaw_cmd = run_chainsaw_safely(
            src_path,
            rules_dir_resolved,
            mapping_resolved,
            sigma_root_resolved,
            detections_json,
            cfg.timeout,
            cfg.log_chainsaw,
            preferred=cfg.chainsaw_format,
        )
    else:
        info(f"Skipping chainsaw hunt (using existing {detections_json})")

    # Load detections (auto-regenerate if bad)
    try:
        detections = load_detections_strict(detections_json, cfg.parse_format, cfg.max_detections)
    except LoaderError as e:
        info(f"Detections load failed: {e}")
        info("Attempting to regenerate detections via Chainsaw once (JSON)...")
        ensure_chainsaw_available()
        chainsaw_label, chainsaw_cmd = run_chainsaw_safely(
            src_path,
            rules_dir_resolved,
            mapping_resolved,
            sigma_root_resolved,
            detections_json,
            cfg.timeout,
            cfg.log_chainsaw,
            preferred="json",
        )
        detections = load_detections_strict(detections_json, cfg.parse_format, cfg.max_detections)

    # Raw markdown
    raw_md = build_raw_md(detections, cfg.chunk_size)

    # Environment block (Sysmon)
    sysmon_info = load_sysmon_info(cfg.sysmon_info_path)
    environment_md = build_environment_md(sysmon_info)

    # Prepare LLM chunks
    chunks = list(chunk(detections, cfg.chunk_size))

    # Global deadline
    global_deadline_ts = 0.0
    if cfg.abort_after_minutes > 0:
        global_deadline_ts = time.time() + cfg.abort_after_minutes * 60.0
        info(f"Global deadline active: {cfg.abort_after_minutes} minute(s)")

    # LLM summarization
    try:
        if cfg.two_pass:
            llm_md, in_tokens, out_tokens, usage_by_model = two_pass_summarize(
                client,
                chunks,
                cfg.micro_truncate,
                cfg.micro_include_script,
                cfg.final_max_input_tokens,
                chunk_model=cfg.chunk_model,
                final_model=cfg.final_model,
                temperature=cfg.llm_temperature,
                max_retries=cfg.llm_max_retries,
                timeout_s=cfg.llm_timeout,
                environment_md=environment_md,
                force_no_temperature=cfg.force_no_temperature,
                seed=cfg.llm_seed,
                stream=cfg.stream,
                micro_workers=cfg.micro_workers,
                rpm=cfg.rpm,
                micro_max_seconds=cfg.micro_max_seconds,
                global_deadline_ts=global_deadline_ts,
            )
        else:
            _total_in_est, _per_chunk = guardrail_estimate_or_die(
                chunks,
                cfg.system_prompt,
                cfg.max_chunks,
                cfg.max_input_tokens,
                no_script=cfg.no_script,
                truncate_script=cfg.truncate_script,
            )
            # For single-pass, reuse chunked path; no extra perf knobs here
            llm_md, in_tokens, out_tokens, usage_by_model = call_llm_chunked(
                client,
                chunks,
                cfg.system_prompt,
                no_script=cfg.no_script,
                truncate_script=cfg.truncate_script,
                model=cfg.chunk_model,
                temperature=cfg.llm_temperature,
                max_retries=cfg.llm_max_retries,
                timeout_s=cfg.llm_timeout,
                environment_md=environment_md,
                force_no_temperature=cfg.force_no_temperature,
                seed=cfg.llm_seed,
                stream=cfg.stream,
            )
    except KeyboardInterrupt:
        info("Interrupted by user or deadline; writing partial outputs if any…")
        llm_md = "# 🔍 Chainsaw Detection Summary (Interrupted)\n\nRun interrupted before completion.\n"
        in_tokens = out_tokens = 0
        usage_by_model = {}

    # Outputs
    dated = cfg.outdir / datetime.today().strftime("%Y-%m-%d")
    raw_md_path, llm_md_path, pdf_path, html_path = write_outputs(
        dated, raw_md, llm_md, cfg.make_pdf, cfg.make_html, cfg.css_path
    )

    # Persist usage + run meta
    usage_path = write_usage_json(dated, usage_by_model)
    run_meta_path = write_run_meta(
        dated,
        chainsaw_label=chainsaw_label,
        chainsaw_cmd=chainsaw_cmd,
        rules_dir=rules_dir_resolved,
        mapping_path=mapping_resolved,
        sigma_root=sigma_root_resolved,
        evtx_kind=src_kind,
        evtx_path=src_path,
        cfg=cfg,
        sysmon=sysmon_info,
        usage_by_model=usage_by_model,
    )

    # Console output
    console.rule("[bold green]🔍 LLM-Summarized Report[/bold green]")
    console.print(Markdown(llm_md))
    console.rule("[bold green]End of Summary[/bold green]")

    total_tokens = in_tokens + out_tokens
    est_cost, lines = estimate_cost_by_model_with(pricing, usage_by_model)
    console.print(f"\n[green]✓ LLM Markdown:[/green] {llm_md_path}")
    console.print(f"[green]✓ Raw Markdown:[/green] {raw_md_path}")
    if cfg.make_pdf:
        if pdf_path:
            console.print(f"[green]✓ PDF:[/green] {pdf_path}")
        else:
            console.print("[yellow]• PDF generation failed (install XeLaTeX or set PDF engine).[/yellow]")
    if html_path:
        console.print(f"[green]✓ HTML:[/green] {html_path}")
        if not cfg.css_path:
            console.print(f"[green]✓ CSS:[/green] {dated / 'report.css'}")
    console.print(f"[cyan]🧠 Tokens used (est):[/cyan] {total_tokens}")
    for ln in lines:
        console.print(f"[cyan]{ln}[/cyan]")
    console.print(f"[cyan]💸 Estimated total cost:[/cyan] ${est_cost}")
    console.print(f"[green]✓ Usage JSON:[/green] {usage_path}")
    console.print(f"[green]✓ Run Metadata:[/green] {run_meta_path}")


if __name__ == "__main__":
    main()
