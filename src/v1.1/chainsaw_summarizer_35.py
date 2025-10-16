# File: chainsaw_summarizer_35.py
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pypandoc
import tiktoken
from dotenv import load_dotenv
from openai import OpenAI
from openai._exceptions import (
    APIConnectionError,
    APIError,
    BadRequestError,
    RateLimitError,
)
from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

# --- Console / Model / Pricing ---
console = Console()

MODEL = "gpt-3.5-turbo"
IN_PRICE, OUT_PRICE = 0.0005, 0.0015  # per 1K tokens

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


# ---------------- Config ----------------
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


# ---------------- Errors/helpers ----------------
class LoaderError(Exception):
    pass


def die(msg: str, code: int = 1) -> None:
    console.print(Panel.fit(f"[red]✘ {msg}[/red]", box=box.ROUNDED))
    sys.exit(code)


def ok(msg: str) -> None:
    console.print(Panel.fit(f"[green]✔ {msg}[/green]", box=box.ROUNDED))


def info(msg: str) -> None:
    console.print(Panel.fit(f"[yellow]⚙ {msg}[/yellow]", box=box.ROUNDED))


# ---------------- CLI ----------------
def parse_args() -> AppConfig:
    p = argparse.ArgumentParser(description="AI Chainsaw Summary Generator (3.5-turbo)")
    # Defaults per request
    p.add_argument(
        "--hunt",
        action="store_true",
        default=True,
        help="Run chainsaw hunt before summarizing (default: on)",
    )
    p.add_argument("--evtx-root", type=Path, default=Path("/mnt/evtx_share/DFIR-Lab-Logs"))
    p.add_argument(
        "--evtx-scope",
        choices=["dir", "file"],
        default="dir",
        help="Hunt the latest date directory (dir) or a single log (file).",
    )
    p.add_argument(
        "--prefer-logs",
        type=str,
        default="PowerShell-Operational.evtx,Security.evtx",
        help="Comma list to try in file mode (first that exists wins).",
    )
    p.add_argument("--max-detections", type=int, default=1000, help="0 = no cap")
    p.add_argument("--chunk-size", type=int, default=25)
    p.add_argument("--max-chunks", type=int, default=100)
    p.add_argument("--max-input-tokens", type=int, default=120_000)
    p.add_argument(
        "--outdir",
        type=Path,
        default=Path.home() / "DFIR-Labs" / "chainsaw_summaries",
    )
    p.add_argument("--rules", type=Path, default=Path("chainsaw/rules"))
    p.add_argument("--mapping", type=Path, default=Path("chainsaw/sigma-mapping.yml"))
    p.add_argument(
        "--sigma-root",
        type=Path,
        default=None,
        help="Sigma repo root (-s). Defaults to parent of --rules if named 'rules'.",
    )
    p.add_argument("--chainsaw-format", choices=["auto", "json", "jsonl"], default="auto")
    p.add_argument("--log-chainsaw", type=Path, default=None)
    p.add_argument("--latex", action="store_true")
    p.add_argument("--html", action="store_true")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--system-prompt", type=str, default=DEFAULT_SYSTEM_PROMPT)
    p.add_argument(
        "--detections",
        type=Path,
        default=Path.home() / "chainsaw_output" / "detections.json",
    )
    p.add_argument("--format", choices=["auto", "json", "jsonl"], default="auto")
    p.add_argument("--css", type=Path, default=None)
    # Prompt size controls
    p.add_argument("--no-script", action="store_true", help="Exclude ScriptBlockText from LLM prompt")
    p.add_argument(
        "--truncate-script",
        type=int,
        default=0,
        help="If >0, include only the first N characters of ScriptBlockText",
    )
    # Two-pass
    p.add_argument("--two-pass", action="store_true", help="Enable micro → final two-pass summarization")
    p.add_argument(
        "--micro-truncate",
        type=int,
        default=200,
        help="Chars of ScriptBlockText to keep in micro pass (0=omit)",
    )
    p.add_argument(
        "--micro-include-script",
        action="store_true",
        help="Include truncated ScriptBlockText in micro pass",
    )
    p.add_argument(
        "--final-max-input-tokens",
        type=int,
        default=20000,
        help="Guardrail for final merge input tokens",
    )

    a = p.parse_args()

    sigma_root = a.sigma_root or (a.rules.parent if a.rules.name.lower() == "rules" else a.rules)
    prefer_logs = [s.strip() for s in a.prefer_logs.split(",") if s.strip()]
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
    )


# ---------------- Chainsaw prerequisites ----------------
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


# ---------------- Chainsaw execution (JSON-safe) ----------------
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
) -> None:
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


def run_chainsaw_jsonl(
    src: Path,
    rules_dir: Path,
    mapping: Path,
    sigma_root: Path,
    output_json: Path,
    timeout: int,
    log_path: Optional[Path],
) -> None:
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


def run_chainsaw_capture_json_stdout(
    src: Path,
    rules_dir: Path,
    mapping: Path,
    sigma_root: Path,
    output_json: Path,
    timeout: int,
    log_path: Optional[Path],
) -> None:
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


def run_chainsaw_safely(
    src: Path,
    rules_dir: Path,
    mapping: Path,
    sigma_root: Path,
    output_json: Path,
    timeout: int,
    log_path: Optional[Path],
    preferred: str = "auto",
) -> None:
    info("Running chainsaw hunt...")
    output_json.parent.mkdir(parents=True, exist_ok=True)
    attempts: List[Tuple[str, callable]] = []
    if preferred == "json":
        attempts = [
            ("json", run_chainsaw_json),
            ("jsonl", run_chainsaw_jsonl),
            ("json-stdout", run_chainsaw_capture_json_stdout),
        ]
    elif preferred == "jsonl":
        attempts = [
            ("jsonl", run_chainsaw_jsonl),
            ("json", run_chainsaw_json),
            ("json-stdout", run_chainsaw_capture_json_stdout),
        ]
    else:
        attempts = [
            ("json", run_chainsaw_json),
            ("jsonl", run_chainsaw_jsonl),
            ("json-stdout", run_chainsaw_capture_json_stdout),
        ]

    last_err: Optional[Exception] = None
    for label, fn in attempts:
        try:
            fn(src, rules_dir, mapping, sigma_root, output_json, timeout, log_path)
            if _file_looks_json(output_json):
                ok(f"Chainsaw hunt completed ({label})")
                return
            else:
                info(f"Chainsaw produced non-JSON output with mode '{label}'. Trying next...")
        except subprocess.TimeoutExpired:
            die("Chainsaw timed out.")
        except subprocess.CalledProcessError as e:
            last_err = e
            info(f"Chainsaw attempt '{label}' failed: {e}")
            continue
        except Exception as e:
            last_err = e
            info(f"Chainsaw attempt '{label}' error: {e}")
            continue
    if last_err:
        die(f"Chainsaw failed to produce JSON after retries: {last_err}")
    else:
        die("Chainsaw produced non-JSON output; try --chainsaw-format json or jsonl and recheck mapping/rules.")


# ---------------- Loader (JSON/JSONL/auto) ----------------
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


# ---------------- Markdown builders ----------------
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
    # Why: large script blocks explode token counts
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


# ---------------- LLM utils ----------------
def get_encoder() -> tiktoken.Encoding:
    try:
        return tiktoken.encoding_for_model(MODEL)
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
        die(
            f"Chunk guardrail exceeded: {len(chunks)} chunks > --max-chunks {max_chunks}.\n"
            "Tip: increase --chunk-size or raise --max-chunks."
        )
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
            "Tip: increase --chunk-size, use --no-script or --truncate-script, reduce --max-detections, or raise --max-input-tokens."
        )
    return total, per_chunk_inputs


def call_llm(client: OpenAI, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
    backoff = 1.0
    for _ in range(5):
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
            )
            return resp.choices[0].message.content or ""
        except (RateLimitError, APIError, APIConnectionError):
            time.sleep(backoff)
            backoff = min(backoff * 2, 8)
            continue
        except BadRequestError as e:
            die(f"Bad request: {e}")
        except Exception as e:
            die(f"LLM error: {e}")
    die("LLM retries exceeded.")
    return ""  # unreachable


def call_llm_chunked(
    client: OpenAI,
    chunks: List[List[Dict[str, Any]]],
    system_prompt: str,
    *,
    no_script: bool,
    truncate_script: int,
) -> Tuple[str, int, int]:
    enc = get_encoder()
    total_in, total_out = 0, 0
    sections: List[str] = []
    for idx, ch in enumerate(chunks, 1):
        prompt = build_chunk_prompt(ch, no_script=no_script, truncate_script=truncate_script)
        total_in += estimate_tokens(enc, prompt) + estimate_tokens(enc, system_prompt)
        content = call_llm(client, system_prompt, prompt, temperature=0.2)
        sections.append(f"### Chunk {idx}\n\n{content}\n")
        total_out += estimate_tokens(enc, content)
    cover = (
        "# 🔍 Chainsaw Detection Summary (LLM)\n\n"
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}\n"
        f"- Model: `{MODEL}`\n"
        f"- Chunks: {len(chunks)}\n\n---\n"
    )
    return cover + "\n".join(sections), total_in, total_out


# ---------------- Two-pass mode ----------------
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
) -> Tuple[str, int, int]:
    enc = get_encoder()
    total_in = 0
    total_out = 0

    # Pass 1: micro summaries
    micro_sections: List[str] = []
    info("Two-pass: generating micro-summaries...")
    for idx, ch in enumerate(chunks, 1):
        prompt = build_micro_prompt(ch, include_script=micro_include_script, micro_truncate=micro_truncate)
        total_in += estimate_tokens(enc, DEFAULT_SYSTEM_PROMPT) + estimate_tokens(enc, prompt)
        content = call_llm(client, DEFAULT_SYSTEM_PROMPT, prompt, temperature=0.2)
        total_out += estimate_tokens(enc, content)
        micro_sections.append(f"## Micro {idx}\n{content}")

    # Pass 2: final merge with guardrail
    final_user = build_final_merge_prompt(micro_sections)
    est_final_in = estimate_tokens(enc, DEFAULT_FINAL_SYSTEM) + estimate_tokens(enc, final_user)
    if est_final_in > final_max_input_tokens:
        info(f"Final merge prompt too large ({est_final_in} > {final_max_input_tokens}). Compressing micro-sections…")
        pairs = sorted(((estimate_tokens(enc, s), s) for s in micro_sections), key=lambda x: x[0])
        keep: List[str] = []
        running = estimate_tokens(enc, DEFAULT_FINAL_SYSTEM)
        for tok, s in pairs:
            if running + tok <= final_max_input_tokens:
                keep.append(s)
                running += tok
            else:
                break
        if not keep:
            shortened = micro_sections[0][: max(5000, final_max_input_tokens // 4)]
            keep = [shortened]
        final_user = build_final_merge_prompt(keep)

    info("Two-pass: merging micro-summaries...")
    final_content = call_llm(client, DEFAULT_FINAL_SYSTEM, final_user, temperature=0.2)
    total_in += estimate_tokens(enc, DEFAULT_FINAL_SYSTEM) + estimate_tokens(enc, final_user)
    total_out += estimate_tokens(enc, final_content)

    head = (
        "# 🔍 Chainsaw Detection Summary (LLM, Two-Pass)\n\n"
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}\n"
        f"- Model: `{MODEL}`\n"
        f"- Chunks: {len(chunks)}\n"
        f"- Mode: two-pass (micro → final)\n\n---\n"
        "## Final Executive Report\n\n"
    )
    appendix = "\n\n---\n\n## Appendix: Micro-Summaries\n\n" + "\n\n".join(micro_sections)
    return head + final_content + appendix, total_in, total_out


# ---------------- Costs ----------------
def cost_estimate(in_tokens: int, out_tokens: int) -> float:
    return round((in_tokens / 1000.0) * IN_PRICE + (out_tokens / 1000.0) * OUT_PRICE, 6)


# ---------------- HTML/PDF output helpers ----------------
def ensure_css(base_dir: Path, css_path: Optional[Path]) -> Path:
    if css_path and css_path.exists():
        return css_path
    out = base_dir / "report.css"
    if not out.exists():
        out.write_text(DEFAULT_CSS, encoding="utf-8")
    return out


def sanitize_md_for_pandoc(text: str) -> str:
    """
    Replace standalone '---' lines (Pandoc may treat as YAML front-matter) with <hr />.
    Also avoid starting the document with '---'.
    """
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
                extra_args=[
                    "--standalone",
                    "--pdf-engine=xelatex",
                    "--metadata",
                    "title=DFIR Chainsaw Summary (LLM)",
                ],
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


# ---------------- Main ----------------
def main() -> None:
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        die("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)

    cfg = parse_args()

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

    # Hunt if requested (default: on)
    if cfg.hunt:
        ensure_chainsaw_available()
        run_chainsaw_safely(
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
        run_chainsaw_safely(
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

    # Build raw MD
    raw_md = build_raw_md(detections, cfg.chunk_size)

    # Prepare chunks
    chunks = list(chunk(detections, cfg.chunk_size))

    # LLM summary (two-pass or single-pass)
    if cfg.two_pass:
        llm_md, in_tokens, out_tokens = two_pass_summarize(
            client,
            chunks,
            cfg.micro_truncate,
            cfg.micro_include_script,
            cfg.final_max_input_tokens,
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
        llm_md, in_tokens, out_tokens = call_llm_chunked(
            client,
            chunks,
            cfg.system_prompt,
            no_script=cfg.no_script,
            truncate_script=cfg.truncate_script,
        )

    # Outputs
    dated = cfg.outdir / datetime.today().strftime("%Y-%m-%d")
    raw_md_path, llm_md_path, pdf_path, html_path = write_outputs(
        dated, raw_md, llm_md, cfg.make_pdf, cfg.make_html, cfg.css_path
    )

    # Console output
    console.rule("[bold green]🔍 LLM-Summarized Report[/bold green]")
    console.print(Markdown(llm_md))
    console.rule("[bold green]End of Summary[/bold green]")

    total_tokens = in_tokens + out_tokens
    est_cost = cost_estimate(in_tokens, out_tokens)
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
    console.print(f"[cyan]💸 Estimated cost:[/cyan] ${est_cost}")


if __name__ == "__main__":
    main()
