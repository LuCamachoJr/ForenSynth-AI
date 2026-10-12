"""Local Windows/Linux desktop interface; no web listener or shell command construction."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .cli import parser, run
from .integrity import verify_run


def gui_arguments(values):
    """Pure argument mapping, also exercised without a graphical display."""
    source = "--input" if values["source_mode"] == "detections" else "--evtx-root"
    arguments = [
        source,
        values["source"],
        "--outdir",
        values["outdir"],
        "--case-id",
        values["case_id"],
        "--environment",
        values["environment"],
    ]
    if source == "--evtx-root":
        arguments.extend(["--rules", values["rules"], "--mapping", values["mapping"]])
    for name in ("html", "export-evidence-csv", "export-stix", "authorized-test"):
        if values.get(name):
            arguments.append("--" + name)
    if values.get("cloud"):
        if not values.get("cloud_authorized"):
            raise ValueError("Confirm authorization to send selected evidence fields to OpenAI")
        arguments.extend(
            [
                "--ai",
                "cloud",
                "--model",
                values["model"],
                "--limit-detections",
                str(values["limit"]),
                "--max-requests",
                str(values["requests"]),
                "--max-total-tokens",
                str(values["tokens"]),
            ]
        )
    return arguments


def open_local_path(path):
    target = Path(path).resolve(strict=True)
    if sys.platform == "win32":
        os.startfile(str(target))
    else:
        subprocess.Popen(
            ["xdg-open", str(target)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


class Application:
    def __init__(self, root):
        self.root = root
        self.messages = queue.Queue()
        self.running = False
        self.output = None
        root.title(f"ForenSynth AI {__version__} — Evidence Review")
        root.geometry("920x780")
        root.minsize(780, 650)
        root.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("TkDefaultFont", 19, "bold"))
        style.configure("TButton", padding=7)
        frame = ttk.Frame(root, padding=20)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="ForenSynth AI", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            frame, text="Evidence-linked DFIR reports • Offline by default • Analyst reviewed"
        ).pack(anchor="w", pady=(4, 16))
        self.vars = {
            "source_mode": tk.StringVar(value="detections"),
            "source": tk.StringVar(),
            "rules": tk.StringVar(),
            "mapping": tk.StringVar(),
            "outdir": tk.StringVar(value=str(Path.home() / "ForenSynth" / "Reports")),
            "case_id": tk.StringVar(value="case-001"),
            "environment": tk.StringVar(value="unknown"),
            "html": tk.BooleanVar(value=True),
            "export-evidence-csv": tk.BooleanVar(value=True),
            "export-stix": tk.BooleanVar(value=True),
            "authorized-test": tk.BooleanVar(value=False),
            "cloud": tk.BooleanVar(value=False),
            "cloud_authorized": tk.BooleanVar(value=False),
            "model": tk.StringVar(value="gpt-5-mini"),
            "limit": tk.StringVar(value="1000"),
            "requests": tk.StringVar(value="20"),
            "tokens": tk.StringVar(value="100000"),
        }
        inputs = ttk.LabelFrame(frame, text="Source and case", padding=12)
        inputs.pack(fill="x", pady=4)
        inputs.columnconfigure(1, weight=1)
        ttk.Label(inputs, text="Source type").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            inputs,
            state="readonly",
            values=["detections", "evtx"],
            textvariable=self.vars["source_mode"],
            width=20,
        ).grid(row=0, column=1, sticky="w", padx=8)
        self.path_row(inputs, 1, "Evidence source", "source", self.browse_source)
        self.path_row(inputs, 2, "Sigma rules (EVTX)", "rules", lambda: self.browse_dir("rules"))
        self.path_row(inputs, 3, "Mapping (EVTX)", "mapping", lambda: self.browse_file("mapping"))
        self.path_row(inputs, 4, "Output folder", "outdir", lambda: self.browse_dir("outdir"))
        ttk.Label(inputs, text="Case ID").grid(row=5, column=0, sticky="w", pady=5)
        ttk.Entry(inputs, textvariable=self.vars["case_id"]).grid(
            row=5, column=1, sticky="ew", padx=8
        )
        ttk.Combobox(
            inputs,
            state="readonly",
            values=["unknown", "lab", "simulation", "production"],
            textvariable=self.vars["environment"],
            width=16,
        ).grid(row=5, column=2)
        ttk.Checkbutton(
            inputs, text="Authorized test activity", variable=self.vars["authorized-test"]
        ).grid(row=6, column=1, sticky="w")
        outputs = ttk.LabelFrame(frame, text="Report exports", padding=10)
        outputs.pack(fill="x", pady=8)
        for index, (key, label) in enumerate(
            [
                ("html", "HTML report"),
                ("export-evidence-csv", "Evidence CSV"),
                ("export-stix", "STIX 2.1 bundle"),
            ]
        ):
            ttk.Checkbutton(outputs, text=label, variable=self.vars[key]).grid(
                row=0, column=index, padx=12
            )
        ttk.Label(
            outputs,
            text="Full evidence and SHA-256 manifest are always written. Indicators require analyst review.",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        ai = ttk.LabelFrame(frame, text="Optional cloud synthesis", padding=10)
        ai.pack(fill="x", pady=4)
        ttk.Checkbutton(
            ai,
            text="Enable OpenAI (uses OPENAI_API_KEY from the environment)",
            variable=self.vars["cloud"],
        ).grid(row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(
            ai, text="Selected host, account, command and script fields may contain sensitive data."
        ).grid(row=1, column=0, columnspan=4, sticky="w")
        ttk.Checkbutton(
            ai,
            text="I am authorized to send these fields to OpenAI",
            variable=self.vars["cloud_authorized"],
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=4)
        for index, (key, label) in enumerate(
            [
                ("model", "Model"),
                ("limit", "AI selection limit"),
                ("requests", "Max requests"),
                ("tokens", "Token budget"),
            ]
        ):
            ttk.Label(ai, text=label).grid(row=3, column=index, sticky="w", padx=6)
            ttk.Entry(ai, textvariable=self.vars[key], width=18 if index == 0 else 14).grid(
                row=4, column=index, padx=6, pady=4, sticky="ew"
            )
        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=12)
        self.run_button = ttk.Button(actions, text="Create report", command=self.start)
        self.run_button.pack(side="left")
        self.verify_button = ttk.Button(actions, text="Verify run checksums", command=self.verify)
        self.verify_button.pack(side="left", padx=10)
        self.open_button = ttk.Button(
            actions, text="Open output folder", command=self.open_output, state="disabled"
        )
        self.open_button.pack(side="left")
        self.progress = ttk.Progressbar(frame, mode="indeterminate")
        self.progress.pack(fill="x")
        self.status = tk.StringVar(
            value="Ready. Processing stays local unless cloud synthesis is enabled."
        )
        ttk.Label(frame, textvariable=self.status, wraplength=850).pack(anchor="w", pady=8)
        self.log = tk.Text(frame, height=6, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text="Beta: findings need review. Checksums detect changes; unsigned manifests do not prove authorship.",
            wraplength=850,
        ).pack(anchor="w", pady=(8, 0))
        root.after(100, self.poll)

    def path_row(self, frame, row, label, key, browse):
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.vars[key]).grid(row=row, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text="Browse", command=browse).grid(row=row, column=2)

    def browse_file(self, key):
        value = filedialog.askopenfilename(parent=self.root)
        if value:
            self.vars[key].set(value)

    def browse_dir(self, key):
        value = filedialog.askdirectory(parent=self.root)
        if value:
            self.vars[key].set(value)

    def browse_source(self):
        if self.vars["source_mode"].get() == "evtx":
            self.browse_dir("source")
        else:
            self.browse_file("source")

    def set_busy(self, value):
        self.running = value
        for button in (self.run_button, self.verify_button):
            button.configure(state="disabled" if value else "normal")
        if value:
            self.progress.start(15)
        else:
            self.progress.stop()

    def start(self):
        if self.running:
            return
        try:
            values = {key: value.get() for key, value in self.vars.items()}
            if not values["source"] or not values["outdir"]:
                raise ValueError("Choose an evidence source and output folder")
            args = parser().parse_args(gui_arguments(values))
        except (ValueError, SystemExit) as exc:
            messagebox.showerror("Check inputs", str(exc), parent=self.root)
            return
        self.set_busy(True)
        self.status.set("Processing evidence. Keep the application open until completion.")

        def work():
            try:
                output, doc = run(args)
                checked = verify_run(output)
                self.messages.put(
                    (
                        "done",
                        output,
                        f"Created {len(doc['detections'])} matches / {len(doc['events'])} events. Verified {checked} files. Warnings: {len(doc['run']['warnings'])}.",
                    )
                )
            except Exception as exc:
                self.messages.put(("error", None, f"{type(exc).__name__}: {exc}"))

        threading.Thread(target=work, daemon=True).start()

    def verify(self):
        folder = filedialog.askdirectory(parent=self.root, title="Choose a completed run folder")
        if not folder:
            return
        self.set_busy(True)

        def work():
            try:
                count = verify_run(folder)
                self.messages.put(
                    (
                        "verified",
                        Path(folder),
                        f"SHA-256 matches for {count} files. This verifies consistency with the unsigned manifest.",
                    )
                )
            except Exception as exc:
                self.messages.put(("error", None, f"Verification failed: {exc}"))

        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        try:
            while True:
                kind, output, text = self.messages.get_nowait()
                self.set_busy(False)
                self.status.set(text)
                self.log.configure(state="normal")
                self.log.insert("end", text + "\n")
                self.log.see("end")
                self.log.configure(state="disabled")
                if output:
                    self.output = output
                    self.open_button.configure(state="normal")
                if kind == "error":
                    messagebox.showerror("ForenSynth", text, parent=self.root)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def open_output(self):
        try:
            if self.output:
                open_local_path(self.output)
        except OSError as exc:
            messagebox.showerror("Open folder", str(exc), parent=self.root)

    def close(self):
        if self.running:
            messagebox.showinfo(
                "Processing in progress",
                "Wait for processing to finish before closing.",
                parent=self.root,
            )
            return
        self.root.destroy()


def main():
    root = tk.Tk()
    Application(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
