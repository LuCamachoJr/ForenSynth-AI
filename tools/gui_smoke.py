"""Exercise the actual Tkinter UI against a synthetic offline export."""

import tempfile
import time
import tkinter as tk
from pathlib import Path

from forensynth.gui import Application
from forensynth.integrity import verify_run

root = tk.Tk()
app = Application(root)
app.vars["source"].set(str(Path("examples/v2.4/synthetic_detections.json").resolve()))
app.vars["environment"].set("simulation")
app.vars["authorized-test"].set(True)
with tempfile.TemporaryDirectory() as output:
    app.vars["outdir"].set(output)
    app.start()
    deadline = time.monotonic() + 30
    while app.running and time.monotonic() < deadline:
        root.update()
        time.sleep(0.05)
    assert not app.running and app.output, app.status.get()
    assert verify_run(app.output) > 0
    print(app.status.get())
root.destroy()
