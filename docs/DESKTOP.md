# ForenSynth AI desktop beta

The GUI runs locally on Windows and Linux using Tkinter. There is no web listener,
telemetry upload, or browser-hosted evidence processing. Cloud synthesis is opt-in.

## Run from Python

Requires Python 3.11+. Windows Python installers normally include Tcl/Tk. On
Debian/Ubuntu Linux, install `python3-tk` for the Python version you use.

```sh
python -m venv venv
# Windows: venv\Scripts\activate
# Linux: source venv/bin/activate
python -m pip install '.[llm]'
forensynth-gui
```

Without installing the package, after installing runtime dependencies:
`PYTHONPATH=src python -m forensynth.gui` on Linux; installing is recommended on Windows.

Choose a detection export or collected EVTX directory, set the case context and
output folder, then select Create report. EVTX mode requires Chainsaw on PATH,
a Sigma directory, and a compatible mapping. Keep the app open during processing.
Long-running work runs off the GUI thread; results return through a queue.

Reports use a unique output directory. Evidence JSON and original bytes are always
retained. HTML, CSV, and STIX exports are selected by default. After processing,
all generated run files are SHA-256 checked. Verify run checksums can recheck a
completed folder later. CLI equivalent: `forensynth --verify-run /path/to/run`.

## Cloud AI

Set `OPENAI_API_KEY` in the launching environment. The GUI does not save keys or
read a secrets file. Enable OpenAI and confirm authorization to send selected
fields. Host/account names, commands, and scripts can contain sensitive information.
API usage is separately billed by your provider; source installation costs nothing.
The GUI exposes a model, selection limit, request cap, and estimated token budget.
For reviewed indicators and pinned ATT&CK datasets, use the CLI advanced options.

## Desktop packages

The **Build desktop beta** workflow produces separate Windows and Ubuntu x64
artifacts with a `SHA256SUMS` file covering all distribution files. Download the
artifact from the repository's Actions page, extract the complete folder, and
launch `ForenSynth-AI.exe` on Windows or `ForenSynth-AI` on Linux. Do not move the
executable out of its supporting directory. Linux builds target Ubuntu 22.04 or
newer compatible desktops; other distributions need their own compatibility tests.

These are beta build artifacts, not signed production installers. Windows builds
must be built on Windows; this project does not cross-compile them on Linux.

Build locally:

```sh
python -m pip install '.[llm,desktop]'
pyinstaller --noconfirm --clean --onedir --windowed --name ForenSynth-AI --collect-data forensynth --collect-all stix2 --collect-all jsonschema --collect-all jsonschema_specifications tools/launch_gui.py
python tools/distribution_checksums.py dist/ForenSynth-AI
python tools/distribution_checksums.py dist/ForenSynth-AI --verify
```

For a single file, Windows `Get-FileHash PATH -Algorithm SHA256` and Linux
`sha256sum PATH` compute checksums. For the whole build, use the verification
script above. Hashes prove consistency with the checksum list, not publisher
identity. Obtain both from the expected repository; independent code signing
and authenticated release distribution remain future release work.

## Secure implementation choices

- Offline default; cloud authorization is separate and explicit.
- API key stays in the environment, never written to project outputs.
- No shell interpolation; Chainsaw receives a list of arguments.
- Original source bytes preserved; normalized data validated and references checked.
- HTML text escaped, CSV formula prefixes neutralized, STIX patterns validated.
- Checksum verification rejects traversal, absolute paths, malformed hashes and symlinks.
- Model refusals and unsupported evidence references are rejected, not rendered as facts.
- No remediation actions or automatic execution of evidence content.

Secure coding reduces specific risks; independent security review and real-world
Windows/Linux testing remain necessary before production adoption.
