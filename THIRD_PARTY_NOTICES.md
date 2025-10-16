# Third-Party Notices

ForenSynth AI references or interacts with the following third-party projects. We do **not** relicense their work; each project remains under its own license. If any third-party content is vendored inside this repo, its license file is kept alongside the code under `third_party/`.

> If you add or vendor a new dependency, update this file in the same PR.

---

## Runtime tools / rules referenced (not redistributed here)

- **Sigma Rules (SigmaHQ/sigma)**  
  Use: Rule pack loaded by Chainsaw at runtime for EVTX hunting. Not bundled.  
  License: https://github.com/SigmaHQ/sigma/blob/master/LICENSE

- **Chainsaw (WithSecureLabs/chainsaw)**  
  Use: External binary used to hunt/export detections (JSON/CSV). Not bundled.  
  License: https://github.com/WithSecureLabs/chainsaw/blob/main/LICENSE

- **SwiftOnSecurity Sysmon Config**  
  Use: Referenced config for telemetry generation in lab write-ups. Not bundled.  
  License: https://github.com/SwiftOnSecurity/sysmon-config/blob/master/LICENSE.txt

- **Pandoc** (optional exporter)  
  Use: Optional local tool to convert Markdown → PDF/HTML. Not bundled.  
  License: https://github.com/jgm/pandoc/blob/main/COPYING

- **LaTeX distribution (MiKTeX/TeX Live)** (optional exporter)  
  Use: Optional local typesetting for PDF output. Not bundled.  
  Info: https://miktex.org/copying  |  https://www.tug.org/texlive/copying.html

## Python libraries (installed via `requirements.txt`)

- This project uses common Python packages (e.g., `openai`, `jinja2`, `pandas`, `rich`, etc.).  
  Each package remains under its own license as published on PyPI/GitHub.  
  Consider generating a summary with `pip-licenses` and placing it in `docs/`.

---

## Vendored content (only if you commit third-party code)

If you copy any third-party code/configs into this repo, place them under:

- `third_party/<project_name>/`
  - `(original files)`
  - `LICENSE` *(the project’s original license file)*

Then add a short entry above pointing to `third_party/<project_name>/LICENSE`.

