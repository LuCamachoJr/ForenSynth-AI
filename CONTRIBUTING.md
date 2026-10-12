# Contributing

Develop against `src/forensynth`, with regression tests in `tests`. Historical scripts
are snapshots, not active implementation targets. Submit changes through pull requests.

Install `python -m pip install -e '.[llm,dev]'` and run the tests and lint commands in
README. CI requires them to pass on Python 3.11 and 3.12.

Use synthetic or explicitly shareable evidence fixtures. Do not commit API keys,
private customer telemetry, memory dumps, or collected EVTX. Reports may contain
hostnames, accounts, commands, paths, and observables; review before sharing.

Schema changes must declare compatibility and update validation, exports, documentation,
and meaningful regression tests. An AI-generated finding must retain source references,
classification, limitations, and pending analyst review. Do not promote rule matches
or unassessed observables into confirmed compromises or malicious indicators.

Report bugs with version, sanitized reproduction, expected behavior, and actual behavior.
Include source/model/tool versions where relevant; do not include secrets.
