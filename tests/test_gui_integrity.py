import json
import runpy
from pathlib import Path

import pytest

from forensynth.cli import main, parser, run
from forensynth.gui import gui_arguments
from forensynth.integrity import verify_run


def values(**updates):
    return {
        "source_mode": "detections",
        "source": "evidence.json",
        "outdir": "reports",
        "case_id": "fixture",
        "environment": "lab",
        "html": True,
        "export-evidence-csv": True,
        "export-stix": True,
        "cloud": False,
        "cloud_authorized": False,
        "model": "gpt-5-mini",
        "limit": "1000",
        "requests": "20",
        "tokens": "100000",
    } | updates


def test_gui_defaults_offline():
    args = parser().parse_args(gui_arguments(values()))
    assert args.ai == "off"
    assert args.html and args.export_stix and args.export_evidence_csv


def test_gui_cloud_requires_explicit_authorization():
    with pytest.raises(ValueError, match="authorization"):
        gui_arguments(values(cloud=True))
    args = parser().parse_args(gui_arguments(values(cloud=True, cloud_authorized=True)))
    assert args.ai == "cloud"


def test_gui_evtx_arguments_are_literal_paths():
    args = parser().parse_args(
        gui_arguments(
            values(
                source_mode="evtx",
                rules="rules",
                mapping="map.yml",
                source="evidence;echo injected",
            )
        )
    )
    assert str(args.evtx_root) == "evidence;echo injected"


def test_run_manifest_detects_tampering(input_path, tmp_path):
    output, _ = run(parser().parse_args(["--input", str(input_path), "--outdir", str(tmp_path)]))
    assert verify_run(output) >= 4
    (output / "report.md").write_text("tampered")
    with pytest.raises(ValueError, match="mismatch"):
        verify_run(output)


@pytest.mark.parametrize("name", ["../outside", "/tmp/outside", "C:\\outside", "..\\outside"])
def test_manifest_paths_restricted(tmp_path, name):
    (tmp_path / "manifest.json").write_text(json.dumps({name: "a" * 64}))
    with pytest.raises(ValueError, match="Unsafe"):
        verify_run(tmp_path)


def test_manifest_symlinks_rejected(tmp_path):
    target = tmp_path / "target"
    target.write_text("x")
    try:
        (tmp_path / "link").symlink_to(target)
    except OSError:
        pytest.skip("Symlinks unavailable")
    (tmp_path / "manifest.json").write_text(json.dumps({"link": "a" * 64}))
    with pytest.raises(ValueError):
        verify_run(tmp_path)


def test_verify_cli(input_path, tmp_path):
    output, _ = run(parser().parse_args(["--input", str(input_path), "--outdir", str(tmp_path)]))
    assert main(["--verify-run", str(output)]) == 0


def test_distribution_checksums_cover_all_files(tmp_path):
    tool = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "tools/distribution_checksums.py")
    )
    (tmp_path / "app").write_bytes(b"fixture executable")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets/schema.json").write_text("{}")
    assert tool["checksums"](tmp_path) == 2
    assert tool["checksums"](tmp_path, True) == 2
    (tmp_path / "assets/schema.json").write_text("changed")
    with pytest.raises(ValueError, match="mismatch"):
        tool["checksums"](tmp_path, True)


def test_distribution_checksums_reject_unlisted_file(tmp_path):
    tool = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "tools/distribution_checksums.py")
    )
    (tmp_path / "app").write_bytes(b"fixture")
    tool["checksums"](tmp_path)
    (tmp_path / "extra").write_text("unlisted")
    with pytest.raises(ValueError, match="cover all"):
        tool["checksums"](tmp_path, True)
