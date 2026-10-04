"""Tests for the CLI: stdin/file modes, --check, --in-place, --json-report."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parent.parent
SECRET_LINE = "deploy key=sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs end\n"
CLEAN_LINE = "all clear, nothing here\n"


def run_cli(*args, stdin_text=None):
    env = {"PYTHONPATH": str(PKG), "PATH": "/usr/bin:/bin"}
    return subprocess.run(
        [sys.executable, "-m", "logredact.cli", *args],
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(PKG),
    )


def test_stdin_to_stdout():
    proc = run_cli(stdin_text=SECRET_LINE)
    assert proc.returncode == 0
    assert "[REDACTED:OPENAI_API_KEY]" in proc.stdout
    assert "sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs" not in proc.stdout


def test_check_mode_exit_codes(tmp_path):
    dirty = tmp_path / "dirty.log"
    dirty.write_text(SECRET_LINE)
    clean = tmp_path / "clean.log"
    clean.write_text(CLEAN_LINE)

    assert run_cli("--check", str(dirty)).returncode == 1
    assert run_cli("--check", str(clean)).returncode == 0


def test_check_mode_prints_no_log_contents():
    proc = run_cli("--check", stdin_text=SECRET_LINE)
    assert proc.returncode == 1
    assert "sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs" not in proc.stdout
    assert "sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs" not in proc.stderr


def test_in_place_rewrites_file(tmp_path):
    target = tmp_path / "app.log"
    target.write_text(SECRET_LINE + CLEAN_LINE)
    proc = run_cli("--in-place", str(target))
    assert proc.returncode == 0
    rewritten = target.read_text()
    assert "[REDACTED:OPENAI_API_KEY]" in rewritten
    assert "sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs" not in rewritten
    assert CLEAN_LINE in rewritten


def test_json_report_lists_findings():
    proc = run_cli("--json-report", "--check", stdin_text=SECRET_LINE)
    report = json.loads(proc.stdout)
    assert len(report) == 1
    assert report[0]["kind"] == "OPENAI_API_KEY"
    assert report[0]["line"] == 1
    assert "preview" in report[0]


def test_multiple_files(tmp_path):
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text(SECRET_LINE)
    b.write_text(CLEAN_LINE)
    proc = run_cli(str(a), str(b))
    assert proc.returncode == 0
    assert proc.stdout.count("[REDACTED:OPENAI_API_KEY]") == 1
    assert "all clear" in proc.stdout
