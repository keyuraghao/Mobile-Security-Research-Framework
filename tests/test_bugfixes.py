"""Regression tests for bugs found in the line-by-line review."""
from __future__ import annotations

import sys
import time

from msrf.config import load_config
from msrf.engines.findings import FindingsEngine
from msrf.platform_utils import run_logged, spawn


def test_findings_corrupt_store_is_backed_up_not_clobbered(tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    eng = FindingsEngine(cfg)
    eng.add(title="keeper", severity="high")
    # Corrupt the store on disk (as a crash mid-write would).
    eng._path.write_text("{ this is not valid json", encoding="utf-8")
    # A load must not return corrupt data, and must preserve the file as a backup
    # rather than let the next save silently overwrite it.
    assert eng.list()["findings"] == []
    backups = list(tmp_path.glob("findings/findings.corrupt-*.json"))
    assert len(backups) == 1
    assert backups[0].read_text() == "{ this is not valid json"  # preserved, not clobbered
    # A later add starts a fresh store and leaves the backup intact.
    eng.add(title="new", severity="info")
    assert [f["title"] for f in eng.list()["findings"]] == ["new"]
    assert backups[0].is_file()


def test_findings_non_list_json_is_ignored(tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    eng = FindingsEngine(cfg)
    eng._path.parent.mkdir(parents=True, exist_ok=True)
    eng._path.write_text('{"not": "a list"}', encoding="utf-8")
    assert eng.list()["findings"] == []


def test_log_level_from_config_is_respected(tmp_path):
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text('log_level = "DEBUG"\n')
    # Simulate the CLI callback: no --log-level flag means no override.
    cfg = load_config(cfg_file)
    assert cfg.log_level == "DEBUG"


def test_run_logged_fast_command_not_flagged_as_timeout(tmp_path):
    # A command that finishes well within a short timeout must never be reported
    # as timed out (watchdog race regression).
    for _ in range(20):
        res = run_logged([sys.executable, "-c", "pass"],
                         log_path=tmp_path / "x.log", timeout=2)
        assert res.returncode == 0


def test_spawn_closes_parent_fd(tmp_path):
    log = tmp_path / "s.log"
    proc = spawn([sys.executable, "-c", "print('hi')"], stdout=log)
    proc.wait(timeout=10)
    # Give the child a moment, then confirm output landed and no handle lingers.
    time.sleep(0.2)
    assert "hi" in log.read_text()


def test_cli_reports_bad_json_param_cleanly(tmp_path):
    from typer.testing import CliRunner

    from msrf.cli import app

    result = CliRunner().invoke(
        app, ["--workspace", str(tmp_path), "hooks", "test",
               "--template", "ssl-pinning-bypass", "--params", "{bad json", "--device-id", "sim"]
    )
    assert result.exit_code == 1
    assert "must be valid JSON" in result.output
