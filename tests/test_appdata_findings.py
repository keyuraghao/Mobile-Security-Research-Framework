from __future__ import annotations

import pytest

from mobiot.config import load_config
from mobiot.engines.appdata import AppDataEngine
from mobiot.engines.findings import FindingsEngine
from mobiot.reporting import FORMATS


@pytest.fixture()
def cfg(tmp_path):
    c = load_config(workspace=tmp_path)
    c.ensure_dirs()
    return c


def test_appdata_sim_pull_and_parse(cfg):
    eng = AppDataEngine(cfg)
    pull = eng.pull("jakhar.aseem.diva", device_id="sim")
    assert any(f.endswith(".db") for f in pull["files"])
    files = eng.databases("jakhar.aseem.diva")["files"]
    db = next(f for f in files if f["type"] == "sqlite")
    tables = eng.tables(db["path"])["tables"]
    names = {t["name"] for t in tables}
    assert "myuser" in names
    rows = eng.rows(db["path"], "myuser")
    assert rows["columns"] == ["user", "password"]
    assert any("admin" in r for r in rows["rows"])


def test_appdata_rejects_path_traversal(cfg):
    eng = AppDataEngine(cfg)
    eng.pull("com.x", device_id="sim")
    with pytest.raises(Exception):
        eng.open("/etc/passwd")


def test_findings_add_list_delete(cfg):
    eng = FindingsEngine(cfg)
    item = eng.add("Test issue", severity="high", description="d", target="app")
    assert eng.list()["findings"]
    eng.delete(item["id"])
    assert eng.list()["findings"] == []


def test_findings_reports_all_formats(cfg):
    eng = FindingsEngine(cfg)
    eng.add("Issue A", severity="high")
    eng.add("Issue B", severity="warning")
    assert set(eng.report_formats()["formats"]) == set(FORMATS)
    for fmt in FORMATS:
        result = eng.report(format=fmt)
        from pathlib import Path

        assert Path(result["report"]).is_file()
        assert Path(result["report"]).stat().st_size > 0


def test_findings_import_scan_missing(cfg):
    eng = FindingsEngine(cfg)
    assert eng.import_scan("deadbeef")["imported"] == 0
