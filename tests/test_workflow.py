"""Workflow engine: one-step assessments (also exposed on CLI + MCP)."""
from __future__ import annotations

from pathlib import Path

import pytest

from msrf.config import load_config
from msrf.engines.workflow import WorkflowEngine

DIVA = Path(__file__).resolve().parent.parent / "Test_Aplication" / "diva-beta.apk"


def _engine(tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    return WorkflowEngine(cfg)


def test_list_assessments(tmp_path):
    names = {a["name"] for a in _engine(tmp_path).list_assessments()["assessments"]}
    assert {"static_assessment", "dynamic_smoke"} <= names


def test_dynamic_smoke_on_simulator(tmp_path):
    res = _engine(tmp_path).dynamic_smoke(package="jakhar.aseem.diva", device_id="sim")
    assert res["assessment"] == "dynamic_smoke"
    assert len(res["checks"]) == 3
    # On the simulator every listed hook loads.
    assert all(c.get("loaded") for c in res["checks"])


@pytest.mark.skipif(not DIVA.is_file(), reason="sample APK not present")
def test_static_assessment_end_to_end(tmp_path):
    pytest.importorskip("mobsf")
    res = _engine(tmp_path).static_assessment(str(DIVA), report_format="json")
    assert res["assessment"] == "static"
    assert res["scan_hash"]
    assert res["findings_imported"] > 0
    assert res["high"] >= 1
    assert Path(res["report"]).is_file()
    # Steps ran in order.
    assert [s["step"] for s in res["steps"]] == [
        "scan", "report_loaded", "import_findings", "report"]
