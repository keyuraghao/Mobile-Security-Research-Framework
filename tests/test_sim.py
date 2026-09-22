from __future__ import annotations

import pytest

from mobiot.config import load_config
from mobiot.engines.hooks import HooksEngine
from mobiot.engines.sim import SimEngine
from mobiot.sim import FridaScriptSimulator, SimDevice


@pytest.fixture()
def sim(tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    return SimEngine(cfg)


def test_default_device_has_diva():
    device = SimDevice.default()
    ids = {a.identifier for a in device.apps}
    assert "jakhar.aseem.diva" in ids
    assert device.abi == "arm64-v8a"


def test_validate_catches_placeholder():
    sim = FridaScriptSimulator()
    report = sim.validate("Java.perform(function(){ var X = '{{CLASS}}'; });")
    assert not report["ok"]
    assert any("placeholder" in i for i in report["issues"])


def test_validate_catches_unbalanced():
    sim = FridaScriptSimulator()
    report = sim.validate("Java.perform(function(){ ")
    assert not report["ok"]


def test_validate_ok_for_valid_script():
    sim = FridaScriptSimulator()
    report = sim.validate("Java.perform(function(){ send({tag:'x', msg:'hi'}); });")
    assert report["ok"], report["issues"]


def test_simulate_ssl_pinning():
    sim = FridaScriptSimulator()
    src = "Java.perform(function(){ send({tag:'ssl-pinning-bypass', msg:'x'}); });"
    msgs = sim.simulate(src)
    assert any("SSL pinning bypass installed" in m["msg"] for m in msgs)


def test_run_hook_produces_messages(sim):
    result = sim.run_hook(template="ssl-pinning-bypass")
    assert result["loaded"] is True
    assert result["message_count"] > 0
    assert result["device"] == "sim"


def test_run_hook_hook_method_reflects_params(sim):
    result = sim.run_hook(
        template="hook-method",
        params={"CLASS": "a.B", "METHOD": "c"},
    )
    joined = " ".join(m["msg"] for m in result["messages"])
    assert "a.B" in joined and "c" in joined


def test_hooks_test_via_sim_device(tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    engine = HooksEngine(cfg)
    # device_id="sim" must work with no frida / no device attached.
    result = engine.test(template="root-bypass", device_id="sim")
    assert result["simulated"] is True
    assert result["loaded"] is True
    assert any("Root detection bypass installed" in m["msg"] for m in result["messages"])
