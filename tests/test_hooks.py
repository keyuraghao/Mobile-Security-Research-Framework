from __future__ import annotations

import pytest

from msrf.config import load_config
from msrf.engines.hooks import HooksEngine
from msrf.exceptions import EngineError
from msrf.mobsf_scripts import scripts_dir

# MobSF is an optional heavy backend; its Frida script library is only present
# when the mobsf package is installed (e.g. the standalone bundle). Skip the
# scripts-library tests cleanly when it is not (as CI does not install MobSF).
requires_mobsf_scripts = pytest.mark.skipif(
    scripts_dir() is None, reason="MobSF frida scripts not installed"
)


@pytest.fixture()
def engine(tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    return HooksEngine(cfg)


def test_list_templates(engine):
    result = engine.list_templates()
    names = {t["name"] for t in result["templates"]}
    assert "ssl-pinning-bypass" in names
    assert "hook-method" in names


def test_generate_parameterless(engine):
    result = engine.generate("ssl-pinning-bypass")
    assert "Java.perform" in result["script"]
    assert result["path"].endswith("ssl-pinning-bypass.js")


def test_generate_with_params(engine):
    result = engine.generate(
        "hook-method",
        params={"CLASS": "com.example.Foo", "METHOD": "bar"},
    )
    assert "com.example.Foo" in result["script"]
    assert "bar" in result["script"]
    assert "{{" not in result["script"]


def test_generate_missing_param(engine):
    with pytest.raises(EngineError):
        engine.generate("hook-method", params={"CLASS": "com.example.Foo"})


def test_generate_unknown_template(engine):
    with pytest.raises(EngineError):
        engine.generate("no-such-template")


def test_test_requires_target(engine):
    with pytest.raises(EngineError):
        engine.test()  # neither template nor script_path


@requires_mobsf_scripts
def test_mobsf_script_library(engine):
    res = engine.mobsf_scripts()
    assert res["count"] > 100  # MobSF ships ~118 scripts
    ids = {s["id"] for s in res["scripts"]}
    assert any(i.startswith("ios/") for i in ids)  # iOS scripts included
    assert any(i.startswith("android/") for i in ids)


@requires_mobsf_scripts
def test_mobsf_script_source_and_traversal(engine):
    import pytest as _pt
    src = engine.mobsf_script_source("android/default/ssl_pinning_bypass")["script"]
    assert "Java" in src or "console" in src or "send" in src
    with _pt.raises(Exception):
        engine.mobsf_script_source("../../../../etc/passwd")


def test_save_script_anywhere(engine, tmp_path):
    dest = tmp_path / "nested" / "my_hook"
    res = engine.save_script("Java.perform(function(){ send('x'); });", str(dest))
    from pathlib import Path
    assert Path(res["path"]).is_file()
    assert res["path"].endswith(".js")  # extension added when missing


def test_save_script_rejects_empty(engine, tmp_path):
    with pytest.raises(EngineError):
        engine.save_script("   \n", str(tmp_path / "x.js"))


def test_combine_multiple_methods_and_template(engine):
    res = engine.combine([
        {"class": "com.a.B", "method": "m1"},
        {"class": "com.a.C", "method": "m2"},
        {"template": "ssl-pinning-bypass"},
    ])
    assert res["count"] == 3
    assert res["hooks"] == ["com.a.B.m1", "com.a.C.m2", "ssl-pinning-bypass"]
    # One combined script hooking every target (each keeps its own Java.perform).
    assert res["script"].count("Java.perform") >= 3
    assert "com.a.B" in res["script"] and "com.a.C" in res["script"]


def test_combine_raw_source_and_save(engine, tmp_path):
    out = tmp_path / "combined.js"
    res = engine.combine([{"source": "// raw\nJava.perform(function(){});", "label": "mine"}],
                         out_path=str(out))
    assert out.is_file()
    assert "mine" in res["hooks"]


def test_combine_rejects_empty_and_bad_spec(engine):
    with pytest.raises(EngineError):
        engine.combine([])
    with pytest.raises(EngineError):
        engine.combine([{"nonsense": 1}])


def test_test_accepts_raw_source_on_simulator(engine):
    res = engine.test(source="Java.perform(function(){ send({tag:'t',msg:'hi'}); });",
                      device_id="sim")
    assert res["loaded"] is True
    assert res["simulated"] is True
