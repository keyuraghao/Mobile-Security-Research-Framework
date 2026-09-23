from __future__ import annotations

import pytest

from msrf.config import load_config
from msrf.engines.base import Engine
from msrf.exceptions import ConfigurationError
from msrf.registry import all_engines, engine_names, get_engine

EXPECTED = {"sast", "dast", "hooks", "runtime", "proxy", "network", "iot", "sim"}


def test_all_builtin_engines_registered():
    assert EXPECTED.issubset(set(engine_names()))


def test_get_engine_returns_instance(tmp_path):
    cfg = load_config(workspace=tmp_path)
    engine = get_engine("hooks", cfg)
    assert isinstance(engine, Engine)
    assert engine.name == "hooks"


def test_unknown_engine_raises(tmp_path):
    cfg = load_config(workspace=tmp_path)
    with pytest.raises(ConfigurationError):
        get_engine("nope", cfg)


def test_every_engine_has_actions(tmp_path):
    cfg = load_config(workspace=tmp_path)
    for engine in all_engines(cfg):
        actions = list(engine.actions())
        assert actions, f"{engine.name} has no actions"
        for spec in actions:
            assert spec.summary, f"{engine.name}.{spec.name} missing summary"


def test_preflight_returns_report(tmp_path):
    cfg = load_config(workspace=tmp_path)
    for engine in all_engines(cfg):
        report = engine.preflight()
        assert report["engine"] == engine.name
        assert "ready" in report
