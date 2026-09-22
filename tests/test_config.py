from __future__ import annotations

import pytest

from mobiot.config import load_config
from mobiot.exceptions import ConfigurationError


def test_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("MOBIOT_CONFIG", raising=False)
    cfg = load_config(workspace=tmp_path)
    assert cfg.workspace == tmp_path
    assert cfg.mobsf.port == 8000
    assert cfg.proxy.mode == "regular"


def test_ensure_dirs(tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    for path in (cfg.reports_dir, cfg.captures_dir, cfg.certs_dir, cfg.logs_dir, cfg.network_dir):
        assert path.is_dir()


def test_toml_override(tmp_path):
    conf = tmp_path / "config.toml"
    conf.write_text(
        "log_level = 'DEBUG'\n[proxy]\nmode = 'wireguard'\nlisten_port = 9090\n"
    )
    cfg = load_config(conf, workspace=tmp_path)
    assert cfg.log_level == "DEBUG"
    assert cfg.proxy.mode == "wireguard"
    assert cfg.proxy.listen_port == 9090


def test_invalid_proxy_mode(tmp_path):
    conf = tmp_path / "config.toml"
    conf.write_text("[proxy]\nmode = 'nonsense'\n")
    with pytest.raises(ConfigurationError):
        load_config(conf, workspace=tmp_path)


def test_missing_config_file_raises(tmp_path):
    with pytest.raises(ConfigurationError):
        load_config(tmp_path / "does-not-exist.toml")
