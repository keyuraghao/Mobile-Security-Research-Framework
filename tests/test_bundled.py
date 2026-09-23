from __future__ import annotations

from msrf import bundled
from msrf.config import load_config


def test_no_vendor_is_noop(tmp_path, monkeypatch):
    monkeypatch.delenv("MSRF_VENDOR_DIR", raising=False)
    cfg = load_config(workspace=tmp_path)
    report = bundled.activate(cfg)
    # Not frozen and no vendor dir -> nothing bundled, no error.
    assert report["bundled"] is False


def test_vendor_dir_detected_and_wired(tmp_path, monkeypatch):
    vendor = tmp_path / "vendor"
    # Fake a jadx launcher and a frida-server dir.
    (vendor / "jadx" / "bin").mkdir(parents=True)
    jadx = vendor / "jadx" / "bin" / "jadx"
    jadx.write_text("#!/bin/sh\n")
    jadx.chmod(0o755)
    (vendor / "frida-server").mkdir(parents=True)
    monkeypatch.setenv("MSRF_VENDOR_DIR", str(vendor))

    cfg = load_config(workspace=tmp_path)
    report = bundled.activate(cfg)
    assert report["bundled"] is True
    assert report.get("jadx", "").endswith("jadx")
    assert cfg.frida.server_dir == vendor / "frida-server"
    assert cfg.mobsf.use_system_jadx is True
