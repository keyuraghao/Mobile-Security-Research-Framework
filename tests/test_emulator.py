"""Emulator engine: normal windowed launch, live log streaming, safe downloads.

A real emulator needs the Android SDK and host virtualization, so these tests
stub the SDK tools and check the commands and log output the engine produces.
"""
from __future__ import annotations

import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from msrf.config import load_config
from msrf.engines import emulator as emu_mod
from msrf.engines.emulator import EmulatorEngine
from msrf.exceptions import EngineError
from msrf.platform_utils import run_logged


@pytest.fixture()
def engine(tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    return EmulatorEngine(cfg)


def _stub_boot(monkeypatch, engine):
    """Pretend the SDK exists and Android boots immediately; capture launch args."""
    launched: list[list[str]] = []
    monkeypatch.setattr(engine, "_emulator", lambda: "emulator")
    monkeypatch.setattr(engine, "_adb", lambda: "adb")
    monkeypatch.setattr(engine, "_avd_exists", lambda: True)
    monkeypatch.setattr(emu_mod, "spawn", lambda args, stdout=None: launched.append(args))
    monkeypatch.setattr(
        emu_mod, "run",
        lambda cmd, **kw: SimpleNamespace(stdout="1\n" if "getprop" in cmd else "", stderr=""),
    )
    return launched


def test_start_is_normal_windowed_emulator(monkeypatch, engine):
    launched = _stub_boot(monkeypatch, engine)
    res = engine.start()
    args = launched[0]
    assert res["started"] is True
    assert args[:3] == ["emulator", "-avd", engine.cfg.avd_name]
    # Normal launch: its own window, no root-only flags.
    assert "-no-window" not in args
    assert "-writable-system" not in args
    assert "-no-snapshot" not in args


def test_start_writable_system_only_for_root_flow(monkeypatch, engine):
    launched = _stub_boot(monkeypatch, engine)
    engine.start(writable_system=True)
    assert "-writable-system" in launched[0]
    assert "-no-snapshot" in launched[0]


def test_start_headless_is_opt_in(monkeypatch, engine):
    launched = _stub_boot(monkeypatch, engine)
    engine.cfg.headless = True
    engine.start()
    assert "-no-window" in launched[0]


def test_boot_progress_goes_to_live_log(monkeypatch, engine):
    _stub_boot(monkeypatch, engine)
    engine.start()
    tail = engine.log_tail()["tail"]
    assert "Launching emulator" in tail
    assert "Android booted" in tail


def test_step_streams_command_output_to_live_log(engine):
    engine._step("Demo step", [sys.executable, "-c", "print('hello from step')"])
    tail = engine.log_tail()["tail"]
    assert "Demo step" in tail
    assert "hello from step" in tail


def test_run_logged_timeout_kills_silent_hang(tmp_path):
    from msrf.exceptions import CommandError

    with pytest.raises(CommandError):
        run_logged([sys.executable, "-c", "import time; time.sleep(30)"],
                   log_path=tmp_path / "x.log", timeout=1)


class _FakeResp:
    def __init__(self, chunks, fail_after=None):
        self._chunks = chunks
        self._fail_after = fail_after
        self.headers = {"content-length": str(sum(len(c) for c in chunks))}

    def raise_for_status(self):
        return None

    def iter_bytes(self, _size):
        for i, c in enumerate(self._chunks):
            if self._fail_after is not None and i >= self._fail_after:
                raise OSError("connection dropped")
            yield c


def _fake_stream(resp):
    @contextmanager
    def stream(*_a, **_k):
        yield resp
    return stream


def test_download_reports_progress_and_finishes(monkeypatch, engine, tmp_path):
    import httpx

    monkeypatch.setattr(httpx, "stream", _fake_stream(_FakeResp([b"a" * 1000] * 10)))
    dest = tmp_path / "img.zip"
    engine._download("https://example.invalid/img.zip", dest)
    assert dest.stat().st_size == 10_000
    assert not (tmp_path / "img.zip.part").exists()
    tail = engine.log_tail()["tail"]
    assert "100%" in tail and "Downloaded img.zip" in tail


def test_interrupted_download_leaves_no_partial_file(monkeypatch, engine, tmp_path):
    import httpx

    monkeypatch.setattr(httpx, "stream", _fake_stream(_FakeResp([b"a"] * 10, fail_after=3)))
    dest = tmp_path / "img.zip"
    with pytest.raises(EngineError):
        engine._download("https://example.invalid/img.zip", dest)
    # Neither a truncated final file nor a stale .part is left behind.
    assert not dest.exists()
    assert not (tmp_path / "img.zip.part").exists()
    assert "Download FAILED" in engine.log_tail()["tail"]


def test_provision_stops_before_restart(monkeypatch, engine):
    calls: list[str] = []
    monkeypatch.setattr(engine, "setup", lambda: calls.append("setup"))
    monkeypatch.setattr(engine, "start", lambda writable_system=False: calls.append(
        f"start(ws={writable_system})"))
    monkeypatch.setattr(engine, "root", lambda: calls.append("root"))
    monkeypatch.setattr(engine, "stop", lambda: calls.append("stop"))
    monkeypatch.setattr(engine, "install_lsposed", lambda: calls.append("lsposed"))
    monkeypatch.setattr(engine, "install_modules", lambda m=None: calls.append("modules"))
    monkeypatch.setattr(engine, "install_root_checker", lambda: calls.append("checker"))
    engine.provision()
    # Never two emulators: a stop sits between the two starts.
    assert calls == ["setup", "start(ws=True)", "root", "stop", "start(ws=True)",
                     "lsposed", "modules", "checker"]


# -- hardware acceleration / fail-fast launch ------------------------------

_ACCEL_OK = "accel:\n0\nWHPX(10.0.19045) is installed and usable.\naccel\n"
_ACCEL_BAD = ("accel:\n1\nAndroid Emulator requires an Intel/AMD processor with virtualization "
              "extension support.  (Virtualization extension is not supported)\naccel\n")
# Tail of a real Windows log where the PC had no virtualization.
_REAL_WINDOWS_FAILURE = (
    "INFO         |   Checking: hasCompatibleHypervisor\n"
    "INFO         |      Ok: Hypervisor compatibility to run avd: `msrf` are met\n"
    "WARNING      | encryption is off\n"
    "ERROR        | x86 emulation currently requires hardware acceleration!\n"
    "CPU acceleration status: Android Emulator requires an Intel/AMD processor with "
    "virtualization extension support.  (Virtualization extension is not supported)\n"
)


class _Proc:
    def __init__(self, code=None):
        self.code = code

    def poll(self):
        return self.code


def _stub_launch(monkeypatch, engine, accel=_ACCEL_OK, help_text="-no-metrics", proc=None,
                 on_spawn=None):
    launched: list[list[str]] = []
    monkeypatch.setattr(engine, "_emulator", lambda: "emulator")
    monkeypatch.setattr(engine, "_adb", lambda: "adb")
    monkeypatch.setattr(engine, "_avd_exists", lambda: True)

    def fake_spawn(args, stdout=None):
        launched.append(args)
        if on_spawn:
            on_spawn(stdout)
        return proc or _Proc()

    def fake_run(cmd, **kw):
        if "-accel-check" in cmd:
            out = accel
        elif "-help" in cmd:
            out = help_text
        elif "getprop" in cmd:
            out = "1\n"
        else:
            out = ""
        return SimpleNamespace(stdout=out, stderr="")

    monkeypatch.setattr(emu_mod, "spawn", fake_spawn)
    monkeypatch.setattr(emu_mod, "run", fake_run)
    return launched


def test_parse_accel_check():
    ok, detail = emu_mod._parse_accel_check(_ACCEL_OK)
    assert ok is True and detail == "WHPX(10.0.19045) is installed and usable."
    ok, detail = emu_mod._parse_accel_check(_ACCEL_BAD)
    assert ok is False and "not supported" in detail
    assert emu_mod._parse_accel_check("garbage")[0] is None


def test_launch_passes_no_metrics_when_supported(monkeypatch, engine):
    launched = _stub_launch(monkeypatch, engine)
    engine.start()
    assert "-no-metrics" in launched[0]


def test_launch_skips_no_metrics_on_old_emulator(monkeypatch, engine):
    launched = _stub_launch(monkeypatch, engine, help_text="-avd <name>")
    engine.start()
    assert "-no-metrics" not in launched[0]


def test_launch_refuses_without_virtualization(monkeypatch, engine):
    launched = _stub_launch(monkeypatch, engine, accel=_ACCEL_BAD)
    with pytest.raises(EngineError) as err:
        engine.start()
    assert launched == []                          # never started the emulator
    assert "virtualization" in str(err.value).lower()
    assert "fix it" in engine.log_tail()["tail"]


def test_launch_fails_fast_when_emulator_exits(monkeypatch, engine):
    import time

    def write_failure(log):
        log.write_text(_REAL_WINDOWS_FAILURE, encoding="utf-8")

    # accel-check "unknown" (older emulator): launch proceeds, then the process dies.
    _stub_launch(monkeypatch, engine, accel="", proc=_Proc(code=1), on_spawn=write_failure)
    t0 = time.monotonic()
    with pytest.raises(EngineError) as err:
        engine.start()
    assert time.monotonic() - t0 < 5               # no 5-minute wait
    msg = str(err.value)
    assert "closed right after starting" in msg
    assert "virtualization" in msg.lower()
