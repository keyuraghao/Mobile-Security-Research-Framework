from __future__ import annotations

import os

import pytest

# The GUI is optional; skip cleanly if PyQt6 isn't installed.
pytest.importorskip("PyQt6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from msrf.config import load_config  # noqa: E402
from msrf.gui.main import MainWindow  # noqa: E402

# Keep windows alive for the whole module: a window that is garbage-collected
# while its worker threads are still running crashes Qt when the result signal
# is delivered to the deleted C++ object.
_WINDOWS: list[MainWindow] = []


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app
    # Drain any outstanding workers before the module tears down.
    from PyQt6.QtCore import QThreadPool

    QThreadPool.globalInstance().waitForDone(5000)
    for _ in range(5):
        app.processEvents()


def _make_window(cfg) -> MainWindow:
    win = MainWindow(cfg)
    _WINDOWS.append(win)
    return win


def _drain(qapp, win) -> None:
    win.pool.waitForDone(5000)
    for _ in range(5):
        qapp.processEvents()


def test_mainwindow_builds_all_tabs(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    titles = [win.tabs.tabText(i) for i in range(win.tabs.count())]
    assert titles == [
        "Dashboard",
        "Static (SAST)",
        "Frida Hooks",
        "Dynamic (DAST)",
        "Emulator",
        "App Data",
        "Proxy",
        "Network",
        "IoT",
        "Findings",
        "Help",
    ]


def test_sast_view_has_all_analyzer_tabs(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    sub = [win.sast_view.tabs.tabText(i) for i in range(win.sast_view.tabs.count())]
    for expected in (
        "Overview", "Findings", "Permissions", "Certificate", "Manifest",
        "Network", "Code Analysis", "Binary / NDK", "API", "Trackers",
        "Secrets", "Components", "Files", "Raw JSON",
    ):
        assert expected in sub


def test_hook_library_loads_into_combo(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    win._load_hooks()
    _drain(qapp, win)
    assert win.hook_combo.count() >= 15  # large inbuilt library


def test_sast_view_populates_tables(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    ctx = {
        "file_name": "x.apk",
        "package_name": "com.x",
        "appsec": {
            "security_score": 42,
            "high": [{"title": "H", "description": "d"}],
            "warning": [], "info": [],
        },
        "permissions": {"android.permission.INTERNET": {"status": "normal", "info": "net"}},
        "certificate_analysis": {"certificate_findings": [["info", "signed", "ok"]]},
        "manifest_analysis": {
            "manifest_findings": [{"severity": "high", "title": "t", "description": "d"}]
        },
        "code_analysis": {
            "findings": {"rule1": {"metadata": {"severity": "warning"}, "files": {"a.java": "1"}}}
        },
        "files": ["a/b.txt", "c.xml"],
    }
    win.sast_view._populate(ctx)
    assert "42" in win.sast_view.summary.text()
    assert win.sast_view.t_findings.rowCount() == 1
    assert win.sast_view.t_perms.rowCount() == 1
    assert win.sast_view.t_code.rowCount() == 1
    assert win.sast_view.file_tree.topLevelItemCount() == 2  # 'a' dir + 'c.xml'


class _SlowEmulator:
    """Stands in for the emulator engine: writes to the live log over ~1.5s."""

    def __init__(self, log_path):
        self.log_path = log_path

    def start(self):
        import time

        for i in range(3):
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"boot line {i}\n")
            time.sleep(0.5)
        return {"started": True}


def _find_emulator_view(win):
    from msrf.gui.emulator_view import EmulatorView

    for i in range(win.tabs.count()):
        if isinstance(win.tabs.widget(i), EmulatorView):
            return win.tabs.widget(i)
    raise AssertionError("Emulator tab not found")


def test_emulator_tab_shows_live_log_progress_and_resets(qapp, tmp_path):
    import time

    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    view = _find_emulator_view(win)
    win._engines["emulator"] = _SlowEmulator(cfg.logs_dir / "emulator.log")

    launch = next(b for b in view._busy_buttons if b.text() == "Launch emulator")
    launch.click()
    assert view.progress.maximum() == 0          # busy animation on
    assert not launch.isEnabled()                # no double launch
    assert "Running: Launching emulator" in view.activity.text()

    # Log lines must appear while the step is still running (live, not at the end).
    seen_live = False
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and not seen_live:
        qapp.processEvents()
        if "boot line 0" in view.output.toPlainText() and view._steps:
            seen_live = True
        time.sleep(0.05)
    assert seen_live

    _drain(qapp, win)
    for _ in range(10):
        qapp.processEvents()
    text = view.output.toPlainText()
    assert "boot line 2" in text
    assert "✔ Launching emulator" in text
    assert view.progress.maximum() == 1          # busy animation off
    assert launch.isEnabled()
    assert view.activity.text().startswith("Idle")


def test_background_connection_poll_is_quiet(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    assert win._conn_timer.interval() == 30000   # not every 6s any more
    busy_before = win._busy
    win._refresh_connection()
    assert win._busy == busy_before              # no busy flicker for the poll
    _drain(qapp, win)


def test_severity_sorts_most_severe_first(qapp):
    from msrf.gui.sast_view import _Table

    t = _Table(["Severity", "Issue"])
    t.fill([["info", "a"], ["warning", "b"], ["high", "c"], ["secure", "d"], ["high", "e"]],
           sev_col=0)
    order = [t.item(r, 0).text() for r in range(t.rowCount())]
    assert order == ["high", "high", "warning", "info", "secure"]


def test_dast_simulator_target_enumerates_and_explains_hardware_only(qapp, tmp_path):
    from msrf.gui.dast_view import DastView

    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    view = next(win.tabs.widget(i) for i in range(win.tabs.count())
                if isinstance(win.tabs.widget(i), DastView))
    view.device.setCurrentIndex(view.device.findData("sim"))

    view.technique.setCurrentIndex(view.technique.findText("Enumerate: applications"))
    view._run()
    _drain(qapp, win)
    out = view.output.toPlainText()
    assert "jakhar.aseem.diva" in out
    assert "error" not in out.lower()

    view.technique.setCurrentIndex(view.technique.findText("Device: capture logcat"))
    view._run()
    _drain(qapp, win)
    assert "needs a real device or the emulator" in view.output.toPlainText()
