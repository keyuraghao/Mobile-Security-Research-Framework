from __future__ import annotations

import os

import pytest

# The GUI is optional; skip cleanly if PyQt6 isn't installed.
pytest.importorskip("PyQt6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from mobiot.config import load_config  # noqa: E402
from mobiot.gui.main import MainWindow  # noqa: E402

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
