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
        "Activity",
        "Settings",
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


def _hooks_view(win):
    from msrf.gui.hooks_view import HooksView

    return next(win.tabs.widget(i) for i in range(win.tabs.count())
                if isinstance(win.tabs.widget(i), HooksView))


def test_hook_library_loads_into_combo(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    view = _hooks_view(win)
    assert view.combo.count() >= 15  # large inbuilt library


def test_multi_hook_builds_combined_script(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    view = _hooks_view(win)
    # Two method rows on two classes, one library hook row.
    view.multi.setRowCount(0)
    view._multi_add_row("com.a.B", "login")
    view._multi_add_row("com.a.C", "check")
    view.multi_lib.setCurrentIndex(view.multi_lib.findData("ssl-pinning-bypass"))
    view._multi_add_lib()
    view._multi_build()
    _drain(qapp, win)
    script = view.custom.toPlainText()
    assert script.count("Java.perform") >= 3
    assert "com.a.B" in script and "com.a.C" in script


def test_custom_hook_runs_typed_source_on_simulator(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    view = _hooks_view(win)
    view.device.setCurrentIndex(view.device.findData("sim"))
    view.custom.setPlainText("Java.perform(function(){ send({tag:'t', msg:'hi'}); });")
    view._custom_run()
    _drain(qapp, win)
    assert "loaded=True" in view.output.toPlainText()


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


def test_settings_save_and_reload_roundtrip(qapp, tmp_path, monkeypatch):
    import msrf.config as cfgmod
    from msrf.config import load_config

    # Redirect the default config path into the temp dir.
    cfg_path = tmp_path / "config.toml"
    monkeypatch.setattr(cfgmod, "DEFAULT_CONFIG_PATH", cfg_path)
    from msrf.gui import settings_view
    monkeypatch.setattr(settings_view, "DEFAULT_CONFIG_PATH", cfg_path)

    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    view = next(win.tabs.widget(i) for i in range(win.tabs.count())
                if isinstance(win.tabs.widget(i), settings_view.SettingsView))
    view.mobsf_port.setValue(8222)
    view.emu_api.setValue(29)
    view.vt_enabled.setChecked(True)
    view._save()
    assert cfg_path.is_file()
    reloaded = load_config(cfg_path)
    assert reloaded.mobsf.port == 8222
    assert reloaded.emulator.api_level == 29
    assert reloaded.mobsf.vt_enabled is True


def test_window_geometry_is_remembered(qapp, tmp_path):
    from PyQt6.QtGui import QCloseEvent

    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    win._settings.remove("geometry")
    win.resize(1000, 700)
    win.closeEvent(QCloseEvent())
    assert win._settings.value("geometry") is not None


def test_findings_filter_hides_nonmatching_rows(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    fv = win.findings_view
    fv._fill([
        {"severity": "high", "source": "sast", "title": "SQL injection", "id": "1"},
        {"severity": "info", "source": "manual", "title": "verbose logging", "id": "2"},
    ])
    fv.search.edit.setText("sql")
    assert not fv.table.isRowHidden(0)
    assert fv.table.isRowHidden(1)
    fv.search.edit.clear()
    assert not fv.table.isRowHidden(1)


def test_table_copy_helpers_cover_selection(qapp, tmp_path):
    from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem

    from msrf.gui.table_tools import as_json, as_markdown, as_tsv, selected_grid

    t = QTableWidget(2, 2)
    t.setHorizontalHeaderLabels(["Severity", "Issue"])
    for r, (s, i) in enumerate([("high", "a"), ("info", "b")]):
        t.setItem(r, 0, QTableWidgetItem(s))
        t.setItem(r, 1, QTableWidgetItem(i))
    t.selectAll()
    headers, rows = selected_grid(t)
    assert headers == ["Severity", "Issue"] and len(rows) == 2
    assert as_tsv(headers, rows).splitlines()[1] == "high\ta"
    assert '"Severity": "high"' in as_json(headers, rows)
    assert as_markdown(headers, rows).startswith("| Severity | Issue |")


def test_drag_drop_loads_apk_into_static(qapp, tmp_path):
    from PyQt6.QtCore import QMimeData, QPointF, Qt, QUrl
    from PyQt6.QtGui import QDragEnterEvent, QDropEvent

    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"PK\x03\x04")
    md = QMimeData()
    md.setUrls([QUrl.fromLocalFile(str(apk))])
    pos = QPointF(1, 1)
    args = (Qt.DropAction.CopyAction, md, Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier)
    enter = QDragEnterEvent(pos.toPoint(), *args)
    win.dragEnterEvent(enter)
    assert enter.isAccepted()
    win.dropEvent(QDropEvent(pos, *args))
    assert win.sast_view.path.text() == str(apk)
    assert win.tabs.currentWidget() is win.sast_view


def test_dashboard_shows_engines_and_finding_charts(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    dash = win.dashboard_view
    # feed known engine + findings data straight into the fill path
    dash._fill({
        "engines": {"sast": {"ready": True, "details": {"x": 1}},
                    "iot": {"ready": False, "details": {"error": "no nmap"}}},
        "findings": [
            {"severity": "high", "source": "sast"},
            {"severity": "high", "source": "sast"},
            {"severity": "info", "source": "manual"},
        ],
    })
    assert dash.table.rowCount() == 2
    assert dash.table.item(0, 1).text() in ("Ready", "Not ready")
    assert dash.table.cellWidget(0, 2) is not None      # info button present
    assert dash.c_sev_bar._data[0][0] == "High"          # most severe first
    assert dash.c_sev_bar._data[0][1] == 2
    assert "2/2" not in dash.summary.text()              # 1 of 2 ready
    assert "1/2 engines ready" in dash.summary.text()
    assert "3 findings" in dash.summary.text()


def test_activity_log_records_labelled_tasks(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    activity = next(win.tabs.widget(i) for i in range(win.tabs.count())
                    if win.tabs.tabText(i) == "Activity")
    before = activity.table.rowCount()
    win.submit(lambda: {"ok": 1}, label="Test task", params={"x": 1})
    _drain(qapp, win)
    for _ in range(10):
        qapp.processEvents()
    assert activity.table.rowCount() == before + 1
    # newest row is at the top and shows the label + finished status
    assert activity.table.item(0, 0).text() == "Test task"
    assert activity.table.item(0, 2).text() == "finished"
    activity.table.selectRow(0)
    assert '"ok": 1' in activity.out.toPlainText()
    assert '"x": 1' in activity.params.toPlainText()


def test_quiet_tasks_are_not_logged(qapp, tmp_path):
    cfg = load_config(workspace=tmp_path)
    cfg.ensure_dirs()
    win = _make_window(cfg)
    _drain(qapp, win)
    n = len(win.activity.entries)
    win.submit(lambda: 1, quiet=True, label="should be skipped")
    _drain(qapp, win)
    assert len(win.activity.entries) == n
