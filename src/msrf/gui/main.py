"""msrf desktop application (PyQt6): classic Windows-style shell.

A menu bar / tool bar / status bar application with a tabbed workspace over the
msrf engines: a connection dashboard, static analysis (tabular, with an APK
file browser), the inbuilt Frida hook library, dynamic/device control, traffic
proxy, network setup, IoT recon, and help (including MCP setup). Engine calls run
on worker threads so the UI stays responsive.
"""
from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Callable
from typing import Any

from PyQt6.QtCore import Qt, QThreadPool, QTimer
from PyQt6.QtGui import QAction, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import get_version
from ..config import Config, load_config
from ..registry import get_engine
from . import theme
from .activity import ActivityLog, ActivityView
from .appdata_view import AppDataView
from .dashboard_view import DashboardView
from .dast_view import DastView
from .emulator_screen import EmulatorScreen
from .emulator_view import EmulatorView
from .findings_view import FindingsView
from .help_view import HelpView
from .hooks_view import HooksView
from .icon import app_icon
from .sast_view import SASTView
from .settings_view import SettingsView
from .worker import Worker


class OutputPane(QPlainTextEdit):
    """Read-only monospace log pane."""

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 10))

    def log(self, text: str) -> None:
        self.appendPlainText(text)

    def log_json(self, data: Any) -> None:
        self.appendPlainText(json.dumps(data, indent=2, default=str))

    def rule(self, title: str) -> None:
        self.appendPlainText(f"\n--- {title} " + "-" * max(0, 40 - len(title)))


def _button(text: str, primary: bool = False) -> QPushButton:
    b = QPushButton(text)
    if primary:
        b.setObjectName("primary")
    return b


class MainWindow(QMainWindow):
    def __init__(self, config: Config) -> None:
        super().__init__()
        self.config = config
        self.pool = QThreadPool.globalInstance()
        self._engines: dict[str, Any] = {}
        self._busy = 0

        from PyQt6.QtCore import QSettings

        self._settings = QSettings()
        self.activity = ActivityLog(config.workspace)

        self.setWindowTitle(
            f"Mobile Security Research Framework  {get_version()}"
        )
        self.setWindowIcon(app_icon())
        self.setAcceptDrops(True)  # drop an APK/IPA anywhere to analyse it
        self.resize(1180, 760)
        # Restore the last window size/position, if any (per-viewer convenience).
        geo = self._settings.value("geometry")
        if geo is not None:
            with contextlib.suppress(Exception):
                self.restoreGeometry(geo)

        self._build_menu()
        self._build_toolbar()
        self._build_statusbar()

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(False)
        self.setCentralWidget(self.tabs)

        self.sast_view = SASTView(self)
        self.findings_view = FindingsView(self)
        self.dashboard_view = DashboardView(self)
        self.tabs.addTab(self.dashboard_view, "Dashboard")
        self.tabs.addTab(self.sast_view, "Static (SAST)")
        self.tabs.addTab(HooksView(self), "Frida Hooks")
        self.tabs.addTab(DastView(self), "Dynamic (DAST)")
        self.tabs.addTab(EmulatorView(self), "Emulator")
        self.tabs.addTab(AppDataView(self), "App Data")
        self.tabs.addTab(self._tab_proxy(), "Proxy")
        self.tabs.addTab(self._tab_network(), "Network")
        self.tabs.addTab(self._tab_iot(), "IoT")
        self.tabs.addTab(self.findings_view, "Findings")
        self.tabs.addTab(ActivityView(self), "Activity")
        self.tabs.addTab(SettingsView(self), "Settings")
        self.tabs.addTab(HelpView(), "Help")

        # Dockable live emulator screen: side-by-side with the tabs, or floated
        # into its own window, so it stays usable while working in any tab.
        self.screen_dock = QDockWidget("Emulator Screen", self)
        self.screen_dock.setObjectName("emulator_screen_dock")
        self.screen_dock.setWidget(EmulatorScreen(self))
        self.screen_dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
            | QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.screen_dock)
        self.screen_dock.hide()
        toggle = self.screen_dock.toggleViewAction()
        toggle.setText("Emulator screen (side-by-side)")
        self._view_menu.addAction(toggle)
        self._toolbar.addAction(toggle)

        # Background connection-info poll (quiet: no busy indicator, no flicker).
        self._conn_timer = QTimer(self)
        self._conn_timer.timeout.connect(self._refresh_connection)
        self._conn_timer.start(30000)
        self._refresh_connection()

    # -- infra -----------------------------------------------------------

    def engine(self, name: str):
        if name not in self._engines:
            self._engines[name] = get_engine(name, self.config)
        return self._engines[name]

    def submit(
        self,
        fn: Callable[..., Any],
        *args: Any,
        on_result: Callable[[Any], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        quiet: bool = False,
        label: str | None = None,
        params: Any = None,
        **kwargs: Any,
    ) -> None:
        # ``quiet`` tasks (e.g. the periodic connection poll) do not toggle the
        # global busy indicator, so they run in the background without flashing
        # the progress bar or otherwise looking like the app is "refreshing".
        # A ``label`` records the task in the Activity log (Output/Log/Params).
        eid = self.activity.start(label, params) if (label and not quiet) else None
        if not quiet:
            self._set_busy(True)

        def _res(r: Any) -> None:
            if eid is not None:
                self.activity.finish(eid, "finished", output=r)
            if on_result:
                on_result(r)

        def _err(e: str) -> None:
            if eid is not None:
                self.activity.finish(eid, "error", log=str(e))
            if on_error:
                on_error(e)

        worker = Worker(fn, *args, **kwargs)
        worker.signals.result.connect(_res)
        worker.signals.error.connect(_err)
        if not quiet:
            worker.signals.finished.connect(lambda: self._set_busy(False))
        self.pool.start(worker)

    def _set_busy(self, busy: bool) -> None:
        self._busy += 1 if busy else -1
        self.progress.setVisible(self._busy > 0)

    def status(self, message: str, timeout: int = 0) -> None:
        self.statusBar().showMessage(message, timeout)

    def _set_theme(self, mode: str) -> None:
        self._settings.setValue("theme", mode)
        resolved = theme.apply(QApplication.instance(), mode)
        self.status(f"Theme: {mode} ({resolved})", 4000)

    def import_scan_findings(self, scan_hash: str) -> None:
        """Auto-collect a completed scan's findings into the Findings store."""
        self.submit(
            lambda: self.engine("findings").import_scan(scan_hash),
            on_result=lambda d: self.findings_view.refresh(),
            on_error=lambda e: None,
        )

    # -- chrome ----------------------------------------------------------

    def _build_menu(self) -> None:
        mbar = self.menuBar()
        m_file = mbar.addMenu("&File")
        act_open = QAction("&Open App for Analysis…", self)
        act_open.setShortcut("Ctrl+O")
        act_open.triggered.connect(self._menu_open_app)
        m_file.addAction(act_open)
        act_ws = QAction("Open &Workspace Folder", self)
        act_ws.triggered.connect(self._open_workspace)
        m_file.addAction(act_ws)
        act_settings = QAction("&Settings", self)
        act_settings.setShortcut("Ctrl+,")
        act_settings.triggered.connect(self._open_settings)
        m_file.addAction(act_settings)
        m_file.addSeparator()
        act_exit = QAction("E&xit", self)
        act_exit.setShortcut("Ctrl+Q")
        act_exit.triggered.connect(self.close)
        m_file.addAction(act_exit)

        self._view_menu = mbar.addMenu("&View")
        theme_menu = self._view_menu.addMenu("&Theme")
        from PyQt6.QtGui import QActionGroup

        group = QActionGroup(self)
        group.setExclusive(True)
        current = self._settings.value("theme", "light")
        for mode in ("light", "dark", "system"):
            act = QAction(mode.capitalize(), self, checkable=True)
            act.setChecked(mode == current)
            act.triggered.connect(lambda _=False, m=mode: self._set_theme(m))
            group.addAction(act)
            theme_menu.addAction(act)
        self._view_menu.addSeparator()

        m_tools = mbar.addMenu("&Tools")
        act_pre = QAction("&Preflight (check readiness)", self)
        act_pre.triggered.connect(lambda: (self.tabs.setCurrentIndex(0), self._refresh_dashboard()))
        m_tools.addAction(act_pre)
        act_mcp = QAction("&MCP server setup…", self)
        act_mcp.triggered.connect(lambda: self.tabs.setCurrentWidget(self.tabs.widget(self.tabs.count() - 1)))
        m_tools.addAction(act_mcp)

        m_help = mbar.addMenu("&Help")
        act_doc = QAction("&Documentation", self)
        act_doc.setShortcut("F1")
        act_doc.triggered.connect(lambda: self.tabs.setCurrentWidget(self.tabs.widget(self.tabs.count() - 1)))
        m_help.addAction(act_doc)
        act_about = QAction("&About", self)
        act_about.triggered.connect(self._about)
        m_help.addAction(act_about)

    def _build_toolbar(self) -> None:
        tb = self.addToolBar("Main")
        self._toolbar = tb
        tb.setMovable(False)
        a_open = QAction("Open App", self)
        a_open.triggered.connect(self._menu_open_app)
        tb.addAction(a_open)
        a_refresh = QAction("Refresh Status", self)
        a_refresh.triggered.connect(self._refresh_dashboard)
        tb.addAction(a_refresh)
        tb.addSeparator()
        a_help = QAction("Help", self)
        a_help.triggered.connect(lambda: self.tabs.setCurrentWidget(self.tabs.widget(self.tabs.count() - 1)))
        tb.addAction(a_help)

    def _build_statusbar(self) -> None:
        sb = self.statusBar()
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedWidth(120)
        self.progress.setFixedHeight(14)
        self.progress.setTextVisible(False)
        self.progress.hide()
        self.conn_sast = QLabel("SAST: …")
        self.conn_dev = QLabel("Devices: …")
        self.conn_ws = QLabel(f"Workspace: {self.config.workspace}")
        for w in (self.conn_sast, self.conn_dev, self.conn_ws):
            sb.addPermanentWidget(w)
        sb.addPermanentWidget(self.progress)
        self.status("Ready")

    def _about(self) -> None:
        box = QMessageBox(self)
        box.setWindowTitle("About")
        box.setIconPixmap(app_icon().pixmap(64, 64))
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(
            f"<h2>Mobile Security Research Framework</h2>"
            f"<p>version {get_version()}</p>"
            "<p>Unified, self-contained <b>Mobile &amp; IoT SAST / DAST / "
            "penetration-testing</b> toolkit.</p>"
            "<p>Bundles MobSF, Frida, objection, mitmproxy, nmap and binwalk behind "
            "one desktop app, a CLI and an MCP server.</p>"
            "<p>License: GPL-3.0-only<br>"
            'Project: <a href="https://github.com/keyuraghao/Mobile-Security-Research-Framework">'
            "github.com/keyuraghao/Mobile-Security-Research-Framework</a></p>"
            "<p style='color:#a33'>For authorised security testing only.</p>"
        )
        box.exec()

    def _menu_open_app(self) -> None:
        start_dir = str(self._settings.value("last_app_dir", ""))
        path, _ = QFileDialog.getOpenFileName(
            self, "Select application", start_dir,
            "Mobile apps (*.apk *.ipa);;All files (*)"
        )
        if path:
            self.load_app(path)

    def _open_workspace(self) -> None:
        from PyQt6.QtCore import QUrl
        from PyQt6.QtGui import QDesktopServices

        self.config.ensure_dirs()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.config.workspace)))

    def _open_settings(self) -> None:
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == "Settings":
                self.tabs.setCurrentIndex(i)
                return

    def load_app(self, path: str) -> None:
        """Load an app path into the Static tab (used by Open and drag-drop)."""
        from pathlib import Path as _P

        self._settings.setValue("last_app_dir", str(_P(path).parent))
        self.sast_view.path.setText(path)
        self.tabs.setCurrentWidget(self.sast_view)

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt override
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if any(u.toLocalFile().lower().endswith((".apk", ".ipa")) for u in urls):
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt override
        for u in event.mimeData().urls():
            p = u.toLocalFile()
            if p.lower().endswith((".apk", ".ipa")):
                self.load_app(p)
                self.status(f"Loaded {p}", 5000)
                break

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        # Remember the window size/position for next launch.
        with contextlib.suppress(Exception):
            self._settings.setValue("geometry", self.saveGeometry())
        super().closeEvent(event)

    # -- connection info -------------------------------------------------

    def _refresh_connection(self) -> None:
        def work():
            info = {"sast": False, "devices": 0}
            try:
                import mobsf  # noqa: F401

                info["sast"] = True
            except Exception:
                info["sast"] = False
            try:
                from .. import device as dev

                info["devices"] = len([d for d in dev.list_devices() if d.state == "device"])
            except Exception:
                info["devices"] = 0
            return info

        self.submit(work, on_result=self._apply_connection, quiet=True)

    def _apply_connection(self, info: dict) -> None:
        self.conn_sast.setText("SAST: ready" if info.get("sast") else "SAST: unavailable")
        self.conn_dev.setText(f"Devices: {info.get('devices', 0)}")

    # -- Dashboard -------------------------------------------------------

    def _refresh_dashboard(self) -> None:
        self.dashboard_view.refresh()

    # -- generic action tabs ---------------------------------------------

    def _tab_network(self) -> QWidget:
        return self._actions_tab(
            "network",
            [
                ("Host IPs", "host_ips", {}),
                ("Install CA on device", "install_ca", {}),
                ("Setup local interception", "setup_local", {}),
                ("Setup anywhere (WireGuard)", "setup_anywhere", {}),
            ],
        )

    def _tab_proxy(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        row.addWidget(QLabel("Mode:"))
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(["regular", "transparent", "wireguard", "socks5"])
        row.addWidget(self.proxy_mode)
        start = _button("Start capture", primary=True)
        stop = _button("Stop capture")
        stat = _button("Status")
        row.addWidget(start)
        row.addWidget(stop)
        row.addWidget(stat)
        row.addStretch(1)
        lay.addLayout(row)
        out = OutputPane()
        lay.addWidget(out, 1)
        start.clicked.connect(lambda: self.submit(
            lambda: self.engine("proxy").start_capture(mode=self.proxy_mode.currentText()),
            on_result=out.log_json, on_error=lambda e: out.log(f"error: {e}")))
        stop.clicked.connect(lambda: self.submit(
            lambda: self.engine("proxy").stop_capture(),
            on_result=out.log_json, on_error=lambda e: out.log(f"error: {e}")))
        stat.clicked.connect(lambda: self.submit(
            lambda: self.engine("proxy").status(),
            on_result=out.log_json, on_error=lambda e: out.log(f"error: {e}")))
        return w

    def _tab_iot(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        self.iot_target = QLineEdit()
        self.iot_target.setPlaceholderText("target host or CIDR, e.g. 192.168.1.0/24")
        self.iot_ports = QLineEdit()
        self.iot_ports.setPlaceholderText("ports e.g. 1-1024")
        self.iot_ports.setFixedWidth(150)
        row.addWidget(self.iot_target, 1)
        row.addWidget(self.iot_ports)
        scan = _button("Port scan", primary=True)
        disco = _button("Host discovery")
        row.addWidget(scan)
        row.addWidget(disco)
        lay.addLayout(row)
        frow = QHBoxLayout()
        self.iot_fw = QLineEdit()
        self.iot_fw.setPlaceholderText("firmware image path …")
        fbrowse = _button("Browse")
        fscan = _button("Firmware scan")
        frow.addWidget(self.iot_fw, 1)
        frow.addWidget(fbrowse)
        frow.addWidget(fscan)
        lay.addLayout(frow)
        out = OutputPane()
        lay.addWidget(out, 1)

        def browse():
            path, _ = QFileDialog.getOpenFileName(self, "Firmware image")
            if path:
                self.iot_fw.setText(path)

        scan.clicked.connect(lambda: self.submit(
            lambda: self.engine("iot").port_scan(self.iot_target.text().strip(), ports=self.iot_ports.text().strip() or None),
            on_result=out.log_json, on_error=lambda e: out.log(f"error: {e}")))
        disco.clicked.connect(lambda: self.submit(
            lambda: self.engine("iot").host_discovery(self.iot_target.text().strip()),
            on_result=out.log_json, on_error=lambda e: out.log(f"error: {e}")))
        fbrowse.clicked.connect(browse)
        fscan.clicked.connect(lambda: self.submit(
            lambda: self.engine("iot").firmware_scan(self.iot_fw.text().strip()),
            on_result=out.log_json, on_error=lambda e: out.log(f"error: {e}")))
        return w

    def _actions_tab(self, engine_name: str, actions: list) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        out = OutputPane()
        for label, method, kwargs in actions:
            btn = _button(label)
            row.addWidget(btn)

            def make(m=method, kw=kwargs):
                def handler():
                    out.rule(m)
                    self.submit(
                        lambda: getattr(self.engine(engine_name), m)(**kw),
                        on_result=out.log_json,
                        on_error=lambda e: out.log(f"error: {e}"),
                    )
                return handler

            btn.clicked.connect(make())
        row.addStretch(1)
        lay.addLayout(row)
        lay.addWidget(out, 1)
        return w


def run() -> int:
    """Launch the msrf desktop GUI."""
    config = load_config()
    config.ensure_dirs()
    from .. import bundled

    bundled.activate(config)
    app = QApplication(sys.argv)
    app.setApplicationName("msrf")  # technical id (QSettings/platform); stable
    app.setApplicationDisplayName("Mobile Security Research Framework")
    app.setApplicationVersion(get_version())
    app.setOrganizationName("msrf")
    app.setDesktopFileName("msrf")
    app.setWindowIcon(app_icon())
    from PyQt6.QtCore import QSettings

    theme.apply(app, QSettings().value("theme", "light"))
    window = MainWindow(config)
    window.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
