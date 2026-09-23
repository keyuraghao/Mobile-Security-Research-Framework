"""msrf desktop application (PyQt6) — classic Windows-style shell.

A menu bar / tool bar / status bar application with a tabbed workspace over the
msrf engines: a connection dashboard, static analysis (tabular, with an APK
file browser), the inbuilt Frida hook library, dynamic/device control, traffic
proxy, network setup, IoT recon, and help (including MCP setup). Engine calls run
on worker threads so the UI stays responsive.
"""
from __future__ import annotations

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
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import get_version
from ..config import Config, load_config
from ..registry import all_engines, get_engine
from . import theme
from .appdata_view import AppDataView
from .dast_view import DastView
from .emulator_screen import EmulatorScreen
from .emulator_view import EmulatorView
from .findings_view import FindingsView
from .help_view import HelpView
from .icon import app_icon
from .sast_view import SASTView
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

        self.setWindowTitle(
            f"Mobile Security and Research Framework  {get_version()}"
        )
        self.setWindowIcon(app_icon())
        self.resize(1180, 760)

        self._build_menu()
        self._build_toolbar()
        self._build_statusbar()

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(False)
        self.setCentralWidget(self.tabs)

        self.sast_view = SASTView(self)
        self.findings_view = FindingsView(self)
        self.tabs.addTab(self._tab_dashboard(), "Dashboard")
        self.tabs.addTab(self.sast_view, "Static (SAST)")
        self.tabs.addTab(self._tab_hooks(), "Frida Hooks")
        self.tabs.addTab(DastView(self), "Dynamic (DAST)")
        self.tabs.addTab(EmulatorView(self), "Emulator")
        self.tabs.addTab(AppDataView(self), "App Data")
        self.tabs.addTab(self._tab_proxy(), "Proxy")
        self.tabs.addTab(self._tab_network(), "Network")
        self.tabs.addTab(self._tab_iot(), "IoT")
        self.tabs.addTab(self.findings_view, "Findings")
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

        # Periodic connection-info refresh.
        self._conn_timer = QTimer(self)
        self._conn_timer.timeout.connect(self._refresh_connection)
        self._conn_timer.start(6000)
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
        **kwargs: Any,
    ) -> None:
        self._set_busy(True)
        worker = Worker(fn, *args, **kwargs)
        if on_result:
            worker.signals.result.connect(on_result)
        if on_error:
            worker.signals.error.connect(on_error)
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
            f"<h2>Mobile Security and Research Framework</h2>"
            f"<p>version {get_version()}</p>"
            "<p>Unified, self-contained <b>Mobile &amp; IoT SAST / DAST / "
            "penetration-testing</b> toolkit.</p>"
            "<p>Bundles MobSF, Frida, objection, mitmproxy, nmap and binwalk behind "
            "one desktop app, a CLI and an MCP server.</p>"
            "<p>License: GPL-3.0-only<br>"
            'Project: <a href="https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest">'
            "github.com/keyuraghao/Mobile_SAST_DAST_Pentest</a></p>"
            "<p style='color:#a33'>For authorised security testing only.</p>"
        )
        box.exec()

    def _menu_open_app(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select application", "", "Mobile apps (*.apk *.ipa);;All files (*)"
        )
        if path:
            self.sast_view.path.setText(path)
            self.tabs.setCurrentWidget(self.sast_view)

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

        self.submit(work, on_result=self._apply_connection)

    def _apply_connection(self, info: dict) -> None:
        self.conn_sast.setText("SAST: ready" if info.get("sast") else "SAST: unavailable")
        self.conn_dev.setText(f"Devices: {info.get('devices', 0)}")

    # -- Dashboard -------------------------------------------------------

    def _tab_dashboard(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        head = QHBoxLayout()
        head.addWidget(QLabel("<b>Engine readiness &amp; connection</b>"))
        head.addStretch(1)
        refresh = _button("Refresh", primary=True)
        head.addWidget(refresh)
        lay.addLayout(head)

        self.dash_table = QTableWidget(0, 3)
        self.dash_table.setHorizontalHeaderLabels(["Engine", "Status", "Details"])
        self.dash_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.dash_table.verticalHeader().setVisible(False)
        self.dash_table.setAlternatingRowColors(True)
        lay.addWidget(self.dash_table, 1)

        refresh.clicked.connect(self._refresh_dashboard)
        self._refresh_dashboard()
        return w

    def _refresh_dashboard(self) -> None:
        def work():
            report = {}
            for eng in all_engines(self.config):
                try:
                    report[eng.name] = eng.preflight()
                except Exception as exc:
                    report[eng.name] = {"ready": False, "details": {"error": str(exc)}}
            return report

        self.submit(work, on_result=self._fill_dashboard)

    def _fill_dashboard(self, report: dict) -> None:
        self.dash_table.setRowCount(0)
        for name, data in sorted(report.items()):
            r = self.dash_table.rowCount()
            self.dash_table.insertRow(r)
            self.dash_table.setItem(r, 0, QTableWidgetItem(name))
            ready = data.get("ready")
            cell = QTableWidgetItem("Ready" if ready else "Not ready")
            cell.setForeground(
                Qt.GlobalColor.darkGreen if ready else Qt.GlobalColor.darkRed
            )
            self.dash_table.setItem(r, 1, cell)
            self.dash_table.setItem(
                r, 2, QTableWidgetItem(json.dumps(data.get("details", {}), default=str))
            )
        self.dash_table.resizeColumnsToContents()
        self.dash_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

    # -- Frida hooks -----------------------------------------------------

    def _tab_hooks(self) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        left = QVBoxLayout()
        left.addWidget(QLabel("<b>Inbuilt hook library</b>"))
        self.hook_combo = QComboBox()
        left.addWidget(self.hook_combo)
        self.hook_summary = QLabel("")
        self.hook_summary.setWordWrap(True)
        left.addWidget(self.hook_summary)

        box = QGroupBox("Parameters (custom-target hooks only)")
        pf = QVBoxLayout(box)
        self.hook_class = QLineEdit()
        self.hook_class.setPlaceholderText("CLASS  e.g. jakhar.aseem.diva.APICreds")
        self.hook_method = QLineEdit()
        self.hook_method.setPlaceholderText("METHOD  e.g. access")
        self.hook_filter = QLineEdit()
        self.hook_filter.setPlaceholderText("FILTER  e.g. diva")
        pf.addWidget(self.hook_class)
        pf.addWidget(self.hook_method)
        pf.addWidget(self.hook_filter)
        left.addWidget(box)

        dev = QHBoxLayout()
        dev.addWidget(QLabel("Target:"))
        self.hook_device = QComboBox()
        self.hook_device.addItem("Simulator (no device needed)", "sim")
        self.hook_device.addItem("USB device (real)", "usb")
        dev.addWidget(self.hook_device, 1)
        left.addLayout(dev)

        btns = QHBoxLayout()
        gen = _button("View script")
        runb = _button("Run hook", primary=True)
        btns.addWidget(gen)
        btns.addWidget(runb)
        left.addLayout(btns)
        left.addStretch(1)

        lw = QWidget()
        lw.setLayout(left)
        lw.setFixedWidth(370)
        lay.addWidget(lw)
        self.hook_output = OutputPane()
        lay.addWidget(self.hook_output, 1)

        self._hook_meta: dict[str, dict] = {}
        self.hook_combo.currentIndexChanged.connect(self._hook_selected)
        gen.clicked.connect(self._hook_view)
        runb.clicked.connect(self._hook_run)
        self._load_hooks()
        return w

    def _load_hooks(self) -> None:
        def work():
            return self.engine("hooks").list_templates()["templates"]

        def done(tpls):
            self.hook_combo.clear()
            self._hook_meta.clear()
            for t in sorted(tpls, key=lambda x: (x["category"], x["name"])):
                self.hook_combo.addItem(f"[{t['category']}] {t['name']}", t["name"])
                self._hook_meta[t["name"]] = t
            self._hook_selected()

        self.submit(work, on_result=done)

    def _current_hook(self):
        name = self.hook_combo.currentData()
        return name, self._hook_meta.get(name, {})

    def _hook_selected(self) -> None:
        name, meta = self._current_hook()
        if not meta:
            return
        self.hook_summary.setText(meta.get("summary", ""))
        params = meta.get("params", {})
        self.hook_class.setEnabled("CLASS" in params)
        self.hook_method.setEnabled("METHOD" in params)
        self.hook_filter.setEnabled("FILTER" in params)

    def _hook_params(self, meta: dict):
        params = meta.get("params", {})
        out = {}
        if "CLASS" in params and self.hook_class.text().strip():
            out["CLASS"] = self.hook_class.text().strip()
        if "METHOD" in params and self.hook_method.text().strip():
            out["METHOD"] = self.hook_method.text().strip()
        if "FILTER" in params and self.hook_filter.text().strip():
            out["FILTER"] = self.hook_filter.text().strip()
        return out or None

    def _hook_view(self) -> None:
        name, meta = self._current_hook()
        params = self._hook_params(meta)
        self.hook_output.rule(f"script: {name}")
        self.submit(
            lambda: self.engine("hooks").generate(name, params=params),
            on_result=lambda d: self.hook_output.log(d["script"]),
            on_error=lambda e: self.hook_output.log(f"error: {e}"),
        )

    def _hook_run(self) -> None:
        name, meta = self._current_hook()
        params = self._hook_params(meta)
        dev = self.hook_device.currentData()
        device_id = "sim" if dev == "sim" else None
        self.hook_output.rule(f"run: {name} on {dev}")
        self.submit(
            lambda: self.engine("hooks").test(template=name, params=params, device_id=device_id),
            on_result=self._hook_ran,
            on_error=lambda e: self.hook_output.log(f"error: {e}"),
        )

    def _hook_ran(self, res: dict) -> None:
        self.hook_output.log(f"loaded={res.get('loaded')}  messages={res.get('message_count')}")
        for m in res.get("messages", []):
            if isinstance(m, dict):
                self.hook_output.log(f"  [{m.get('tag')}] {m.get('msg')}")
            else:
                self.hook_output.log(f"  {m}")

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
    app.setApplicationDisplayName("Mobile Security and Research Framework")
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
