"""mobiot desktop application (PyQt6).

A tabbed control centre over the mobiot engine layer: preflight dashboard,
static analysis (MobSF), the inbuilt Frida hook library, dynamic/device control,
traffic proxy, network setup and IoT recon. Every engine call runs on a worker
thread so the UI stays responsive.
"""
from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

from PyQt6.QtCore import Qt, QThreadPool
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import get_version
from ..config import Config, load_config
from ..registry import all_engines, get_engine
from . import theme
from .worker import Worker

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _label(text: str, obj: str | None = None) -> QLabel:
    lab = QLabel(text)
    if obj:
        lab.setObjectName(obj)
    return lab


def _button(text: str, primary: bool = False) -> QPushButton:
    btn = QPushButton(text)
    if primary:
        btn.setObjectName("primary")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


class OutputPane(QPlainTextEdit):
    """A read-only monospace log pane with helpers for JSON output."""

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("monospace", 10))

    def log(self, text: str) -> None:
        self.appendPlainText(text)

    def log_json(self, data: Any) -> None:
        self.appendPlainText(json.dumps(data, indent=2, default=str))

    def rule(self, title: str) -> None:
        self.appendPlainText(f"\n=== {title} " + "=" * max(0, 40 - len(title)))


# ---------------------------------------------------------------------------
# main window
# ---------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self, config: Config) -> None:
        super().__init__()
        self.config = config
        self.pool = QThreadPool.globalInstance()
        self._engines: dict[str, Any] = {}
        self._busy = 0

        self.setWindowTitle(f"mobiot — Mobile & IoT Security Toolkit  v{get_version()}")
        self.resize(1080, 720)

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(12)

        layout.addLayout(self._build_header())

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # indeterminate
        self.progress.setFixedHeight(4)
        self.progress.setTextVisible(False)
        self.progress.hide()
        layout.addWidget(self.progress)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.tabs.addTab(self._tab_dashboard(), "Dashboard")
        self.tabs.addTab(self._tab_sast(), "Static (SAST)")
        self.tabs.addTab(self._tab_hooks(), "Frida Hooks")
        self.tabs.addTab(self._tab_dynamic(), "Dynamic")
        self.tabs.addTab(self._tab_proxy(), "Proxy")
        self.tabs.addTab(self._tab_network(), "Network")
        self.tabs.addTab(self._tab_iot(), "IoT")

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
        """Run ``fn`` on a worker thread with a busy indicator."""
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

    def _build_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.addWidget(_label("◈ mobiot", "brand"))
        sub = _label("Mobile & IoT · SAST / DAST / Pentest", "muted")
        row.addWidget(sub)
        row.addStretch(1)
        row.addWidget(_label(f"workspace: {self.config.workspace}", "muted"))
        return row

    # -- Dashboard -------------------------------------------------------

    def _tab_dashboard(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        top = QHBoxLayout()
        top.addWidget(_label("Engine readiness", "h2"))
        top.addStretch(1)
        refresh = _button("Refresh", primary=True)
        top.addWidget(refresh)
        lay.addLayout(top)

        self.dash_table = QTableWidget(0, 3)
        self.dash_table.setHorizontalHeaderLabels(["Engine", "Ready", "Details"])
        self.dash_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.dash_table.verticalHeader().setVisible(False)
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
            row = self.dash_table.rowCount()
            self.dash_table.insertRow(row)
            self.dash_table.setItem(row, 0, QTableWidgetItem(name))
            ready = data.get("ready")
            pill = QTableWidgetItem("● ready" if ready else "● not ready")
            pill.setForeground(
                Qt.GlobalColor.green if ready else Qt.GlobalColor.red
            )
            self.dash_table.setItem(row, 1, pill)
            details = data.get("details", {})
            self.dash_table.setItem(
                row, 2, QTableWidgetItem(json.dumps(details, default=str))
            )

    # -- SAST ------------------------------------------------------------

    def _tab_sast(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        srv = QHBoxLayout()
        self.sast_status = _label("MobSF: unknown", "muted")
        start_btn = _button("Start MobSF server")
        srv.addWidget(start_btn)
        srv.addWidget(self.sast_status)
        srv.addStretch(1)
        lay.addLayout(srv)

        pick = QHBoxLayout()
        self.sast_path = QLineEdit()
        self.sast_path.setPlaceholderText("Path to APK / IPA / APPX …")
        browse = _button("Browse")
        scan = _button("Scan", primary=True)
        pick.addWidget(self.sast_path, 1)
        pick.addWidget(browse)
        pick.addWidget(scan)
        lay.addLayout(pick)

        self.sast_score = _label("No scan yet.", "h2")
        lay.addWidget(self.sast_score)

        self.sast_tree = QTreeWidget()
        self.sast_tree.setHeaderLabels(["Severity", "Finding"])
        self.sast_tree.header().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        lay.addWidget(self.sast_tree, 1)

        acts = QHBoxLayout()
        self.sast_pdf_btn = _button("Save PDF report")
        acts.addStretch(1)
        acts.addWidget(self.sast_pdf_btn)
        lay.addLayout(acts)

        self._sast_hash: str | None = None
        start_btn.clicked.connect(self._sast_start_server)
        browse.clicked.connect(self._sast_browse)
        scan.clicked.connect(self._sast_scan)
        self.sast_pdf_btn.clicked.connect(self._sast_pdf)
        self._refresh_sast_status()
        return w

    def _refresh_sast_status(self) -> None:
        def work():
            return self.engine("sast").server_status()

        self.submit(
            work,
            on_result=lambda d: self.sast_status.setText(
                f"MobSF: {'running' if d.get('running') else 'stopped'} · {d.get('url')}"
            ),
            on_error=lambda e: self.sast_status.setText("MobSF: error"),
        )

    def _sast_start_server(self) -> None:
        self.sast_status.setText("MobSF: starting…")
        self.submit(
            lambda: self.engine("sast").start_server(),
            on_result=lambda d: self._refresh_sast_status(),
            on_error=lambda e: self.sast_status.setText(f"MobSF: {e[:60]}"),
        )

    def _sast_browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select app", "", "Apps (*.apk *.ipa *.appx *.zip);;All files (*)"
        )
        if path:
            self.sast_path.setText(path)

    def _sast_scan(self) -> None:
        path = self.sast_path.text().strip()
        if not path:
            return
        self.sast_score.setText("Scanning…")
        self.sast_tree.clear()
        self.submit(
            lambda: self.engine("sast").scan(path),
            on_result=self._sast_scanned,
            on_error=lambda e: self.sast_score.setText(f"Scan failed: {e[:80]}"),
        )

    def _sast_scanned(self, data: dict) -> None:
        self._sast_hash = data.get("hash")
        self.sast_score.setText(f"Scanned {data.get('file_name')} — loading scorecard…")
        self.submit(
            lambda: self.engine("sast").scorecard(self._sast_hash),
            on_result=self._sast_scorecard,
            on_error=lambda e: self.sast_score.setText(f"Scorecard failed: {e[:80]}"),
        )

    def _sast_scorecard(self, sc: dict) -> None:
        score = sc.get("security_score", "?")
        high = sc.get("high", []) or []
        warn = sc.get("warning", []) or []
        info = sc.get("info", []) or []
        self.sast_score.setText(
            f"Security score: {score}/100   ·   "
            f"HIGH {len(high)}   WARN {len(warn)}   INFO {len(info)}"
        )
        self.sast_tree.clear()
        for sev, items, color in (
            ("HIGH", high, Qt.GlobalColor.red),
            ("WARNING", warn, Qt.GlobalColor.yellow),
            ("INFO", info, Qt.GlobalColor.cyan),
        ):
            parent = QTreeWidgetItem([sev, f"{len(items)} finding(s)"])
            parent.setForeground(0, color)
            for it in items:
                title = it.get("title") or it.get("name") or str(it)
                title = " ".join(str(title).split())[:160]
                parent.addChild(QTreeWidgetItem(["", title]))
            self.sast_tree.addTopLevelItem(parent)
            parent.setExpanded(True)

    def _sast_pdf(self) -> None:
        if not self._sast_hash:
            return
        self.submit(
            lambda: self.engine("sast").pdf(self._sast_hash),
            on_result=lambda d: self.sast_score.setText(f"PDF saved: {d.get('pdf')}"),
            on_error=lambda e: self.sast_score.setText(f"PDF failed: {e[:90]}"),
        )

    # -- Frida hooks (flagship) ------------------------------------------

    def _tab_hooks(self) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)

        left = QVBoxLayout()
        left.addWidget(_label("Inbuilt hook library", "h2"))
        self.hook_combo = QComboBox()
        left.addWidget(self.hook_combo)
        self.hook_summary = _label("", "muted")
        self.hook_summary.setWordWrap(True)
        left.addWidget(self.hook_summary)

        params_box = QGroupBox("Parameters (only for custom-target hooks)")
        pform = QVBoxLayout(params_box)
        self.hook_class = QLineEdit()
        self.hook_class.setPlaceholderText("CLASS  e.g. jakhar.aseem.diva.APICreds")
        self.hook_method = QLineEdit()
        self.hook_method.setPlaceholderText("METHOD  e.g. access")
        self.hook_filter = QLineEdit()
        self.hook_filter.setPlaceholderText("FILTER  e.g. diva")
        pform.addWidget(self.hook_class)
        pform.addWidget(self.hook_method)
        pform.addWidget(self.hook_filter)
        left.addWidget(params_box)

        dev = QHBoxLayout()
        dev.addWidget(_label("Target:", "muted"))
        self.hook_device = QComboBox()
        self.hook_device.addItem("sim — built-in simulator (no device needed)", "sim")
        self.hook_device.addItem("USB device (real, via frida)", "usb")
        dev.addWidget(self.hook_device, 1)
        left.addLayout(dev)

        btns = QHBoxLayout()
        gen_btn = _button("View script")
        run_btn = _button("Run hook", primary=True)
        btns.addWidget(gen_btn)
        btns.addWidget(run_btn)
        left.addLayout(btns)
        left.addStretch(1)

        left_w = QWidget()
        left_w.setLayout(left)
        left_w.setFixedWidth(380)
        lay.addWidget(left_w)

        self.hook_output = OutputPane()
        lay.addWidget(self.hook_output, 1)

        self._hook_meta: dict[str, dict] = {}
        self.hook_combo.currentIndexChanged.connect(self._hook_selected)
        gen_btn.clicked.connect(self._hook_view)
        run_btn.clicked.connect(self._hook_run)
        self._load_hooks()
        return w

    def _load_hooks(self) -> None:
        def work():
            return self.engine("hooks").list_templates()["templates"]

        def done(tpls):
            self.hook_combo.clear()
            self._hook_meta.clear()
            for t in sorted(tpls, key=lambda x: (x["category"], x["name"])):
                label = f"[{t['category']}] {t['name']}"
                self.hook_combo.addItem(label, t["name"])
                self._hook_meta[t["name"]] = t
            self._hook_selected()

        self.submit(work, on_result=done)

    def _current_hook(self) -> tuple[str, dict]:
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

    def _hook_params(self, meta: dict) -> dict | None:
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
            lambda: self.engine("hooks").test(
                template=name, params=params, device_id=device_id
            ),
            on_result=self._hook_ran,
            on_error=lambda e: self.hook_output.log(f"error: {e}"),
        )

    def _hook_ran(self, res: dict) -> None:
        self.hook_output.log(
            f"loaded={res.get('loaded')}  messages={res.get('message_count')}"
        )
        for m in res.get("messages", []):
            if isinstance(m, dict):
                self.hook_output.log(f"  [{m.get('tag')}] {m.get('msg')}")
            else:
                self.hook_output.log(f"  {m}")
        val = res.get("validation")
        if val and not val.get("ok"):
            self.hook_output.log(f"  validation issues: {val.get('issues')}")

    # -- Dynamic ---------------------------------------------------------

    def _tab_dynamic(self) -> QWidget:
        return self._simple_actions_tab(
            "dast",
            [
                ("List devices", "devices", {}),
                ("List applications", "applications", {}),
                ("List processes", "processes", {}),
                ("Provision frida-server", "provision_frida_server", {}),
            ],
        )

    # -- Proxy -----------------------------------------------------------

    def _tab_proxy(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        row.addWidget(_label("Mode:", "muted"))
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(["regular", "transparent", "wireguard", "socks5"])
        row.addWidget(self.proxy_mode)
        start = _button("Start capture", primary=True)
        stop = _button("Stop capture")
        status = _button("Status")
        row.addWidget(start)
        row.addWidget(stop)
        row.addWidget(status)
        row.addStretch(1)
        lay.addLayout(row)
        out = OutputPane()
        lay.addWidget(out, 1)

        start.clicked.connect(
            lambda: self.submit(
                lambda: self.engine("proxy").start_capture(
                    mode=self.proxy_mode.currentText()
                ),
                on_result=out.log_json,
                on_error=lambda e: out.log(f"error: {e}"),
            )
        )
        stop.clicked.connect(
            lambda: self.submit(
                lambda: self.engine("proxy").stop_capture(),
                on_result=out.log_json,
                on_error=lambda e: out.log(f"error: {e}"),
            )
        )
        status.clicked.connect(
            lambda: self.submit(
                lambda: self.engine("proxy").status(),
                on_result=out.log_json,
                on_error=lambda e: out.log(f"error: {e}"),
            )
        )
        return w

    # -- Network ---------------------------------------------------------

    def _tab_network(self) -> QWidget:
        return self._simple_actions_tab(
            "network",
            [
                ("Host IPs", "host_ips", {}),
                ("Install CA on device", "install_ca", {}),
                ("Setup local interception", "setup_local", {}),
                ("Setup anywhere (WireGuard)", "setup_anywhere", {}),
            ],
        )

    # -- IoT -------------------------------------------------------------

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

        scan.clicked.connect(
            lambda: self.submit(
                lambda: self.engine("iot").port_scan(
                    self.iot_target.text().strip(),
                    ports=self.iot_ports.text().strip() or None,
                ),
                on_result=out.log_json,
                on_error=lambda e: out.log(f"error: {e}"),
            )
        )
        disco.clicked.connect(
            lambda: self.submit(
                lambda: self.engine("iot").host_discovery(self.iot_target.text().strip()),
                on_result=out.log_json,
                on_error=lambda e: out.log(f"error: {e}"),
            )
        )
        fbrowse.clicked.connect(browse)
        fscan.clicked.connect(
            lambda: self.submit(
                lambda: self.engine("iot").firmware_scan(self.iot_fw.text().strip()),
                on_result=out.log_json,
                on_error=lambda e: out.log(f"error: {e}"),
            )
        )
        return w

    # -- generic action tab ----------------------------------------------

    def _simple_actions_tab(self, engine_name: str, actions: list) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        out = OutputPane()

        for label, method, kwargs in actions:
            btn = _button(label)
            row.addWidget(btn)

            def make_handler(m=method, kw=kwargs):
                def handler():
                    out.rule(m)
                    self.submit(
                        lambda: getattr(self.engine(engine_name), m)(**kw),
                        on_result=out.log_json,
                        on_error=lambda e: out.log(f"error: {e}"),
                    )

                return handler

            btn.clicked.connect(make_handler())
        row.addStretch(1)
        lay.addLayout(row)
        lay.addWidget(out, 1)
        return w


def run() -> int:
    """Launch the mobiot desktop GUI."""
    config = load_config()
    config.ensure_dirs()
    # In a standalone build, point every engine at the bundled tools so nothing
    # is downloaded or required externally.
    from .. import bundled

    bundled.activate(config)
    app = QApplication(sys.argv)
    app.setStyleSheet(theme.STYLESHEET)
    window = MainWindow(config)
    window.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
