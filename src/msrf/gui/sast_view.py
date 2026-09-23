"""Static-analysis (SAST) view: tabular results plus an APK file browser.

Presents the full output of every MobSF analyzer as sortable tables (findings,
permissions, certificate, manifest, network, code analysis, binary/NDK,
trackers, URLs/domains, secrets, components) and lets the user browse the app's
internal files and view their contents. All engine calls run on worker threads
so the UI stays smooth.
"""
from __future__ import annotations

from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .table_tools import install_copy_menu


def _sev_brush(severity: str) -> QBrush | None:
    color = theme.SEVERITY_COLORS.get(str(severity).lower())
    return QBrush(QColor(color)) if color else None


class _Table(QTableWidget):
    """A read-only, sortable results table."""

    def __init__(self, headers: list[str]) -> None:
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(
            len(headers) - 1, QHeaderView.ResizeMode.Stretch
        )
        self.setWordWrap(False)
        self._sorted_once = False
        install_copy_menu(self)  # right-click: copy rows as TSV / JSON / Markdown

    def fill(self, rows: list[list[Any]], sev_col: int | None = None) -> None:
        self.setSortingEnabled(False)
        self.setRowCount(0)
        for row in rows:
            r = self.rowCount()
            self.insertRow(r)
            for c, value in enumerate(row):
                is_sev = sev_col is not None and c == sev_col
                item = theme.SeverityItem(str(value)) if is_sev else QTableWidgetItem(str(value))
                if is_sev:
                    brush = _sev_brush(value)
                    if brush:
                        item.setForeground(brush)
                        f = item.font()
                        f.setBold(True)
                        item.setFont(f)
                self.setItem(r, c, item)
        if sev_col is not None and not self._sorted_once:
            # Default view: most severe first. Later header clicks are kept.
            self.horizontalHeader().setSortIndicator(sev_col, Qt.SortOrder.AscendingOrder)
            self._sorted_once = True
        self.setSortingEnabled(True)
        self.resizeColumnsToContents()
        self.horizontalHeader().setSectionResizeMode(
            self.columnCount() - 1, QHeaderView.ResizeMode.Stretch
        )


class SASTView(QWidget):
    """The Static (SAST) tab."""

    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._hash: str | None = None
        self._build()

    # -- construction ----------------------------------------------------

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)

        bar = QHBoxLayout()
        self.path = QLineEdit()
        self.path.setPlaceholderText("Select an APK or IPA to analyse…")
        open_btn = QPushButton("Open…")
        self.scan_btn = QPushButton("Analyze")
        self.scan_btn.setObjectName("primary")
        self.onestep_btn = QPushButton("One-Step Assessment")
        self.onestep_btn.setToolTip(
            "Scan, collect findings and generate a PDF report in one step")
        self.export_btn = QPushButton("Export report")
        self.export_btn.setEnabled(False)
        bar.addWidget(QLabel("Application:"))
        bar.addWidget(self.path, 1)
        bar.addWidget(open_btn)
        bar.addWidget(self.scan_btn)
        bar.addWidget(self.onestep_btn)
        bar.addWidget(self.export_btn)
        lay.addLayout(bar)

        self.summary = QLabel("No analysis yet. Analysis runs in-process; no server or login required.")
        self.summary.setStyleSheet("padding:4px;")
        lay.addWidget(self.summary)

        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)

        self.t_overview = _Table(["Property", "Value"])
        self.t_findings = _Table(["Severity", "Category", "Issue", "Description"])
        self.t_perms = _Table(["Permission", "Status", "Info"])
        self.t_cert = _Table(["Severity", "Finding", "Detail"])
        self.t_manifest = _Table(["Severity", "Issue", "Description"])
        self.t_network = _Table(["Severity", "Finding"])
        self.t_code = _Table(["Severity", "Rule", "Standards", "Files"])
        self.t_binary = _Table(["File", "Check", "Severity", "Description"])
        self.t_trackers = _Table(["Tracker", "Categories"])
        self.t_urls = _Table(["Type", "Value", "Location"])
        self.t_secrets = _Table(["Possible hardcoded secret"])
        self.t_components = _Table(["Type", "Name", "Exported"])
        self.t_api = _Table(["API usage", "Files"])
        self.t_malware = _Table(["Permission", "Type", "Description"])
        self.t_apkid = _Table(["DEX", "Type", "Value"])
        self.t_behaviour = _Table(["Severity", "Behaviour", "Files"])
        self.t_sbom = _Table(["Package / dependency"])
        self.t_niap = _Table(["Requirement", "Detail"])
        self.t_permmap = _Table(["Permission", "Files"])
        self.t_ios = _Table(["Section", "Property", "Value"])
        self.t_strings = _Table(["Source", "String"])
        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setFont(QFont("Consolas", 9))
        self.raw_view.setPlaceholderText("Full raw MobSF report (JSON) appears here after analysis.")

        self.tabs.addTab(self.t_overview, "Overview")
        self.tabs.addTab(self.t_findings, "Findings")
        self.tabs.addTab(self.t_perms, "Permissions")
        self.tabs.addTab(self.t_cert, "Certificate")
        self.tabs.addTab(self.t_manifest, "Manifest")
        self.tabs.addTab(self.t_network, "Network")
        self.tabs.addTab(self.t_code, "Code Analysis")
        self.tabs.addTab(self.t_binary, "Binary / NDK")
        self.tabs.addTab(self.t_api, "API")
        self.tabs.addTab(self.t_malware, "Malware Perms")
        self.tabs.addTab(self.t_apkid, "APKID")
        self.tabs.addTab(self.t_behaviour, "Behaviour")
        self.tabs.addTab(self.t_niap, "NIAP")
        self.tabs.addTab(self.t_permmap, "Perm Mapping")
        self.tabs.addTab(self.t_trackers, "Trackers")
        self.tabs.addTab(self.t_urls, "URLs / Domains / Email")
        self.tabs.addTab(self.t_secrets, "Secrets")
        self.tabs.addTab(self.t_sbom, "SBOM")
        self.tabs.addTab(self.t_strings, "Strings")
        self.tabs.addTab(self.t_components, "Components")
        self.tabs.addTab(self.t_ios, "iOS")
        self.tabs.addTab(self._build_files_tab(), "Files")
        self.tabs.addTab(self.raw_view, "Raw JSON")

        open_btn.clicked.connect(self._open)
        self.scan_btn.clicked.connect(self._scan)
        self.onestep_btn.clicked.connect(self._one_step)
        self.export_btn.clicked.connect(self._export)

    def _build_files_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Internal files"])
        self.file_tree.setColumnCount(1)
        self.viewer = QPlainTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setPlaceholderText("Select a file to view its contents.")
        self.viewer.setFont(QFont("Consolas", 10))
        splitter.addWidget(self.file_tree)
        splitter.addWidget(self.viewer)
        splitter.setSizes([340, 720])
        lay.addWidget(splitter)
        self.file_tree.itemSelectionChanged.connect(self._open_file)
        return w

    # -- actions ---------------------------------------------------------

    def _open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select application", "", "Mobile apps (*.apk *.ipa);;All files (*)"
        )
        if path:
            self.path.setText(path)

    def _scan(self) -> None:
        p = self.path.text().strip()
        if not p:
            return
        self.summary.setText("Analyzing… running all MobSF analyzers in-process.")
        self.scan_btn.setEnabled(False)
        self.host.status(f"Analyzing {p} …")
        self.host.submit(
            lambda: self.host.engine("sast").scan(p),
            on_result=self._scanned,
            on_error=self._scan_failed,
            label=f"SAST scan: {p.rsplit('/', 1)[-1]}", params={"app": p},
        )

    def _one_step(self) -> None:
        p = self.path.text().strip()
        if not p:
            return
        self.summary.setText("One-Step Assessment: scan, collect findings, generate a report…")
        self.scan_btn.setEnabled(False)
        self.onestep_btn.setEnabled(False)
        self.host.status("One-Step Assessment running…")
        self.host.submit(
            lambda: self.host.engine("workflow").static_assessment(p, report_format="pdf"),
            on_result=self._one_step_done,
            on_error=self._scan_failed,
            label=f"One-Step: {p.rsplit('/', 1)[-1]}", params={"app": p},
        )

    def _one_step_done(self, res: dict) -> None:
        self.scan_btn.setEnabled(True)
        self.onestep_btn.setEnabled(True)
        self.summary.setText(
            f"One-Step done: score {res.get('security_score')}/100, "
            f"{res.get('findings_imported')} findings, report: {res.get('report')}"
        )
        self.host.status(f"One-Step report: {res.get('report')}", 12000)
        # Load the full report into the tables and refresh Findings.
        if res.get("scan_hash"):
            self._hash = res["scan_hash"]
            self.host.submit(
                lambda: self.host.engine("sast").report(res["scan_hash"]),
                on_result=self._populate,
            )
        if hasattr(self.host, "findings_view"):
            self.host.findings_view.refresh()

    def _scan_failed(self, err: str) -> None:
        self.scan_btn.setEnabled(True)
        self.onestep_btn.setEnabled(True)
        self.summary.setText(f"Analysis failed: {err}")
        self.host.status("Analysis failed")

    def _scanned(self, summary: dict) -> None:
        self._hash = summary.get("hash")
        self.host.submit(
            lambda: self.host.engine("sast").report(self._hash),
            on_result=self._populate,
            on_error=self._scan_failed,
        )

    def _populate(self, ctx: dict) -> None:
        self.scan_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        appsec = ctx.get("appsec") or {}
        self.summary.setText(
            f"{ctx.get('file_name')}  ·  {ctx.get('package_name')}  ·  "
            f"security score {appsec.get('security_score')}/100  ·  "
            f"HIGH {len(appsec.get('high', []) or [])}  "
            f"WARN {len(appsec.get('warning', []) or [])}  "
            f"INFO {len(appsec.get('info', []) or [])}"
        )
        self._fill_overview(ctx)
        self._fill_findings(appsec)
        self._fill_permissions(ctx)
        self._fill_certificate(ctx)
        self._fill_manifest(ctx)
        self._fill_network(ctx)
        self._fill_code(ctx)
        self._fill_binary(ctx)
        self._fill_api(ctx)
        self._fill_malware(ctx)
        self._fill_apkid(ctx)
        self._fill_behaviour(ctx)
        self._fill_niap(ctx)
        self._fill_permmap(ctx)
        self._fill_trackers(ctx)
        self._fill_urls(ctx)
        self._fill_secrets(ctx)
        self._fill_sbom(ctx)
        self._fill_strings(ctx)
        self._fill_components(ctx)
        self._fill_ios(ctx)
        self._fill_files(ctx.get("files") or [])
        import json as _json

        self.raw_view.setPlainText(_json.dumps(ctx, indent=2, default=str))
        self.host.status(
            f"Analysis complete: score {appsec.get('security_score')}/100", 8000
        )
        # Auto-collect the findings into the central Findings store.
        if self._hash and hasattr(self.host, "import_scan_findings"):
            self.host.import_scan_findings(self._hash)

    def _export(self) -> None:
        if not self._hash:
            return
        self.host.submit(
            lambda: self.host.engine("sast").export(self._hash),
            on_result=lambda d: self.host.status(f"Report exported: {d.get('report')}", 8000),
            on_error=lambda e: self.host.status(f"Export failed: {e}", 8000),
        )

    # -- table population ------------------------------------------------

    def _fill_overview(self, ctx: dict) -> None:
        rows = [
            ["File name", ctx.get("file_name")],
            ["Size", ctx.get("size")],
            ["App name", ctx.get("app_name")],
            ["Package", ctx.get("package_name")],
            ["Main activity", ctx.get("main_activity")],
            ["Min SDK", ctx.get("min_sdk")],
            ["Target SDK", ctx.get("target_sdk")],
            ["Max SDK", ctx.get("max_sdk")],
            ["Version", f"{ctx.get('version_name')} ({ctx.get('version_code')})"],
            ["MD5", ctx.get("md5")],
            ["SHA1", ctx.get("sha1")],
            ["SHA256", ctx.get("sha256")],
            ["Security score", (ctx.get("appsec") or {}).get("security_score")],
        ]
        self.t_overview.fill(rows)

    def _fill_findings(self, appsec: dict) -> None:
        rows = []
        for sev in ("high", "warning", "info"):
            for it in appsec.get(sev, []) or []:
                rows.append([sev, it.get("section", ""), it.get("title", ""), _clean(it.get("description"))])
        self.t_findings.fill(rows, sev_col=0)

    def _fill_permissions(self, ctx: dict) -> None:
        rows = [
            [name, (m or {}).get("status", ""), (m or {}).get("info", "")]
            for name, m in (ctx.get("permissions") or {}).items()
        ]
        self.t_perms.fill(rows, sev_col=1)

    def _fill_certificate(self, ctx: dict) -> None:
        rows = []
        for f in (ctx.get("certificate_analysis") or {}).get("certificate_findings") or []:
            if isinstance(f, list | tuple) and len(f) >= 3:
                rows.append([f[0], f[1], _clean(f[2])])
            elif isinstance(f, list | tuple) and len(f) == 2:
                rows.append([f[0], f[1], ""])
        self.t_cert.fill(rows, sev_col=0)

    def _fill_manifest(self, ctx: dict) -> None:
        rows = [
            [f.get("severity"), f.get("title"), _clean(f.get("description"))]
            for f in (ctx.get("manifest_analysis") or {}).get("manifest_findings") or []
        ]
        self.t_manifest.fill(rows, sev_col=0)

    def _fill_network(self, ctx: dict) -> None:
        rows = [
            [f.get("severity"), _clean(f.get("description"))]
            for f in (ctx.get("network_security") or {}).get("network_findings") or []
        ]
        self.t_network.fill(rows, sev_col=0)

    def _fill_code(self, ctx: dict) -> None:
        rows = []
        for rule, data in (ctx.get("code_analysis") or {}).get("findings", {}).items():
            meta = (data or {}).get("metadata") or {}
            standards = ", ".join(
                str(meta[k]) for k in ("cwe", "owasp-mobile", "masvs") if meta.get(k)
            )
            files = (data or {}).get("files") or {}
            rows.append(
                [meta.get("severity", "info"), rule, standards, f"{len(files)} file(s)"]
            )
        self.t_code.fill(rows, sev_col=0)

    def _fill_binary(self, ctx: dict) -> None:
        rows = []
        binary = ctx.get("binary_analysis") or []
        if isinstance(binary, dict):  # iOS shape -> surfaced in the iOS tab
            binary = []
        for so in binary:
            if not isinstance(so, dict):
                continue
            name = so.get("name")
            for check in ("nx", "pie", "stack_canary", "relocation_readonly", "rpath", "runpath", "fortify", "symbol"):
                c = so.get(check)
                if isinstance(c, dict) and c.get("severity"):
                    rows.append([name, check, c.get("severity"), _clean(c.get("description"))])
        self.t_binary.fill(rows, sev_col=2)

    def _fill_api(self, ctx: dict) -> None:
        rows = []
        for name, data in (ctx.get("android_api") or {}).items():
            meta = (data or {}).get("metadata") or {}
            files = (data or {}).get("files") or {}
            rows.append([meta.get("description", name), f"{len(files)} file(s)"])
        self.t_api.fill(rows)

    def _fill_malware(self, ctx: dict) -> None:
        mp = ctx.get("malware_permissions") or {}
        rows = []
        for p in mp.get("top_malware_permissions") or []:
            rows.append([p, "top-abused", ""])
        for p in mp.get("other_abused_permissions") or []:
            rows.append([p, "abused", ""])
        self.t_malware.fill(rows, sev_col=1)

    def _fill_strings(self, ctx: dict) -> None:
        strings = ctx.get("strings") or {}
        rows = []
        for source in ("strings_apk_res", "strings_so", "strings_code"):
            for s in (strings.get(source) or [])[:1500]:
                val = s if isinstance(s, str) else next(iter(s.values()), "") if isinstance(s, dict) else str(s)
                rows.append([source.replace("strings_", ""), _clean(val)[:200]])
        self.t_strings.fill(rows)

    def _fill_trackers(self, ctx: dict) -> None:
        rows = [
            [t.get("name"), t.get("categories")]
            for t in (ctx.get("trackers") or {}).get("trackers") or []
        ]
        self.t_trackers.fill(rows)

    def _fill_urls(self, ctx: dict) -> None:
        rows = []
        for d, meta in (ctx.get("domains") or {}).items():
            bad = "malware" if (meta or {}).get("bad") == "yes" else "domain"
            rows.append([bad, d, (meta or {}).get("geolocation", {}).get("country_short", "")])
        for u in ctx.get("urls") or []:
            for link in u.get("urls", []):
                rows.append(["url", link, u.get("path", "")])
        for em in ctx.get("emails") or []:
            if isinstance(em, dict):
                for addr in em.get("emails", []):
                    rows.append(["email", addr, em.get("path", "")])
            else:
                rows.append(["email", str(em), ""])
        for fb in ctx.get("firebase_urls") or []:
            val = fb.get("url") if isinstance(fb, dict) else fb
            rows.append(["firebase", str(val), "open" if (isinstance(fb, dict) and fb.get("open")) else ""])
        self.t_urls.fill(rows, sev_col=0)

    def _fill_apkid(self, ctx: dict) -> None:
        rows = []
        for dexname, data in (ctx.get("apkid") or {}).items():
            for key, vals in (data or {}).items():
                vals = vals if isinstance(vals, list) else [vals]
                for v in vals:
                    rows.append([dexname, key, str(v)])
        self.t_apkid.fill(rows)

    def _fill_behaviour(self, ctx: dict) -> None:
        rows = []
        for _bid, data in (ctx.get("behaviour") or {}).items():
            meta = (data or {}).get("metadata") or {}
            files = (data or {}).get("files") or {}
            rows.append([meta.get("severity", "info"), meta.get("description", _bid), f"{len(files)} file(s)"])
        self.t_behaviour.fill(rows, sev_col=0)

    def _fill_niap(self, ctx: dict) -> None:
        rows = []
        for req, data in (ctx.get("niap_analysis") or {}).items():
            detail = data.get("description") if isinstance(data, dict) else data
            rows.append([req, _clean(detail)])
        self.t_niap.fill(rows)

    def _fill_permmap(self, ctx: dict) -> None:
        rows = []
        for perm, data in (ctx.get("permission_mapping") or {}).items():
            files = data if isinstance(data, list | dict) else [data]
            n = len(files) if hasattr(files, "__len__") else 0
            rows.append([perm, f"{n} location(s)"])
        self.t_permmap.fill(rows)

    def _fill_sbom(self, ctx: dict) -> None:
        pkgs = (ctx.get("sbom") or {}).get("sbom_packages") or []
        rows = []
        for p in pkgs:
            rows.append([p.get("name", str(p)) if isinstance(p, dict) else str(p)])
        self.t_sbom.fill(rows)

    def _fill_ios(self, ctx: dict) -> None:
        """Surface iOS-specific analyzer output (defensive across shapes)."""
        rows: list[list[Any]] = []

        def add(section, obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    rows.append([section, k, _clean(v)[:160]])
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    rows.append([section, str(i), _clean(v)[:160]])
            elif obj:
                rows.append([section, "", _clean(obj)[:160]])

        add("Info.plist", ctx.get("info_plist"))
        add("ATS", ctx.get("ats_analysis"))
        add("Binary info", ctx.get("binary_info"))
        add("Mach-O", ctx.get("macho_analysis"))
        add("Dylib", ctx.get("dylib_analysis"))
        add("Frameworks", ctx.get("framework_analysis"))
        add("App Store", ctx.get("appstore_details"))
        self.t_ios.fill(rows)

    def _fill_secrets(self, ctx: dict) -> None:
        self.t_secrets.fill([[s] for s in ctx.get("secrets") or []])

    def _fill_components(self, ctx: dict) -> None:
        exported = set(ctx.get("exported_activities") or [])
        rows = []
        for label in ("activities", "services", "receivers", "providers"):
            for name in ctx.get(label) or []:
                rows.append([label[:-1], name, "yes" if name in exported else ""])
        self.t_components.fill(rows)

    # -- file browser ----------------------------------------------------

    def _fill_files(self, files: list[str]) -> None:
        self.file_tree.clear()
        self.viewer.clear()
        root_nodes: dict[str, QTreeWidgetItem] = {}
        for path in sorted(files):
            parts = path.split("/")
            parent = None
            key = ""
            for i, part in enumerate(parts):
                key = f"{key}/{part}"
                nodes = root_nodes
                if key not in nodes:
                    item = QTreeWidgetItem([part])
                    if i == len(parts) - 1:
                        item.setData(0, Qt.ItemDataRole.UserRole, path)
                    if parent is None:
                        self.file_tree.addTopLevelItem(item)
                    else:
                        parent.addChild(item)
                    nodes[key] = item
                parent = nodes[key]

    def _open_file(self) -> None:
        items = self.file_tree.selectedItems()
        if not items or not self._hash:
            return
        rel = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not rel:
            return  # a directory node
        self.viewer.setPlainText(f"Loading {rel} …")
        self.host.submit(
            lambda: self.host.engine("sast").file_content(self._hash, rel),
            on_result=self._show_file,
            on_error=lambda e: self.viewer.setPlainText(f"Cannot open: {e}"),
        )

    def _show_file(self, res: dict) -> None:
        header = f"# {res.get('path')}  ({res.get('size')} bytes)"
        if res.get("decoded") == "android-binary-xml":
            header += "  [decoded from Android binary XML]"
        elif res.get("binary"):
            header += "  [binary, hex view]"
        if res.get("truncated"):
            header += "  [truncated]"
        self.viewer.setPlainText(header + "\n\n" + res.get("content", ""))


def _clean(text: Any) -> str:
    return " ".join(str(text or "").split())
