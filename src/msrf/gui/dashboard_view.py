"""Dashboard: engine readiness at a glance plus findings charts.

The engine table shows only the name and status; an info button per row opens
the full preflight details in a dialog (they are noisy in a column). Below,
charts summarise the findings collected so far: counts by severity (bar and
donut) and by source, plus an engine-readiness donut.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .charts import BarChart, DonutChart

# Severity buckets shown in the charts, in order, with a colour each.
_SEV_ORDER = ["critical", "high", "warning", "medium", "low", "info", "note"]
_SOURCE_COLORS = ["#4aa3ff", "#3fb950", "#d19a00", "#a371f7", "#e05561", "#26c6da"]


def _sev_color(name: str) -> str:
    return theme.SEVERITY_COLORS.get(name, "#8899a6")


class DashboardView(QWidget):
    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._build()
        self.refresh()

    # -- layout ----------------------------------------------------------

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        head = QHBoxLayout()
        head.addWidget(QLabel("<b>Dashboard</b>"))
        self.summary = QLabel("")
        head.addSpacing(12)
        head.addWidget(self.summary)
        head.addStretch(1)
        refresh = QPushButton("Refresh")
        refresh.setObjectName("primary")
        refresh.clicked.connect(self.refresh)
        head.addWidget(refresh)
        lay.addLayout(head)

        body = QHBoxLayout()
        lay.addLayout(body, 1)

        # Left: engine readiness table (Engine | Status | info button).
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Engine", "Status", ""])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setMaximumWidth(360)
        body.addWidget(self.table)

        # Right: a 2x2 grid of charts.
        charts = QGridLayout()
        self.c_sev_bar = BarChart("Findings by severity")
        self.c_sev_donut = DonutChart("Severity share")
        self.c_source = BarChart("Findings by source")
        self.c_engines = DonutChart("Engine readiness")
        charts.addWidget(self.c_sev_bar, 0, 0)
        charts.addWidget(self.c_sev_donut, 0, 1)
        charts.addWidget(self.c_source, 1, 0)
        charts.addWidget(self.c_engines, 1, 1)
        wrap = QWidget()
        wrap.setLayout(charts)
        body.addWidget(wrap, 1)

    # -- data ------------------------------------------------------------

    def refresh(self) -> None:
        def work() -> dict[str, Any]:
            from ..registry import all_engines

            report: dict[str, Any] = {}
            for eng in all_engines(self.host.config):
                try:
                    report[eng.name] = eng.preflight()
                except Exception as exc:
                    report[eng.name] = {"ready": False, "details": {"error": str(exc)}}
            try:
                findings = self.host.engine("findings").list()["findings"]
            except Exception:
                findings = []
            return {"engines": report, "findings": findings}

        self.host.submit(work, on_result=self._fill,
                         on_error=lambda e: self.host.status(f"Dashboard error: {e}", 8000))

    def _fill(self, data: dict) -> None:
        report = data.get("engines", {})
        findings = data.get("findings", [])
        self._fill_table(report)
        self._fill_charts(report, findings)

    def _fill_table(self, report: dict) -> None:
        self.table.setRowCount(0)
        ready = 0
        for name, info in sorted(report.items()):
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(name))
            is_ready = bool(info.get("ready"))
            ready += int(is_ready)
            cell = QTableWidgetItem("Ready" if is_ready else "Not ready")
            cell.setForeground(Qt.GlobalColor.darkGreen if is_ready else Qt.GlobalColor.darkRed)
            self.table.setItem(r, 1, cell)
            btn = QPushButton("i")
            btn.setFixedWidth(26)
            btn.setToolTip(f"Show {name} details")
            btn.clicked.connect(lambda _=False, n=name, d=info: self._show_details(n, d))
            self.table.setCellWidget(r, 2, btn)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._ready = (ready, len(report))

    def _fill_charts(self, report: dict, findings: list[dict]) -> None:
        sev = Counter(str(f.get("severity", "info")).lower() for f in findings)
        # Ordered known severities first, then any extras that appeared.
        ordered = [s for s in _SEV_ORDER if sev.get(s)]
        ordered += [s for s in sev if s not in _SEV_ORDER]
        sev_data = [(s.capitalize(), sev[s], _sev_color(s)) for s in ordered]
        self.c_sev_bar.set_data(sev_data)
        self.c_sev_donut.set_data(sev_data)

        src = Counter(str(f.get("source", "other")).lower() for f in findings)
        src_data = [(s.upper(), n, _SOURCE_COLORS[i % len(_SOURCE_COLORS)])
                    for i, (s, n) in enumerate(sorted(src.items()))]
        self.c_source.set_data(src_data)

        ready, total = getattr(self, "_ready", (0, 0))
        self.c_engines.set_data([
            ("Ready", ready, "#3fb950"),
            ("Not ready", max(0, total - ready), "#e05561"),
        ])
        self.summary.setText(
            f"<span style='color:#888'>{ready}/{total} engines ready"
            f"  ·  {len(findings)} findings</span>"
        )

    def _show_details(self, name: str, info: dict) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle(f"{name} details")
        dlg.setMinimumSize(520, 360)
        v = QVBoxLayout(dlg)
        ready = "Ready" if info.get("ready") else "Not ready"
        v.addWidget(QLabel(f"<b>{name}</b>: {ready}"))
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText(json.dumps(info.get("details", info), indent=2, default=str))
        v.addWidget(text, 1)
        close = QPushButton("Close")
        close.clicked.connect(dlg.accept)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(close)
        v.addLayout(row)
        dlg.exec()
