"""Findings view: aggregated results, manual entry, and report generation.

Shows every finding (from static analysis and any the user adds) in one table,
lets the user add their own via a "+" dialog or delete existing ones, and
generates a report in PDF / HTML / XLSX / CSV / JSON / Markdown.
"""
from __future__ import annotations

from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .sast_view import _sev_brush, _Table

_SEVERITIES = ["high", "warning", "info", "secure", "hotspot", "note"]


class _AddDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add finding")
        self.setMinimumWidth(460)
        form = QFormLayout(self)
        self.title = QLineEdit()
        self.severity = QComboBox()
        self.severity.addItems(_SEVERITIES)
        self.target = QLineEdit()
        self.description = QPlainTextEdit()
        self.description.setFixedHeight(120)
        form.addRow("Title:", self.title)
        form.addRow("Severity:", self.severity)
        form.addRow("Target:", self.target)
        form.addRow("Description:", self.description)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def value(self) -> dict[str, Any]:
        return {
            "title": self.title.text().strip(),
            "severity": self.severity.currentText(),
            "target": self.target.text().strip(),
            "description": self.description.toPlainText().strip(),
        }


class FindingsView(QWidget):
    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        bar = QHBoxLayout()
        add = QPushButton("+  Add finding")
        add.setObjectName("primary")
        delete = QPushButton("Delete selected")
        refresh = QPushButton("Refresh")
        importb = QPushButton("Import from last scan")
        bar.addWidget(add)
        bar.addWidget(delete)
        bar.addWidget(importb)
        bar.addWidget(refresh)
        bar.addStretch(1)
        bar.addWidget(QLabel("Report:"))
        self.fmt = QComboBox()
        self.fmt.addItems(["pdf", "html", "xlsx", "csv", "json", "md"])
        bar.addWidget(self.fmt)
        gen = QPushButton("Generate report")
        gen.setObjectName("primary")
        bar.addWidget(gen)
        lay.addLayout(bar)

        self.table = _Table(["Severity", "Source", "Title", "Target", "Created"])
        lay.addWidget(self.table, 1)

        add.clicked.connect(self._add)
        delete.clicked.connect(self._delete)
        refresh.clicked.connect(self.refresh)
        importb.clicked.connect(self._import)
        gen.clicked.connect(self._generate)
        self.refresh()

    def refresh(self) -> None:
        self.host.submit(
            lambda: self.host.engine("findings").list()["findings"],
            on_result=self._fill,
            on_error=lambda e: self.host.status(f"Findings error: {e}", 8000),
        )

    def _fill(self, findings: list[dict]) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for f in findings:
            r = self.table.rowCount()
            self.table.insertRow(r)
            cells = [f.get("severity", ""), f.get("source", ""), f.get("title", ""),
                     f.get("target", ""), f.get("created", "")]
            for c, val in enumerate(cells):
                item = QTableWidgetItem(str(val))
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, f.get("id"))
                    brush = _sev_brush(val)
                    if brush:
                        item.setForeground(brush)
                self.table.setItem(r, c, item)
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()

    def _add(self) -> None:
        dlg = _AddDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        v = dlg.value()
        if not v["title"]:
            return
        self.host.submit(
            lambda: self.host.engine("findings").add(
                v["title"], severity=v["severity"], description=v["description"],
                source="manual", target=v["target"],
            ),
            on_result=lambda d: self.refresh(),
            on_error=lambda e: self.host.status(f"Add failed: {e}", 8000),
        )

    def _delete(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        fid = self.table.item(items[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        if not fid:
            return
        self.host.submit(
            lambda: self.host.engine("findings").delete(fid),
            on_result=lambda d: self.refresh(),
            on_error=lambda e: self.host.status(f"Delete failed: {e}", 8000),
        )

    def _import(self) -> None:
        h = getattr(self.host.sast_view, "_hash", None)
        if not h:
            self.host.status("Run a static analysis first to import its findings.", 6000)
            return
        self.host.submit(
            lambda: self.host.engine("findings").import_scan(h),
            on_result=lambda d: (self.host.status(f"Imported {d.get('imported')} findings", 6000), self.refresh()),
            on_error=lambda e: self.host.status(f"Import failed: {e}", 8000),
        )

    def _generate(self) -> None:
        fmt = self.fmt.currentText()
        self.host.status(f"Generating {fmt.upper()} report …")
        self.host.submit(
            lambda: self.host.engine("findings").report(format=fmt),
            on_result=lambda d: self.host.status(f"Report saved: {d.get('report')}", 12000),
            on_error=lambda e: self.host.status(f"Report failed: {e}", 8000),
        )
