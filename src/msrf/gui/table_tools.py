"""Reusable table quality-of-life helpers: copy-to-clipboard and live filter.

Any ``QTableWidget`` in the app can get a right-click "copy as TSV / JSON /
Markdown" menu and a search box that hides non-matching rows. Kept dependency
free so it works on every results table (SAST tables, Findings, dashboard).
"""
from __future__ import annotations

import json

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QGuiApplication
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QTableWidget,
    QWidget,
)


def _cell(table: QTableWidget, r: int, c: int) -> str:
    item = table.item(r, c)
    return item.text() if item else ""


def _headers(table: QTableWidget) -> list[str]:
    out = []
    for c in range(table.columnCount()):
        h = table.horizontalHeaderItem(c)
        out.append(h.text() if h else str(c))
    return out


def selected_grid(table: QTableWidget) -> tuple[list[str], list[list[str]]]:
    """Return (headers, rows) for the current selection, or the current row."""
    ranges = table.selectedRanges()
    headers = _headers(table)
    if not ranges:
        r = table.currentRow()
        if r < 0:
            return headers, []
        return headers, [[_cell(table, r, c) for c in range(table.columnCount())]]
    rows = sorted({i for rng in ranges for i in range(rng.topRow(), rng.bottomRow() + 1)})
    data = [[_cell(table, r, c) for c in range(table.columnCount())] for r in rows]
    return headers, data


def as_tsv(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["\t".join(headers)]
    lines += ["\t".join(row) for row in rows]
    return "\n".join(lines)


def as_json(headers: list[str], rows: list[list[str]]) -> str:
    return json.dumps([dict(zip(headers, row, strict=False)) for row in rows], indent=2)


def as_markdown(headers: list[str], rows: list[list[str]]) -> str:
    def esc(s: str) -> str:
        return s.replace("|", "\\|")

    out = ["| " + " | ".join(esc(h) for h in headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    out += ["| " + " | ".join(esc(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def install_copy_menu(table: QTableWidget, status=None) -> None:
    """Add a right-click "Copy" menu (cell, TSV, JSON, Markdown) to ``table``."""
    table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def show(pos) -> None:
        menu = QMenu(table)
        item = table.itemAt(pos)

        def copy(text: str, what: str) -> None:
            if not text:
                return
            QGuiApplication.clipboard().setText(text)
            if status:
                status(f"{what} copied", 3000)

        if item is not None:
            act = QAction("Copy cell", table)
            act.triggered.connect(lambda: copy(item.text(), "Cell"))
            menu.addAction(act)
            menu.addSeparator()
        headers, rows = selected_grid(table)
        n = len(rows)
        for label, fn in (
            (f"Copy {n} row(s) as TSV", as_tsv),
            (f"Copy {n} row(s) as JSON", as_json),
            (f"Copy {n} row(s) as Markdown", as_markdown),
        ):
            act = QAction(label, table)
            act.setEnabled(n > 0)
            act.triggered.connect(
                lambda _=False, f=fn, lbl=label: copy(f(headers, rows), lbl.split(" as ")[-1])
            )
            menu.addAction(act)
        menu.exec(table.viewport().mapToGlobal(pos))

    table.customContextMenuRequested.connect(show)


def filter_table(table: QTableWidget, text: str) -> int:
    """Hide rows that do not contain ``text`` (case-insensitive). Returns shown count."""
    needle = text.lower().strip()
    shown = 0
    for r in range(table.rowCount()):
        if not needle:
            match = True
        else:
            match = any(needle in _cell(table, r, c).lower()
                        for c in range(table.columnCount()))
        table.setRowHidden(r, not match)
        shown += int(match)
    return shown


class SearchBar(QWidget):
    """A small search box that live-filters a bound table; Esc clears it."""

    def __init__(self, table: QTableWidget, status=None, placeholder: str = "Filter rows…"):
        super().__init__()
        self._table = table
        self._status = status
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(QLabel("Filter:"))
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(placeholder + "  (Esc to clear)")
        self.edit.setClearButtonEnabled(True)
        self.edit.textChanged.connect(self._apply)
        lay.addWidget(self.edit, 1)
        self.count = QLabel("")
        lay.addWidget(self.count)

    def _apply(self, text: str) -> None:
        shown = filter_table(self._table, text)
        total = self._table.rowCount()
        self.count.setText(f"{shown}/{total}" if text.strip() else "")

    def refresh(self) -> None:
        """Re-apply the current filter (call after the table is repopulated)."""
        self._apply(self.edit.text())

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.key() == Qt.Key.Key_Escape:
            self.edit.clear()
        else:
            super().keyPressEvent(event)

    def focus(self) -> None:
        self.edit.setFocus()
        self.edit.selectAll()
