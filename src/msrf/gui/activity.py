"""Activity log: a Console-style record of every task the app runs.

Inspired by Core Impact's Executed Modules panel. Every non-quiet background
task is recorded with its label, the engine/action or parameters it ran with,
start/finish times, a status, and its result. Selecting a row shows three tabs,
Output (the result), Log (errors or messages) and Parameters, so a run can be
inspected and reproduced. Entries are appended to ``<workspace>/activity.jsonl``
so the history survives a restart.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .table_tools import SearchBar, install_copy_menu

_STATUS_COLOR = {"running": "#4aa3ff", "finished": "#3fb950", "error": "#e05561"}
_MAX_ROWS = 500  # keep the table light; full history stays in the .jsonl file


class ActivityLog:
    """In-memory task history with append-only persistence to the workspace."""

    def __init__(self, workspace: Path) -> None:
        self._path = Path(workspace) / "activity.jsonl"
        self._entries: list[dict[str, Any]] = []
        self._next_id = 0
        self._listeners: list[Any] = []
        self._load()

    def subscribe(self, fn) -> None:
        self._listeners.append(fn)

    def _notify(self) -> None:
        for fn in list(self._listeners):
            fn()

    def _load(self) -> None:
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in lines[-_MAX_ROWS:]:
            try:
                self._entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        self._next_id = len(self._entries)

    def _append(self, entry: dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass

    @property
    def entries(self) -> list[dict[str, Any]]:
        return self._entries

    def start(self, label: str, params: Any = None) -> int:
        eid = self._next_id
        self._next_id += 1
        self._entries.append({
            "id": eid, "label": label, "status": "running",
            "started": time.strftime("%H:%M:%S"), "_t0": time.monotonic(),
            "finished": "", "elapsed": "", "params": params,
            "output": None, "log": "",
        })
        if len(self._entries) > _MAX_ROWS:
            self._entries = self._entries[-_MAX_ROWS:]
        self._notify()
        return eid

    def finish(self, eid: int, status: str, output: Any = None, log: str = "") -> None:
        for e in reversed(self._entries):
            if e["id"] == eid:
                e["status"] = status
                e["finished"] = time.strftime("%H:%M:%S")
                e["elapsed"] = f"{time.monotonic() - e.get('_t0', time.monotonic()):.1f}s"
                e["output"] = output
                e["log"] = log
                persist = {k: v for k, v in e.items() if not k.startswith("_")}
                self._append(persist)
                self._notify()
                return

    def clear(self) -> None:
        import contextlib
        self._entries.clear()
        with contextlib.suppress(OSError):
            self._path.unlink(missing_ok=True)
        self._notify()


class ActivityView(QWidget):
    """Table of tasks with an Output / Log / Parameters detail pane."""

    _changed = pyqtSignal()

    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self.log = host.activity
        self._build()
        # Marshal cross-thread notifications onto the GUI thread via a signal.
        self._changed.connect(self._refresh)
        self.log.subscribe(self._changed.emit)
        self._refresh()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("<b>Activity</b>  (every task the app runs)"))
        bar.addStretch(1)
        clear = QPushButton("Clear")
        clear.clicked.connect(self.log.clear)
        bar.addWidget(clear)
        lay.addLayout(bar)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Task", "Started", "Status", "Elapsed"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._show_detail)
        install_copy_menu(self.table, self.host.status)

        self.search = SearchBar(self.table, self.host.status, "Filter tasks…")

        self.detail = QTabWidget()
        self.out = _mono()
        self.log_view = _mono()
        self.params = _mono()
        self.detail.addTab(self.out, "Output")
        self.detail.addTab(self.log_view, "Log")
        self.detail.addTab(self.params, "Parameters")

        split = QSplitter(Qt.Orientation.Vertical)
        top = QWidget()
        tl = QVBoxLayout(top)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.addWidget(self.search)
        tl.addWidget(self.table)
        split.addWidget(top)
        split.addWidget(self.detail)
        split.setSizes([360, 240])
        lay.addWidget(split, 1)

    def _refresh(self) -> None:
        keep_id = self._selected_id()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for e in reversed(self.log.entries):  # newest first
            r = self.table.rowCount()
            self.table.insertRow(r)
            name = QTableWidgetItem(str(e.get("label", "")))
            name.setData(Qt.ItemDataRole.UserRole, e.get("id"))
            self.table.setItem(r, 0, name)
            self.table.setItem(r, 1, QTableWidgetItem(str(e.get("started", ""))))
            st = QTableWidgetItem(str(e.get("status", "")))
            color = _STATUS_COLOR.get(e.get("status"))
            if color:
                st.setForeground(QColor(color))
            self.table.setItem(r, 2, st)
            self.table.setItem(r, 3, QTableWidgetItem(str(e.get("elapsed", ""))))
            if keep_id is not None and e.get("id") == keep_id:
                self.table.selectRow(r)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.search.refresh()

    def _selected_id(self):
        items = self.table.selectedItems()
        if not items:
            return None
        return self.table.item(items[0].row(), 0).data(Qt.ItemDataRole.UserRole)

    def _show_detail(self) -> None:
        eid = self._selected_id()
        entry = next((e for e in self.log.entries if e.get("id") == eid), None)
        if entry is None:
            return
        out = entry.get("output")
        self.out.setPlainText(json.dumps(out, indent=2, default=str) if out is not None else "")
        self.log_view.setPlainText(str(entry.get("log") or ""))
        params = entry.get("params")
        self.params.setPlainText(json.dumps(params, indent=2, default=str) if params else "")


def _mono() -> QPlainTextEdit:
    w = QPlainTextEdit()
    w.setReadOnly(True)
    w.setFont(QFont("Consolas", 10))
    return w
