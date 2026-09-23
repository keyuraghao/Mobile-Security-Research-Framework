"""App Data view: grab and open the databases a running app writes.

Pull an app's data files (SQLite databases, shared_prefs) from the built-in
simulator sample data or a real device, then browse them: SQLite databases show
a table picker and a rows grid; shared_prefs XML shows key/value/type rows;
other files show a text or hex preview.
"""
from __future__ import annotations

from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .sast_view import _Table


class AppDataView(QWidget):
    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._current: str | None = None
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Target:"))
        self.device = QComboBox()
        self.device.addItem("Simulator (sample data)", "sim")
        self.device.addItem("USB device (real, run-as)", "usb")
        bar.addWidget(self.device)
        bar.addWidget(QLabel("Package:"))
        self.package = QLineEdit("jakhar.aseem.diva")
        bar.addWidget(self.package, 1)
        self.grab_btn = QPushButton("Grab data files")
        self.grab_btn.setObjectName("primary")
        bar.addWidget(self.grab_btn)
        lay.addLayout(bar)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.files = QListWidget()
        self.files.setMinimumWidth(280)
        split.addWidget(self.files)

        right = QWidget()
        rlay = QVBoxLayout(right)
        rlay.setContentsMargins(0, 0, 0, 0)
        trow = QHBoxLayout()
        trow.addWidget(QLabel("Table:"))
        self.table_combo = QComboBox()
        self.table_combo.setMinimumWidth(240)
        trow.addWidget(self.table_combo)
        trow.addStretch(1)
        rlay.addLayout(trow)

        self.stack = QStackedWidget()
        self.rows_table = _Table(["(no data)"])
        self.kv_table = _Table(["Key", "Type", "Value"])
        self.text_view = QPlainTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setFont(QFont("Consolas", 10))
        self.stack.addWidget(self.rows_table)  # 0
        self.stack.addWidget(self.kv_table)    # 1
        self.stack.addWidget(self.text_view)   # 2
        rlay.addWidget(self.stack, 1)
        split.addWidget(right)
        split.setSizes([300, 780])
        lay.addWidget(split, 1)

        self.grab_btn.clicked.connect(self._grab)
        self.files.itemSelectionChanged.connect(self._select_file)
        self.table_combo.currentIndexChanged.connect(self._load_rows)

    # -- actions ---------------------------------------------------------

    def _grab(self) -> None:
        pkg = self.package.text().strip()
        if not pkg:
            return
        device_id = self.device.currentData()
        self.host.status(f"Grabbing data files for {pkg} …")
        self.host.submit(
            lambda: self.host.engine("appdata").pull(pkg, device_id=device_id),
            on_result=lambda d: self._grabbed(pkg),
            on_error=lambda e: self.host.status(f"Grab failed: {e}", 8000),
        )

    def _grabbed(self, pkg: str) -> None:
        self.host.submit(
            lambda: self.host.engine("appdata").databases(pkg),
            on_result=self._list_files,
            on_error=lambda e: self.host.status(f"List failed: {e}", 8000),
        )

    def _list_files(self, data: dict) -> None:
        self.files.clear()
        for f in data.get("files", []):
            item = QListWidgetItem(f"{f['rel']}   [{f['type']}]")
            item.setData(Qt.ItemDataRole.UserRole, f)
            self.files.addItem(item)
        self.host.status(f"Grabbed {len(data.get('files', []))} file(s)", 6000)

    def _select_file(self) -> None:
        items = self.files.selectedItems()
        if not items:
            return
        meta: dict[str, Any] = items[0].data(Qt.ItemDataRole.UserRole)
        self._current = meta["path"]
        self.table_combo.blockSignals(True)
        self.table_combo.clear()
        self.table_combo.blockSignals(False)
        self.host.submit(
            lambda: self.host.engine("appdata").open(meta["path"]),
            on_result=self._show,
            on_error=lambda e: self._show_text(f"Cannot open: {e}"),
        )

    def _show(self, info: dict) -> None:
        kind = info.get("type")
        if kind == "sqlite":
            self.table_combo.blockSignals(True)
            self.table_combo.clear()
            for t in info.get("tables", []):
                self.table_combo.addItem(f"{t['name']}  ({t['rows']} rows)", t["name"])
            self.table_combo.blockSignals(False)
            self._load_rows()
        elif kind == "xml":
            rows = [[e["key"], e["type"], e["value"]] for e in info.get("entries", [])]
            self.kv_table.fill(rows)
            self.stack.setCurrentWidget(self.kv_table)
        elif kind == "text":
            self._show_text(info.get("content", ""))
        else:
            self._show_text("[binary file]\n\n" + info.get("preview_hex", ""))

    def _load_rows(self) -> None:
        table = self.table_combo.currentData()
        if not table or not self._current:
            return
        self.host.submit(
            lambda: self.host.engine("appdata").rows(self._current, table),
            on_result=self._fill_rows,
            on_error=lambda e: self._show_text(f"Query failed: {e}"),
        )

    def _fill_rows(self, res: dict) -> None:
        cols = res.get("columns") or ["(empty)"]
        self.rows_table.setColumnCount(len(cols))
        self.rows_table.setHorizontalHeaderLabels(cols)
        self.rows_table.fill(res.get("rows", []))
        self.stack.setCurrentWidget(self.rows_table)

    def _show_text(self, text: str) -> None:
        self.text_view.setPlainText(text)
        self.stack.setCurrentWidget(self.text_view)
