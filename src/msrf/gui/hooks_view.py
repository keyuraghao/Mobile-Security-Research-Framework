"""Frida Hooks tab: run library hooks, write your own, or combine many at once.

Three sub-tabs share one Target and Package selector and one output pane:

* Library: pick an inbuilt hook, fill its parameters, view, copy or run it.
* Custom: type or paste any Frida JavaScript, load/save it anywhere, run it.
* Multi-hook: list several classes/methods (and library hooks), combine them
  into one script and run them all against one app in a single session.
"""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

DEFAULT_PACKAGE = "jakhar.aseem.diva"


def _editor() -> QPlainTextEdit:
    e = QPlainTextEdit()
    e.setFont(QFont("Consolas", 10))
    e.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    e.setTabStopDistance(28)
    return e


class HooksView(QWidget):
    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._meta: dict[str, dict] = {}
        self._build()
        self._load_templates()

    # -- layout ----------------------------------------------------------

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)

        # Shared target + package row.
        top = QHBoxLayout()
        top.addWidget(QLabel("Target:"))
        self.device = QComboBox()
        self.device.addItem("Simulator (no device needed)", "sim")
        self.device.addItem("Device or emulator (adb)", "usb")
        top.addWidget(self.device)
        top.addWidget(QLabel("Package:"))
        self.package = QLineEdit(DEFAULT_PACKAGE)
        self.package.setToolTip("The app to inject into (its package identifier).")
        top.addWidget(self.package, 1)
        outer.addLayout(top)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_library(), "Library")
        self.tabs.addTab(self._build_custom(), "Custom hook")
        self.tabs.addTab(self._build_multi(), "Multi-hook")
        outer.addWidget(self.tabs)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        self.output.setMaximumBlockCount(8000)
        outer.addWidget(self.output, 1)

    def _build_library(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        row.addWidget(QLabel("Hook:"))
        self.combo = QComboBox()
        self.combo.setMinimumWidth(280)
        self.combo.currentIndexChanged.connect(self._template_selected)
        row.addWidget(self.combo, 1)
        lay.addLayout(row)
        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        lay.addWidget(self.summary)

        box = QGroupBox("Parameters (for custom-target hooks)")
        pf = QVBoxLayout(box)
        self.p_class = QLineEdit()
        self.p_class.setPlaceholderText("CLASS  e.g. jakhar.aseem.diva.APICreds")
        self.p_method = QLineEdit()
        self.p_method.setPlaceholderText("METHOD  e.g. access")
        self.p_filter = QLineEdit()
        self.p_filter.setPlaceholderText("FILTER  e.g. diva")
        pf.addWidget(self.p_class)
        pf.addWidget(self.p_method)
        pf.addWidget(self.p_filter)
        lay.addWidget(box)

        btns = QHBoxLayout()
        view = QPushButton("View script")
        view.clicked.connect(self._lib_view)
        copy = QPushButton("Copy script")
        copy.clicked.connect(self._lib_copy)
        edit = QPushButton("Send to Custom")
        edit.setToolTip("Open this script in the Custom hook editor to tweak it.")
        edit.clicked.connect(self._lib_to_custom)
        run = QPushButton("Run hook")
        run.setObjectName("primary")
        run.clicked.connect(self._lib_run)
        for b in (view, copy, edit):
            btns.addWidget(b)
        btns.addStretch(1)
        btns.addWidget(run)
        lay.addLayout(btns)
        lay.addStretch(1)
        return w

    def _build_custom(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(QLabel(
            "Type or paste any Frida JavaScript. Save it anywhere to reuse later, "
            "or run it on the target above."
        ))
        self.custom = _editor()
        self.custom.setPlaceholderText(
            "Java.perform(function () {\n"
            "    var C = Java.use('com.example.Target');\n"
            "    C.someMethod.implementation = function () {\n"
            "        send({ tag: 'demo', msg: 'called someMethod' });\n"
            "        return this.someMethod.apply(this, arguments);\n"
            "    };\n"
            "});"
        )
        lay.addWidget(self.custom, 1)
        btns = QHBoxLayout()
        for text, slot in (("Load file", self._custom_load),
                           ("Save as", self._custom_save),
                           ("Copy", self._custom_copy),
                           ("Clear", lambda: self.custom.clear())):
            b = QPushButton(text)
            b.clicked.connect(slot)
            btns.addWidget(b)
        btns.addStretch(1)
        run = QPushButton("Run script")
        run.setObjectName("primary")
        run.clicked.connect(self._custom_run)
        btns.addWidget(run)
        lay.addLayout(btns)
        return w

    def _build_multi(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(QLabel(
            "Hook many functions of one app at once. Add class/method rows (leave "
            "method blank to trace every method of the class), then build and run "
            "them together in a single injection."
        ))
        self.multi = QTableWidget(0, 2)
        self.multi.setHorizontalHeaderLabels(["Class (fully-qualified)", "Method (blank = all)"])
        self.multi.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.multi.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        lay.addWidget(self.multi, 1)

        row = QHBoxLayout()
        add = QPushButton("Add row")
        add.clicked.connect(lambda: self._multi_add_row())
        rm = QPushButton("Remove selected")
        rm.clicked.connect(self._multi_remove)
        row.addWidget(add)
        row.addWidget(rm)
        row.addWidget(QLabel("  or add a library hook:"))
        self.multi_lib = QComboBox()
        self.multi_lib.setMinimumWidth(200)
        row.addWidget(self.multi_lib)
        add_lib = QPushButton("Add hook")
        add_lib.clicked.connect(self._multi_add_lib)
        row.addWidget(add_lib)
        row.addStretch(1)
        lay.addLayout(row)

        btns = QHBoxLayout()
        build = QPushButton("Build combined script")
        build.clicked.connect(self._multi_build)
        run = QPushButton("Build and run all")
        run.setObjectName("primary")
        run.clicked.connect(self._multi_run)
        btns.addStretch(1)
        btns.addWidget(build)
        btns.addWidget(run)
        lay.addLayout(btns)
        self._multi_add_row("jakhar.aseem.diva.APICreds", "access")
        return w

    # -- shared helpers --------------------------------------------------

    def _device_id(self):
        return "sim" if self.device.currentData() == "sim" else None

    def _pkg(self) -> str:
        return self.package.text().strip() or DEFAULT_PACKAGE

    def _log(self, text: str) -> None:
        self.output.appendPlainText(text)

    def _rule(self, title: str) -> None:
        self._log(f"\n--- {title} " + "-" * max(0, 46 - len(title)))

    def _run_source(self, source: str, label: str) -> None:
        if not source.strip():
            self._log("Nothing to run: the script is empty.")
            return
        self._rule(f"run {label} on {self.device.currentData()} ({self._pkg()})")
        self.host.status(f"Frida: running {label}")
        self.host.submit(
            lambda: self.host.engine("hooks").test(
                source=source, package=self._pkg(), device_id=self._device_id()),
            on_result=self._show_result,
            on_error=lambda e: self._log(f"error: {e}"),
        )

    def _show_result(self, res: dict) -> None:
        self._log(f"loaded={res.get('loaded')}  messages={res.get('message_count')}")
        for m in res.get("messages", []):
            if isinstance(m, dict):
                self._log(f"  [{m.get('tag')}] {m.get('msg')}")
            else:
                self._log(f"  {m}")
        for e in res.get("errors", []):
            self._log(f"  ERROR {e}")

    def _copy(self, text: str, what: str) -> None:
        if not text.strip():
            self.host.status("Nothing to copy", 3000)
            return
        QGuiApplication.clipboard().setText(text)
        self.host.status(f"{what} copied to clipboard", 3000)

    def _save(self, text: str) -> None:
        if not text.strip():
            self.host.status("Nothing to save", 3000)
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Frida script", "hook.js",
                                              "JavaScript (*.js);;All files (*)")
        if not path:
            return
        self.host.submit(
            lambda: self.host.engine("hooks").save_script(text, path),
            on_result=lambda d: self.host.status(f"Saved {d['path']}", 5000),
            on_error=lambda e: self._log(f"save error: {e}"),
        )

    # -- library ---------------------------------------------------------

    def _load_templates(self) -> None:
        def done(tpls):
            self.combo.clear()
            self.multi_lib.clear()
            self._meta.clear()
            for t in sorted(tpls, key=lambda x: (x["category"], x["name"])):
                self.combo.addItem(f"[{t['category']}] {t['name']}", t["name"])
                self.multi_lib.addItem(t["name"], t["name"])
                self._meta[t["name"]] = t
            self._template_selected()
        self.host.submit(lambda: self.host.engine("hooks").list_templates()["templates"],
                         on_result=done, on_error=lambda e: self._log(f"error: {e}"))

    def _current_template(self):
        name = self.combo.currentData()
        return name, self._meta.get(name, {})

    def _template_selected(self) -> None:
        _name, meta = self._current_template()
        if not meta:
            return
        self.summary.setText(meta.get("summary", ""))
        params = meta.get("params", {})
        self.p_class.setEnabled("CLASS" in params)
        self.p_method.setEnabled("METHOD" in params)
        self.p_filter.setEnabled("FILTER" in params)

    def _lib_params(self):
        _name, meta = self._current_template()
        params = meta.get("params", {})
        out = {}
        for key, widget in (("CLASS", self.p_class), ("METHOD", self.p_method),
                            ("FILTER", self.p_filter)):
            if key in params and widget.text().strip():
                out[key] = widget.text().strip()
        return out or None

    def _lib_generate(self, then) -> None:
        name, _meta = self._current_template()
        self.host.submit(
            lambda: self.host.engine("hooks").generate(name, params=self._lib_params())["script"],
            on_result=then,
            on_error=lambda e: self._log(f"error: {e}"),
        )

    def _lib_view(self) -> None:
        name, _ = self._current_template()
        self._rule(f"script: {name}")
        self._lib_generate(self._log)

    def _lib_copy(self) -> None:
        self._lib_generate(lambda s: self._copy(s, "Script"))

    def _lib_to_custom(self) -> None:
        def to_editor(s):
            self.custom.setPlainText(s)
            self.tabs.setCurrentIndex(1)
        self._lib_generate(to_editor)

    def _lib_run(self) -> None:
        name, _ = self._current_template()
        self._lib_generate(lambda s: self._run_source(s, name))

    # -- custom ----------------------------------------------------------

    def _custom_load(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open Frida script", "",
                                              "JavaScript (*.js);;All files (*)")
        if not path:
            return
        try:
            self.custom.setPlainText(Path(path).read_text(encoding="utf-8", errors="replace"))
            self.host.status(f"Loaded {path}", 4000)
        except OSError as exc:
            self._log(f"load error: {exc}")

    def _custom_save(self) -> None:
        self._save(self.custom.toPlainText())

    def _custom_copy(self) -> None:
        self._copy(self.custom.toPlainText(), "Script")

    def _custom_run(self) -> None:
        self._run_source(self.custom.toPlainText(), "custom script")

    # -- multi-hook ------------------------------------------------------

    def _multi_add_row(self, cls: str = "", method: str = "") -> None:
        r = self.multi.rowCount()
        self.multi.insertRow(r)
        self.multi.setItem(r, 0, QTableWidgetItem(cls))
        self.multi.setItem(r, 1, QTableWidgetItem(method))

    def _multi_remove(self) -> None:
        rows = sorted({i.row() for i in self.multi.selectedItems()}, reverse=True)
        for r in rows:
            self.multi.removeRow(r)

    def _multi_add_lib(self) -> None:
        name = self.multi_lib.currentData()
        if name:
            # Encode a library template as a row using the special "@template" class.
            self._multi_add_row(f"@{name}", "")

    def _multi_specs(self) -> list[dict]:
        specs: list[dict] = []
        for r in range(self.multi.rowCount()):
            cls = (self.multi.item(r, 0).text() if self.multi.item(r, 0) else "").strip()
            method = (self.multi.item(r, 1).text() if self.multi.item(r, 1) else "").strip()
            if not cls:
                continue
            if cls.startswith("@"):
                specs.append({"template": cls[1:]})
            elif method:
                specs.append({"class": cls, "method": method})
            else:
                # No method: trace every method of the class.
                specs.append({"template": "method-trace", "params": {"CLASS": cls}})
        return specs

    def _multi_combine(self, then) -> None:
        specs = self._multi_specs()
        if not specs:
            self._log("Add at least one class to the multi-hook list.")
            return
        self.host.submit(
            lambda: self.host.engine("hooks").combine(specs),
            on_result=then,
            on_error=lambda e: self._log(f"error: {e}"),
        )

    def _multi_build(self) -> None:
        def done(res):
            self.custom.setPlainText(res["script"])
            self.tabs.setCurrentIndex(1)
            self._log(f"Built combined script with {res['count']} hook(s): "
                      + ", ".join(res["hooks"]))
        self._multi_combine(done)

    def _multi_run(self) -> None:
        def done(res):
            self._run_source(res["script"], f"{res['count']} combined hooks")
        self._multi_combine(done)
