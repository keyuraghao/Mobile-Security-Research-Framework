"""Emulator view: provision and drive a rooted Android emulator.

Dropdowns choose the Android API level, image variant and ABI; checkboxes pick
which common Xposed/LSPosed modules to install. Buttons run each step (setup,
start, root, LSPosed, modules, root checker) or the whole pipeline. Long steps
run on worker threads and stream status to the log.
"""
from __future__ import annotations

import json
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..engines.emulator import CURATED_MODULES


class EmulatorView(QWidget):
    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._module_boxes: dict[str, QCheckBox] = {}
        self._build()
        self._status()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        note = QLabel(
            "<b>Managed rooted Android emulator</b> (Magisk + LSPosed). "
            "Requires host virtualization: Linux <b>KVM</b>, Windows <b>WHPX/HAXM</b> "
            "or <b>Hyper-V</b>, macOS <b>Hypervisor.framework</b>. The Android SDK, "
            "system image and modules download automatically on first run (a few GB)."
        )
        note.setTextFormat(Qt.TextFormat.RichText)
        note.setWordWrap(True)
        lay.addWidget(note)

        steps = QLabel(
            "<b>How to use:</b> &nbsp; 1) pick API / image / ABI below &nbsp;→&nbsp; "
            "2) click <b>Provision all-in-one</b> (does Setup → Start → Root → LSPosed → "
            "Modules → Root checker). &nbsp; Or run the buttons one by one. &nbsp; "
            "3) In the emulator, open <b>LSPosed</b> to enable the installed modules, and "
            "<b>Magisk</b> to confirm root. &nbsp; Use <b>Status</b> anytime to check "
            "tools / booted / rooted state."
        )
        steps.setTextFormat(Qt.TextFormat.RichText)
        steps.setWordWrap(True)
        steps.setStyleSheet(
            "background:#eef4fa; border:1px solid #b8d4ec; border-radius:4px; padding:8px;"
        )
        lay.addWidget(steps)

        cfg = QGroupBox("Configuration")
        grid = QGridLayout(cfg)
        grid.addWidget(QLabel("API level:"), 0, 0)
        self.api = QComboBox()
        # Full range: API 7 (Android 2.1) .. 35 (Android 15). Not every level has
        # an x86_64 system image; setup reports if the chosen image is unavailable.
        self.api.addItems([str(i) for i in range(7, 36)])
        self.api.setCurrentText("33")
        grid.addWidget(self.api, 0, 1)
        grid.addWidget(QLabel("Image:"), 0, 2)
        self.image = QComboBox()
        self.image.addItems(["google_apis", "default", "google_apis_playstore"])
        grid.addWidget(self.image, 0, 3)
        grid.addWidget(QLabel("ABI:"), 0, 4)
        self.abi = QComboBox()
        self.abi.addItems(["x86_64", "arm64-v8a", "x86"])
        grid.addWidget(self.abi, 0, 5)
        self.headless = QCheckBox("Headless")
        grid.addWidget(self.headless, 0, 6)
        lay.addWidget(cfg)

        actions = QHBoxLayout()
        for label, slot in (
            ("List images", self._list_images),
            ("Setup", self._setup),
            ("Start", self._start),
            ("Stop", self._stop),
            ("Root (Magisk)", self._root),
            ("Install LSPosed", self._lsposed),
            ("Root checker", self._rootchecker),
            ("Status", self._status),
        ):
            b = QPushButton(label)
            b.clicked.connect(slot)
            actions.addWidget(b)
        actions.addStretch(1)
        prov = QPushButton("Provision all-in-one")
        prov.setObjectName("primary")
        prov.clicked.connect(self._provision)
        actions.addWidget(prov)
        lay.addLayout(actions)

        mods = QGroupBox("Xposed / LSPosed modules")
        mlay = QHBoxLayout(mods)
        for name in CURATED_MODULES:
            cb = QCheckBox(name)
            cb.setChecked(True)
            self._module_boxes[name] = cb
            mlay.addWidget(cb)
        install_sel = QPushButton("Install selected")
        install_sel.clicked.connect(self._install_modules)
        add_custom = QPushButton("Add custom APK…")
        add_custom.clicked.connect(self._add_custom)
        mlay.addStretch(1)
        mlay.addWidget(install_sel)
        mlay.addWidget(add_custom)
        lay.addWidget(mods)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        lay.addWidget(self.output, 1)

    # -- helpers ---------------------------------------------------------

    def _apply_cfg(self) -> None:
        c = self.host.config.emulator
        c.api_level = int(self.api.currentText())
        c.image_type = self.image.currentText()
        c.abi = self.abi.currentText()
        c.headless = self.headless.isChecked()

    def _run(self, method: str, **kwargs: Any) -> None:
        self._apply_cfg()
        self.output.appendPlainText(f"\n--- emulator.{method} ---")
        self.host.status(f"emulator: {method} …")
        self.host.submit(
            lambda: getattr(self.host.engine("emulator"), method)(**kwargs),
            on_result=lambda d: self.output.appendPlainText(json.dumps(d, indent=2, default=str)),
            on_error=lambda e: self.output.appendPlainText(f"error: {e}"),
        )

    # -- slots -----------------------------------------------------------

    def _setup(self) -> None:
        self._run("setup")

    def _start(self) -> None:
        self._run("start")

    def _stop(self) -> None:
        self._run("stop")

    def _root(self) -> None:
        self._run("root")

    def _lsposed(self) -> None:
        self._run("install_lsposed")

    def _rootchecker(self) -> None:
        self._run("install_root_checker")

    def _status(self) -> None:
        self._run("status")

    def _list_images(self) -> None:
        self._apply_cfg()
        self._run("list_images", api_level=int(self.api.currentText()))

    def _provision(self) -> None:
        mods = [n for n, cb in self._module_boxes.items() if cb.isChecked()]
        self._run("provision", modules=mods)

    def _install_modules(self) -> None:
        mods = [n for n, cb in self._module_boxes.items() if cb.isChecked()]
        self._run("install_modules", names=mods)

    def _add_custom(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Xposed module APK", "", "APK (*.apk)")
        if path:
            self._run("add_module", apk_path=path)
