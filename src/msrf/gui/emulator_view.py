"""Emulator view: the normal Android emulator, with live progress and logs.

The main flow is the same as Android Studio: create a virtual device, then
launch it; the SDK emulator opens in its own window showing the phone screen.
While any step runs, an activity line shows what is happening and for how long,
a progress bar shows the app is working, and the live log streams every line
the step writes to ``logs/emulator.log`` (also kept on disk, so a hang can be
diagnosed even after closing the app). Rooting with Magisk and installing
LSPosed/Xposed modules are optional and live under "Advanced".
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices, QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..engines.emulator import CURATED_MODULES

# Friendly names for the activity line.
_STEP_TITLES = {
    "setup": "Creating virtual device (downloads the SDK and system image on first run)",
    "start": "Launching emulator and waiting for Android to boot",
    "stop": "Stopping emulator",
    "status": "Checking status",
    "list_images": "Listing available system images",
    "root": "Rooting with Magisk",
    "install_lsposed": "Installing LSPosed",
    "install_modules": "Installing Xposed modules",
    "add_module": "Installing custom module",
    "install_root_checker": "Installing Magisk app",
    "provision": "Rooted all-in-one setup",
}
# If a running step writes nothing for this long, point the user at the log.
_QUIET_WARN_SECS = 60


class EmulatorView(QWidget):
    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._module_boxes: dict[str, QCheckBox] = {}
        self._busy_buttons: list[QPushButton] = []
        # Running steps: id -> (title, start time). Stop/Status stay usable while
        # a long step runs, so more than one can be active at once.
        self._steps: dict[int, tuple[str, float]] = {}
        self._next_id = 0
        self._last_output = 0.0
        self._log_pos = 0
        self._build()
        self._load_existing_log()

        self._tail_timer = QTimer(self)
        self._tail_timer.timeout.connect(self._tail_log)
        self._tail_timer.start(500)
        self._clock = QTimer(self)
        self._clock.timeout.connect(self._update_activity)

    # -- layout ----------------------------------------------------------

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        intro = QLabel(
            "<b>Android emulator</b>: the same emulator Android Studio uses. "
            "<b>Launch</b> opens it in its own window, where you see and use the phone. "
            "First run downloads the Android SDK and a system image (a few GB). Needs "
            "virtualization: <b>KVM</b> on Linux, <b>WHPX</b> or <b>HAXM</b> on Windows, "
            "<b>Hypervisor.framework</b> on macOS."
        )
        intro.setTextFormat(Qt.TextFormat.RichText)
        intro.setWordWrap(True)
        lay.addWidget(intro)

        # 1. Virtual device
        dev = QGroupBox("1. Virtual device")
        grid = QGridLayout(dev)
        grid.addWidget(QLabel("API level:"), 0, 0)
        self.api = QComboBox()
        # API 7 (Android 2.1) .. 35 (Android 15). Not every level has every
        # image/ABI; setup picks the closest one that exists and says so.
        self.api.addItems([str(i) for i in range(7, 36)])
        self.api.setCurrentText("33")
        grid.addWidget(self.api, 0, 1)
        grid.addWidget(QLabel("Image:"), 0, 2)
        self.image = QComboBox()
        self.image.addItems(["google_apis", "google_apis_playstore", "default"])
        grid.addWidget(self.image, 0, 3)
        grid.addWidget(QLabel("ABI:"), 0, 4)
        self.abi = QComboBox()
        self.abi.addItems(["x86_64", "arm64-v8a", "x86"])
        grid.addWidget(self.abi, 0, 5)
        grid.setColumnStretch(6, 1)
        list_btn = QPushButton("List images")
        list_btn.clicked.connect(self._list_images)
        grid.addWidget(list_btn, 0, 7)
        create_btn = QPushButton("Create device")
        create_btn.setToolTip("Install the SDK + system image and create the virtual device")
        create_btn.clicked.connect(lambda: self._run("setup"))
        grid.addWidget(create_btn, 0, 8)
        self._busy_buttons += [list_btn, create_btn]
        lay.addWidget(dev)

        # 2. Run
        run_box = QGroupBox("2. Run")
        rlay = QHBoxLayout(run_box)
        launch = QPushButton("Launch emulator")
        launch.setObjectName("primary")
        launch.setToolTip("Open the emulator in its own window")
        launch.clicked.connect(lambda: self._run("start"))
        stop = QPushButton("Stop")
        stop.clicked.connect(lambda: self._run("stop"))
        status = QPushButton("Status")
        status.clicked.connect(lambda: self._run("status"))
        rlay.addWidget(launch)
        rlay.addWidget(stop)
        rlay.addWidget(status)
        rlay.addStretch(1)
        self._busy_buttons.append(launch)
        lay.addWidget(run_box)

        # Activity + progress
        act = QGroupBox("Activity")
        alay = QVBoxLayout(act)
        self.activity = QLabel("Idle")
        self.activity.setWordWrap(True)
        alay.addWidget(self.activity)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setMaximumHeight(14)
        alay.addWidget(self.progress)
        lay.addWidget(act)

        # Live log
        log_box = QGroupBox("Live log")
        llay = QVBoxLayout(log_box)
        bar = QHBoxLayout()
        self.log_label = QLabel(f"<code>{self._log_path()}</code>")
        self.log_label.setTextFormat(Qt.TextFormat.RichText)
        self.log_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        bar.addWidget(self.log_label, 1)
        for text, slot in (("Open log file", self._open_log),
                           ("Copy path", self._copy_log_path),
                           ("Clear view", self._clear_view)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            bar.addWidget(b)
        llay.addLayout(bar)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        self.output.setMaximumBlockCount(5000)
        llay.addWidget(self.output, 1)
        lay.addWidget(log_box, 1)

        # Advanced (optional, collapsed)
        self.adv_toggle = QToolButton()
        self.adv_toggle.setText("Advanced: root and Xposed (optional)")
        self.adv_toggle.setCheckable(True)
        self.adv_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.adv_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.adv_toggle.toggled.connect(self._toggle_advanced)
        lay.addWidget(self.adv_toggle)

        self.advanced = QGroupBox()
        adv = QVBoxLayout(self.advanced)
        adv.addWidget(QLabel(
            "Changes the virtual device for deeper testing. Root with Magisk first, "
            "then install LSPosed and modules, then enable them in the LSPosed app."
        ))
        arow = QHBoxLayout()
        for label, method in (("Root (Magisk)", "root"),
                              ("Install LSPosed", "install_lsposed"),
                              ("Install Magisk app", "install_root_checker")):
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, m=method: self._run(m))
            arow.addWidget(b)
            self._busy_buttons.append(b)
        self.headless = QCheckBox("Launch without window (headless)")
        arow.addWidget(self.headless)
        arow.addStretch(1)
        prov = QPushButton("Rooted all-in-one")
        prov.setToolTip("Create device, launch, root, LSPosed, modules, Magisk app")
        prov.clicked.connect(self._provision)
        arow.addWidget(prov)
        self._busy_buttons.append(prov)
        adv.addLayout(arow)
        mrow = QHBoxLayout()
        mrow.addWidget(QLabel("Modules:"))
        for name in CURATED_MODULES:
            cb = QCheckBox(name)
            cb.setChecked(True)
            self._module_boxes[name] = cb
            mrow.addWidget(cb)
        mrow.addStretch(1)
        inst = QPushButton("Install selected")
        inst.clicked.connect(self._install_modules)
        custom = QPushButton("Add custom APK…")
        custom.clicked.connect(self._add_custom)
        mrow.addWidget(inst)
        mrow.addWidget(custom)
        self._busy_buttons += [inst, custom]
        adv.addLayout(mrow)
        self.advanced.setVisible(False)
        lay.addWidget(self.advanced)

    def _toggle_advanced(self, on: bool) -> None:
        self.advanced.setVisible(on)
        self.adv_toggle.setArrowType(Qt.ArrowType.DownArrow if on else Qt.ArrowType.RightArrow)

    # -- running steps ---------------------------------------------------

    def _apply_cfg(self) -> None:
        c = self.host.config.emulator
        c.api_level = int(self.api.currentText())
        c.image_type = self.image.currentText()
        c.abi = self.abi.currentText()
        c.headless = self.headless.isChecked()

    def _run(self, method: str, **kwargs: Any) -> None:
        self._apply_cfg()
        title = _STEP_TITLES.get(method, method)
        sid = self._begin(title)
        self.host.status(f"Emulator: {title}")
        self.host.submit(
            lambda: getattr(self.host.engine("emulator"), method)(**kwargs),
            on_result=lambda d, s=sid: self._done(s, d, None),
            on_error=lambda e, s=sid: self._done(s, None, e),
        )

    def _begin(self, title: str) -> int:
        sid = self._next_id
        self._next_id += 1
        self._steps[sid] = (title, time.monotonic())
        self._last_output = time.monotonic()
        self.output.appendPlainText(f"\n▶ {title}")
        self.progress.setRange(0, 0)  # busy animation
        for b in self._busy_buttons:
            b.setEnabled(False)
        self._clock.start(1000)
        self._update_activity()
        return sid

    def _done(self, sid: int, result: Any, error: str | None) -> None:
        self._tail_log()  # flush the last lines before the summary
        title, started = self._steps.pop(sid, ("step", time.monotonic()))
        secs = int(time.monotonic() - started)
        if error:
            self.output.appendPlainText(f"✖ {title} failed after {_fmt(secs)}: {error}")
        else:
            self.output.appendPlainText(json.dumps(result, indent=2, default=str))
            self.output.appendPlainText(f"✔ {title} finished in {_fmt(secs)}")
        if self._steps:
            self._update_activity()
        else:
            self._clock.stop()
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            for b in self._busy_buttons:
                b.setEnabled(True)
            state = "failed" if error else "finished"
            self.activity.setText(f"Idle. Last step {state}: {title} ({_fmt(secs)}).")
            self.host.status(f"Emulator: {title} {state}", 6000)

    def _update_activity(self) -> None:
        if not self._steps:
            return
        now = time.monotonic()
        text = "\n".join(f"Running: {title}   ⏱ {_fmt(int(now - start))}"
                         for title, start in self._steps.values())
        # Silence is measured from the newest step start or the last log line,
        # whichever is later.
        newest_start = max(start for _t, start in self._steps.values())
        quiet = int(now - max(self._last_output, newest_start))
        if quiet >= _QUIET_WARN_SECS:
            text += (f"\nNo new log output for {_fmt(quiet)}. Large downloads and first "
                     "boot can be slow; if it stays silent, check the live log below.")
        self.activity.setText(text)

    # -- live log --------------------------------------------------------

    def _log_path(self) -> Path:
        return Path(self.host.config.logs_dir) / "emulator.log"

    def _load_existing_log(self) -> None:
        """Show the end of any earlier log (e.g. from a run that hung)."""
        path = self._log_path()
        try:
            data = path.read_bytes()
        except OSError:
            return
        self._log_pos = len(data)
        lines = data.decode(errors="replace").splitlines()[-200:]
        if lines:
            self.output.appendPlainText("… previous log (last 200 lines) …")
            self.output.appendPlainText("\n".join(lines))
            self.output.appendPlainText("… end of previous log …")

    def _tail_log(self) -> None:
        path = self._log_path()
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size < self._log_pos:  # log was cleared/rotated
            self._log_pos = 0
        if size == self._log_pos:
            return
        try:
            with path.open("rb") as fh:
                fh.seek(self._log_pos)
                chunk = fh.read()
        except OSError:
            return
        self._log_pos += len(chunk)
        text = chunk.decode(errors="replace").rstrip("\n")
        if text:
            self.output.appendPlainText(text)
            self._last_output = time.monotonic()

    def _open_log(self) -> None:
        path = self._log_path()
        if not path.is_file():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _copy_log_path(self) -> None:
        QGuiApplication.clipboard().setText(str(self._log_path()))
        self.host.status("Log path copied", 3000)

    def _clear_view(self) -> None:
        self.output.clear()

    # -- slots -----------------------------------------------------------

    def _list_images(self) -> None:
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


def _fmt(secs: int) -> str:
    m, s = divmod(max(0, secs), 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
