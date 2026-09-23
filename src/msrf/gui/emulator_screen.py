"""Live emulator/device screen mirror as a dockable, floatable panel.

Mirrors a connected emulator or device by polling ``adb exec-out screencap`` and
forwards taps and hardware keys back with ``adb shell input``. Self-contained
(uses the bundled adb), so it works alongside the other tabs and can be popped
out into its own window. Frame rate is modest (a few fps); for full-speed mirror
use scrcpy separately.
"""
from __future__ import annotations

import subprocess

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..platform_utils import NO_WINDOW, which

_KEYS = {"Home": 3, "Back": 4, "Recents": 187, "Power": 26, "Menu": 82}


class _Screen(QLabel):
    """Displays a frame and maps clicks to device coordinates."""

    def __init__(self, on_tap) -> None:
        super().__init__()
        self._on_tap = on_tap
        self._dev_size = (0, 0)  # device pixels of the current frame
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumSize(220, 380)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self.setText("No emulator/device.\nStart one in the Emulator tab, then Connect.")

    def set_frame(self, pix: QPixmap) -> None:
        self._dev_size = (pix.width(), pix.height())
        self.setPixmap(
            pix.scaled(
                self.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )

    def mousePressEvent(self, ev) -> None:  # noqa: N802 - Qt override
        dw, dh = self._dev_size
        pm = self.pixmap()
        if not dw or pm is None or pm.isNull():
            return
        # The scaled pixmap is centered; compute its rect within the label.
        sw, sh = pm.width(), pm.height()
        ox = (self.width() - sw) / 2
        oy = (self.height() - sh) / 2
        x = ev.position().x() - ox
        y = ev.position().y() - oy
        if 0 <= x <= sw and 0 <= y <= sh:
            self._on_tap(int(x / sw * dw), int(y / sh * dh))


class EmulatorScreen(QWidget):
    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._serial: str | None = None
        self._build()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        bar = QHBoxLayout()
        self.device = QComboBox()
        self.device.setMinimumWidth(140)
        bar.addWidget(self.device)
        refresh = QPushButton("↻")
        refresh.setFixedWidth(28)
        refresh.setToolTip("Refresh device list")
        refresh.clicked.connect(self._refresh_devices)
        bar.addWidget(refresh)
        self.live_btn = QPushButton("Connect")
        self.live_btn.setCheckable(True)
        self.live_btn.toggled.connect(self._toggle_live)
        bar.addWidget(self.live_btn)
        bar.addStretch(1)
        for label in ("Back", "Home", "Recents"):
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, k=label: self._key(k))
            bar.addWidget(b)
        lay.addLayout(bar)
        self.screen = _Screen(self._tap)
        lay.addWidget(self.screen, 1)
        self._refresh_devices()

    # -- adb helpers -----------------------------------------------------

    def _adb(self) -> str | None:
        try:
            return self.host.engine("emulator")._adb() or which("adb")
        except Exception:
            return which("adb")

    def _refresh_devices(self) -> None:
        adb = self._adb()
        self.device.clear()
        if not adb:
            return
        try:
            out = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=10, **NO_WINDOW)
            for line in out.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device":
                    self.device.addItem(parts[0], parts[0])
        except Exception:
            pass

    def _current_serial(self) -> str | None:
        return self.device.currentData()

    # -- live loop -------------------------------------------------------

    def _toggle_live(self, on: bool) -> None:
        if on:
            self._serial = self._current_serial()
            self.live_btn.setText("Disconnect")
            self.timer.start(450)
            self._tick()
        else:
            self.live_btn.setText("Connect")
            self.timer.stop()

    def _tick(self) -> None:
        adb = self._adb()
        serial = self._serial
        if not adb or not serial:
            self.screen.setText("No device selected.")
            self.timer.stop()
            self.live_btn.setChecked(False)
            return
        try:
            out = subprocess.run(
                [adb, "-s", serial, "exec-out", "screencap", "-p"],
                capture_output=True, timeout=10, **NO_WINDOW,
            )
            pix = QPixmap()
            if out.returncode == 0 and out.stdout and pix.loadFromData(out.stdout):
                self.screen.set_frame(pix)
            else:
                self.screen.setText("Waiting for screen…")
        except Exception as exc:
            self.screen.setText(f"Mirror error: {exc}")

    # -- input forwarding ------------------------------------------------

    def _tap(self, x: int, y: int) -> None:
        adb = self._adb()
        if adb and self._serial:
            self.host.submit(
                lambda: subprocess.run(
                    [adb, "-s", self._serial, "shell", "input", "tap", str(x), str(y)],
                    capture_output=True, timeout=10, **NO_WINDOW,
                )
            )

    def _key(self, name: str) -> None:
        adb = self._adb()
        serial = self._current_serial()
        code = _KEYS.get(name)
        if adb and serial and code:
            self.host.submit(
                lambda: subprocess.run(
                    [adb, "-s", serial, "shell", "input", "keyevent", str(code)],
                    capture_output=True, timeout=10, **NO_WINDOW,
                )
            )
