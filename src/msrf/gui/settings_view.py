"""Settings tab: view and change configuration, saved to the config file.

Groups the settings a user is most likely to change (theme, workspace, MobSF
offline profile, proxy ports, emulator defaults). Save writes them to the
per-user ``config.toml`` so they persist across restarts. Theme and emulator
defaults apply immediately; MobSF and proxy changes apply next launch (they are
read when those services start), which the tab states plainly.
"""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..config import DEFAULT_CONFIG_PATH, Config, save_config


class SettingsView(QWidget):
    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._build()
        self._load_from_config()

    # -- layout ----------------------------------------------------------

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.addWidget(QLabel(
            "<b>Settings</b> are saved to <code>" + str(DEFAULT_CONFIG_PATH) + "</code>. "
            "Theme and emulator defaults apply right away; MobSF and proxy changes "
            "apply the next time you start the app."
        ))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        form_host = QVBoxLayout(body)

        # General
        gen = QGroupBox("General")
        gf = QFormLayout(gen)
        self.theme = QComboBox()
        self.theme.addItems(["light", "dark", "system"])
        self.theme.currentTextChanged.connect(self._apply_theme_live)
        gf.addRow("Theme:", self.theme)
        ws = QHBoxLayout()
        self.workspace = QLineEdit()
        browse = QPushButton("Browse")
        browse.clicked.connect(self._pick_workspace)
        ws.addWidget(self.workspace, 1)
        ws.addWidget(browse)
        gf.addRow("Workspace:", ws)
        self.log_level = QComboBox()
        self.log_level.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        gf.addRow("Log level:", self.log_level)
        form_host.addWidget(gen)

        # MobSF
        mob = QGroupBox("MobSF (static/dynamic analysis)")
        mf = QFormLayout(mob)
        self.mobsf_port = _spin(1, 65535)
        mf.addRow("Server port:", self.mobsf_port)
        self.mobsf_timeout = _dspin(10, 600, " s")
        mf.addRow("Startup timeout:", self.mobsf_timeout)
        self.offline_profile = QCheckBox("Offline profile (fast, no runtime downloads)")
        self.use_system_jadx = QCheckBox("Use system jadx (on PATH)")
        self.api_only = QCheckBox("REST API only (no web UI)")
        self.disable_auth = QCheckBox("Disable web-UI login")
        self.async_analysis = QCheckBox("Async analysis (needs a worker)")
        self.domain_malware = QCheckBox("Domain malware check (online)")
        self.vt_enabled = QCheckBox("VirusTotal lookups (online)")
        for cb in (self.offline_profile, self.use_system_jadx, self.api_only,
                   self.disable_auth, self.async_analysis, self.domain_malware,
                   self.vt_enabled):
            mf.addRow(cb)
        form_host.addWidget(mob)

        # Proxy
        prox = QGroupBox("Proxy (mitmproxy)")
        pf = QFormLayout(prox)
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(["regular", "transparent", "wireguard", "socks5", "upstream"])
        pf.addRow("Default mode:", self.proxy_mode)
        self.proxy_host = QLineEdit()
        pf.addRow("Listen host:", self.proxy_host)
        self.proxy_port = _spin(1, 65535)
        pf.addRow("Listen port:", self.proxy_port)
        self.proxy_web = _spin(1, 65535)
        pf.addRow("Web UI port:", self.proxy_web)
        self.proxy_wg = _spin(1, 65535)
        pf.addRow("WireGuard UDP port:", self.proxy_wg)
        form_host.addWidget(prox)

        # Emulator
        emu = QGroupBox("Emulator defaults")
        ef = QFormLayout(emu)
        self.emu_avd = QLineEdit()
        ef.addRow("AVD name:", self.emu_avd)
        self.emu_api = _spin(7, 35)
        ef.addRow("API level:", self.emu_api)
        self.emu_image = QComboBox()
        self.emu_image.addItems(["google_apis", "google_apis_playstore", "default"])
        ef.addRow("Image:", self.emu_image)
        self.emu_abi = QComboBox()
        self.emu_abi.addItems(["x86_64", "arm64-v8a", "x86"])
        ef.addRow("ABI:", self.emu_abi)
        self.emu_headless = QCheckBox("Launch without a window (headless)")
        ef.addRow(self.emu_headless)
        self.emu_boot = _dspin(60, 1200, " s")
        ef.addRow("Boot timeout:", self.emu_boot)
        form_host.addWidget(emu)

        form_host.addStretch(1)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        # Actions
        actions = QHBoxLayout()
        open_cfg = QPushButton("Open config file")
        open_cfg.clicked.connect(self._open_config)
        open_ws = QPushButton("Open workspace folder")
        open_ws.clicked.connect(self._open_workspace)
        reset = QPushButton("Reset to defaults")
        reset.clicked.connect(self._reset_defaults)
        save = QPushButton("Save settings")
        save.setObjectName("primary")
        save.clicked.connect(self._save)
        actions.addWidget(open_cfg)
        actions.addWidget(open_ws)
        actions.addStretch(1)
        actions.addWidget(reset)
        actions.addWidget(save)
        outer.addLayout(actions)
        self.saved_note = QLabel("")
        self.saved_note.setStyleSheet("color: #3fb950;")
        outer.addWidget(self.saved_note)

    # -- load / save -----------------------------------------------------

    def _load_from_config(self, cfg: Config | None = None) -> None:
        c = cfg or self.host.config
        self.theme.blockSignals(True)
        self.theme.setCurrentText(str(self.host._settings.value("theme", "light")))
        self.theme.blockSignals(False)
        self.workspace.setText(str(c.workspace))
        self.log_level.setCurrentText(c.log_level)
        self.mobsf_port.setValue(c.mobsf.port)
        self.mobsf_timeout.setValue(c.mobsf.startup_timeout)
        self.offline_profile.setChecked(c.mobsf.offline_profile)
        self.use_system_jadx.setChecked(c.mobsf.use_system_jadx)
        self.api_only.setChecked(c.mobsf.api_only)
        self.disable_auth.setChecked(c.mobsf.disable_authentication)
        self.async_analysis.setChecked(c.mobsf.async_analysis)
        self.domain_malware.setChecked(c.mobsf.domain_malware_scan)
        self.vt_enabled.setChecked(c.mobsf.vt_enabled)
        self.proxy_mode.setCurrentText(c.proxy.mode)
        self.proxy_host.setText(c.proxy.listen_host)
        self.proxy_port.setValue(c.proxy.listen_port)
        self.proxy_web.setValue(c.proxy.web_port)
        self.proxy_wg.setValue(c.proxy.wireguard_port)
        self.emu_avd.setText(c.emulator.avd_name)
        self.emu_api.setValue(c.emulator.api_level)
        self.emu_image.setCurrentText(c.emulator.image_type)
        self.emu_abi.setCurrentText(c.emulator.abi)
        self.emu_headless.setChecked(c.emulator.headless)
        self.emu_boot.setValue(c.emulator.boot_timeout)

    def _apply_to_config(self) -> None:
        c = self.host.config
        c.workspace = Path(self.workspace.text().strip() or str(c.workspace)).expanduser()
        c.log_level = self.log_level.currentText()
        c.mobsf.port = self.mobsf_port.value()
        c.mobsf.startup_timeout = self.mobsf_timeout.value()
        c.mobsf.offline_profile = self.offline_profile.isChecked()
        c.mobsf.use_system_jadx = self.use_system_jadx.isChecked()
        c.mobsf.api_only = self.api_only.isChecked()
        c.mobsf.disable_authentication = self.disable_auth.isChecked()
        c.mobsf.async_analysis = self.async_analysis.isChecked()
        c.mobsf.domain_malware_scan = self.domain_malware.isChecked()
        c.mobsf.vt_enabled = self.vt_enabled.isChecked()
        c.proxy.mode = self.proxy_mode.currentText()
        c.proxy.listen_host = self.proxy_host.text().strip() or "0.0.0.0"
        c.proxy.listen_port = self.proxy_port.value()
        c.proxy.web_port = self.proxy_web.value()
        c.proxy.wireguard_port = self.proxy_wg.value()
        c.emulator.avd_name = self.emu_avd.text().strip() or "msrf"
        c.emulator.api_level = self.emu_api.value()
        c.emulator.image_type = self.emu_image.currentText()
        c.emulator.abi = self.emu_abi.currentText()
        c.emulator.headless = self.emu_headless.isChecked()
        c.emulator.boot_timeout = self.emu_boot.value()

    def _save(self) -> None:
        self._apply_to_config()
        self.host._settings.setValue("theme", self.theme.currentText())
        try:
            self.host.config.ensure_dirs()
            path = save_config(self.host.config)
        except Exception as exc:
            QMessageBox.warning(self, "Save failed", f"Could not save settings:\n{exc}")
            return
        self.saved_note.setText(
            f"Saved to {path}. Theme and emulator defaults apply now; "
            "MobSF and proxy changes apply next launch."
        )
        self.host.status(f"Settings saved to {path}", 6000)

    def _reset_defaults(self) -> None:
        if QMessageBox.question(self, "Reset settings",
                                "Reset all settings on this tab to defaults?") \
                != QMessageBox.StandardButton.Yes:
            return
        self._load_from_config(Config())

    def _apply_theme_live(self, mode: str) -> None:
        self.host._set_theme(mode)

    def _pick_workspace(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose workspace folder",
                                                self.workspace.text())
        if path:
            self.workspace.setText(path)

    def _open_config(self) -> None:
        if not DEFAULT_CONFIG_PATH.is_file():
            self._save()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(DEFAULT_CONFIG_PATH)))

    def _open_workspace(self) -> None:
        ws = Path(self.workspace.text().strip() or str(self.host.config.workspace))
        ws.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(ws)))


def _spin(lo: int, hi: int) -> QSpinBox:
    s = QSpinBox()
    s.setRange(lo, hi)
    s.setAlignment(Qt.AlignmentFlag.AlignRight)
    return s


def _dspin(lo: float, hi: float, suffix: str) -> QDoubleSpinBox:
    s = QDoubleSpinBox()
    s.setRange(lo, hi)
    s.setDecimals(0)
    s.setSuffix(suffix)
    s.setAlignment(Qt.AlignmentFlag.AlignRight)
    return s
