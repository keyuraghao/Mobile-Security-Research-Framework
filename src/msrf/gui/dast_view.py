"""Dynamic-analysis (DAST) view with dropdown-driven techniques.

Surfaces the dynamic techniques msrf supports: device/app/process
enumeration, frida-server provisioning, the full inbuilt Frida hook library, and
objection runtime operations. The user picks a target (built-in simulator or a
real device), a technique from a dropdown, fills any needed fields, and runs it.
"""
from __future__ import annotations

import json
from typing import Any

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

# Enumerate techniques the built-in simulator can answer (dast method -> sim method).
_SIM_EQUIVALENT = {"devices": "status", "applications": "applications", "processes": "processes"}


class DastView(QWidget):
    def __init__(self, host) -> None:
        super().__init__()
        self.host = host
        self._techniques: list[dict[str, Any]] = []
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        box = QGroupBox("Dynamic technique")
        form = QVBoxLayout(box)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Target:"))
        self.device = QComboBox()
        self.device.addItem("Simulator (no device needed)", "sim")
        self.device.addItem("Device or emulator (adb)", "usb")
        r1.addWidget(self.device)
        r1.addWidget(QLabel("Package:"))
        self.package = QLineEdit("jakhar.aseem.diva")
        r1.addWidget(self.package, 1)
        form.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Technique:"))
        self.technique = QComboBox()
        self.technique.setMinimumWidth(360)
        r2.addWidget(self.technique, 1)
        self.run_btn = QPushButton("Run technique")
        self.run_btn.setObjectName("primary")
        r2.addWidget(self.run_btn)
        form.addLayout(r2)

        r3 = QHBoxLayout()
        r3.addWidget(QLabel("Command:"))
        self.command = QLineEdit()
        self.command.setPlaceholderText("objection command, e.g. android hooking list activities")
        self.command.setEnabled(False)
        r3.addWidget(self.command, 1)
        form.addLayout(r3)

        lay.addWidget(box)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        lay.addWidget(self.output, 1)

        self.technique.currentIndexChanged.connect(self._technique_changed)
        self.run_btn.clicked.connect(self._run)
        self._load_techniques()

    def _load_techniques(self) -> None:
        # Static techniques first; Frida hooks are appended once loaded.
        base = [
            {"label": "Enumerate: devices", "engine": "dast", "method": "devices"},
            {"label": "Enumerate: applications", "engine": "dast", "method": "applications"},
            {"label": "Enumerate: processes", "engine": "dast", "method": "processes"},
            {"label": "Provision frida-server on device", "engine": "dast", "method": "provision_frida_server"},
            {"label": "Objection: disable SSL pinning", "engine": "runtime", "method": "disable_ssl_pinning", "pkg": True},
            {"label": "Objection: disable root detection", "engine": "runtime", "method": "disable_root_detection", "pkg": True},
            {"label": "Objection: list keystore", "engine": "runtime", "method": "keystore_list", "pkg": True},
            {"label": "Objection: list classes", "engine": "runtime", "method": "list_classes", "pkg": True},
            {"label": "Objection: run command", "engine": "runtime", "method": "run_command", "pkg": True, "cmd": True},
            # On-device techniques (adb): need a real connected device.
            {"label": "Device: capture logcat", "engine": "dast", "method": "logcat"},
            {"label": "Device: dumpsys (all)", "engine": "dast", "method": "dumpsys"},
            {"label": "Device: dumpsys (service)", "engine": "dast", "method": "dumpsys", "cmd": True, "cmd_arg": "service"},
            {"label": "Device: screenshot", "engine": "dast", "method": "screenshot"},
            {"label": "Device: install APK", "engine": "dast", "method": "install_app", "cmd": True, "cmd_arg": "apk_path"},
            {"label": "Device: pull APK(s)", "engine": "dast", "method": "pull_apk", "pkg": True},
            {"label": "Device: start activity", "engine": "dast", "method": "start_activity", "pkg": True, "cmd": True, "cmd_arg": "activity"},
            {"label": "Device: send deeplink", "engine": "dast", "method": "deeplink", "cmd": True, "cmd_arg": "uri"},
        ]
        self._techniques = base
        for t in base:
            self.technique.addItem(t["label"], t)

        def add_hooks(tpls):
            for t in sorted(tpls, key=lambda x: (x["category"], x["name"])):
                spec = {
                    "label": f"Frida hook: {t['name']} ({t['category']})",
                    "engine": "hooks",
                    "method": "test",
                    "template": t["name"],
                    "params": t.get("params", {}),
                }
                self._techniques.append(spec)
                self.technique.addItem(spec["label"], spec)

        def add_mobsf_scripts(res):
            for s in res.get("scripts", []):
                spec = {
                    "label": f"MobSF [{s['platform']}/{s['category']}] {s['name']}",
                    "engine": "hooks",
                    "method": "test",
                    "mobsf_script": s["id"],
                }
                self._techniques.append(spec)
                self.technique.addItem(spec["label"], spec)

        self.host.submit(
            lambda: self.host.engine("hooks").list_templates()["templates"],
            on_result=add_hooks,
        )
        self.host.submit(
            lambda: self.host.engine("hooks").mobsf_scripts(),
            on_result=add_mobsf_scripts,
        )

    def _technique_changed(self) -> None:
        spec = self.technique.currentData() or {}
        self.command.setEnabled(bool(spec.get("cmd")))
        self.command.setPlaceholderText(
            f"{spec.get('cmd_arg', 'command')} …" if spec.get("cmd") else "n/a"
        )

    def _run(self) -> None:
        spec = self.technique.currentData()
        if not spec:
            return
        device_choice = self.device.currentData()
        pkg = self.package.text().strip()
        self.output.appendPlainText(f"\n--- {spec['label']} ---")

        engine = spec["engine"]
        method = spec["method"]
        kwargs: dict[str, Any] = {}
        if device_choice == "sim" and engine != "hooks":
            # The simulator answers the enumerate techniques itself; everything
            # else here (adb, objection, frida-server) needs real hardware.
            sim_method = _SIM_EQUIVALENT.get(method)
            if not sim_method:
                self.output.appendPlainText(
                    "This technique needs a real device or the emulator. Set Target to "
                    "'Device or emulator (adb)' and make sure one is connected "
                    "(Emulator tab > Launch emulator)."
                )
                return
            engine, method = "sim", sim_method
        elif engine == "hooks":
            kwargs["device_id"] = "sim" if device_choice == "sim" else None
            kwargs["package"] = pkg
            if spec.get("mobsf_script"):
                kwargs["mobsf_script"] = spec["mobsf_script"]
            else:
                kwargs["template"] = spec["template"]
                if spec.get("params"):
                    defaults = {"CLASS": pkg + ".MainActivity", "METHOD": "onCreate", "FILTER": pkg}
                    kwargs["params"] = {k: defaults.get(k, "") for k in spec["params"]}
        elif engine != "sim":
            if spec.get("pkg"):
                kwargs["package"] = pkg
            if spec.get("cmd"):
                kwargs[spec.get("cmd_arg", "command")] = self.command.text().strip()

        self.host.submit(
            lambda: getattr(self.host.engine(engine), method)(**kwargs),
            on_result=lambda d: self.output.appendPlainText(json.dumps(d, indent=2, default=str)),
            on_error=lambda e: self.output.appendPlainText(f"error: {e}"),
            label=f"DAST: {spec['label']}", params=kwargs or None,
        )
