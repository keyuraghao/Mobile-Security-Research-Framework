"""Simulator engine — a built-in device & Frida target requiring nothing external.

Exposes the built-in simulator (:mod:`mobiot.sim`) as first-class actions so the
dynamic-analysis and Frida-payload workflows can be demonstrated and tested with
no Android emulator, SDK or physical device attached. Select it elsewhere with
``--device sim`` (e.g. ``mobiot hooks test --template ssl-pinning-bypass
--device-id sim``).
"""
from __future__ import annotations

from typing import Any

from ..config import Config
from ..registry import register
from ..sim import FridaScriptSimulator, SimDevice
from .base import Engine, action
from .hooks import HooksEngine


@register
class SimEngine(Engine):
    """Built-in device/app simulator for dependency-free testing."""

    name = "sim"
    summary = "Built-in Android/Frida simulator — test with nothing external attached."

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.device = SimDevice.default()
        self.simulator = FridaScriptSimulator()
        self._hooks = HooksEngine(config)

    def preflight(self) -> dict[str, Any]:
        return {
            "engine": self.name,
            "ready": True,  # always available; pure in-process
            "details": {
                "device_id": self.device.id,
                "abi": self.device.abi,
                "apps": [a.identifier for a in self.device.apps],
            },
        }

    @action("Describe the built-in simulated device.")
    def status(self) -> dict[str, Any]:
        d = self.device
        return {
            "id": d.id,
            "name": d.name,
            "type": d.type,
            "abi": d.abi,
            "android_version": d.android_version,
            "rooted": d.rooted,
            "apps": d.applications(),
        }

    @action("List applications on the simulated device.")
    def applications(self) -> dict[str, Any]:
        return {"device": self.device.id, "applications": self.device.applications()}

    @action("List processes on the simulated device.")
    def processes(self) -> dict[str, Any]:
        return {"device": self.device.id, "processes": self.device.processes()}

    @action("Validate a Frida script without running it (heuristic checks).")
    def validate(
        self,
        template: str | None = None,
        script_path: str | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        source = self._resolve_source(template, script_path, params)
        return {"template": template, **self.simulator.validate(source)}

    @action(
        "Generate + validate + simulate a Frida payload against the built-in target."
    )
    def run_hook(
        self,
        template: str | None = None,
        script_path: str | None = None,
        params: dict[str, str] | None = None,
        package: str = "jakhar.aseem.diva",
    ) -> dict[str, Any]:
        """Simulate injecting a payload into the built-in DIVA-like app.

        Mirrors ``hooks test`` but runs entirely in-process: the script is
        validated, then realistic ``send()`` output is produced for the template.
        No device, emulator or frida-server is required.
        """
        source = self._resolve_source(template, script_path, params)
        report = self.simulator.validate(source)
        messages = self.simulator.simulate(source) if report["ok"] else []
        return {
            "device": self.device.id,
            "package": package,
            "template": template,
            "validation": report,
            "loaded": report["ok"],
            "message_count": len(messages),
            "messages": messages,
        }

    def _resolve_source(
        self,
        template: str | None,
        script_path: str | None,
        params: dict[str, str] | None,
    ) -> str:
        from pathlib import Path

        from ..exceptions import EngineError

        if script_path:
            return Path(script_path).expanduser().read_text(encoding="utf-8")
        if template:
            return self._hooks.generate(template, params=params)["script"]
        raise EngineError("sim", "Provide either 'template' or 'script_path'.")
