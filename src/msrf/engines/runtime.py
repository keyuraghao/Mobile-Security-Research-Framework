"""Runtime engine — runtime mobile exploration via objection.

Wraps the ``objection`` CLI (itself Frida-powered) to run one-shot runtime
commands against an app non-interactively: disabling SSL pinning, defeating root
detection, dumping the keystore, listing classes, and arbitrary objection
commands. Requires a Frida-instrumentable target (frida-server on Android, or a
gadget-embedded app).
"""
from __future__ import annotations

from typing import Any

from ..config import Config
from ..platform_utils import require_tool, run, which
from ..registry import register
from .base import Engine, action

_OBJECTION_HINT = "Install with 'pip install objection'."


@register
class RuntimeEngine(Engine):
    """Runtime exploration and hooking via objection."""

    name = "runtime"
    summary = "Runtime app exploration and patching via objection."

    def __init__(self, config: Config) -> None:
        super().__init__(config)

    def preflight(self) -> dict[str, Any]:
        path = which("objection")
        return {
            "engine": self.name,
            "ready": path is not None,
            "details": {"objection": path},
        }

    def _run_objection(
        self, package: str, command: str, device_id: str | None, timeout: float
    ) -> dict[str, Any]:
        objection = require_tool("objection", hint=_OBJECTION_HINT)
        argv = [objection]
        if device_id:
            argv += ["-S", device_id]
        argv += ["-g", package, "explore", "-s", command]
        # Feed 'exit' so objection leaves its REPL after the startup command.
        result = run(argv, input_text="exit\n", timeout=timeout, check=False)
        return {
            "package": package,
            "command": command,
            "returncode": result.returncode,
            "output": result.stdout + ("\n" + result.stderr if result.stderr else ""),
        }

    @action("Run an arbitrary objection command against an app.", mutating=True)
    def run_command(
        self,
        package: str,
        command: str,
        device_id: str | None = None,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        """Execute a single objection command (e.g. ``android hooking list classes``)."""
        return self._run_objection(package, command, device_id, timeout)

    @action("Disable SSL pinning in an app via objection.", mutating=True)
    def disable_ssl_pinning(
        self, package: str, device_id: str | None = None
    ) -> dict[str, Any]:
        return self._run_objection(package, "android sslpinning disable", device_id, 120.0)

    @action("Disable root detection in an app via objection.", mutating=True)
    def disable_root_detection(
        self, package: str, device_id: str | None = None
    ) -> dict[str, Any]:
        return self._run_objection(package, "android root disable", device_id, 120.0)

    @action("List Android Keystore entries used by an app via objection.")
    def keystore_list(
        self, package: str, device_id: str | None = None
    ) -> dict[str, Any]:
        return self._run_objection(package, "android keystore list", device_id, 120.0)

    @action("List classes loaded by an app via objection.")
    def list_classes(
        self, package: str, device_id: str | None = None
    ) -> dict[str, Any]:
        return self._run_objection(package, "android hooking list classes", device_id, 180.0)
