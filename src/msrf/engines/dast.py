"""DAST engine — dynamic analysis via MobSF and Frida device orchestration.

Combines two capabilities:

* MobSF's dynamic-analysis REST endpoints (start/stop a session, pull the
  dynamic report) for an app already uploaded via the SAST engine.
* Frida device/process enumeration and frida-server provisioning, so a device
  is ready for instrumentation (see the ``hooks`` engine for script injection).
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

from .. import device as dev
from ..config import Config
from ..exceptions import EngineError, ToolNotFoundError
from ..platform_utils import NO_WINDOW, frida_server_arch, require_tool, run, which
from ..provisioning import ensure_frida_server
from ..registry import register
from .base import Engine, action
from .sast import MobSFServer

try:
    import frida
except Exception:  # pragma: no cover
    frida = None  # type: ignore[assignment]


def _require_frida() -> frida:
    if frida is None:
        raise ToolNotFoundError(
            "frida", "Install with 'pip install frida frida-tools'."
        )
    return frida


@register
class DASTEngine(Engine):
    """Dynamic application security testing (MobSF dynamic + Frida)."""

    name = "dast"
    summary = "Dynamic analysis via MobSF and Frida device orchestration."

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.server = MobSFServer(config)

    def preflight(self) -> dict[str, Any]:
        details: dict[str, Any] = {
            "frida_python": frida is not None,
            "frida_cli": which("frida"),
            "adb": which("adb"),
        }
        ready = frida is not None and which("adb") is not None
        try:
            details["devices"] = [d.serial for d in dev.list_devices()]
        except Exception as exc:  # adb missing or server not started
            details["devices_error"] = str(exc)
        return {"engine": self.name, "ready": ready, "details": details}

    # -- Frida device/process enumeration --------------------------------

    @action("List Frida-visible devices (USB, remote, local).")
    def devices(self) -> dict[str, Any]:
        f = _require_frida()
        out = []
        for d in f.enumerate_devices():
            out.append({"id": d.id, "name": d.name, "type": d.type})
        return {"devices": out}

    @action("List running processes on a device via Frida.")
    def processes(self, device_id: str | None = None) -> dict[str, Any]:
        f = _require_frida()
        device = f.get_usb_device(timeout=10) if not device_id else f.get_device(device_id)
        procs = [{"pid": p.pid, "name": p.name} for p in device.enumerate_processes()]
        return {"device": device.id, "processes": procs}

    @action("List installed applications on a device via Frida.")
    def applications(self, device_id: str | None = None) -> dict[str, Any]:
        f = _require_frida()
        device = f.get_usb_device(timeout=10) if not device_id else f.get_device(device_id)
        apps = [
            {"identifier": a.identifier, "name": a.name, "pid": a.pid}
            for a in device.enumerate_applications()
        ]
        return {"device": device.id, "applications": apps}

    # -- frida-server provisioning ---------------------------------------

    @action(
        "Push and start a matching frida-server binary on a rooted Android device.",
        mutating=True,
    )
    def provision_frida_server(
        self,
        server_binary: str | None = None,
        serial: str | None = None,
        remote_path: str = "/data/local/tmp/frida-server",
    ) -> dict[str, Any]:
        """Deploy frida-server to the device and launch it in the background.

        The binary is resolved without bundling anything in the package: an
        explicit ``server_binary``, then ``config.frida.server_dir``, then a
        cached/downloaded frida-server matching the device ABI and the installed
        Frida version (fetched on demand into the workspace).

        Args:
            server_binary: Explicit path to a frida-server binary (optional).
            serial: Target device serial (defaults to the sole device).
            remote_path: Where to place the binary on the device.
        """
        serial = dev.resolve_serial(serial)
        abi = dev.device_abi(serial)
        arch = frida_server_arch(abi)

        if server_binary:
            binary = Path(server_binary).expanduser()
            if not binary.is_file():
                raise EngineError("dast", f"frida-server binary not found: {binary}")
        else:
            # Fetch on demand (cached); no binaries are shipped in the package.
            binary = ensure_frida_server(
                arch,
                cache_dir=self.config.workspace / "frida-server",
                local_dir=self.config.frida.server_dir,
            )
        dev.push(binary, remote_path, serial=serial)
        dev.shell(["chmod", "755", remote_path], serial=serial)
        # Launch detached; ignore output.
        adb = require_tool("adb")
        from ..platform_utils import spawn

        spawn([adb, "-s", serial, "shell", remote_path, "-D"])
        return {
            "device": serial,
            "arch": arch,
            "binary": str(binary),
            "remote_path": remote_path,
            "started": True,
        }

    # -- MobSF dynamic analysis ------------------------------------------

    @action("List apps available for MobSF dynamic analysis.")
    def dynamic_apps(self) -> dict[str, Any]:
        with self.server.client() as client:
            return client.dynamic_get_apps()

    @action("Start a MobSF dynamic-analysis session for a scan hash.", mutating=True)
    def dynamic_start(self, scan_hash: str) -> dict[str, Any]:
        with self.server.client() as client:
            return client.dynamic_start(scan_hash)

    @action("Stop the MobSF dynamic-analysis session for a scan hash.", mutating=True)
    def dynamic_stop(self, scan_hash: str) -> dict[str, Any]:
        with self.server.client() as client:
            return client.dynamic_stop(scan_hash)

    @action("Fetch the MobSF dynamic-analysis JSON report for a scan hash.")
    def dynamic_report(self, scan_hash: str) -> dict[str, Any]:
        with self.server.client() as client:
            return client.dynamic_report_json(scan_hash)

    # -- on-device techniques (adb) --------------------------------------

    @action("Install an APK onto a device.", mutating=True)
    def install_app(self, apk_path: str, serial: str | None = None) -> dict[str, Any]:
        out = dev.install(Path(apk_path).expanduser(), serial=serial)
        return {"output": out}

    @action("Pull an installed app's APK(s) off the device.")
    def pull_apk(
        self, package: str, serial: str | None = None, out_dir: str | None = None
    ) -> dict[str, Any]:
        adb = dev.adb_path()
        serial = dev.resolve_serial(serial)
        paths = dev.shell(["pm", "path", package], serial=serial).splitlines()
        remotes = [p.split(":", 1)[1].strip() for p in paths if p.startswith("package:")]
        if not remotes:
            raise EngineError("dast", f"App {package!r} not found on device.")
        dest = Path(out_dir).expanduser() if out_dir else self.config.workspace / "apks" / package
        dest.mkdir(parents=True, exist_ok=True)
        pulled = []
        for r in remotes:
            local = dest / Path(r).name
            run([adb, "-s", serial, "pull", r, str(local)], check=False)
            pulled.append(str(local))
        return {"package": package, "pulled": pulled}

    @action("Capture the device logcat buffer.")
    def logcat(
        self, serial: str | None = None, lines: int = 500, clear: bool = False
    ) -> dict[str, Any]:
        adb = dev.adb_path()
        serial = dev.resolve_serial(serial)
        if clear:
            run([adb, "-s", serial, "logcat", "-c"], check=False)
            return {"cleared": True}
        out = run([adb, "-s", serial, "logcat", "-d", "-t", str(lines)], check=False, timeout=60)
        return {"lines": out.stdout.splitlines()}

    @action("Dump device runtime state via dumpsys (optionally one service).")
    def dumpsys(self, service: str | None = None, serial: str | None = None) -> dict[str, Any]:
        serial = dev.resolve_serial(serial)
        cmd = ["dumpsys"] + ([service] if service else [])
        out = dev.shell(cmd, serial=serial, timeout=120)
        return {"service": service or "all", "output": out[:200000]}

    @action("Take a device screenshot and save it to the workspace.")
    def screenshot(self, serial: str | None = None, out_path: str | None = None) -> dict[str, Any]:
        adb = dev.adb_path()
        serial = dev.resolve_serial(serial)
        target = (
            Path(out_path).expanduser()
            if out_path
            else self.config.workspace / "screenshots" / f"{serial}-{int(time.time())}.png"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(  # noqa: S603
            [adb, "-s", serial, "exec-out", "screencap", "-p"],
            capture_output=True, timeout=30, check=False, **NO_WINDOW,
        )
        if proc.returncode != 0 or not proc.stdout:
            err = proc.stderr.decode(errors="replace")[:200]
            raise EngineError("dast", f"screencap failed: {err}")
        target.write_bytes(proc.stdout)
        return {"screenshot": str(target)}

    @action("Start an activity (component) on the device.", mutating=True)
    def start_activity(
        self, package: str, activity: str, serial: str | None = None
    ) -> dict[str, Any]:
        serial = dev.resolve_serial(serial)
        comp = activity if "/" in activity else f"{package}/{activity}"
        out = dev.shell(["am", "start", "-n", comp], serial=serial)
        return {"component": comp, "output": out.strip()}

    @action("Activity tester: launch each activity and screenshot it.", mutating=True)
    def activity_tester(
        self, package: str, activities: list[str], serial: str | None = None
    ) -> dict[str, Any]:
        """Launch each activity in ``activities`` and capture a screenshot.

        Pass the exported/browsable activities from a static scan
        (``sast report`` -> ``exported_activities``).
        """
        serial = dev.resolve_serial(serial)
        results = []
        for act in activities:
            comp = act if "/" in act else f"{package}/{act}"
            try:
                dev.shell(["am", "start", "-n", comp], serial=serial)
                time.sleep(1.5)
                shot = self.screenshot(serial=serial)
                results.append({"activity": comp, "screenshot": shot["screenshot"]})
            except Exception as exc:
                results.append({"activity": comp, "error": str(exc)})
        return {"package": package, "tested": results}

    @action("Send a deeplink/URI intent to the device.", mutating=True)
    def deeplink(self, uri: str, serial: str | None = None) -> dict[str, Any]:
        serial = dev.resolve_serial(serial)
        out = dev.shell(
            ["am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", uri],
            serial=serial,
        )
        return {"uri": uri, "output": out.strip()}
