"""Android device helpers built on ``adb`` (cross-platform).

``adb`` is located via :func:`mobiot.platform_utils.which`, so this works
wherever the Android platform-tools are installed and on ``PATH`` — Linux,
macOS or Windows. iOS device support is intentionally out of scope here; the
Frida/objection engines talk to iOS over USB via their own tooling.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .exceptions import EngineError
from .platform_utils import require_tool, run

_ADB_HINT = "Install Android platform-tools and ensure 'adb' is on your PATH."


@dataclass(slots=True)
class Device:
    """A connected Android device or emulator."""

    serial: str
    state: str  # device, offline, unauthorized, ...
    model: str | None = None


def adb_path() -> str:
    """Return the resolved path to ``adb`` or raise :class:`ToolNotFoundError`."""
    return require_tool("adb", hint=_ADB_HINT)


def _adb(args: list[str], *, serial: str | None = None, timeout: float = 60.0):
    cmd = [adb_path()]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    return run(cmd, timeout=timeout, check=True)


def list_devices() -> list[Device]:
    """Return all devices known to the adb server."""
    result = run([adb_path(), "devices", "-l"], check=True)
    devices: list[Device] = []
    for line in result.stdout.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        serial, state = parts[0], parts[1]
        model = None
        for token in parts[2:]:
            if token.startswith("model:"):
                model = token.split(":", 1)[1]
        devices.append(Device(serial=serial, state=state, model=model))
    return devices


def resolve_serial(serial: str | None = None) -> str:
    """Return a usable device serial, defaulting to the sole connected device.

    Raises:
        EngineError: If no device (or, when ``serial`` is omitted, more than one)
            is available.
    """
    devices = [d for d in list_devices() if d.state == "device"]
    if serial:
        if any(d.serial == serial for d in devices):
            return serial
        raise EngineError("device", f"Device {serial!r} is not connected/ready.")
    if not devices:
        raise EngineError("device", "No ready Android device/emulator connected.")
    if len(devices) > 1:
        serials = ", ".join(d.serial for d in devices)
        raise EngineError(
            "device",
            f"Multiple devices connected ({serials}); specify one explicitly.",
        )
    return devices[0].serial


def getprop(name: str, serial: str | None = None) -> str:
    """Read a device system property via ``adb shell getprop``."""
    serial = resolve_serial(serial)
    return _adb(["shell", "getprop", name], serial=serial).stdout.strip()


def device_abi(serial: str | None = None) -> str:
    """Return the primary CPU ABI of the device (e.g. ``arm64-v8a``)."""
    return getprop("ro.product.cpu.abi", serial=serial)


def is_root(serial: str | None = None) -> bool:
    """Best-effort check for a rooted device / adb root shell."""
    serial = resolve_serial(serial)
    out = _adb(["shell", "id"], serial=serial).stdout
    return "uid=0" in out


def shell(command: list[str], serial: str | None = None, timeout: float = 120.0) -> str:
    """Run an ``adb shell`` command and return combined stdout."""
    serial = resolve_serial(serial)
    return _adb(["shell", *command], serial=serial, timeout=timeout).stdout


def push(local: Path, remote: str, serial: str | None = None) -> None:
    """Push a file to the device."""
    serial = resolve_serial(serial)
    if not Path(local).is_file():
        raise EngineError("device", f"Local file not found: {local}")
    _adb(["push", str(local), remote], serial=serial, timeout=300.0)


def install(apk: Path, serial: str | None = None, reinstall: bool = True) -> str:
    """Install an APK, returning adb's output."""
    serial = resolve_serial(serial)
    if not Path(apk).is_file():
        raise EngineError("device", f"APK not found: {apk}")
    args = ["install"]
    if reinstall:
        args.append("-r")
    args.append(str(apk))
    return _adb(args, serial=serial, timeout=600.0).stdout.strip()


def reverse(remote_port: int, local_port: int, serial: str | None = None) -> None:
    """Set up ``adb reverse`` so the device can reach a host-side service.

    ``tcp:remote_port`` on the device forwards to ``tcp:local_port`` on the host.
    """
    serial = resolve_serial(serial)
    _adb(["reverse", f"tcp:{remote_port}", f"tcp:{local_port}"], serial=serial)


def set_global_http_proxy(host_port: str, serial: str | None = None) -> None:
    """Configure the device-wide HTTP proxy (``host:port`` or ``:0`` to clear)."""
    serial = resolve_serial(serial)
    _adb(["shell", "settings", "put", "global", "http_proxy", host_port], serial=serial)


def clear_global_http_proxy(serial: str | None = None) -> None:
    """Remove the device-wide HTTP proxy setting."""
    set_global_http_proxy(":0", serial=serial)
