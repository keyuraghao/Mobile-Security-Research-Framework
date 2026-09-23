"""Resolve and activate tools bundled inside a standalone build.

A standalone msrf build ships its heavy dependencies inside the executable
(under a ``vendor/`` tree): a Java runtime, jadx, Android platform-tools (adb),
and frida-server binaries. At startup :func:`activate` points the environment and
config at those bundled copies so no engine ever downloads or requires anything
external.

Layout of the bundled ``vendor/`` tree (populated per-OS by the release build)::

    vendor/jre/                      # a full JRE; its bin/ holds java
    vendor/jadx/bin/jadx[.bat]       # jadx launcher (uses the bundled JRE)
    vendor/platform-tools/adb[.exe]  # Android platform-tools
    vendor/frida-server/frida-server-<ver>-android-<arch>   # device binaries

When not frozen, ``MSRF_VENDOR_DIR`` may point at a vendor tree for testing.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .logging import get_logger
from .platform_utils import IS_WINDOWS

log = get_logger("bundled")


def is_frozen() -> bool:
    """True when running from a PyInstaller (or similar) standalone build."""
    return bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")


def vendor_root() -> Path | None:
    """Return the bundled ``vendor/`` directory, or None if there is none.

    Resolution order: an explicit ``MSRF_VENDOR_DIR`` (for testing), then the
    PyInstaller extraction dir (``sys._MEIPASS/vendor``), then a ``vendor/``
    folder next to the executable.
    """
    env = os.environ.get("MSRF_VENDOR_DIR")
    if env:
        p = Path(env)
        return p if p.is_dir() else None
    if is_frozen():
        meipass = Path(sys._MEIPASS) / "vendor"  # type: ignore[attr-defined]
        if meipass.is_dir():
            return meipass
        beside = Path(sys.executable).parent / "vendor"
        if beside.is_dir():
            return beside
    return None


def _exe(name: str) -> str:
    return f"{name}.exe" if IS_WINDOWS else name


def java_home(root: Path) -> Path | None:
    jre = root / "jre"
    return jre if (jre / "bin" / _exe("java")).is_file() else None


def jadx_binary(root: Path) -> Path | None:
    launcher = "jadx.bat" if IS_WINDOWS else "jadx"
    candidate = root / "jadx" / "bin" / launcher
    return candidate if candidate.is_file() else None


def adb_binary(root: Path) -> Path | None:
    candidate = root / "platform-tools" / _exe("adb")
    return candidate if candidate.is_file() else None


def frida_server_dir(root: Path) -> Path | None:
    d = root / "frida-server"
    return d if d.is_dir() else None


def _prepend_path(*dirs: Path) -> None:
    parts = [str(d) for d in dirs if d and d.is_dir()]
    if not parts:
        return
    existing = os.environ.get("PATH", "")
    os.environ["PATH"] = os.pathsep.join([*parts, existing]) if existing else os.pathsep.join(parts)


def activate(config) -> dict[str, object]:
    """Wire the environment and ``config`` to the bundled tools.

    Idempotent. Returns a report of what was activated (useful for diagnostics
    and the GUI dashboard). Safe to call when nothing is bundled: it no-ops.
    """
    root = vendor_root()
    report: dict[str, object] = {
        "bundled": root is not None,
        "vendor_root": str(root) if root else None,
    }
    if root is None:
        return report

    # Java runtime -> JAVA_HOME + PATH (MobSF and jadx need it).
    jh = java_home(root)
    if jh:
        os.environ["JAVA_HOME"] = str(jh)
        os.environ["MOBSF_JAVA_DIRECTORY"] = str(jh / "bin")
        _prepend_path(jh / "bin")
        report["java_home"] = str(jh)

    # jadx -> PATH + MobSF setting (skips MobSF's runtime download).
    jadx = jadx_binary(root)
    if jadx:
        _prepend_path(jadx.parent)
        os.environ.setdefault("MOBSF_JADX_BINARY", str(jadx))
        config.mobsf.use_system_jadx = True
        report["jadx"] = str(jadx)

    # adb -> PATH.
    adb = adb_binary(root)
    if adb:
        _prepend_path(adb.parent)
        report["adb"] = str(adb)

    # frida-server binaries -> config.frida.server_dir (skips downloads).
    fsd = frida_server_dir(root)
    if fsd:
        config.frida.server_dir = fsd
        report["frida_server_dir"] = str(fsd)

    log.info("Activated bundled tools: %s", report)
    return report
