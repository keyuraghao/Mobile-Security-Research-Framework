"""Discover and read MobSF's bundled Frida instrumentation scripts.

MobSF ships a large, maintained library of Frida scripts (API monitor, SSL/root/
debugger/jailbreak bypasses, crypto and keychain dumps, activity/deeplink traces,
and much more) for both Android and iOS. Rather than reimplement them, msrf
exposes them directly through the hooks engine. Located via the installed ``mobsf``
package (works in the standalone bundle, which collects the package data).
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any


@lru_cache(maxsize=1)
def scripts_dir() -> Path | None:
    """Return MobSF's ``frida_scripts`` directory, or None if unavailable."""
    try:
        import mobsf

        base = Path(os.path.dirname(mobsf.__file__))
        d = base / "DynamicAnalyzer" / "tools" / "frida_scripts"
        return d if d.is_dir() else None
    except Exception:
        return None


def list_scripts(platform: str | None = None) -> list[dict[str, Any]]:
    """List all bundled MobSF Frida scripts.

    Each entry: ``{name, platform, category, id, path}`` where ``id`` is the
    stable ``<platform>/<category>/<name>`` used to select a script.
    """
    root = scripts_dir()
    if not root:
        return []
    out: list[dict[str, Any]] = []
    for plat_dir in sorted(root.iterdir()):
        if not plat_dir.is_dir() or plat_dir.name not in ("android", "ios"):
            continue
        if platform and plat_dir.name != platform:
            continue
        for cat_dir in sorted(plat_dir.iterdir()):
            if not cat_dir.is_dir():
                continue
            for js in sorted(cat_dir.glob("*.js")):
                name = js.stem
                out.append(
                    {
                        "name": name,
                        "platform": plat_dir.name,
                        "category": cat_dir.name,
                        "id": f"{plat_dir.name}/{cat_dir.name}/{name}",
                        "path": str(js),
                    }
                )
    return out


def read_script(script_id: str) -> str:
    """Return the JS source of a script by its ``<platform>/<category>/<name>`` id."""
    root = scripts_dir()
    if not root:
        raise FileNotFoundError("MobSF frida scripts are not available.")
    # Guard against traversal: id must be exactly platform/category/name.
    parts = script_id.split("/")
    if len(parts) != 3 or any(p in ("", "..", ".") for p in parts):
        raise ValueError(f"Invalid script id: {script_id!r}")
    target = (root / parts[0] / parts[1] / f"{parts[2]}.js").resolve()
    if not target.is_relative_to(root.resolve()) or not target.is_file():
        raise FileNotFoundError(f"Script not found: {script_id}")
    return target.read_text(encoding="utf-8", errors="replace")
