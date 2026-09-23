"""App-data engine: grab and open the databases a mobile app writes at runtime.

A running app stores data under ``/data/data/<package>/`` (SQLite databases,
``shared_prefs`` XML, files, caches). This engine pulls those files off the
target and parses them so they can be inspected:

* ``--device-id sim`` (the built-in simulator / emulator): materialises a set of
  realistic sample data files (a DIVA-style insecure SQLite DB + shared_prefs)
  so the grab/parse/open workflow works with nothing external attached.
* a real device serial: pulls the app's data via ``adb exec-out run-as`` (for a
  debuggable app) so no root is required.

Parsing is handled by :mod:`msrf.dbtools` (read-only SQLite, shared_prefs XML,
generic fallback).
"""
from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from .. import dbtools
from .. import device as dev
from ..config import Config
from ..exceptions import EngineError
from ..platform_utils import require_tool, run, which
from ..registry import register
from ..sim import SIM_DEVICE_ID
from .base import Engine, action

_DB_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".db3", ".realm")


@register
class AppDataEngine(Engine):
    """Grab and open an app's on-device databases and stored files."""

    name = "appdata"
    summary = "Pull and open a running app's databases (SQLite), shared_prefs and files."

    def __init__(self, config: Config) -> None:
        super().__init__(config)

    def preflight(self) -> dict[str, Any]:
        return {
            "engine": self.name,
            "ready": True,  # sim path always works; adb enables real devices
            "details": {"adb": which("adb"), "simulator": True},
        }

    # -- storage locations ----------------------------------------------

    def _pkg_dir(self, package: str) -> Path:
        return self.config.workspace / "appdata" / package

    # -- pulling ---------------------------------------------------------

    @action(
        "Grab an app's data files (databases, shared_prefs) from the target.",
        mutating=True,
    )
    def pull(self, package: str, device_id: str = SIM_DEVICE_ID) -> dict[str, Any]:
        """Pull ``package``'s data files and return the local file list.

        Args:
            package: Application id, e.g. ``jakhar.aseem.diva``.
            device_id: ``sim`` for the built-in emulator sample data, or an adb
                device serial for a real device (uses ``run-as``).
        """
        dest = self._pkg_dir(package)
        dest.mkdir(parents=True, exist_ok=True)
        if device_id == SIM_DEVICE_ID:
            files = self._materialise_sample(package, dest)
            source = "simulator"
        else:
            files = self._pull_real(package, device_id, dest)
            source = device_id
        return {"package": package, "source": source, "dir": str(dest), "files": files}

    def _pull_real(self, package: str, serial: str, dest: Path) -> list[str]:
        adb = require_tool("adb", hint="Install Android platform-tools.")
        serial = dev.resolve_serial(serial)
        # List regular files under the app's data dir via run-as (debuggable app).
        listing = run(
            [adb, "-s", serial, "exec-out", "run-as", package, "find", ".", "-type", "f"],
            check=False,
        )
        if listing.returncode != 0:
            raise EngineError(
                "appdata",
                "Could not access app data via run-as. The app must be debuggable, "
                "or use a rooted device. adb said: " + (listing.stderr.strip() or "?"),
            )
        pulled: list[str] = []
        for rel in listing.stdout.splitlines():
            rel = rel.strip().lstrip("./")
            if not rel:
                continue
            low = rel.lower()
            if not (low.endswith(_DB_SUFFIXES) or "/databases/" in low or "shared_prefs" in low):
                continue
            local = dest / rel
            local.parent.mkdir(parents=True, exist_ok=True)
            # Binary-safe: capture raw bytes so SQLite files are not corrupted.
            proc = subprocess.run(  # noqa: S603 - argv list, shell=False
                [adb, "-s", serial, "exec-out", "run-as", package, "cat", rel],
                capture_output=True,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                local.write_bytes(proc.stdout)
                pulled.append(rel)
        return pulled

    def _materialise_sample(self, package: str, dest: Path) -> list[str]:
        """Create realistic sample data files for the simulator target."""
        files: list[str] = []

        db_dir = dest / "databases"
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = db_dir / "ids2.db"
        if db_path.exists():
            db_path.unlink()
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("CREATE TABLE myuser (user TEXT, password TEXT)")
            conn.executemany(
                "INSERT INTO myuser VALUES (?, ?)",
                [("admin", "p@ssw0rd123"), ("diva", "s3cr3t"), ("guest", "guest")],
            )
            conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
            conn.executemany(
                "INSERT INTO notes (title, body) VALUES (?, ?)",
                [("api-key", "AKIA_EXAMPLE_1234567890"), ("pin", "4869")],
            )
            conn.commit()
        finally:
            conn.close()
        files.append("databases/ids2.db")

        sp_dir = dest / "shared_prefs"
        sp_dir.mkdir(parents=True, exist_ok=True)
        sp = sp_dir / f"{package}_preferences.xml"
        sp.write_text(
            '<?xml version="1.0" encoding="utf-8" standalone="yes" ?>\n'
            "<map>\n"
            '    <string name="user">admin</string>\n'
            '    <string name="password">p@ssw0rd123</string>\n'
            '    <boolean name="remember_me" value="true" />\n'
            '    <string name="auth_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo</string>\n'
            "</map>\n"
        )
        files.append(f"shared_prefs/{package}_preferences.xml")
        return files

    # -- listing / parsing ----------------------------------------------

    @action("List the data files already pulled for an app.")
    def databases(self, package: str) -> dict[str, Any]:
        base = self._pkg_dir(package)
        if not base.is_dir():
            return {"package": package, "files": []}
        out = []
        for p in sorted(base.rglob("*")):
            if p.is_file():
                out.append(
                    {"path": str(p), "rel": str(p.relative_to(base)), "type": _safe_type(p)}
                )
        return {"package": package, "dir": str(base), "files": out}

    @action("Open a pulled data file and describe it (SQLite tables, XML, ...).")
    def open(self, path: str) -> dict[str, Any]:
        return dbtools.open_file(self._checked(path))

    @action("List the tables of a pulled SQLite database.")
    def tables(self, path: str) -> dict[str, Any]:
        return {"path": path, "tables": dbtools.sqlite_tables(self._checked(path))}

    @action("Read rows from a table of a pulled SQLite database.")
    def rows(self, path: str, table: str, limit: int = 500, offset: int = 0) -> dict[str, Any]:
        return dbtools.sqlite_rows(self._checked(path), table, limit=limit, offset=offset)

    def _checked(self, path: str) -> Path:
        """Resolve a path and ensure it stays within the appdata workspace."""
        base = (self.config.workspace / "appdata").resolve()
        target = Path(path).expanduser().resolve()
        if not target.is_relative_to(base):
            raise EngineError("appdata", "Path is outside the app-data workspace.")
        if not target.is_file():
            raise EngineError("appdata", f"File not found: {path}")
        return target


def _safe_type(p: Path) -> str:
    try:
        return dbtools.detect_type(p)
    except Exception:
        return "unknown"
