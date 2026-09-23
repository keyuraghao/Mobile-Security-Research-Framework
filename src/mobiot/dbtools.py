"""Parse and open mobile app data files pulled off a device.

Supports the file types a mobile app commonly writes under its data directory:
SQLite databases (``.db`` / ``.sqlite`` / no-extension), Android
``shared_prefs`` XML, and a generic fallback (text or hex preview) for anything
else (Realm, LevelDB, protobuf, ...).

SQLite access is strictly read-only (``mode=ro``) and table names are validated
against the database's own catalogue before use, so a crafted file cannot cause
arbitrary SQL to run.
"""
from __future__ import annotations

import sqlite3
import xml.etree.ElementTree as ET  # noqa: S405 - parsing our own pulled files
from pathlib import Path
from typing import Any

from .exceptions import EngineError

_SQLITE_MAGIC = b"SQLite format 3\x00"


def detect_type(path: str | Path) -> str:
    """Return one of ``sqlite``, ``xml``, ``realm``, ``text`` or ``binary``."""
    p = Path(path)
    try:
        head = p.open("rb").read(16)
    except OSError as exc:
        raise EngineError("appdata", f"Cannot read {p}: {exc}") from exc
    if head.startswith(_SQLITE_MAGIC):
        return "sqlite"
    if head[:4] == b"REAL" or p.suffix == ".realm":
        return "realm"
    stripped = head.lstrip()
    if stripped[:5] == b"<?xml" or p.suffix == ".xml":
        return "xml"
    if _is_probably_text(head):
        return "text"
    return "binary"


def _is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    printable = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(data) > 0.85


def _connect_ro(path: Path) -> sqlite3.Connection:
    try:
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise EngineError("appdata", f"Cannot open SQLite db {path}: {exc}") from exc


def sqlite_tables(path: str | Path) -> list[dict[str, Any]]:
    """Return the database's tables and views with row counts."""
    p = Path(path)
    conn = _connect_ro(p)
    try:
        cur = conn.execute(
            "SELECT name, type FROM sqlite_master "
            "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name"
        )
        result = []
        for name, kind in cur.fetchall():
            try:
                # name comes from sqlite_master and is double-quoted; not user input.
                count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]  # noqa: S608
            except sqlite3.Error:
                count = None
            result.append({"name": name, "type": kind, "rows": count})
        return result
    finally:
        conn.close()


def sqlite_rows(
    path: str | Path, table: str, limit: int = 500, offset: int = 0
) -> dict[str, Any]:
    """Return ``columns`` and ``rows`` for ``table`` (validated, read-only)."""
    p = Path(path)
    conn = _connect_ro(p)
    try:
        valid = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
            ).fetchall()
        }
        if table not in valid:
            raise EngineError("appdata", f"No such table {table!r} in database.")
        # table validated against the catalogue above and double-quoted.
        cur = conn.execute(f'SELECT * FROM "{table}" LIMIT ? OFFSET ?', (limit, offset))  # noqa: S608
        columns = [d[0] for d in cur.description]
        rows = [[_cell(v) for v in row] for row in cur.fetchall()]
        return {"table": table, "columns": columns, "rows": rows, "count": len(rows)}
    finally:
        conn.close()


def _cell(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex() if len(value) <= 64 else value[:64].hex() + "…"
    return value


def parse_shared_prefs(path: str | Path) -> dict[str, Any]:
    """Parse an Android ``shared_prefs`` XML file into key/value/type rows."""
    p = Path(path)
    try:
        tree = ET.parse(p)  # noqa: S314 - our own pulled file
    except ET.ParseError as exc:
        raise EngineError("appdata", f"Invalid shared_prefs XML {p}: {exc}") from exc
    rows = []
    for el in tree.getroot():
        key = el.get("name", "")
        if el.tag == "string":
            value, vtype = (el.text or ""), "string"
        else:
            value = el.get("value", el.text or "")
            vtype = el.tag
        rows.append({"key": key, "type": vtype, "value": value})
    return {"entries": rows}


def open_file(path: str | Path) -> dict[str, Any]:
    """Open any pulled data file and return a structured view of its content."""
    p = Path(path)
    kind = detect_type(p)
    info: dict[str, Any] = {"path": str(p), "type": kind, "size": p.stat().st_size}
    if kind == "sqlite":
        info["tables"] = sqlite_tables(p)
    elif kind == "xml":
        info.update(parse_shared_prefs(p))
    elif kind == "text":
        info["content"] = p.read_text(errors="replace")[:200000]
    else:
        info["preview_hex"] = p.read_bytes()[:512].hex()
    return info
