"""Findings engine: a single store for all results across the assessment.

Aggregates findings from the tool's analyses (e.g. static analysis) and lets the
user add their own manual findings. Persisted as JSON in the workspace so the
findings survive restarts and can be exported. Exposed on the CLI, the GUI
Findings tab, and the MCP server like every other engine.
"""
from __future__ import annotations

import contextlib
import json
import time
import uuid
from pathlib import Path
from typing import Any

from ..config import Config
from ..registry import register
from .base import Engine, action

_SEVERITIES = ("high", "warning", "info", "secure", "hotspot", "note")


@register
class FindingsEngine(Engine):
    """Store, add and manage assessment findings."""

    name = "findings"
    summary = "Central store of all findings; add your own or import from scans."

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._path = config.workspace / "findings" / "findings.json"

    def preflight(self) -> dict[str, Any]:
        return {
            "engine": self.name,
            "ready": True,
            "details": {"store": str(self._path), "count": len(self._load())},
        }

    # -- persistence -----------------------------------------------------

    def _load(self) -> list[dict[str, Any]]:
        if not self._path.is_file():
            return []
        try:
            data = json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            # Never silently start from empty and let the next save overwrite a
            # damaged store: move the bad file aside so its data is preserved.
            import time

            backup = self._path.with_name(f"findings.corrupt-{int(time.time())}.json")
            with contextlib.suppress(OSError):
                self._path.rename(backup)
            self.log.warning("findings store was unreadable (%s); backed up to %s", exc, backup)
            return []
        return data if isinstance(data, list) else []

    def _save(self, items: list[dict[str, Any]]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(items, indent=2, default=str))

    # -- actions ---------------------------------------------------------

    @action("List all stored findings.")
    def list(self) -> dict[str, Any]:
        return {"findings": self._load()}

    @action("Add a finding to the store.", mutating=True)
    def add(
        self,
        title: str,
        severity: str = "info",
        description: str = "",
        source: str = "manual",
        target: str = "",
    ) -> dict[str, Any]:
        """Add a finding. ``severity`` is one of high/warning/info/secure/hotspot/note."""
        severity = severity if severity in _SEVERITIES else "info"
        item = {
            "id": uuid.uuid4().hex[:12],
            "title": title,
            "severity": severity,
            "description": description,
            "source": source,
            "target": target,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        items = self._load()
        items.append(item)
        self._save(items)
        return item

    @action("Delete a finding by id.", mutating=True)
    def delete(self, finding_id: str) -> dict[str, Any]:
        items = self._load()
        kept = [f for f in items if f.get("id") != finding_id]
        self._save(kept)
        return {"deleted": len(items) - len(kept), "id": finding_id}

    @action("Delete all findings.", mutating=True)
    def clear(self) -> dict[str, Any]:
        self._save([])
        return {"cleared": True}

    @action("Import findings from a cached static-analysis scan into the store.", mutating=True)
    def import_scan(self, scan_hash: str) -> dict[str, Any]:
        """Pull a SAST scan's findings (high/warning/info) into the store, deduped."""
        report_path = self.config.reports_dir / f"{scan_hash}.json"
        if not report_path.is_file():
            return {"imported": 0, "reason": "no cached report"}
        report = json.loads(report_path.read_text())
        appsec = report.get("appsec") or {}
        target = report.get("file_name") or scan_hash
        items = self._load()
        seen = {(f.get("source"), f.get("title"), f.get("target")) for f in items}
        imported = 0
        for severity in ("high", "warning", "info"):
            for it in appsec.get(severity, []) or []:
                title = it.get("title", "")
                key = ("sast", title, target)
                if key in seen:
                    continue
                items.append(
                    {
                        "id": uuid.uuid4().hex[:12],
                        "title": title,
                        "severity": severity,
                        "description": it.get("description", ""),
                        "source": "sast",
                        "target": target,
                        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
                seen.add(key)
                imported += 1
        self._save(items)
        return {"imported": imported, "total": len(items)}

    @action("List the report formats the reporting system can generate.")
    def report_formats(self) -> dict[str, Any]:
        from .. import reporting

        return {"formats": list(reporting.FORMATS)}

    @action("Generate a report of all findings in a chosen format.")
    def report(self, format: str = "pdf", out_path: str | None = None) -> dict[str, Any]:
        """Render all findings to a report file.

        Args:
            format: One of json, csv, md, html, xlsx, pdf.
            out_path: Optional output path; defaults to the reports workspace.
        """
        from .. import get_version, reporting

        target = (
            Path(out_path).expanduser()
            if out_path
            else self.config.reports_dir / f"msrf-report.{format.lower()}"
        )
        path = reporting.generate(
            self._load(),
            format,
            target,
            meta={"tool_version": get_version()},
        )
        return {"report": str(path), "format": format.lower(), "count": len(self._load())}
