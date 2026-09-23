"""Workflow engine: one-step, guided assessments that chain several engines.

Inspired by Core Impact's Rapid Penetration Test (RPT) "one-step" wizards: a
single action runs an ordered pipeline and ends with a report, so a whole
assessment is one call. Because every ``@action`` is exposed on the CLI, the
GUI and the MCP server, an AI client can drive these end-to-end too.
"""
from __future__ import annotations

from typing import Any

from ..config import Config
from ..exceptions import EngineError
from ..registry import get_engine, register
from .base import Engine, action


@register
class WorkflowEngine(Engine):
    """One-step, multi-engine assessment pipelines."""

    name = "workflow"
    summary = "One-step guided assessments (scan, collect findings, report) across engines."

    def __init__(self, config: Config) -> None:
        super().__init__(config)

    def _eng(self, name: str):
        return get_engine(name, self.config)

    @action(
        "One-step static assessment: scan an app, collect its findings, and generate a report.",
        mutating=True,
    )
    def static_assessment(
        self, app_path: str, report_format: str = "pdf"
    ) -> dict[str, Any]:
        """Run the full static pipeline for ``app_path`` and return a summary.

        Steps, in order (each feeds the next): MobSF static scan -> load the
        report -> import its findings into the findings store -> render a report
        in ``report_format`` (pdf, html, xlsx, csv, json, md).
        """
        sast = self._eng("sast")
        findings = self._eng("findings")
        steps: list[dict[str, Any]] = []

        scan = sast.scan(app_path)
        scan_hash = scan.get("hash")
        steps.append({"step": "scan", "hash": scan_hash, "file": scan.get("file_name")})
        if not scan_hash:
            raise EngineError("workflow", "Static scan did not return a hash.")

        report = sast.report(scan_hash)
        appsec = report.get("appsec") or {}
        steps.append({"step": "report_loaded", "security_score": appsec.get("security_score")})

        imported = findings.import_scan(scan_hash)
        steps.append({"step": "import_findings", "imported": imported.get("imported", 0)})

        rendered = findings.report(format=report_format)
        steps.append({"step": "report", "path": rendered.get("report")})

        return {
            "assessment": "static",
            "app": scan.get("file_name") or app_path,
            "scan_hash": scan_hash,
            "security_score": appsec.get("security_score"),
            "high": len(appsec.get("high", []) or []),
            "warning": len(appsec.get("warning", []) or []),
            "info": len(appsec.get("info", []) or []),
            "findings_imported": imported.get("imported", 0),
            "report": rendered.get("report"),
            "format": report_format,
            "steps": steps,
        }

    @action(
        "One-step dynamic smoke test: run key Frida checks against an app on the simulator.",
        mutating=True,
    )
    def dynamic_smoke(
        self, package: str = "jakhar.aseem.diva", device_id: str = "sim"
    ) -> dict[str, Any]:
        """Run a small, safe set of inbuilt hooks against ``package``.

        Uses the built-in simulator by default (``device_id="sim"``), so it needs
        no device. Returns each hook's load status and message count.
        """
        hooks = self._eng("hooks")
        checks = ["ssl-pinning-bypass", "root-bypass", "crypto-monitor"]
        results = []
        for name in checks:
            try:
                res = hooks.test(template=name, package=package, device_id=device_id)
                results.append({
                    "hook": name, "loaded": res.get("loaded"),
                    "messages": res.get("message_count"),
                })
            except Exception as exc:  # keep going; report per-hook failures
                results.append({"hook": name, "error": str(exc)})
        return {"assessment": "dynamic_smoke", "package": package,
                "device": device_id, "checks": results}

    @action("List the one-step assessments this engine can run.")
    def list_assessments(self) -> dict[str, Any]:
        return {
            "assessments": [
                {"name": "static_assessment",
                 "does": "scan an app, collect findings, generate a report"},
                {"name": "dynamic_smoke",
                 "does": "run key Frida checks on the simulator or a device"},
            ]
        }
