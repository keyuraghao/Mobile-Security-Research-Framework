"""Thin REST client for a running MobSF server.

Covers the MobSF v1 REST API surface mobiot needs for static and dynamic
analysis. Transport is :mod:`httpx`; all methods raise :class:`EngineError`
with a useful message on HTTP or transport failure.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from .exceptions import EngineError


class MobSFClient:
    """Client for the MobSF REST API.

    Args:
        base_url: e.g. ``http://127.0.0.1:8000``.
        api_key: MobSF REST API key (from server startup or config).
        timeout: Per-request timeout in seconds.
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 300.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": api_key},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> MobSFClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internal --------------------------------------------------------

    def _post(self, path: str, **kwargs: Any) -> httpx.Response:
        try:
            resp = self._client.post(path, **kwargs)
            resp.raise_for_status()
            return resp
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500]
            raise EngineError(
                "sast", f"MobSF {path} failed ({exc.response.status_code}): {body}"
            ) from exc
        except httpx.HTTPError as exc:
            raise EngineError("sast", f"MobSF {path} request error: {exc}") from exc

    def _get(self, path: str, **kwargs: Any) -> httpx.Response:
        try:
            resp = self._client.get(path, **kwargs)
            resp.raise_for_status()
            return resp
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500]
            raise EngineError(
                "sast", f"MobSF {path} failed ({exc.response.status_code}): {body}"
            ) from exc
        except httpx.HTTPError as exc:
            raise EngineError("sast", f"MobSF {path} request error: {exc}") from exc

    # -- API surface -----------------------------------------------------

    def ping(self) -> bool:
        """Return True if the server responds (used for readiness checks)."""
        try:
            self._client.get("/", timeout=5.0)
            return True
        except httpx.HTTPError:
            return False

    def upload(self, file_path: Path) -> dict[str, Any]:
        """Upload an APK/IPA/APPX/ZIP; returns ``{hash, scan_type, file_name}``."""
        path = Path(file_path)
        if not path.is_file():
            raise EngineError("sast", f"File not found: {path}")
        with path.open("rb") as handle:
            files = {"file": (path.name, handle, "application/octet-stream")}
            resp = self._post("/api/v1/upload", files=files)
        return resp.json()

    def scan(self, scan_hash: str, *, re_scan: bool = False) -> dict[str, Any]:
        """Trigger (or re-trigger) a static scan for a previously uploaded file."""
        data = {"hash": scan_hash, "re_scan": "1" if re_scan else "0"}
        return self._post("/api/v1/scan", data=data).json()

    def report_json(self, scan_hash: str) -> dict[str, Any]:
        """Return the full JSON report for a scan."""
        return self._post("/api/v1/report_json", data={"hash": scan_hash}).json()

    def scorecard(self, scan_hash: str) -> dict[str, Any]:
        """Return the app security scorecard for a scan."""
        return self._post("/api/v1/scorecard", data={"hash": scan_hash}).json()

    def download_pdf(self, scan_hash: str, out_path: Path) -> Path:
        """Download the PDF report to ``out_path`` and return it.

        MobSF renders PDFs with ``wkhtmltopdf``; when that system tool is
        missing it returns a JSON error instead of PDF bytes. We detect that and
        raise a clear, actionable :class:`EngineError` rather than writing a
        broken file.
        """
        resp = self._post("/api/v1/download_pdf", data={"hash": scan_hash})
        content_type = resp.headers.get("content-type", "")
        if "application/pdf" not in content_type:
            detail = resp.text[:300]
            hint = ""
            if "wkhtmltopdf" in detail.lower():
                hint = (
                    " Install wkhtmltopdf (e.g. 'apt install wkhtmltopdf' / "
                    "'brew install wkhtmltopdf') to enable PDF reports; JSON and "
                    "scorecard reports work without it."
                )
            raise EngineError("sast", f"PDF generation failed: {detail}.{hint}")
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(resp.content)
        return out_path

    def recent_scans(self, page: int = 1, page_size: int = 25) -> dict[str, Any]:
        """List recent scans."""
        return self._get(
            "/api/v1/scans", params={"page": page, "page_size": page_size}
        ).json()

    def delete_scan(self, scan_hash: str) -> dict[str, Any]:
        """Delete a scan and its artefacts from the server."""
        return self._post("/api/v1/delete_scan", data={"hash": scan_hash}).json()

    # -- dynamic analysis (Android) --------------------------------------

    def dynamic_get_apps(self) -> dict[str, Any]:
        """List APKs available for dynamic analysis."""
        return self._get("/api/v1/dynamic/get_apps").json()

    def dynamic_start(self, scan_hash: str) -> dict[str, Any]:
        """Start a dynamic-analysis session for the given app hash."""
        return self._post(
            "/api/v1/dynamic/start_analysis", data={"hash": scan_hash}
        ).json()

    def dynamic_stop(self, scan_hash: str) -> dict[str, Any]:
        """Stop the running dynamic-analysis session."""
        return self._post(
            "/api/v1/dynamic/stop_analysis", data={"hash": scan_hash}
        ).json()

    def dynamic_report_json(self, scan_hash: str) -> dict[str, Any]:
        """Return the dynamic-analysis JSON report."""
        return self._post(
            "/api/v1/dynamic/report_json", data={"hash": scan_hash}
        ).json()
