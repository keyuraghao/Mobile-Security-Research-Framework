"""SAST engine — static analysis via MobSF.

Manages a native MobSF server (start/stop/status) in the shared virtualenv and
drives the MobSF REST API to upload apps, run static scans and fetch reports.
The server is launched with a deterministic API key and a workspace-scoped
``MOBSF_HOME_DIR`` so runs are reproducible and self-contained.
"""
from __future__ import annotations

import contextlib
import os
import secrets
import time
from pathlib import Path
from typing import Any

from ..config import Config
from ..exceptions import EngineError
from ..mobsf_client import MobSFClient
from ..platform_utils import spawn, which
from ..registry import register
from .base import Engine, action

try:  # psutil ships as a MobSF dependency; degrade gracefully if absent.
    import psutil
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]


class MobSFServer:
    """Lifecycle manager for a native MobSF server process."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.mobsf = config.mobsf
        self._pid_file = config.logs_dir / "mobsf.pid"
        self._log_file = config.logs_dir / "mobsf.log"
        self._key_file = config.workspace / "mobsf_api_key"
        self._secret_file = config.workspace / "mobsf_secret_key"
        self._home_dir = config.workspace / "mobsf_home"

    # -- api key persistence ---------------------------------------------

    def api_key(self) -> str:
        """Return the API key, generating and persisting one if needed."""
        if self.mobsf.api_key:
            return self.mobsf.api_key
        if self._key_file.is_file():
            return self._key_file.read_text().strip()
        key = secrets.token_hex(32)
        self.config.ensure_dirs()
        self._key_file.write_text(key)
        return key

    def secret_key(self) -> str:
        """Return the Django secret key, generating and persisting if needed.

        Setting ``MOBSF_SECRET_KEY`` short-circuits MobSF's first-run block —
        the code path that otherwise downloads JADX from GitHub and can hang.
        """
        if self.mobsf.secret_key:
            return self.mobsf.secret_key
        if self._secret_file.is_file():
            return self._secret_file.read_text().strip()
        key = secrets.token_urlsafe(48)
        self.config.ensure_dirs()
        self._secret_file.write_text(key)
        return key

    # -- offline / slim profile ------------------------------------------

    def _build_env(self) -> dict[str, str]:
        """Build the MobSF launch environment (offline profile when enabled)."""
        self._home_dir.mkdir(parents=True, exist_ok=True)
        env: dict[str, str] = {
            "MOBSF_API_KEY": self.api_key(),
            "MOBSF_HOME_DIR": str(self._home_dir),
        }
        if not self.mobsf.offline_profile:
            return env

        # Fast, download-free, headless-REST profile (see deep-dive findings).
        env["MOBSF_SECRET_KEY"] = self.secret_key()
        env["MOBSF_API_ONLY"] = "1" if self.mobsf.api_only else "0"
        env["MOBSF_DISABLE_AUTHENTICATION"] = (
            "1" if self.mobsf.disable_authentication else "0"
        )
        env["MOBSF_ASYNC_ANALYSIS"] = "1" if self.mobsf.async_analysis else "0"
        env["MOBSF_DOMAIN_MALWARE_SCAN"] = "1" if self.mobsf.domain_malware_scan else "0"
        env["MOBSF_VT_ENABLED"] = "1" if self.mobsf.vt_enabled else ""
        env["MOBSF_DEBUG"] = "0"
        env["MOBSF_RATELIMIT"] = "1000/m"

        if self.mobsf.use_system_jadx:
            jadx = which("jadx")
            if jadx:
                env["MOBSF_JADX_BINARY"] = jadx
        return env

    def _prepare_home(self) -> None:
        """Pre-launch prep so the offline profile actually takes effect.

        * Delete the generated ``config.py`` — once present it shadows the
          env-driven defaults, so we remove it to guarantee our env wins.
        * Belt-and-suspenders: satisfy MobSF's expected JADX path with a link to
          the system binary so the download is never attempted (POSIX only).
        """
        if not self.mobsf.offline_profile:
            return
        self._home_dir.mkdir(parents=True, exist_ok=True)
        (self._home_dir / "config.py").unlink(missing_ok=True)

        if self.mobsf.use_system_jadx:
            jadx = which("jadx")
            if jadx and os.name != "nt":
                jadx_dir = self._home_dir / "tools" / "jadx" / "jadx-1.5.0" / "bin"
                jadx_dir.mkdir(parents=True, exist_ok=True)
                link = jadx_dir / "jadx"
                with contextlib.suppress(OSError):
                    if link.is_symlink() or link.exists():
                        link.unlink()
                    link.symlink_to(jadx)

    # -- process management ----------------------------------------------

    def _read_pid(self) -> int | None:
        if not self._pid_file.is_file():
            return None
        try:
            return int(self._pid_file.read_text().strip())
        except ValueError:
            return None

    def is_running(self) -> bool:
        pid = self._read_pid()
        if pid is None:
            return False
        if psutil is not None:
            return psutil.pid_exists(pid)
        try:  # POSIX fallback
            import os

            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _launch_command(self, listen: str) -> list[str]:
        entry = which("mobsf")
        if entry:
            return [entry, listen]
        # Fallback: run the module with the current interpreter.
        import sys

        return [sys.executable, "-m", "mobsf", listen]

    def start(self, wait: bool = True) -> dict[str, Any]:
        """Start the MobSF server if not already running."""
        self.config.ensure_dirs()
        client = self.client()
        if client.ping():
            return {"started": False, "already_running": True, "url": self.mobsf.url}

        self._prepare_home()
        listen = f"{self.mobsf.host}:{self.mobsf.port}"
        env = self._build_env()
        proc = spawn(
            self._launch_command(listen),
            cwd=self.mobsf.home or None,
            env=env,
            stdout=self._log_file,
        )
        self._pid_file.write_text(str(proc.pid))

        if not wait:
            return {"started": True, "pid": proc.pid, "url": self.mobsf.url}

        deadline = time.time() + self.mobsf.startup_timeout
        while time.time() < deadline:
            if client.ping():
                return {"started": True, "pid": proc.pid, "url": self.mobsf.url}
            if proc.poll() is not None:
                tail = self._log_file.read_text()[-1500:] if self._log_file.is_file() else ""
                raise EngineError(
                    "sast",
                    f"MobSF exited during startup (code {proc.returncode}).\n{tail}",
                )
            time.sleep(1.5)
        raise EngineError(
            "sast",
            f"MobSF did not become ready within {self.mobsf.startup_timeout}s. "
            f"See log: {self._log_file}",
        )

    def stop(self) -> dict[str, Any]:
        """Stop the MobSF server process (and children)."""
        pid = self._read_pid()
        if pid is None or not self.is_running():
            self._pid_file.unlink(missing_ok=True)
            return {"stopped": False, "reason": "not running"}
        if psutil is not None:
            try:
                proc = psutil.Process(pid)
                for child in proc.children(recursive=True):
                    child.terminate()
                proc.terminate()
                _, alive = psutil.wait_procs([proc], timeout=10)
                for p in alive:
                    p.kill()
            except psutil.NoSuchProcess:
                pass
        else:  # pragma: no cover - POSIX fallback
            import contextlib
            import os
            import signal

            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)
        self._pid_file.unlink(missing_ok=True)
        return {"stopped": True, "pid": pid}

    def client(self) -> MobSFClient:
        return MobSFClient(self.mobsf.url, self.api_key())


@register
class SASTEngine(Engine):
    """Static application security testing via MobSF."""

    name = "sast"
    summary = "Static analysis of APK/IPA/APPX using MobSF."

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.server = MobSFServer(config)

    def preflight(self) -> dict[str, Any]:
        client = self.server.client()
        reachable = client.ping()
        return {
            "engine": self.name,
            "ready": reachable,
            "details": {
                "mobsf_url": self.config.mobsf.url,
                "server_running": self.server.is_running(),
                "reachable": reachable,
                "mobsf_cli": which("mobsf") or "python -m mobsf",
            },
        }

    # -- server control ---------------------------------------------------

    @action("Start the MobSF server in the background.", background=True)
    def start_server(self, wait: bool = True) -> dict[str, Any]:
        return self.server.start(wait=wait)

    @action("Stop the MobSF server.", mutating=True)
    def stop_server(self) -> dict[str, Any]:
        return self.server.stop()

    @action("Report MobSF server status and the REST API key location.")
    def server_status(self) -> dict[str, Any]:
        return {
            "running": self.server.is_running(),
            "reachable": self.server.client().ping(),
            "url": self.config.mobsf.url,
            "api_key_configured": bool(self.config.mobsf.api_key)
            or (self.config.workspace / "mobsf_api_key").is_file(),
        }

    # -- scanning ---------------------------------------------------------

    @action("Upload and statically scan an app; returns the scan hash.", mutating=True)
    def scan(self, app_path: str, re_scan: bool = False) -> dict[str, Any]:
        """Upload ``app_path`` to MobSF and run a static scan.

        Args:
            app_path: Path to an APK/IPA/APPX/ZIP on the local filesystem.
            re_scan: Force a fresh scan even if a cached result exists.
        """
        path = Path(app_path).expanduser()
        with self.server.client() as client:
            if not client.ping():
                raise EngineError(
                    "sast", "MobSF server is not running. Run 'sast start-server' first."
                )
            uploaded = client.upload(path)
            scan_hash = uploaded["hash"]
            self.log.info("Uploaded %s -> hash %s", path.name, scan_hash)
            client.scan(scan_hash, re_scan=re_scan)
            return {
                "hash": scan_hash,
                "file_name": uploaded.get("file_name"),
                "scan_type": uploaded.get("scan_type"),
            }

    @action("Fetch the full JSON static-analysis report for a scan hash.")
    def report(self, scan_hash: str) -> dict[str, Any]:
        with self.server.client() as client:
            return client.report_json(scan_hash)

    @action("Fetch the app security scorecard for a scan hash.")
    def scorecard(self, scan_hash: str) -> dict[str, Any]:
        with self.server.client() as client:
            return client.scorecard(scan_hash)

    @action("Download the PDF report for a scan hash into the workspace.")
    def pdf(self, scan_hash: str, out_path: str | None = None) -> dict[str, Any]:
        target = (
            Path(out_path).expanduser()
            if out_path
            else self.config.reports_dir / f"{scan_hash}.pdf"
        )
        with self.server.client() as client:
            saved = client.download_pdf(scan_hash, target)
        return {"pdf": str(saved)}

    @action("List recent scans stored on the MobSF server.")
    def recent(self, page: int = 1, page_size: int = 25) -> dict[str, Any]:
        with self.server.client() as client:
            return client.recent_scans(page=page, page_size=page_size)

    @action("Delete a scan and its artefacts from the MobSF server.", mutating=True)
    def delete(self, scan_hash: str) -> dict[str, Any]:
        with self.server.client() as client:
            return client.delete_scan(scan_hash)
