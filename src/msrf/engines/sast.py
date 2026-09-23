"""SAST engine: static analysis via MobSF.

Manages a native MobSF server (start/stop/status) in the shared virtualenv and
drives the MobSF REST API to upload apps, run static scans and fetch reports.
The server is launched with a deterministic API key and a workspace-scoped
``MOBSF_HOME_DIR`` so runs are reproducible and self-contained.
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from .. import mobsf_direct
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
        self._server_thread = None

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

        Setting ``MOBSF_SECRET_KEY`` short-circuits MobSF's first-run block,
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

        * Delete the generated ``config.py``, because once present it shadows the
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
        if self._server_thread is not None and self._server_thread.is_alive():
            return True
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

    def _use_in_process(self) -> bool:
        if self.mobsf.in_process is not None:
            return self.mobsf.in_process
        # Auto: in a frozen standalone build there is no separate interpreter to
        # spawn, so serve MobSF in-process.
        import sys

        return bool(getattr(sys, "frozen", False))

    def start(self, wait: bool = True) -> dict[str, Any]:
        """Start the MobSF server if not already running."""
        self.config.ensure_dirs()
        client = self.client()
        if client.ping():
            return {"started": False, "already_running": True, "url": self.mobsf.url}

        if self._use_in_process():
            return self._start_in_process(wait=wait)

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

    def _start_in_process(self, wait: bool = True) -> dict[str, Any]:
        """Serve MobSF inside this process via waitress (no subprocess).

        This is what lets a standalone build run MobSF with no separate install
        or interpreter: it configures Django, runs migrations once, and serves
        the WSGI app on a daemon thread. The server lives for the process
        lifetime; ``stop`` is a no-op in this mode.
        """
        import os
        import threading

        # Apply the offline profile to this process's environment.
        for key, value in self._build_env().items():
            os.environ[key] = value
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mobsf.MobSF.settings")
        self._prepare_home()

        error: dict[str, Any] = {}

        def serve() -> None:
            try:
                import django

                django.setup()
                from django.core.management import call_command

                for args in (
                    ("makemigrations",),
                    ("makemigrations", "StaticAnalyzer"),
                    ("migrate",),
                ):
                    try:
                        call_command(*args, interactive=False, verbosity=0)
                    except Exception as exc:  # non-fatal migration edge cases
                        self.log.debug("migration step %s: %s", args, exc)
                try:
                    call_command("create_roles", verbosity=0)
                except Exception as exc:
                    self.log.debug("create_roles: %s", exc)

                from mobsf.MobSF.wsgi import application
                from waitress import serve as waitress_serve

                waitress_serve(
                    application,
                    host=self.mobsf.host,
                    port=self.mobsf.port,
                    threads=10,
                    channel_timeout=3600,
                    _quiet=True,
                )
            except Exception as exc:  # pragma: no cover - reported via error dict
                error["error"] = str(exc)
                self.log.exception("In-process MobSF server failed")

        thread = threading.Thread(target=serve, name="mobsf-server", daemon=True)
        thread.start()
        self._server_thread = thread

        if not wait:
            return {"started": True, "in_process": True, "url": self.mobsf.url}

        deadline = time.time() + self.mobsf.startup_timeout
        client = self.client()
        while time.time() < deadline:
            if client.ping():
                return {"started": True, "in_process": True, "url": self.mobsf.url}
            if error:
                raise EngineError("sast", f"In-process MobSF failed: {error['error']}")
            if not thread.is_alive():
                raise EngineError(
                    "sast", f"In-process MobSF thread exited: {error.get('error', 'unknown')}"
                )
            time.sleep(1.5)
        raise EngineError(
            "sast",
            f"In-process MobSF did not become ready within {self.mobsf.startup_timeout}s.",
        )

    def stop(self) -> dict[str, Any]:
        """Stop the MobSF server process (and children)."""
        if self._server_thread is not None and self._server_thread.is_alive():
            # In-process (waitress) server lives for the app lifetime.
            return {"stopped": False, "reason": "in-process server; exits with the app"}
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
        try:
            import mobsf  # noqa: F401

            mobsf_ok = True
        except Exception:
            mobsf_ok = False
        return {
            "engine": self.name,
            "ready": mobsf_ok,
            "details": {
                "mode": "direct in-process analysis (no server, our own output)",
                "mobsf_available": mobsf_ok,
                "java": which("java"),
                "jadx": which("jadx"),
                "django_configured": mobsf_direct.is_configured(),
            },
        }

    # -- local report cache ----------------------------------------------

    def _report_path(self, scan_hash: str) -> Path:
        return self.config.reports_dir / f"{scan_hash}.json"

    def _load_report(self, scan_hash: str) -> dict[str, Any]:
        path = self._report_path(scan_hash)
        if not path.is_file():
            raise EngineError(
                "sast", f"No cached report for {scan_hash!r}. Run 'sast scan' first."
            )
        return json.loads(path.read_text())

    # -- scanning (direct, in-process) -----------------------------------

    @action("Statically scan an app in-process; returns a scan summary.", mutating=True)
    def scan(self, app_path: str, re_scan: bool = False) -> dict[str, Any]:
        """Analyse ``app_path`` (APK/IPA) directly in-process via MobSF's engine.

        No MobSF server is started and no REST is used: the raw result is
        computed in-process, cached locally, and returned as our own summary.
        The full report is available via ``report`` / ``scorecard``.
        """
        context = mobsf_direct.analyze(
            app_path,
            self.server._build_env(),
            self.server._prepare_home,
            rescan=re_scan,
        )
        scan_hash = context["hash"]
        self.config.reports_dir.mkdir(parents=True, exist_ok=True)
        self._report_path(scan_hash).write_text(json.dumps(context, default=str))
        self.log.info("Scanned %s -> %s", context.get("file_name"), scan_hash)

        appsec = context.get("appsec", {}) or {}
        return {
            "hash": scan_hash,
            "file_name": context.get("file_name"),
            "scan_type": context.get("scan_type"),
            "security_score": appsec.get("security_score"),
            "high": len(appsec.get("high", []) or []),
            "warning": len(appsec.get("warning", []) or []),
            "info": len(appsec.get("info", []) or []),
        }

    @action("Fetch the full JSON static-analysis report for a scan hash.")
    def report(self, scan_hash: str) -> dict[str, Any]:
        return self._load_report(scan_hash)

    @action("Fetch the app security scorecard (score + findings) for a scan hash.")
    def scorecard(self, scan_hash: str) -> dict[str, Any]:
        return self._load_report(scan_hash).get("appsec", {})

    def _app_extract_dir(self, scan_hash: str) -> Path:
        """Directory where MobSF extracted the scanned app's internal files."""
        return self.config.workspace / "mobsf_home" / "uploads" / scan_hash

    @action("List the internal files of a scanned app.")
    def files(self, scan_hash: str) -> dict[str, Any]:
        report = self._load_report(scan_hash)
        return {"hash": scan_hash, "files": report.get("files", [])}

    @action("Read one internal file of a scanned app (path relative to app root).")
    def file_content(
        self, scan_hash: str, rel_path: str, max_bytes: int = 300000
    ) -> dict[str, Any]:
        """Return the content of a file inside the extracted app.

        Path traversal is rejected: the resolved target must stay within the
        app's extraction directory.
        """
        base = self._app_extract_dir(scan_hash).resolve()
        target = (base / rel_path).resolve()
        if not target.is_relative_to(base):
            raise EngineError("sast", "Path escapes the application directory.")
        if not target.is_file():
            raise EngineError("sast", f"File not found in app: {rel_path}")
        raw = target.read_bytes()
        size = len(raw)
        # Compiled Android XML (AndroidManifest.xml, res/**/*.xml) is binary
        # "AXML"; decode it back to readable XML with MobSF's bundled decoder.
        if raw[:4] == _AXML_MAGIC:
            xml = _decode_axml(raw)
            if xml is not None:
                return {"path": rel_path, "binary": False, "decoded": "android-binary-xml",
                        "size": size, "truncated": False, "content": xml}
        try:
            content = raw[:max_bytes].decode("utf-8")
            return {"path": rel_path, "binary": False, "size": size,
                    "truncated": size > max_bytes, "content": content}
        except UnicodeDecodeError:
            pass
        limit = min(max_bytes, _HEX_VIEW_BYTES)
        return {"path": rel_path, "binary": True, "size": size,
                "truncated": size > limit, "content": _hexdump(raw[:limit])}

    @action("Export a scan's full report to a JSON file in the workspace.")
    def export(self, scan_hash: str, out_path: str | None = None) -> dict[str, Any]:
        report = self._load_report(scan_hash)
        target = (
            Path(out_path).expanduser()
            if out_path
            else self.config.reports_dir / f"{scan_hash}.export.json"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2, default=str))
        return {"report": str(target)}

    @action("List locally cached scans.")
    def recent(self) -> dict[str, Any]:
        scans = []
        for p in sorted(self.config.reports_dir.glob("*.json")):
            if p.name.endswith(".export.json"):
                continue
            try:
                data = json.loads(p.read_text())
            except Exception as exc:
                self.log.debug("skipping unreadable report %s: %s", p, exc)
                continue
            scans.append(
                {
                    "hash": data.get("hash", p.stem),
                    "file_name": data.get("file_name"),
                    "scan_type": data.get("scan_type"),
                    "security_score": (data.get("appsec") or {}).get("security_score"),
                }
            )
        return {"scans": scans}

    @action("Delete a cached scan report.", mutating=True)
    def delete(self, scan_hash: str) -> dict[str, Any]:
        removed = False
        export = self.config.reports_dir / f"{scan_hash}.export.json"
        for p in (self._report_path(scan_hash), export):
            if p.is_file():
                p.unlink()
                removed = True
        return {"deleted": removed, "hash": scan_hash}

    # -- optional server mode (web UI / external REST clients) ------------

    @action("Start the MobSF web/REST server (optional; not needed for scans).",
            background=True)
    def start_server(self, wait: bool = True) -> dict[str, Any]:
        return self.server.start(wait=wait)

    @action("Stop the MobSF server.", mutating=True)
    def stop_server(self) -> dict[str, Any]:
        return self.server.stop()

    @action("Report optional MobSF server status.")
    def server_status(self) -> dict[str, Any]:
        return {
            "running": self.server.is_running(),
            "reachable": self.server.client().ping(),
            "url": self.config.mobsf.url,
        }


_AXML_MAGIC = b"\x03\x00\x08\x00"
#: Binary files are shown as a hex dump; cap it so huge files stay responsive.
_HEX_VIEW_BYTES = 64 * 1024


def _decode_axml(raw: bytes) -> str | None:
    """Decode Android binary XML to text, or None if it cannot be decoded."""
    try:
        from mobsf.StaticAnalyzer.tools.androguard4.axml import AXMLPrinter

        printer = AXMLPrinter(raw)
        if not printer.is_valid():
            return None
        return printer.get_xml().decode("utf-8", errors="replace")
    except Exception:
        return None


def _hexdump(data: bytes) -> str:
    """Classic offset / hex / text dump, 16 bytes per line."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<47}  {text}")
    return "\n".join(lines)
