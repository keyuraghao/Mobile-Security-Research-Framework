"""Proxy engine — traffic interception via mitmproxy.

Runs ``mitmdump`` headless in the background, capturing flows to the workspace,
and can decode a captured flow file to JSON. Supports every mitmproxy mode,
including ``wireguard`` — which lets a device on *any* network tunnel its traffic
back to the analysis host (see the ``network`` engine for the device-side setup).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ..config import Config
from ..exceptions import EngineError
from ..platform_utils import require_tool, spawn, which
from ..registry import register
from .base import Engine, action

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

_MITM_HINT = "Install with 'pip install mitmproxy'."


@register
class ProxyEngine(Engine):
    """Intercept and record traffic with mitmproxy."""

    name = "proxy"
    summary = "Intercept and record app traffic with mitmproxy (incl. WireGuard mode)."

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._pid_file = config.logs_dir / "mitmproxy.pid"
        self._meta_file = config.logs_dir / "mitmproxy.json"

    def preflight(self) -> dict[str, Any]:
        return {
            "engine": self.name,
            "ready": which("mitmdump") is not None,
            "details": {
                "mitmdump": which("mitmdump"),
                "running": self.is_running(),
                "ca_cert": str(self._ca_cert_path()),
            },
        }

    # -- process helpers --------------------------------------------------

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
        try:  # pragma: no cover
            import os

            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _ca_cert_path(self) -> Path:
        # mitmproxy stores its CA under ~/.mitmproxy by default.
        return Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

    # -- actions ----------------------------------------------------------

    @action("Start a background mitmproxy capture.", background=True, mutating=True)
    def start_capture(
        self,
        mode: str | None = None,
        listen_port: int | None = None,
        out_file: str | None = None,
    ) -> dict[str, Any]:
        """Start ``mitmdump`` in the background, writing flows to a file.

        Args:
            mode: One of ``regular``, ``transparent``, ``wireguard``,
                ``socks5``, ``upstream``. Defaults to the configured proxy mode.
            listen_port: TCP/UDP listen port (defaults to configured port).
            out_file: Flow output path (defaults to a timestamped file in the
                captures workspace).
        """
        if self.is_running():
            return {"started": False, "already_running": True, "pid": self._read_pid()}

        mitmdump = require_tool("mitmdump", hint=_MITM_HINT)
        self.config.ensure_dirs()
        mode = mode or self.config.proxy.mode
        port = listen_port or self.config.proxy.listen_port
        stamp = time.strftime("%Y%m%d-%H%M%S")
        flow_path = (
            Path(out_file).expanduser()
            if out_file
            else self.config.captures_dir / f"capture-{stamp}.flows"
        )
        log_path = self.config.logs_dir / "mitmproxy.log"

        argv = [
            mitmdump,
            "--mode",
            mode if mode != "regular" else "regular",
            "--listen-host",
            self.config.proxy.listen_host,
            "--listen-port",
            str(port if mode != "wireguard" else self.config.proxy.wireguard_port),
            "-w",
            str(flow_path),
            "--set",
            "block_global=false",
        ]
        proc = spawn(argv, stdout=log_path)
        self._pid_file.write_text(str(proc.pid))
        meta = {
            "pid": proc.pid,
            "mode": mode,
            "listen_host": self.config.proxy.listen_host,
            "listen_port": port if mode != "wireguard" else self.config.proxy.wireguard_port,
            "flow_file": str(flow_path),
            "log_file": str(log_path),
        }
        import json

        self._meta_file.write_text(json.dumps(meta, indent=2))
        # Give it a moment to bind / generate wireguard config.
        time.sleep(2.0)
        if proc.poll() is not None:
            tail = log_path.read_text()[-1200:] if log_path.is_file() else ""
            raise EngineError("proxy", f"mitmproxy exited immediately.\n{tail}")
        return {"started": True, **meta}

    @action("Stop the background mitmproxy capture.", mutating=True)
    def stop_capture(self) -> dict[str, Any]:
        pid = self._read_pid()
        if pid is None or not self.is_running():
            self._pid_file.unlink(missing_ok=True)
            return {"stopped": False, "reason": "not running"}
        if psutil is not None:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                _, alive = psutil.wait_procs([proc], timeout=8)
                for p in alive:
                    p.kill()
            except psutil.NoSuchProcess:
                pass
        else:  # pragma: no cover
            import contextlib
            import os
            import signal

            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)
        self._pid_file.unlink(missing_ok=True)
        return {"stopped": True, "pid": pid}

    @action("Report mitmproxy capture status and metadata.")
    def status(self) -> dict[str, Any]:
        import json

        meta = {}
        if self._meta_file.is_file():
            meta = json.loads(self._meta_file.read_text())
        return {"running": self.is_running(), **meta}

    @action("Decode a captured mitmproxy flow file into a JSON summary.")
    def read_flows(self, flow_file: str, limit: int = 200) -> dict[str, Any]:
        """Parse a ``.flows`` file into request/response summaries."""
        path = Path(flow_file).expanduser()
        if not path.is_file():
            raise EngineError("proxy", f"Flow file not found: {path}")
        try:
            from mitmproxy import http as mhttp
            from mitmproxy import io as mio
        except Exception as exc:  # pragma: no cover
            raise EngineError("proxy", f"mitmproxy library unavailable: {exc}") from exc

        flows: list[dict[str, Any]] = []
        with path.open("rb") as handle:
            reader = mio.FlowReader(handle)
            for flow in reader.stream():
                if not isinstance(flow, mhttp.HTTPFlow):
                    continue
                req = flow.request
                entry: dict[str, Any] = {
                    "method": req.method,
                    "url": req.pretty_url,
                    "host": req.host,
                    "request_headers": dict(req.headers),
                }
                if flow.response is not None:
                    entry["status_code"] = flow.response.status_code
                    entry["content_type"] = flow.response.headers.get("content-type")
                flows.append(entry)
                if len(flows) >= limit:
                    break
        return {"flow_file": str(path), "count": len(flows), "flows": flows}
