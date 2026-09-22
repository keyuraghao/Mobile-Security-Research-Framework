"""IoT engine — network reconnaissance and firmware analysis.

Wraps ``nmap`` for host/port discovery and ``binwalk`` for firmware signature
scanning and extraction. Both tools are located on ``PATH`` cross-platform.
Scanning and firmware extraction must only be performed against systems you own
or are explicitly authorised to test.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

try:  # defusedxml hardens XML parsing; fall back to stdlib if unavailable.
    from defusedxml import ElementTree as ET
    from defusedxml.ElementTree import ParseError
except Exception:  # pragma: no cover
    import xml.etree.ElementTree as ET
    from xml.etree.ElementTree import ParseError

from ..exceptions import EngineError
from ..platform_utils import require_tool, run, which
from ..registry import register
from .base import Engine, action

_NMAP_HINT = "Install nmap from your package manager (e.g. apt install nmap)."
_BINWALK_HINT = "Install binwalk from your package manager or 'pip install binwalk'."


@register
class IoTEngine(Engine):
    """IoT reconnaissance (nmap) and firmware analysis (binwalk)."""

    name = "iot"
    summary = "IoT host/port scanning (nmap) and firmware analysis (binwalk)."

    def preflight(self) -> dict[str, Any]:
        return {
            "engine": self.name,
            "ready": which("nmap") is not None or which("binwalk") is not None,
            "details": {"nmap": which("nmap"), "binwalk": which("binwalk")},
        }

    # -- network recon ----------------------------------------------------

    @action("Discover live hosts on a network with an nmap ping sweep.")
    def host_discovery(self, network: str, timeout: float = 300.0) -> dict[str, Any]:
        """Run ``nmap -sn`` (ping sweep) against ``network`` (e.g. 192.168.1.0/24)."""
        nmap = require_tool("nmap", hint=_NMAP_HINT)
        xml_path = self._xml_out("discovery")
        run(
            [nmap, "-sn", "-oX", str(xml_path), network],
            timeout=timeout,
            check=True,
        )
        return {"network": network, "hosts": self._parse_hosts(xml_path)}

    @action("Scan ports/services on a target host with nmap.")
    def port_scan(
        self,
        target: str,
        ports: str | None = None,
        service_detection: bool = True,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        """Run an nmap port/service scan against ``target``.

        Args:
            target: Host or CIDR to scan.
            ports: Port spec (e.g. ``"1-1024"`` or ``"80,443,8080"``); default
                is nmap's default port set.
            service_detection: Enable ``-sV`` version detection.
        """
        nmap = require_tool("nmap", hint=_NMAP_HINT)
        xml_path = self._xml_out("portscan")
        argv = [nmap, "-oX", str(xml_path)]
        if service_detection:
            argv.append("-sV")
        if ports:
            argv += ["-p", ports]
        argv.append(target)
        run(argv, timeout=timeout, check=True)
        return {"target": target, "hosts": self._parse_hosts(xml_path)}

    def _xml_out(self, tag: str) -> Path:
        self.config.ensure_dirs()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return self.config.network_dir / f"nmap-{tag}-{stamp}.xml"

    def _parse_hosts(self, xml_path: Path) -> list[dict[str, Any]]:
        try:
            # Parser is defusedxml when available (see import guard above).
            tree = ET.parse(xml_path)  # noqa: S314
        except ParseError as exc:
            raise EngineError("iot", f"Failed to parse nmap output: {exc}") from exc
        hosts: list[dict[str, Any]] = []
        for host in tree.getroot().findall("host"):
            status = host.find("status")
            addr_el = host.find("address")
            entry: dict[str, Any] = {
                "state": status.get("state") if status is not None else None,
                "address": addr_el.get("addr") if addr_el is not None else None,
                "ports": [],
            }
            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")
                entry["ports"].append(
                    {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": state.get("state") if state is not None else None,
                        "service": service.get("name") if service is not None else None,
                        "product": service.get("product") if service is not None else None,
                        "version": service.get("version") if service is not None else None,
                    }
                )
            hosts.append(entry)
        return hosts

    # -- firmware analysis ------------------------------------------------

    @action("Scan a firmware image for embedded file signatures (binwalk).")
    def firmware_scan(self, firmware_path: str, timeout: float = 600.0) -> dict[str, Any]:
        """Run a binwalk signature scan (no extraction) over a firmware image."""
        binwalk = require_tool("binwalk", hint=_BINWALK_HINT)
        path = Path(firmware_path).expanduser()
        if not path.is_file():
            raise EngineError("iot", f"Firmware file not found: {path}")
        result = run([binwalk, str(path)], timeout=timeout, check=False)
        return {"firmware": str(path), "output": result.stdout, "stderr": result.stderr}

    @action("Extract embedded filesystems/files from a firmware image (binwalk -e).", mutating=True)
    def firmware_extract(
        self, firmware_path: str, out_dir: str | None = None, timeout: float = 1800.0
    ) -> dict[str, Any]:
        """Extract a firmware image with ``binwalk -e`` into ``out_dir``."""
        binwalk = require_tool("binwalk", hint=_BINWALK_HINT)
        path = Path(firmware_path).expanduser()
        if not path.is_file():
            raise EngineError("iot", f"Firmware file not found: {path}")
        target_dir = (
            Path(out_dir).expanduser()
            if out_dir
            else self.config.workspace / "firmware" / path.stem
        )
        target_dir.mkdir(parents=True, exist_ok=True)
        # binwalk (v2 and v3) extract into the current working directory.
        result = run(
            [binwalk, "-e", str(path)],
            cwd=target_dir,
            timeout=timeout,
            check=False,
        )
        extracted = [str(p) for p in target_dir.rglob("*") if p.is_file()][:500]
        return {
            "firmware": str(path),
            "out_dir": str(target_dir),
            "output": result.stdout,
            "stderr": result.stderr,
            "extracted_sample": extracted,
        }
