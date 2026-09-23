"""MCP (Model Context Protocol) server for msrf.

Exposes every engine action as an MCP tool named ``<engine>_<action>`` so an MCP
client (Claude, an IDE agent, etc.) can drive the whole toolkit. Tools are
generated from the registry, so new engines/actions become MCP tools with no
changes here.
"""
from __future__ import annotations

import inspect
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools import Tool

from . import get_version
from .config import Config, load_config
from .engines.base import ActionSpec
from .exceptions import MsrfError
from .logging import configure_logging
from .registry import all_engines, engine_classes, get_engine


def build_server(config: Config) -> FastMCP:
    """Construct a :class:`FastMCP` server with all engine actions registered."""
    mcp = FastMCP(
        name="msrf",
        instructions=(
            "msrf is a unified, self-contained Mobile & IoT SAST/DAST/pentest "
            "toolkit. Every capability is exposed here as a tool named "
            "<engine>_<action> across engines: sast (static analysis, in-process, "
            "no server needed), dast (Frida devices/dynamic), hooks (20+ inbuilt "
            "Frida payloads), runtime (objection), proxy (mitmproxy incl. "
            "WireGuard), network (device interception setup), iot (nmap/binwalk), "
            "and sim (built-in device/Frida simulator needing nothing attached). "
            "Use for AUTHORISED security testing only. "
            "Discover the full surface with 'msrf_capabilities'; check readiness "
            "with 'msrf_preflight'. Static analysis is direct/in-process: just "
            "call 'sast_scan' with a file path (no server, no login). For hooks "
            "with no device, pass device_id='sim'. Read the workspace layout with "
            "'msrf_workspace'."
        ),
    )

    @mcp.tool(
        name="msrf_capabilities",
        description="List every engine and action with parameters and flags.",
    )
    def capabilities() -> dict[str, Any]:
        catalog: dict[str, Any] = {"version": get_version(), "engines": {}}
        for engine_cls in engine_classes():
            actions = []
            for spec in engine_cls.actions():
                sig = inspect.signature(spec.func)
                params = {}
                for pname, p in sig.parameters.items():
                    if pname == "self":
                        continue
                    params[pname] = {
                        "annotation": _annotation_name(p.annotation),
                        "required": p.default is inspect.Parameter.empty,
                        "default": None
                        if p.default is inspect.Parameter.empty
                        else repr(p.default),
                    }
                actions.append(
                    {
                        "tool": f"{engine_cls.name}_{spec.func.__name__}",
                        "action": spec.name,
                        "summary": spec.summary,
                        "background": spec.background,
                        "mutating": spec.mutating,
                        "params": params,
                    }
                )
            catalog["engines"][engine_cls.name] = {
                "summary": engine_cls.summary,
                "actions": actions,
            }
        return catalog

    @mcp.tool(name="msrf_preflight", description="Health-check every engine.")
    def preflight() -> dict[str, Any]:
        report = {}
        for eng in all_engines(config):
            try:
                report[eng.name] = eng.preflight()
            except Exception as exc:
                report[eng.name] = {"engine": eng.name, "ready": False, "error": str(exc)}
        return report

    @mcp.tool(
        name="msrf_workspace",
        description="Report the workspace layout and where artefacts live.",
    )
    def workspace() -> dict[str, Any]:
        from . import bundled

        return {
            "workspace": str(config.workspace),
            "reports": str(config.reports_dir),
            "captures": str(config.captures_dir),
            "certs": str(config.certs_dir),
            "logs": str(config.logs_dir),
            "network": str(config.network_dir),
            "bundled_tools": bundled.vendor_root() is not None,
        }

    @mcp.tool(name="msrf_version", description="Return the msrf version.")
    def version() -> dict[str, str]:
        return {"version": get_version()}

    for engine_cls in engine_classes():
        for spec in engine_cls.actions():
            tool_fn = _make_tool(config, engine_cls.name, spec)
            mcp.add_tool(
                Tool.from_function(
                    tool_fn,
                    name=f"{engine_cls.name}_{spec.func.__name__}",
                    description=spec.summary,
                )
            )
    return mcp


def _annotation_name(annotation: Any) -> str:
    """Human-readable name for a parameter annotation."""
    if annotation is inspect.Parameter.empty:
        return "str"
    return getattr(annotation, "__name__", str(annotation))


def _make_tool(config: Config, engine_name: str, spec: ActionSpec):
    """Build a standalone callable mirroring an action, for MCP schema generation."""
    sig = inspect.signature(spec.func)
    params = [
        p for name, p in sig.parameters.items() if name != "self"
    ]

    def tool_fn(**kwargs: Any) -> Any:
        try:
            engine = get_engine(engine_name, config)
            method = getattr(engine, spec.func.__name__)
            return method(**kwargs)
        except MsrfError as exc:
            return {"error": str(exc), "engine": engine_name, "action": spec.name}

    # Give FastMCP a real signature/annotations to derive the input schema.
    tool_fn.__signature__ = inspect.Signature(params)  # type: ignore[attr-defined]
    tool_fn.__annotations__ = {
        p.name: (p.annotation if p.annotation is not inspect.Parameter.empty else str)
        for p in params
    } | {"return": dict}
    tool_fn.__name__ = f"{engine_name}_{spec.func.__name__}"
    tool_fn.__doc__ = spec.summary
    return tool_fn


def run_server(
    config: Config | None = None,
    *,
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    """Build and run the MCP server on the requested transport."""
    config = config or load_config()
    config.ensure_dirs()
    configure_logging(config.log_level, log_file=config.logs_dir / "mcp.log")
    # Point engines at bundled tools when running from a standalone build so the
    # MCP server has the same full, self-contained capability as the GUI/CLI.
    from . import bundled

    bundled.activate(config)
    mcp = build_server(config)
    if transport == "stdio":
        mcp.run()
    elif transport in {"http", "streamable-http"}:
        mcp.run(transport="http", host=host, port=port)
    else:
        raise MsrfError(f"Unknown MCP transport: {transport!r}")


def main() -> None:  # console-script entry point
    run_server()


if __name__ == "__main__":  # pragma: no cover
    main()
