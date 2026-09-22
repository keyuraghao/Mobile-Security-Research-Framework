"""MCP (Model Context Protocol) server for mobiot.

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
from .exceptions import MobiotError
from .logging import configure_logging
from .registry import all_engines, engine_classes, get_engine


def build_server(config: Config) -> FastMCP:
    """Construct a :class:`FastMCP` server with all engine actions registered."""
    mcp = FastMCP(
        name="mobiot",
        instructions=(
            "mobiot is a unified Mobile & IoT SAST/DAST/pentest toolkit. Tools are "
            "grouped by engine (sast_, dast_, hooks_, runtime_, proxy_, network_, "
            "iot_). Use for AUTHORISED security testing only. Start with "
            "'mobiot_preflight' to see which engines are ready, and "
            "'sast_start_server' before static/dynamic MobSF operations."
        ),
    )

    @mcp.tool(name="mobiot_preflight", description="Health-check every engine.")
    def preflight() -> dict[str, Any]:
        report = {}
        for eng in all_engines(config):
            try:
                report[eng.name] = eng.preflight()
            except Exception as exc:
                report[eng.name] = {"engine": eng.name, "ready": False, "error": str(exc)}
        return report

    @mcp.tool(name="mobiot_version", description="Return the mobiot version.")
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
        except MobiotError as exc:
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
    mcp = build_server(config)
    if transport == "stdio":
        mcp.run()
    elif transport in {"http", "streamable-http"}:
        mcp.run(transport="http", host=host, port=port)
    else:
        raise MobiotError(f"Unknown MCP transport: {transport!r}")


def main() -> None:  # console-script entry point
    run_server()


if __name__ == "__main__":  # pragma: no cover
    main()
