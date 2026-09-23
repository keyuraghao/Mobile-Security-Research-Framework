"""Command-line interface for mobiot.

The CLI is generated from the engine registry: every :class:`Engine` becomes a
subcommand group and every ``@action`` becomes a command whose options mirror the
method signature. Adding an engine or action therefore extends the CLI with no
extra code here.

Usage examples::

    mobiot info                     # list engines and actions
    mobiot preflight                # health-check every engine
    mobiot sast start-server
    mobiot sast scan ./app.apk
    mobiot hooks list-templates
    mobiot hooks test --template ssl-pinning-bypass
    mobiot serve                    # run the MCP server
"""
from __future__ import annotations

import inspect
import json as jsonlib
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from . import get_version
from .config import Config, load_config
from .exceptions import MobiotError
from .logging import configure_logging
from .registry import all_engines, engine_classes, get_engine

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="mobiot",
    help="Unified Mobile & IoT SAST/DAST/pentest toolkit.",
    no_args_is_help=True,
    add_completion=True,
)

# Global runtime state populated by the main callback.
_STATE: dict[str, Any] = {"config": None, "json": False}


def _config() -> Config:
    cfg = _STATE.get("config")
    if cfg is None:
        cfg = load_config()
        _STATE["config"] = cfg
    return cfg


def _emit(result: Any) -> None:
    """Print a command result as plain JSON (machine-readable, pipes into jq)."""
    print(jsonlib.dumps(result, indent=2, default=str))


@app.callback()
def main(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to a TOML config file."
    ),
    workspace: Path | None = typer.Option(
        None, "--workspace", "-w", help="Override the workspace directory."
    ),
    log_level: str = typer.Option("INFO", "--log-level", help="Logging level."),
) -> None:
    """Initialise configuration and logging for every subcommand."""
    overrides: dict[str, Any] = {}
    if workspace is not None:
        overrides["workspace"] = workspace
    if log_level:
        overrides["log_level"] = log_level
    cfg = load_config(config, **overrides)
    cfg.ensure_dirs()
    configure_logging(cfg.log_level, log_file=cfg.logs_dir / "mobiot.log")
    # Point engines at bundled tools when running from a standalone build.
    from . import bundled

    bundled.activate(cfg)
    _STATE["config"] = cfg


@app.command()
def version() -> None:
    """Print the mobiot version."""
    console.print(f"mobiot {get_version()}")


@app.command()
def info() -> None:
    """List every engine and its actions."""
    table = Table(title="mobiot engines", show_lines=False)
    table.add_column("Engine", style="bold cyan")
    table.add_column("Action")
    table.add_column("Description")
    for engine_cls in engine_classes():
        first = True
        for spec in sorted(engine_cls.actions(), key=lambda s: s.name):
            table.add_row(
                engine_cls.name if first else "",
                spec.name.replace("_", "-"),
                spec.summary,
            )
            first = False
    console.print(table)


@app.command()
def preflight(engine: str | None = typer.Argument(None, help="Engine to check.")) -> None:
    """Health-check one engine, or every engine when none is given."""
    cfg = _config()
    engines = [get_engine(engine, cfg)] if engine else all_engines(cfg)
    report = {}
    for eng in engines:
        try:
            report[eng.name] = eng.preflight()
        except Exception as exc:  # keep going; report the failure
            report[eng.name] = {"engine": eng.name, "ready": False, "error": str(exc)}
    _emit(report)


@app.command()
def ui() -> None:
    """Launch the mobiot desktop application (PyQt6)."""
    try:
        from .gui import run as run_gui
    except ImportError as exc:  # PyQt6 not installed
        err_console.print(
            "[red]The GUI requires PyQt6.[/red] Install it with: "
            "pip install 'mobiot[gui]'"
        )
        raise typer.Exit(code=1) from exc
    raise typer.Exit(code=run_gui())


@app.command()
def serve(
    transport: str = typer.Option("stdio", help="MCP transport: stdio or http."),
    host: str = typer.Option("127.0.0.1", help="Host for http transport."),
    port: int = typer.Option(8765, help="Port for http transport."),
) -> None:
    """Run the mobiot MCP server."""
    from .mcp_server import run_server

    run_server(_config(), transport=transport, host=host, port=port)


# ---------------------------------------------------------------------------
# Dynamic per-engine subcommands generated from @action signatures.
# ---------------------------------------------------------------------------


def _is_dict_annotation(annotation: Any) -> bool:
    return "dict" in str(annotation).lower()


def _build_command(engine_name: str, method_name: str, spec) -> Any:
    """Create a Typer-compatible command function mirroring an action signature."""
    sig = inspect.signature(spec.func)
    new_params: list[inspect.Parameter] = []
    dict_params: set[str] = set()

    for pname, param in sig.parameters.items():
        if pname == "self":
            continue
        annotation = param.annotation
        has_default = param.default is not inspect.Parameter.empty

        if _is_dict_annotation(annotation):
            # Accept dict params as a JSON string option.
            dict_params.add(pname)
            default = typer.Option(
                None, help=f"{pname} as a JSON object string."
            )
            new_params.append(
                inspect.Parameter(
                    pname,
                    inspect.Parameter.KEYWORD_ONLY,
                    default=default,
                    annotation=str,
                )
            )
            continue

        if has_default:
            default = typer.Option(param.default, help=spec.summary if False else None)
            kind = inspect.Parameter.KEYWORD_ONLY
        else:
            default = typer.Argument(..., help=f"{pname}")
            kind = inspect.Parameter.POSITIONAL_OR_KEYWORD
        ann = annotation if annotation is not inspect.Parameter.empty else str
        new_params.append(
            inspect.Parameter(pname, kind, default=default, annotation=ann)
        )

    def command(**kwargs: Any) -> None:
        call_kwargs: dict[str, Any] = {}
        for key, value in kwargs.items():
            if key in dict_params:
                call_kwargs[key] = jsonlib.loads(value) if value else None
            else:
                call_kwargs[key] = value
        try:
            engine = get_engine(engine_name, _config())
            method = getattr(engine, method_name)
            result = method(**call_kwargs)
        except MobiotError as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        _emit(result)

    command.__name__ = method_name
    command.__doc__ = spec.summary
    command.__signature__ = inspect.Signature(new_params)  # type: ignore[attr-defined]
    command.__annotations__ = {
        p.name: p.annotation for p in new_params
    } | {"return": None}
    return command


def _register_engine_commands() -> None:
    for engine_cls in engine_classes():
        sub = typer.Typer(
            name=engine_cls.name,
            help=engine_cls.summary,
            no_args_is_help=True,
        )
        for spec in engine_cls.actions():
            method_name = spec.func.__name__
            command = _build_command(engine_cls.name, method_name, spec)
            sub.command(
                name=spec.name.replace("_", "-"),
                help=spec.summary,
            )(command)
        app.add_typer(sub, name=engine_cls.name)


_register_engine_commands()


def run() -> None:  # console-script entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    run()
