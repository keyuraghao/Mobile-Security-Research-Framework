"""Logging setup for msrf.

Uses Rich for readable, coloured console output when available, and always
attaches a plain rotating file handler under the workspace ``logs`` directory
so runs are auditable after the fact.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False


def get_logger(name: str = "msrf") -> logging.Logger:
    """Return a namespaced logger under the ``msrf`` root logger."""
    if name == "msrf" or name.startswith("msrf."):
        return logging.getLogger(name)
    return logging.getLogger(f"msrf.{name}")


def configure_logging(
    level: str = "INFO",
    *,
    log_file: Path | None = None,
    force: bool = False,
) -> None:
    """Configure the ``msrf`` root logger exactly once.

    Args:
        level: Logging level name (``DEBUG``, ``INFO``, ...).
        log_file: Optional path for a rotating file handler.
        force: Reconfigure even if already configured (used by tests/CLI).
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    root = logging.getLogger("msrf")
    root.setLevel(level.upper())
    root.handlers.clear()
    root.propagate = False

    console_handler: logging.Handler
    try:
        from rich.logging import RichHandler

        console_handler = RichHandler(
            rich_tracebacks=True,
            show_path=False,
            markup=False,
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    except Exception:  # pragma: no cover - rich always present in our deps
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
    root.addHandler(console_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
            )
        )
        root.addHandler(file_handler)

    _CONFIGURED = True
