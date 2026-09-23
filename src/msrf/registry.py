"""Central engine registry.

Engines register themselves here so the CLI and MCP server can enumerate every
available capability without importing each engine explicitly. Adding a new
engine in a future release is a two-line change: subclass :class:`Engine`,
apply :func:`register`.
"""
from __future__ import annotations

from collections.abc import Iterator

from .config import Config
from .engines.base import Engine
from .exceptions import ConfigurationError

_REGISTRY: dict[str, type[Engine]] = {}


def register(engine_cls: type[Engine]) -> type[Engine]:
    """Class decorator that registers an :class:`Engine` subclass by its name."""
    name = engine_cls.name
    if not name:
        raise ConfigurationError(
            f"Engine {engine_cls.__name__} must define a non-empty 'name'."
        )
    if name in _REGISTRY and _REGISTRY[name] is not engine_cls:
        raise ConfigurationError(f"Duplicate engine name registered: {name!r}")
    _REGISTRY[name] = engine_cls
    return engine_cls


def engine_names() -> list[str]:
    """Return all registered engine names, sorted."""
    _load_builtins()
    return sorted(_REGISTRY)


def engine_classes() -> Iterator[type[Engine]]:
    """Yield all registered engine classes."""
    _load_builtins()
    yield from _REGISTRY.values()


def get_engine(name: str, config: Config) -> Engine:
    """Instantiate a registered engine by name with the shared config."""
    _load_builtins()
    try:
        engine_cls = _REGISTRY[name]
    except KeyError:
        raise ConfigurationError(
            f"Unknown engine {name!r}. Available: {', '.join(sorted(_REGISTRY))}"
        ) from None
    return engine_cls(config)


def all_engines(config: Config) -> list[Engine]:
    """Instantiate every registered engine."""
    return [cls(config) for cls in engine_classes()]


_BUILTINS_LOADED = False


def _load_builtins() -> None:
    """Import built-in engine modules so their ``@register`` runs.

    Import is lazy and idempotent to avoid import cycles at module load time.
    """
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return
    # Importing each module triggers its @register decorator.
    from .engines import (  # noqa: F401
        appdata,
        dast,
        emulator,
        findings,
        hooks,
        iot,
        network,
        proxy,
        runtime,
        sast,
        sim,
    )

    _BUILTINS_LOADED = True
