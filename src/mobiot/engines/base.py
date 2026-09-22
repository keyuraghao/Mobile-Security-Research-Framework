"""Engine base class and the ``@action`` decorator.

An :class:`Engine` groups related security operations (SAST, proxy, IoT, ...).
Individual operations are ordinary methods decorated with :func:`action`, which
records lightweight metadata used to auto-expose them on both the CLI and the
MCP server. This is the single extension point of mobiot: to add a capability in
a future release, write an ``Engine`` subclass, decorate its methods with
``@action`` and register it with :func:`mobiot.registry.register` — the CLI and
MCP surfaces pick it up automatically, no wiring required.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..logging import get_logger


@dataclass(slots=True)
class ActionSpec:
    """Metadata describing a single engine operation."""

    name: str
    summary: str
    func: Callable[..., Any]
    #: Whether this action starts a long-running background service.
    background: bool = False
    #: Whether this action may modify a target device/network (write op).
    mutating: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)

    def signature(self) -> inspect.Signature:
        return inspect.signature(self.func)


def action(
    summary: str,
    *,
    name: str | None = None,
    background: bool = False,
    mutating: bool = False,
    tags: tuple[str, ...] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Mark an :class:`Engine` method as an externally exposed action.

    Args:
        summary: One-line human description (used for ``--help`` and MCP docs).
        name: Override the exposed action name (defaults to the method name).
        background: True if the action launches a persistent service.
        mutating: True if the action changes device/network state.
        tags: Free-form tags for grouping/filtering.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        func._mobiot_action = ActionSpec(  # type: ignore[attr-defined]
            name=name or func.__name__,
            summary=summary,
            func=func,
            background=background,
            mutating=mutating,
            tags=tags,
        )
        return func

    return decorator


class Engine:
    """Base class for all mobiot engines.

    Subclasses set :attr:`name` and :attr:`summary`, take the shared
    :class:`~mobiot.config.Config` in ``__init__`` and implement operations as
    ``@action``-decorated methods.
    """

    #: Short, unique identifier (e.g. ``"sast"``). Used as a CLI subcommand and
    #: as the prefix for MCP tool names (``sast_scan``).
    name: str = ""
    #: One-line description shown in help output.
    summary: str = ""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.log = get_logger(self.name or self.__class__.__name__)

    # -- action discovery -------------------------------------------------

    @classmethod
    def actions(cls) -> Iterator[ActionSpec]:
        """Yield every :class:`ActionSpec` declared on this engine."""
        seen: set[str] = set()
        for _, member in inspect.getmembers(cls, predicate=inspect.isfunction):
            spec = getattr(member, "_mobiot_action", None)
            if spec is not None and spec.name not in seen:
                seen.add(spec.name)
                yield spec

    def bound_actions(self) -> Iterator[tuple[ActionSpec, Callable[..., Any]]]:
        """Yield ``(spec, bound_method)`` pairs for this instance."""
        for spec in self.actions():
            yield spec, getattr(self, spec.func.__name__)

    # -- lifecycle / health ----------------------------------------------

    def preflight(self) -> dict[str, Any]:
        """Return a health/readiness report for this engine.

        Subclasses should override to check for their external dependencies
        (installed tools, reachable services). The default reports readiness.
        """
        return {"engine": self.name, "ready": True, "details": {}}
