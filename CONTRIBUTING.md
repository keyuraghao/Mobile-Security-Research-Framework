# Contributing to msrf

Thanks for your interest in improving msrf.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate   # or use uv
pip install -e ".[gui,dev]"
ruff check src tests
QT_QPA_PLATFORM=offscreen pytest -q
```

## Guidelines

- Keep the extensible architecture: a capability is an `Engine` with `@action` methods registered via `@register`; it then appears automatically in the GUI, the CLI and the MCP server.
- Run `ruff check` and `pytest` before opening a PR; keep the suite green.
- Update `CHANGELOG.md` under `## [Unreleased]` for user-visible changes. Each release's notes are generated from its CHANGELOG section.
- Authorised testing only: do not add features whose only purpose is to attack systems without permission.

## Releases

Bump `__version__` (`src/msrf/__init__.py`) and `version` (`pyproject.toml`), add a `## [x.y.z]` CHANGELOG section, then tag `vx.y.z`. CI builds the per-OS bundles + Windows installer, attaches `.sha256` checksums, and fills the release notes from the CHANGELOG.
