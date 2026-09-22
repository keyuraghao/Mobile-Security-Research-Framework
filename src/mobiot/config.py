"""Configuration for mobiot.

Configuration is resolved with the following precedence (highest first):

1. Explicit keyword arguments to :func:`load_config`.
2. Environment variables prefixed ``MOBIOT_`` (e.g. ``MOBIOT_MOBSF_URL``).
3. A TOML config file (``--config`` path, ``$MOBIOT_CONFIG``, or the default
   per-user config path).
4. Built-in defaults, which are computed cross-platform.

All filesystem locations use :mod:`platformdirs` so they land in the correct
place on Linux, macOS and Windows without any hardcoded paths.
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from platformdirs import PlatformDirs
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import ConfigurationError

_DIRS = PlatformDirs(appname="mobiot", appauthor=False)

#: Default per-user config file location (``~/.config/mobiot/config.toml`` etc.).
DEFAULT_CONFIG_PATH = Path(_DIRS.user_config_dir) / "config.toml"


class MobSFConfig(BaseSettings):
    """MobSF (SAST/DAST) server settings."""

    model_config = SettingsConfigDict(env_prefix="MOBIOT_MOBSF_", extra="ignore")

    url: str = Field(default="http://127.0.0.1:8000")
    api_key: str | None = Field(default=None)
    #: Path to the MobSF source checkout, used to launch the server natively.
    home: Path | None = Field(default=None)
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000)
    # First run runs migrations; with the offline profile there are no tool
    # downloads, so startup is fast. Kept generous for slow first migrations.
    startup_timeout: float = Field(default=180.0)

    # -- slim / offline profile (see docs) -------------------------------
    #: Apply the fast, download-free, headless-REST profile at launch.
    offline_profile: bool = Field(default=True)
    #: Use a system jadx binary (found on PATH) instead of MobSF's download.
    use_system_jadx: bool = Field(default=True)
    #: Serve the REST API only (disable the web UI URLs).
    api_only: bool = Field(default=True)
    #: Disable web-UI login (REST always uses the API key regardless).
    disable_authentication: bool = Field(default=True)
    #: Run scans synchronously in-request (no django-q worker needed).
    async_analysis: bool = Field(default=False)
    #: Per-scan outbound feature toggles (kept off for offline speed).
    domain_malware_scan: bool = Field(default=False)
    vt_enabled: bool = Field(default=False)
    #: Persisted Django secret key; setting it skips MobSF's first-run block
    #: (which is what triggers the JADX download). Auto-generated if unset.
    secret_key: str | None = Field(default=None)


class ProxyConfig(BaseSettings):
    """mitmproxy interception settings."""

    model_config = SettingsConfigDict(env_prefix="MOBIOT_PROXY_", extra="ignore")

    listen_host: str = Field(default="0.0.0.0")
    listen_port: int = Field(default=8080)
    #: One of: ``regular``, ``transparent``, ``wireguard``, ``socks5``.
    mode: str = Field(default="regular")
    #: UDP port used when ``mode == "wireguard"``.
    wireguard_port: int = Field(default=51820)
    web_port: int = Field(default=8081)

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, value: str) -> str:
        allowed = {"regular", "transparent", "wireguard", "socks5", "upstream"}
        if value not in allowed:
            raise ValueError(
                f"proxy.mode must be one of {sorted(allowed)}, got {value!r}"
            )
        return value


class FridaConfig(BaseSettings):
    """Frida / dynamic-instrumentation settings."""

    model_config = SettingsConfigDict(env_prefix="MOBIOT_FRIDA_", extra="ignore")

    #: Directory holding downloaded frida-server binaries for push-to-device.
    server_dir: Path | None = Field(default=None)
    #: Remote frida gadget/server host:port (for USB use, leave default).
    device_id: str | None = Field(default=None)


class Config(BaseSettings):
    """Top-level mobiot configuration."""

    model_config = SettingsConfigDict(env_prefix="MOBIOT_", extra="ignore")

    #: Directory for run artefacts (reports, pcaps, keys, logs).
    workspace: Path = Field(default_factory=lambda: Path(_DIRS.user_data_dir))
    log_level: str = Field(default="INFO")

    mobsf: MobSFConfig = Field(default_factory=MobSFConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    frida: FridaConfig = Field(default_factory=FridaConfig)

    # -- derived workspace sub-directories -------------------------------

    @property
    def reports_dir(self) -> Path:
        return self.workspace / "reports"

    @property
    def captures_dir(self) -> Path:
        return self.workspace / "captures"

    @property
    def certs_dir(self) -> Path:
        return self.workspace / "certs"

    @property
    def logs_dir(self) -> Path:
        return self.workspace / "logs"

    @property
    def network_dir(self) -> Path:
        return self.workspace / "network"

    def ensure_dirs(self) -> None:
        """Create every workspace sub-directory if missing (idempotent)."""
        for path in (
            self.workspace,
            self.reports_dir,
            self.captures_dir,
            self.certs_dir,
            self.logs_dir,
            self.network_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigurationError(f"Invalid TOML in {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigurationError(f"Cannot read config {path}: {exc}") from exc


def resolve_config_path(explicit: Path | str | None = None) -> Path | None:
    """Return the config file path to load, or ``None`` if there is none.

    Precedence: ``explicit`` -> ``$MOBIOT_CONFIG`` -> default path if it exists.
    """
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigurationError(f"Config file not found: {path}")
        return path
    env_path = os.environ.get("MOBIOT_CONFIG")
    if env_path:
        path = Path(env_path).expanduser()
        if not path.is_file():
            raise ConfigurationError(f"$MOBIOT_CONFIG not found: {path}")
        return path
    if DEFAULT_CONFIG_PATH.is_file():
        return DEFAULT_CONFIG_PATH
    return None


def load_config(
    config_path: Path | str | None = None, **overrides: Any
) -> Config:
    """Build a :class:`Config` from file, environment and explicit overrides.

    Args:
        config_path: Optional explicit TOML path.
        **overrides: Values that take precedence over everything else. Nested
            engine sections may be passed as dicts, e.g.
            ``load_config(mobsf={"port": 8100})``.
    """
    data: dict[str, Any] = {}
    path = resolve_config_path(config_path)
    if path is not None:
        data = _read_toml(path)

    # Merge overrides (shallow-merge nested engine sections).
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key] = {**data[key], **value}
        else:
            data[key] = value

    try:
        config = Config(**data)
    except Exception as exc:  # pydantic ValidationError and friends
        raise ConfigurationError(str(exc)) from exc

    config.workspace = config.workspace.expanduser()
    return config
