"""On-demand provisioning of heavy runtime assets.

Nothing large is shipped inside the msrf package. Assets such as the
frida-server binary (tens of MB, arch-specific, version-locked) are downloaded
on first use and cached in the workspace. This keeps the published package small
and avoids vendoring binaries that would otherwise go stale against the installed
Frida version.
"""
from __future__ import annotations

import lzma
from pathlib import Path

import httpx

from .exceptions import EngineError
from .logging import get_logger

log = get_logger("provisioning")

_FRIDA_RELEASE = (
    "https://github.com/frida/frida/releases/download/"
    "{version}/frida-server-{version}-android-{arch}.xz"
)


def installed_frida_version() -> str | None:
    """Return the version of the installed Frida Python package, if any."""
    try:
        import frida

        return frida.__version__
    except Exception:
        return None


def ensure_frida_server(
    arch: str,
    cache_dir: Path,
    *,
    version: str | None = None,
    local_dir: Path | None = None,
    timeout: float = 300.0,
) -> Path:
    """Return a path to a frida-server binary for ``arch``, fetching if needed.

    Resolution order:
      1. A matching binary already in ``local_dir`` (e.g. the user's Frida
         folder) — used as-is, nothing is downloaded.
      2. A previously cached download in ``cache_dir``.
      3. A fresh download from the Frida GitHub release matching the installed
         Frida version (or ``version`` if given), decompressed into the cache.

    Args:
        arch: frida-server arch token (``arm64``, ``arm``, ``x86_64``, ``x86``).
        cache_dir: Directory to cache downloaded binaries.
        version: Frida version to fetch; defaults to the installed Python
            package version so client and server always match.
        local_dir: Optional directory of pre-supplied frida-server binaries.
        timeout: Download timeout in seconds.

    Raises:
        EngineError: If no version can be determined or the download fails.
    """
    # 1. Pre-supplied local binary.
    if local_dir:
        found = _find_local(Path(local_dir), arch)
        if found:
            log.info("Using local frida-server: %s", found)
            return found

    version = version or installed_frida_version()
    if not version:
        raise EngineError(
            "provisioning",
            "Cannot determine Frida version to fetch frida-server. "
            "Install Frida or pass an explicit version.",
        )

    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / f"frida-server-{version}-android-{arch}"

    # 2. Cached download.
    if target.is_file() and target.stat().st_size > 0:
        return target

    # 3. Download + decompress.
    url = _FRIDA_RELEASE.format(version=version, arch=arch)
    log.info("Downloading frida-server %s (%s) from %s", version, arch, url)
    try:
        with httpx.stream("GET", url, follow_redirects=True, timeout=timeout) as resp:
            resp.raise_for_status()
            compressed = target.with_suffix(".xz")
            with compressed.open("wb") as fh:
                for chunk in resp.iter_bytes(chunk_size=65536):
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        raise EngineError(
            "provisioning",
            f"Failed to download frida-server from {url}: {exc}",
        ) from exc

    try:
        with lzma.open(compressed) as src, target.open("wb") as dst:
            dst.write(src.read())
    except lzma.LZMAError as exc:
        raise EngineError("provisioning", f"Failed to decompress {compressed}: {exc}") from exc
    finally:
        compressed.unlink(missing_ok=True)

    target.chmod(0o755)
    return target


def _find_local(local_dir: Path, arch: str) -> Path | None:
    if not local_dir.is_dir():
        return None
    for candidate in sorted(local_dir.iterdir()):
        name = candidate.name
        if (
            candidate.is_file()
            and "frida-server" in name
            and arch in name
            and not name.endswith(".xz")
        ):
            return candidate
    return None
