#!/usr/bin/env python3
"""Download the native tools msrf bundles into ``vendor/`` for the current OS.

Run before PyInstaller in the release build. Populates:

    vendor/jre/                      Temurin JRE (java)
    vendor/jadx/bin/jadx[.bat]       jadx decompiler
    vendor/platform-tools/adb[.exe]  Android platform-tools
    vendor/frida-server/…            frida-server binaries (all common ABIs)

Cross-platform (Linux/Windows/macOS). Best-effort per tool: a failed download is
logged and skipped so a partial vendor tree still builds (the app degrades for
that one capability rather than failing the whole build).
"""
from __future__ import annotations

import io
import lzma
import platform
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor"
JADX_VERSION = "1.5.0"
FRIDA_ABIS = ["arm64", "arm", "x86_64", "x86"]


def _os() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _download(url: str) -> bytes:
    print(f"  GET {url}", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "msrf-vendor"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()


def _extract_zip(data: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest)


def _extract_tar(data: bytes, dest: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        tf.extractall(dest, filter="data")


def fetch_jre() -> None:
    osname = _os()
    arch = "aarch64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"
    adoptium_os = {"windows": "windows", "macos": "mac", "linux": "linux"}[osname]
    url = (
        f"https://api.adoptium.net/v3/binary/latest/17/ga/"
        f"{adoptium_os}/{arch}/jre/hotspot/normal/eclipse"
    )
    data = _download(url)
    tmp = VENDOR / "_jre_tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    if osname == "windows":
        _extract_zip(data, tmp)
    else:
        _extract_tar(data, tmp)
    # The archive has a single top-level dir; normalize to vendor/jre.
    top = next(p for p in tmp.iterdir() if p.is_dir())
    home = top / "Contents" / "Home" if osname == "macos" and (top / "Contents" / "Home").is_dir() else top
    dest = VENDOR / "jre"
    shutil.rmtree(dest, ignore_errors=True)
    shutil.move(str(home), str(dest))
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"  jre -> {dest}", flush=True)


def fetch_jadx() -> None:
    url = (
        f"https://github.com/skylot/jadx/releases/download/"
        f"v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"
    )
    dest = VENDOR / "jadx"
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    _extract_zip(_download(url), dest)
    for f in (dest / "bin").glob("jadx*"):
        f.chmod(0o755)
    print(f"  jadx -> {dest}", flush=True)


def fetch_platform_tools() -> None:
    osname = _os()
    plat = {"windows": "windows", "macos": "darwin", "linux": "linux"}[osname]
    url = f"https://dl.google.com/android/repository/platform-tools-latest-{plat}.zip"
    tmp = VENDOR / "_pt_tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    _extract_zip(_download(url), tmp)
    dest = VENDOR / "platform-tools"
    shutil.rmtree(dest, ignore_errors=True)
    shutil.move(str(tmp / "platform-tools"), str(dest))
    shutil.rmtree(tmp, ignore_errors=True)
    adb = dest / ("adb.exe" if osname == "windows" else "adb")
    if adb.is_file():
        adb.chmod(0o755)
    print(f"  platform-tools -> {dest}", flush=True)


def fetch_frida_server() -> None:
    try:
        import frida

        version = frida.__version__
    except Exception:
        print("  frida not installed; skipping frida-server", flush=True)
        return
    dest = VENDOR / "frida-server"
    dest.mkdir(parents=True, exist_ok=True)
    for abi in FRIDA_ABIS:
        url = (
            f"https://github.com/frida/frida/releases/download/"
            f"{version}/frida-server-{version}-android-{abi}.xz"
        )
        try:
            data = _download(url)
            out = dest / f"frida-server-{version}-android-{abi}"
            out.write_bytes(lzma.decompress(data))
            out.chmod(0o755)
        except Exception as exc:
            print(f"  skip frida-server {abi}: {exc}", flush=True)
    print(f"  frida-server -> {dest}", flush=True)


def main() -> int:
    VENDOR.mkdir(parents=True, exist_ok=True)
    print(f"Vendoring native tools for {_os()} into {VENDOR}", flush=True)
    for name, fn in (
        ("jre", fetch_jre),
        ("jadx", fetch_jadx),
        ("platform-tools", fetch_platform_tools),
        ("frida-server", fetch_frida_server),
    ):
        try:
            fn()
        except Exception as exc:  # best-effort per tool
            print(f"  WARNING: {name} failed: {exc}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
