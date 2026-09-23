"""Emulator engine: a managed, rooted Android emulator for dynamic pentesting.

Provisions and drives an Android Virtual Device (AVD) so the target app can be
run and observed with a rooted, instrumented Android:

* ``setup``     - install the SDK packages (emulator + system image) and create
                  the AVD.
* ``start`` / ``stop`` - boot / kill the emulator and connect adb.
* ``root``      - root the AVD's system image with Magisk (via rootAVD).
* ``install_lsposed`` / ``install_modules`` - install LSPosed and a curated set
  of common Xposed modules for pentesting; ``add_module`` adds your own.
* ``install_root_checker`` - install a root-checker app.
* ``provision`` - run the whole pipeline end to end.

A bootable rooted Android is large (multi-GB system image) and requires host
virtualization (KVM on Linux, HAXM/WHPX on Windows, Hypervisor.framework on
macOS), so everything here provisions on the user's machine on first run; it is
not bundled in the app. Steps are best-effort and report detailed status.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..config import Config
from ..exceptions import EngineError
from ..platform_utils import IS_WINDOWS, run, spawn, which
from ..registry import register
from .base import Engine, action

# Curated, commonly-used Xposed/LSPosed modules for mobile pentesting. Each is
# downloaded from its GitHub release on demand; add your own via add_module.
CURATED_MODULES: dict[str, str] = {
    "JustTrustMe": "https://github.com/Fuzion24/JustTrustMe/releases/download/v2.0/JustTrustMe.apk",
    "Inspeckage": "https://github.com/ac-pm/Inspeckage/releases/download/v2.4/Inspeckage-2.4.apk",
    "HideMyApplist": "https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest/download/HMA-release.apk",
}
ROOT_CHECKER_URL = (
    "https://f-droid.org/repo/com.joeykrim.rootcheck_1.apk"  # placeholder; user can swap
)


@register
class EmulatorEngine(Engine):
    """Manage a rooted Android emulator (AVD) with Magisk + LSPosed."""

    name = "emulator"
    summary = "Provision and drive a rooted Android emulator (Magisk + LSPosed + modules)."

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.cfg = config.emulator

    # -- SDK discovery ---------------------------------------------------

    def _sdk_root(self) -> Path:
        if self.cfg.sdk_root:
            return Path(self.cfg.sdk_root)
        for env in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
            val = os.environ.get(env)
            if val and Path(val).is_dir():
                return Path(val)
        return self.config.workspace / "android-sdk"

    def _tool(self, name: str, *subdirs: str) -> str | None:
        """Find an SDK tool under known SDK sub-directories, else on PATH."""
        root = self._sdk_root()
        exe = f"{name}.exe" if IS_WINDOWS and name in {"adb", "emulator"} else name
        bat = f"{name}.bat" if IS_WINDOWS else name
        candidates = []
        for sub in subdirs:
            candidates += [root / sub / exe, root / sub / bat]
        for c in candidates:
            if c.is_file():
                return str(c)
        return which(name)

    def _sdkmanager(self) -> str | None:
        return self._tool("sdkmanager", "cmdline-tools/latest/bin", "cmdline-tools/bin", "tools/bin")

    def _avdmanager(self) -> str | None:
        return self._tool("avdmanager", "cmdline-tools/latest/bin", "cmdline-tools/bin", "tools/bin")

    def _emulator(self) -> str | None:
        return self._tool("emulator", "emulator")

    def _adb(self) -> str | None:
        return self._tool("adb", "platform-tools")

    def _image_pkg(self) -> str:
        return f"system-images;android-{self.cfg.api_level};{self.cfg.image_type};{self.cfg.abi}"

    # -- status ----------------------------------------------------------

    def preflight(self) -> dict[str, Any]:
        return self.status()

    @action("Report emulator/SDK status: tools, AVD, running and rooted state.")
    def status(self) -> dict[str, Any]:
        adb = self._adb()
        running = False
        rooted = False
        if adb:
            devs = run([adb, "devices"], check=False)
            running = any(
                line.strip().endswith("device") and line.startswith("emulator")
                for line in devs.stdout.splitlines()
            )
            if running:
                r = run([adb, "shell", "su", "-c", "id"], check=False)
                rooted = "uid=0" in r.stdout
        return {
            "engine": self.name,
            "ready": bool(self._emulator() and self._avdmanager()),
            "details": {
                "sdk_root": str(self._sdk_root()),
                "sdkmanager": self._sdkmanager(),
                "avdmanager": self._avdmanager(),
                "emulator": self._emulator(),
                "adb": self._adb(),
                "avd": self.cfg.avd_name,
                "avd_exists": self._avd_exists(),
                "running": running,
                "rooted": rooted,
                "system_image": self._image_pkg(),
            },
        }

    def _avd_exists(self) -> bool:
        emu = self._emulator()
        if not emu:
            return False
        out = run([emu, "-list-avds"], check=False)
        return self.cfg.avd_name in out.stdout.split()

    # -- setup / lifecycle ----------------------------------------------

    @action("Install the SDK packages (emulator + system image) and create the AVD.",
            background=True, mutating=True)
    def setup(self) -> dict[str, Any]:
        sdkmanager = self._sdkmanager()
        avdmanager = self._avdmanager()
        if not sdkmanager or not avdmanager:
            raise EngineError(
                "emulator",
                "Android SDK command-line tools not found. Install Android "
                "'cmdline-tools' and set ANDROID_SDK_ROOT (or emulator.sdk_root). "
                f"Looked under {self._sdk_root()}.",
            )
        image = self._image_pkg()
        env = {"ANDROID_SDK_ROOT": str(self._sdk_root())}
        # Accept licenses then install packages.
        run([sdkmanager, "--licenses"], input_text="y\n" * 20, env=env, check=False, timeout=600)
        for pkg in ("platform-tools", "emulator", image):
            self.log.info("Installing SDK package %s", pkg)
            run([sdkmanager, pkg], env=env, check=True, timeout=3600)
        if not self._avd_exists():
            run(
                [avdmanager, "create", "avd", "-n", self.cfg.avd_name,
                 "-k", image, "--device", "pixel_5", "--force"],
                input_text="no\n", env=env, check=True, timeout=300,
            )
        return {"created": True, "avd": self.cfg.avd_name, "image": image}

    @action("Boot the emulator and wait for Android to come up.", background=True, mutating=True)
    def start(self) -> dict[str, Any]:
        emu = self._emulator()
        adb = self._adb()
        if not emu or not adb:
            raise EngineError("emulator", "Emulator/adb not found; run 'emulator setup' first.")
        if not self._avd_exists():
            raise EngineError("emulator", f"AVD {self.cfg.avd_name!r} does not exist; run setup.")
        args = [emu, "-avd", self.cfg.avd_name, "-writable-system", "-no-snapshot"]
        if self.cfg.headless:
            args += ["-no-window", "-no-audio"]
        log = self.config.logs_dir / "emulator.log"
        spawn(args, stdout=log)
        # Wait for boot.
        run([adb, "wait-for-device"], check=False, timeout=self.cfg.boot_timeout)
        import time

        deadline = time.time() + self.cfg.boot_timeout
        while time.time() < deadline:
            done = run([adb, "shell", "getprop", "sys.boot_completed"], check=False)
            if done.stdout.strip() == "1":
                return {"started": True, "avd": self.cfg.avd_name, "log": str(log)}
            time.sleep(3)
        raise EngineError("emulator", f"Emulator did not finish booting in {self.cfg.boot_timeout}s.")

    @action("Stop the running emulator.", mutating=True)
    def stop(self) -> dict[str, Any]:
        adb = self._adb()
        if adb:
            run([adb, "emu", "kill"], check=False)
        return {"stopped": True}

    # -- rooting / modules ----------------------------------------------

    @action("Root the running emulator with Magisk (via rootAVD).", background=True, mutating=True)
    def root(self) -> dict[str, Any]:
        """Patch the AVD ramdisk with Magisk using the rootAVD script.

        Requires the emulator installed and booted at least once. rootAVD is
        downloaded into the workspace on first use.
        """
        root_dir = self.config.workspace / "rootAVD"
        script = self._ensure_rootavd(root_dir)
        sdk = str(self._sdk_root())
        env = {"ANDROID_SDK_ROOT": sdk}
        # rootAVD lists ramdisks; the typical invocation patches the AVD's image.
        image = self._image_pkg().replace(";", "/")
        ramdisk = f"system-images/{image}/ramdisk.img"
        result = run(
            ["bash", str(script), ramdisk] if not IS_WINDOWS else [str(script), ramdisk],
            cwd=root_dir, env=env, check=False, timeout=1800,
        )
        return {
            "attempted": True,
            "ramdisk": ramdisk,
            "output_tail": (result.stdout + result.stderr)[-1500:],
            "note": "Reboot the emulator after rooting, then verify with 'emulator status'.",
        }

    def _ensure_rootavd(self, dest: Path) -> Path:
        script = dest / ("rootAVD.bat" if IS_WINDOWS else "rootAVD.sh")
        if script.is_file():
            return script
        git = which("git")
        if not git:
            raise EngineError(
                "emulator",
                "git is required to fetch rootAVD, or place rootAVD in " + str(dest),
            )
        run([git, "clone", "--depth", "1",
             "https://gitlab.com/newbit/rootAVD.git", str(dest)], check=True, timeout=600)
        return script

    @action("Install LSPosed (Zygisk) into the rooted emulator.", background=True, mutating=True)
    def install_lsposed(self) -> dict[str, Any]:
        adb = self._require_running_adb()
        zip_path = self._download(
            "https://github.com/LSPosed/LSPosed/releases/latest/download/LSPosed-v1.9.2-zygisk-release.zip",
            self.config.workspace / "modules" / "LSPosed.zip",
        )
        remote = "/data/local/tmp/LSPosed.zip"
        run([adb, "push", str(zip_path), remote], check=False)
        # Flash via Magisk (requires Magisk installed by root()).
        out = run([adb, "shell", "su", "-c", f"magisk --install-module {remote}"], check=False)
        return {"attempted": True, "output": (out.stdout + out.stderr)[-1000:]}

    @action("Install curated common Xposed modules (or a chosen subset).",
            background=True, mutating=True)
    def install_modules(self, names: list[str] | None = None) -> dict[str, Any]:
        adb = self._require_running_adb()
        selected = names or list(CURATED_MODULES)
        results = {}
        for name in selected:
            url = CURATED_MODULES.get(name)
            if not url:
                results[name] = "unknown module"
                continue
            try:
                apk = self._download(url, self.config.workspace / "modules" / f"{name}.apk")
                out = run([adb, "install", "-r", str(apk)], check=False)
                results[name] = "installed" if "Success" in out.stdout else out.stdout.strip()[:120]
            except Exception as exc:
                results[name] = f"failed: {exc}"
        return {"modules": results, "note": "Enable modules in the LSPosed manager app."}

    @action("List the curated modules available to install.")
    def list_modules(self) -> dict[str, Any]:
        return {"curated": list(CURATED_MODULES)}

    @action("Add and install a custom Xposed module APK.", mutating=True)
    def add_module(self, apk_path: str) -> dict[str, Any]:
        adb = self._require_running_adb()
        p = Path(apk_path).expanduser()
        if not p.is_file():
            raise EngineError("emulator", f"APK not found: {p}")
        out = run([adb, "install", "-r", str(p)], check=False)
        return {"apk": str(p), "output": out.stdout.strip()[:200]}

    @action("Install a root-checker app for quick verification.", mutating=True)
    def install_root_checker(self) -> dict[str, Any]:
        adb = self._require_running_adb()
        apk = self._download(ROOT_CHECKER_URL, self.config.workspace / "modules" / "rootchecker.apk")
        out = run([adb, "install", "-r", str(apk)], check=False)
        return {"output": out.stdout.strip()[:200]}

    @action("Full pipeline: setup, start, root, LSPosed, modules, root checker.",
            background=True, mutating=True)
    def provision(self, modules: list[str] | None = None) -> dict[str, Any]:
        steps: dict[str, Any] = {}
        steps["setup"] = self.setup()
        steps["start"] = self.start()
        steps["root"] = self.root()
        steps["start_after_root"] = self.start()
        steps["lsposed"] = self.install_lsposed()
        steps["modules"] = self.install_modules(modules)
        steps["root_checker"] = self.install_root_checker()
        return {"provisioned": True, "steps": steps}

    # -- helpers ---------------------------------------------------------

    def _require_running_adb(self) -> str:
        adb = self._adb()
        if not adb:
            raise EngineError("emulator", "adb not found; run 'emulator setup' first.")
        return adb

    def _download(self, url: str, dest: Path) -> Path:
        import urllib.request

        if not url.lower().startswith("https://"):
            raise EngineError("emulator", f"Refusing non-https download URL: {url}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_file() and dest.stat().st_size > 0:
            return dest
        self.log.info("Downloading %s", url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mobiot"})  # noqa: S310
            with urllib.request.urlopen(req, timeout=600) as resp:  # noqa: S310
                dest.write_bytes(resp.read())
        except Exception as exc:
            raise EngineError("emulator", f"Download failed for {url}: {exc}") from exc
        return dest
