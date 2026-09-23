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

# Curated, commonly-used Xposed/LSPosed modules for mobile pentesting, mapped to
# their GitHub repo. The latest release APK is resolved at install time (via the
# GitHub API) so links never go stale; add your own via add_module.
CURATED_MODULES: dict[str, str] = {
    "JustTrustMe": "Fuzion24/JustTrustMe",
    "Inspeckage": "ac-pm/Inspeckage",
    "HideMyApplist": "Dr-TSNG/Hide-My-Applist",
    "XPrivacyLua": "M66B/XPrivacyLua",
    "TrustMeAlready": "ViRb3/TrustMeAlready",
}
LSPOSED_REPO = "JingMatrix/LSPosed"  # maintained LSPosed fork with releases
MAGISK_REPO = "topjohnwu/Magisk"  # Magisk app doubles as the root manager/checker


@register
class EmulatorEngine(Engine):
    """Manage a rooted Android emulator (AVD) with Magisk + LSPosed."""

    name = "emulator"
    summary = "Provision and drive a rooted Android emulator (Magisk + LSPosed + modules)."

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.cfg = config.emulator
        self._resolved_image: str | None = None

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
        if self._resolved_image:
            return self._resolved_image
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

    @action("Install the SDK (cmdline-tools, emulator, system image) and create the AVD.",
            background=True, mutating=True)
    def setup(self) -> dict[str, Any]:
        # Auto-provision the Android command-line tools if missing.
        sdkmanager = self._ensure_cmdline_tools()
        avdmanager = self._avdmanager()
        if not avdmanager:
            raise EngineError("emulator", "avdmanager not found after installing cmdline-tools.")
        env = {"ANDROID_SDK_ROOT": str(self._sdk_root())}
        # Accept licenses then install core packages.
        run([sdkmanager, "--licenses"], input_text="y\n" * 30, env=env, check=False, timeout=600)
        for pkg in ("platform-tools", "emulator"):
            self.log.info("Installing SDK package %s", pkg)
            run([sdkmanager, pkg], env=env, check=True, timeout=3600)
        # Resolve a system image that actually exists for the chosen API level.
        available = self._available_system_images(sdkmanager, env)
        image = self._resolve_image(available)
        self._resolved_image = image
        self.log.info("Installing system image %s", image)
        run([sdkmanager, image], env=env, check=True, timeout=3600)
        # (Re)create the AVD against the resolved image.
        run(
            [avdmanager, "create", "avd", "-n", self.cfg.avd_name,
             "-k", image, "--device", "pixel_5", "--force"],
            input_text="no\n", env=env, check=True, timeout=300,
        )
        return {"created": True, "avd": self.cfg.avd_name, "image": image}

    def _available_system_images(self, sdkmanager: str, env: dict[str, str]) -> set[str]:
        out = run([sdkmanager, "--list"], env=env, check=False, timeout=600)
        images: set[str] = set()
        for line in (out.stdout + out.stderr).splitlines():
            tok = line.strip().split("|")[0].strip()
            if tok.startswith("system-images;"):
                images.add(tok)
        return images

    def _resolve_image(self, available: set[str]) -> str:
        api = self.cfg.api_level
        want = self._image_pkg()
        if want in available:
            return want
        types = [self.cfg.image_type, "google_apis", "google_apis_playstore",
                 "default", "aosp_atd", "google_atd"]
        abis = [self.cfg.abi, "x86_64", "x86", "arm64-v8a"]
        for t in dict.fromkeys(types):
            for a in dict.fromkeys(abis):
                cand = f"system-images;android-{api};{t};{a}"
                if cand in available:
                    return cand
        options = sorted(i for i in available if f"android-{api};" in i)
        if options:
            return options[0]
        # Nothing for this API: report what IS available near it.
        near = sorted({i.split(";")[1] for i in available})
        raise EngineError(
            "emulator",
            f"No system image exists for API {api}. Available API levels with "
            f"images: {', '.join(a.replace('android-', '') for a in near)}. "
            "Pick one of those (x86_64 images generally start around API 21).",
        )

    @action("List Android system images available to install (optionally for one API).")
    def list_images(self, api_level: int | None = None) -> dict[str, Any]:
        sdkmanager = self._ensure_cmdline_tools()
        env = {"ANDROID_SDK_ROOT": str(self._sdk_root())}
        images = sorted(self._available_system_images(sdkmanager, env))
        if api_level is not None:
            images = [i for i in images if f"android-{api_level};" in i]
        return {"count": len(images), "images": images}

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

    def _latest_asset(
        self, repo: str, exts: tuple[str, ...], prefer: tuple[str, ...] = ()
    ) -> str:
        """Resolve the latest release's asset URL matching one of ``exts``.

        Prefers assets whose name contains all of ``prefer`` and avoids debug
        builds when a non-debug asset exists.
        """
        import httpx

        api = f"https://api.github.com/repos/{repo}/releases/latest"
        try:
            r = httpx.get(
                api, timeout=60, follow_redirects=True,
                headers={"User-Agent": "msrf", "Accept": "application/vnd.github+json"},
            )
            r.raise_for_status()
            assets = r.json().get("assets", [])
        except Exception as exc:
            raise EngineError("emulator", f"Cannot query releases for {repo}: {exc}") from exc
        matches = [a for a in assets if a.get("name", "").lower().endswith(exts)]
        if not matches:
            raise EngineError("emulator", f"No {exts} asset in the latest release of {repo}.")
        if prefer:
            pref = [a for a in matches if all(p in a["name"].lower() for p in prefer)]
            if pref:
                return pref[0]["browser_download_url"]
        non_debug = [a for a in matches if "debug" not in a["name"].lower()]
        return (non_debug or matches)[0]["browser_download_url"]

    @action("Install LSPosed (Zygisk) into the rooted emulator.", background=True, mutating=True)
    def install_lsposed(self) -> dict[str, Any]:
        adb = self._require_running_adb()
        url = self._latest_asset(LSPOSED_REPO, (".zip",), prefer=("zygisk", "release"))
        zip_path = self._download(url, self.config.workspace / "modules" / "LSPosed.zip")
        remote = "/data/local/tmp/LSPosed.zip"
        run([adb, "push", str(zip_path), remote], check=False)
        # Flash via Magisk (requires Magisk installed by root()).
        out = run([adb, "shell", "su", "-c", f"magisk --install-module {remote}"], check=False)
        return {"attempted": True, "source": url, "output": (out.stdout + out.stderr)[-1000:]}

    @action("Install curated common Xposed modules (or a chosen subset).",
            background=True, mutating=True)
    def install_modules(self, names: list[str] | None = None) -> dict[str, Any]:
        adb = self._require_running_adb()
        selected = names or list(CURATED_MODULES)
        results = {}
        for name in selected:
            repo = CURATED_MODULES.get(name)
            if not repo:
                results[name] = "unknown module"
                continue
            try:
                url = self._latest_asset(repo, (".apk",))
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

    @action("Install the Magisk app (root manager + checker) for verification.", mutating=True)
    def install_root_checker(self) -> dict[str, Any]:
        adb = self._require_running_adb()
        url = self._latest_asset(MAGISK_REPO, (".apk",), prefer=("release",))
        apk = self._download(url, self.config.workspace / "modules" / "Magisk.apk")
        out = run([adb, "install", "-r", str(apk)], check=False)
        return {"source": url, "output": out.stdout.strip()[:200]}

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
        # Use httpx (bundled, verifies via certifi) so downloads work inside the
        # frozen app where urllib has no CA bundle.
        import httpx

        if not url.lower().startswith("https://"):
            raise EngineError("emulator", f"Refusing non-https download URL: {url}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_file() and dest.stat().st_size > 0:
            return dest
        self.log.info("Downloading %s", url)
        try:
            with httpx.stream(
                "GET", url, follow_redirects=True, timeout=600,
                headers={"User-Agent": "msrf"},
            ) as resp:
                resp.raise_for_status()
                with dest.open("wb") as fh:
                    for chunk in resp.iter_bytes(65536):
                        fh.write(chunk)
        except Exception as exc:
            dest.unlink(missing_ok=True)
            raise EngineError("emulator", f"Download failed for {url}: {exc}") from exc
        return dest

    # -- SDK bootstrap ---------------------------------------------------

    _CLT_VERSION = "11076708"

    def _ensure_cmdline_tools(self) -> str:
        """Return sdkmanager, auto-installing the Android command-line tools.

        Downloads Google's command-line tools into the SDK root and lays them out
        at ``cmdline-tools/latest`` (the layout sdkmanager expects), using the
        bundled JRE for Java.
        """
        existing = self._sdkmanager()
        if existing:
            return existing
        import shutil
        import zipfile

        from ..platform_utils import os_name

        plat = {"windows": "win", "macos": "mac", "linux": "linux"}.get(os_name(), "linux")
        url = (
            "https://dl.google.com/android/repository/"
            f"commandlinetools-{plat}-{self._CLT_VERSION}_latest.zip"
        )
        root = self._sdk_root()
        root.mkdir(parents=True, exist_ok=True)
        zpath = root / "cmdline-tools.zip"
        self._download(url, zpath)
        tmp = root / "_clt_tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        with zipfile.ZipFile(zpath) as zf:
            zf.extractall(tmp)
        latest = root / "cmdline-tools" / "latest"
        latest.parent.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(latest, ignore_errors=True)
        shutil.move(str(tmp / "cmdline-tools"), str(latest))
        shutil.rmtree(tmp, ignore_errors=True)
        zpath.unlink(missing_ok=True)
        # Make bin scripts executable on POSIX.
        if not IS_WINDOWS:
            import contextlib

            for f in (latest / "bin").glob("*"):
                with contextlib.suppress(OSError):
                    f.chmod(0o755)
        found = self._sdkmanager()
        if not found:
            raise EngineError("emulator", "Installed command-line tools but sdkmanager still not found.")
        return found
