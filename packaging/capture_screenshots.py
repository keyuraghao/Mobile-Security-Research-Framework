#!/usr/bin/env python3
"""Regenerate the README screenshots from the current desktop app.

Drives the real GUI the way a user would: scans a sample APK in the Static tab,
waits for the real results, opens a file in the Files browser, lets the scan's
findings flow into the Findings tab, then saves one picture per view. Run it
before each release so the README never shows an old UI.

Usage (from the repo root, inside the project venv):
    QT_QPA_PLATFORM=offscreen python packaging/capture_screenshots.py \
        [--apk Test_Aplication/diva-beta.apk] [--out docs/screenshots]
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent
WIDTH, HEIGHT = 1280, 800


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apk", default=str(ROOT / "Test_Aplication" / "diva-beta.apk"))
    ap.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    ap.add_argument("--scan-timeout", type=float, default=1200.0)
    args = ap.parse_args()

    from PyQt6.QtCore import QThreadPool
    from PyQt6.QtWidgets import QApplication

    from msrf.config import load_config
    from msrf.gui import theme
    from msrf.gui.emulator_view import EmulatorView
    from msrf.gui.main import MainWindow

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    app = QApplication(sys.argv)
    app.setApplicationName("msrf")
    app.setApplicationDisplayName("Mobile Security and Research Framework")
    theme.apply(app, "light")

    # A neutral, fixed demo workspace so the pictures never show the
    # developer's home folder; the APK is scanned from a copy inside it.
    demo = Path(tempfile.gettempdir()) / "msrf-demo"
    shutil.rmtree(demo, ignore_errors=True)
    cfg = load_config(workspace=demo)
    cfg.ensure_dirs()
    apk = demo / "samples" / Path(args.apk).name
    apk.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.apk, apk)
    win = MainWindow(cfg)
    win.resize(WIDTH, HEIGHT)
    win.show()

    def pump(secs: float = 0.3) -> None:
        end = time.monotonic() + secs
        while time.monotonic() < end:
            app.processEvents()
            time.sleep(0.02)

    def wait_until(cond, timeout: float, what: str) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            app.processEvents()
            if cond():
                return
            time.sleep(0.05)
        raise SystemExit(f"Timed out waiting for {what}")

    def settle() -> None:
        QThreadPool.globalInstance().waitForDone(60000)
        pump(0.5)

    def tab(title: str) -> int:
        for i in range(win.tabs.count()):
            if win.tabs.tabText(i) == title:
                win.tabs.setCurrentIndex(i)
                pump()
                return i
        raise SystemExit(f"No tab named {title!r}")

    def shot(name: str) -> None:
        pump(0.4)
        path = out / name
        win.grab().save(str(path))
        print(f"  saved {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")

    # (No Dashboard picture: it lists local tool paths and the host's LAN IP.)
    settle()

    # Static analysis: real scan of the sample APK.
    sast = win.sast_view
    tab("Static (SAST)")
    sast.path.setText(str(apk))
    print(f"Scanning {apk} (this runs every MobSF analyzer; can take a few minutes)...")
    sast._scan()
    wait_until(lambda: "security score" in sast.summary.text()
               or "failed" in sast.summary.text().lower(),
               args.scan_timeout, "the scan to finish")
    if "failed" in sast.summary.text().lower():
        raise SystemExit(sast.summary.text())
    settle()

    def sast_sub(title: str) -> None:
        for i in range(sast.tabs.count()):
            if sast.tabs.tabText(i) == title:
                sast.tabs.setCurrentIndex(i)
                pump()
                return
        raise SystemExit(f"No SAST sub-tab {title!r}")

    sast_sub("Findings")
    shot("02_sast_findings.png")
    sast_sub("Permissions")
    shot("03_sast_permissions.png")
    sast_sub("Code Analysis")
    shot("04_sast_code.png")

    # Files: open AndroidManifest.xml in the internal file browser.
    sast_sub("Files")
    tree = sast.file_tree
    target = None
    for i in range(tree.topLevelItemCount()):
        if tree.topLevelItem(i).text(0) == "AndroidManifest.xml":
            target = tree.topLevelItem(i)
            break
    if target is not None:
        tree.setCurrentItem(target)
        target.setSelected(True)
        sast._open_file()
        wait_until(lambda: not sast.viewer.toPlainText().startswith("Loading"),
                   60, "the file viewer")
    shot("05_sast_files.png")

    # Frida hook library: run the SSL-pinning bypass on the built-in simulator.
    from msrf.gui.hooks_view import HooksView
    hooks = win.tabs.widget(tab("Frida Hooks"))
    assert isinstance(hooks, HooksView)
    i = hooks.combo.findData("ssl-pinning-bypass")
    if i >= 0:
        hooks.combo.setCurrentIndex(i)
    hooks._lib_run()
    settle()
    shot("06_frida_hooks.png")

    # Dynamic: run a technique against the simulator so the output pane is real.
    dast = win.tabs.widget(tab("Dynamic (DAST)"))
    labels = [dast.technique.itemText(k) for k in range(dast.technique.count())]
    for want in ("apps", "applications", "processes"):
        hit = next((k for k, lab in enumerate(labels) if want in lab.lower()), None)
        if hit is not None:
            dast.technique.setCurrentIndex(hit)
            break
    dast._run()
    settle()
    shot("07_dast.png")

    tab("Help")
    shot("08_help.png")

    # Emulator: run a real Status so the live log/activity have content.
    idx = tab("Emulator")
    emu = win.tabs.widget(idx)
    assert isinstance(emu, EmulatorView)
    emu._run("status")
    settle()
    shot("09_emulator.png")

    # Findings: the scan's findings were auto-imported.
    win.findings_view.refresh()
    settle()
    tab("Findings")
    shot("10_findings.png")

    # Theme pair on the SAST findings view.
    tab("Static (SAST)")
    sast_sub("Findings")
    shot("11_theme_light.png")
    theme.apply(app, "dark")
    pump(0.5)
    shot("12_theme_dark.png")
    theme.apply(app, "light")

    settle()
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
