# PyInstaller spec for the fully self-contained mobiot desktop app.
# Bundles MobSF (+ its vendored analysers and data), apkid rules, Frida,
# mitmproxy, objection and the mobiot package so nothing is downloaded at runtime.
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas, binaries, hiddenimports = [], [], []

# Packages whose code + data files must all ship.
for pkg in ("mobiot", "mobsf", "apkid", "apksigtool"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# Submodules that are imported dynamically.
for pkg in ("mitmproxy", "objection", "frida", "frida_tools", "django"):
    try:
        hiddenimports += collect_submodules(pkg)
    except Exception:
        pass

# MobSF's Django apps are referenced by string in settings.INSTALLED_APPS.
hiddenimports += [
    "mobsf.MobSF",
    "mobsf.StaticAnalyzer",
    "mobsf.DynamicAnalyzer",
    "mobsf.MalwareAnalyzer",
]

# Optionally bundle a vendor/ tree of native tools (jre, jadx, adb, frida-server)
# populated by the release build; harmless when absent.
import os
if os.path.isdir("vendor"):
    for root, _dirs, files in os.walk("vendor"):
        for f in files:
            full = os.path.join(root, f)
            datas.append((full, os.path.join(*full.split(os.sep)[:-1]) or "vendor"))

a = Analysis(
    ["packaging/mobiot_app.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="mobiot",
    console=False,
    disable_windowed_traceback=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="mobiot",
)
