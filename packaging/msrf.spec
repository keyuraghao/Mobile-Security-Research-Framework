# PyInstaller spec for the fully self-contained msrf desktop app.
# Bundles MobSF (+ its vendored analysers and data), apkid rules, Frida,
# mitmproxy, objection and the msrf package so nothing is downloaded at runtime.
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas, binaries, hiddenimports = [], [], []

# Packages whose code + data files must all ship (openpyxl/fpdf carry data used
# by the reporting engine; certifi's CA bundle is needed for HTTPS downloads in
# the frozen app; all are imported lazily so must be forced in).
for pkg in ("msrf", "mobsf", "apkid", "apksigtool", "libsast", "openpyxl", "fpdf", "certifi"):
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

# Modules referenced only by string (Django LOGGING/config, DB backends) that
# PyInstaller's static analysis cannot see.
hiddenimports += [
    "colorlog",
    "colorlog.formatter",
    "django.db.backends.sqlite3",
    "django.template.loaders.filesystem",
    "django.template.loaders.app_directories",
]

# Optionally bundle a vendor/ tree of native tools (jre, jadx, adb, frida-server)
# populated by the release build; harmless when absent. Placed under the project
# root (parent of this spec's directory).
import os
_root = os.path.dirname(SPECPATH)
_vendor = os.path.join(_root, "vendor")
if os.path.isdir(_vendor):
    for dirpath, _dirs, files in os.walk(_vendor):
        rel = os.path.relpath(dirpath, _root)  # e.g. vendor/jre/bin
        for f in files:
            datas.append((os.path.join(dirpath, f), rel))

a = Analysis(
    [os.path.join(SPECPATH, "msrf_app.py")],
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

_icon = os.path.join(_root, "src", "msrf", "data", "icon.ico")
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="msrf",
    console=False,
    disable_windowed_traceback=False,
    icon=_icon if os.path.isfile(_icon) else None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="msrf",
)
