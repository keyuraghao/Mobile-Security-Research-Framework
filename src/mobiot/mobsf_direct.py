"""Direct, in-process MobSF static analysis (no HTTP server, no templates).

Instead of running MobSF's Django server and consuming its REST/HTML output, we
configure Django once and call MobSF's analysis facade directly, then render the
raw result dict through our own UI. This is lighter to bundle (no URL/template/
static layer) and gives us full control over presentation.

Facade used (verified against MobSF 4.5.4):
  * android: ``apk_analysis_task(checksum, app_dic, rescan) -> (context, err)``
  * ios:     ``ipa_analysis_task(checksum, app_dic, rescan) -> (context, err)``
  * scoring: ``get_android_dashboard`` / ``get_ios_dashboard`` -> ``appsec``
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .exceptions import EngineError
from .logging import get_logger

log = get_logger("mobsf_direct")

_LOCK = threading.RLock()
_CONFIGURED = False


def is_configured() -> bool:
    return _CONFIGURED


def ensure_configured(
    env: dict[str, str],
    prepare: Callable[[], None],
) -> None:
    """Configure Django + run migrations once for in-process analysis.

    Args:
        env: Environment variables (the MobSF offline profile) to apply before
            Django reads its settings.
        prepare: Callback that prepares the MobSF home dir (jadx wiring etc.).
    """
    global _CONFIGURED
    with _LOCK:
        if _CONFIGURED:
            return
        import os

        for key, value in env.items():
            os.environ[key] = value
        prepare()
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mobsf.MobSF.settings")

        import django

        django.setup()
        from django.core.management import call_command

        # Ensure the schema exists (analysis persists to sqlite under the home).
        call_command("migrate", interactive=False, verbosity=0, run_syncdb=True)
        _CONFIGURED = True
        log.info("MobSF configured for in-process analysis")


_ANDROID_EXTS = {".apk"}
_IOS_EXTS = {".ipa"}


def analyze(
    app_path: str | Path,
    env: dict[str, str],
    prepare: Callable[[], None],
    *,
    rescan: bool = False,
) -> dict[str, Any]:
    """Run MobSF static analysis on ``app_path`` in-process and return the dict.

    Supports Android APK and iOS IPA. Raises :class:`EngineError` on unsupported
    types or analysis failure.
    """
    path = Path(app_path).expanduser()
    if not path.is_file():
        raise EngineError("sast", f"File not found: {path}")
    ext = path.suffix.lower()
    ensure_configured(env, prepare)

    from django.conf import settings
    from mobsf.MobSF.views.scanning import add_to_recent_scan, handle_uploaded_file

    if ext in _ANDROID_EXTS:
        scan_type = "apk"
    elif ext in _IOS_EXTS:
        scan_type = "ipa"
    else:
        raise EngineError(
            "sast",
            f"Unsupported file type {ext!r}. Direct analysis supports .apk and .ipa.",
        )

    with path.open("rb") as handle:
        checksum = handle_uploaded_file(handle, ext)
    add_to_recent_scan(
        {
            "analyzer": "static_analyzer",
            "status": "success",
            "hash": checksum,
            "scan_type": scan_type,
            "file_name": path.name,
        }
    )

    if scan_type == "apk":
        context = _analyze_apk(checksum, path, scan_type, settings, rescan)
    else:
        context = _analyze_ipa(checksum, path, scan_type, settings, rescan)
    context.setdefault("hash", checksum)
    context.setdefault("file_name", path.name)
    context.setdefault("scan_type", scan_type)
    return context


def _base_app_dic(checksum: str, path: Path, settings) -> dict[str, Any]:
    return {
        "dir": Path(settings.BASE_DIR),
        "app_name": path.name,
        "md5": checksum,
        "app_dir": Path(settings.UPLD_DIR) / checksum,
        "tools_dir": (Path(settings.BASE_DIR) / "StaticAnalyzer" / "tools").as_posix(),
        "icon_path": "",
    }


def _analyze_apk(checksum, path, scan_type, settings, rescan) -> dict[str, Any]:
    from mobsf.StaticAnalyzer.views.android.apk import (
        apk_analysis_task,
        initialize_app_dic,
    )
    from mobsf.StaticAnalyzer.views.common.appsec import get_android_dashboard

    app_dic = _base_app_dic(checksum, path, settings)
    initialize_app_dic(app_dic, scan_type)
    context, err = apk_analysis_task(checksum, app_dic, rescan)
    if err:
        raise EngineError("sast", f"APK analysis failed: {err}")
    try:
        context["appsec"] = get_android_dashboard(context, from_ctx=True)
    except Exception as exc:  # scoring is best-effort
        log.debug("appsec dashboard failed: %s", exc)
    return context


def _analyze_ipa(checksum, path, scan_type, settings, rescan) -> dict[str, Any]:
    from mobsf.StaticAnalyzer.views.common.appsec import get_ios_dashboard
    from mobsf.StaticAnalyzer.views.ios.ipa import initialize_app_dic, ipa_analysis_task

    app_dic = _base_app_dic(checksum, path, settings)
    initialize_app_dic(app_dic, scan_type)
    context, err = ipa_analysis_task(checksum, app_dic, rescan)
    if err:
        raise EngineError("sast", f"IPA analysis failed: {err}")
    try:
        context["appsec"] = get_ios_dashboard(context, from_ctx=True)
    except Exception as exc:
        log.debug("ios appsec dashboard failed: %s", exc)
    return context
