"""Format a full MobSF static-analysis result into readable text.

Renders the output of every analyzer MobSF runs (certificate, permissions,
manifest, network security, binary/NDK, code-analysis SAST rules, Android API,
APKID, trackers, domains/URLs/emails, secrets, malware permissions, behaviour,
SBOM, components and files) so the whole analysis appears in one output window.
Defensive against missing/variant keys so it works across app types.
"""
from __future__ import annotations

from typing import Any

_SEV_ORDER = {"high": 0, "warning": 1, "secure": 2, "info": 3, "hotspot": 4}


def _hr(title: str) -> str:
    bar = "=" * max(0, 66 - len(title))
    return f"\n=== {title} {bar}"


def _wrap(text: str, width: int = 100) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: width - 1] + "…"


def format_report(ctx: dict[str, Any]) -> str:
    """Return a full, sectioned textual report for a MobSF result dict."""
    out: list[str] = []
    e = out.append

    # -- summary ---------------------------------------------------------
    e(_hr("APP SUMMARY"))
    e(f"File        : {ctx.get('file_name')}  ({ctx.get('size')})")
    e(f"App name    : {ctx.get('app_name')}   type: {ctx.get('app_type')}")
    e(f"Package     : {ctx.get('package_name')}")
    e(f"Main activity: {ctx.get('main_activity')}")
    e(
        f"SDK         : min {ctx.get('min_sdk')} / target {ctx.get('target_sdk')} "
        f"/ max {ctx.get('max_sdk')}   version {ctx.get('version_name')} "
        f"({ctx.get('version_code')})"
    )
    e(f"MD5         : {ctx.get('md5')}")
    e(f"SHA1        : {ctx.get('sha1')}")
    e(f"SHA256      : {ctx.get('sha256')}")

    # -- security scorecard ---------------------------------------------
    appsec = ctx.get("appsec") or {}
    if appsec:
        e(_hr("SECURITY SCORECARD"))
        e(
            f"Security score: {appsec.get('security_score')}/100   "
            f"trackers: {appsec.get('total_trackers')}"
        )
        for sev in ("high", "warning", "info", "secure", "hotspot"):
            items = appsec.get(sev) or []
            if not items:
                continue
            e(f"\n[{sev.upper()}] ({len(items)})")
            for it in items:
                e(f"  • {it.get('title', it)}")
                if it.get("description"):
                    e(f"      {_wrap(it['description'])}")

    # -- certificate -----------------------------------------------------
    cert = ctx.get("certificate_analysis") or {}
    if cert:
        e(_hr("CERTIFICATE ANALYSIS"))
        if cert.get("certificate_info"):
            for line in str(cert["certificate_info"]).splitlines():
                if line.strip():
                    e(f"  {line.strip()}")
        for finding in cert.get("certificate_findings") or []:
            if isinstance(finding, list | tuple) and len(finding) >= 2:
                sev, title = finding[0], finding[1]
                e(f"  [{sev}] {title}")

    # -- permissions -----------------------------------------------------
    perms = ctx.get("permissions") or {}
    if perms:
        e(_hr(f"PERMISSIONS ({len(perms)})"))
        for name, meta in perms.items():
            status = (meta or {}).get("status", "")
            info = (meta or {}).get("info", "")
            e(f"  [{status}] {name}  {('- ' + info) if info else ''}")

    # -- manifest --------------------------------------------------------
    manifest = (ctx.get("manifest_analysis") or {}).get("manifest_findings") or []
    if manifest:
        e(_hr(f"MANIFEST ANALYSIS ({len(manifest)})"))
        for f in _sorted_by_sev(manifest):
            e(f"  [{f.get('severity')}] {f.get('title')}")
            if f.get("description"):
                e(f"      {_wrap(f['description'])}")

    # -- network security -----------------------------------------------
    net = (ctx.get("network_security") or {}).get("network_findings") or []
    if net:
        e(_hr(f"NETWORK SECURITY ({len(net)})"))
        for f in net:
            e(f"  [{f.get('severity')}] {_wrap(f.get('description') or f)}")

    # -- code analysis (SAST rules) -------------------------------------
    code = (ctx.get("code_analysis") or {}).get("findings") or {}
    if code:
        e(_hr(f"CODE ANALYSIS: SAST rules ({len(code)})"))
        for rule, data in _sorted_code(code):
            meta = (data or {}).get("metadata") or {}
            sev = meta.get("severity", "info")
            desc = meta.get("description", rule)
            e(f"  [{sev}] {rule}: {_wrap(desc)}")
            owasp = meta.get("owasp-mobile") or meta.get("owasp")
            cwe = meta.get("cwe")
            tags = ", ".join(t for t in (cwe, owasp, meta.get("masvs")) if t)
            if tags:
                e(f"      {tags}")
            files = (data or {}).get("files") or {}
            for path, lines in list(files.items())[:8]:
                e(f"      - {path}:{lines}")
            if len(files) > 8:
                e(f"      … +{len(files) - 8} more file(s)")

    # -- binary / NDK ----------------------------------------------------
    binary = ctx.get("binary_analysis") or []
    if binary:
        e(_hr(f"BINARY / NDK ANALYSIS ({len(binary)})"))
        for so in binary:
            e(f"  {so.get('name')}")
            for check in ("nx", "pie", "stack_canary", "relocation_readonly", "rpath", "runpath", "fortify", "symbol"):
                c = so.get(check)
                if isinstance(c, dict) and c.get("severity"):
                    e(f"      [{c['severity']}] {check}: {_wrap(c.get('description') or '')}")

    # -- android api -----------------------------------------------------
    api = ctx.get("android_api") or {}
    if api:
        e(_hr(f"ANDROID API USAGE ({len(api)})"))
        for name, data in api.items():
            meta = (data or {}).get("metadata") or {}
            e(f"  • {meta.get('description', name)}")

    # -- malware permissions --------------------------------------------
    mp = ctx.get("malware_permissions") or {}
    if mp.get("top_malware_permissions") or mp.get("other_abused_permissions"):
        e(_hr("MALWARE PERMISSIONS"))
        for p in mp.get("top_malware_permissions") or []:
            e(f"  [top-abused] {p}")
        for p in mp.get("other_abused_permissions") or []:
            e(f"  [abused] {p}")

    # -- trackers --------------------------------------------------------
    trk = ctx.get("trackers") or {}
    e(_hr(f"TRACKERS ({trk.get('detected_trackers', 0)}/{trk.get('total_trackers', 0)})"))
    for t in trk.get("trackers") or []:
        e(f"  • {t.get('name')}  ({t.get('categories')})")

    # -- domains / urls / emails / secrets ------------------------------
    domains = ctx.get("domains") or {}
    if domains:
        e(_hr(f"DOMAINS ({len(domains)})"))
        for d, meta in list(domains.items())[:60]:
            bad = "MALWARE" if (meta or {}).get("bad") == "yes" else "ok"
            e(f"  [{bad}] {d}")

    urls = ctx.get("urls") or []
    if urls:
        total = sum(len(u.get("urls", [])) for u in urls)
        e(_hr(f"URLs ({total} across {len(urls)} file(s))"))
        for u in urls[:40]:
            for link in (u.get("urls") or [])[:5]:
                e(f"  {link}   ({u.get('path')})")

    emails = ctx.get("emails") or []
    if emails:
        e(_hr(f"EMAILS ({len(emails)})"))
        for em in emails[:40]:
            e(f"  {em.get('emails') if isinstance(em, dict) else em}")

    secrets = ctx.get("secrets") or []
    if secrets:
        e(_hr(f"POSSIBLE HARDCODED SECRETS ({len(secrets)})"))
        for s in secrets:
            e(f"  {_wrap(s, 120)}")

    firebase = ctx.get("firebase_urls") or []
    if firebase:
        e(_hr(f"FIREBASE ({len(firebase)})"))
        for f in firebase:
            e(f"  {f}")

    # -- apkid -----------------------------------------------------------
    apkid = ctx.get("apkid") or {}
    if apkid:
        e(_hr("APKID (compiler / packer / obfuscator)"))
        for dexname, data in apkid.items():
            e(f"  {dexname}")
            for key, vals in (data or {}).items():
                e(f"      {key}: {', '.join(vals) if isinstance(vals, list) else vals}")

    # -- behaviour -------------------------------------------------------
    behaviour = ctx.get("behaviour") or {}
    if behaviour:
        e(_hr(f"BEHAVIOUR ({len(behaviour)})"))
        for _bid, data in list(behaviour.items())[:40]:
            meta = (data or {}).get("metadata") or {}
            e(f"  • {meta.get('description', _bid)}")

    # -- sbom ------------------------------------------------------------
    sbom = (ctx.get("sbom") or {}).get("sbom_packages") or []
    if sbom:
        e(_hr(f"SBOM: dependencies ({len(sbom)})"))
        for pkg in sbom[:60]:
            if isinstance(pkg, dict):
                e(f"  {pkg.get('name')} {pkg.get('version', '')}")
            else:
                e(f"  {pkg}")

    # -- components ------------------------------------------------------
    e(_hr("COMPONENTS"))
    for label in ("activities", "services", "receivers", "providers"):
        comp = ctx.get(label) or []
        e(f"  {label}: {len(comp)}")
    exported = ctx.get("exported_activities") or []
    if exported:
        e(f"  exported activities: {', '.join(exported)}")

    files = ctx.get("files") or []
    e(_hr(f"FILES ({len(files)})"))
    for f in files[:40]:
        e(f"  {f}")
    if len(files) > 40:
        e(f"  … +{len(files) - 40} more")

    return "\n".join(out)


def _sorted_by_sev(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 5))


def _sorted_code(findings: dict) -> list[tuple[str, dict]]:
    def key(item):
        meta = (item[1] or {}).get("metadata") or {}
        return _SEV_ORDER.get(meta.get("severity", "info"), 5)

    return sorted(findings.items(), key=key)
