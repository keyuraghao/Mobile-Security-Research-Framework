"""Built-in device & Frida-script simulator.

Provides a self-contained target so the dynamic-analysis and Frida-payload
workflows can be exercised with *nothing external attached* — no Android
emulator, no SDK, no physical device. It is not a real Android runtime: it
cannot execute an APK or real Frida JS. Instead it:

* Models a small DIVA-like Android device/app (``SimDevice`` / ``SimApp``).
* Statically validates a generated Frida script (``FridaScriptSimulator.
  validate``) — the same checks that catch a broken payload before it hits a
  real device.
* Produces realistic ``send()`` output for the bundled hook templates
  (``FridaScriptSimulator.simulate``) so a payload can be "run" and inspected.

Use it via ``--device sim`` (hooks/dast) or the ``sim`` engine. For real
execution, attach a device/emulator and use its serial instead.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: The identifier that selects the built-in simulator instead of a real device.
SIM_DEVICE_ID = "sim"

#: Canned simulated output for the data-driven monitor/bypass hooks.
_CANNED: dict[str, list[str]] = {
    "hostname-verifier-bypass": [
        "Default HostnameVerifier -> accept all",
        "Hostname verifier bypass installed",
    ],
    "anti-frida-bypass": [
        "Debug.isDebuggerConnected -> false",
        'Runtime.exec("ps") blocked',
        "Anti-Frida/debugger bypass installed",
    ],
    "biometric-bypass": [
        "Suppressed onAuthenticationError(7)",
        "Biometric bypass installed (best-effort)",
    ],
    "keystore-monitor": [
        "KeyStore.getKey(alias=user_credentials)",
        "KeyStore.getCertificate(alias=user_credentials)",
        "KeyStore monitor installed",
    ],
    "sharedprefs-monitor": [
        "write putString(auth_token = eyJhbGciOi...)",
        "read getString(username) = admin",
        "SharedPreferences monitor installed",
    ],
    "sqlite-monitor": [
        "execSQL: CREATE TABLE users(id INTEGER, pass TEXT)",
        "rawQuery: SELECT * FROM users WHERE name = 'admin'",
        "SQLite monitor installed",
    ],
    "fileio-monitor": [
        "write open: /data/data/jakhar.aseem.diva/files/secret.txt",
        "read open: /data/data/jakhar.aseem.diva/shared_prefs/app.xml",
        "File I/O monitor installed",
    ],
    "clipboard-monitor": [
        "setPrimaryClip: ClipData { text/plain 's3cr3t-token' }",
        "Clipboard monitor installed",
    ],
    "base64-monitor": [
        "encodeToString -> dmVuZG9yc2VjcmV0",
        'decode("dmVuZG9yc2VjcmV0")',
        "Base64 monitor installed",
    ],
    "http-monitor": [
        "openConnection: https://api.example.com/v1/login",
        "OkHttp request: https://api.example.com/v1/profile",
        "HTTP monitor installed",
    ],
    "intent-monitor": [
        "startActivity: Intent { cmp=jakhar.aseem.diva/.APICreds2Activity }",
        "Intent.putExtra(token = abc123)",
        "Intent monitor installed",
    ],
    "logcat-monitor": [
        "D/DIVA: user tapped access button",
        "E/DIVA: api key = sekret-api-key",
        "Logcat monitor installed",
    ],
    "load-library-monitor": [
        'System.loadLibrary("divajni")',
        "Native library load monitor installed",
    ],
}

_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")
_TAG_RE = re.compile(r"tag:\s*'([\w-]+)'")
_TARGET_RE = re.compile(r"var\s+TARGET\s*=\s*'([^']*)'")
_METHOD_RE = re.compile(r"var\s+METHOD\s*=\s*'([^']*)'")
_FILTER_RE = re.compile(r"var\s+FILTER\s*=\s*'([^']*)'")


@dataclass(slots=True)
class SimApp:
    """A simulated Android application."""

    identifier: str
    name: str
    pid: int
    classes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SimDevice:
    """A simulated Android device with a small set of apps and processes."""

    id: str = SIM_DEVICE_ID
    name: str = "msrf built-in simulator"
    type: str = "emulator"
    abi: str = "arm64-v8a"
    android_version: str = "13"
    rooted: bool = True
    apps: list[SimApp] = field(default_factory=list)

    @classmethod
    def default(cls) -> SimDevice:
        """A device pre-loaded with a DIVA-like target app."""
        diva = SimApp(
            identifier="jakhar.aseem.diva",
            name="DIVA",
            pid=0,
            classes=[
                "jakhar.aseem.diva.MainActivity",
                "jakhar.aseem.diva.APICreds",
                "jakhar.aseem.diva.APICreds2Activity",
                "jakhar.aseem.diva.InsecureDataStorage1Activity",
                "jakhar.aseem.diva.SQLInjectionActivity",
                "jakhar.aseem.diva.AccessControl1Activity",
            ],
        )
        return cls(apps=[diva])

    def processes(self) -> list[dict]:
        base = [
            {"pid": 1, "name": "init"},
            {"pid": 1123, "name": "system_server"},
            {"pid": 2050, "name": "com.android.systemui"},
        ]
        for i, app in enumerate(self.apps, start=1):
            base.append({"pid": 9000 + i, "name": app.identifier})
        return base

    def applications(self) -> list[dict]:
        return [
            {"identifier": a.identifier, "name": a.name, "pid": a.pid}
            for a in self.apps
        ]

    def find_app(self, identifier: str) -> SimApp | None:
        return next((a for a in self.apps if a.identifier == identifier), None)


class FridaScriptSimulator:
    """Statically validate and simulate execution of Frida hook scripts."""

    def validate(self, source: str) -> dict:
        """Run heuristic sanity checks on a Frida script.

        Returns a report with ``ok`` and a list of ``issues``. These mirror the
        classes of mistake that break a payload on a real device: empty script,
        unresolved template placeholders, missing ``Java.perform`` wrapper and
        unbalanced brackets.
        """
        issues: list[str] = []
        if not source.strip():
            issues.append("script is empty")
        leftover = sorted(set(_PLACEHOLDER_RE.findall(source)))
        if leftover:
            issues.append(f"unresolved template placeholders: {', '.join(leftover)}")
        if "Java.perform" not in source and "ObjC." not in source:
            issues.append(
                "no 'Java.perform' (Android) or 'ObjC.' (iOS) entry point found"
            )
        # Count brackets on code only — strip strings/comments so JVM type
        # signatures like '[Ljava/lang/String;' don't cause false positives.
        code = _strip_strings_and_comments(source)
        for open_c, close_c in (("{", "}"), ("(", ")"), ("[", "]")):
            if code.count(open_c) != code.count(close_c):
                issues.append(f"unbalanced '{open_c}{close_c}' brackets")
        return {"ok": not issues, "issues": issues}

    def simulate(self, source: str) -> list[dict]:
        """Produce realistic ``send()`` payloads for a bundled template script.

        The template is identified by the ``tag:`` marker embedded in each
        bundled script. Parameterised templates (hook-method, method-trace,
        list-classes) read their target class/method/filter out of the rendered
        source so the simulated output reflects the actual payload.
        """
        tags = _TAG_RE.findall(source)
        tag = tags[0] if tags else "custom"
        target = _first_group(_TARGET_RE, source)
        method = _first_group(_METHOD_RE, source)
        filt = _first_group(_FILTER_RE, source)

        builder = {
            "ssl-pinning-bypass": self._ssl,
            "root-bypass": self._root,
            "crypto-monitor": self._crypto,
            "webview-inspect": self._webview,
            "method-trace": lambda: self._method_trace(target),
            "hook-method": lambda: self._hook_method(target, method),
            "dump-stacktrace": lambda: self._hook_method(target, method),
            "list-classes": lambda: self._list_classes(filt),
        }.get(tag)
        if builder is not None:
            return builder()
        # Data-driven canned output for the monitor/bypass hook library.
        lines = _CANNED.get(tag)
        if lines is not None:
            return [self._msg(tag, line) for line in lines]
        return [self._msg(tag, "script loaded (no simulator profile)")]

    # -- per-template simulated output -----------------------------------

    def _msg(self, tag: str, msg: str) -> dict:
        return {"tag": tag, "msg": msg}

    def _ssl(self) -> list[dict]:
        t = "ssl-pinning-bypass"
        return [
            self._msg(t, "SSLContext.init hooked -> trusting all certificates"),
            self._msg(t, "OkHttp CertificatePinner.check bypassed for api.example.com"),
            self._msg(t, "TrustManagerImpl.verifyChain bypassed for api.example.com"),
            self._msg(t, "SSL pinning bypass installed"),
        ]

    def _root(self) -> list[dict]:
        t = "root-bypass"
        return [
            self._msg(t, 'File.exists("/system/xbin/su") -> false'),
            self._msg(t, 'Runtime.exec("which su") blocked'),
            self._msg(t, "Hiding root package com.topjohnwu.magisk"),
            self._msg(t, "Root detection bypass installed"),
        ]

    def _crypto(self) -> list[dict]:
        t = "crypto-monitor"
        return [
            self._msg(t, 'Cipher.getInstance("AES/CBC/PKCS5Padding")'),
            self._msg(t, "SecretKeySpec key=76656e646f7273656372657430303100 algo=AES"),
            self._msg(t, "Cipher.doFinal input=48656c6c6f20776f726c64"),
            self._msg(t, "Cipher.doFinal output=a1b2c3d4e5f6..."),
            self._msg(t, "Crypto monitor installed"),
        ]

    def _webview(self) -> list[dict]:
        t = "webview-inspect"
        return [
            self._msg(t, "loadUrl: https://example.com/app"),
            self._msg(t, "addJavascriptInterface: AndroidBridge (com.example.Bridge)"),
            self._msg(t, "WebView inspection installed"),
        ]

    def _method_trace(self, target: str) -> list[dict]:
        t = "method-trace"
        target = target or "jakhar.aseem.diva.APICreds"
        return [
            self._msg(t, f"{target}.onCreate(android.os.Bundle@0) = undefined"),
            self._msg(t, f"{target}.access(view@1) = true"),
            self._msg(t, f"Traced 3 method overloads on {target}"),
        ]

    def _hook_method(self, target: str, method: str) -> list[dict]:
        t = "hook-method"
        target = target or "jakhar.aseem.diva.APICreds"
        method = method or "access"
        return [
            self._msg(t, f"Hooked 1 overload(s) of {target}.{method}"),
            self._msg(t, f"CALL {target}.{method}(secret_key_here)"),
            self._msg(t, f"RET  {target}.{method} -> true"),
        ]

    def _list_classes(self, filt: str) -> list[dict]:
        t = "list-classes"
        pool = [
            "jakhar.aseem.diva.MainActivity",
            "jakhar.aseem.diva.APICreds",
            "jakhar.aseem.diva.SQLInjectionActivity",
            "java.lang.String",
            "android.app.Activity",
        ]
        matched = [c for c in pool if not filt or filt.lower() in c.lower()]
        out = [self._msg(t, c) for c in matched]
        out.append(self._msg(t, f"Enumeration complete: {len(matched)} matching class(es)"))
        return out


def _first_group(pattern: re.Pattern[str], source: str) -> str:
    """Return the first capture group of ``pattern`` in ``source``, or ""."""
    match = pattern.search(source)
    return match.group(1) if match else ""


def _strip_strings_and_comments(source: str) -> str:
    """Blank out JS strings and comments so bracket counting sees code only."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)  # block comments
    source = re.sub(r"//[^\n]*", "", source)  # line comments
    source = re.sub(r"'(?:\\.|[^'\\])*'", "''", source)  # single-quoted
    source = re.sub(r'"(?:\\.|[^"\\])*"', '""', source)  # double-quoted
    return source
