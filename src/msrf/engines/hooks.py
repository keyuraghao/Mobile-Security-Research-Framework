"""Hooks engine — Frida JavaScript payload generation and testing.

Generates Frida hook scripts from a bundled, parameterised template library and
runs them against a target application (by default the intentionally-vulnerable
DIVA app) to confirm a payload loads and fires before it is used in a real
assessment. All instrumentation is for AUTHORISED testing only.
"""
from __future__ import annotations

import contextlib
import json
import re
import time
from importlib.resources import files
from pathlib import Path
from typing import Any

from ..config import Config
from ..exceptions import EngineError, ToolNotFoundError
from ..registry import register
from ..sim import SIM_DEVICE_ID, FridaScriptSimulator
from .base import Engine, action

try:
    import frida
except Exception:  # pragma: no cover
    frida = None  # type: ignore[assignment]

#: Default dummy target: the DIVA (Damn Insecure and Vulnerable App) package.
DEFAULT_DUMMY_PACKAGE = "jakhar.aseem.diva"

_PARAM_RE = re.compile(r"\{\{(\w+)\}\}")


@register
class HooksEngine(Engine):
    """Generate and test Frida instrumentation payloads."""

    name = "hooks"
    summary = "Generate Frida JS payloads from templates and test them on a dummy app."

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._templates_root = files("msrf.data.frida_templates")

    # -- template library -------------------------------------------------

    def _manifest(self) -> dict[str, Any]:
        raw = (self._templates_root / "manifest.json").read_text(encoding="utf-8")
        return json.loads(raw)["templates"]

    def _template_source(self, file_name: str) -> str:
        return (self._templates_root / file_name).read_text(encoding="utf-8")

    @action("List available Frida payload templates and their parameters.")
    def list_templates(self) -> dict[str, Any]:
        manifest = self._manifest()
        return {
            "templates": [
                {
                    "name": name,
                    "summary": meta["summary"],
                    "platform": meta.get("platform", "android"),
                    "category": meta.get("category", "other"),
                    "params": meta.get("params", {}),
                }
                for name, meta in sorted(manifest.items())
                if not meta.get("hidden")
            ]
        }

    @action("List MobSF's bundled Frida script library (Android + iOS, ~118 scripts).")
    def mobsf_scripts(self, platform: str | None = None) -> dict[str, Any]:
        """List every MobSF-bundled Frida script (by ``<platform>/<category>/<name>``).

        Args:
            platform: Optional filter, ``android`` or ``ios``.
        """
        from .. import mobsf_scripts as ms

        scripts = ms.list_scripts(platform)
        return {"count": len(scripts), "scripts": scripts}

    @action("Show the source of a MobSF Frida script by its id.")
    def mobsf_script_source(self, script_id: str) -> dict[str, Any]:
        from .. import mobsf_scripts as ms

        return {"id": script_id, "script": ms.read_script(script_id)}

    # -- generation -------------------------------------------------------

    @action("Render a Frida payload from a template; optionally save it to disk.")
    def generate(
        self,
        template: str,
        params: dict[str, str] | None = None,
        out_path: str | None = None,
    ) -> dict[str, Any]:
        """Generate a Frida script from a named template.

        Args:
            template: Template name from :meth:`list_templates`.
            params: Values for the template placeholders (e.g. ``{"CLASS": "..."}``).
            out_path: Optional path to write the rendered script; defaults to
                ``<workspace>/hooks/<template>.js``.
        """
        manifest = self._manifest()
        if template not in manifest:
            raise EngineError(
                "hooks",
                f"Unknown template {template!r}. Available: {', '.join(sorted(manifest))}",
            )
        meta = manifest[template]
        source = self._template_source(meta["file"])
        params = params or {}

        required = set(meta.get("params", {}))
        missing = required - set(params)
        if missing:
            raise EngineError(
                "hooks",
                f"Template {template!r} requires params: {', '.join(sorted(missing))}",
            )
        rendered = _PARAM_RE.sub(
            lambda m: str(params.get(m.group(1), m.group(0))), source
        )
        # Any placeholder left unfilled is an error.
        leftover = _PARAM_RE.findall(rendered)
        if leftover:
            raise EngineError(
                "hooks", f"Unresolved placeholders: {', '.join(sorted(set(leftover)))}"
            )

        target = (
            Path(out_path).expanduser()
            if out_path
            else self.config.workspace / "hooks" / f"{template}.js"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        return {"template": template, "path": str(target), "script": rendered}

    # -- testing ----------------------------------------------------------

    @action(
        "Test a Frida payload against a target app (default: DIVA) and capture output.",
        mutating=True,
    )
    def test(
        self,
        template: str | None = None,
        script_path: str | None = None,
        mobsf_script: str | None = None,
        params: dict[str, str] | None = None,
        package: str = DEFAULT_DUMMY_PACKAGE,
        device_id: str | None = None,
        spawn: bool = True,
        duration: float = 6.0,
    ) -> dict[str, Any]:
        """Inject a payload into ``package`` and collect its messages.

        Provide either ``template`` (rendered with ``params``) or ``script_path``
        (a pre-written ``.js`` file). The target defaults to the bundled dummy
        app (DIVA); override ``package`` to test elsewhere.

        Args:
            template: Template name to render and inject.
            script_path: Path to an existing script to inject instead.
            params: Params for ``template``.
            package: Target application identifier.
            device_id: Frida device id; defaults to the USB device.
            spawn: Spawn the app fresh (True) or attach to a running instance.
            duration: Seconds to collect messages before detaching.

        Returns:
            Captured messages, plus a ``loaded`` flag and any error payloads.
            When ``device_id`` is ``"sim"`` the built-in simulator runs the
            payload in-process (no frida, no device required).
        """
        if not template and not script_path and not mobsf_script:
            raise EngineError(
                "hooks", "Provide 'template', 'script_path', or 'mobsf_script'."
            )

        if mobsf_script:
            from .. import mobsf_scripts

            source = mobsf_scripts.read_script(mobsf_script)
        elif script_path:
            source = Path(script_path).expanduser().read_text(encoding="utf-8")
        else:
            source = self.generate(template, params=params)["script"]  # type: ignore[arg-type]

        # Built-in simulator: no external device or frida needed.
        if device_id == SIM_DEVICE_ID:
            simulator = FridaScriptSimulator()
            report = simulator.validate(source)
            messages = simulator.simulate(source) if report["ok"] else []
            return {
                "device": SIM_DEVICE_ID,
                "package": package,
                "template": template,
                "simulated": True,
                "validation": report,
                "loaded": report["ok"],
                "message_count": len(messages),
                "messages": messages,
                "errors": [],
            }

        if frida is None:
            raise ToolNotFoundError("frida", "Install with 'pip install frida'.")

        device = (
            frida.get_usb_device(timeout=10)
            if not device_id
            else frida.get_device(device_id)
        )

        messages: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: Any) -> None:
            mtype = message.get("type")
            if mtype == "send":
                messages.append(message.get("payload"))
            elif mtype == "log":
                # Many MobSF scripts report via console.log.
                messages.append(message.get("payload"))
            elif mtype == "error":
                errors.append(message)

        pid = None
        session = None
        try:
            if spawn:
                pid = device.spawn([package])
                session = device.attach(pid)
            else:
                session = device.attach(package)
            script = session.create_script(source)
            script.on("message", on_message)
            script.load()
            loaded = True
            if spawn and pid is not None:
                device.resume(pid)
            time.sleep(duration)
        except frida.ProcessNotFoundError as exc:
            raise EngineError(
                "hooks",
                f"App {package!r} not found on device. Is it installed? ({exc})",
            ) from exc
        except frida.ServerNotRunningError as exc:
            raise EngineError(
                "hooks",
                "frida-server is not running on the device. "
                "Run 'dast provision-frida-server' first.",
            ) from exc
        except Exception as exc:
            raise EngineError("hooks", f"Injection failed: {exc}") from exc
        finally:
            if session is not None:
                with contextlib.suppress(Exception):
                    session.detach()

        return {
            "package": package,
            "template": template or mobsf_script,
            "loaded": loaded,
            "message_count": len(messages),
            "messages": messages,
            "errors": errors,
        }
