"""Help view: usage guide, engine overview, connection info, and MCP setup."""
from __future__ import annotations

import sys

from PyQt6.QtWidgets import QTextBrowser, QVBoxLayout, QWidget

from .. import get_version


def _mobiot_command() -> str:
    """Best-effort path to invoke mobiot (the frozen exe, or 'mobiot')."""
    if getattr(sys, "frozen", False):
        return sys.executable
    return "mobiot"


HELP_HTML = """
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; color: #1a1a1a; }}
  h2 {{ color: #0a64ad; border-bottom: 1px solid #a0a0a0; padding-bottom: 3px; }}
  h3 {{ color: #0a4a80; margin-bottom: 4px; }}
  code, pre {{ background: #f4f4f4; border: 1px solid #ddd; font-family: Consolas, monospace; }}
  pre {{ padding: 8px; }}
  table {{ border-collapse: collapse; }}
  td, th {{ border: 1px solid #c0c0c0; padding: 4px 8px; text-align: left; }}
  th {{ background: #eef4fa; }}
  .note {{ background: #fff8e1; border: 1px solid #e0c060; padding: 8px; }}
</style>

<h1>Mobile Security and Research Framework <small>{version}</small></h1>
<p>A self-contained Mobile &amp; IoT SAST / DAST / penetration-testing toolkit.
Everything it needs is bundled: MobSF, a Java runtime, jadx, adb, Frida,
frida-server, mitmproxy and objection. No install, no server, no login.</p>

<div class="note"><b>Authorised testing only.</b> Use mobiot only on applications,
devices and networks you own or are explicitly permitted to test.</div>

<h2>Getting started</h2>
<ol>
  <li><b>Static analysis</b> &mdash; open the <b>Static (SAST)</b> tab, choose an APK/IPA,
      and click <b>Analyze</b>. Results appear as tables (findings, permissions,
      certificate, manifest, network, code analysis, binary/NDK, trackers,
      URLs/domains, secrets, components) and you can browse the app's internal
      files under the <b>Files</b> sub-tab.</li>
  <li><b>Frida hooks</b> &mdash; the <b>Frida Hooks</b> tab has 20+ inbuilt payloads.
      Pick one and run it on the built-in <b>simulator</b> (no device needed) or a
      connected device.</li>
  <li><b>Dynamic / Proxy / Network / IoT</b> &mdash; device instrumentation, traffic
      interception (including WireGuard), interception-network setup, and nmap /
      binwalk recon.</li>
</ol>

<h2>Connection information</h2>
<p>The <b>Dashboard</b> tab and the <b>status bar</b> (bottom) show what is ready on
this machine:</p>
<table>
  <tr><th>Item</th><th>Meaning</th></tr>
  <tr><td>SAST engine</td><td>MobSF analysis runs in-process. Ready means the bundled analyzer loaded.</td></tr>
  <tr><td>Device</td><td>Android devices detected via adb. Needed only for live dynamic analysis.</td></tr>
  <tr><td>Frida / simulator</td><td>The built-in simulator is always ready; a real device enables live hooks.</td></tr>
  <tr><td>Workspace</td><td>Where reports, captures, certificates and logs are stored.</td></tr>
</table>

<h2>Rooted emulator &mdash; step by step</h2>
<p>The <b>Emulator</b> tab provisions and drives a rooted Android emulator so you can
run the target app and observe its behaviour. It needs host virtualization
(Linux <b>KVM</b>, Windows <b>WHPX/HAXM</b> or <b>Hyper-V</b>, macOS
<b>Hypervisor.framework</b>). The Android SDK, system image and modules download
automatically on first run (a few GB).</p>
<ol>
  <li>Open the <b>Emulator</b> tab and choose the <b>API level</b>, <b>image</b> and <b>ABI</b>
      (x86_64 is fastest under virtualization).</li>
  <li>Click <b>Provision all-in-one</b> &mdash; this runs, in order: <b>Setup</b> (SDK +
      system image + AVD), <b>Start</b> (boot), <b>Root</b> (Magisk), <b>Install LSPosed</b>,
      <b>Install modules</b> and <b>Root checker</b>. You can also run each button
      individually.</li>
  <li>When it finishes, open <b>LSPosed</b> inside the emulator to enable the installed
      modules, and <b>Magisk</b> to confirm root.</li>
  <li>Use <b>Status</b> at any time to see the tool paths and whether the emulator is
      booted and rooted. Tick modules (JustTrustMe, Inspeckage, HideMyApplist, ...) or add
      your own APK before installing.</li>
</ol>
<p>Once the emulator is up, the other tabs work against it automatically: analyze in
<b>Static</b>, hook in <b>Frida Hooks</b> / <b>Dynamic</b>, grab databases in <b>App
Data</b>, and collect results in <b>Findings</b>.</p>

<h2>MCP server &mdash; how it is set up</h2>
<p>mobiot ships a Model Context Protocol (MCP) server that exposes <b>every</b>
engine action as a tool, so an AI client (for example Claude) can drive the whole
toolkit. Tools are named <code>&lt;engine&gt;_&lt;action&gt;</code> (e.g.
<code>sast_scan</code>, <code>hooks_test</code>), plus <code>mobiot_capabilities</code>
(full self-introspection), <code>mobiot_preflight</code> and
<code>mobiot_workspace</code>.</p>

<h3>How to set it up</h3>
<p>Run the server over stdio (default) or HTTP:</p>
<pre>{cmd} serve
{cmd} serve --transport http --port 8765</pre>

<p>Point an MCP client at it with a config like:</p>
<pre>{{
  "mcpServers": {{
    "mobiot": {{
      "command": "{cmd_json}",
      "args": ["serve"]
    }}
  }}
}}</pre>

<p>For HTTP transport, connect the client to
<code>http://127.0.0.1:8765</code> instead. Once connected, ask the client to call
<code>mobiot_capabilities</code> to discover the full tool surface, then
<code>mobiot_preflight</code> to see what is ready.</p>

<h2>Command line</h2>
<p>The same executable is also a CLI. Examples:</p>
<pre>{cmd} info
{cmd} preflight
{cmd} sast scan app.apk
{cmd} hooks test --template ssl-pinning-bypass --device-id sim</pre>
"""


class HelpView(QWidget):
    def __init__(self) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        cmd = _mobiot_command()
        browser.setHtml(
            HELP_HTML.format(
                version=get_version(),
                cmd=cmd,
                cmd_json=cmd.replace("\\", "\\\\"),
            )
        )
        lay.addWidget(browser)
