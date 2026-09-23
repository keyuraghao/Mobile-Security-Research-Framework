# Changelog

All notable changes to **mobiot** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-22

Fully self-contained desktop app: download one file per OS, run it, nothing else required.

### Added
- **Standalone per-OS bundles.** The release ships a self-contained app for Linux, Windows and macOS that bundles MobSF, a JRE, jadx, adb, frida-server, Frida, mitmproxy and objection. No install, no downloads, no login. The one executable is also the CLI and MCP server (run with arguments).
- **Direct in-process MobSF analysis.** Static analysis calls MobSF's analyzer facade directly (`mobsf_direct.py`), returning the raw result which is rendered through mobiot's own UI and output. No MobSF server, REST, templates or login.
- **20+ inbuilt Frida hooks** across bypass/monitor/recon/trace categories, run with one click or one command.
- **Built-in device/Frida simulator** (`sim` engine) to generate and test payloads with nothing attached.
- **MCP full self-introspection**: `mobiot_capabilities` and `mobiot_workspace`, plus bundled-tool activation so the MCP server has the same self-contained capability as the GUI/CLI.
- **PyQt6 desktop GUI** (`mobiot ui`).
- **On-demand and bundled tool provisioning** (`provisioning.py`, `bundled.py`, `packaging/fetch_vendor.py`).

### Changed
- MobSF runs with authentication disabled and web UI off; the app never presents a login.

## [0.1.0] - 2026-09-22

Initial public release.

### Added
- **Extensible engine architecture** — a registry + `@action` decorator so new
  capabilities auto-expose on the CLI, the desktop GUI and the MCP server with no
  extra wiring.
- **`sast` engine** — native MobSF server management and static analysis
  (upload, scan, JSON/scorecard/PDF reports, recent scans, delete).
- **`dast` engine** — MobSF dynamic analysis plus Frida device/process/app
  enumeration and on-demand frida-server provisioning.
- **`hooks` engine** — a **library of 20+ inbuilt Frida hooks** across four
  categories (bypass / monitor / recon / trace): SSL-pinning, hostname-verifier,
  root, anti-Frida and biometric bypasses; crypto, keystore, SharedPreferences,
  SQLite, file-I/O, clipboard, Base64, HTTP, intent, logcat and native-library
  monitors; class enumeration; method trace/hook and stack-trace dumps. Hooks run
  with one command — JavaScript is only needed for truly custom targets.
- **`runtime` engine** — objection-driven runtime exploration (SSL/root bypass,
  keystore listing, class listing, arbitrary commands).
- **`proxy` engine** — mitmproxy capture in regular/transparent/socks/upstream/
  **wireguard** modes, plus flow-file decoding to JSON.
- **`network` engine** — set up the dynamic-analysis network anywhere: host-IP
  discovery, CA-cert install, device proxy wiring (Wi-Fi or `adb reverse`), and a
  WireGuard "device anywhere" tunnel with QR output.
- **`iot` engine** — nmap host discovery / port-service scanning and binwalk
  firmware signature scanning and extraction.
- **`sim` engine** — a built-in, dependency-free DIVA-like device + Frida-script
  simulator so payloads and the dynamic workflow can be generated, validated and
  "run" with nothing external attached.
- **Desktop application** (`mobiot ui`, PyQt6) — a cross-platform tabbed control
  centre (Dashboard, Static, Frida Hooks, Dynamic, Proxy, Network, IoT) with all
  engine calls on worker threads.
- **CLI** (`mobiot`) auto-generated from the registry (`info`, `preflight`,
  `version`, `serve`, `ui`, and every engine action).
- **MCP server** (`mobiot-mcp` / `mobiot serve`) exposing every action as a tool
  over stdio or HTTP.
- **MobSF slim/offline profile** (on by default) — deterministic `MOBSF_SECRET_KEY`
  (skips the first-run block that downloads ~104MB JADX and can hang), system
  `jadx`, headless REST-only, no telemetry; the vendored MobSF source is patched
  to make its startup update-check opt-in for guaranteed zero egress.
- **Cross-platform** throughout: tool discovery via `PATH`, no hardcoded paths,
  `platformdirs` workspace, shell-free subprocess execution.

[Unreleased]: https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest/releases/tag/v0.2.0
[0.1.0]: https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest/releases/tag/v0.1.0
