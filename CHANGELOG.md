# Changelog

All notable changes to **mobiot** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/keyuraghao/mobiot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/keyuraghao/mobiot/releases/tag/v0.1.0
