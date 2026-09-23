# Changelog

All notable changes to **mobiot** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Full MobSF Frida script library** exposed through the hooks engine
  (`hooks.mobsf_scripts` / `mobsf_script_source`, and `hooks.test --mobsf-script`):
  all ~118 MobSF-bundled scripts for Android and iOS (API monitor, SSL/root/
  debugger/jailbreak bypasses, crypto & keychain dumps, activity/deeplink traces,
  biometric bypass, and the whole `others/` library). The Dynamic (DAST) dropdown
  now offers 150+ techniques.
- **On-device DAST techniques (adb):** `dast.install_app`, `pull_apk`, `logcat`,
  `dumpsys`, `screenshot`, `start_activity`, `activity_tester`, `deeplink` —
  matching MobSF's device operations.
- **Static-analysis rendering completeness:** dedicated GUI tables for every
  analyzer that was previously Raw-JSON-only (APKID, behaviour, NIAP,
  permission-mapping, SBOM; emails + firebase folded into URLs), plus an iOS tab
  (Info.plist, ATS, Mach-O, dylib/framework, App Store).

### Notes
- SAST already runs *every* MobSF analyzer for APK/IPA (mobiot calls MobSF's
  `apk_analysis_task`/`ipa_analysis_task` directly). Remaining coverage items are
  specialised: source-zip / `.aab` / `.appx` / `.so` inputs (same analyzers,
  different container), a native TLS-tester harness, Frida-gadget APK patching for
  non-rooted, and the full iOS dynamic (Corellium/jailbroken-SSH) subsystem.

## [0.3.1] - 2026-09-22

### Added
- **Dockable live emulator screen** — a side-by-side panel that mirrors a connected emulator/device (screencap polling, tap + hardware-key forwarding via the bundled adb) and can be floated into its own window, so it stays usable while working in any other tab (View menu / toolbar toggle).
- **Emulator API-level dropdown** spans API 7 (Android 2.1) to 35 (Android 15).
- **In-app emulator flow guide** on the Emulator and Help tabs (step-by-step provisioning).
- **Automated releases**: per-release notes generated from `CHANGELOG.md` and a `.sha256` checksum attached for every asset; README status badges (CI, release, downloads, Python, platforms, license).

### Fixed
- Emulator (and other) downloads failed with `SSL: CERTIFICATE_VERIFY_FAILED` in the standalone app; downloads now use httpx with the bundled `certifi` CA store.
- `emulator setup` now auto-downloads the Android command-line tools (using the bundled JRE) and installs the emulator + system image, instead of erroring when no SDK is present.
- LSPosed / Magisk / Xposed-module downloads resolve the latest release via the GitHub API (no more 404s), preferring release over debug builds.

## [0.3.0] - 2026-09-22

Professional desktop UI, real analyzer output, and a full pentest workflow.

### Added
- **Professional classic-Windows UI**: menu bar, tool bar, status bar with live connection info, an application icon, an About dialog, and app metadata.
- **Tabular static analysis**: every MobSF analyzer rendered as sortable tables (findings, permissions, certificate, manifest, network, code analysis, binary/NDK, API, malware perms, trackers, URLs/domains, secrets, strings, components) plus a Raw JSON tab.
- **APK internal file browser**: browse the app's files and view their contents (new `sast.files` / `sast.file_content`).
- **Dynamic (DAST) techniques panel** with dropdowns: enumeration, the full Frida hook library, and objection runtime operations.
- **Managed rooted emulator** (`emulator` engine + tab): provision an AVD, root it with Magisk, install LSPosed + curated Xposed modules + a root checker; config dropdowns and an all-in-one Provision.
- **App-data database grabber** (`appdata` engine + tab): pull a running app's SQLite databases and shared_prefs (from a device or simulator sample data) and open them (tables/rows, XML).
- **Findings store** (`findings` engine + tab): central results, auto-import from scans, a "+" dialog to add your own, and delete.
- **Multi-format reporting**: PDF, HTML, XLSX, CSV, JSON, Markdown.
- CLI now prints plain JSON (pipes into `jq`).

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

[Unreleased]: https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest/releases/tag/v0.3.1
[0.3.0]: https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest/releases/tag/v0.3.0
[0.2.0]: https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest/releases/tag/v0.2.0
[0.1.0]: https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest/releases/tag/v0.1.0
