#!/usr/bin/env python3
"""Print the CHANGELOG.md section for a version, for use as release notes.

Usage: python packaging/extract_changelog.py 0.3.1
Reads CHANGELOG.md next to the repo root and prints the body of the matching
``## [<version>]`` section (without the heading line). Falls back to a short
message when the section is missing so the release still gets a body.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def extract(version: str, changelog: str) -> str:
    version = version.lstrip("v")
    lines = changelog.splitlines()
    out: list[str] = []
    in_section = False
    header = re.compile(r"^## \[")
    want = re.compile(rf"^## \[{re.escape(version)}\]")
    for line in lines:
        if header.match(line):
            if in_section:
                break
            in_section = bool(want.match(line))
            continue
        if in_section:
            out.append(line)
    body = "\n".join(out).strip()
    return body


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: extract_changelog.py <version>", file=sys.stderr)
        return 2
    version = sys.argv[1]
    root = Path(__file__).resolve().parent.parent
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    body = extract(version, changelog)
    if not body:
        body = f"Release {version}. See CHANGELOG.md for details."
    header = (
        f"## Mobile Security and Research Framework {version}\n\n"
        "Self-contained Mobile & IoT SAST / DAST / pentest toolkit "
        "(desktop app + CLI + MCP server).\n\n"
        "### Download\n\n"
        "Windows: run `MSRF-<version>-setup.exe`, or unzip `MSRF-windows-x86_64.zip`. "
        "Linux and macOS: unzip the `MSRF-*.zip` for your OS and run `msrf`. "
        "Everything is bundled, nothing else to install. "
        "Each file has a matching `.sha256` for verification.\n\n"
    )
    print(header + body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
