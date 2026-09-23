from __future__ import annotations

import json

from typer.testing import CliRunner

from msrf.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "msrf" in result.stdout


def test_info_lists_engines():
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    for name in ("sast", "hooks", "network", "iot", "proxy"):
        assert name in result.stdout


def test_engine_subcommands_exist():
    # Each engine should have registered a subcommand group.
    result = runner.invoke(app, ["hooks", "--help"])
    assert result.exit_code == 0
    assert "list-templates" in result.stdout


def test_hooks_list_templates(tmp_path):
    result = runner.invoke(
        app, ["--workspace", str(tmp_path), "hooks", "list-templates"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    names = {t["name"] for t in payload["templates"]}
    assert "root-bypass" in names


def test_hooks_generate_with_json_params(tmp_path):
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "hooks",
            "generate",
            "hook-method",
            "--params",
            '{"CLASS": "a.B", "METHOD": "c"}',
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "a.B" in payload["script"]
