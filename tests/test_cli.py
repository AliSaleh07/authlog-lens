"""Tests for AuthLog Lens CLI entrypoint."""

import os
import json
from authlog_lens.cli import main


def test_cli_analyze_normal_exit_zero():
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "auth_sample_normal.log")
    code = main(["analyze", path, "--strict"])
    assert code == 0


def test_cli_analyze_attack_exit_one_on_strict():
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "auth_sample_attack.log")
    code = main(["analyze", path, "--strict"])
    assert code == 1


def test_cli_json_export(capsys):
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "auth_sample_normal.log")
    code = main(["analyze", path, "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "parsed_events" in data
    assert "alerts" in data
