"""
Tests for the `riskcalc` command line interface.
"""

import json

from click.testing import CliRunner

from riskcalc.cli import cli
from riskcalc.utils import list_profiles

REQUEST = "example/request.yaml"
PROFILE = "example/profile.yaml"


def test_calculate_prints_terminal_report():
    result = CliRunner().invoke(cli, ["calculate", "-r", REQUEST, "-p", PROFILE])
    assert result.exit_code == 0
    assert "Rating: critical" in result.output
    assert "Contributions:" in result.output


def test_calculate_json_flag_emits_parseable_json():
    result = CliRunner().invoke(
        cli, ["calculate", "-r", REQUEST, "-p", PROFILE, "--json"]
    )
    assert result.exit_code == 0

    payload = json.loads(result.output)
    assert payload["rating"] == "critical"
    assert payload["raw_score"] == 309.0
    assert any(c["source"] == "vulnerability.cvss" for c in payload["contributions"])


def test_missing_request_file_is_a_usage_error():
    result = CliRunner().invoke(
        cli, ["calculate", "-r", "does-not-exist.yaml", "-p", PROFILE]
    )
    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_invalid_profile_reports_a_clean_error(tmp_path):
    broken = tmp_path / "broken.yaml"
    broken.write_text("name: broken\n")  # missing required fields

    result = CliRunner().invoke(cli, ["calculate", "-r", REQUEST, "-p", str(broken)])
    assert result.exit_code == 1
    assert "Error:" in result.output


def test_profiles_lists_every_bundled_profile():
    result = CliRunner().invoke(cli, ["profiles"])
    assert result.exit_code == 0
    for stem in list_profiles():
        assert stem in result.output
    assert "Default risk profile" in result.output


def test_profiles_json_is_parseable_and_covers_all():
    result = CliRunner().invoke(cli, ["profiles", "--json"])
    assert result.exit_code == 0

    payload = json.loads(result.output)
    assert {row["profile"] for row in payload} == set(list_profiles())
    assert all(row["name"] and row["version"] for row in payload)
