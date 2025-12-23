from unittest.mock import patch

import pytest
from click.testing import CliRunner

import cleancloud.cli as cli_module
from cleancloud.cli import cli

pytest.skip(
    "Azure tests disabled for now",
    allow_module_level=True,
)


class FakeResult:
    """
    Minimal fake result object for CLI integration tests.
    """

    def __init__(self, confidence: str):
        self.confidence = confidence

    def to_dict(self):
        return {"confidence": self.confidence}


def test_cli_exits_2_on_high_confidence():
    runner = CliRunner()
    fake_results = [FakeResult("High")]

    # ⬇️ CHANGE run_scan IF NEEDED (see section below)
    with patch.object(cli_module, "run_scan", return_value=fake_results):
        result = runner.invoke(cli, ["scan"])

    assert result.exit_code == 2


def test_cli_does_not_fail_on_medium_confidence():
    runner = CliRunner()
    fake_results = [FakeResult("Medium")]

    with patch.object(cli_module, "run_scan", return_value=fake_results):
        result = runner.invoke(cli, ["scan"])

    assert result.exit_code == 0


def test_cli_no_findings_exit_0():
    runner = CliRunner()

    with patch.object(cli_module, "run_scan", return_value=[]):
        result = runner.invoke(cli, ["scan"])

    assert result.exit_code == 0
