import json
import os
import subprocess
import sys
import tempfile

import pytest


@pytest.mark.e2e
@pytest.mark.gcp
def test_cli_gcp_scan_runs():
    cmd = [
        sys.executable,
        "-m",
        "cleancloud.cli",
        "scan",
        "--provider",
        "gcp",
        "--fail-on-findings",
    ]
    if project := os.environ.get("CLEANCLOUD_GCP_TEST_PROJECT"):
        cmd += ["--project", project]

    result = subprocess.run(cmd, capture_output=True, text=True)

    # CLI should exit with code 0 (no findings) or 2 (findings present)
    assert result.returncode in (0, 2)
    assert "Starting CleanCloud scan" in result.stdout


@pytest.mark.e2e
@pytest.mark.gcp
def test_cli_gcp_scan_json_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = os.path.join(tmpdir, "out.json")

        cmd = [
            sys.executable,
            "-m",
            "cleancloud.cli",
            "scan",
            "--provider",
            "gcp",
            "--output",
            "json",
            "--output-file",
            output_file,
        ]
        if project := os.environ.get("CLEANCLOUD_GCP_TEST_PROJECT"):
            cmd += ["--project", project]

        result = subprocess.run(cmd, capture_output=True, text=True)

        assert result.returncode == 0, f"CLI failed:\n{result.stderr}"
        assert os.path.exists(output_file)

        with open(output_file) as f:
            data = json.load(f)

        assert "summary" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)

        rules_failed = data["summary"].get("rules_failed", 0)
        assert (
            rules_failed == 0
        ), f"{rules_failed} rule(s) failed during scan — check CLI output above for details"
