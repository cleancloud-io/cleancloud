import subprocess
import sys

import pytest


@pytest.mark.e2e
@pytest.mark.aws
def test_cli_scan_runs():
    cmd = [
        sys.executable,
        "-m",
        "cleancloud.cli",
        "scan",
        "--provider",
        "aws",
        "--region",
        "us-east-1",
        "--fail-on-findings",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # CLI should exit with code 0 or 2 (depending on findings)
    assert result.returncode in (0, 2)
    assert "Starting CleanCloud scan" in result.stdout
