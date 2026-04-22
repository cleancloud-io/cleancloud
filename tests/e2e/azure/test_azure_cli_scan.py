import json
import os
import subprocess
import tempfile

import pytest


@pytest.mark.e2e
@pytest.mark.azure
def test_cli_azure_scan_json_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = os.path.join(tmpdir, "out.json")

        result = subprocess.run(
            [
                "cleancloud",
                "scan",
                "--provider",
                "azure",
                "--output",
                "json",
                "--output-file",
                output_file,
            ],
            capture_output=True,
            text=True,
        )

        # CLI should not crash
        assert result.returncode == 0, (
            f"cleancloud scan exited {result.returncode}\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

        # Output file must exist
        assert os.path.exists(output_file)

        # JSON must be valid
        with open(output_file) as f:
            data = json.load(f)

        assert "summary" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)

        summary = data["summary"]

        # No rule-level failures — if any rule errored, rules_failed appears in summary.
        # A non-zero value means a rule threw an unexpected exception during the scan.
        rules_failed = summary.get("rules_failed", 0)
        assert rules_failed == 0, (
            f"rules_failed={rules_failed} — one or more Azure rules errored during scan.\n"
            f"Check per_subscription for details:\n"
            + json.dumps(summary.get("per_subscription", []), indent=2)
        )

        skipped_rules = summary.get("skipped_rules", [])
        assert skipped_rules == [], (
            "skipped_rules present — Azure scan degraded silently due to missing "
            "permissions or rule-level handling.\n" + json.dumps(skipped_rules, indent=2)
        )

        # No failed subscriptions
        assert "subscriptions_failed" not in summary, (
            "subscriptions_failed present — some subscriptions could not be scanned:\n"
            + json.dumps(summary.get("subscriptions_failed", []), indent=2)
        )

        # Every subscription that was scanned must report zero rule failures
        for sub in summary.get("per_subscription", []):
            assert sub.get("rules_failed", 0) == 0, (
                f"Subscription {sub.get('name')} ({sub.get('id')}) "
                f"had {sub['rules_failed']} rule failure(s)"
            )
