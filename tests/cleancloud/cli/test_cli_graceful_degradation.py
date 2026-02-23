"""
CLI integration tests for graceful degradation when permissions are missing.
Verifies the scan command displays skipped rules and continues without failing.
"""

from datetime import datetime, timezone

from click.testing import CliRunner

from cleancloud.cli import cli
from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel


def _fake_finding(resource_id="vol-1"):
    return Finding(
        provider="aws",
        rule_id="aws.ebs.volume.unattached",
        resource_type="aws.ebs.volume",
        resource_id=resource_id,
        region="us-east-1",
        title="Unattached EBS Volume",
        summary="Volume unattached",
        reason="Volume unattached for 30 days",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={},
        evidence=Evidence(signals_used=["state=available"], signals_not_checked=[]),
    )


_SKIPPED = [
    {
        "rule": "find_idle_rds_instances",
        "missing_permissions": "Missing required IAM permissions: rds:DescribeDBInstances",
    }
]


def test_cli_shows_skipped_rules_in_output(monkeypatch):
    """Scan output includes skipped rules section when permissions are missing."""
    monkeypatch.setattr(
        "cleancloud.providers.aws.scan._scan_aws_region",
        lambda profile, region: ([_fake_finding()], _SKIPPED),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--provider", "aws", "--region", "us-east-1"],
    )

    assert result.exit_code == 0
    assert "Rules skipped" in result.output
    assert "idle_rds_instances" in result.output
    assert "rds:DescribeDBInstances" in result.output
    assert "cleancloud doctor" in result.output


def test_cli_exits_0_with_skipped_rules_and_no_policy_flags(monkeypatch):
    """Skipped rules alone do not trigger a non-zero exit code."""
    monkeypatch.setattr(
        "cleancloud.providers.aws.scan._scan_aws_region",
        lambda profile, region: ([], _SKIPPED),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--provider", "aws", "--region", "us-east-1"],
    )

    assert result.exit_code == 0


def test_cli_findings_still_reported_alongside_skipped_rules(monkeypatch):
    """Findings from successful rules are still reported when other rules are skipped."""
    monkeypatch.setattr(
        "cleancloud.providers.aws.scan._scan_aws_region",
        lambda profile, region: ([_fake_finding("vol-99")], _SKIPPED),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--provider", "aws", "--region", "us-east-1"],
    )

    assert result.exit_code == 0
    assert "vol-99" in result.output
    assert "Rules skipped" in result.output


def test_cli_no_skipped_section_when_all_rules_pass(monkeypatch):
    """No skipped rules section shown when all rules complete successfully."""
    monkeypatch.setattr(
        "cleancloud.providers.aws.scan._scan_aws_region",
        lambda profile, region: ([_fake_finding()], []),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--provider", "aws", "--region", "us-east-1"],
    )

    assert result.exit_code == 0
    assert "Rules skipped" not in result.output
    assert "Rules executed" not in result.output
