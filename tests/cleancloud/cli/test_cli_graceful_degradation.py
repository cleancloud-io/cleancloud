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
from cleancloud.providers.gcp.scan import ProjectScanResult


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


def _fake_gcp_finding(resource_id="projects/my-project/zones/us-central1-a/disks/disk-1"):
    return Finding(
        provider="gcp",
        rule_id="gcp.compute.disk.unattached",
        resource_type="gcp.compute.disk",
        resource_id=resource_id,
        region="us-central1-a",
        title="Unattached Persistent Disk",
        summary="Disk unattached",
        reason="Disk has been unattached for 30 days",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={"labels": {}},
        evidence=Evidence(signals_used=["status=READY, no users"], signals_not_checked=[]),
    )


_SKIPPED = [
    {
        "rule": "find_idle_rds_instances",
        "missing_permissions": "Missing required IAM permissions: rds:DescribeDBInstances",
    }
]

_GCP_SKIPPED = [
    {
        "rule": "find_idle_sql_instances",
        "missing_permissions": "GCP permission denied: cloudsql.instances.list",
        "project_id": "my-project",
        "project_name": "My Project",
    }
]


def _gcp_scan_result(findings, skipped):
    """Return a minimal scan_gcp_with_project_selection tuple."""
    proj = ProjectScanResult(
        project_id="my-project",
        project_name="My Project",
        status="success",
        findings=findings,
        skipped_rules=skipped,
        rules_succeeded=len(_fake_gcp_finding.__defaults__ or []) + 1,
    )
    return ("explicit", findings, ["my-project"], skipped, [proj])


def test_cli_shows_skipped_rules_in_output(monkeypatch):
    """Scan output includes skipped rules section when permissions are missing."""
    monkeypatch.setattr(
        "cleancloud.providers.aws.scan._scan_aws_region",
        lambda profile, region, rules: ([_fake_finding()], _SKIPPED),
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
        lambda profile, region, rules: ([], _SKIPPED),
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
        lambda profile, region, rules: ([_fake_finding("vol-99")], _SKIPPED),
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
        lambda profile, region, rules: ([_fake_finding()], []),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--provider", "aws", "--region", "us-east-1"],
    )

    assert result.exit_code == 0
    assert "Rules skipped" not in result.output
    assert "Rules executed" not in result.output


# ---------------------------------------------------------------------------
# GCP graceful degradation
# ---------------------------------------------------------------------------


def test_gcp_cli_shows_skipped_rules_in_output(monkeypatch):
    """GCP scan output includes skipped rules section when permissions are missing."""
    monkeypatch.setattr(
        "cleancloud.scan.command.scan_gcp_with_project_selection",
        lambda **kwargs: _gcp_scan_result([_fake_gcp_finding()], _GCP_SKIPPED),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--provider", "gcp", "--project", "my-project"],
    )

    assert result.exit_code == 0
    assert "Rules skipped" in result.output
    assert "idle_sql_instances" in result.output
    assert "cloudsql.instances.list" in result.output
    assert "cleancloud doctor" in result.output


def test_gcp_cli_exits_0_with_skipped_rules_and_no_policy_flags(monkeypatch):
    """GCP skipped rules alone do not trigger a non-zero exit code."""
    monkeypatch.setattr(
        "cleancloud.scan.command.scan_gcp_with_project_selection",
        lambda **kwargs: _gcp_scan_result([], _GCP_SKIPPED),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--provider", "gcp", "--project", "my-project"],
    )

    assert result.exit_code == 0


def test_gcp_cli_findings_still_reported_alongside_skipped_rules(monkeypatch):
    """GCP findings from successful rules are still reported when other rules are skipped."""
    finding = _fake_gcp_finding("projects/my-project/zones/us-central1-a/disks/disk-99")
    monkeypatch.setattr(
        "cleancloud.scan.command.scan_gcp_with_project_selection",
        lambda **kwargs: _gcp_scan_result([finding], _GCP_SKIPPED),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--provider", "gcp", "--project", "my-project"],
    )

    assert result.exit_code == 0
    assert "disk-99" in result.output
    assert "Rules skipped" in result.output


def test_gcp_cli_no_skipped_section_when_all_rules_pass(monkeypatch):
    """No skipped rules section shown when all GCP rules complete successfully."""
    monkeypatch.setattr(
        "cleancloud.scan.command.scan_gcp_with_project_selection",
        lambda **kwargs: _gcp_scan_result([_fake_gcp_finding()], []),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--provider", "gcp", "--project", "my-project"],
    )

    assert result.exit_code == 0
    assert "Rules skipped" not in result.output
