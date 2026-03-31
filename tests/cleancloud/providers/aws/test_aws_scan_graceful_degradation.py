"""
Tests for graceful degradation when AWS rules encounter missing permissions.
Rules that raise PermissionError should be skipped, not counted as failures.
"""

from datetime import datetime, timezone
from unittest.mock import patch

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.scan import _scan_aws_region, scan_aws_regions


def _make_finding(resource_id="vol-1", region="us-east-1"):
    return Finding(
        provider="aws",
        rule_id="aws.ebs.volume.unattached",
        resource_type="aws.ebs.volume",
        resource_id=resource_id,
        region=region,
        title="Unattached EBS Volume",
        summary="Volume has been unattached",
        reason="Volume unattached for 30 days",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={},
        evidence=Evidence(signals_used=["state=available"], signals_not_checked=[]),
    )


def _good_rule(session, region):
    return [_make_finding()]


def _permission_error_rule(session, region):
    raise PermissionError("Missing required IAM permissions: rds:DescribeDBInstances")


def _another_permission_error_rule(session, region):
    raise PermissionError("Missing required IAM permissions: ec2:DescribeNatGateways")


def _error_rule(session, region):
    raise RuntimeError("Something unexpected happened")


@patch("cleancloud.providers.aws.scan.create_aws_session")
def test_permission_error_goes_to_skipped_not_failed(mock_session):
    """A rule raising PermissionError is recorded in skipped_rules, not as a scan failure."""
    findings, skipped_rules = _scan_aws_region(
        profile=None, region="us-east-1", rules=[_good_rule, _permission_error_rule]
    )

    assert len(findings) == 1
    assert len(skipped_rules) == 1
    assert skipped_rules[0]["rule"] == "_permission_error_rule"
    assert "rds:DescribeDBInstances" in skipped_rules[0]["missing_permissions"]


@patch("cleancloud.providers.aws.scan.create_aws_session")
def test_all_permission_errors_returns_empty_no_exception(mock_session):
    """All rules failing with PermissionError returns ([], skipped_all) without RuntimeError."""
    findings, skipped_rules = _scan_aws_region(
        profile=None,
        region="us-east-1",
        rules=[_permission_error_rule, _another_permission_error_rule],
    )

    assert findings == []
    assert len(skipped_rules) == 2
    rule_names = {s["rule"] for s in skipped_rules}
    assert "_permission_error_rule" in rule_names
    assert "_another_permission_error_rule" in rule_names


@patch("cleancloud.providers.aws.scan.create_aws_session")
def test_mixed_success_and_permission_error(mock_session):
    """Findings from successful rules are returned alongside skipped rule info."""
    findings, skipped_rules = _scan_aws_region(
        profile=None, region="us-east-1", rules=[_good_rule, _permission_error_rule]
    )

    assert len(findings) == 1
    assert findings[0].resource_id == "vol-1"
    assert len(skipped_rules) == 1


@patch("cleancloud.providers.aws.scan.create_aws_session")
def test_non_permission_error_still_counted_as_failure(mock_session):
    """Non-PermissionError exceptions are still counted as rule failures (existing behavior)."""
    findings, skipped_rules = _scan_aws_region(
        profile=None, region="us-east-1", rules=[_good_rule, _error_rule]
    )

    # Good rule still returns findings
    assert len(findings) == 1
    # Error rule is NOT in skipped_rules
    assert len(skipped_rules) == 0


@patch("cleancloud.providers.aws.scan.create_aws_session")
def test_skipped_rules_deduplicated_across_regions(mock_session):
    """scan_aws_regions deduplicates the same skipped rule reported by multiple regions."""
    # Both regions will skip _permission_error_rule — should only appear once in summary
    findings, skipped_rules = scan_aws_regions(
        profile=None,
        regions_to_scan=["us-east-1", "eu-west-1"],
        rules=[_good_rule, _permission_error_rule],
    )

    assert len(findings) == 2  # one finding per region
    # Same rule skipped in both regions — deduplicated to one entry
    assert len(skipped_rules) == 1
    assert skipped_rules[0]["rule"] == "_permission_error_rule"


@patch("cleancloud.providers.aws.scan.create_aws_session")
def test_region_still_stamped_on_findings(mock_session):
    """Region is correctly set on findings even when some rules are skipped."""
    findings, _ = _scan_aws_region(
        profile=None,
        region="ap-southeast-1",
        rules=[_good_rule, _permission_error_rule],
    )

    assert all(f.region == "ap-southeast-1" for f in findings)
