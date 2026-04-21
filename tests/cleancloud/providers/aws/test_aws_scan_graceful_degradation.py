"""
Tests for graceful degradation when AWS rules encounter missing permissions.
Rules that raise PermissionError should be skipped, not counted as failures.
"""

import functools
from datetime import datetime, timezone
from unittest.mock import patch

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.scan import (
    AWS_AI_RULES,
    _get_active_aws_regions,
    _scan_aws_region,
    scan_aws_regions,
    scan_aws_with_region_selection,
)


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
def test_non_permission_error_tracked_in_skipped_rules(mock_session):
    """Non-PermissionError exceptions are tracked in skipped_rules with 'error' key."""
    findings, skipped_rules = _scan_aws_region(
        profile=None, region="us-east-1", rules=[_good_rule, _error_rule]
    )

    # Good rule still returns findings — scan never blows up
    assert len(findings) == 1
    # Error rule IS tracked in skipped_rules, but with 'error' key (not 'missing_permissions')
    assert len(skipped_rules) == 1
    assert skipped_rules[0]["rule"] == "_error_rule"
    assert "error" in skipped_rules[0]
    assert "missing_permissions" not in skipped_rules[0]
    assert "RuntimeError" in skipped_rules[0]["error"]


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


@patch("cleancloud.providers.aws.scan.create_aws_session")
def test_parameterized_rule_uses_original_name_in_skipped_rules(mock_session):
    findings, skipped_rules = _scan_aws_region(
        profile=None,
        region="us-east-1",
        rules=[functools.partial(_permission_error_rule)],
    )

    assert findings == []
    assert len(skipped_rules) == 1
    assert skipped_rules[0]["rule"] == "_permission_error_rule"


@patch("cleancloud.providers.aws.scan.scan_aws_regions")
@patch("cleancloud.providers.aws.scan._get_active_aws_regions")
@patch("cleancloud.providers.aws.scan.create_aws_session")
def test_region_selection_detects_parameterized_ai_rules(
    mock_create_session, mock_get_regions, mock_scan_regions
):
    session = mock_create_session.return_value
    session.client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_get_regions.return_value = ["us-east-1"]
    mock_scan_regions.return_value = ([], [])

    parameterized_rule = functools.partial(AWS_AI_RULES[0], idle_days_threshold=21)

    scan_aws_with_region_selection(
        profile=None,
        region=None,
        all_regions=True,
        rules=[parameterized_rule],
    )

    mock_get_regions.assert_called_once_with(session, include_ai=True)


@patch("cleancloud.providers.aws.scan.set_cached_regions")
@patch("cleancloud.providers.aws.scan.get_cached_regions")
def test_region_discovery_does_not_cache_partial_results_after_errors(
    mock_get_cached_regions, mock_set_cached_regions
):
    class _StsClient:
        def get_caller_identity(self):
            return {"Account": "123456789012"}

    class _Ec2Client:
        def describe_regions(self, **kwargs):
            return {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "us-west-2"}]}

    class _Session:
        def client(self, service_name, **kwargs):
            if service_name == "sts":
                return _StsClient()
            if service_name == "ec2":
                return _Ec2Client()
            raise AssertionError(service_name)

    def _region_probe(session, region, include_ai=False):
        if region == "us-east-1":
            return True, None
        return False, "Error: throttled"

    mock_get_cached_regions.return_value = None

    with patch(
        "cleancloud.providers.aws.scan._region_has_cleancloud_resources", side_effect=_region_probe
    ):
        regions = _get_active_aws_regions(_Session(), include_ai=True)

    assert regions == ["us-east-1"]
    mock_set_cached_regions.assert_not_called()
