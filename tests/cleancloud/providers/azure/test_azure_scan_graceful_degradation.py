"""
Tests for graceful degradation when Azure rules encounter missing permissions.
Rules raising PermissionError or HttpResponseError(403) are skipped, not failed.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from azure.core.exceptions import HttpResponseError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.azure.scan import _scan_azure_subscription


def _make_finding(resource_id="disk-1"):
    return Finding(
        provider="azure",
        rule_id="azure.unattached_disk",
        resource_type="azure.compute.disk",
        resource_id=resource_id,
        region="eastus",
        title="Unattached Managed Disk",
        summary="Disk not attached to any VM",
        reason="Disk unattached for 30 days",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.MEDIUM,
        detected_at=datetime.now(timezone.utc),
        details={},
        evidence=Evidence(signals_used=["disk_state=Unattached"], signals_not_checked=[]),
    )


def _good_rule(subscription_id, credential, region_filter=None):
    return [_make_finding()]


def _permission_error_rule(subscription_id, credential, region_filter=None):
    raise PermissionError("Missing required permissions: Microsoft.Compute/disks/read")


def _http_403_rule(subscription_id, credential, region_filter=None):
    error = HttpResponseError()
    error.status_code = 403
    raise error


def _http_404_rule(subscription_id, credential, region_filter=None):
    error = HttpResponseError()
    error.status_code = 404
    raise error


def test_permission_error_skips_azure_rule():
    """PermissionError from an Azure rule goes to skipped_rules, not rules_failed."""
    with patch(
        "cleancloud.providers.azure.scan.AZURE_RULES",
        [_good_rule, _permission_error_rule],
    ):
        findings, skipped_rules, rules_failed = _scan_azure_subscription(
            subscription_id="sub-123",
            subscription_name="test-sub",
            credential=MagicMock(),
            region_filter=None,
        )

    assert len(findings) == 1
    assert len(skipped_rules) == 1
    assert skipped_rules[0]["rule"] == "_permission_error_rule"
    assert "Microsoft.Compute/disks/read" in skipped_rules[0]["missing_permissions"]
    assert rules_failed == 0


def test_http_403_skips_azure_rule():
    """HttpResponseError with status 403 is treated as a skipped rule, not a failure."""
    with patch(
        "cleancloud.providers.azure.scan.AZURE_RULES",
        [_good_rule, _http_403_rule],
    ):
        findings, skipped_rules, rules_failed = _scan_azure_subscription(
            subscription_id="sub-123",
            subscription_name="test-sub",
            credential=MagicMock(),
            region_filter=None,
        )

    assert len(findings) == 1
    assert len(skipped_rules) == 1
    assert skipped_rules[0]["rule"] == "_http_403_rule"
    assert "403" in skipped_rules[0]["missing_permissions"]
    assert rules_failed == 0


def test_http_non_403_is_still_a_failure():
    """HttpResponseError with non-403 status increments rules_failed, not skipped_rules."""
    with patch(
        "cleancloud.providers.azure.scan.AZURE_RULES",
        [_good_rule, _http_404_rule],
    ):
        findings, skipped_rules, rules_failed = _scan_azure_subscription(
            subscription_id="sub-123",
            subscription_name="test-sub",
            credential=MagicMock(),
            region_filter=None,
        )

    assert len(findings) == 1
    assert len(skipped_rules) == 0
    assert rules_failed == 1


def test_all_permission_errors_no_exception():
    """All Azure rules failing with PermissionError returns empty findings without raising."""
    with patch(
        "cleancloud.providers.azure.scan.AZURE_RULES",
        [_permission_error_rule, _http_403_rule],
    ):
        findings, skipped_rules, rules_failed = _scan_azure_subscription(
            subscription_id="sub-123",
            subscription_name="test-sub",
            credential=MagicMock(),
            region_filter=None,
        )

    assert findings == []
    assert len(skipped_rules) == 2
    assert rules_failed == 0
