"""
Tests for multi-account scanning — aggregation, isolation, failure handling,
org discovery, and account tagging on findings.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from cleancloud.config.accounts import AccountConfig, MultiAccountConfig
from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.multi_account import (
    AccountScanResult,
    discover_org_accounts,
    scan_account,
    scan_multiple_accounts,
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


def _access_denied():
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Not authorized to assume role"}},
        "AssumeRole",
    )


# ---------------------------------------------------------------------------
# scan_account
# ---------------------------------------------------------------------------


@patch("cleancloud.providers.aws.multi_account.scan_aws_regions_with_session")
@patch("cleancloud.providers.aws.multi_account.assume_role")
@patch("cleancloud.providers.aws.multi_account.create_aws_session")
def test_scan_account_success_tags_findings(mock_create_session, mock_assume, mock_scan):
    mock_assume.return_value = MagicMock()
    finding = _make_finding()
    mock_scan.return_value = ([finding], [], [])

    account = AccountConfig(id="111111111111", name="prod")
    result = scan_account(
        profile=None,
        account=account,
        role_name="CleanCloudReadOnlyRole",
        region="us-east-1",
        external_id=None,
        regions_override=["us-east-1"],
    )

    assert result.status == "success"
    assert len(result.findings) == 1
    assert result.findings[0].account_id == "111111111111"
    assert result.findings[0].account_name == "prod"


@patch("cleancloud.providers.aws.multi_account.assume_role")
@patch("cleancloud.providers.aws.multi_account.create_aws_session")
def test_scan_account_access_denied_returns_failed(mock_create_session, mock_assume):
    mock_assume.side_effect = _access_denied()

    account = AccountConfig(id="111111111111", name="prod")
    result = scan_account(
        profile=None,
        account=account,
        role_name="CleanCloudReadOnlyRole",
        region="us-east-1",
        external_id=None,
    )

    assert result.status == "failed"
    assert result.findings == []
    assert "AccessDenied" in result.error


@patch("cleancloud.providers.aws.multi_account.assume_role")
@patch("cleancloud.providers.aws.multi_account.create_aws_session")
def test_scan_account_unexpected_error_returns_failed(mock_create_session, mock_assume):
    mock_assume.side_effect = RuntimeError("network timeout")

    account = AccountConfig(id="111111111111", name="prod")
    result = scan_account(
        profile=None,
        account=account,
        role_name="CleanCloudReadOnlyRole",
        region="us-east-1",
        external_id=None,
    )

    assert result.status == "failed"
    assert "network timeout" in result.error


@patch("cleancloud.providers.aws.multi_account.scan_aws_regions_with_session")
@patch("cleancloud.providers.aws.multi_account._get_active_aws_regions")
@patch("cleancloud.providers.aws.multi_account.assume_role")
@patch("cleancloud.providers.aws.multi_account.create_aws_session")
def test_scan_account_all_regions_uses_assumed_session(
    mock_create_session, mock_assume, mock_get_regions, mock_scan
):
    assumed_session = MagicMock()
    mock_assume.return_value = assumed_session
    mock_get_regions.return_value = ["us-east-1", "eu-west-1"]
    mock_scan.return_value = ([], [], [])

    account = AccountConfig(id="111111111111", name="prod")
    scan_account(
        profile=None,
        account=account,
        role_name="CleanCloudReadOnlyRole",
        region=None,
        external_id=None,
        regions_override=None,  # triggers per-account discovery
    )

    # Region discovery must use the assumed session, not hub
    mock_get_regions.assert_called_once_with(assumed_session)
    mock_scan.assert_called_once_with(assumed_session, ["us-east-1", "eu-west-1"])


@patch("cleancloud.providers.aws.multi_account.scan_aws_regions_with_session")
@patch("cleancloud.providers.aws.multi_account._get_active_aws_regions")
@patch("cleancloud.providers.aws.multi_account.assume_role")
@patch("cleancloud.providers.aws.multi_account.create_aws_session")
def test_scan_account_all_regions_falls_back_to_us_east_1_when_none_detected(
    mock_create_session, mock_assume, mock_get_regions, mock_scan
):
    mock_assume.return_value = MagicMock()
    mock_get_regions.return_value = []  # No active regions found
    mock_scan.return_value = ([], [], [])

    account = AccountConfig(id="111111111111", name="prod")
    result = scan_account(
        profile=None,
        account=account,
        role_name="CleanCloudReadOnlyRole",
        region=None,
        external_id=None,
        regions_override=None,  # triggers per-account discovery
    )

    mock_scan.assert_called_once_with(mock_assume.return_value, ["us-east-1"])
    assert result.regions_scanned == ["us-east-1"]


# ---------------------------------------------------------------------------
# scan_multiple_accounts
# ---------------------------------------------------------------------------


@patch("cleancloud.providers.aws.multi_account.scan_account")
@patch("cleancloud.providers.aws.multi_account.create_aws_session")
def test_scan_multiple_accounts_aggregates_findings(mock_create_session, mock_scan_account):
    mock_create_session.return_value = MagicMock()
    mock_create_session.return_value.client.return_value.get_caller_identity.return_value = {
        "Account": "000000000000"
    }

    finding_a = _make_finding("vol-1")
    finding_b = _make_finding("vol-2")
    mock_scan_account.side_effect = [
        AccountScanResult(
            account_id="111111111111", account_name="prod", findings=[finding_a], status="success"
        ),
        AccountScanResult(
            account_id="222222222222", account_name="dev", findings=[finding_b], status="success"
        ),
    ]

    config = MultiAccountConfig(
        accounts=[
            AccountConfig(id="111111111111", name="prod"),
            AccountConfig(id="222222222222", name="dev"),
        ],
        role_name="CleanCloudReadOnlyRole",
    )
    results = scan_multiple_accounts(config, region="us-east-1", all_regions=False, profile=None)

    assert len(results) == 2
    all_findings = [f for r in results for f in r.findings]
    assert len(all_findings) == 2


@patch("cleancloud.providers.aws.multi_account.scan_account")
@patch("cleancloud.providers.aws.multi_account.create_aws_session")
def test_scan_multiple_accounts_one_failure_does_not_stop_others(
    mock_create_session, mock_scan_account
):
    mock_create_session.return_value = MagicMock()
    mock_create_session.return_value.client.return_value.get_caller_identity.return_value = {
        "Account": "000000000000"
    }

    finding = _make_finding("vol-1")
    mock_scan_account.side_effect = [
        AccountScanResult(
            account_id="111111111111",
            account_name="prod",
            status="failed",
            error="AccessDenied: role not found",
        ),
        AccountScanResult(
            account_id="222222222222", account_name="dev", findings=[finding], status="success"
        ),
    ]

    config = MultiAccountConfig(
        accounts=[
            AccountConfig(id="111111111111", name="prod"),
            AccountConfig(id="222222222222", name="dev"),
        ],
        role_name="CleanCloudReadOnlyRole",
    )
    results = scan_multiple_accounts(config, region="us-east-1", all_regions=False, profile=None)

    statuses = {r.account_id: r.status for r in results}
    assert statuses["111111111111"] == "failed"
    assert statuses["222222222222"] == "success"


# ---------------------------------------------------------------------------
# discover_org_accounts
# ---------------------------------------------------------------------------


def test_discover_org_accounts_returns_active_only():
    mock_session = MagicMock()
    mock_orgs = MagicMock()
    mock_session.client.return_value = mock_orgs

    mock_orgs.get_paginator.return_value.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111111111111", "Name": "prod", "Status": "ACTIVE"},
                {"Id": "222222222222", "Name": "suspended-account", "Status": "SUSPENDED"},
                {"Id": "333333333333", "Name": "dev", "Status": "ACTIVE"},
            ]
        }
    ]

    accounts = discover_org_accounts(mock_session)

    assert len(accounts) == 2
    ids = [a.id for a in accounts]
    assert "111111111111" in ids
    assert "333333333333" in ids
    assert "222222222222" not in ids


def test_discover_org_accounts_raises_permission_error_on_access_denied():
    mock_session = MagicMock()
    mock_orgs = MagicMock()
    mock_session.client.return_value = mock_orgs

    mock_orgs.get_paginator.return_value.paginate.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Not authorized"}},
        "ListAccounts",
    )

    with pytest.raises(PermissionError, match="organizations:ListAccounts"):
        discover_org_accounts(mock_session)


def test_discover_org_accounts_raises_on_empty_org():
    mock_session = MagicMock()
    mock_orgs = MagicMock()
    mock_session.client.return_value = mock_orgs

    mock_orgs.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [{"Id": "111111111111", "Name": "old", "Status": "SUSPENDED"}]}
    ]

    with pytest.raises(ValueError, match="No active accounts"):
        discover_org_accounts(mock_session)
