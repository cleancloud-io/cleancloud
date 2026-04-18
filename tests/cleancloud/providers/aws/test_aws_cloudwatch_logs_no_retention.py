from cleancloud.providers.aws.rules.cloudwatch_logs_no_retention import (
    find_cloudwatch_logs_no_retention,
)


def _run(mock_boto3_session, log_groups):
    logs = mock_boto3_session._logs
    paginator = logs.get_paginator.return_value
    paginator.paginate.return_value = [{"logGroups": log_groups}]
    return find_cloudwatch_logs_no_retention(mock_boto3_session, "us-east-1")


def test_find_cloudwatch_logs_no_retention(mock_boto3_session):
    findings = _run(
        mock_boto3_session,
        [
            {"logGroupName": "/aws/lambda/never-expire", "storedBytes": 12345},
            {"logGroupName": "/aws/lambda/expire-30", "retentionInDays": 30},
        ],
    )
    resource_ids = {f.resource_id for f in findings}
    assert "/aws/lambda/never-expire" in resource_ids
    assert "/aws/lambda/expire-30" not in resource_ids


def test_risk_level_high_for_large_group(mock_boto3_session):
    """≥ 1 GB stored → HIGH risk."""
    findings = _run(
        mock_boto3_session,
        [{"logGroupName": "/large/group", "storedBytes": 2 * 1024**3}],  # 2 GB
    )
    assert len(findings) == 1
    assert findings[0].risk.value == "high"


def test_risk_level_medium_for_small_group(mock_boto3_session):
    """Non-zero but < 1 GB stored → MEDIUM risk."""
    findings = _run(
        mock_boto3_session,
        [{"logGroupName": "/small/group", "storedBytes": 512 * 1024}],  # 512 KB
    )
    assert len(findings) == 1
    assert findings[0].risk.value == "medium"


def test_risk_level_low_for_empty_group(mock_boto3_session):
    """Zero storedBytes → LOW risk (policy gap only, no current cost)."""
    findings = _run(
        mock_boto3_session,
        [{"logGroupName": "/empty/group", "storedBytes": 0}],
    )
    assert len(findings) == 1
    assert findings[0].risk.value == "low"


def test_zero_stored_bytes_still_flagged(mock_boto3_session):
    """Empty log group is still flagged — zero storedBytes ≠ no future cost risk."""
    findings = _run(
        mock_boto3_session,
        [{"logGroupName": "/new/empty", "storedBytes": 0}],
    )
    assert len(findings) == 1
    assert "grow rapidly" in findings[0].details["estimated_monthly_storage_cost"]
