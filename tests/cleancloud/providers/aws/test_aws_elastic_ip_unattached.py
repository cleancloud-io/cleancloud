from datetime import datetime, timedelta, timezone

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.providers.aws.rules.elastic_ip_unattached import (
    find_unattached_elastic_ips,
)


def test_find_unattached_elastic_ips(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    old_date = datetime.now(timezone.utc) - timedelta(days=60)
    recent_date = datetime.now(timezone.utc) - timedelta(days=10)

    # Mock describe_addresses (non-paginated by AWS)
    ec2.describe_addresses.return_value = {
        "Addresses": [
            {
                "AllocationId": "eipalloc-1",
                "PublicIp": "203.0.113.1",
                "Domain": "vpc",
                "AllocationTime": old_date,
                # No AssociationId = unattached
            },
            {
                "AllocationId": "eipalloc-2",
                "PublicIp": "203.0.113.2",
                "Domain": "vpc",
                "AllocationTime": old_date,
                "AssociationId": "eipassoc-123",  # attached
                "InstanceId": "i-123",
            },
            {
                "AllocationId": "eipalloc-3",
                "PublicIp": "203.0.113.3",
                "Domain": "vpc",
                "AllocationTime": recent_date,  # too young
                # No AssociationId = unattached but recent
            },
            {
                # No AllocationId (genuine EC2-Classic EIP — identified by PublicIp)
                "PublicIp": "203.0.113.4",
                "Domain": "standard",
                # No AllocationTime
                # No AssociationId = unattached
            },
            {
                "AllocationId": "eipalloc-5",
                "PublicIp": "203.0.113.5",
                "Domain": "vpc",
                # No AllocationTime (VPC EIP missing timestamp — should be skipped)
                # No AssociationId = unattached
            },
        ]
    }

    findings = find_unattached_elastic_ips(mock_boto3_session, region)
    eip_ids = {f.resource_id for f in findings}
    findings_by_id = {f.resource_id: f for f in findings}

    # Positive: old (60 days) unattached EIP
    assert "eipalloc-1" in eip_ids

    # Positive: classic EIP (domain=standard) without AllocationTime (flagged conservatively)
    # Uses PublicIp as resource_id since Classic EIPs have no AllocationId
    assert "203.0.113.4" in eip_ids

    # Negative: attached EIP
    assert "eipalloc-2" not in eip_ids

    # Negative: unattached but too young (10 days < 30 day threshold)
    assert "eipalloc-3" not in eip_ids

    # Negative: VPC EIP without AllocationTime — cannot determine age, skip
    assert "eipalloc-5" not in eip_ids

    assert len(findings) == 2

    # Verify cost estimate ($3.75/month for each EIP)
    for f in findings:
        assert f.estimated_monthly_cost_usd == 3.75

    # Verify title includes "(Review Recommended)"
    for f in findings:
        assert f.title == "Unattached Elastic IP (Review Recommended)"

    # Verify confidence is HIGH for all findings
    for f in findings:
        assert f.confidence == ConfidenceLevel.HIGH

    # Verify VPC EIP details and wording
    f1 = findings_by_id["eipalloc-1"]
    assert f1.details["is_classic"] is False
    assert f1.details["age_days"] == 60
    assert "allocation_time" in f1.details
    assert "allocated" in f1.summary and "currently unattached" in f1.summary
    assert "allocated" in f1.evidence.signals_used[1]

    # Verify Classic EIP details, wording, and PublicIp fallback for resource_id
    f4 = findings_by_id["203.0.113.4"]
    assert f4.resource_id == "203.0.113.4"
    assert f4.details["is_classic"] is True
    assert "age_days" not in f4.details
    assert "allocation_time" not in f4.details
    assert "Classic" in f4.summary
    assert any("Classic EIP" in s for s in f4.evidence.signals_used)
    assert any("deprecated" in s for s in f4.evidence.signals_used)
    assert f4.evidence.time_window == "Unknown (Classic EIP, no AllocationTime)"


def test_find_unattached_elastic_ips_custom_threshold(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    date_45_days_ago = datetime.now(timezone.utc) - timedelta(days=45)

    ec2.describe_addresses.return_value = {
        "Addresses": [
            {
                "AllocationId": "eipalloc-5",
                "PublicIp": "203.0.113.5",
                "Domain": "vpc",
                "AllocationTime": date_45_days_ago,
            }
        ]
    }

    # Test with custom 60-day threshold
    findings = find_unattached_elastic_ips(mock_boto3_session, region, days_unattached=60)
    eip_ids = {f.resource_id for f in findings}

    # Should NOT be detected (45 days < 60 days threshold)
    assert "eipalloc-5" not in eip_ids

    # Test with custom 30-day threshold (default)
    findings = find_unattached_elastic_ips(mock_boto3_session, region, days_unattached=30)
    eip_ids = {f.resource_id for f in findings}

    # Should be detected (45 days >= 30 days threshold)
    assert "eipalloc-5" in eip_ids

    # Verify wording uses allocation age, not unattached duration
    f = findings[0]
    assert "allocated" in f.summary
    assert "currently unattached" in f.summary
    assert f.evidence.time_window == "30 days since allocation"


def test_find_unattached_elastic_ips_empty(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    ec2.describe_addresses.return_value = {"Addresses": []}

    findings = find_unattached_elastic_ips(mock_boto3_session, region)

    assert len(findings) == 0
