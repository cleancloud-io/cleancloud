from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from cleancloud.providers.aws.rules.nat_gateway_idle import find_idle_nat_gateways


def test_find_idle_nat_gateways(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    now = datetime.now(timezone.utc)
    old_date = now - timedelta(days=30)
    recent_date = now - timedelta(days=5)

    # Mock paginator for describe_nat_gateways
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "NatGateways": [
                # Idle NAT Gateway (30 days old, no traffic) - should be flagged
                {
                    "NatGatewayId": "nat-idle123",
                    "State": "available",
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "NatGatewayAddresses": [
                        {
                            "AllocationId": "eipalloc-123",
                            "PublicIp": "54.1.2.3",
                            "PrivateIp": "10.0.1.100",
                        }
                    ],
                    "Tags": [{"Key": "Name", "Value": "idle-nat-gateway"}],
                },
                # Active NAT Gateway (has traffic) - should NOT be flagged
                {
                    "NatGatewayId": "nat-active456",
                    "State": "available",
                    "CreateTime": old_date,
                    "VpcId": "vpc-456",
                    "SubnetId": "subnet-456",
                    "NatGatewayAddresses": [],
                    "Tags": [],
                },
                # Young NAT Gateway (5 days old) - should NOT be flagged
                {
                    "NatGatewayId": "nat-young789",
                    "State": "available",
                    "CreateTime": recent_date,
                    "VpcId": "vpc-789",
                    "SubnetId": "subnet-789",
                    "NatGatewayAddresses": [],
                    "Tags": [],
                },
                # Pending NAT Gateway - should NOT be flagged
                {
                    "NatGatewayId": "nat-pending000",
                    "State": "pending",
                    "CreateTime": old_date,
                    "VpcId": "vpc-000",
                    "SubnetId": "subnet-000",
                    "NatGatewayAddresses": [],
                    "Tags": [],
                },
            ]
        }
    ]

    # Mock CloudWatch client
    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        ec2 if service == "ec2" else cloudwatch_mock
    )

    # Mock CloudWatch metrics - idle for nat-idle123, active for nat-active456
    def mock_get_metric_statistics(**kwargs):
        nat_id = kwargs["Dimensions"][0]["Value"]
        if nat_id == "nat-idle123":
            # No traffic
            return {"Datapoints": []}
        elif nat_id == "nat-active456":
            # Has traffic
            return {"Datapoints": [{"Sum": 1000000}]}
        else:
            return {"Datapoints": []}

    cloudwatch_mock.get_metric_statistics.side_effect = mock_get_metric_statistics

    findings = find_idle_nat_gateways(mock_boto3_session, region)
    nat_ids = {f.resource_id for f in findings}

    # Should flag idle NAT Gateway
    assert "nat-idle123" in nat_ids

    # Should NOT flag active NAT Gateway (has traffic)
    assert "nat-active456" not in nat_ids

    # Should NOT flag young NAT Gateway
    assert "nat-young789" not in nat_ids

    # Should NOT flag pending NAT Gateway
    assert "nat-pending000" not in nat_ids

    # Verify finding details
    assert len(findings) == 1
    finding = findings[0]
    assert finding.provider == "aws"
    assert finding.rule_id == "aws.ec2.nat_gateway.idle"
    assert finding.confidence.value == "medium"
    assert finding.risk.value == "medium"
    assert finding.details["name"] == "idle-nat-gateway"
    assert finding.details["vpc_id"] == "vpc-123"
    assert "~$32/month" in finding.details["estimated_monthly_cost"]


def test_find_idle_nat_gateways_empty_account(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [{"NatGateways": []}]

    # Mock CloudWatch client (needed even for empty results)
    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        ec2 if service == "ec2" else cloudwatch_mock
    )

    findings = find_idle_nat_gateways(mock_boto3_session, region)
    assert findings == []


def test_find_idle_nat_gateways_custom_threshold(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    now = datetime.now(timezone.utc)
    # NAT Gateway is 20 days old
    creation_date = now - timedelta(days=20)

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "NatGateways": [
                {
                    "NatGatewayId": "nat-test",
                    "State": "available",
                    "CreateTime": creation_date,
                    "VpcId": "vpc-test",
                    "SubnetId": "subnet-test",
                    "NatGatewayAddresses": [],
                    "Tags": [],
                },
            ]
        }
    ]

    # Mock CloudWatch - no traffic
    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        ec2 if service == "ec2" else cloudwatch_mock
    )
    cloudwatch_mock.get_metric_statistics.return_value = {"Datapoints": []}

    # With 30-day threshold, should NOT be flagged (only 20 days old)
    findings_30 = find_idle_nat_gateways(mock_boto3_session, region, days_idle=30)
    assert len(findings_30) == 0

    # With 14-day threshold, should be flagged (20 > 14)
    findings_14 = find_idle_nat_gateways(mock_boto3_session, region, days_idle=14)
    assert len(findings_14) == 1
    assert findings_14[0].resource_id == "nat-test"


def test_find_idle_nat_gateways_with_traffic(mock_boto3_session):
    """NAT Gateway with traffic should not be flagged."""
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    now = datetime.now(timezone.utc)
    old_date = now - timedelta(days=30)

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "NatGateways": [
                {
                    "NatGatewayId": "nat-active",
                    "State": "available",
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "NatGatewayAddresses": [],
                    "Tags": [],
                },
            ]
        }
    ]

    # Mock CloudWatch - has traffic
    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        ec2 if service == "ec2" else cloudwatch_mock
    )
    cloudwatch_mock.get_metric_statistics.return_value = {
        "Datapoints": [
            {"Sum": 50000000},  # 50 MB of traffic
            {"Sum": 100000000},  # 100 MB of traffic
        ]
    }

    findings = find_idle_nat_gateways(mock_boto3_session, region)
    assert findings == []


def test_find_idle_nat_gateways_title_includes_threshold(mock_boto3_session):
    """Verify title includes the days_idle threshold."""
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    now = datetime.now(timezone.utc)
    old_date = now - timedelta(days=30)

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "NatGateways": [
                {
                    "NatGatewayId": "nat-test",
                    "State": "available",
                    "CreateTime": old_date,
                    "VpcId": "vpc-test",
                    "SubnetId": "subnet-test",
                    "NatGatewayAddresses": [],
                    "Tags": [],
                },
            ]
        }
    ]

    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        ec2 if service == "ec2" else cloudwatch_mock
    )
    cloudwatch_mock.get_metric_statistics.return_value = {"Datapoints": []}

    # Test with custom threshold
    findings = find_idle_nat_gateways(mock_boto3_session, region, days_idle=7)
    assert len(findings) == 1
    assert "7+ Days" in findings[0].title
