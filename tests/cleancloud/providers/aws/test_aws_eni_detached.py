from datetime import datetime, timedelta, timezone

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.providers.aws.rules.eni_detached import find_detached_enis


def test_find_detached_enis(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    old_date = datetime.now(timezone.utc) - timedelta(days=90)  # Older than 60-day threshold
    recent_date = datetime.now(timezone.utc) - timedelta(days=30)  # Younger than 60-day threshold

    # Mock paginator for describe_network_interfaces
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-1",
                    "Status": "available",  # Detached
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "User-created ENI",
                    "InterfaceType": "interface",  # Standard ENI
                    "TagSet": [{"Key": "Name", "Value": "test-eni"}],
                },
                {
                    "NetworkInterfaceId": "eni-2",
                    "Status": "in-use",  # Attached
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "Attached ENI",
                    "InterfaceType": "interface",
                },
                {
                    "NetworkInterfaceId": "eni-3",
                    "Status": "available",  # Detached but recent
                    "CreateTime": recent_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "Recently created",
                    "InterfaceType": "interface",
                },
                {
                    "NetworkInterfaceId": "eni-4",
                    "Status": "available",  # AWS infrastructure (Load Balancer)
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "ELB app/my-alb/1234567890",
                    "InterfaceType": "load_balancer",  # AWS infrastructure - exclude
                },
                {
                    "NetworkInterfaceId": "eni-5",
                    "Status": "available",  # Detached Lambda ENI (USER resource - should flag!)
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "AWS Lambda VPC ENI-my-function",
                    "InterfaceType": "interface",  # Standard ENI type
                    "RequesterManaged": True,  # Created by AWS service, but YOUR resource
                },
                {
                    "NetworkInterfaceId": "eni-6",
                    "Status": "available",  # Detached, old, no tags
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "",
                    "InterfaceType": "interface",
                    "TagSet": [],
                },
            ]
        }
    ]

    findings = find_detached_enis(mock_boto3_session, region)
    eni_ids = {f.resource_id for f in findings}
    findings_by_id = {f.resource_id: f for f in findings}

    # Positive: old (90 days) detached standard ENI with tags
    assert "eni-1" in eni_ids

    # Positive: old (90 days) detached Lambda ENI (RequesterManaged but user resource!)
    assert "eni-5" in eni_ids

    # Positive: old (90 days) detached ENI without tags
    assert "eni-6" in eni_ids

    # Negative: attached ENI
    assert "eni-2" not in eni_ids

    # Negative: detached but too young (30 days < 60 day threshold)
    assert "eni-3" not in eni_ids

    # Negative: AWS infrastructure (Load Balancer)
    assert "eni-4" not in eni_ids

    # Verify we got exactly 3 findings (including Lambda ENI)
    assert len(findings) == 3

    # Verify title includes "(Review Recommended)"
    for f in findings:
        assert f.title == "Detached Network Interface (Review Recommended)"

    # Verify confidence is MEDIUM for all findings
    for f in findings:
        assert f.confidence == ConfidenceLevel.MEDIUM

    # Verify standard ENI details
    f1 = findings_by_id["eni-1"]
    assert f1.details["interface_type"] == "interface"
    assert f1.details["requester_managed"] is False
    assert f1.details["age_days"] == 90
    assert "created" in f1.summary and "currently detached" in f1.summary

    # Verify Lambda ENI details and requester-managed signal
    f5 = findings_by_id["eni-5"]
    assert f5.details["interface_type"] == "interface"
    assert f5.details["requester_managed"] is True
    assert any("requester-managed" in s for s in f5.evidence.signals_used)

    # Verify untagged ENI has "no tags" signal
    f6 = findings_by_id["eni-6"]
    assert f6.details["requester_managed"] is False
    assert any("no tags" in s for s in f6.evidence.signals_used)

    # Verify Hyperplane in signals_not_checked
    for f in findings:
        assert any("Hyperplane" in s for s in f.evidence.signals_not_checked)


def test_find_detached_enis_custom_threshold(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    date_45_days_ago = datetime.now(timezone.utc) - timedelta(days=45)

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-7",
                    "Status": "available",
                    "CreateTime": date_45_days_ago,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "Test ENI",
                    "InterfaceType": "interface",
                }
            ]
        }
    ]

    # Test with custom 60-day threshold
    findings = find_detached_enis(mock_boto3_session, region, max_age_days=60)
    eni_ids = {f.resource_id for f in findings}

    # Should NOT be detected (45 days < 60 days threshold)
    assert "eni-7" not in eni_ids

    # Test with custom 30-day threshold
    findings = find_detached_enis(mock_boto3_session, region, max_age_days=30)
    eni_ids = {f.resource_id for f in findings}

    # Should be detected (45 days >= 30 days threshold)
    assert "eni-7" in eni_ids

    # Verify wording uses creation age, not detached duration
    f = findings[0]
    assert "created" in f.summary
    assert "currently detached" in f.summary
    assert f.evidence.time_window == "30 days since creation"


def test_find_detached_enis_empty(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [{"NetworkInterfaces": []}]

    findings = find_detached_enis(mock_boto3_session, region)

    assert len(findings) == 0


def test_find_detached_enis_interface_types(mock_boto3_session):
    """Test that InterfaceType correctly distinguishes AWS infrastructure from user resources."""
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    old_date = datetime.now(timezone.utc) - timedelta(days=60)

    # Test various interface types
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-user-1",
                    "Status": "available",
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "User-created ENI",
                    "InterfaceType": "interface",  # Standard - should be flagged
                },
                {
                    "NetworkInterfaceId": "eni-lambda-1",
                    "Status": "available",
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "Lambda VPC ENI",
                    "InterfaceType": "interface",  # Lambda = user resource - should be flagged!
                    "RequesterManaged": True,
                },
                {
                    "NetworkInterfaceId": "eni-elb-1",
                    "Status": "available",
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "ELB app/my-alb/1234567890",
                    "InterfaceType": "load_balancer",  # AWS infrastructure - exclude
                },
                {
                    "NetworkInterfaceId": "eni-nat-1",
                    "Status": "available",
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "NAT Gateway",
                    "InterfaceType": "nat_gateway",  # AWS infrastructure - exclude
                },
                {
                    "NetworkInterfaceId": "eni-vpce-1",
                    "Status": "available",
                    "CreateTime": old_date,
                    "VpcId": "vpc-123",
                    "SubnetId": "subnet-123",
                    "AvailabilityZone": "us-east-1a",
                    "Description": "VPC Endpoint",
                    "InterfaceType": "vpc_endpoint",  # AWS infrastructure - exclude
                },
            ]
        }
    ]

    findings = find_detached_enis(mock_boto3_session, region)
    eni_ids = {f.resource_id for f in findings}
    findings_by_id = {f.resource_id: f for f in findings}

    # Should flag user resources (including Lambda!)
    assert "eni-user-1" in eni_ids
    assert "eni-lambda-1" in eni_ids  # Lambda ENI is a user resource!

    # Should exclude AWS infrastructure
    assert "eni-elb-1" not in eni_ids
    assert "eni-nat-1" not in eni_ids
    assert "eni-vpce-1" not in eni_ids

    assert len(findings) == 2  # Only user-1 and lambda-1

    # Verify interface_type and requester_managed in details
    f_user = findings_by_id["eni-user-1"]
    assert f_user.details["interface_type"] == "interface"
    assert f_user.details["requester_managed"] is False

    f_lambda = findings_by_id["eni-lambda-1"]
    assert f_lambda.details["interface_type"] == "interface"
    assert f_lambda.details["requester_managed"] is True
    assert any("requester-managed" in s for s in f_lambda.evidence.signals_used)
