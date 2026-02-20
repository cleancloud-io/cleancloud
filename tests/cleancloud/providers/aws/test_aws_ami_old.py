from datetime import datetime, timedelta, timezone

from cleancloud.providers.aws.rules.ami_old import find_old_amis


def test_find_old_amis(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    old_date = datetime.now(timezone.utc) - timedelta(days=200)
    recent_date = datetime.now(timezone.utc) - timedelta(days=30)

    # Mock paginator
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "Images": [
                # Old AMI - should be flagged
                {
                    "ImageId": "ami-old123",
                    "Name": "old-golden-image",
                    "CreationDate": old_date.isoformat(),
                    "State": "available",
                    "PlatformDetails": "Linux/UNIX",
                    "Architecture": "x86_64",
                    "RootDeviceType": "ebs",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/xvda",
                            "Ebs": {
                                "SnapshotId": "snap-abc123",
                                "VolumeSize": 50,
                            },
                        }
                    ],
                    "Tags": [{"Key": "Name", "Value": "OldImage"}],
                },
                # Recent AMI - should NOT be flagged
                {
                    "ImageId": "ami-new456",
                    "Name": "new-image",
                    "CreationDate": recent_date.isoformat(),
                    "State": "available",
                    "PlatformDetails": "Linux/UNIX",
                    "Architecture": "x86_64",
                    "RootDeviceType": "ebs",
                    "BlockDeviceMappings": [],
                    "Tags": [],
                },
                # Old but pending AMI - should NOT be flagged
                {
                    "ImageId": "ami-pending789",
                    "Name": "pending-image",
                    "CreationDate": old_date.isoformat(),
                    "State": "pending",
                    "PlatformDetails": "Linux/UNIX",
                    "Architecture": "x86_64",
                    "RootDeviceType": "ebs",
                    "BlockDeviceMappings": [],
                    "Tags": [],
                },
            ]
        }
    ]

    findings = find_old_amis(mock_boto3_session, region)
    ami_ids = {f.resource_id for f in findings}

    # Should flag old available AMI
    assert "ami-old123" in ami_ids

    # Should NOT flag recent AMI
    assert "ami-new456" not in ami_ids

    # Should NOT flag pending AMI
    assert "ami-pending789" not in ami_ids

    # Verify finding details
    assert len(findings) == 1
    finding = findings[0]
    assert finding.provider == "aws"
    assert finding.rule_id == "aws.ec2.ami.old"
    assert finding.confidence.value == "medium"
    assert finding.risk.value == "low"
    assert finding.details["ami_name"] == "old-golden-image"
    assert finding.details["age_days"] >= 200
    assert finding.details["total_size_gb"] == 50
    assert "snap-abc123" in finding.details["snapshot_ids"]
    assert finding.estimated_monthly_cost_usd == 2.5  # 50 GB * $0.05


def test_find_old_amis_empty_account(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [{"Images": []}]

    findings = find_old_amis(mock_boto3_session, region)
    assert findings == []


def test_find_old_amis_custom_threshold(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    # AMI is 100 days old
    creation_date = datetime.now(timezone.utc) - timedelta(days=100)

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "Images": [
                {
                    "ImageId": "ami-test",
                    "Name": "test-image",
                    "CreationDate": creation_date.isoformat(),
                    "State": "available",
                    "PlatformDetails": "Linux/UNIX",
                    "Architecture": "x86_64",
                    "RootDeviceType": "ebs",
                    "BlockDeviceMappings": [],
                    "Tags": [],
                },
            ]
        }
    ]

    # With 180-day threshold (default), should NOT be flagged
    findings_180 = find_old_amis(mock_boto3_session, region, days_old=180)
    assert len(findings_180) == 0

    # With 90-day threshold, should be flagged
    findings_90 = find_old_amis(mock_boto3_session, region, days_old=90)
    assert len(findings_90) == 1
    assert findings_90[0].resource_id == "ami-test"


def test_find_old_amis_no_creation_date(mock_boto3_session):
    """AMIs without creation date should be skipped."""
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "Images": [
                {
                    "ImageId": "ami-nodate",
                    "Name": "no-date-image",
                    "State": "available",
                    # No CreationDate field
                },
            ]
        }
    ]

    findings = find_old_amis(mock_boto3_session, region)
    assert findings == []


def test_find_old_amis_cost_estimate(mock_boto3_session):
    """Verify cost estimates are calculated based on snapshot size."""
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    old_date = datetime.now(timezone.utc) - timedelta(days=200)

    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "Images": [
                {
                    "ImageId": "ami-large",
                    "Name": "large-image",
                    "CreationDate": old_date.isoformat(),
                    "State": "available",
                    "PlatformDetails": "Linux/UNIX",
                    "Architecture": "x86_64",
                    "RootDeviceType": "ebs",
                    "BlockDeviceMappings": [
                        {"Ebs": {"SnapshotId": "snap-1", "VolumeSize": 100}},
                        {"Ebs": {"SnapshotId": "snap-2", "VolumeSize": 500}},
                    ],
                    "Tags": [],
                },
            ]
        }
    ]

    findings = find_old_amis(mock_boto3_session, region)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.details["total_size_gb"] == 600
    assert "$30.00/month" in finding.details["estimated_monthly_cost"]
    assert finding.estimated_monthly_cost_usd == 30.0  # 600 GB * $0.05
