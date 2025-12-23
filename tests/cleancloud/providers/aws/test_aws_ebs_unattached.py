from datetime import datetime, timedelta, timezone

from cleancloud.providers.aws.rules.ebs_unattached import (
    find_unattached_ebs_volumes,
)


def test_find_unattached_ebs_volumes(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    old_date = datetime.now(timezone.utc) - timedelta(days=60)

    # --- Proper paginator mocking ---
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "Volumes": [
                {
                    "VolumeId": "vol-1",
                    "State": "available",  # unattached
                    "CreateTime": old_date,
                    "Size": 10,
                    "AvailabilityZone": "us-east-1a",
                    "Tags": [],
                },
                {
                    "VolumeId": "vol-2",
                    "State": "in-use",  # attached
                    "CreateTime": old_date,
                    "Size": 20,
                    "AvailabilityZone": "us-east-1a",
                    "Tags": [],
                },
            ]
        }
    ]

    findings = find_unattached_ebs_volumes(mock_boto3_session, region)
    volume_ids = {f.resource_id for f in findings}

    # Positive
    assert "vol-1" in volume_ids

    # Negative
    assert "vol-2" not in volume_ids
