from datetime import datetime, timedelta, timezone

from cleancloud.providers.aws.rules.ebs_snapshot_old import (
    find_old_ebs_snapshots,
)


def test_find_old_ebs_snapshots(mock_boto3_session):
    region = "us-east-1"
    ec2 = mock_boto3_session._ec2

    old_date = datetime.now(timezone.utc) - timedelta(days=90)
    recent_date = datetime.now(timezone.utc) - timedelta(days=5)

    # --- Proper paginator mocking ---
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "Snapshots": [
                {
                    "SnapshotId": "snap-1",
                    "StartTime": old_date,
                    "VolumeSize": 10,
                    "Tags": [],
                },
                {
                    "SnapshotId": "snap-2",
                    "StartTime": recent_date,
                    "VolumeSize": 10,
                    "Tags": [],
                },
            ]
        }
    ]

    findings = find_old_ebs_snapshots(mock_boto3_session, region)
    snapshot_ids = {f.resource_id for f in findings}

    # Positive
    assert "snap-1" in snapshot_ids

    # Negative
    assert "snap-2" not in snapshot_ids

    # Verify cost estimate (10 GB * $0.05/GB)
    finding = [f for f in findings if f.resource_id == "snap-1"][0]
    assert finding.estimated_monthly_cost_usd == 0.5
