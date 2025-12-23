import pytest
from botocore.exceptions import ClientError

from cleancloud.providers.aws.rules.untagged_resources import find_untagged_resources


@pytest.fixture
def mock_boto3_session(monkeypatch, mocker):
    # Mock boto3 session
    mock_session = mocker.MagicMock()

    # --- Mock EC2 ---
    ec2 = mocker.MagicMock()
    mock_session.client.return_value = ec2
    mock_session.client.side_effect = lambda service_name, region_name=None: {
        "ec2": ec2,
        "s3": s3,
        "logs": logs,
    }[service_name]

    # Mock EBS volumes
    ec2.get_paginator.return_value.paginate.return_value = [
        {
            "Volumes": [
                {"VolumeId": "vol-1", "Tags": None, "AvailabilityZone": "us-east-1a", "Size": 10},
                {
                    "VolumeId": "vol-2",
                    "Tags": [{"Key": "Name", "Value": "prod"}],
                    "AvailabilityZone": "us-east-1b",
                    "Size": 20,
                },
            ]
        }
    ]

    # --- Mock S3 ---
    s3 = mocker.MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "bucket-1"}]}
    s3.get_bucket_tagging.side_effect = ClientError(
        {"Error": {"Code": "NoSuchTagSet", "Message": "No tags"}}, "GetBucketTagging"
    )
    s3.exceptions = type("s3_exceptions", (), {"ClientError": ClientError})

    # --- Mock CloudWatch Logs ---
    logs = mocker.MagicMock()
    logs.get_paginator.return_value.paginate.return_value = [
        {
            "logGroups": [
                {"logGroupName": "/aws/lambda/untagged", "tags": None},
                {"logGroupName": "/aws/lambda/tagged", "tags": {"env": "prod"}},
            ]
        }
    ]

    return mock_session


def test_find_untagged_resources(mock_boto3_session):
    findings = find_untagged_resources(mock_boto3_session, "us-east-1")
    resource_ids = [f.resource_id for f in findings]

    # --- EBS ---
    assert "vol-1" in resource_ids
    assert "vol-2" not in resource_ids

    # --- S3 ---
    assert "bucket-1" in resource_ids

    # --- CloudWatch Logs ---
    assert "/aws/lambda/untagged" in resource_ids
    assert "/aws/lambda/tagged" not in resource_ids
