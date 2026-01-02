import boto3
import pytest


@pytest.mark.e2e
@pytest.mark.aws
def test_aws_credentials_work():
    session = boto3.Session()
    ec2 = session.client("ec2")
    try:
        regions = ec2.describe_regions()["Regions"]
    except Exception as e:
        pytest.fail(f"AWS auth/session failed: {e}")

    assert len(regions) > 0
