import boto3
from boto3.session import Session


def create_aws_session(profile: str | None, region: str) -> Session:
    """
    Create a boto3 session.

    Read-only usage only.
    """
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)

    return boto3.Session(region_name=region)
