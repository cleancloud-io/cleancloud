from typing import Optional

import boto3
from boto3.session import Session


def create_aws_session(profile: Optional[str], region: str) -> Session:
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)

    return boto3.Session(region_name=region)
