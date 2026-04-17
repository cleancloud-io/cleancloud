import time
from typing import Optional

import boto3
import botocore.exceptions
from boto3.session import Session
from botocore.config import Config

# Applied to all STS and Organizations clients in multi-account scanning.
# Standard mode uses exponential backoff with jitter — handles throttling
# when scanning many accounts in parallel.
BOTO_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})


def create_aws_session(profile: Optional[str], region: str) -> Session:
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def assume_role(
    session: Session,
    account_id: str,
    role_name: str,
    region: str,
    external_id: Optional[str] = None,
    max_attempts: int = 3,
) -> Session:
    """
    Assume a cross-account IAM role and return a new boto3 Session
    backed by the temporary credentials.

    Retries on throttling/transient errors with exponential backoff.
    Raises immediately on AccessDenied or invalid role ARN.
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    session_name = f"cleancloud-{account_id}"

    params: dict = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": 900,  # 15 min — enough for any scan, works with all MaxSessionDuration configs
    }
    if external_id:
        params["ExternalId"] = external_id

    sts = session.client("sts", config=BOTO_CONFIG)

    last_error: Exception = RuntimeError("assume_role failed with no attempts")
    for attempt in range(1, max_attempts + 1):
        try:
            response = sts.assume_role(**params)
            creds = response["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            # Non-retryable: bad config or explicit denial
            if code in (
                "AccessDenied",
                "NoSuchEntity",
                "ValidationError",
                "InvalidParameter",
            ):
                raise
            # Retryable: throttling or transient AWS errors
            last_error = e
            if attempt < max_attempts:
                time.sleep(2**attempt)
        except Exception as e:
            last_error = e
            if attempt < max_attempts:
                time.sleep(2**attempt)

    raise last_error
