import boto3
import pytest

from cleancloud.safety.aws.allowlist import FORBIDDEN_AWS_API_PREFIXES


class ForbiddenAwsCallError(Exception):
    pass


@pytest.fixture(autouse=True)
def guard_boto3_clients(monkeypatch):
    """
    Intercept boto3 client usage and block any mutating API calls at runtime.
    """

    original_client = boto3.client

    def guarded_client(*args, **kwargs):
        client = original_client(*args, **kwargs)
        original_getattr = client.__getattribute__

        def guarded_getattr(name):
            for forbidden in FORBIDDEN_AWS_API_PREFIXES:
                if name.startswith(forbidden):
                    raise ForbiddenAwsCallError(
                        f"Forbidden AWS SDK call attempted at runtime: {name}"
                    )
            return original_getattr(name)

        monkeypatch.setattr(client, "__getattribute__", guarded_getattr)
        return client

    monkeypatch.setattr(boto3, "client", guarded_client)


@pytest.mark.safety
@pytest.mark.aws
def test_runtime_guard_allows_readonly_calls():
    """
    Sanity check: Describe/List/Get calls must remain accessible.
    """
    ec2 = boto3.client("ec2", region_name="us-east-1")

    # Do not call AWS — just validate attribute access
    assert hasattr(ec2, "describe_volumes")
