"""
Tests for assume_role() — retry logic, ExternalId, AccessDenied handling.
"""

from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from cleancloud.providers.aws.session import assume_role


def _make_hub_session(sts_response=None, side_effect=None):
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_session.client.return_value = mock_sts

    if side_effect:
        mock_sts.assume_role.side_effect = side_effect
    elif sts_response:
        mock_sts.assume_role.return_value = sts_response

    return mock_session, mock_sts


def _sts_response(account_id="111111111111"):
    return {
        "Credentials": {
            "AccessKeyId": "ASIA_FAKE",
            "SecretAccessKey": "fake-secret",
            "SessionToken": "fake-token",
        }
    }


def test_assume_role_returns_session_with_credentials():
    hub_session, mock_sts = _make_hub_session(sts_response=_sts_response())

    with patch("cleancloud.providers.aws.session.boto3.Session") as mock_boto_session:
        assume_role(hub_session, "111111111111", "CleanCloudReadOnlyRole", "us-east-1")

    mock_boto_session.assert_called_once_with(
        aws_access_key_id="ASIA_FAKE",
        aws_secret_access_key="fake-secret",
        aws_session_token="fake-token",
        region_name="us-east-1",
    )


def test_assume_role_builds_correct_arn():
    hub_session, mock_sts = _make_hub_session(sts_response=_sts_response())

    with patch("cleancloud.providers.aws.session.boto3.Session"):
        assume_role(hub_session, "111111111111", "MyCustomRole", "us-east-1")

    call_kwargs = mock_sts.assume_role.call_args[1]
    assert call_kwargs["RoleArn"] == "arn:aws:iam::111111111111:role/MyCustomRole"
    assert call_kwargs["RoleSessionName"] == "cleancloud-111111111111"


def test_assume_role_includes_external_id_when_provided():
    hub_session, mock_sts = _make_hub_session(sts_response=_sts_response())

    with patch("cleancloud.providers.aws.session.boto3.Session"):
        assume_role(hub_session, "111111111111", "MyRole", "us-east-1", external_id="my-secret")

    call_kwargs = mock_sts.assume_role.call_args[1]
    assert call_kwargs["ExternalId"] == "my-secret"


def test_assume_role_omits_external_id_when_not_provided():
    hub_session, mock_sts = _make_hub_session(sts_response=_sts_response())

    with patch("cleancloud.providers.aws.session.boto3.Session"):
        assume_role(hub_session, "111111111111", "MyRole", "us-east-1")

    call_kwargs = mock_sts.assume_role.call_args[1]
    assert "ExternalId" not in call_kwargs


def test_assume_role_raises_immediately_on_access_denied():
    error = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
        "AssumeRole",
    )
    hub_session, mock_sts = _make_hub_session(side_effect=error)

    with pytest.raises(botocore.exceptions.ClientError) as exc_info:
        assume_role(hub_session, "111111111111", "MyRole", "us-east-1", max_attempts=3)

    assert exc_info.value.response["Error"]["Code"] == "AccessDenied"
    # Should not retry — called exactly once
    assert mock_sts.assume_role.call_count == 1


def test_assume_role_retries_on_throttling():
    throttle_error = botocore.exceptions.ClientError(
        {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
        "AssumeRole",
    )
    success_response = _sts_response()

    hub_session, mock_sts = _make_hub_session()
    mock_sts.assume_role.side_effect = [throttle_error, success_response]

    with patch("cleancloud.providers.aws.session.boto3.Session"):
        with patch("cleancloud.providers.aws.session.time.sleep"):
            assume_role(hub_session, "111111111111", "MyRole", "us-east-1", max_attempts=3)

    assert mock_sts.assume_role.call_count == 2


def test_assume_role_raises_after_max_retries():
    throttle_error = botocore.exceptions.ClientError(
        {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
        "AssumeRole",
    )
    hub_session, mock_sts = _make_hub_session(side_effect=throttle_error)

    with pytest.raises(botocore.exceptions.ClientError):
        with patch("cleancloud.providers.aws.session.time.sleep"):
            assume_role(hub_session, "111111111111", "MyRole", "us-east-1", max_attempts=3)

    assert mock_sts.assume_role.call_count == 3
