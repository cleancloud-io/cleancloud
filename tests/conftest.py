from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_boto3_session():
    session = MagicMock()

    ec2 = MagicMock()
    s3 = MagicMock()
    logs = MagicMock()
    rds = MagicMock()
    elbv2 = MagicMock()
    elb = MagicMock()

    def client_side_effect(service_name, *args, **kwargs):
        if service_name == "ec2":
            return ec2
        if service_name == "s3":
            return s3
        if service_name == "logs":
            return logs
        if service_name == "rds":
            return rds
        if service_name == "elbv2":
            return elbv2
        if service_name == "elb":
            return elb
        raise ValueError(f"Unexpected service: {service_name}")

    session.client.side_effect = client_side_effect

    # Attach for test access
    session._ec2 = ec2
    session._s3 = s3
    session._logs = logs
    session._rds = rds
    session._elbv2 = elbv2
    session._elb = elb

    return session
