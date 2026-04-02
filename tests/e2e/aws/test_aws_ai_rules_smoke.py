from datetime import datetime

import boto3
import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.aws.rules.sagemaker_endpoint_idle import (
    find_idle_sagemaker_endpoints,
)


@pytest.mark.e2e
@pytest.mark.aws
def test_aws_ai_rules_run_without_error():
    session = boto3.Session()
    region = "us-east-1"

    rules = [
        find_idle_sagemaker_endpoints,
    ]

    all_results = []
    for rule in rules:
        rule_results = rule(session, region)
        assert isinstance(
            rule_results, list
        ), f"{rule.__name__} returned {type(rule_results)} instead of list"
        all_results.extend(rule_results)

    for f in all_results:
        assert isinstance(f, Finding)
        assert f.provider == "aws"
        assert f.rule_id.startswith("aws.sagemaker.")
        assert f.resource_id
        assert f.region
        assert f.detected_at and isinstance(f.detected_at, datetime)
