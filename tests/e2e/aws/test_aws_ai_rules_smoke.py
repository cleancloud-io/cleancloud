from datetime import datetime

import boto3
import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.aws.rules.sagemaker_endpoint_idle import (
    find_idle_sagemaker_endpoints,
)
from cleancloud.providers.aws.rules.sagemaker_notebook_idle import (
    find_idle_sagemaker_notebooks,
)


@pytest.mark.e2e
@pytest.mark.aws
def test_aws_ai_rules_run_without_error():
    session = boto3.Session()
    region = "us-east-1"

    rules = [
        find_idle_sagemaker_endpoints,
        find_idle_sagemaker_notebooks,
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


@pytest.mark.e2e
@pytest.mark.aws
def test_sagemaker_notebook_idle_returns_list_of_findings():
    """Smoke test: rule runs without error and returns typed findings."""
    session = boto3.Session()
    findings = find_idle_sagemaker_notebooks(session, "us-east-1")

    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id == "aws.sagemaker.notebook.idle"
        assert f.resource_type == "aws.sagemaker.notebook"
        assert f.provider == "aws"
        assert f.resource_id
        assert f.region == "us-east-1"
        assert f.detected_at and isinstance(f.detected_at, datetime)
        assert f.estimated_monthly_cost_usd >= 0
        assert f.confidence.value in ("high", "medium")
        assert f.risk.value in ("high", "medium")
