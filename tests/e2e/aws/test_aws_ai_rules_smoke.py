from datetime import datetime

import boto3
import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.aws.rules.ec2_gpu_idle import find_idle_gpu_instances
from cleancloud.providers.aws.rules.sagemaker_endpoint_idle import (
    find_idle_sagemaker_endpoints,
)
from cleancloud.providers.aws.rules.sagemaker_notebook_idle import (
    find_idle_sagemaker_notebooks,
)

_AWS_AI_RULE_IDS = {
    "aws.sagemaker.endpoint.idle",
    "aws.sagemaker.notebook.idle",
    "aws.ec2.gpu.idle",
}


@pytest.mark.e2e
@pytest.mark.aws
def test_aws_ai_rules_run_without_error():
    session = boto3.Session()
    region = "us-east-1"

    rules = [
        find_idle_sagemaker_endpoints,
        find_idle_sagemaker_notebooks,
        find_idle_gpu_instances,
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
        assert f.rule_id in _AWS_AI_RULE_IDS
        assert f.resource_id
        assert f.region
        assert f.detected_at and isinstance(f.detected_at, datetime)


@pytest.mark.e2e
@pytest.mark.aws
def test_ec2_gpu_idle_returns_list_of_findings():
    """Smoke test: rule runs without error and returns typed findings."""
    session = boto3.Session()
    findings = find_idle_gpu_instances(session, "us-east-1")

    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id == "aws.ec2.gpu.idle"
        assert f.resource_type == "aws.ec2.instance"
        assert f.provider == "aws"
        assert f.resource_id
        assert f.region == "us-east-1"
        assert f.detected_at and isinstance(f.detected_at, datetime)
        assert f.estimated_monthly_cost_usd > 0
        assert f.confidence.value in ("high", "medium")
        assert f.risk.value in ("critical", "high")
        assert f.details["gpu_metric_available"] in (True, False)
        assert f.details["idle_signal"] in ("gpu_utilisation", "cpu_utilisation_fallback")


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
