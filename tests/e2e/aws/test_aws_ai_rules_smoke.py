from datetime import datetime

import boto3
import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.aws.rules.ai.bedrock_provisioned_idle import (
    find_idle_bedrock_provisioned_throughputs,
)
from cleancloud.providers.aws.rules.ai.ec2_gpu_idle import find_idle_gpu_instances
from cleancloud.providers.aws.rules.ai.sagemaker_endpoint_idle import (
    find_idle_sagemaker_endpoints,
)
from cleancloud.providers.aws.rules.ai.sagemaker_notebook_idle import (
    find_idle_sagemaker_notebooks,
)
from cleancloud.providers.aws.rules.ai.sagemaker_studio_app_idle import (
    find_idle_sagemaker_studio_apps,
)
from cleancloud.providers.aws.rules.ai.sagemaker_training_job_long_running import (
    find_long_running_sagemaker_training_jobs,
)

_AWS_AI_RULE_IDS = {
    "aws.sagemaker.endpoint.idle",
    "aws.sagemaker.notebook.idle",
    "aws.ec2.gpu.idle",
    "aws.bedrock.provisioned_throughput.idle",
    "aws.sagemaker.studio_app.idle",
    "aws.sagemaker.training_job.long_running",
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
        find_idle_bedrock_provisioned_throughputs,
        find_idle_sagemaker_studio_apps,
        find_long_running_sagemaker_training_jobs,
    ]

    all_results = []
    for rule in rules:
        try:
            rule_results = rule(session, region)
        except PermissionError as e:
            pytest.fail(f"Missing IAM permissions for {rule.__name__}: {e}")
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
        assert f.details["idle_signal"] in (
            "gpu_utilisation",
            "cpu_utilisation_fallback",
        )


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


@pytest.mark.e2e
@pytest.mark.aws
def test_bedrock_provisioned_throughput_idle_returns_list_of_findings():
    """Smoke test: rule runs without error and returns typed findings."""
    session = boto3.Session()
    try:
        findings = find_idle_bedrock_provisioned_throughputs(session, "us-east-1")
    except PermissionError as e:
        pytest.fail(f"Missing IAM permissions: {e}")

    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id == "aws.bedrock.provisioned_throughput.idle"
        assert f.resource_type == "aws.bedrock.provisioned_throughput"
        assert f.provider == "aws"
        assert f.resource_id
        assert f.region == "us-east-1"
        assert f.detected_at and isinstance(f.detected_at, datetime)
        assert f.confidence.value in ("high", "medium")
        assert f.risk.value in ("critical", "high")
        assert "desired_model_units" in f.details
        assert "commitment_duration" in f.details


@pytest.mark.e2e
@pytest.mark.aws
def test_sagemaker_studio_app_idle_returns_list_of_findings():
    """Smoke test: rule runs without error and returns typed findings."""
    session = boto3.Session()
    try:
        findings = find_idle_sagemaker_studio_apps(session, "us-east-1")
    except PermissionError as e:
        pytest.fail(f"Missing IAM permissions: {e}")

    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id == "aws.sagemaker.studio_app.idle"
        assert f.resource_type == "aws.sagemaker.studio_app"
        assert f.provider == "aws"
        assert f.resource_id
        assert f.region == "us-east-1"
        assert f.detected_at and isinstance(f.detected_at, datetime)
        assert f.confidence.value in ("high", "medium")
        assert f.risk.value in ("critical", "high", "medium")
        assert "domain_id" in f.details
        assert "app_type" in f.details
        assert f.details["app_type"] in ("KernelGateway", "JupyterLab", "CodeEditor")
        assert "waste_score" in f.details
        assert "cost_basis" in f.details


@pytest.mark.e2e
@pytest.mark.aws
def test_sagemaker_training_job_long_running_returns_list_of_findings():
    """Smoke test: rule runs without error and returns typed findings."""
    session = boto3.Session()
    try:
        findings = find_long_running_sagemaker_training_jobs(session, "us-east-1")
    except PermissionError as e:
        pytest.fail(f"Missing IAM permissions: {e}")

    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id == "aws.sagemaker.training_job.long_running"
        assert f.resource_type == "aws.sagemaker.training_job"
        assert f.provider == "aws"
        assert f.resource_id
        assert f.region == "us-east-1"
        assert f.detected_at and isinstance(f.detected_at, datetime)
        assert f.confidence.value in ("high", "medium")
        assert f.risk.value in ("critical", "high", "medium")
        assert "job_name" in f.details
        assert "instance_type" in f.details
        assert "instance_count" in f.details
        assert "duration_hours" in f.details
        assert "accrued_cost_usd" in f.details
        assert "cost_basis" in f.details
