from datetime import datetime

import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.gcp.rules.vertex_endpoint_idle import (
    find_idle_vertex_endpoints,
)
from cleancloud.providers.gcp.rules.vertex_training_job_long_running import (
    find_long_running_vertex_training_jobs,
)
from cleancloud.providers.gcp.rules.workbench_idle import find_idle_workbench_instances
from cleancloud.providers.gcp.session import create_gcp_session

_GCP_AI_RULE_IDS = {
    "gcp.vertex.endpoint.idle",
    "gcp.vertex.workbench.idle",
    "gcp.vertex.training_job.long_running",
}


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_ai_rules_run_without_error():
    session = create_gcp_session()
    projects = session.list_projects()
    assert projects, "No accessible GCP projects found — check ADC credentials"

    project_id = projects[0]["id"]
    credentials = session.credentials

    rules = [
        find_idle_vertex_endpoints,
        find_idle_workbench_instances,
        find_long_running_vertex_training_jobs,
    ]

    all_results = []
    for rule in rules:
        try:
            rule_results = rule(project_id=project_id, credentials=credentials)
        except PermissionError as e:
            pytest.fail(f"Missing IAM permissions for {rule.__name__}: {e}")
        assert isinstance(
            rule_results, list
        ), f"{rule.__name__} returned {type(rule_results)} instead of list"
        all_results.extend(rule_results)

    for f in all_results:
        assert isinstance(f, Finding)
        assert f.provider == "gcp"
        assert f.rule_id in _GCP_AI_RULE_IDS
        assert f.resource_id
        assert f.region
        assert f.detected_at and isinstance(f.detected_at, datetime)


@pytest.mark.e2e
@pytest.mark.gcp
def test_vertex_training_job_long_running_returns_list_of_findings():
    """Smoke test: rule runs without error and returns typed findings."""
    session = create_gcp_session()
    projects = session.list_projects()
    assert projects, "No accessible GCP projects found — check ADC credentials"

    project_id = projects[0]["id"]
    credentials = session.credentials

    try:
        findings = find_long_running_vertex_training_jobs(
            project_id=project_id, credentials=credentials
        )
    except PermissionError as e:
        pytest.fail(f"Missing IAM permissions: {e}")

    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id == "gcp.vertex.training_job.long_running"
        assert f.resource_type == "gcp.vertex.training_job"
        assert f.provider == "gcp"
        assert f.resource_id
        assert f.region
        assert f.detected_at and isinstance(f.detected_at, datetime)
        assert f.estimated_monthly_cost_usd is None
        assert f.confidence.value in ("high", "medium")
        assert f.risk.value in ("critical", "high", "medium")
        assert "job_name" in f.details
        assert "job_type" in f.details
        assert f.details["job_type"] in ("customJob", "trainingPipeline")
        assert "duration_hours" in f.details
        assert "accrued_cost_usd" in f.details
        assert "burn_rate_per_hour" in f.details
        assert "is_gpu" in f.details
