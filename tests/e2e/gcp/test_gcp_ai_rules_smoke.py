from datetime import datetime

import pytest
from google.auth.transport.requests import AuthorizedSession

from cleancloud.core.finding import Finding
from cleancloud.providers.gcp.rules.ai.featurestore_idle import find_idle_featurestores
from cleancloud.providers.gcp.rules.ai.tpu_idle import find_idle_tpu_nodes
from cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle import (
    find_idle_vertex_endpoints,
)
from cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running import (
    find_long_running_vertex_training_jobs,
)
from cleancloud.providers.gcp.rules.ai.workbench_idle import find_idle_workbench_instances
from cleancloud.providers.gcp.session import create_gcp_session

_GCP_AI_RULE_IDS = {
    "gcp.vertex.endpoint.idle",
    "gcp.vertex.workbench.idle",
    "gcp.vertex.training_job.long_running",
    "gcp.tpu.idle",
    "gcp.vertex.featurestore.idle",
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
        find_idle_tpu_nodes,
        find_idle_featurestores,
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
        assert "is_accelerator" in f.details


@pytest.mark.e2e
@pytest.mark.gcp
def test_tpu_idle_returns_list_of_findings():
    """Smoke test: gcp.tpu.idle runs without error and returns typed findings."""
    session = create_gcp_session()
    projects = session.list_projects()
    assert projects, "No accessible GCP projects found — check ADC credentials"

    project_id = projects[0]["id"]
    credentials = session.credentials

    # Pre-flight: verify TPU API is enabled and tpu.nodes.list permission is present.
    # The rule silently returns [] for both cases — the e2e test must be explicit.
    _check_session = AuthorizedSession(credentials)
    _resp = _check_session.get(
        f"https://tpu.googleapis.com/v2/projects/{project_id}/locations/-/nodes?pageSize=1"
    )
    if _resp.status_code == 403:
        _details = _resp.json().get("error", {}).get("details", [{}])
        _reason = _details[0].get("reason", "") if _details else ""
        if _reason == "SERVICE_DISABLED":
            pytest.fail(
                f"Cloud TPU API is disabled in project '{project_id}'. "
                f"Enable it with: gcloud services enable tpu.googleapis.com --project={project_id}"
            )
        pytest.fail(
            f"Missing tpu.nodes.list permission in project '{project_id}'. "
            "Grant roles/tpu.viewer to the scanning identity."
        )

    try:
        findings = find_idle_tpu_nodes(project_id=project_id, credentials=credentials)
    except PermissionError as e:
        pytest.fail(f"Missing IAM permissions: {e}")

    # gcp.tpu.idle currently emits no findings (join barrier, spec 8.3): the loop
    # below is vacuously empty today but must stay correct for when emission is unblocked.
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id == "gcp.tpu.idle"
        assert f.resource_type == "gcp.tpu.node"
        assert f.provider == "gcp"
        assert f.resource_id
        assert f.region
        assert f.detected_at and isinstance(f.detected_at, datetime)
        assert f.estimated_monthly_cost_usd is None  # pricing varies; no flat estimate
        assert f.confidence.value in ("high", "medium", "low")
        assert f.risk.value in ("critical", "high", "medium")
        assert "node_id" in f.details
        assert "zone" in f.details
        assert "tpu_type" in f.details
        assert "idle_days_threshold" in f.details
        assert "duty_cycle_threshold_pct" in f.details
        assert "telemetry_join_state" in f.details
        assert "telemetry_coverage_state" in f.details
        assert "telemetry_state" in f.details


@pytest.mark.e2e
@pytest.mark.gcp
def test_featurestore_idle_returns_list_of_findings():
    """Smoke test: gcp.vertex.featurestore.idle runs without error and returns typed findings."""
    session = create_gcp_session()
    projects = session.list_projects()
    assert projects, "No accessible GCP projects found — check ADC credentials"

    project_id = projects[0]["id"]
    credentials = session.credentials

    try:
        findings = find_idle_featurestores(project_id=project_id, credentials=credentials)
    except PermissionError as e:
        pytest.fail(f"Missing IAM permissions: {e}")

    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id == "gcp.vertex.featurestore.idle"
        assert f.resource_type in ("gcp.vertex.featurestore", "gcp.vertex.feature_online_store")
        assert f.provider == "gcp"
        assert f.resource_id
        assert f.region
        assert f.detected_at and isinstance(f.detected_at, datetime)
        assert f.estimated_monthly_cost_usd is not None
        assert f.estimated_monthly_cost_usd > 0
        assert f.confidence.value in ("high", "medium")
        assert f.risk.value in ("high", "medium")
        assert "store_id" in f.details
        assert "store_type" in f.details
        assert "idle_days_threshold" in f.details
        assert "pricing_scope" in f.details
