"""
E2E smoke tests for GCP AI/ML rules (--category ai).

These tests require real GCP credentials (Application Default Credentials) and
a project with the Vertex AI API enabled.

Run with:
    pytest -m "e2e and gcp" tests/e2e/gcp/test_gcp_ai_rules_smoke.py

Set CLEANCLOUD_GCP_TEST_PROJECT to specify a project. If unset, the default
project from gcloud / ADC is used.
"""

import os
from datetime import datetime

import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.gcp.rules.vertex_endpoint_idle import (
    find_idle_vertex_endpoints,
)
from cleancloud.providers.gcp.session import create_gcp_session


def _get_test_project_and_credentials():
    """Return (project_id, credentials) for smoke tests using ADC."""
    session = create_gcp_session(project_id=os.environ.get("CLEANCLOUD_GCP_TEST_PROJECT"))
    projects = session.list_projects()
    assert projects, "No accessible GCP projects found — check ADC credentials"
    return projects[0]["id"], session.credentials


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_ai_rules_run_without_error():
    """
    All GCP AI rules must execute without raising an unhandled exception.

    PermissionError is acceptable (rule requires a permission not granted to
    the test account) and causes the test to be skipped.
    """
    project_id, credentials = _get_test_project_and_credentials()

    rules = [
        find_idle_vertex_endpoints,
    ]

    all_results = []
    skipped = []
    for rule in rules:
        try:
            rule_results = rule(project_id=project_id, credentials=credentials)
        except PermissionError:
            skipped.append(rule.__name__)
            continue

        assert isinstance(
            rule_results, list
        ), f"{rule.__name__} returned {type(rule_results)} instead of list"
        all_results.extend(rule_results)

    if skipped:
        pytest.skip(f"Rules skipped (missing permissions): {', '.join(skipped)}")

    for f in all_results:
        assert isinstance(f, Finding), f"unexpected type {type(f)}"
        assert f.provider == "gcp", f"wrong provider {f.provider!r}"
        assert f.rule_id == "gcp.vertex.endpoint.idle", f"bad rule_id {f.rule_id!r}"
        assert f.resource_id, "empty resource_id"
        assert f.region, "empty region"
        assert f.detected_at and isinstance(
            f.detected_at, datetime
        ), "missing or invalid detected_at"
        assert f.confidence is not None, "missing confidence"


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_vertex_endpoint_idle_smoke():
    """Vertex AI endpoint idle rule returns a list without error."""
    project_id, credentials = _get_test_project_and_credentials()
    try:
        results = find_idle_vertex_endpoints(project_id=project_id, credentials=credentials)
        assert isinstance(results, list)
    except PermissionError:
        pytest.skip("aiplatform.endpoints.list permission not granted")


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_vertex_endpoint_idle_finding_fields():
    """Any findings from the Vertex AI rule have all required fields populated."""
    project_id, credentials = _get_test_project_and_credentials()
    try:
        results = find_idle_vertex_endpoints(project_id=project_id, credentials=credentials)
    except PermissionError:
        pytest.skip("aiplatform.endpoints.list permission not granted")

    for f in results:
        assert f.provider == "gcp"
        assert f.rule_id == "gcp.vertex.endpoint.idle"
        assert f.resource_type == "gcp.vertex.endpoint"
        assert f.resource_id.startswith("projects/")
        assert f.region
        assert f.title
        assert f.estimated_monthly_cost_usd >= 0
        assert f.risk is not None
        assert f.confidence is not None
        assert isinstance(f.detected_at, datetime)
