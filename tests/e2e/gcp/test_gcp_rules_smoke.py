"""
E2E smoke tests for GCP rules.

These tests require real GCP credentials (Application Default Credentials) and
a project with the Compute Engine and Cloud SQL APIs enabled.

Run with:
    pytest -m "e2e and gcp" tests/e2e/gcp/

Set CLEANCLOUD_GCP_TEST_PROJECT to specify a project. If unset, the default
project from gcloud / ADC is used.
"""

import os
from datetime import datetime

import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.gcp.rules.disk_unattached import find_unattached_disks
from cleancloud.providers.gcp.rules.ip_unused import find_unused_static_ips
from cleancloud.providers.gcp.rules.snapshot_old import find_old_snapshots
from cleancloud.providers.gcp.rules.sql_instance_idle import find_idle_sql_instances
from cleancloud.providers.gcp.rules.vm_stopped import find_stopped_vms
from cleancloud.providers.gcp.session import create_gcp_session


def _get_test_project_and_credentials():
    """Return (project_id, credentials) for smoke tests using ADC."""
    session = create_gcp_session(project_id=os.environ.get("CLEANCLOUD_GCP_TEST_PROJECT"))
    projects = session.list_projects()
    assert projects, "No accessible GCP projects found — check ADC credentials"
    return projects[0]["id"], session.credentials


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_rules_run_without_error():
    """
    All 5 GCP rules must execute without raising an unhandled exception.

    PermissionError is acceptable (rule requires a permission not granted to
    the test account) and is caught. Any other exception fails the test.
    """
    project_id, credentials = _get_test_project_and_credentials()

    rules = [
        ("find_unattached_disks", find_unattached_disks),
        ("find_stopped_vms", find_stopped_vms),
        ("find_unused_static_ips", find_unused_static_ips),
        ("find_old_snapshots", find_old_snapshots),
        ("find_idle_sql_instances", find_idle_sql_instances),
    ]

    for rule_name, rule_fn in rules:
        try:
            results = rule_fn(project_id=project_id, credentials=credentials)
        except PermissionError:
            # Account doesn't have the required IAM permission — acceptable in CI
            pytest.skip(f"{rule_name} skipped: insufficient permissions")
            continue

        assert isinstance(results, list), f"{rule_name} returned {type(results)} instead of list"

        for f in results:
            assert isinstance(f, Finding), f"{rule_name}: unexpected type {type(f)}"
            assert f.provider == "gcp", f"{rule_name}: wrong provider {f.provider!r}"
            assert f.rule_id.startswith("gcp."), f"{rule_name}: bad rule_id {f.rule_id!r}"
            assert f.resource_id, f"{rule_name}: empty resource_id"
            assert f.region, f"{rule_name}: empty region"
            assert f.detected_at and isinstance(
                f.detected_at, datetime
            ), f"{rule_name}: missing or invalid detected_at"
            assert f.confidence is not None, f"{rule_name}: missing confidence"


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_disk_rule_smoke():
    """Disk unattached rule returns a list without error."""
    project_id, credentials = _get_test_project_and_credentials()
    try:
        results = find_unattached_disks(project_id=project_id, credentials=credentials)
        assert isinstance(results, list)
    except PermissionError:
        pytest.skip("compute.disks.list permission not granted")


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_vm_stopped_rule_smoke():
    """Stopped VM rule returns a list without error."""
    project_id, credentials = _get_test_project_and_credentials()
    try:
        results = find_stopped_vms(project_id=project_id, credentials=credentials)
        assert isinstance(results, list)
    except PermissionError:
        pytest.skip("compute.instances.list permission not granted")


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_ip_unused_rule_smoke():
    """Unused IP rule returns a list without error."""
    project_id, credentials = _get_test_project_and_credentials()
    try:
        results = find_unused_static_ips(project_id=project_id, credentials=credentials)
        assert isinstance(results, list)
    except PermissionError:
        pytest.skip("compute.addresses.list permission not granted")


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_snapshot_old_rule_smoke():
    """Old snapshot rule returns a list without error."""
    project_id, credentials = _get_test_project_and_credentials()
    try:
        results = find_old_snapshots(project_id=project_id, credentials=credentials)
        assert isinstance(results, list)
    except PermissionError:
        pytest.skip("compute.snapshots.list permission not granted")


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_sql_idle_rule_smoke():
    """Cloud SQL idle rule returns a list without error."""
    project_id, credentials = _get_test_project_and_credentials()
    try:
        results = find_idle_sql_instances(project_id=project_id, credentials=credentials)
        assert isinstance(results, list)
    except PermissionError:
        pytest.skip("cloudsql.instances.list permission not granted")
