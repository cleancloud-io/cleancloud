from datetime import datetime

import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.gcp.rules.disk_unattached import find_unattached_disks
from cleancloud.providers.gcp.rules.ip_unused import find_unused_static_ips
from cleancloud.providers.gcp.rules.snapshot_old import find_old_snapshots
from cleancloud.providers.gcp.rules.sql_instance_idle import find_idle_sql_instances
from cleancloud.providers.gcp.rules.vm_stopped import find_stopped_vms
from cleancloud.providers.gcp.session import create_gcp_session


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_rules_run_without_error():
    session = create_gcp_session()
    projects = session.list_projects()
    assert projects, "No accessible GCP projects found — check ADC credentials"

    project_id = projects[0]["id"]
    credentials = session.credentials

    rules = [
        find_unattached_disks,
        find_stopped_vms,
        find_unused_static_ips,
        find_old_snapshots,
        find_idle_sql_instances,
    ]

    all_results = []
    for rule in rules:
        rule_results = rule(project_id=project_id, credentials=credentials)
        assert isinstance(
            rule_results, list
        ), f"{rule.__name__} returned {type(rule_results)} instead of list"
        all_results.extend(rule_results)

    for f in all_results:
        assert isinstance(f, Finding)
        assert f.provider == "gcp"
        assert f.rule_id.startswith("gcp.")
        assert f.resource_id
        assert f.region
        assert f.detected_at and isinstance(f.detected_at, datetime)
