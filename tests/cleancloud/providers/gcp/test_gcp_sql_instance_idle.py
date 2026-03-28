"""Unit tests for gcp.sql.instance.idle rule."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.providers.gcp.rules.sql_instance_idle import find_idle_sql_instances


def _make_instance(
    name,
    state="RUNNABLE",
    instance_type="CLOUD_SQL_INSTANCE",
    region="us-central1",
    database_version="POSTGRES_14",
    tier="db-n1-standard-2",
    labels=None,
    create_time=None,
    availability_type="ZONAL",
    data_disk_size_gb=None,
    data_disk_type="PD_SSD",
    backup_retained_count=None,
):
    settings = {
        "tier": tier,
        "userLabels": labels or {},
        "availabilityType": availability_type,
        "dataDiskType": data_disk_type,
    }
    if data_disk_size_gb is not None:
        settings["dataDiskSizeGb"] = data_disk_size_gb
    if backup_retained_count is not None:
        settings["backupConfiguration"] = {
            "backupRetentionSettings": {"retainedBackups": backup_retained_count}
        }
    instance = {
        "name": name,
        "state": state,
        "instanceType": instance_type,
        "region": region,
        "databaseVersion": database_version,
        "settings": settings,
    }
    if create_time is not None:
        instance["createTime"] = create_time
    return instance


def _patch_sql_and_monitoring(monkeypatch, instances, has_connections=False):
    """Patch both _list_sql_instances and _has_connections helpers."""
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle._list_sql_instances",
        lambda project_id, credentials: instances,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle._has_connections",
        lambda client, project_id, instance_name: has_connections,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle.monitoring_v3.MetricServiceClient",
        lambda credentials: MagicMock(),
    )


def test_idle_instance_flagged(monkeypatch):
    """A RUNNABLE instance with zero connections over 14 days is flagged."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("idle-db")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.sql.instance.idle"
    assert f.provider == "gcp"
    assert "idle-db" in f.resource_id
    assert f.region == "us-central1"
    assert f.confidence == ConfidenceLevel.HIGH


def test_active_instance_not_flagged(monkeypatch):
    """A RUNNABLE instance with active connections is not flagged."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("active-db")],
        has_connections=True,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_non_runnable_instance_skipped(monkeypatch):
    """Instances not in RUNNABLE state are skipped."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[
            _make_instance("suspended-db", state="SUSPENDED"),
            _make_instance("maintenance-db", state="MAINTENANCE"),
        ],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_read_replica_skipped(monkeypatch):
    """Read replicas are excluded regardless of connection state."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("replica-db", instance_type="READ_REPLICA_INSTANCE")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_cost_from_known_tier(monkeypatch):
    """Monthly cost is populated for a known tier."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("expensive-db", tier="db-n1-standard-2")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == 93.10


def test_cost_none_for_unknown_tier(monkeypatch):
    """Unknown tiers result in None cost estimate."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("custom-db", tier="db-custom-16-65536")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd is None


def test_region_filter(monkeypatch):
    """Only instances in the matching region are flagged."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[
            _make_instance("central-db", region="us-central1"),
            _make_instance("east-db", region="us-east1"),
        ],
        has_connections=False,
    )
    findings = find_idle_sql_instances(
        project_id="proj-1", credentials=MagicMock(), region_filter="us-east1"
    )

    assert len(findings) == 1
    assert findings[0].details["region"] == "us-east1"


def test_empty_instance_list_returns_empty(monkeypatch):
    """No Cloud SQL instances → no findings."""
    _patch_sql_and_monitoring(monkeypatch, instances=[], has_connections=False)
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_permission_error_propagates(monkeypatch):
    """PermissionError from _list_sql_instances propagates to caller."""
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle._list_sql_instances",
        lambda project_id, credentials: (_ for _ in ()).throw(
            PermissionError("cloudsql.instances.list permission required")
        ),
    )
    with pytest.raises(PermissionError, match="cloudsql.instances.list"):
        find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())


def test_monitoring_client_error_returns_empty(monkeypatch):
    """If the monitoring client cannot be created, return empty (don't false-positive)."""
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle._list_sql_instances",
        lambda project_id, credentials: [_make_instance("idle-db")],
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle.monitoring_v3.MetricServiceClient",
        MagicMock(side_effect=Exception("monitoring not available")),
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_labels_in_details(monkeypatch):
    """userLabels from instance settings appear in finding details."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("labeled-db", labels={"env": "staging", "owner": "team-a"})],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["labels"] == {"env": "staging", "owner": "team-a"}


def test_details_include_tier_and_version(monkeypatch):
    """Finding details include tier and database_version."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("typed-db", tier="db-f1-micro", database_version="MYSQL_8_0")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["tier"] == "db-f1-micro"
    assert findings[0].details["database_version"] == "MYSQL_8_0"


# ---------------------------------------------------------------------------
# Storage, HA, backup retention, custom tier parsing
# ---------------------------------------------------------------------------


def test_ha_enabled_in_details_and_signal(monkeypatch):
    """HA-enabled instance should have ha_enabled=True and an HA signal."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("ha-db", availability_type="REGIONAL")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["ha_enabled"] is True
    assert any("HA" in s for s in findings[0].evidence.signals_used)


def test_ha_disabled_no_ha_signal(monkeypatch):
    """Non-HA instance should have ha_enabled=False and no HA signal."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("zonal-db", availability_type="ZONAL")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["ha_enabled"] is False
    assert not any("HA enabled" in s for s in findings[0].evidence.signals_used)


def test_storage_size_in_details_and_signal(monkeypatch):
    """data_disk_size_gb should appear in details and signals when present."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("big-db", data_disk_size_gb=500)],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["data_disk_size_gb"] == 500
    assert any("500" in s for s in findings[0].evidence.signals_used)


def test_backup_retention_in_details(monkeypatch):
    """backup_retained_count should appear in details when configured."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("backup-db", backup_retained_count=14)],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["backup_retained_count"] == 14


def test_custom_tier_cpu_memory_parsed(monkeypatch):
    """db-custom-{cpu}-{memory_mb} tier should be parsed into cpu_count and memory_gb."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("custom-db", tier="db-custom-2-7680")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["cpu_count"] == 2
    assert findings[0].details["memory_gb"] == 7.5  # 7680 MB / 1024


def test_non_custom_tier_no_cpu_memory(monkeypatch):
    """Standard tier names should not produce cpu_count/memory_gb in details."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("std-db", tier="db-n1-standard-2")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert "cpu_count" not in findings[0].details
    assert "memory_gb" not in findings[0].details


# ---------------------------------------------------------------------------
# Cost-based confidence (Point 2)
# ---------------------------------------------------------------------------


def test_high_cost_tier_has_high_confidence(monkeypatch):
    """Tiers costing > $50/month should produce HIGH confidence findings."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("expensive-db", tier="db-n1-standard-2")],  # $93.10
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].confidence == ConfidenceLevel.HIGH


def test_low_cost_tier_has_medium_confidence(monkeypatch):
    """Cheap tiers (likely dev DBs) should produce MEDIUM confidence findings."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("dev-db", tier="db-f1-micro")],  # $7.67 — below $50
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].confidence == ConfidenceLevel.MEDIUM


def test_unknown_tier_has_medium_confidence(monkeypatch):
    """Unknown tier (no cost estimate) should produce MEDIUM confidence."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("unknown-db", tier="db-custom-16-65536")],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].confidence == ConfidenceLevel.MEDIUM


# ---------------------------------------------------------------------------
# New instance skip (Point 3)
# ---------------------------------------------------------------------------


def test_new_instance_within_24h_skipped(monkeypatch):
    """An instance created less than 24 hours ago should not be flagged."""
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("brand-new-db", create_time=recent)],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings == []


def test_older_instance_not_skipped_by_create_time(monkeypatch):
    """An instance created more than 24 hours ago should still be evaluated."""
    old = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("old-db", create_time=old)],
        has_connections=False,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# _list_sql_instances unit tests
# ---------------------------------------------------------------------------


def test_list_sql_instances_403_raises(monkeypatch):
    """HTTP 403 from Cloud SQL API raises PermissionError."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _list_sql_instances

    mock_session = MagicMock()
    mock_session.get.return_value = MagicMock(status_code=403)
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle.AuthorizedSession",
        lambda credentials: mock_session,
    )
    with pytest.raises(PermissionError, match="cloudsql.instances.list"):
        _list_sql_instances("proj-1", MagicMock())


def test_list_sql_instances_404_returns_empty(monkeypatch):
    """HTTP 404 from Cloud SQL API returns empty list (API not enabled)."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _list_sql_instances

    mock_session = MagicMock()
    mock_session.get.return_value = MagicMock(status_code=404)
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle.AuthorizedSession",
        lambda credentials: mock_session,
    )
    result = _list_sql_instances("proj-1", MagicMock())
    assert result == []


def test_list_sql_instances_returns_items(monkeypatch):
    """Successful Cloud SQL API response returns the 'items' list."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _list_sql_instances

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"items": [{"name": "db-1"}, {"name": "db-2"}]}
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle.AuthorizedSession",
        lambda credentials: mock_session,
    )
    result = _list_sql_instances("proj-1", MagicMock())
    assert len(result) == 2
    assert result[0]["name"] == "db-1"


# ---------------------------------------------------------------------------
# _has_connections unit tests
# ---------------------------------------------------------------------------


def test_has_connections_returns_true_on_exception(monkeypatch):
    """If monitoring raises any exception, _has_connections returns True (conservative)."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _has_connections

    bad_client = MagicMock()
    bad_client.list_time_series.side_effect = Exception("monitoring down")
    result = _has_connections(bad_client, "proj-1", "db-1")
    assert result is True
