"""Unit tests for gcp.sql.instance.idle rule."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.gcp.rules.sql_instance_idle import find_idle_sql_instances


# Default create_time: 30 days ago — always old enough for the full 14-day window
def _old_create_time() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_instance(
    name,
    state="RUNNABLE",
    instance_type="CLOUD_SQL_INSTANCE",
    region="us-central1",
    database_version="POSTGRES_14",
    tier="db-n1-standard-2",
    labels=None,
    create_time=None,
    master_instance_name=None,
    availability_type="ZONAL",
    data_disk_size_gb=None,
    data_disk_type="PD_SSD",
    backup_retained_count=None,
):
    """Build a minimal Cloud SQL instance dict as returned by the Admin API."""
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
    instance: dict = {
        "name": name,
        "state": state,
        "instanceType": instance_type,
        "region": region,
        "databaseVersion": database_version,
        "settings": settings,
        # Always provide a createTime that is old enough unless the test overrides it
        "createTime": create_time if create_time is not None else _old_create_time(),
    }
    if master_instance_name:
        instance["masterInstanceName"] = master_instance_name
    return instance


def _patch_sql_and_monitoring(
    monkeypatch,
    instances,
    active_connections_max=0.0,
):
    """
    Patch _list_sql_instances and _query_active_connections.

    active_connections_max:
        0.0   → confirmed idle
        >0.0  → active (instance will be skipped)
        None  → unresolved coverage (instance will be skipped)
    """
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle._list_sql_instances",
        lambda project_id, credentials: instances,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle._query_active_connections",
        lambda client, project_id, instance_name, instance_region, window_start, window_end: active_connections_max,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle.monitoring_v3.MetricServiceClient",
        lambda credentials: MagicMock(),
    )


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


def test_idle_instance_flagged(monkeypatch):
    """A RUNNABLE primary instance with zero connections over 14 days is flagged."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("idle-db")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.sql.instance.idle"
    assert f.provider == "gcp"
    assert "idle-db" in f.resource_id
    assert f.region == "us-central1"
    assert f.confidence == ConfidenceLevel.HIGH
    assert f.risk == RiskLevel.HIGH


def test_active_instance_not_flagged(monkeypatch):
    """A RUNNABLE instance with active connections is not flagged."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("active-db")],
        active_connections_max=3.0,
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
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_read_replica_skipped(monkeypatch):
    """Read replicas are excluded regardless of connection state."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("replica-db", instance_type="READ_REPLICA_INSTANCE")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_on_premises_instance_skipped(monkeypatch):
    """ON_PREMISES_INSTANCE type is skipped."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("onprem-db", instance_type="ON_PREMISES_INSTANCE")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Replica exclusion: masterInstanceName (spec 8.6 / 9.4)
# ---------------------------------------------------------------------------


def test_master_instance_name_skips(monkeypatch):
    """Instance with masterInstanceName set is excluded even if instanceType is primary."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[
            _make_instance(
                "pseudo-primary",
                instance_type="CLOUD_SQL_INSTANCE",
                master_instance_name="real-primary",
            )
        ],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Age / full-window coverage (spec 8.7, 8.8, 9.5)
# ---------------------------------------------------------------------------


def test_missing_createtime_skips(monkeypatch):
    """Instance with no createTime field is skipped."""
    instance = _make_instance("no-time-db")
    del instance["createTime"]
    _patch_sql_and_monitoring(monkeypatch, instances=[instance], active_connections_max=0.0)
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_empty_createtime_skips(monkeypatch):
    """Instance with empty createTime string is skipped."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("empty-time-db", create_time="")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_unparsable_createtime_skips(monkeypatch):
    """Instance with unparsable createTime is skipped."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("bad-time-db", create_time="not-a-date")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_instance_too_young_for_full_window_skips(monkeypatch):
    """Instance created within the idle window (e.g. 7 days ago for a 14-day window) is skipped."""
    recent = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("young-db", create_time=recent)],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock(), idle_days=14)
    assert findings == []


def test_instance_just_within_24h_skipped(monkeypatch):
    """Instance created 2 hours ago is skipped (much newer than window_start)."""
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("brand-new-db", create_time=recent)],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_instance_older_than_idle_window_evaluated(monkeypatch):
    """An instance created well before the idle window start is evaluated."""
    old = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("old-db", create_time=old)],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Metric coverage (spec 8.9, 9.6–9.7)
# ---------------------------------------------------------------------------


def test_unresolved_metric_skips(monkeypatch):
    """Instance where _query_active_connections returns None is skipped."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("no-metric-db")],
        active_connections_max=None,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_monitoring_permission_denied_raises(monkeypatch):
    """PermissionError from _query_active_connections propagates to caller."""
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle._list_sql_instances",
        lambda project_id, credentials: [_make_instance("db-1")],
    )

    def _raise_perm(*args, **kwargs):
        raise PermissionError("monitoring.timeSeries.list permission required")

    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle._query_active_connections",
        _raise_perm,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.sql_instance_idle.monitoring_v3.MetricServiceClient",
        lambda credentials: MagicMock(),
    )
    with pytest.raises(PermissionError, match="monitoring.timeSeries.list"):
        find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())


# ---------------------------------------------------------------------------
# Region filter (spec 8.3)
# ---------------------------------------------------------------------------


def test_region_filter(monkeypatch):
    """Only instances in the matching region are flagged."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[
            _make_instance("central-db", region="us-central1"),
            _make_instance("east-db", region="us-east1"),
        ],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(
        project_id="proj-1", credentials=MagicMock(), region_filter="us-east1"
    )

    assert len(findings) == 1
    assert findings[0].details["region"] == "us-east1"


# ---------------------------------------------------------------------------
# Empty results
# ---------------------------------------------------------------------------


def test_empty_instance_list_returns_empty(monkeypatch):
    """No Cloud SQL instances -> no findings."""
    _patch_sql_and_monitoring(monkeypatch, instances=[], active_connections_max=0.0)
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Failure behavior (spec 9.13)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Cost model (spec 9.10): always None
# ---------------------------------------------------------------------------


def test_estimated_monthly_cost_is_none(monkeypatch):
    """estimated_monthly_cost_usd is always None — no flat tier lookup table."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("any-db", tier="db-n1-standard-2")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd is None


def test_custom_tier_cost_also_none(monkeypatch):
    """Custom tier (db-custom-*) also produces None cost estimate."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("custom-db", tier="db-custom-16-65536")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# Confidence / Risk (spec 9.11, 9.12): always HIGH
# ---------------------------------------------------------------------------


def test_confidence_always_high(monkeypatch):
    """Confidence is always HIGH when a finding is emitted."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("any-db", tier="db-f1-micro")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings[0].confidence == ConfidenceLevel.HIGH


def test_risk_always_high(monkeypatch):
    """Risk is always HIGH when a finding is emitted."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("any-db")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings[0].risk == RiskLevel.HIGH


# ---------------------------------------------------------------------------
# Finding details shape (spec 10.3)
# ---------------------------------------------------------------------------


def test_details_include_tier_and_version(monkeypatch):
    """Finding details include tier and database_version."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("typed-db", tier="db-f1-micro", database_version="MYSQL_8_0")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["tier"] == "db-f1-micro"
    assert findings[0].details["database_version"] == "MYSQL_8_0"


def test_instance_type_in_details(monkeypatch):
    """instance_type appears in finding details."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("primary-db")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["instance_type"] == "CLOUD_SQL_INSTANCE"


def test_created_at_in_details_is_iso_format(monkeypatch):
    """created_at in details is an ISO 8601 string with T separator."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("dated-db")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    created_at = findings[0].details["created_at"]
    assert isinstance(created_at, str)
    assert "T" in created_at


def test_idle_days_threshold_in_details(monkeypatch):
    """idle_days_threshold appears in finding details."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("any-db")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock(), idle_days=21)
    assert findings[0].details["idle_days_threshold"] == 21


def test_metric_coverage_in_details(monkeypatch):
    """metric_coverage is 'FULL' in finding details."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("any-db")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["metric_coverage"] == "FULL"


def test_active_connections_max_in_details(monkeypatch):
    """active_connections_max is 0.0 in finding details for an idle instance."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("idle-db")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["active_connections_max"] == 0.0


def test_availability_type_in_details(monkeypatch):
    """availability_type appears in finding details."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("zonal-db", availability_type="ZONAL")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["availability_type"] == "ZONAL"


def test_labels_in_details(monkeypatch):
    """userLabels from instance settings appear in finding details."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("labeled-db", labels={"env": "staging", "owner": "team-a"})],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["labels"] == {"env": "staging", "owner": "team-a"}


# ---------------------------------------------------------------------------
# HA context (spec 9.9)
# ---------------------------------------------------------------------------


def test_ha_enabled_in_details_and_signal(monkeypatch):
    """HA-enabled instance should have ha_enabled=True and an HA signal."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("ha-db", availability_type="REGIONAL")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["ha_enabled"] is True
    assert any("HA" in s for s in findings[0].evidence.signals_used)


def test_ha_disabled_no_ha_signal(monkeypatch):
    """Non-HA instance should have ha_enabled=False and no HA signal."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("zonal-db", availability_type="ZONAL")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["ha_enabled"] is False
    assert not any("HA enabled" in s for s in findings[0].evidence.signals_used)


# ---------------------------------------------------------------------------
# Storage / backup context (spec 9.9)
# ---------------------------------------------------------------------------


def test_storage_size_in_details_and_signal(monkeypatch):
    """data_disk_size_gb should appear in details and signals when present."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("big-db", data_disk_size_gb=500)],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["data_disk_size_gb"] == 500
    assert any("500" in s for s in findings[0].evidence.signals_used)


def test_backup_retention_in_details(monkeypatch):
    """backup_retained_count should appear in details when configured."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("backup-db", backup_retained_count=14)],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["backup_retained_count"] == 14


# ---------------------------------------------------------------------------
# Custom tier CPU/memory parsing
# ---------------------------------------------------------------------------


def test_custom_tier_cpu_memory_parsed(monkeypatch):
    """db-custom-{cpu}-{memory_mb} tier should be parsed into cpu_count and memory_gb."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("custom-db", tier="db-custom-2-7680")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["cpu_count"] == 2
    assert findings[0].details["memory_gb"] == 7.5  # 7680 MB / 1024


def test_non_custom_tier_no_cpu_memory(monkeypatch):
    """Standard tier names should not produce cpu_count/memory_gb in details."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("std-db", tier="db-n1-standard-2")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())

    assert "cpu_count" not in findings[0].details
    assert "memory_gb" not in findings[0].details


# ---------------------------------------------------------------------------
# Evidence content (spec 10.2)
# ---------------------------------------------------------------------------


def test_evidence_discloses_runnable_state(monkeypatch):
    """signals_used discloses RUNNABLE state."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("db-1")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert any("RUNNABLE" in s for s in findings[0].evidence.signals_used)


def test_evidence_discloses_metric_coverage_full(monkeypatch):
    """signals_used discloses full metric coverage."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("db-1")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert any("FULL" in s for s in findings[0].evidence.signals_used)


def test_evidence_discloses_active_connections_max(monkeypatch):
    """signals_used discloses the active_connections_max value."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("db-1")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert any("active_connections_max" in s for s in findings[0].evidence.signals_used)


def test_evidence_signals_not_checked_present(monkeypatch):
    """signals_not_checked is populated with known blind spots."""
    _patch_sql_and_monitoring(
        monkeypatch,
        instances=[_make_instance("db-1")],
        active_connections_max=0.0,
    )
    findings = find_idle_sql_instances(project_id="proj-1", credentials=MagicMock())
    assert len(findings[0].evidence.signals_not_checked) > 0


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
# _query_active_connections unit tests
# ---------------------------------------------------------------------------


def _make_mock_point(val: int, dt: datetime):
    """Create a mock monitoring data point with an integer value and UTC timestamp."""
    p = MagicMock()
    p.value.WhichOneof.return_value = "int64_value"
    p.value.int64_value = val
    p.interval.end_time.seconds = int(dt.timestamp())
    p.interval.end_time.nanos = 0
    return p


def test_query_active_connections_no_series_returns_none():
    """No time series returned → unresolved coverage → None."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([])  # no series

    now = datetime.now(timezone.utc)
    result = _query_active_connections(
        mock_client, "proj-1", "db-1", "us-central1", now - timedelta(days=14), now
    )
    assert result is None


def test_query_active_connections_series_no_points_returns_none():
    """Series present but no points → unusable → None."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    mock_series = MagicMock()
    mock_series.points = []
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    now = datetime.now(timezone.utc)
    result = _query_active_connections(
        mock_client, "proj-1", "db-1", "us-central1", now - timedelta(days=14), now
    )
    assert result is None


def test_query_active_connections_zero_returns_zero():
    """Series with all-zero points spanning the window → max = 0.0 → confirmed idle."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    # Use a short window so two edge points cover it without triggering gap or edge checks
    now = datetime.now(timezone.utc)
    w_start = now - timedelta(minutes=3)
    w_end = now
    mock_series = MagicMock()
    mock_series.points = [
        _make_mock_point(0, w_start + timedelta(seconds=30)),
        _make_mock_point(0, w_end - timedelta(seconds=30)),
    ]
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    result = _query_active_connections(mock_client, "proj-1", "db-1", "us-central1", w_start, w_end)
    assert result == 0.0


def test_query_active_connections_nonzero_returns_max():
    """Series with nonzero points spanning the window → maximum value returned."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    now = datetime.now(timezone.utc)
    w_start = now - timedelta(minutes=4)
    w_end = now
    mock_series = MagicMock()
    mock_series.points = [
        _make_mock_point(0, w_start + timedelta(seconds=30)),
        _make_mock_point(5, w_start + timedelta(minutes=2)),
        _make_mock_point(2, w_end - timedelta(seconds=30)),
    ]
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    result = _query_active_connections(mock_client, "proj-1", "db-1", "us-central1", w_start, w_end)
    assert result == 5.0


def test_query_active_connections_permission_denied_raises():
    """PermissionDenied from monitoring raises PermissionError."""
    from google.api_core.exceptions import PermissionDenied

    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    mock_client = MagicMock()
    mock_client.list_time_series.side_effect = PermissionDenied("denied")

    now = datetime.now(timezone.utc)
    with pytest.raises(PermissionError, match="monitoring.timeSeries.list"):
        _query_active_connections(
            mock_client, "proj-1", "db-1", "us-central1", now - timedelta(days=14), now
        )


def test_query_active_connections_generic_exception_returns_none():
    """Any unexpected exception from monitoring returns None (skip, don't false-positive)."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    mock_client = MagicMock()
    mock_client.list_time_series.side_effect = Exception("unexpected error")

    now = datetime.now(timezone.utc)
    result = _query_active_connections(
        mock_client, "proj-1", "db-1", "us-central1", now - timedelta(days=14), now
    )
    assert result is None


def test_query_active_connections_aggregates_multiple_series():
    """max is aggregated across all matched series (database label variants)."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    now = datetime.now(timezone.utc)
    w_start = now - timedelta(minutes=4)
    w_end = now

    def _make_series(vals_and_times):
        s = MagicMock()
        s.points = [_make_mock_point(v, t) for v, t in vals_and_times]
        return s

    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter(
        [
            _make_series(
                [
                    (0, w_start + timedelta(seconds=30)),
                    (0, w_end - timedelta(seconds=30)),
                ]
            ),  # database=mydb — all zero
            _make_series(
                [
                    (0, w_start + timedelta(seconds=30)),
                    (3, w_end - timedelta(seconds=30)),
                ]
            ),  # database=otherdb — nonzero peak
        ]
    )

    result = _query_active_connections(mock_client, "proj-1", "db-1", "us-central1", w_start, w_end)
    assert result == 3.0


# ---------------------------------------------------------------------------
# Coverage quality tests (spec 9.6.8–9.6.9)
# ---------------------------------------------------------------------------


def test_query_active_connections_partial_window_start_returns_none():
    """Data starts too late (after window_start + tolerance) → partial window → None."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    now = datetime.now(timezone.utc)
    w_start = now - timedelta(days=14)
    w_end = now
    # Single point well past window_start + tolerance
    mock_series = MagicMock()
    mock_series.points = [_make_mock_point(0, w_start + timedelta(days=7))]
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    result = _query_active_connections(mock_client, "proj-1", "db-1", "us-central1", w_start, w_end)
    assert result is None


def test_query_active_connections_partial_window_end_returns_none():
    """Data ends too early (before window_end - tolerance) → partial window → None."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    now = datetime.now(timezone.utc)
    w_start = now - timedelta(days=14)
    w_end = now
    # Points only up to day 7 — end well before window_end - tolerance
    mock_series = MagicMock()
    mock_series.points = [
        _make_mock_point(0, w_start + timedelta(minutes=1)),
        _make_mock_point(0, w_start + timedelta(days=7)),  # stops at day 7
    ]
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    result = _query_active_connections(mock_client, "proj-1", "db-1", "us-central1", w_start, w_end)
    assert result is None


def test_query_active_connections_large_gap_returns_none():
    """Points at start and end but with a large gap in the middle → None."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    now = datetime.now(timezone.utc)
    w_start = now - timedelta(days=14)
    w_end = now
    # Points bound the window, but there is a multi-day gap in the middle
    mock_series = MagicMock()
    mock_series.points = [
        _make_mock_point(0, w_start + timedelta(minutes=1)),
        _make_mock_point(0, w_start + timedelta(days=3)),  # 3-day gap after previous
        _make_mock_point(0, w_end - timedelta(minutes=1)),
    ]
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    result = _query_active_connections(mock_client, "proj-1", "db-1", "us-central1", w_start, w_end)
    assert result is None


def test_query_active_connections_unreadable_timestamps_returns_none():
    """Any point whose timestamp cannot be parsed → coverage unresolved → None immediately."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    mock_point = MagicMock()
    # Value is readable — the failure must be in the timestamp, not the value type
    mock_point.value.WhichOneof.return_value = "int64_value"
    mock_point.value.int64_value = 0
    # MagicMock for seconds causes datetime.fromtimestamp to raise TypeError
    mock_point.interval.end_time.seconds = MagicMock()
    mock_point.interval.end_time.nanos = 0
    mock_series = MagicMock()
    mock_series.points = [mock_point]
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    now = datetime.now(timezone.utc)
    result = _query_active_connections(
        mock_client, "proj-1", "db-1", "us-central1", now - timedelta(days=14), now
    )
    assert result is None


def test_query_active_connections_unrecognized_value_type_returns_none():
    """Point with an unrecognized value type (not int64 or double) → unresolved → None."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    now = datetime.now(timezone.utc)
    w_start = now - timedelta(minutes=3)
    mock_point = MagicMock()
    mock_point.value.WhichOneof.return_value = "distribution_value"  # not int64 or double
    mock_point.interval.end_time.seconds = int(w_start.timestamp()) + 30
    mock_point.interval.end_time.nanos = 0
    mock_series = MagicMock()
    mock_series.points = [mock_point]
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    result = _query_active_connections(mock_client, "proj-1", "db-1", "us-central1", w_start, now)
    assert result is None


def test_query_active_connections_unset_value_type_returns_none():
    """Point with no value field set (WhichOneof returns None) → unresolved → None."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    now = datetime.now(timezone.utc)
    w_start = now - timedelta(minutes=3)
    mock_point = MagicMock()
    mock_point.value.WhichOneof.return_value = None  # no value oneof field set
    mock_point.interval.end_time.seconds = int(w_start.timestamp()) + 30
    mock_point.interval.end_time.nanos = 0
    mock_series = MagicMock()
    mock_series.points = [mock_point]
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    result = _query_active_connections(mock_client, "proj-1", "db-1", "us-central1", w_start, now)
    assert result is None


def test_query_active_connections_small_gaps_tolerated():
    """Gaps within tolerance (< 10 min) are allowed — full coverage is accepted."""
    from cleancloud.providers.gcp.rules.sql_instance_idle import _query_active_connections

    now = datetime.now(timezone.utc)
    w_start = now - timedelta(minutes=30)
    w_end = now
    # Points every 5 minutes — gaps are 5 min, within the 10-min tolerance
    times = [w_start + timedelta(minutes=i) for i in range(0, 31, 5)]
    mock_series = MagicMock()
    mock_series.points = [_make_mock_point(0, t) for t in times]
    mock_client = MagicMock()
    mock_client.list_time_series.return_value = iter([mock_series])

    result = _query_active_connections(mock_client, "proj-1", "db-1", "us-central1", w_start, w_end)
    assert result == 0.0
