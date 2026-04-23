"""
Tests for azure.sql.database.idle — spec-aligned.

Covers: must-emit, must-skip, online-state contract, age contract,
        elastic-pool contract, replica/secondary contract (incl. source_database_id
        NOT a standalone skip), paused-state contract, metrics contract (incl.
        all-None datapoints → zero), finding shape, evidence contract,
        region filter, failure behavior, SDK/ARM camelCase fallbacks,
        _query_metric and helper unit tests.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from cleancloud.providers.azure.rules.sql_database_idle import (
    _is_paused,
    _is_replica_secondary,
    _query_metric,
    find_idle_sql_databases,
)

# ---------------------------------------------------------------------------
# Constants / shared fixtures
# ---------------------------------------------------------------------------

_SUB = "sub-123"
_IDLE_DAYS = 14


# ---------------------------------------------------------------------------
# Monitor mock sentinels
# ---------------------------------------------------------------------------

_ABSENT = object()  # metric absent from response → unknown → skip
_EMPTY_SERIES = object()  # metric present, no data items → unknown → skip
_NONE_DPS = object()  # metric present, data items all None → 0.0 (spec 9.6 rule 2)


# ---------------------------------------------------------------------------
# Object helpers
# ---------------------------------------------------------------------------


def _server_id(name: str = "srv") -> str:
    return f"/subscriptions/{_SUB}/resourceGroups/rg1" f"/providers/Microsoft.Sql/servers/{name}"


def _db_id(name: str = "mydb", server: str = "srv") -> str:
    return (
        f"/subscriptions/{_SUB}/resourceGroups/rg1"
        f"/providers/Microsoft.Sql/servers/{server}/databases/{name}"
    )


def _old_enough(days: int = 30) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def _too_young(days: int = 5) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def _make_server(name: str = "srv", location: str = "eastus") -> SimpleNamespace:
    return SimpleNamespace(id=_server_id(name), name=name, location=location)


def _make_db(
    name: str = "mydb",
    location: str = "eastus",
    status: str = "Online",
    creation_date=None,
    elastic_pool_id=None,
    secondary_type=None,
    source_database_id=None,
    paused_date=None,
    resumed_date=None,
    sku=None,
    tags=None,
    server: str = "srv",
    **extra,
) -> SimpleNamespace:
    cd = creation_date if creation_date is not None else _old_enough()
    ns = SimpleNamespace(
        id=_db_id(name, server),
        name=name,
        location=location,
        status=status,
        creation_date=cd,
        elastic_pool_id=elastic_pool_id,
        secondary_type=secondary_type,
        source_database_id=source_database_id,
        paused_date=paused_date,
        resumed_date=resumed_date,
        sku=sku,
        tags=tags,
        current_service_objective_name=None,
        auto_pause_delay=None,
        properties=None,
    )
    for k, v in extra.items():
        setattr(ns, k, v)
    return ns


# ---------------------------------------------------------------------------
# Monitor client mock
# ---------------------------------------------------------------------------


def _make_monitor_client(overrides: dict = None, raise_on: str = None):
    """
    Build a mock MonitorManagementClient.

    overrides — per-metric value:
      float        regular datapoint value (0.0 = zero, > 0 = active)
      _ABSENT      metric absent from response → unknown → skip
      _EMPTY_SERIES metric present, series has no data items → unknown → skip
      _NONE_DPS    metric present, data items exist but all aggregated values None
                   → usable series, confirmed zero (spec 9.6 rule 2) → 0.0

    Any metric not listed in overrides defaults to 0.0 (confirmed zero).
    raise_on — metric name that causes the list() call to raise.
    """
    defaults = {
        "connection_successful": 0.0,
        "sessions_count": 0.0,
        "cpu_percent": 0.0,
        "physical_data_read_percent": 0.0,
        "log_write_percent": 0.0,
    }
    spec = {**defaults, **(overrides or {})}

    def _mock_list(resource_uri, metricnames, aggregation="Total", **kwargs):
        if raise_on and metricnames == raise_on:
            raise RuntimeError("Monitor unavailable")

        val = spec.get(metricnames, 0.0)
        agg_attr = "total" if aggregation == "Total" else "maximum"

        if val is _ABSENT:
            return SimpleNamespace(value=[])

        if val is _EMPTY_SERIES:
            ts = SimpleNamespace(data=[])
            metric = SimpleNamespace(name=SimpleNamespace(value=metricnames), timeseries=[ts])
            return SimpleNamespace(value=[metric])

        if val is _NONE_DPS:
            dp = SimpleNamespace(**{agg_attr: None, "total": None, "maximum": None})
            ts = SimpleNamespace(data=[dp])
            metric = SimpleNamespace(name=SimpleNamespace(value=metricnames), timeseries=[ts])
            return SimpleNamespace(value=[metric])

        # Regular numeric value
        dp = SimpleNamespace(**{agg_attr: val, "total": val, "maximum": val})
        ts = SimpleNamespace(data=[dp])
        metric = SimpleNamespace(name=SimpleNamespace(value=metricnames), timeseries=[ts])
        return SimpleNamespace(value=[metric])

    mon = MagicMock()
    mon.metrics.list.side_effect = _mock_list
    return mon


# ---------------------------------------------------------------------------
# SQL client mock + run helper
# ---------------------------------------------------------------------------


def _make_sql_client(server=None, dbs=None, db_list_raises: bool = False):
    sql = MagicMock()
    sql.servers.list.return_value = [server or _make_server()]
    if db_list_raises:
        sql.databases.list_by_server.side_effect = Exception("listing failed")
    else:
        sql.databases.list_by_server.return_value = dbs or []
    return sql


def _run(
    dbs,
    server=None,
    region_filter=None,
    idle_days: int = _IDLE_DAYS,
    monitor=None,
    db_list_raises: bool = False,
):
    sql = _make_sql_client(server=server, dbs=dbs, db_list_raises=db_list_raises)
    mon = monitor or _make_monitor_client()
    return find_idle_sql_databases(
        subscription_id=_SUB,
        credential=None,
        region_filter=region_filter,
        client=sql,
        monitor_client=mon,
        idle_days=idle_days,
    )


# ===========================================================================
# TestMustEmit — spec §13.1
# ===========================================================================


class TestMustEmit:
    def test_fully_qualifying_database_emits(self):
        db = _make_db()
        assert len(_run([db])) == 1

    def test_all_five_metrics_zero_emits(self):
        db = _make_db()
        mon = _make_monitor_client()  # all zero by default
        assert len(_run([db], monitor=mon)) == 1

    def test_multiple_qualifying_databases_all_emit(self):
        dbs = [_make_db(name=f"db{i}") for i in range(3)]
        assert len(_run(dbs)) == 3


# ===========================================================================
# TestMustSkip — spec §13.2
# ===========================================================================


class TestMustSkip:
    def test_master_skips(self):
        assert _run([_make_db(name="master")]) == []

    def test_elastic_pool_skips(self):
        db = _make_db(
            elastic_pool_id=(
                "/subscriptions/sub/resourceGroups/rg"
                "/providers/Microsoft.Sql/servers/srv/elasticPools/pool1"
            )
        )
        assert _run([db]) == []

    def test_status_not_online_skips(self):
        assert _run([_make_db(status="Offline")]) == []

    def test_paused_status_skips(self):
        assert _run([_make_db(status="Paused")]) == []

    def test_secondary_type_skips(self):
        assert _run([_make_db(secondary_type="Geo")]) == []

    def test_younger_than_idle_days_skips(self):
        assert _run([_make_db(creation_date=_too_young(5))]) == []

    def test_connections_zero_sessions_count_nonzero_skips(self):
        db = _make_db()
        mon = _make_monitor_client(overrides={"sessions_count": 1.0})
        assert _run([db], monitor=mon) == []

    def test_connections_zero_cpu_nonzero_skips(self):
        db = _make_db()
        mon = _make_monitor_client(overrides={"cpu_percent": 5.0})
        assert _run([db], monitor=mon) == []

    def test_metric_query_fails_skips(self):
        db = _make_db()
        mon = _make_monitor_client(overrides={"connection_successful": _ABSENT})
        assert _run([db], monitor=mon) == []


# ===========================================================================
# TestOnlineStateContract — spec §9.1
# ===========================================================================


class TestOnlineStateContract:
    def test_online_emits(self):
        assert len(_run([_make_db(status="Online")])) == 1

    def test_offline_skips(self):
        assert _run([_make_db(status="Offline")]) == []

    def test_paused_skips(self):
        assert _run([_make_db(status="Paused")]) == []

    def test_creating_skips(self):
        assert _run([_make_db(status="Creating")]) == []

    def test_status_none_skips(self):
        db = _make_db()
        db.status = None
        assert _run([db]) == []

    def test_nested_snake_case_status_online_emits(self):
        db = _make_db()
        db.status = None
        db.properties = SimpleNamespace(status="Online")
        assert len(_run([db])) == 1

    def test_nested_snake_case_status_offline_skips(self):
        db = _make_db()
        db.status = None
        db.properties = SimpleNamespace(status="Offline")
        assert _run([db]) == []


# ===========================================================================
# TestAgeContract — spec §9.2
# ===========================================================================


class TestAgeContract:
    def test_old_enough_emits(self):
        assert len(_run([_make_db(creation_date=_old_enough(30))])) == 1

    def test_too_young_skips(self):
        assert _run([_make_db(creation_date=_too_young(5))]) == []

    def test_exactly_idle_days_old_emits(self):
        # age_days == idle_days: 14 < 14 is False → proceeds
        db = _make_db(creation_date=_old_enough(_IDLE_DAYS))
        assert len(_run([db])) == 1

    def test_creation_date_absent_skips(self):
        db = _make_db()
        db.creation_date = None
        assert _run([db]) == []

    def test_creation_date_as_iso_string_emits(self):
        cd_str = _old_enough(30).strftime("%Y-%m-%dT%H:%M:%SZ")
        db = _make_db()
        db.creation_date = cd_str
        assert len(_run([db])) == 1

    def test_creation_date_as_iso_string_too_young_skips(self):
        cd_str = _too_young(5).strftime("%Y-%m-%dT%H:%M:%SZ")
        db = _make_db()
        db.creation_date = cd_str
        assert _run([db]) == []

    def test_nested_camel_case_creation_date_emits(self):
        db = _make_db()
        db.creation_date = None
        db.properties = SimpleNamespace(creationDate=_old_enough(30))
        assert len(_run([db])) == 1

    def test_nested_snake_case_creation_date_emits(self):
        db = _make_db()
        db.creation_date = None
        db.properties = SimpleNamespace(creation_date=_old_enough(30))
        assert len(_run([db])) == 1


# ===========================================================================
# TestElasticPoolContract — spec §9.3
# ===========================================================================


class TestElasticPoolContract:
    def test_elastic_pool_id_present_skips(self):
        db = _make_db(elastic_pool_id="/subscriptions/sub/pool1")
        assert _run([db]) == []

    def test_elastic_pool_id_none_emits(self):
        assert len(_run([_make_db(elastic_pool_id=None)])) == 1

    def test_elastic_pool_id_empty_string_emits(self):
        assert len(_run([_make_db(elastic_pool_id="")])) == 1

    def test_nested_camel_case_elastic_pool_id_skips(self):
        db = _make_db()
        db.elastic_pool_id = None
        db.properties = SimpleNamespace(elasticPoolId="/subscriptions/sub/pool1")
        assert _run([db]) == []

    def test_nested_snake_case_elastic_pool_id_skips(self):
        db = _make_db()
        db.elastic_pool_id = None
        db.properties = SimpleNamespace(elastic_pool_id="/subscriptions/sub/pool1")
        assert _run([db]) == []


# ===========================================================================
# TestReplicaSecondaryContract — spec §9.4
# ===========================================================================


class TestReplicaSecondaryContract:
    def test_secondary_type_geo_skips(self):
        assert _run([_make_db(secondary_type="Geo")]) == []

    def test_secondary_type_named_skips(self):
        assert _run([_make_db(secondary_type="Named")]) == []

    def test_source_database_id_alone_does_not_skip(self):
        """
        spec 9.4: source_database_id alone is NOT a standalone skip signal.
        It must be paired with secondary/replica-shaped control-plane context.
        A restore copy has source_database_id but is not a replica.
        """
        db = _make_db(source_database_id="/subscriptions/sub/databases/source")
        assert len(_run([db])) == 1

    def test_neither_signal_emits(self):
        assert len(_run([_make_db(secondary_type=None, source_database_id=None)])) == 1

    def test_nested_camel_case_secondary_type_skips(self):
        db = _make_db()
        db.secondary_type = None
        db.properties = SimpleNamespace(secondaryType="Geo")
        assert _run([db]) == []

    def test_nested_snake_case_secondary_type_skips(self):
        db = _make_db()
        db.secondary_type = None
        db.properties = SimpleNamespace(secondary_type="Geo")
        assert _run([db]) == []

    def test_nested_source_database_id_alone_does_not_skip(self):
        """Even via nested path, source_database_id alone must not skip."""
        db = _make_db()
        db.source_database_id = None
        db.properties = SimpleNamespace(sourceDatabaseId="/subscriptions/sub/db/src")
        assert len(_run([db])) == 1


# ===========================================================================
# TestPausedStateContract — spec §9.5
# ===========================================================================


class TestPausedStateContract:
    def test_status_paused_skips(self):
        assert _run([_make_db(status="Paused")]) == []

    def test_paused_date_without_resumed_date_skips(self):
        db = _make_db(paused_date=_old_enough(2))
        assert _run([db]) == []

    def test_paused_date_with_later_resumed_date_does_not_skip(self):
        # resumed after pausing → not currently paused
        db = _make_db(paused_date=_old_enough(5), resumed_date=_old_enough(1))
        assert len(_run([db])) == 1

    def test_paused_date_with_earlier_resumed_date_skips(self):
        # paused_date > resumed_date → currently paused again
        db = _make_db(paused_date=_old_enough(1), resumed_date=_old_enough(5))
        assert _run([db]) == []

    def test_no_paused_date_does_not_skip(self):
        assert len(_run([_make_db(paused_date=None)])) == 1

    def test_nested_camel_case_paused_date_skips(self):
        db = _make_db()
        db.paused_date = None
        db.resumed_date = None
        db.properties = SimpleNamespace(pausedDate=_old_enough(2))
        assert _run([db]) == []

    def test_nested_camel_case_paused_resumed_pair_does_not_skip(self):
        db = _make_db()
        db.paused_date = None
        db.resumed_date = None
        db.properties = SimpleNamespace(pausedDate=_old_enough(5), resumedDate=_old_enough(1))
        assert len(_run([db])) == 1


# ===========================================================================
# TestMetricsContract — spec §9.6
# ===========================================================================


class TestMetricsContract:
    def test_all_five_zero_emits(self):
        assert len(_run([_make_db()])) == 1

    def test_connection_successful_nonzero_skips(self):
        mon = _make_monitor_client(overrides={"connection_successful": 10.0})
        assert _run([_make_db()], monitor=mon) == []

    def test_sessions_count_nonzero_skips(self):
        mon = _make_monitor_client(overrides={"sessions_count": 2.0})
        assert _run([_make_db()], monitor=mon) == []

    def test_cpu_percent_nonzero_skips(self):
        mon = _make_monitor_client(overrides={"cpu_percent": 0.5})
        assert _run([_make_db()], monitor=mon) == []

    def test_physical_data_read_nonzero_skips(self):
        mon = _make_monitor_client(overrides={"physical_data_read_percent": 10.0})
        assert _run([_make_db()], monitor=mon) == []

    def test_log_write_nonzero_skips(self):
        mon = _make_monitor_client(overrides={"log_write_percent": 3.0})
        assert _run([_make_db()], monitor=mon) == []

    def test_metric_absent_from_response_skips(self):
        """Metric absent from response → unknown → skip (spec 9.6 rule 3)."""
        mon = _make_monitor_client(overrides={"connection_successful": _ABSENT})
        assert _run([_make_db()], monitor=mon) == []

    def test_series_with_no_data_items_skips(self):
        """Metric present, series has no data items → unusable → skip (spec 9.6 rule 4)."""
        mon = _make_monitor_client(overrides={"cpu_percent": _EMPTY_SERIES})
        assert _run([_make_db()], monitor=mon) == []

    def test_series_with_all_none_datapoints_is_confirmed_zero_emits(self):
        """
        Metric present, data items exist but all aggregated values are None →
        usable series, all datapoints 0-or-None → confirmed zero (spec 9.6 rule 2) → emit.
        """
        mon = _make_monitor_client(overrides={"sessions_count": _NONE_DPS})
        assert len(_run([_make_db()], monitor=mon)) == 1

    def test_all_none_datapoints_on_all_metrics_emits(self):
        """All five metrics returning None datapoints still counts as zero → emit."""
        mon = _make_monitor_client(
            overrides={
                m: _NONE_DPS
                for m in [
                    "connection_successful",
                    "sessions_count",
                    "cpu_percent",
                    "physical_data_read_percent",
                    "log_write_percent",
                ]
            }
        )
        assert len(_run([_make_db()], monitor=mon)) == 1

    def test_metric_query_exception_skips(self):
        mon = _make_monitor_client(raise_on="log_write_percent")
        assert _run([_make_db()], monitor=mon) == []

    def test_second_metric_fails_skips_db(self):
        mon = _make_monitor_client(raise_on="sessions_count")
        assert _run([_make_db()], monitor=mon) == []


# ===========================================================================
# TestFindingShape — spec §11
# ===========================================================================


class TestFindingShape:
    def _finding(self, **db_kwargs):
        db = _make_db(**db_kwargs)
        findings = _run([db])
        assert len(findings) == 1
        return findings[0]

    def test_provider_is_azure(self):
        assert self._finding().provider == "azure"

    def test_rule_id(self):
        assert self._finding().rule_id == "azure.sql.database.idle"

    def test_resource_type(self):
        assert self._finding().resource_type == "azure.sql.database"

    def test_resource_id_is_database_arm_id(self):
        db = _make_db()
        findings = _run([db])
        assert findings[0].resource_id == db.id

    def test_region_is_normalized_lowercase(self):
        db = _make_db(location="East US")
        findings = _run([db])
        assert findings[0].region == "east us"

    def test_estimated_monthly_cost_is_none(self):
        assert self._finding().estimated_monthly_cost_usd is None

    def test_risk_is_high(self):
        from cleancloud.core.risk import RiskLevel

        assert self._finding().risk == RiskLevel.HIGH

    def test_confidence_is_high(self):
        from cleancloud.core.confidence import ConfidenceLevel

        assert self._finding().confidence == ConfidenceLevel.HIGH

    def test_details_has_all_required_keys(self):
        required = {
            "database_name",
            "server_name",
            "status",
            "current_service_objective_name",
            "sku_tier",
            "elastic_pool_id",
            "auto_pause_delay",
            "paused_date",
            "creation_date",
            "idle_days",
            "connection_successful",
            "sessions_count",
            "cpu_percent",
            "physical_data_read_percent",
            "log_write_percent",
            "tags",
        }
        assert required <= set(self._finding().details.keys())

    def test_details_database_name(self):
        assert self._finding(name="proddb").details["database_name"] == "proddb"

    def test_details_all_metric_values_zero(self):
        d = self._finding().details
        assert d["connection_successful"] == 0.0
        assert d["sessions_count"] == 0.0
        assert d["cpu_percent"] == 0.0
        assert d["physical_data_read_percent"] == 0.0
        assert d["log_write_percent"] == 0.0

    def test_details_idle_days_reflects_param(self):
        db = _make_db()
        findings = _run([db], idle_days=7)
        assert findings[0].details["idle_days"] == 7

    def test_tags_defaults_to_empty_dict_when_absent(self):
        assert self._finding(tags=None).details["tags"] == {}

    def test_tags_preserved_when_set(self):
        assert self._finding(tags={"env": "prod"}).details["tags"] == {"env": "prod"}

    def test_evidence_signals_used_count_is_ten(self):
        assert len(self._finding().evidence.signals_used) == 10

    def test_evidence_signals_not_checked_count_is_four(self):
        assert len(self._finding().evidence.signals_not_checked) == 4

    def test_evidence_time_window_reflects_idle_days(self):
        db = _make_db()
        findings = _run([db], idle_days=7)
        assert findings[0].evidence.time_window == "7 days"

    def test_evidence_signals_include_all_five_metrics(self):
        signals = self._finding().evidence.signals_used
        assert any("connection_successful" in s for s in signals)
        assert any("sessions_count" in s for s in signals)
        assert any("cpu_percent" in s for s in signals)
        assert any("physical_data_read_percent" in s for s in signals)
        assert any("log_write_percent" in s for s in signals)


# ===========================================================================
# TestRegionFilter — spec §8.3
# ===========================================================================


class TestRegionFilter:
    def test_matching_region_emits(self):
        db = _make_db(location="eastus")
        server = _make_server(location="eastus")
        assert len(_run([db], server=server, region_filter="eastus")) == 1

    def test_non_matching_region_skips(self):
        db = _make_db(location="westus")
        server = _make_server(location="westus")
        assert _run([db], server=server, region_filter="eastus") == []

    def test_no_filter_emits_all(self):
        dbs = [_make_db(name=f"db{i}") for i in range(3)]
        assert len(_run(dbs)) == 3

    def test_region_filter_case_insensitive(self):
        db = _make_db(location="eastus")
        server = _make_server(location="eastus")
        assert len(_run([db], server=server, region_filter="EastUS")) == 1

    def test_server_level_prefilter_skips_all_dbs_on_mismatched_server(self):
        db = _make_db(location="westus")
        server = _make_server(location="westus")
        assert _run([db], server=server, region_filter="northeurope") == []


# ===========================================================================
# TestFailureBehavior — spec §12
# ===========================================================================


class TestFailureBehavior:
    def test_db_listing_fails_skips_server(self):
        """Per spec 12: per-server listing failure → skip server, not propagate."""
        assert _run([_make_db()], db_list_raises=True) == []

    def test_metric_exception_skips_db(self):
        """Per spec 12: metric query failure → skip database."""
        mon = _make_monitor_client(raise_on="cpu_percent")
        assert _run([_make_db()], monitor=mon) == []

    def test_db_with_no_id_skips(self):
        db = _make_db()
        db.id = None
        assert _run([db]) == []

    def test_db_with_empty_id_skips(self):
        db = _make_db()
        db.id = ""
        assert _run([db]) == []

    def test_db_with_no_name_skips(self):
        db = _make_db()
        db.name = None
        assert _run([db]) == []

    def test_db_with_empty_name_skips(self):
        db = _make_db()
        db.name = ""
        assert _run([db]) == []


# ===========================================================================
# TestSDKFallbacks — SDK-first / nested snake_case / ARM camelCase
# ===========================================================================


class TestSDKFallbacks:
    def test_status_via_nested_snake_case_emits(self):
        db = _make_db()
        db.status = None
        db.properties = SimpleNamespace(status="Online")
        assert len(_run([db])) == 1

    def test_creation_date_via_nested_camel_case_emits(self):
        db = _make_db()
        db.creation_date = None
        db.properties = SimpleNamespace(creationDate=_old_enough(30))
        assert len(_run([db])) == 1

    def test_creation_date_via_nested_snake_case_emits(self):
        db = _make_db()
        db.creation_date = None
        db.properties = SimpleNamespace(creation_date=_old_enough(30))
        assert len(_run([db])) == 1

    def test_elastic_pool_id_via_nested_camel_case_skips(self):
        db = _make_db()
        db.elastic_pool_id = None
        db.properties = SimpleNamespace(elasticPoolId="/subscriptions/sub/pool1")
        assert _run([db]) == []

    def test_secondary_type_via_nested_camel_case_skips(self):
        db = _make_db()
        db.secondary_type = None
        db.properties = SimpleNamespace(secondaryType="Geo")
        assert _run([db]) == []

    def test_paused_date_via_nested_camel_case_skips(self):
        db = _make_db()
        db.paused_date = None
        db.resumed_date = None
        db.properties = SimpleNamespace(pausedDate=_old_enough(2))
        assert _run([db]) == []

    def test_paused_and_resumed_via_nested_camel_case_does_not_skip(self):
        db = _make_db()
        db.paused_date = None
        db.resumed_date = None
        db.properties = SimpleNamespace(pausedDate=_old_enough(5), resumedDate=_old_enough(1))
        assert len(_run([db])) == 1

    def test_source_database_id_via_nested_camel_case_does_not_skip(self):
        """source_database_id alone is not a skip signal even via nested path."""
        db = _make_db()
        db.source_database_id = None
        db.properties = SimpleNamespace(sourceDatabaseId="/subscriptions/sub/db/src")
        assert len(_run([db])) == 1


# ===========================================================================
# Unit tests — _query_metric
# ===========================================================================


def _now():
    return datetime.now(timezone.utc)


def _window():
    return _now() - timedelta(days=14), _now()


def _mon_returning(response):
    mon = MagicMock()
    mon.metrics.list.return_value = response
    return mon


class TestQueryMetric:
    def test_metric_absent_from_response_returns_none(self):
        mon = _mon_returning(SimpleNamespace(value=[]))
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result is None

    def test_empty_series_no_data_items_returns_none(self):
        ts = SimpleNamespace(data=[])
        metric = SimpleNamespace(name=SimpleNamespace(value="cpu_percent"), timeseries=[ts])
        mon = _mon_returning(SimpleNamespace(value=[metric]))
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result is None

    def test_no_timeseries_at_all_returns_none(self):
        metric = SimpleNamespace(name=SimpleNamespace(value="cpu_percent"), timeseries=[])
        mon = _mon_returning(SimpleNamespace(value=[metric]))
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result is None

    def test_all_none_datapoints_returns_zero(self):
        """Usable series with data items but all None → confirmed zero (spec 9.6 rule 2)."""
        dp = SimpleNamespace(maximum=None)
        ts = SimpleNamespace(data=[dp])
        metric = SimpleNamespace(name=SimpleNamespace(value="cpu_percent"), timeseries=[ts])
        mon = _mon_returning(SimpleNamespace(value=[metric]))
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result == 0.0

    def test_zero_datapoint_returns_zero(self):
        dp = SimpleNamespace(maximum=0.0)
        ts = SimpleNamespace(data=[dp])
        metric = SimpleNamespace(name=SimpleNamespace(value="cpu_percent"), timeseries=[ts])
        mon = _mon_returning(SimpleNamespace(value=[metric]))
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result == 0.0

    def test_nonzero_datapoint_returns_value(self):
        dp = SimpleNamespace(maximum=5.0)
        ts = SimpleNamespace(data=[dp])
        metric = SimpleNamespace(name=SimpleNamespace(value="cpu_percent"), timeseries=[ts])
        mon = _mon_returning(SimpleNamespace(value=[metric]))
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result == 5.0

    def test_max_of_multiple_datapoints(self):
        dps = [
            SimpleNamespace(maximum=1.0),
            SimpleNamespace(maximum=5.0),
            SimpleNamespace(maximum=2.0),
        ]
        ts = SimpleNamespace(data=dps)
        metric = SimpleNamespace(name=SimpleNamespace(value="cpu_percent"), timeseries=[ts])
        mon = _mon_returning(SimpleNamespace(value=[metric]))
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result == 5.0

    def test_total_aggregation_uses_total_attr(self):
        dp = SimpleNamespace(total=42.0, maximum=0.0)
        ts = SimpleNamespace(data=[dp])
        metric = SimpleNamespace(
            name=SimpleNamespace(value="connection_successful"), timeseries=[ts]
        )
        mon = _mon_returning(SimpleNamespace(value=[metric]))
        w_start, w_end = _window()
        result = _query_metric(
            mon, "rid", "connection_successful", "Total", "total", w_start, w_end
        )
        assert result == 42.0

    def test_exception_returns_none(self):
        mon = MagicMock()
        mon.metrics.list.side_effect = RuntimeError("Network error")
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result is None

    def test_metric_name_matched_case_insensitively(self):
        """Metric name matching is case-insensitive."""
        dp = SimpleNamespace(maximum=3.0)
        ts = SimpleNamespace(data=[dp])
        metric = SimpleNamespace(name=SimpleNamespace(value="CPU_PERCENT"), timeseries=[ts])
        mon = _mon_returning(SimpleNamespace(value=[metric]))
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result == 3.0

    def test_plain_string_metric_name_matched(self):
        """Metric name as plain string (not LocalizableString) is handled."""
        dp = SimpleNamespace(maximum=1.0)
        ts = SimpleNamespace(data=[dp])
        metric = SimpleNamespace(name="cpu_percent", timeseries=[ts])
        mon = _mon_returning(SimpleNamespace(value=[metric]))
        w_start, w_end = _window()
        result = _query_metric(mon, "rid", "cpu_percent", "Maximum", "maximum", w_start, w_end)
        assert result == 1.0


# ===========================================================================
# Unit tests — _is_replica_secondary
# ===========================================================================


class TestIsReplicaSecondaryUnit:
    def test_secondary_type_non_empty_is_replica(self):
        assert _is_replica_secondary(_make_db(secondary_type="Geo")) is True

    def test_secondary_type_named_is_replica(self):
        assert _is_replica_secondary(_make_db(secondary_type="Named")) is True

    def test_source_database_id_alone_is_not_replica(self):
        """Spec 9.4: source_database_id is not a standalone replica indicator."""
        db = _make_db(source_database_id="/subscriptions/sub/databases/source")
        assert _is_replica_secondary(db) is False

    def test_neither_field_is_not_replica(self):
        assert _is_replica_secondary(_make_db()) is False

    def test_nested_secondary_type_is_replica(self):
        db = _make_db()
        db.secondary_type = None
        db.properties = SimpleNamespace(secondaryType="Geo")
        assert _is_replica_secondary(db) is True


# ===========================================================================
# Unit tests — _is_paused
# ===========================================================================


class TestIsPausedUnit:
    def test_status_paused_is_paused(self):
        assert _is_paused(_make_db(status="Paused")) is True

    def test_paused_date_no_resumed_is_paused(self):
        assert _is_paused(_make_db(paused_date=_old_enough(2))) is True

    def test_paused_date_with_later_resumed_is_not_paused(self):
        db = _make_db(paused_date=_old_enough(5), resumed_date=_old_enough(1))
        assert _is_paused(db) is False

    def test_paused_date_with_earlier_resumed_is_paused(self):
        db = _make_db(paused_date=_old_enough(1), resumed_date=_old_enough(5))
        assert _is_paused(db) is True

    def test_no_paused_date_is_not_paused(self):
        assert _is_paused(_make_db()) is False

    def test_online_status_without_paused_date_is_not_paused(self):
        assert _is_paused(_make_db(status="Online")) is False
