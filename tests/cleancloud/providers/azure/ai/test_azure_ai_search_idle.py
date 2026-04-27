"""Tests for azure.ai_search.idle rule.

Spec: docs/specs/azure/ai/ai_search_idle.md
"""

import math
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Optional

import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

from cleancloud.providers.azure.rules.ai.ai_search_idle import (
    _SUPPORTED_SKUS,
    RULE_METADATA,
    _check_object_surfaces,
    _evaluate_metric,
    _extract_resource_group,
    _MetricResult,
    _norm_location,
    _normalize_sku,
    _resolve_capacity,
    _resolve_created_at,
    _resolve_provisioning_state,
    _resolve_status,
    find_idle_ai_search_services,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUB = "sub-123"
_RG = "rg-search"
_SVC_NAME = "my-search-svc"
_SVC_ID = (
    f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
    f"/providers/Microsoft.Search/searchServices/{_SVC_NAME}"
)
_WINDOW_DAYS = 90

# Minimum observed day-buckets needed for 95% coverage over 90-day window.
_MIN_BUCKETS = math.ceil(_WINDOW_DAYS * 0.95)  # 86

# Fixed clean window for unit tests: avoids fractional-day rounding sensitivity.
_UNIT_WINDOW_END = datetime(2024, 4, 1, 0, 0, 0, tzinfo=timezone.utc)
_UNIT_WINDOW_START = _UNIT_WINDOW_END - timedelta(days=_WINDOW_DAYS)


# ---------------------------------------------------------------------------
# Metric response builders
# ---------------------------------------------------------------------------


def _make_datapoints(
    agg_attr: str = "average",
    value: float = 0.0,
    n: int = _WINDOW_DAYS,
    window_start: Optional[datetime] = None,
) -> list:
    """n daily datapoints, timestamped one hour into each day of the window."""
    if window_start is None:
        window_start = datetime.now(timezone.utc) - timedelta(days=_WINDOW_DAYS)
    dps = []
    for i in range(n):
        ts = window_start + timedelta(days=i, hours=1)
        dp = SimpleNamespace(timestamp=ts, total=None, average=None, maximum=None)
        setattr(dp, agg_attr, value)
        dps.append(dp)
    return dps


def _make_metric_response(datapoints: list) -> SimpleNamespace:
    ts_obj = SimpleNamespace(data=datapoints)
    metric = SimpleNamespace(timeseries=[ts_obj])
    return SimpleNamespace(value=[metric])


def _make_no_timeseries_response() -> SimpleNamespace:
    metric = SimpleNamespace(timeseries=[])
    return SimpleNamespace(value=[metric])


def _make_empty_value_response() -> SimpleNamespace:
    return SimpleNamespace(value=[])


# ---------------------------------------------------------------------------
# Monitor client mock
# ---------------------------------------------------------------------------


def _make_zero_monitor() -> SimpleNamespace:
    """Returns zero for all three required metrics (95%-covered)."""

    def _list(*args, **kwargs):
        name = kwargs.get("metricnames", "")
        if name == "SearchQueriesPerSecond":
            return _make_metric_response(_make_datapoints("average", 0.0))
        elif name in ("DocumentsProcessedCount", "SkillExecutionCount"):
            return _make_metric_response(_make_datapoints("total", 0.0))
        return _make_empty_value_response()

    return SimpleNamespace(metrics=SimpleNamespace(list=_list))


def _make_active_monitor(active_metric: str, agg_attr: str) -> SimpleNamespace:
    """Returns non-zero for active_metric, zero for the others."""

    def _list(*args, **kwargs):
        name = kwargs.get("metricnames", "")
        if name == active_metric:
            return _make_metric_response(_make_datapoints(agg_attr, 1.0))
        if name == "SearchQueriesPerSecond":
            return _make_metric_response(_make_datapoints("average", 0.0))
        return _make_metric_response(_make_datapoints("total", 0.0))

    return SimpleNamespace(metrics=SimpleNamespace(list=_list))


def _make_unknown_monitor() -> SimpleNamespace:
    """Returns no data (UNKNOWN) for all metrics."""

    def _list(*args, **kwargs):
        return _make_empty_value_response()

    return SimpleNamespace(metrics=SimpleNamespace(list=_list))


def _make_raising_monitor(exc) -> SimpleNamespace:
    """Raises exc on every metrics.list call."""

    def _list(*args, **kwargs):
        raise exc

    return SimpleNamespace(metrics=SimpleNamespace(list=_list))


# ---------------------------------------------------------------------------
# Data-plane client mock
# ---------------------------------------------------------------------------


class _MockDpClient:
    """Mock data-plane client; all required and optional surfaces empty by default."""

    def __init__(
        self,
        *,
        fail_required: Optional[str] = None,
        non_empty_required: Optional[str] = None,
        fail_optional: Optional[str] = None,
        non_empty_optional: Optional[str] = None,
    ):
        self._fail_required = fail_required
        self._non_empty_required = non_empty_required
        self._fail_optional = fail_optional
        self._non_empty_optional = non_empty_optional

    def _req(self, key: str):
        if key == self._fail_required:
            raise RuntimeError(f"simulated failure on required surface '{key}'")
        if key == self._non_empty_required:
            return [SimpleNamespace(name="item1")]
        return []

    def _opt(self, key: str):
        if key == self._fail_optional:
            raise RuntimeError(f"simulated failure on optional surface '{key}'")
        if key == self._non_empty_optional:
            return [SimpleNamespace(name="item1")]
        return []

    def list_indexes(self):
        return self._req("indexes")

    def list_indexers(self):
        return self._req("indexers")

    def list_data_source_connections(self):
        return self._req("data_sources")

    def list_skillsets(self):
        return self._req("skillsets")

    def list_synonym_maps(self):
        return self._req("synonym_maps")

    def list_aliases(self):
        return self._opt("aliases")

    def list_knowledge_sources(self):
        return self._opt("knowledge_sources")

    def list_agents(self):
        return self._opt("agents")


def _make_dp_factory(**kwargs) -> callable:
    return lambda endpoint: _MockDpClient(**kwargs)


def _make_none_dp_factory() -> callable:
    """Factory that always returns None (package unavailable)."""
    return lambda endpoint: None


# ---------------------------------------------------------------------------
# Service builder
# ---------------------------------------------------------------------------


def _make_service(
    *,
    name: str = _SVC_NAME,
    svc_id: Optional[str] = None,
    location: str = "eastus",
    sku_name: str = "standard",
    provisioning_state: str = "succeeded",
    status: str = "running",
    age_days: int = 90,
    replica_count: int = 1,
    partition_count: int = 1,
    tags: Optional[dict] = None,
    hosting_mode: Optional[str] = None,
    rg: str = _RG,
) -> SimpleNamespace:
    if svc_id is None:
        svc_id = (
            f"/subscriptions/{_SUB}/resourceGroups/{rg}"
            f"/providers/Microsoft.Search/searchServices/{name}"
        )
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=age_days) if age_days is not None else None
    system_data = SimpleNamespace(created_at=created_at) if created_at is not None else None
    return SimpleNamespace(
        id=svc_id,
        name=name,
        location=location,
        sku=SimpleNamespace(name=sku_name),
        provisioning_state=provisioning_state,
        status=status,
        replica_count=replica_count,
        partition_count=partition_count,
        system_data=system_data,
        tags=tags or {},
        hosting_mode=hosting_mode,
    )


def _make_search_client(services: list) -> SimpleNamespace:
    return SimpleNamespace(services=SimpleNamespace(list_by_subscription=lambda: services))


# ---------------------------------------------------------------------------
# Call helper
# ---------------------------------------------------------------------------


def _call(
    search_client,
    monitor_client,
    *,
    dp_factory: Optional[callable] = None,
    region_filter: Optional[str] = None,
) -> list:
    if dp_factory is None:
        dp_factory = _make_dp_factory()
    return find_idle_ai_search_services(
        subscription_id=_SUB,
        credential=None,
        client=search_client,
        monitor_client=monitor_client,
        data_plane_factory=dp_factory,
        region_filter=region_filter,
    )


# ===========================================================================
# Integration tests
# ===========================================================================


class TestMustEmit:
    """Spec 4, 8.13: all required signals resolved and zero -> emit."""

    def test_happy_path_emits_one_finding(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        findings = _call(sc, _make_zero_monitor())
        assert len(findings) == 1
        assert findings[0].rule_id == "azure.ai_search.idle"

    def test_no_services_returns_empty(self):
        sc = _make_search_client([])
        findings = _call(sc, _make_zero_monitor())
        assert findings == []

    def test_multiple_idle_services_all_emitted(self):
        svc1 = _make_service(name="s1")
        svc2 = _make_service(name="s2")
        sc = _make_search_client([svc1, svc2])
        findings = _call(sc, _make_zero_monitor())
        assert len(findings) == 2


# ---------------------------------------------------------------------------


class TestIdNameGuards:
    """Spec 8.1-8.2: id and name guards."""

    def test_id_none_skips(self):
        svc = _make_service()
        svc.id = None
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_id_empty_skips(self):
        svc = _make_service()
        svc.id = ""
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_name_none_skips(self):
        svc = _make_service()
        svc.name = None
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_name_empty_skips(self):
        svc = _make_service()
        svc.name = ""
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_valid_id_and_name_proceeds(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1


# ---------------------------------------------------------------------------


class TestRegionFilter:
    """Spec 8.3, 7: region filter uses exact lowercase match; spaces preserved."""

    def test_filter_excludes_non_matching(self):
        svc = _make_service(location="westeurope")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor(), region_filter="eastus") == []

    def test_filter_matches_same_lowercase(self):
        svc = _make_service(location="eastus")
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor(), region_filter="eastus")) == 1

    def test_filter_matches_after_lowercasing(self):
        svc = _make_service(location="EastUS")
        sc = _make_search_client([svc])
        # "EastUS" normalized to "eastus" == filter "eastus"
        assert len(_call(sc, _make_zero_monitor(), region_filter="eastus")) == 1

    def test_filter_spaces_preserved_not_stripped(self):
        # spec 7: do NOT remove spaces
        svc = _make_service(location="east us")
        sc = _make_search_client([svc])
        # "east us" != "eastus": spaces are NOT stripped
        assert _call(sc, _make_zero_monitor(), region_filter="eastus") == []

    def test_filter_spaces_preserved_matches_with_spaces(self):
        svc = _make_service(location="east us")
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor(), region_filter="east us")) == 1

    def test_no_filter_includes_all(self):
        svc = _make_service(location="australiaeast")
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor(), region_filter=None)) == 1


# ---------------------------------------------------------------------------


class TestProvisioningStateContract:
    """Spec 8.4, 9.1: provisioning_state must resolve exactly to 'succeeded'."""

    def test_succeeded_emits(self):
        svc = _make_service(provisioning_state="succeeded")
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_updating_skips(self):
        svc = _make_service(provisioning_state="Updating")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_failed_skips(self):
        svc = _make_service(provisioning_state="Failed")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_none_skips(self):
        svc = _make_service(provisioning_state=None)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_conflict_sdk_nested_skips(self):
        svc = _make_service(provisioning_state="succeeded")
        svc.properties = SimpleNamespace(provisioning_state="Failed", provisioningState=None)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_nested_only_succeeded_emits(self):
        svc = _make_service()
        del svc.provisioning_state  # SDK attribute absent
        svc.properties = SimpleNamespace(provisioning_state="succeeded", provisioningState=None)
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_provisioning_state_capitalized_skips(self):
        # Only exact "succeeded" is eligible; "Succeeded" is not
        svc = _make_service(provisioning_state="Succeeded")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []


# ---------------------------------------------------------------------------


class TestStatusContract:
    """Spec 8.5, 9.1: status must resolve exactly to 'running'."""

    def test_running_emits(self):
        svc = _make_service(status="running")
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_degraded_skips(self):
        svc = _make_service(status="degraded")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_disabled_skips(self):
        svc = _make_service(status="disabled")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_none_skips(self):
        svc = _make_service(status=None)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_conflict_skips(self):
        svc = _make_service(status="running")
        svc.properties = SimpleNamespace(status="degraded")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_nested_only_running_emits(self):
        svc = _make_service()
        del svc.status
        svc.properties = SimpleNamespace(status="running")
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_status_capitalized_skips(self):
        svc = _make_service(status="Running")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []


# ---------------------------------------------------------------------------


class TestSkuContract:
    """Spec 8.6, 9.2: supported dedicated billable tiers."""

    @pytest.mark.parametrize(
        "sku",
        [
            "basic",
            "standard",
            "standard2",
            "standard3",
            "storage_optimized_l1",
            "storage_optimized_l2",
        ],
    )
    def test_supported_sku_emits(self, sku):
        svc = _make_service(sku_name=sku)
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_free_sku_skips(self):
        svc = _make_service(sku_name="free")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_unknown_sku_skips(self):
        svc = _make_service(sku_name="enterprise")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_camelcase_storage_optimized_l1_normalized(self):
        svc = _make_service(sku_name="StorageOptimizedL1")
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_camelcase_storage_optimized_l2_normalized(self):
        svc = _make_service(sku_name="StorageOptimizedL2")
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_mixed_case_standard_normalized(self):
        svc = _make_service(sku_name="Standard")
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_sku_none_skips(self):
        svc = _make_service()
        svc.sku = None
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_sku_name_none_skips(self):
        svc = _make_service()
        svc.sku = SimpleNamespace(name=None)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_hyphenated_storage_optimized_skips(self):
        # "storage-optimized-l1" must not match "storage_optimized_l1" (spec 7: lowercase only)
        svc = _make_service(sku_name="storage-optimized-l1")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_punctuated_standard_skips(self):
        svc = _make_service(sku_name="stan-dard")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []


# ---------------------------------------------------------------------------


class TestCreatedAtContract:
    """Spec 8.7: created_at must be present, valid, and service age >= 90 days."""

    def test_age_exactly_90_days_emits(self):
        svc = _make_service(age_days=90)
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_age_89_days_skips(self):
        svc = _make_service(age_days=89)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_age_200_days_emits(self):
        svc = _make_service(age_days=200)
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_system_data_absent_skips(self):
        svc = _make_service(age_days=90)
        svc.system_data = None
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_created_at_none_skips(self):
        svc = _make_service(age_days=90)
        svc.system_data = SimpleNamespace(created_at=None)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_created_at_future_skips(self):
        future = datetime.now(timezone.utc) + timedelta(days=1)
        svc = _make_service()
        svc.system_data = SimpleNamespace(created_at=future)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_created_at_string_valid_iso_parsed(self):
        ts = datetime.now(timezone.utc) - timedelta(days=91)
        svc = _make_service()
        svc.system_data = SimpleNamespace(created_at=ts.isoformat())
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_created_at_string_invalid_skips(self):
        svc = _make_service()
        svc.system_data = SimpleNamespace(created_at="not-a-date")
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_created_at_non_string_non_datetime_skips(self):
        svc = _make_service()
        svc.system_data = SimpleNamespace(created_at=12345)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_no_age_only_fallback(self):
        # Spec 8.7: absent created_at is skip, not fallback to age-only
        svc = _make_service(age_days=200)
        svc.system_data = None
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []


# ---------------------------------------------------------------------------


class TestCapacityContract:
    """Spec 8.8: replica_count and partition_count must be known positive integers."""

    def test_positive_replica_and_partition_emits(self):
        svc = _make_service(replica_count=2, partition_count=3)
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_replica_count_zero_skips(self):
        svc = _make_service(replica_count=0)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_replica_count_none_skips(self):
        svc = _make_service(replica_count=None)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_partition_count_zero_skips(self):
        svc = _make_service(partition_count=0)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_partition_count_none_skips(self):
        svc = _make_service(partition_count=None)
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_replica_count_conflict_sdk_nested_skips(self):
        svc = _make_service(replica_count=1)
        svc.properties = SimpleNamespace(
            replica_count=2, replicaCount=None, partition_count=None, partitionCount=None
        )
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor()) == []

    def test_replica_count_nested_only_emits(self):
        svc = _make_service()
        del svc.replica_count
        svc.properties = SimpleNamespace(
            replica_count=1, replicaCount=None, partition_count=None, partitionCount=None
        )
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1


# ---------------------------------------------------------------------------


class TestObjectSurfacesContract:
    """Spec 8.9-8.10, 9.3: data-plane structural emptiness."""

    def test_dp_factory_returns_none_skips(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        assert _call(sc, _make_zero_monitor(), dp_factory=_make_none_dp_factory()) == []

    @pytest.mark.parametrize(
        "surface",
        [
            "indexes",
            "indexers",
            "data_sources",
            "skillsets",
            "synonym_maps",
        ],
    )
    def test_non_empty_required_surface_skips(self, surface):
        svc = _make_service()
        sc = _make_search_client([svc])
        dp_factory = _make_dp_factory(non_empty_required=surface)
        assert _call(sc, _make_zero_monitor(), dp_factory=dp_factory) == []

    @pytest.mark.parametrize(
        "surface",
        [
            "indexes",
            "indexers",
            "data_sources",
            "skillsets",
            "synonym_maps",
        ],
    )
    def test_failing_required_surface_skips(self, surface):
        svc = _make_service()
        sc = _make_search_client([svc])
        dp_factory = _make_dp_factory(fail_required=surface)
        assert _call(sc, _make_zero_monitor(), dp_factory=dp_factory) == []

    @pytest.mark.parametrize(
        "surface",
        [
            "aliases",
            "knowledge_sources",
            "agents",
        ],
    )
    def test_non_empty_optional_surface_skips(self, surface):
        # spec 9.3.7: non-empty optional -> skip
        svc = _make_service()
        sc = _make_search_client([svc])
        dp_factory = _make_dp_factory(non_empty_optional=surface)
        assert _call(sc, _make_zero_monitor(), dp_factory=dp_factory) == []

    @pytest.mark.parametrize(
        "surface",
        [
            "aliases",
            "knowledge_sources",
            "agents",
        ],
    )
    def test_failing_optional_surface_still_emits(self, surface):
        # spec 9.3.6: optional surface failure -> omit from counts, do NOT skip service
        svc = _make_service()
        sc = _make_search_client([svc])
        dp_factory = _make_dp_factory(fail_optional=surface)
        assert len(_call(sc, _make_zero_monitor(), dp_factory=dp_factory)) == 1

    def test_optional_surface_method_absent_still_emits(self):
        # spec 9.3.5: optional surfaces not required for eligibility

        class _NoOptionalClient:
            def list_indexes(self):
                return []

            def list_indexers(self):
                return []

            def list_data_source_connections(self):
                return []

            def list_skillsets(self):
                return []

            def list_synonym_maps(self):
                return []

            # No list_aliases, list_knowledge_sources, list_agents

        svc = _make_service()
        sc = _make_search_client([svc])

        def dp_factory(endpoint):
            return _NoOptionalClient()

        assert len(_call(sc, _make_zero_monitor(), dp_factory=dp_factory)) == 1

    def test_all_required_surfaces_empty_emits(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor(), dp_factory=_make_dp_factory())) == 1

    def test_object_counts_in_details(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        findings = _call(sc, _make_zero_monitor())
        assert len(findings) == 1
        counts = findings[0].details["object_counts"]
        for key in ("indexes", "indexers", "data_sources", "skillsets", "synonym_maps"):
            assert counts[key] == 0


# ---------------------------------------------------------------------------


class TestMetricContract:
    """Spec 8.11-8.12, 9.5: all three required metrics must be ZERO."""

    def test_all_zero_emits(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        assert len(_call(sc, _make_zero_monitor())) == 1

    def test_search_queries_per_second_active_skips(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        mon = _make_active_monitor("SearchQueriesPerSecond", "average")
        assert _call(sc, mon) == []

    def test_documents_processed_count_active_skips(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        mon = _make_active_monitor("DocumentsProcessedCount", "total")
        assert _call(sc, mon) == []

    def test_skill_execution_count_active_skips(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        mon = _make_active_monitor("SkillExecutionCount", "total")
        assert _call(sc, mon) == []

    def test_metric_unknown_insufficient_coverage_skips(self):
        # Fewer buckets than 95% threshold -> UNKNOWN -> skip
        def _list(*args, **kwargs):
            name = kwargs.get("metricnames", "")
            if name == "SearchQueriesPerSecond":
                # Only 50 buckets -> 50/90 = 55% < 95% -> UNKNOWN
                return _make_metric_response(_make_datapoints("average", 0.0, n=50))
            return _make_metric_response(_make_datapoints("total", 0.0))

        svc = _make_service()
        sc = _make_search_client([svc])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=_list))
        assert _call(sc, mon) == []

    def test_all_metrics_unknown_skips(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        assert _call(sc, _make_unknown_monitor()) == []

    def test_metric_query_raises_skips(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        mon = _make_raising_monitor(RuntimeError("timeout"))
        assert _call(sc, mon) == []

    def test_metric_timestamp_none_datapoint_skips(self):
        # unparseable timestamp -> UNKNOWN -> skip
        def _list(*args, **kwargs):
            name = kwargs.get("metricnames", "")
            if name == "SearchQueriesPerSecond":
                dps = _make_datapoints("average", 0.0)
                dps[5] = SimpleNamespace(timestamp=None, average=0.0, total=None, maximum=None)
                return _make_metric_response(dps)
            return _make_metric_response(_make_datapoints("total", 0.0))

        svc = _make_service()
        sc = _make_search_client([svc])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=_list))
        assert _call(sc, mon) == []

    def test_metric_non_datetime_timestamp_skips(self):
        # non-datetime timestamp -> UNKNOWN -> skip
        def _list(*args, **kwargs):
            name = kwargs.get("metricnames", "")
            if name == "SearchQueriesPerSecond":
                dps = _make_datapoints("average", 0.0)
                dps[3] = SimpleNamespace(
                    timestamp="2024-01-01T00:00:00Z", average=0.0, total=None, maximum=None
                )
                return _make_metric_response(dps)
            return _make_metric_response(_make_datapoints("total", 0.0))

        svc = _make_service()
        sc = _make_search_client([svc])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=_list))
        assert _call(sc, mon) == []

    def test_metrics_not_queried_when_earlier_check_fails(self):
        """Metrics should not be queried when a pre-condition (e.g. status) fails."""
        called = []

        def _list(*args, **kwargs):
            called.append(kwargs.get("metricnames"))
            return _make_metric_response(_make_datapoints("average", 0.0))

        svc = _make_service(status="degraded")
        sc = _make_search_client([svc])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=_list))
        _call(sc, mon)
        assert called == []

    def test_monitor_not_called_with_interval_p1d(self):
        """No interval= parameter sent to Azure Monitor; source-bucket granularity per spec 9.5.2."""
        captured_kwargs: dict = {}

        def _list(*args, **kwargs):
            captured_kwargs.update(kwargs)
            name = kwargs.get("metricnames", "")
            if name == "SearchQueriesPerSecond":
                return _make_metric_response(_make_datapoints("average", 0.0))
            return _make_metric_response(_make_datapoints("total", 0.0))

        svc = _make_service()
        sc = _make_search_client([svc])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=_list))
        findings = _call(sc, mon)
        assert len(findings) == 1
        assert "interval" not in captured_kwargs

    def test_non_numeric_aggregation_value_skips(self):
        """Non-numeric aggregation value in metric response -> UNKNOWN -> service skipped."""

        def _list(*args, **kwargs):
            name = kwargs.get("metricnames", "")
            if name == "SearchQueriesPerSecond":
                dps = _make_datapoints("average", 0.0)
                bad_ts = dps[5].timestamp
                dps[5] = SimpleNamespace(timestamp=bad_ts, average="N/A", total=None, maximum=None)
                return _make_metric_response(dps)
            return _make_metric_response(_make_datapoints("total", 0.0))

        svc = _make_service()
        sc = _make_search_client([svc])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=_list))
        assert _call(sc, mon) == []

    def test_malformed_timeseries_not_iterable_skips(self):
        """timeseries that is not iterable raises TypeError -> UNKNOWN -> service skipped."""

        def _list(*args, **kwargs):
            name = kwargs.get("metricnames", "")
            if name == "SearchQueriesPerSecond":
                metric = SimpleNamespace(timeseries=42)  # not iterable
                return SimpleNamespace(value=[metric])
            return _make_metric_response(_make_datapoints("total", 0.0))

        svc = _make_service()
        sc = _make_search_client([svc])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=_list))
        assert _call(sc, mon) == []


# ---------------------------------------------------------------------------


class TestFailureBehavior:
    """Spec 12: subscription list propagates; per-service errors skip."""

    def test_service_list_propagates_runtime_error(self):
        def _raise():
            raise RuntimeError("disk full")

        sc = SimpleNamespace(services=SimpleNamespace(list_by_subscription=_raise))
        with pytest.raises(RuntimeError, match="disk full"):
            _call(sc, _make_zero_monitor())

    def test_per_service_http_error_skips_service(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        # HttpResponseError raised during metric evaluation -> skip
        mon = _make_raising_monitor(HttpResponseError("403 Forbidden"))
        assert _call(sc, mon) == []

    def test_per_service_service_request_error_skips(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        mon = _make_raising_monitor(ServiceRequestError("transport error"))
        assert _call(sc, mon) == []

    def test_per_service_service_response_error_skips(self):
        svc = _make_service()
        sc = _make_search_client([svc])
        mon = _make_raising_monitor(ServiceResponseError("response error"))
        assert _call(sc, mon) == []

    def test_one_service_http_error_other_still_emits(self):
        svc_bad = _make_service(name="bad-svc")
        svc_good = _make_service(name="good-svc")
        call_count = []

        def _list(*args, **kwargs):
            call_count.append(1)
            # Fail on first call (bad-svc), succeed on subsequent (good-svc)
            if len(call_count) == 1:
                raise HttpResponseError("403")
            name = kwargs.get("metricnames", "")
            if name == "SearchQueriesPerSecond":
                return _make_metric_response(_make_datapoints("average", 0.0))
            return _make_metric_response(_make_datapoints("total", 0.0))

        sc = _make_search_client([svc_bad, svc_good])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=_list))
        findings = _call(sc, mon)
        assert len(findings) == 1
        assert findings[0].details["service_name"] == "good-svc"


# ---------------------------------------------------------------------------


class TestFindingShape:
    """Spec 11: required finding fields and details."""

    def _get_finding(self):
        svc = _make_service(
            name="shape-svc",
            location="eastus",
            sku_name="standard",
            age_days=120,
            replica_count=2,
            partition_count=3,
            tags={"env": "test"},
            hosting_mode="default",
            rg="rg-shape",
        )
        sc = _make_search_client([svc])
        findings = _call(sc, _make_zero_monitor())
        assert len(findings) == 1
        return findings[0]

    def test_provider(self):
        assert self._get_finding().provider == "azure"

    def test_rule_id(self):
        assert self._get_finding().rule_id == "azure.ai_search.idle"

    def test_resource_type(self):
        assert self._get_finding().resource_type == "azure.ai.search_service"

    def test_resource_id_contains_service_name(self):
        f = self._get_finding()
        assert "shape-svc" in f.resource_id

    def test_region_normalized(self):
        assert self._get_finding().region == "eastus"

    def test_estimated_cost_always_none(self):
        # spec 10: always None
        assert self._get_finding().estimated_monthly_cost_usd is None

    def test_confidence_always_high(self):
        # spec 11.1
        assert self._get_finding().confidence.value == "high"

    def test_risk_always_medium(self):
        # spec 11.1
        assert self._get_finding().risk.value == "medium"

    def test_title_contains_service_name(self):
        assert "shape-svc" in self._get_finding().title

    def test_summary_contains_service_name(self):
        assert "shape-svc" in self._get_finding().summary

    def test_reason_non_empty(self):
        assert self._get_finding().reason

    def test_detected_at_is_datetime(self):
        assert isinstance(self._get_finding().detected_at, datetime)

    def test_details_service_name(self):
        assert self._get_finding().details["service_name"] == "shape-svc"

    def test_details_resource_group(self):
        assert self._get_finding().details["resource_group"] == "rg-shape"

    def test_details_subscription_id(self):
        assert self._get_finding().details["subscription_id"] == _SUB

    def test_details_sku_name(self):
        assert self._get_finding().details["sku_name"] == "standard"

    def test_details_replica_count(self):
        assert self._get_finding().details["replica_count"] == 2

    def test_details_partition_count(self):
        assert self._get_finding().details["partition_count"] == 3

    def test_details_status(self):
        assert self._get_finding().details["status"] == "running"

    def test_details_provisioning_state(self):
        assert self._get_finding().details["provisioning_state"] == "succeeded"

    def test_details_created_at(self):
        assert self._get_finding().details["created_at"]

    def test_details_idle_window_days(self):
        assert self._get_finding().details["idle_window_days"] == 90

    def test_details_object_counts_dict(self):
        assert isinstance(self._get_finding().details["object_counts"], dict)

    def test_details_metrics_used(self):
        metrics = self._get_finding().details["metrics_used"]
        assert "SearchQueriesPerSecond" in metrics
        assert "DocumentsProcessedCount" in metrics
        assert "SkillExecutionCount" in metrics

    def test_details_tags(self):
        assert self._get_finding().details["tags"] == {"env": "test"}

    def test_details_tags_never_none(self):
        # spec 7: tags must never be None in output
        svc = _make_service()
        svc.tags = None
        sc = _make_search_client([svc])
        findings = _call(sc, _make_zero_monitor())
        assert findings[0].details["tags"] == {}

    def test_evidence_signals_used_non_empty(self):
        assert self._get_finding().evidence.signals_used

    def test_evidence_signals_not_checked_non_empty(self):
        assert self._get_finding().evidence.signals_not_checked

    def test_evidence_time_window(self):
        assert "90" in self._get_finding().evidence.time_window


# ===========================================================================
# Unit tests
# ===========================================================================


class TestNormalizeSku:
    """_normalize_sku: strip non-alnum, lowercase, then alias-resolve."""

    def test_standard(self):
        assert _normalize_sku("standard") == "standard"

    def test_standard_mixed_case(self):
        assert _normalize_sku("Standard") == "standard"

    def test_standard2(self):
        assert _normalize_sku("Standard2") == "standard2"

    def test_storage_optimized_l1_camel(self):
        assert _normalize_sku("StorageOptimizedL1") == "storage_optimized_l1"

    def test_storage_optimized_l2_camel(self):
        assert _normalize_sku("StorageOptimizedL2") == "storage_optimized_l2"

    def test_storage_optimized_l1_underscore_already_canonical(self):
        assert _normalize_sku("storage_optimized_l1") == "storage_optimized_l1"

    def test_empty_string(self):
        assert _normalize_sku("") == ""

    def test_none_like(self):
        assert _normalize_sku(None) == ""

    def test_unknown_not_in_supported(self):
        assert _normalize_sku("enterprise") not in _SUPPORTED_SKUS

    def test_hyphenated_storage_optimized_not_normalized(self):
        # Old strip-non-alnum would map "storage-optimized-l1" -> "storageoptimizedl1" -> alias
        # New lowercase-only correctly rejects it (spec 7: lowercase only)
        assert _normalize_sku("storage-optimized-l1") not in _SUPPORTED_SKUS

    def test_punctuated_standard_not_normalized(self):
        # "stan-dard" must NOT map to "standard"
        assert _normalize_sku("stan-dard") not in _SUPPORTED_SKUS

    def test_underscored_canonical_still_matches_directly(self):
        # "storage_optimized_l1" lowercases to itself, direct SUPPORTED_SKUS member
        assert _normalize_sku("storage_optimized_l1") in _SUPPORTED_SKUS


class TestNormLocation:
    """_norm_location: lowercase only; spaces, hyphens, digits preserved (spec 7)."""

    def test_lowercase_unchanged(self):
        assert _norm_location("eastus") == "eastus"

    def test_uppercase_lowercased(self):
        assert _norm_location("EastUS") == "eastus"

    def test_spaces_preserved(self):
        # spec 7: do NOT remove spaces
        assert _norm_location("East US") == "east us"

    def test_hyphens_preserved(self):
        assert _norm_location("east-us") == "east-us"

    def test_empty_string(self):
        assert _norm_location("") == ""

    def test_none_returns_empty(self):
        assert _norm_location(None) == ""


class TestExtractResourceGroup:
    """_extract_resource_group: ARM id parsing."""

    def test_valid_arm_id(self):
        rg = _extract_resource_group(
            "/subscriptions/sub-1/resourceGroups/my-rg/providers/Microsoft.Search/searchServices/svc1"
        )
        assert rg == "my-rg"

    def test_case_insensitive_resourcegroups(self):
        rg = _extract_resource_group(
            "/subscriptions/sub-1/ResourceGroups/my-rg/providers/foo/bar/baz"
        )
        assert rg == "my-rg"

    def test_no_resourcegroups_segment_returns_none(self):
        assert _extract_resource_group("/subscriptions/sub-1/providers/foo") is None

    def test_empty_id_returns_none(self):
        assert _extract_resource_group("") is None

    def test_none_returns_none(self):
        assert _extract_resource_group(None) is None


class TestResolveProvisioningState:

    def test_sdk_value_returned(self):
        svc = SimpleNamespace(provisioning_state="succeeded")
        assert _resolve_provisioning_state(svc) == "succeeded"

    def test_nested_fallback(self):
        svc = SimpleNamespace(
            properties=SimpleNamespace(provisioning_state="succeeded", provisioningState=None)
        )
        assert _resolve_provisioning_state(svc) == "succeeded"

    def test_nested_camel_fallback(self):
        svc = SimpleNamespace(
            properties=SimpleNamespace(provisioning_state=None, provisioningState="succeeded")
        )
        assert _resolve_provisioning_state(svc) == "succeeded"

    def test_conflict_returns_none(self):
        svc = SimpleNamespace(
            provisioning_state="succeeded",
            properties=SimpleNamespace(provisioning_state="Failed", provisioningState=None),
        )
        assert _resolve_provisioning_state(svc) is None

    def test_both_absent_returns_none(self):
        svc = SimpleNamespace()
        assert _resolve_provisioning_state(svc) is None

    def test_both_same_value_no_conflict(self):
        svc = SimpleNamespace(
            provisioning_state="succeeded",
            properties=SimpleNamespace(provisioning_state="succeeded", provisioningState=None),
        )
        assert _resolve_provisioning_state(svc) == "succeeded"


class TestResolveStatus:

    def test_sdk_value_returned(self):
        svc = SimpleNamespace(status="running")
        assert _resolve_status(svc) == "running"

    def test_nested_fallback(self):
        svc = SimpleNamespace(properties=SimpleNamespace(status="running"))
        assert _resolve_status(svc) == "running"

    def test_conflict_returns_none(self):
        svc = SimpleNamespace(
            status="running",
            properties=SimpleNamespace(status="degraded"),
        )
        assert _resolve_status(svc) is None

    def test_both_absent_returns_none(self):
        assert _resolve_status(SimpleNamespace()) is None


class TestResolveCapacity:

    def test_positive_integer_returned(self):
        svc = SimpleNamespace(replica_count=3)
        assert _resolve_capacity(svc, "replica_count", "replica_count", "replicaCount") == 3

    def test_zero_returns_none(self):
        svc = SimpleNamespace(replica_count=0)
        assert _resolve_capacity(svc, "replica_count", "replica_count", "replicaCount") is None

    def test_negative_returns_none(self):
        svc = SimpleNamespace(replica_count=-1)
        assert _resolve_capacity(svc, "replica_count", "replica_count", "replicaCount") is None

    def test_string_integer_coerced(self):
        svc = SimpleNamespace(replica_count="2")
        assert _resolve_capacity(svc, "replica_count", "replica_count", "replicaCount") == 2

    def test_invalid_string_returns_none(self):
        svc = SimpleNamespace(replica_count="n/a")
        assert _resolve_capacity(svc, "replica_count", "replica_count", "replicaCount") is None

    def test_conflict_returns_none(self):
        svc = SimpleNamespace(
            replica_count=1,
            properties=SimpleNamespace(replica_count=2, replicaCount=None),
        )
        assert _resolve_capacity(svc, "replica_count", "replica_count", "replicaCount") is None

    def test_both_absent_returns_none(self):
        assert (
            _resolve_capacity(SimpleNamespace(), "replica_count", "replica_count", "replicaCount")
            is None
        )

    def test_nested_camel_fallback(self):
        svc = SimpleNamespace(properties=SimpleNamespace(replica_count=None, replicaCount=4))
        assert _resolve_capacity(svc, "replica_count", "replica_count", "replicaCount") == 4


class TestResolveCreatedAt:

    def test_tz_aware_datetime_returned(self):
        ts = datetime(2023, 1, 1, tzinfo=timezone.utc)
        svc = SimpleNamespace(system_data=SimpleNamespace(created_at=ts))
        result = _resolve_created_at(svc)
        assert result == ts

    def test_tz_naive_datetime_converted_to_utc(self):
        ts = datetime(2023, 1, 1)  # naive
        svc = SimpleNamespace(system_data=SimpleNamespace(created_at=ts))
        result = _resolve_created_at(svc)
        assert result.tzinfo is not None

    def test_string_iso_parsed(self):
        ts_str = "2023-01-01T00:00:00"
        svc = SimpleNamespace(system_data=SimpleNamespace(created_at=ts_str))
        result = _resolve_created_at(svc)
        assert result is not None
        assert result.year == 2023

    def test_string_with_z_suffix_parsed(self):
        ts_str = "2023-01-01T00:00:00Z"
        svc = SimpleNamespace(system_data=SimpleNamespace(created_at=ts_str))
        result = _resolve_created_at(svc)
        assert result is not None

    def test_invalid_string_returns_none(self):
        svc = SimpleNamespace(system_data=SimpleNamespace(created_at="not-a-date"))
        assert _resolve_created_at(svc) is None

    def test_future_timestamp_returns_none(self):
        future = datetime.now(timezone.utc) + timedelta(days=10)
        svc = SimpleNamespace(system_data=SimpleNamespace(created_at=future))
        assert _resolve_created_at(svc) is None

    def test_none_value_returns_none(self):
        svc = SimpleNamespace(system_data=SimpleNamespace(created_at=None))
        assert _resolve_created_at(svc) is None

    def test_system_data_absent_returns_none(self):
        assert _resolve_created_at(SimpleNamespace()) is None

    def test_system_data_none_returns_none(self):
        svc = SimpleNamespace(system_data=None)
        assert _resolve_created_at(svc) is None

    def test_non_datetime_non_string_returns_none(self):
        svc = SimpleNamespace(system_data=SimpleNamespace(created_at=99999))
        assert _resolve_created_at(svc) is None


class TestCheckObjectSurfaces:

    def test_all_empty_returns_dict_with_counts(self):
        client = _MockDpClient()
        result = _check_object_surfaces(client)
        assert result is not None
        for key in ("indexes", "indexers", "data_sources", "skillsets", "synonym_maps"):
            assert result[key] == 0

    def test_non_empty_required_returns_none(self):
        for surface in ("indexes", "indexers", "data_sources", "skillsets", "synonym_maps"):
            client = _MockDpClient(non_empty_required=surface)
            assert _check_object_surfaces(client) is None, f"expected None for non-empty {surface}"

    def test_required_method_missing_returns_none(self):
        class _MissingIndexers:
            def list_indexes(self):
                return []

            def list_data_source_connections(self):
                return []

            def list_skillsets(self):
                return []

            def list_synonym_maps(self):
                return []

            # no list_indexers

        assert _check_object_surfaces(_MissingIndexers()) is None

    def test_required_raises_returns_none(self):
        client = _MockDpClient(fail_required="skillsets")
        assert _check_object_surfaces(client) is None

    def test_non_empty_optional_returns_none(self):
        for surface in ("aliases", "knowledge_sources", "agents"):
            client = _MockDpClient(non_empty_optional=surface)
            assert _check_object_surfaces(client) is None, f"expected None for non-empty {surface}"

    def test_optional_method_missing_omitted_from_counts(self):
        class _NoOptional:
            def list_indexes(self):
                return []

            def list_indexers(self):
                return []

            def list_data_source_connections(self):
                return []

            def list_skillsets(self):
                return []

            def list_synonym_maps(self):
                return []

        result = _check_object_surfaces(_NoOptional())
        assert result is not None
        assert "aliases" not in result
        assert "knowledge_sources" not in result
        assert "agents" not in result

    def test_optional_raises_omitted_from_counts(self):
        client = _MockDpClient(fail_optional="aliases")
        result = _check_object_surfaces(client)
        assert result is not None
        assert "aliases" not in result

    def test_optional_empty_included_in_counts(self):
        client = _MockDpClient()
        result = _check_object_surfaces(client)
        assert result is not None
        for key in ("aliases", "knowledge_sources", "agents"):
            assert result[key] == 0


class TestEvaluateMetric:
    """Unit tests for _evaluate_metric with a fixed window for determinism."""

    def _zero_mon(self, agg_attr: str, n: int = _WINDOW_DAYS):
        dps = _make_datapoints(agg_attr, 0.0, n, window_start=_UNIT_WINDOW_START)
        response = _make_metric_response(dps)
        return SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))

    def _active_mon(self, agg_attr: str):
        dps = _make_datapoints(agg_attr, 5.0, _WINDOW_DAYS, window_start=_UNIT_WINDOW_START)
        response = _make_metric_response(dps)
        return SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))

    def test_zero_average_returns_zero(self):
        mon = self._zero_mon("average")
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.ZERO

    def test_active_average_returns_active(self):
        mon = self._active_mon("average")
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.ACTIVE

    def test_zero_total_returns_zero(self):
        mon = self._zero_mon("total")
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "DocumentsProcessedCount",
            "Total",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.ZERO

    def test_active_total_returns_active(self):
        mon = self._active_mon("total")
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "DocumentsProcessedCount",
            "Total",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.ACTIVE

    def test_insufficient_coverage_returns_unknown(self):
        # Only 50 of 90 expected buckets -> 55% < 95%
        mon = self._zero_mon("average", n=50)
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_no_timeseries_returns_unknown(self):
        response = _make_no_timeseries_response()
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_empty_value_returns_unknown(self):
        response = _make_empty_value_response()
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_query_exception_returns_unknown(self):
        def _raise(*a, **kw):
            raise RuntimeError("timeout")

        mon = SimpleNamespace(metrics=SimpleNamespace(list=_raise))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_timestamp_none_returns_unknown(self):
        # Any None timestamp -> fail-closed -> UNKNOWN
        dps = _make_datapoints("average", 0.0, _WINDOW_DAYS, window_start=_UNIT_WINDOW_START)
        dps[10] = SimpleNamespace(timestamp=None, average=0.0, total=None, maximum=None)
        response = _make_metric_response(dps)
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_timestamp_not_datetime_returns_unknown(self):
        dps = _make_datapoints("average", 0.0, _WINDOW_DAYS, window_start=_UNIT_WINDOW_START)
        dps[0] = SimpleNamespace(
            timestamp="2024-01-01T00:00:00Z", average=0.0, total=None, maximum=None
        )
        response = _make_metric_response(dps)
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_datapoints_outside_window_filtered(self):
        # Generate 90 datapoints fully outside the window -> 0 observed buckets -> UNKNOWN
        future_start = _UNIT_WINDOW_END + timedelta(days=10)
        dps = _make_datapoints("average", 0.0, _WINDOW_DAYS, window_start=future_start)
        response = _make_metric_response(dps)
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_exact_coverage_threshold_passes(self):
        # Exactly 86 buckets (ceil(90 * 0.95)) -> exactly at threshold -> ZERO
        dps = _make_datapoints("average", 0.0, _MIN_BUCKETS, window_start=_UNIT_WINDOW_START)
        response = _make_metric_response(dps)
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.ZERO

    def test_one_below_coverage_threshold_unknown(self):
        # 85 buckets -> 85/90 = 94.4% < 95%
        dps = _make_datapoints("average", 0.0, _MIN_BUCKETS - 1, window_start=_UNIT_WINDOW_START)
        response = _make_metric_response(dps)
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_no_aggregation_value_reduces_coverage(self):
        # Datapoints with all None agg values don't contribute to bucket coverage
        dps = []
        for i in range(_WINDOW_DAYS):
            ts = _UNIT_WINDOW_START + timedelta(days=i, hours=1)
            # Only first 50 have real values; rest have None -> reduces observed to 50
            val = 0.0 if i < 50 else None
            dps.append(SimpleNamespace(timestamp=ts, average=val, total=None, maximum=None))
        response = _make_metric_response(dps)
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_no_interval_parameter_sent(self):
        """interval= must NOT be passed to Azure Monitor (spec 9.5.2 source-bucket granularity)."""
        captured: dict = {}

        def _list(*args, **kwargs):
            captured.update(kwargs)
            return _make_metric_response(
                _make_datapoints("average", 0.0, _WINDOW_DAYS, window_start=_UNIT_WINDOW_START)
            )

        mon = SimpleNamespace(metrics=SimpleNamespace(list=_list))
        _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert "interval" not in captured

    def test_non_numeric_aggregation_string_returns_unknown(self):
        """Non-numeric aggregation value -> fail-closed -> UNKNOWN (spec 9.5.6 unusable shape)."""
        dps = _make_datapoints("average", 0.0, _WINDOW_DAYS, window_start=_UNIT_WINDOW_START)
        dps[5] = SimpleNamespace(
            timestamp=_UNIT_WINDOW_START + timedelta(days=5, hours=1),
            average="N/A",
            total=None,
            maximum=None,
        )
        response = _make_metric_response(dps)
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_non_numeric_aggregation_dict_returns_unknown(self):
        dps = _make_datapoints("total", 0.0, _WINDOW_DAYS, window_start=_UNIT_WINDOW_START)
        dps[0] = SimpleNamespace(
            timestamp=_UNIT_WINDOW_START + timedelta(hours=1),
            total={"value": 5},
            average=None,
            maximum=None,
        )
        response = _make_metric_response(dps)
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "DocumentsProcessedCount",
            "Total",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_non_iterable_timeseries_returns_unknown(self):
        """timeseries attribute is not None but not iterable -> TypeError -> UNKNOWN."""
        metric = SimpleNamespace(timeseries=42)  # int is not iterable
        response = SimpleNamespace(value=[metric])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.UNKNOWN

    def test_non_iterable_data_returns_unknown(self):
        """ts.data attribute is not None but not iterable -> TypeError -> UNKNOWN."""
        ts_obj = SimpleNamespace(data="malformed")  # string iteration would give characters
        metric = SimpleNamespace(timeseries=[ts_obj])
        response = SimpleNamespace(value=[metric])
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        # Each character in "malformed" has no .timestamp attribute -> AttributeError -> UNKNOWN
        assert result == _MetricResult.UNKNOWN

    def test_subhourly_source_buckets_detect_activity(self):
        """Multiple source buckets per UTC day: any positive bucket makes the day ACTIVE."""
        # Simulate hourly data: 24 buckets per day; one bucket has a spike
        dps = []
        for day in range(_WINDOW_DAYS):
            for hour in range(24):
                ts = _UNIT_WINDOW_START + timedelta(days=day, hours=hour)
                # Day 5, hour 3: tiny spike that daily averaging could dilute toward 0
                val = 0.001 if (day == 5 and hour == 3) else 0.0
                dps.append(SimpleNamespace(timestamp=ts, average=val, total=None, maximum=None))
        response = _make_metric_response(dps)
        mon = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: response))
        result = _evaluate_metric(
            mon,
            _SVC_ID,
            "SearchQueriesPerSecond",
            "Average",
            _UNIT_WINDOW_START,
            _UNIT_WINDOW_END,
        )
        assert result == _MetricResult.ACTIVE


class TestRuleMetadata:

    def test_rule_id(self):
        assert RULE_METADATA["id"] == "azure.ai_search.idle"

    def test_category(self):
        assert RULE_METADATA["category"] == "ai"

    def test_service(self):
        assert RULE_METADATA["service"] == "search"

    def test_cost_impact(self):
        assert RULE_METADATA["cost_impact"] == "high"
