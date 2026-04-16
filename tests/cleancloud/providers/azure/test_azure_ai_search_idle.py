from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.ai_search_idle import (
    RULE_METADATA,
    find_idle_ai_search_services,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_service(
    name="test-search",
    sku_name="standard",
    location="eastus",
    age_days=30,
    replica_count=1,
    partition_count=1,
    rg="rg-search",
):
    svc_id = (
        f"/subscriptions/sub-123/resourceGroups/{rg}"
        f"/providers/Microsoft.Search/searchServices/{name}"
    )
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=age_days) if age_days is not None else None
    system_data = SimpleNamespace(created_at=created_at) if created_at is not None else None
    return SimpleNamespace(
        id=svc_id,
        name=name,
        sku=SimpleNamespace(name=sku_name),
        location=location,
        replica_count=replica_count,
        partition_count=partition_count,
        system_data=system_data,
    )


def _make_average_metric_response(average: float) -> SimpleNamespace:
    """Azure Monitor response for SearchQueriesPerSecond (Average)."""
    dp = SimpleNamespace(average=average)
    ts = SimpleNamespace(data=[dp])
    metric = SimpleNamespace(timeseries=[ts])
    return SimpleNamespace(value=[metric])


def _make_total_metric_response(total: float) -> SimpleNamespace:
    """Azure Monitor response for TotalSearchRequestCount (Total)."""
    dp = SimpleNamespace(total=total)
    ts = SimpleNamespace(data=[dp])
    metric = SimpleNamespace(timeseries=[ts])
    return SimpleNamespace(value=[metric])


def _make_empty_metric_response() -> SimpleNamespace:
    return SimpleNamespace(value=[])


def _make_no_timeseries_response() -> SimpleNamespace:
    """Metric returned but no timeseries data."""
    metric = SimpleNamespace(timeseries=[])
    return SimpleNamespace(value=[metric])


def _make_clients(service, *, avg_response=None, total_response=None):
    """
    avg_response   — returned for SearchQueriesPerSecond calls (default: zero-average)
    total_response — returned for TotalSearchRequestCount calls (default: empty)
    """
    if avg_response is None:
        avg_response = _make_average_metric_response(0.0)
    if total_response is None:
        total_response = _make_empty_metric_response()

    call_log: list[str] = []

    def _metrics_list(*args, **kwargs):
        name = kwargs.get("metricnames", "")
        call_log.append(name)
        if name == "SearchQueriesPerSecond":
            return avg_response
        return total_response

    search_client = SimpleNamespace(
        services=SimpleNamespace(list_by_subscription=lambda: [service])
    )
    monitor_client = SimpleNamespace(metrics=SimpleNamespace(list=_metrics_list))
    monitor_client._call_log = call_log
    return search_client, monitor_client


def _call(search_client, monitor_client, *, idle_days=30, region_filter=None):
    return find_idle_ai_search_services(
        subscription_id="sub-123",
        credential=None,
        client=search_client,
        monitor_client=monitor_client,
        idle_days=idle_days,
        region_filter=region_filter,
    )


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_service_detected():
    """Standard service with zero queries → finding produced."""
    svc = _make_service(age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert len(findings) == 1
    assert findings[0].rule_id == "azure.ai_search.idle"


def test_active_service_skipped():
    """Service with non-zero average queries → no finding."""
    svc = _make_service(age_days=30)
    sc, mon = _make_clients(svc, avg_response=_make_average_metric_response(5.0))
    findings = _call(sc, mon)
    assert findings == []


def test_no_services_returns_empty():
    sc = SimpleNamespace(services=SimpleNamespace(list_by_subscription=lambda: []))
    mon = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_average_metric_response(0.0))
    )
    findings = _call(sc, mon)
    assert findings == []


def test_service_with_no_id_skipped():
    """svc.id = None must be skipped before the monitor call to avoid SDK errors."""
    svc = _make_service(age_days=30)
    svc.id = None
    sc, mon = _make_clients(svc)
    assert _call(sc, mon) == []


# ---------------------------------------------------------------------------
# SKU normalization
# ---------------------------------------------------------------------------


def test_normalize_sku_camel_case_storage_optimized():
    """SDK may return 'StorageOptimizedL1' — should normalize to 'storage_optimized_l1'."""
    from cleancloud.providers.azure.rules.ai_search_idle import _normalize_sku

    assert _normalize_sku("StorageOptimizedL1") == "storage_optimized_l1"
    assert _normalize_sku("StorageOptimizedL2") == "storage_optimized_l2"
    assert _normalize_sku("storage_optimized_l1") == "storage_optimized_l1"
    assert _normalize_sku("Standard") == "standard"
    assert _normalize_sku("Standard2") == "standard2"
    assert _normalize_sku("") == ""


def test_storage_optimized_l1_camelcase_detected():
    """SDK returns 'StorageOptimizedL1' → normalizes → finding produced."""
    svc = _make_service(sku_name="StorageOptimizedL1", age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert len(findings) == 1
    assert findings[0].details["sku"] == "storage_optimized_l1"


# ---------------------------------------------------------------------------
# SKU filtering
# ---------------------------------------------------------------------------


def test_basic_sku_skipped():
    """Basic SKU is not in _WATCHED_SKUS → skipped regardless of traffic."""
    svc = _make_service(sku_name="basic", age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings == []


def test_standard_sku_included():
    svc = _make_service(sku_name="standard", age_days=30)
    sc, mon = _make_clients(svc)
    assert len(_call(sc, mon)) == 1


def test_standard2_sku_included():
    svc = _make_service(sku_name="standard2", age_days=30)
    sc, mon = _make_clients(svc)
    assert len(_call(sc, mon)) == 1


def test_storage_optimized_l1_included():
    svc = _make_service(sku_name="storage_optimized_l1", age_days=30)
    sc, mon = _make_clients(svc)
    assert len(_call(sc, mon)) == 1


def test_storage_optimized_l2_included():
    svc = _make_service(sku_name="storage_optimized_l2", age_days=30)
    sc, mon = _make_clients(svc)
    assert len(_call(sc, mon)) == 1


def test_free_sku_skipped():
    svc = _make_service(sku_name="free", age_days=30)
    sc, mon = _make_clients(svc)
    assert _call(sc, mon) == []


# ---------------------------------------------------------------------------
# Age filtering
# ---------------------------------------------------------------------------


def test_young_service_skipped():
    """Service younger than idle_days // 2 → skipped."""
    svc = _make_service(age_days=10)  # 10 < 30//2=15
    sc, mon = _make_clients(svc)
    assert _call(sc, mon) == []


def test_service_at_half_threshold_skipped():
    """age_days == idle_days // 2 - 1 → skipped."""
    svc = _make_service(age_days=14)  # 14 < 15
    sc, mon = _make_clients(svc)
    assert _call(sc, mon) == []


def test_service_at_half_threshold_still_below_confidence_gate():
    """age_days == idle_days // 2 passes the age gate but is < 75% of idle_days → no finding."""
    svc = _make_service(age_days=15)  # passes age gate (15 >= 15) but 15 < ceil(30*0.75)=23
    sc, mon = _make_clients(svc)
    assert _call(sc, mon) == []


def test_effective_window_capped_to_age():
    """effective_window = min(idle_days, age_days) when age < idle_days."""
    svc = _make_service(age_days=25)  # 25 >= ceil(30*0.75)=23, but 25 < 30 → effective_window=25
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert len(findings) == 1
    assert findings[0].details["age_days"] == 25


def test_no_creation_time_uses_full_window():
    """No system_data → age_days=None, effective_window=idle_days, still detects."""
    svc = _make_service(age_days=None)
    svc.system_data = None
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert len(findings) == 1
    assert findings[0].details["age_days"] is None


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence_age_ge_idle_days():
    """age >= idle_days with zero metric → HIGH confidence."""
    svc = _make_service(age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon, idle_days=30)
    assert findings[0].confidence.value == "high"


def test_medium_confidence_at_75_percent_age():
    """age >= 75% of idle_days but < idle_days → MEDIUM confidence."""
    svc = _make_service(age_days=23)  # ceil(30*0.75)=23, age<30
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon, idle_days=30)
    assert findings[0].confidence.value == "medium"


def test_below_75_percent_age_skipped():
    """age < 75% of idle_days → no finding (insufficient evidence)."""
    svc = _make_service(age_days=22)  # 22 < ceil(30*0.75)=23
    sc, mon = _make_clients(svc)
    assert _call(sc, mon, idle_days=30) == []


def test_medium_confidence_unknown_age():
    """No creation time but metric shows zero → MEDIUM confidence."""
    svc = _make_service(age_days=None)
    svc.system_data = None
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].confidence.value == "medium"


# ---------------------------------------------------------------------------
# Age-only fallback (no metric data)
# ---------------------------------------------------------------------------


def test_age_only_fallback_when_no_timeseries():
    """Both metrics return no data; age >= idle_days*2 → LOW confidence, age_only signal."""
    svc = _make_service(age_days=62)  # >= 30*2=60
    empty = _make_empty_metric_response()
    sc, mon = _make_clients(svc, avg_response=empty, total_response=empty)
    findings = _call(sc, mon, idle_days=30)
    assert len(findings) == 1
    assert findings[0].confidence.value == "low"
    assert findings[0].details["idle_signal"] == "age_only"
    assert findings[0].details["idle_metric"] == "none"


def test_age_only_fallback_requires_2x_idle_days():
    """age < idle_days*2 with no data → no finding."""
    svc = _make_service(age_days=59)
    empty = _make_empty_metric_response()
    sc, mon = _make_clients(svc, avg_response=empty, total_response=empty)
    assert _call(sc, mon, idle_days=30) == []


def test_all_metric_calls_fail_returns_none():
    """Both metrics raise non-permission exceptions → no finding (returns None from helper)."""
    svc = _make_service(age_days=30)

    def _raise(*a, **kw):
        raise RuntimeError("timeout")

    sc = SimpleNamespace(services=SimpleNamespace(list_by_subscription=lambda: [svc]))
    mon = SimpleNamespace(metrics=SimpleNamespace(list=_raise))
    assert _call(sc, mon) == []


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------


def test_medium_risk_for_low_cost():
    """standard × 1 replica × 1 partition = $261 < $1000 → MEDIUM risk."""
    svc = _make_service(sku_name="standard", replica_count=1, partition_count=1, age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].risk.value == "medium"


def test_high_risk_for_high_cost():
    """standard3 × 1 replica × 1 partition = $1047 >= $1000 → HIGH risk."""
    svc = _make_service(sku_name="standard3", replica_count=1, partition_count=1, age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].risk.value == "high"


def test_high_risk_from_replicas():
    """standard × 4 replicas × 1 partition = $1044 >= $1000 → HIGH risk."""
    svc = _make_service(sku_name="standard", replica_count=4, partition_count=1, age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].risk.value == "high"


def test_high_risk_from_partitions():
    """standard × 1 replica × 4 partitions = $1044 >= $1000 → HIGH risk."""
    svc = _make_service(sku_name="standard", replica_count=1, partition_count=4, age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].risk.value == "high"


def test_critical_risk_for_very_high_cost():
    """storage_optimized_l2 × 1 × 1 = $4028 >= $3000 → CRITICAL risk."""
    svc = _make_service(sku_name="storage_optimized_l2", replica_count=1, partition_count=1, age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].risk.value == "critical"
    assert findings[0].estimated_monthly_cost_usd == pytest.approx(4028.0)


def test_critical_risk_threshold_boundary():
    """storage_optimized_l1 × 2 × 1 = $4028 >= $3000 → CRITICAL."""
    svc = _make_service(sku_name="storage_optimized_l1", replica_count=2, partition_count=1, age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].risk.value == "critical"


# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------


def test_known_sku_cost_standard():
    """standard × 2 replicas × 2 partitions = 261 * 4 = $1044/month."""
    svc = _make_service(sku_name="standard", replica_count=2, partition_count=2, age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].estimated_monthly_cost_usd == pytest.approx(1044.0)


def test_known_sku_cost_storage_optimized_l2():
    """storage_optimized_l2 × 1 × 1 = $4028/month."""
    svc = _make_service(sku_name="storage_optimized_l2", age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].estimated_monthly_cost_usd == pytest.approx(4028.0)


def test_cost_source_heuristic_sku_table_for_known_sku():
    svc = _make_service(sku_name="standard", age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].details["cost_source"] == "heuristic_sku_table"


# ---------------------------------------------------------------------------
# Metric fallback (SearchQueriesPerSecond → TotalSearchRequestCount)
# ---------------------------------------------------------------------------


def test_falls_back_to_total_when_avg_has_no_data():
    """First metric has no timeseries; second (Total) shows zero → idle detected."""
    svc = _make_service(age_days=30)
    sc, mon = _make_clients(
        svc,
        avg_response=_make_no_timeseries_response(),
        total_response=_make_total_metric_response(0.0),
    )
    findings = _call(sc, mon)
    assert len(findings) == 1
    assert findings[0].details["idle_signal"] == "metric_zero"


def test_active_on_second_metric_skips():
    """First metric has no data; second (Total) shows non-zero → skip."""
    svc = _make_service(age_days=30)
    sc, mon = _make_clients(
        svc,
        avg_response=_make_no_timeseries_response(),
        total_response=_make_total_metric_response(500.0),
    )
    assert _call(sc, mon) == []


def test_primary_metric_used_when_it_has_data():
    """SearchQueriesPerSecond has data → TotalSearchRequestCount not called."""
    svc = _make_service(age_days=30)
    sc, mon = _make_clients(svc, avg_response=_make_average_metric_response(0.0))
    _call(sc, mon)
    assert "SearchQueriesPerSecond" in mon._call_log
    # TotalSearchRequestCount should NOT be called when primary succeeded
    assert "TotalSearchRequestCount" not in mon._call_log


def test_fallback_metric_called_when_primary_has_no_timeseries():
    svc = _make_service(age_days=30)
    sc, mon = _make_clients(
        svc,
        avg_response=_make_no_timeseries_response(),
        total_response=_make_total_metric_response(0.0),
    )
    _call(sc, mon)
    assert "TotalSearchRequestCount" in mon._call_log


# ---------------------------------------------------------------------------
# Region filtering
# ---------------------------------------------------------------------------


def test_region_filter_excludes_other_regions():
    svc = _make_service(location="westeurope", age_days=30)
    sc, mon = _make_clients(svc)
    assert _call(sc, mon, region_filter="eastus") == []


def test_region_filter_matches_normalised():
    """Spaces/dashes in location or filter should not prevent match."""
    svc = _make_service(location="East US", age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon, region_filter="eastus")
    assert len(findings) == 1


def test_region_filter_normalises_underscores():
    """Underscores in location or filter are stripped during normalisation."""
    svc = _make_service(location="east_us", age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon, region_filter="eastus")
    assert len(findings) == 1


def test_no_region_filter_includes_all():
    svc = _make_service(location="australiaeast", age_days=30)
    sc, mon = _make_clients(svc)
    assert len(_call(sc, mon, region_filter=None)) == 1


# ---------------------------------------------------------------------------
# Permission errors
# ---------------------------------------------------------------------------


def test_monitor_403_raises_permission_error():
    svc = _make_service(age_days=30)

    def _raise(*a, **kw):
        raise Exception("403 Forbidden")

    sc = SimpleNamespace(services=SimpleNamespace(list_by_subscription=lambda: [svc]))
    mon = SimpleNamespace(metrics=SimpleNamespace(list=_raise))
    with pytest.raises(PermissionError):
        _call(sc, mon)


def test_monitor_authorization_failed_raises_permission_error():
    svc = _make_service(age_days=30)

    def _raise(*a, **kw):
        raise Exception("AuthorizationFailed: caller does not have permission")

    sc = SimpleNamespace(services=SimpleNamespace(list_by_subscription=lambda: [svc]))
    mon = SimpleNamespace(metrics=SimpleNamespace(list=_raise))
    with pytest.raises(PermissionError):
        _call(sc, mon)


def test_search_list_403_raises_permission_error():
    def _raise():
        raise Exception("403 Forbidden for search services")

    sc = SimpleNamespace(services=SimpleNamespace(list_by_subscription=_raise))
    mon = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_average_metric_response(0.0))
    )
    with pytest.raises(PermissionError):
        _call(sc, mon)


def test_search_list_authorization_failed_raises_permission_error():
    def _raise():
        raise Exception("AuthorizationFailed on searchServices")

    sc = SimpleNamespace(services=SimpleNamespace(list_by_subscription=_raise))
    mon = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_average_metric_response(0.0))
    )
    with pytest.raises(PermissionError):
        _call(sc, mon)


def test_unexpected_exception_propagates():
    def _raise():
        raise RuntimeError("disk full")

    sc = SimpleNamespace(services=SimpleNamespace(list_by_subscription=_raise))
    mon = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_average_metric_response(0.0))
    )
    with pytest.raises(RuntimeError):
        _call(sc, mon)


# ---------------------------------------------------------------------------
# idle_days clamping
# ---------------------------------------------------------------------------


def test_idle_days_clamped_to_3():
    """idle_days=1 → effective_window clamped to 3 (min effective window)."""
    svc = _make_service(age_days=None)
    svc.system_data = None
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon, idle_days=1)
    # effective_window = min(1, None) → 1 < 3, should be skipped
    # age_days is None, effective_window = idle_days=1 < 3 → skip
    assert findings == []


def test_idle_days_30_with_no_age_uses_window_30():
    svc = _make_service(age_days=None)
    svc.system_data = None
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon, idle_days=30)
    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 30


# ---------------------------------------------------------------------------
# Finding shape
# ---------------------------------------------------------------------------


def test_finding_shape_complete():
    svc = _make_service(
        name="my-search",
        sku_name="standard",
        location="eastus",
        age_days=30,
        replica_count=2,
        partition_count=1,
        rg="rg-ai",
    )
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)

    assert len(findings) == 1
    f = findings[0]
    assert f.provider == "azure"
    assert f.rule_id == "azure.ai_search.idle"
    assert f.resource_type == "azure.ai.search_service"
    assert "my-search" in f.resource_id
    assert f.region == "eastus"
    assert f.title == "Idle Azure AI Search Service: my-search"
    assert "my-search" in f.summary
    assert f.reason
    assert f.risk is not None
    assert f.confidence is not None
    assert isinstance(f.detected_at, datetime)
    assert f.evidence is not None

    d = f.details
    assert d["service_name"] == "my-search"
    assert d["resource_group"] == "rg-ai"
    assert d["sku"] == "standard"
    assert d["location"] == "eastus"
    assert d["replica_count"] == 2
    assert d["partition_count"] == 1
    assert d["age_days"] == 30
    assert d["idle_days_threshold"] == 30
    assert d["idle_signal"] in ("metric_zero", "age_only")
    assert d["idle_metric"]  # always "none" or a metric name
    assert d["estimated_monthly_cost"] == pytest.approx(522.0)  # 261 * 2 replicas
    assert d["cost_source"] == "heuristic_sku_table"


def test_resource_group_parsed_from_id():
    svc = _make_service(rg="my-rg", age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].details["resource_group"] == "my-rg"


def test_estimated_cost_in_finding():
    svc = _make_service(sku_name="standard", replica_count=1, partition_count=1, age_days=30)
    sc, mon = _make_clients(svc)
    findings = _call(sc, mon)
    assert findings[0].estimated_monthly_cost_usd == pytest.approx(261.0)


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    assert RULE_METADATA["id"] == "azure.ai_search.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "search"
    assert RULE_METADATA["cost_impact"] == "high"
