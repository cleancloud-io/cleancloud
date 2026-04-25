"""Tests for azure.aml.compute.idle rule (hardened per spec)."""

import math
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError

from cleancloud.providers.azure.rules.ai.aml_compute_idle import (
    RULE_METADATA,
    _evaluate_metric,
    _extract_resource_group,
    _MetricResult,
    _norm_location,
    _resolve_allocation_state,
    _resolve_compute_type,
    _resolve_created_at,
    _resolve_current_node_count,
    _resolve_int_field,
    _resolve_min_node_count,
    _resolve_provisioning_state,
    _resolve_str_field,
    _series_is_cluster_scoped,
    _to_detail_str,
    find_idle_aml_compute,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_workspace(name="test-workspace", rg="rg-ml"):
    ws_id = (
        f"/subscriptions/sub-123/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{name}"
    )
    return SimpleNamespace(id=ws_id, name=name)


def _make_compute(
    name="test-cluster",
    location="eastus",
    age_days=30,
    min_node_count=2,
    max_node_count=10,
    current_node_count=2,
    target_node_count=2,
    vm_size="Standard_D4_v2",
    vm_priority="Dedicated",
    compute_type="AmlCompute",
    provisioning_state="Succeeded",
    allocation_state="Steady",
    tags=None,
    rg="rg-ml",
    workspace_name="test-workspace",
):
    now = datetime.now(timezone.utc)
    created_on = now - timedelta(days=age_days) if age_days is not None else None

    scale = SimpleNamespace(
        min_node_count=min_node_count,
        max_node_count=max_node_count,
        node_idle_time_before_scale_down="PT120S",
    )
    inner = SimpleNamespace(
        allocation_state=allocation_state,
        scale_settings=scale,
        current_node_count=current_node_count,
        target_node_count=target_node_count,
        vm_size=vm_size,
        vm_priority=vm_priority,
    )
    outer = SimpleNamespace(
        compute_type=compute_type,
        provisioning_state=provisioning_state,
        created_on=created_on,
        properties=inner,
    )
    compute_id = (
        f"/subscriptions/sub-123/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices"
        f"/workspaces/{workspace_name}/computes/{name}"
    )
    return SimpleNamespace(
        id=compute_id,
        name=name,
        location=location,
        tags=tags or {},
        properties=outer,
    )


def _make_cluster_metadata(compute_name: str):
    """Build metadata_values confirming ClusterName = compute_name on a timeseries."""
    name_obj = SimpleNamespace(value="ClusterName")
    return [SimpleNamespace(name=name_obj, value=compute_name)]


def _metric_response_zero(compute_name="test-cluster"):
    """
    Metric response with ClusterName metadata, sufficient coverage, all max=0.
    Evaluates to ZERO for the given compute_name.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=14)
    first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
    expected = math.ceil((now - first_bucket).total_seconds() / 86400)

    datapoints = []
    for i in range(expected):
        noon = first_bucket + timedelta(days=i, hours=12)
        ts = max(noon, window_start + timedelta(seconds=1))
        if ts >= now:
            ts = now - timedelta(seconds=1)
        datapoints.append(SimpleNamespace(timestamp=ts, maximum=0.0))

    ts_obj = SimpleNamespace(data=datapoints, metadata_values=_make_cluster_metadata(compute_name))
    return SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])


def _metric_response_active(compute_name="test-cluster"):
    """
    Metric response with ClusterName metadata, sufficient coverage, max > 0 on day 0.
    Evaluates to ACTIVE for the given compute_name.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=14)
    first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
    expected = math.ceil((now - first_bucket).total_seconds() / 86400)

    datapoints = []
    for i in range(expected):
        noon = first_bucket + timedelta(days=i, hours=12)
        ts = max(noon, window_start + timedelta(seconds=1))
        if ts >= now:
            ts = now - timedelta(seconds=1)
        datapoints.append(SimpleNamespace(timestamp=ts, maximum=(3.0 if i == 0 else 0.0)))

    ts_obj = SimpleNamespace(data=datapoints, metadata_values=_make_cluster_metadata(compute_name))
    return SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])


def _metric_response_unknown():
    """Metric response with no datapoints -> evaluates to UNKNOWN."""
    return SimpleNamespace(value=[])


def _make_clients(workspace, computes, metric_fn=None, compute_name="test-cluster"):
    """
    Build mock ML and Monitor clients.

    When no explicit metric_fn is provided, the default produces a ZERO response
    scoped to compute_name. Pass metric_fn explicitly when the test needs non-default
    behaviour or when the compute name differs from the default.
    """
    if metric_fn is None:

        def metric_fn(*a, **kw):
            return _metric_response_zero(compute_name=compute_name)

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [workspace]),
        machine_learning_compute=SimpleNamespace(list_by_workspace=lambda rg, ws: computes),
    )
    monitor_client = SimpleNamespace(metrics=SimpleNamespace(list=metric_fn))
    return ml_client, monitor_client


def _run(workspace=None, computes=None, metric_fn=None, compute_name="test-cluster", **kwargs):
    """Convenience runner for integration tests."""
    ws = workspace or _make_workspace()
    c = computes if computes is not None else [_make_compute()]
    ml, mon = _make_clients(ws, c, metric_fn, compute_name=compute_name)
    return find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml,
        monitor_client=mon,
        **kwargs,
    )


# ===========================================================================
# Integration: TestMustEmit
# ===========================================================================


class TestMustEmit:
    def test_all_conditions_met_emits(self):
        findings = _run()
        assert len(findings) == 1

    def test_finding_rule_id(self):
        f = _run()[0]
        assert f.rule_id == "azure.aml.compute.idle"

    def test_finding_resource_type(self):
        f = _run()[0]
        assert f.resource_type == "azure.aml.compute"

    def test_finding_provider(self):
        f = _run()[0]
        assert f.provider == "azure"

    def test_confidence_always_high(self):
        f = _run()[0]
        assert f.confidence.value == "high"

    def test_risk_always_medium(self):
        f = _run()[0]
        assert f.risk.value == "medium"

    def test_estimated_cost_always_none(self):
        f = _run()[0]
        assert f.estimated_monthly_cost_usd is None

    def test_resource_id_is_original_arm_id(self):
        c = _make_compute(name="my-cluster")
        findings = _run(computes=[c], compute_name="my-cluster")
        assert findings[0].resource_id == c.id

    def test_region_is_normalized_compute_location(self):
        c = _make_compute(location="EastUS")
        findings = _run(computes=[c])
        assert findings[0].region == "eastus"

    def test_no_computes_returns_empty(self):
        assert _run(computes=[]) == []

    def test_multiple_eligible_computes_all_emitted(self):
        c1 = _make_compute(name="cluster-a", workspace_name="test-workspace")
        c2 = _make_compute(name="cluster-b", workspace_name="test-workspace")

        def metric_fn(*a, **kw):
            # Return response scoped to whichever cluster the filter asks for
            f = kw.get("filter", "")
            name = f.split("'")[1] if "'" in f else "test-cluster"
            return _metric_response_zero(compute_name=name)

        findings = _run(computes=[c1, c2], metric_fn=metric_fn)
        assert len(findings) == 2

    def test_active_metric_skips(self):
        findings = _run(metric_fn=lambda *a, **kw: _metric_response_active())
        assert findings == []

    def test_unknown_metric_skips(self):
        findings = _run(metric_fn=lambda *a, **kw: _metric_response_unknown())
        assert findings == []


# ===========================================================================
# Integration: TestIdGuard (spec 8.1)
# ===========================================================================


class TestIdGuard:
    def test_id_none_skips(self):
        c = _make_compute()
        c.id = None
        assert _run(computes=[c]) == []

    def test_id_empty_string_skips(self):
        c = _make_compute()
        c.id = ""
        assert _run(computes=[c]) == []

    def test_id_absent_skips(self):
        c = _make_compute()
        del c.id
        assert _run(computes=[c]) == []


# ===========================================================================
# Integration: TestNameGuard (spec 8.2)
# ===========================================================================


class TestNameGuard:
    def test_name_none_skips(self):
        c = _make_compute()
        c.name = None
        assert _run(computes=[c]) == []

    def test_name_empty_string_skips(self):
        c = _make_compute()
        c.name = ""
        assert _run(computes=[c]) == []

    def test_name_absent_skips(self):
        c = _make_compute()
        del c.name
        assert _run(computes=[c]) == []


# ===========================================================================
# Integration: TestWorkspaceNameGuard (spec 8.3)
# ===========================================================================


class TestWorkspaceNameGuard:
    def test_workspace_name_none_skips(self):
        ws = _make_workspace()
        ws.name = None
        assert _run(workspace=ws) == []

    def test_workspace_name_empty_skips(self):
        ws = _make_workspace()
        ws.name = ""
        assert _run(workspace=ws) == []

    def test_workspace_id_missing_resource_group_skips(self):
        ws = _make_workspace()
        ws.id = "/subscriptions/sub-123/no-rg-here"
        assert _run(workspace=ws) == []

    def test_workspace_id_none_skips(self):
        ws = _make_workspace()
        ws.id = None
        assert _run(workspace=ws) == []


# ===========================================================================
# Integration: TestRegionFilter (spec 8.4)
# ===========================================================================


class TestRegionFilter:
    def test_no_filter_emits(self):
        assert len(_run(region_filter=None)) == 1

    def test_matching_location_emits(self):
        c = _make_compute(location="eastus")
        assert len(_run(computes=[c], region_filter="eastus")) == 1

    def test_non_matching_location_skips(self):
        c = _make_compute(location="eastus")
        assert _run(computes=[c], region_filter="westeurope") == []

    def test_filter_case_insensitive_match(self):
        c = _make_compute(location="EastUS")
        assert len(_run(computes=[c], region_filter="eastus")) == 1

    def test_filter_case_insensitive_filter_value(self):
        c = _make_compute(location="eastus")
        assert len(_run(computes=[c], region_filter="EASTUS")) == 1

    def test_spaces_preserved_in_location_no_match(self):
        # "east us" != "eastus" — spaces are NOT stripped (spec 7)
        c = _make_compute(location="east us")
        assert _run(computes=[c], region_filter="eastus") == []

    def test_spaces_preserved_match_when_filter_also_has_spaces(self):
        c = _make_compute(location="east us")
        assert len(_run(computes=[c], region_filter="east us")) == 1

    def test_hyphens_preserved_no_match(self):
        c = _make_compute(location="east-us")
        assert _run(computes=[c], region_filter="eastus") == []

    def test_region_filter_on_compute_location_not_workspace_location(self):
        ws = _make_workspace()
        c = _make_compute(location="westus")
        ml, mon = _make_clients(ws, [c])
        findings = find_idle_aml_compute(
            subscription_id="sub-123",
            credential=None,
            region_filter="westus",
            client=ml,
            monitor_client=mon,
        )
        assert len(findings) == 1

    def test_region_stored_normalized_in_finding(self):
        c = _make_compute(location="WestEurope")
        findings = _run(computes=[c], region_filter="westeurope")
        assert findings[0].region == "westeurope"


# ===========================================================================
# Integration: TestComputeTypeContract (spec 8.5)
# ===========================================================================


class TestComputeTypeContract:
    def test_aml_compute_emits(self):
        c = _make_compute(compute_type="AmlCompute")
        assert len(_run(computes=[c])) == 1

    def test_compute_instance_skips(self):
        c = _make_compute(compute_type="ComputeInstance")
        assert _run(computes=[c]) == []

    def test_aks_skips(self):
        c = _make_compute(compute_type="AKS")
        assert _run(computes=[c]) == []

    def test_wrong_case_skips(self):
        c = _make_compute(compute_type="amlcompute")
        assert _run(computes=[c]) == []

    def test_none_compute_type_skips(self):
        c = _make_compute()
        c.properties.compute_type = None
        assert _run(computes=[c]) == []

    def test_conflict_sdk_raw_skips(self):
        c = _make_compute()
        c.properties.compute_type = "AmlCompute"
        c.properties.computeType = "ComputeInstance"
        assert _run(computes=[c]) == []

    def test_raw_camel_case_field_accepted(self):
        c = _make_compute()
        del c.properties.compute_type
        c.properties.computeType = "AmlCompute"
        assert len(_run(computes=[c])) == 1


# ===========================================================================
# Integration: TestProvisioningStateContract (spec 8.6)
# ===========================================================================


class TestProvisioningStateContract:
    def test_succeeded_emits(self):
        c = _make_compute(provisioning_state="Succeeded")
        assert len(_run(computes=[c])) == 1

    def test_failed_skips(self):
        c = _make_compute(provisioning_state="Failed")
        assert _run(computes=[c]) == []

    def test_creating_skips(self):
        c = _make_compute(provisioning_state="Creating")
        assert _run(computes=[c]) == []

    def test_wrong_case_skips(self):
        c = _make_compute(provisioning_state="succeeded")
        assert _run(computes=[c]) == []

    def test_none_skips(self):
        c = _make_compute()
        c.properties.provisioning_state = None
        assert _run(computes=[c]) == []

    def test_conflict_skips(self):
        c = _make_compute()
        c.properties.provisioning_state = "Succeeded"
        c.properties.provisioningState = "Failed"
        assert _run(computes=[c]) == []

    def test_raw_camel_case_accepted(self):
        c = _make_compute()
        del c.properties.provisioning_state
        c.properties.provisioningState = "Succeeded"
        assert len(_run(computes=[c])) == 1


# ===========================================================================
# Integration: TestAllocationStateContract (spec 8.7)
# ===========================================================================


class TestAllocationStateContract:
    def test_steady_emits(self):
        c = _make_compute(allocation_state="Steady")
        assert len(_run(computes=[c])) == 1

    def test_resizing_skips(self):
        c = _make_compute(allocation_state="Resizing")
        assert _run(computes=[c]) == []

    def test_scaling_skips(self):
        c = _make_compute(allocation_state="Scaling")
        assert _run(computes=[c]) == []

    def test_wrong_case_skips(self):
        c = _make_compute(allocation_state="steady")
        assert _run(computes=[c]) == []

    def test_none_skips(self):
        c = _make_compute()
        c.properties.properties.allocation_state = None
        assert _run(computes=[c]) == []

    def test_conflict_skips(self):
        c = _make_compute()
        c.properties.properties.allocation_state = "Steady"
        c.properties.properties.allocationState = "Resizing"
        assert _run(computes=[c]) == []

    def test_raw_camel_case_accepted(self):
        c = _make_compute()
        del c.properties.properties.allocation_state
        c.properties.properties.allocationState = "Steady"
        assert len(_run(computes=[c])) == 1

    def test_inner_props_absent_skips(self):
        c = _make_compute()
        c.properties.properties = None
        assert _run(computes=[c]) == []


# ===========================================================================
# Integration: TestCreatedAtContract (spec 8.8)
# ===========================================================================


class TestCreatedAtContract:
    def test_age_exactly_14_days_emits(self):
        c = _make_compute(age_days=14)
        assert len(_run(computes=[c])) == 1

    def test_age_greater_than_14_days_emits(self):
        c = _make_compute(age_days=30)
        assert len(_run(computes=[c])) == 1

    def test_age_13_days_skips(self):
        c = _make_compute(age_days=13)
        assert _run(computes=[c]) == []

    def test_age_zero_skips(self):
        c = _make_compute(age_days=0)
        assert _run(computes=[c]) == []

    def test_created_on_none_skips(self):
        c = _make_compute()
        c.properties.created_on = None
        assert _run(computes=[c]) == []

    def test_created_on_absent_skips(self):
        c = _make_compute()
        del c.properties.created_on
        assert _run(computes=[c]) == []

    def test_created_on_future_skips(self):
        c = _make_compute()
        c.properties.created_on = datetime.now(timezone.utc) + timedelta(days=1)
        assert _run(computes=[c]) == []

    def test_created_on_invalid_string_skips(self):
        c = _make_compute()
        c.properties.created_on = "not-a-date"
        assert _run(computes=[c]) == []

    def test_created_on_iso_string_parsed(self):
        now = datetime.now(timezone.utc)
        c = _make_compute()
        c.properties.created_on = (now - timedelta(days=30)).isoformat()
        assert len(_run(computes=[c])) == 1

    def test_absent_created_at_skips_no_fallback(self):
        # spec: absent created_at -> skip (no MEDIUM confidence fallback)
        c = _make_compute()
        c.properties.created_on = None
        assert _run(computes=[c]) == []

    def test_camel_case_created_on_accepted(self):
        now = datetime.now(timezone.utc)
        c = _make_compute()
        del c.properties.created_on
        c.properties.createdOn = now - timedelta(days=30)
        assert len(_run(computes=[c])) == 1


# ===========================================================================
# Integration: TestMinNodeCountContract (spec 8.9)
# ===========================================================================


class TestMinNodeCountContract:
    def test_positive_min_emits(self):
        c = _make_compute(min_node_count=1)
        assert len(_run(computes=[c])) == 1

    def test_min_node_count_zero_skips(self):
        c = _make_compute(min_node_count=0)
        assert _run(computes=[c]) == []

    def test_min_node_count_negative_skips(self):
        c = _make_compute(min_node_count=-1)
        assert _run(computes=[c]) == []

    def test_scale_settings_none_skips(self):
        c = _make_compute()
        c.properties.properties.scale_settings = None
        assert _run(computes=[c]) == []

    def test_min_node_count_none_skips(self):
        c = _make_compute()
        c.properties.properties.scale_settings.min_node_count = None
        assert _run(computes=[c]) == []

    def test_raw_scale_settings_camel_case_accepted(self):
        # scaleSettings (raw camelCase) used when scale_settings absent
        c = _make_compute()
        del c.properties.properties.scale_settings
        c.properties.properties.scaleSettings = SimpleNamespace(
            min_node_count=2, max_node_count=10, node_idle_time_before_scale_down="PT120S"
        )
        assert len(_run(computes=[c])) == 1

    def test_raw_min_node_count_camel_case_accepted(self):
        # minNodeCount (raw) used when min_node_count absent on scale_settings;
        # use current_node_count=3 so current >= raw min_node_count=3
        c = _make_compute(current_node_count=3)
        del c.properties.properties.scale_settings.min_node_count
        c.properties.properties.scale_settings.minNodeCount = 3
        assert len(_run(computes=[c])) == 1

    def test_raw_min_node_count_zero_still_skips(self):
        c = _make_compute()
        del c.properties.properties.scale_settings.min_node_count
        c.properties.properties.scale_settings.minNodeCount = 0
        assert _run(computes=[c]) == []


# ===========================================================================
# Integration: TestCurrentNodeCountContract (spec 8.10)
# ===========================================================================


class TestCurrentNodeCountContract:
    def test_current_equals_min_emits(self):
        c = _make_compute(min_node_count=2, current_node_count=2)
        assert len(_run(computes=[c])) == 1

    def test_current_exceeds_min_emits(self):
        c = _make_compute(min_node_count=2, current_node_count=5)
        assert len(_run(computes=[c])) == 1

    def test_current_zero_min_two_skips(self):
        c = _make_compute(min_node_count=2, current_node_count=0)
        assert _run(computes=[c]) == []

    def test_current_less_than_min_skips(self):
        c = _make_compute(min_node_count=3, current_node_count=2)
        assert _run(computes=[c]) == []

    def test_current_none_skips(self):
        c = _make_compute()
        c.properties.properties.current_node_count = None
        assert _run(computes=[c]) == []

    def test_current_negative_skips(self):
        c = _make_compute()
        c.properties.properties.current_node_count = -1
        assert _run(computes=[c]) == []

    def test_raw_current_node_count_camel_case_accepted(self):
        # currentNodeCount (raw) used when current_node_count absent
        c = _make_compute()
        del c.properties.properties.current_node_count
        c.properties.properties.currentNodeCount = 2
        assert len(_run(computes=[c])) == 1

    def test_raw_current_node_count_negative_skips(self):
        c = _make_compute()
        del c.properties.properties.current_node_count
        c.properties.properties.currentNodeCount = -1
        assert _run(computes=[c]) == []


# ===========================================================================
# Integration: TestMetricContract (spec 8.11-8.12, 9.3)
# ===========================================================================


class TestMetricContract:
    def test_metric_zero_emits(self):
        assert len(_run(metric_fn=lambda *a, **kw: _metric_response_zero())) == 1

    def test_metric_active_skips(self):
        assert _run(metric_fn=lambda *a, **kw: _metric_response_active()) == []

    def test_metric_unknown_skips(self):
        assert _run(metric_fn=lambda *a, **kw: _metric_response_unknown()) == []

    def test_monitor_raises_exception_skips(self):
        def _raise(*a, **kw):
            raise RuntimeError("monitor unavailable")

        assert _run(metric_fn=_raise) == []

    def test_metric_filter_uses_cluster_name_dimension(self):
        captured = {}

        def _capture(*a, **kw):
            captured.update(kw)
            return _metric_response_zero()

        _run(metric_fn=_capture)
        assert "filter" in captured
        assert "ClusterName" in captured["filter"]

    def test_metric_filter_uses_compute_name(self):
        captured = {}

        def _capture(*a, **kw):
            captured.update(kw)
            return _metric_response_zero(compute_name="my-special-cluster")

        c = _make_compute(name="my-special-cluster")
        _run(computes=[c], metric_fn=_capture)
        assert "my-special-cluster" in captured["filter"]

    def test_no_interval_parameter_passed(self):
        captured = {}

        def _capture(*a, **kw):
            captured.update(kw)
            return _metric_response_zero()

        _run(metric_fn=_capture)
        assert "interval" not in captured

    def test_metric_name_is_active_nodes(self):
        captured = {}

        def _capture(*a, **kw):
            captured.update(kw)
            return _metric_response_zero()

        _run(metric_fn=_capture)
        assert captured.get("metricnames") == "Active Nodes"

    def test_aggregation_is_maximum(self):
        captured = {}

        def _capture(*a, **kw):
            captured.update(kw)
            return _metric_response_zero()

        _run(metric_fn=_capture)
        assert captured.get("aggregation") == "Maximum"

    def test_series_without_metadata_causes_unknown(self):
        # Timeseries with no metadata_values -> not cluster-scoped -> UNKNOWN -> skip
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=14)
        first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
        expected = math.ceil((now - first_bucket).total_seconds() / 86400)

        datapoints = []
        for i in range(expected):
            noon = first_bucket + timedelta(days=i, hours=12)
            ts = max(noon, window_start + timedelta(seconds=1))
            if ts >= now:
                ts = now - timedelta(seconds=1)
            datapoints.append(SimpleNamespace(timestamp=ts, maximum=0.0))

        ts_obj = SimpleNamespace(data=datapoints)  # no metadata_values
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])

        assert _run(metric_fn=lambda *a, **kw: response) == []

    def test_series_with_wrong_cluster_name_causes_unknown(self):
        # Timeseries with ClusterName="other-cluster" != "test-cluster" -> not cluster-scoped
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=14)
        first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
        expected = math.ceil((now - first_bucket).total_seconds() / 86400)

        datapoints = []
        for i in range(expected):
            noon = first_bucket + timedelta(days=i, hours=12)
            ts = max(noon, window_start + timedelta(seconds=1))
            if ts >= now:
                ts = now - timedelta(seconds=1)
            datapoints.append(SimpleNamespace(timestamp=ts, maximum=0.0))

        ts_obj = SimpleNamespace(
            data=datapoints, metadata_values=_make_cluster_metadata("other-cluster")
        )
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])

        assert _run(metric_fn=lambda *a, **kw: response) == []

    def test_mixed_series_only_cluster_scoped_counted(self):
        # Series for target cluster (max=0) + series for another cluster (max=99).
        # Only the cluster-scoped series counts -> result is ZERO -> emit.
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=14)
        first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
        expected = math.ceil((now - first_bucket).total_seconds() / 86400)

        def _make_dps(max_val=0.0):
            dps = []
            for i in range(expected):
                noon = first_bucket + timedelta(days=i, hours=12)
                ts = max(noon, window_start + timedelta(seconds=1))
                if ts >= now:
                    ts = now - timedelta(seconds=1)
                dps.append(SimpleNamespace(timestamp=ts, maximum=max_val))
            return dps

        ts_target = SimpleNamespace(
            data=_make_dps(0.0), metadata_values=_make_cluster_metadata("test-cluster")
        )
        ts_other = SimpleNamespace(
            data=_make_dps(99.0), metadata_values=_make_cluster_metadata("other-cluster")
        )
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_target, ts_other])])

        assert len(_run(metric_fn=lambda *a, **kw: response)) == 1


# ===========================================================================
# Integration: TestFailureBehavior (spec 12)
# ===========================================================================


class TestFailureBehavior:
    def test_per_workspace_http_error_skips_workspace(self):
        ws = _make_workspace()

        def _fail(rg, ws_name):
            raise HttpResponseError("workspace compute list failed")

        ml_client = SimpleNamespace(
            workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
            machine_learning_compute=SimpleNamespace(list_by_workspace=_fail),
        )
        mon_client = SimpleNamespace(
            metrics=SimpleNamespace(list=lambda *a, **kw: _metric_response_zero())
        )
        findings = find_idle_aml_compute(
            subscription_id="sub-123", credential=None, client=ml_client, monitor_client=mon_client
        )
        assert findings == []

    def test_per_workspace_service_request_error_skips_workspace(self):
        ws = _make_workspace()

        def _fail(rg, ws_name):
            raise ServiceRequestError("network error")

        ml_client = SimpleNamespace(
            workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
            machine_learning_compute=SimpleNamespace(list_by_workspace=_fail),
        )
        mon_client = SimpleNamespace(
            metrics=SimpleNamespace(list=lambda *a, **kw: _metric_response_zero())
        )
        findings = find_idle_aml_compute(
            subscription_id="sub-123", credential=None, client=ml_client, monitor_client=mon_client
        )
        assert findings == []

    def test_good_workspace_preserved_when_other_fails(self):
        ws_good = _make_workspace(name="good-ws", rg="rg-good")
        ws_bad = _make_workspace(name="bad-ws", rg="rg-bad")
        good_compute = _make_compute(workspace_name="good-ws", rg="rg-good")

        def _compute_list(rg, ws_name):
            if ws_name == "bad-ws":
                raise HttpResponseError("bad workspace")
            return [good_compute]

        ml_client = SimpleNamespace(
            workspaces=SimpleNamespace(list_by_subscription=lambda: [ws_good, ws_bad]),
            machine_learning_compute=SimpleNamespace(list_by_workspace=_compute_list),
        )
        mon_client = SimpleNamespace(
            metrics=SimpleNamespace(list=lambda *a, **kw: _metric_response_zero())
        )
        findings = find_idle_aml_compute(
            subscription_id="sub-123", credential=None, client=ml_client, monitor_client=mon_client
        )
        assert len(findings) == 1
        assert findings[0].details["workspace_name"] == "good-ws"

    def test_workspace_list_failure_propagates(self):
        def _fail():
            raise HttpResponseError("subscription list failed")

        ml_client = SimpleNamespace(
            workspaces=SimpleNamespace(list_by_subscription=_fail),
            machine_learning_compute=SimpleNamespace(),
        )
        mon_client = SimpleNamespace()
        with pytest.raises(HttpResponseError):
            find_idle_aml_compute(
                subscription_id="sub-123",
                credential=None,
                client=ml_client,
                monitor_client=mon_client,
            )

    def test_per_compute_http_error_skips_compute_continues(self):
        """HttpResponseError during compute property access skips that compute."""

        class _FailingCompute:
            id = "/subscriptions/sub-123/resourceGroups/rg/providers/ML/workspaces/ws/computes/x"
            name = "x"
            location = "eastus"
            tags = {}

            @property
            def properties(self):
                raise HttpResponseError("compute SDK error")

        ws = _make_workspace()
        good_compute = _make_compute(name="test-cluster")
        ml_client = SimpleNamespace(
            workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
            machine_learning_compute=SimpleNamespace(
                list_by_workspace=lambda rg, ws_n: [_FailingCompute(), good_compute]
            ),
        )
        mon_client = SimpleNamespace(
            metrics=SimpleNamespace(list=lambda *a, **kw: _metric_response_zero())
        )
        findings = find_idle_aml_compute(
            subscription_id="sub-123", credential=None, client=ml_client, monitor_client=mon_client
        )
        assert len(findings) == 1
        assert findings[0].details["cluster_name"] == "test-cluster"

    def test_malformed_compute_no_properties_skips(self):
        c = _make_compute()
        del c.properties
        assert _run(computes=[c]) == []


# ===========================================================================
# Integration: TestFindingShape (spec 11)
# ===========================================================================


class TestFindingShape:
    def _finding(self):
        ws = _make_workspace(name="ws1", rg="rg1")
        c = _make_compute(
            name="cluster1",
            location="eastus",
            min_node_count=3,
            max_node_count=10,
            current_node_count=3,
            target_node_count=3,
            vm_size="Standard_D8_v3",
            vm_priority="Dedicated",
            age_days=30,
            workspace_name="ws1",
            rg="rg1",
            tags={"env": "prod"},
        )
        ml, mon = _make_clients(ws, [c], compute_name="cluster1")
        findings = find_idle_aml_compute(
            subscription_id="sub-123", credential=None, client=ml, monitor_client=mon
        )
        return findings[0]

    def test_details_cluster_name(self):
        assert self._finding().details["cluster_name"] == "cluster1"

    def test_details_workspace_name(self):
        assert self._finding().details["workspace_name"] == "ws1"

    def test_details_resource_group(self):
        assert self._finding().details["resource_group"] == "rg1"

    def test_details_subscription_id(self):
        assert self._finding().details["subscription_id"] == "sub-123"

    def test_details_vm_size(self):
        assert self._finding().details["vm_size"] == "Standard_D8_v3"

    def test_details_vm_priority(self):
        assert self._finding().details["vm_priority"] == "Dedicated"

    def test_details_min_node_count(self):
        assert self._finding().details["min_node_count"] == 3

    def test_details_max_node_count(self):
        assert self._finding().details["max_node_count"] == 10

    def test_details_current_node_count(self):
        assert self._finding().details["current_node_count"] == 3

    def test_details_target_node_count(self):
        assert self._finding().details["target_node_count"] == 3

    def test_details_allocation_state(self):
        assert self._finding().details["allocation_state"] == "Steady"

    def test_details_provisioning_state(self):
        assert self._finding().details["provisioning_state"] == "Succeeded"

    def test_details_created_at_present(self):
        assert self._finding().details["created_at"] is not None

    def test_details_idle_window_days(self):
        assert self._finding().details["idle_window_days"] == 14

    def test_details_metrics_used(self):
        assert self._finding().details["metrics_used"] == ["Active Nodes"]

    def test_details_tags(self):
        assert self._finding().details["tags"] == {"env": "prod"}

    def test_details_tags_never_none(self):
        c = _make_compute()
        c.tags = None
        findings = _run(computes=[c])
        assert findings[0].details["tags"] == {}

    def test_details_node_idle_time_present(self):
        d = self._finding().details
        assert "node_idle_time_before_scale_down" in d

    def test_details_node_idle_time_is_str_or_none(self):
        v = self._finding().details["node_idle_time_before_scale_down"]
        assert v is None or isinstance(v, str)

    def test_details_vm_priority_is_str_or_none(self):
        v = self._finding().details["vm_priority"]
        assert v is None or isinstance(v, str)

    def test_signals_used_includes_aml_compute_type(self):
        signals = " ".join(self._finding().evidence.signals_used)
        assert "AmlCompute" in signals

    def test_signals_used_includes_provisioning_succeeded(self):
        signals = " ".join(self._finding().evidence.signals_used)
        assert "Succeeded" in signals

    def test_signals_used_includes_allocation_steady(self):
        signals = " ".join(self._finding().evidence.signals_used)
        assert "Steady" in signals

    def test_signals_used_includes_age(self):
        signals = " ".join(self._finding().evidence.signals_used)
        assert "14" in signals

    def test_signals_used_includes_min_node_count(self):
        signals = " ".join(self._finding().evidence.signals_used)
        assert "min_node_count" in signals

    def test_signals_used_includes_active_nodes_metric(self):
        signals = " ".join(self._finding().evidence.signals_used)
        assert "Active Nodes" in signals

    def test_signals_not_checked_has_blind_spots(self):
        snc = self._finding().evidence.signals_not_checked
        assert len(snc) >= 3

    def test_no_gpu_risk_escalation(self):
        # Risk is always MEDIUM regardless of GPU (spec 10/11.1)
        c = _make_compute(vm_size="Standard_NC6")
        findings = _run(computes=[c])
        assert findings[0].risk.value == "medium"

    def test_no_age_confidence_degradation(self):
        # Confidence is always HIGH when all conditions are met (spec 11.1)
        c = _make_compute(age_days=14)
        findings = _run(computes=[c])
        assert findings[0].confidence.value == "high"


# ===========================================================================
# Unit: TestSeriesIsClusterScoped
# ===========================================================================


class TestSeriesIsClusterScoped:
    def _ts(self, metadata_values):
        return SimpleNamespace(metadata_values=metadata_values)

    def _mv(self, dim_name, dim_value):
        return SimpleNamespace(name=SimpleNamespace(value=dim_name), value=dim_value)

    def test_matching_cluster_name_returns_true(self):
        ts = self._ts([self._mv("ClusterName", "my-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is True

    def test_case_insensitive_dimension_key_lower(self):
        ts = self._ts([self._mv("clustername", "my-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is True

    def test_case_insensitive_dimension_key_mixed(self):
        ts = self._ts([self._mv("clusterName", "my-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is True

    def test_exact_value_match_required(self):
        # Dimension value matching is case-sensitive
        ts = self._ts([self._mv("ClusterName", "My-Cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is False

    def test_wrong_cluster_name_returns_false(self):
        ts = self._ts([self._mv("ClusterName", "other-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is False

    def test_no_metadata_values_attr_returns_false(self):
        ts = SimpleNamespace()  # no metadata_values attr
        assert _series_is_cluster_scoped(ts, "my-cluster") is False

    def test_empty_metadata_values_returns_false(self):
        ts = self._ts([])
        assert _series_is_cluster_scoped(ts, "my-cluster") is False

    def test_none_metadata_values_returns_false(self):
        ts = self._ts(None)
        assert _series_is_cluster_scoped(ts, "my-cluster") is False

    def test_non_clustername_dimension_ignored(self):
        ts = self._ts([self._mv("NodePoolName", "my-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is False

    def test_multiple_dims_one_matches(self):
        ts = self._ts(
            [
                self._mv("NodePoolName", "np1"),
                self._mv("ClusterName", "my-cluster"),
            ]
        )
        assert _series_is_cluster_scoped(ts, "my-cluster") is True

    def test_none_entry_in_metadata_list_handled_gracefully(self):
        # None as a metadata entry should not crash; subsequent entries still checked
        ts = self._ts([None, self._mv("ClusterName", "my-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is True

    def test_dim_name_not_string_skipped(self):
        ts = self._ts([SimpleNamespace(name=SimpleNamespace(value=42), value="my-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is False

    def test_dim_value_not_string_skipped(self):
        ts = self._ts([SimpleNamespace(name=SimpleNamespace(value="ClusterName"), value=None)])
        assert _series_is_cluster_scoped(ts, "my-cluster") is False

    def test_plain_string_dim_name_returns_true(self):
        # mv.name is a plain str, not a LocalizableString object
        ts = self._ts([SimpleNamespace(name="ClusterName", value="my-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is True

    def test_plain_string_dim_name_case_insensitive(self):
        ts = self._ts([SimpleNamespace(name="clustername", value="my-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is True

    def test_plain_string_dim_name_wrong_cluster(self):
        ts = self._ts([SimpleNamespace(name="ClusterName", value="other-cluster")])
        assert _series_is_cluster_scoped(ts, "my-cluster") is False


# ===========================================================================
# Unit: TestNormLocation
# ===========================================================================


class TestNormLocation:
    def test_uppercase_lowercased(self):
        assert _norm_location("EastUS") == "eastus"

    def test_spaces_preserved(self):
        assert _norm_location("East US") == "east us"

    def test_hyphens_preserved(self):
        assert _norm_location("east-us") == "east-us"

    def test_already_lowercase(self):
        assert _norm_location("eastus") == "eastus"

    def test_empty_string(self):
        assert _norm_location("") == ""

    def test_none_returns_empty(self):
        assert _norm_location(None) == ""

    def test_mixed_case_with_digits(self):
        assert _norm_location("UKSouth2") == "uksouth2"


# ===========================================================================
# Unit: TestExtractResourceGroup
# ===========================================================================


class TestExtractResourceGroup:
    def test_valid_arm_id(self):
        arm_id = "/subscriptions/sub/resourceGroups/my-rg/providers/ML/workspaces/ws"
        assert _extract_resource_group(arm_id) == "my-rg"

    def test_lowercase_resource_groups_key(self):
        arm_id = "/subscriptions/sub/resourcegroups/my-rg/providers/ML/workspaces/ws"
        assert _extract_resource_group(arm_id) == "my-rg"

    def test_mixed_case_resource_groups_key(self):
        arm_id = "/subscriptions/sub/ResourceGroups/my-rg/providers/ML"
        assert _extract_resource_group(arm_id) == "my-rg"

    def test_no_resource_group_returns_none(self):
        assert _extract_resource_group("/subscriptions/sub/providers/ML") is None

    def test_none_returns_none(self):
        assert _extract_resource_group(None) is None

    def test_empty_string_returns_none(self):
        assert _extract_resource_group("") is None


# ===========================================================================
# Unit: TestResolveStrField
# ===========================================================================


class TestResolveStrField:
    def test_sdk_val_only(self):
        obj = SimpleNamespace(snake_f="AmlCompute")
        assert _resolve_str_field(obj, "snake_f", "camelF") == "AmlCompute"

    def test_raw_val_only(self):
        obj = SimpleNamespace(camelF="AmlCompute")
        assert _resolve_str_field(obj, "snake_f", "camelF") == "AmlCompute"

    def test_both_same_returns_value(self):
        obj = SimpleNamespace(snake_f="AmlCompute", camelF="AmlCompute")
        assert _resolve_str_field(obj, "snake_f", "camelF") == "AmlCompute"

    def test_conflict_returns_none(self):
        obj = SimpleNamespace(snake_f="AmlCompute", camelF="ComputeInstance")
        assert _resolve_str_field(obj, "snake_f", "camelF") is None

    def test_both_absent_returns_none(self):
        obj = SimpleNamespace()
        assert _resolve_str_field(obj, "snake_f", "camelF") is None

    def test_non_string_returns_none(self):
        obj = SimpleNamespace(snake_f=42)
        assert _resolve_str_field(obj, "snake_f", "camelF") is None

    def test_obj_none_returns_none(self):
        assert _resolve_str_field(None, "snake_f", "camelF") is None


# ===========================================================================
# Unit: TestResolveIntField
# ===========================================================================


class TestResolveIntField:
    def test_none_obj_returns_none(self):
        assert _resolve_int_field(None, "foo", "fooBar") is None

    def test_snake_case_value(self):
        assert _resolve_int_field(SimpleNamespace(foo=5), "foo", "fooBar") == 5

    def test_camel_case_fallback(self):
        assert _resolve_int_field(SimpleNamespace(fooBar=7), "foo", "fooBar") == 7

    def test_snake_preferred_over_camel(self):
        assert _resolve_int_field(SimpleNamespace(foo=3, fooBar=99), "foo", "fooBar") == 3

    def test_none_snake_falls_through_to_camel(self):
        assert _resolve_int_field(SimpleNamespace(foo=None, fooBar=8), "foo", "fooBar") == 8

    def test_string_numeric_coerced(self):
        assert _resolve_int_field(SimpleNamespace(foo="4"), "foo", "fooBar") == 4

    def test_non_numeric_string_returns_none(self):
        assert _resolve_int_field(SimpleNamespace(foo="bad"), "foo", "fooBar") is None

    def test_both_absent_returns_none(self):
        assert _resolve_int_field(SimpleNamespace(), "foo", "fooBar") is None

    def test_zero_returned_as_zero(self):
        # _resolve_int_field does not filter by range; caller decides
        assert _resolve_int_field(SimpleNamespace(foo=0), "foo", "fooBar") == 0

    def test_negative_returned_as_negative(self):
        # caller enforces range; helper just parses
        assert _resolve_int_field(SimpleNamespace(foo=-1), "foo", "fooBar") == -1


# ===========================================================================
# Unit: TestToDetailStr
# ===========================================================================


class TestToDetailStr:
    def test_none_returns_none(self):
        assert _to_detail_str(None) is None

    def test_string_returned_unchanged(self):
        assert _to_detail_str("Dedicated") == "Dedicated"

    def test_int_stringified(self):
        assert _to_detail_str(3) == "3"

    def test_enum_like_object_uses_str(self):
        class FakeEnum:
            def __str__(self):
                return "LowPriority"

        assert _to_detail_str(FakeEnum()) == "LowPriority"

    def test_result_is_always_str(self):
        assert isinstance(_to_detail_str("PT120S"), str)
        assert isinstance(_to_detail_str(0), str)


# ===========================================================================
# Unit: TestResolveComputeType
# ===========================================================================


class TestResolveComputeType:
    def _make(self, **kwargs):
        outer = SimpleNamespace(**kwargs)
        return SimpleNamespace(properties=outer)

    def test_sdk_field(self):
        c = self._make(compute_type="AmlCompute")
        assert _resolve_compute_type(c) == "AmlCompute"

    def test_raw_camel_field(self):
        c = self._make(computeType="AmlCompute")
        assert _resolve_compute_type(c) == "AmlCompute"

    def test_conflict_returns_none(self):
        c = self._make(compute_type="AmlCompute", computeType="ComputeInstance")
        assert _resolve_compute_type(c) is None

    def test_properties_none_returns_none(self):
        c = SimpleNamespace(properties=None)
        assert _resolve_compute_type(c) is None

    def test_properties_absent_returns_none(self):
        c = SimpleNamespace()
        assert _resolve_compute_type(c) is None


# ===========================================================================
# Unit: TestResolveProvisioningState
# ===========================================================================


class TestResolveProvisioningState:
    def _make(self, **kwargs):
        return SimpleNamespace(properties=SimpleNamespace(**kwargs))

    def test_succeeded(self):
        assert (
            _resolve_provisioning_state(self._make(provisioning_state="Succeeded")) == "Succeeded"
        )

    def test_raw_field(self):
        assert _resolve_provisioning_state(self._make(provisioningState="Succeeded")) == "Succeeded"

    def test_conflict_returns_none(self):
        c = self._make(provisioning_state="Succeeded", provisioningState="Failed")
        assert _resolve_provisioning_state(c) is None

    def test_absent_returns_none(self):
        assert _resolve_provisioning_state(self._make()) is None


# ===========================================================================
# Unit: TestResolveAllocationState
# ===========================================================================


class TestResolveAllocationState:
    def _make(self, **kwargs):
        inner = SimpleNamespace(**kwargs)
        outer = SimpleNamespace(properties=inner)
        return SimpleNamespace(properties=outer)

    def test_steady(self):
        assert _resolve_allocation_state(self._make(allocation_state="Steady")) == "Steady"

    def test_raw_field(self):
        assert _resolve_allocation_state(self._make(allocationState="Steady")) == "Steady"

    def test_conflict_returns_none(self):
        c = self._make(allocation_state="Steady", allocationState="Resizing")
        assert _resolve_allocation_state(c) is None

    def test_inner_none_returns_none(self):
        outer = SimpleNamespace(properties=None)
        c = SimpleNamespace(properties=outer)
        assert _resolve_allocation_state(c) is None

    def test_outer_none_returns_none(self):
        c = SimpleNamespace(properties=None)
        assert _resolve_allocation_state(c) is None


# ===========================================================================
# Unit: TestResolveCreatedAt
# ===========================================================================


class TestResolveCreatedAt:
    def _make(self, created_on):
        return SimpleNamespace(properties=SimpleNamespace(created_on=created_on))

    def test_datetime_with_tz(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        c = self._make(ts)
        result = _resolve_created_at(c)
        assert result == ts

    def test_datetime_without_tz_assumes_utc(self):
        ts = datetime(2025, 1, 1)
        c = self._make(ts)
        result = _resolve_created_at(c)
        assert result.tzinfo is not None

    def test_iso_string(self):
        c = self._make("2025-06-01T12:00:00")
        result = _resolve_created_at(c)
        assert result is not None
        assert result.year == 2025

    def test_z_suffixed_string(self):
        c = self._make("2025-06-01T12:00:00Z")
        result = _resolve_created_at(c)
        assert result is not None

    def test_invalid_string_returns_none(self):
        c = self._make("not-a-date")
        assert _resolve_created_at(c) is None

    def test_none_returns_none(self):
        c = self._make(None)
        assert _resolve_created_at(c) is None

    def test_future_returns_none(self):
        future = datetime.now(timezone.utc) + timedelta(days=1)
        c = self._make(future)
        assert _resolve_created_at(c) is None

    def test_integer_returns_none(self):
        c = self._make(12345)
        assert _resolve_created_at(c) is None

    def test_properties_none_returns_none(self):
        c = SimpleNamespace(properties=None)
        assert _resolve_created_at(c) is None

    def test_camel_case_field_accepted(self):
        now = datetime.now(timezone.utc)
        ts = now - timedelta(days=30)
        outer = SimpleNamespace(createdOn=ts)
        c = SimpleNamespace(properties=outer)
        assert _resolve_created_at(c) == ts


# ===========================================================================
# Unit: TestResolveMinNodeCount
# ===========================================================================


class TestResolveMinNodeCount:
    def _make(self, min_node_count, scale_attr="min_node_count"):
        scale = SimpleNamespace(**{scale_attr: min_node_count})
        inner = SimpleNamespace(scale_settings=scale)
        outer = SimpleNamespace(properties=inner)
        return SimpleNamespace(properties=outer)

    def test_positive_int(self):
        assert _resolve_min_node_count(self._make(3)) == 3

    def test_one(self):
        assert _resolve_min_node_count(self._make(1)) == 1

    def test_zero_returns_none(self):
        assert _resolve_min_node_count(self._make(0)) is None

    def test_negative_returns_none(self):
        assert _resolve_min_node_count(self._make(-1)) is None

    def test_none_returns_none(self):
        assert _resolve_min_node_count(self._make(None)) is None

    def test_string_numeric_coerced(self):
        assert _resolve_min_node_count(self._make("2")) == 2

    def test_scale_settings_none_returns_none(self):
        inner = SimpleNamespace(scale_settings=None)
        outer = SimpleNamespace(properties=inner)
        c = SimpleNamespace(properties=outer)
        assert _resolve_min_node_count(c) is None

    def test_inner_none_returns_none(self):
        outer = SimpleNamespace(properties=None)
        c = SimpleNamespace(properties=outer)
        assert _resolve_min_node_count(c) is None

    def test_raw_camel_case_scale_settings_accepted(self):
        # scaleSettings (raw) accepted when scale_settings absent
        scale = SimpleNamespace(min_node_count=4)
        inner = SimpleNamespace(scaleSettings=scale)
        outer = SimpleNamespace(properties=inner)
        c = SimpleNamespace(properties=outer)
        assert _resolve_min_node_count(c) == 4

    def test_raw_min_node_count_camel_case_accepted(self):
        # minNodeCount (raw) accepted when min_node_count absent on scale_settings
        assert _resolve_min_node_count(self._make(5, scale_attr="minNodeCount")) == 5

    def test_raw_min_node_count_zero_returns_none(self):
        assert _resolve_min_node_count(self._make(0, scale_attr="minNodeCount")) is None

    def test_snake_case_preferred_over_camel(self):
        # snake_case is tried first; camelCase only as fallback
        scale = SimpleNamespace(min_node_count=2, minNodeCount=99)
        inner = SimpleNamespace(scale_settings=scale)
        outer = SimpleNamespace(properties=inner)
        c = SimpleNamespace(properties=outer)
        assert _resolve_min_node_count(c) == 2


# ===========================================================================
# Unit: TestResolveCurrentNodeCount
# ===========================================================================


class TestResolveCurrentNodeCount:
    def _make(self, current, attr="current_node_count"):
        inner = SimpleNamespace(**{attr: current})
        outer = SimpleNamespace(properties=inner)
        return SimpleNamespace(properties=outer)

    def test_positive(self):
        assert _resolve_current_node_count(self._make(5)) == 5

    def test_zero_allowed(self):
        assert _resolve_current_node_count(self._make(0)) == 0

    def test_negative_returns_none(self):
        assert _resolve_current_node_count(self._make(-1)) is None

    def test_none_returns_none(self):
        assert _resolve_current_node_count(self._make(None)) is None

    def test_string_numeric_coerced(self):
        assert _resolve_current_node_count(self._make("3")) == 3

    def test_inner_none_returns_none(self):
        outer = SimpleNamespace(properties=None)
        c = SimpleNamespace(properties=outer)
        assert _resolve_current_node_count(c) is None

    def test_raw_camel_case_accepted(self):
        assert _resolve_current_node_count(self._make(7, attr="currentNodeCount")) == 7

    def test_raw_camel_case_negative_still_none(self):
        assert _resolve_current_node_count(self._make(-2, attr="currentNodeCount")) is None

    def test_snake_case_preferred_over_camel(self):
        inner = SimpleNamespace(current_node_count=3, currentNodeCount=99)
        outer = SimpleNamespace(properties=inner)
        c = SimpleNamespace(properties=outer)
        assert _resolve_current_node_count(c) == 3


# ===========================================================================
# Unit: TestEvaluateMetric
# ===========================================================================


def _monitor_client(response_fn):
    return SimpleNamespace(metrics=SimpleNamespace(list=response_fn))


def _window():
    now = datetime.now(timezone.utc)
    return now - timedelta(days=14), now


class TestEvaluateMetric:
    _NAME = "test-cluster"

    def _zero_response(self):
        return _metric_response_zero(compute_name=self._NAME)

    def _active_response(self):
        return _metric_response_active(compute_name=self._NAME)

    def _ts_with_metadata(self, datapoints):
        """Build a timeseries with correct ClusterName metadata for self._NAME."""
        return SimpleNamespace(data=datapoints, metadata_values=_make_cluster_metadata(self._NAME))

    def test_zero_returns_zero(self):
        ws, we = _window()
        mc = _monitor_client(lambda *a, **kw: self._zero_response())
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.ZERO

    def test_active_returns_active(self):
        ws, we = _window()
        mc = _monitor_client(lambda *a, **kw: self._active_response())
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.ACTIVE

    def test_empty_value_list_returns_unknown(self):
        ws, we = _window()
        mc = _monitor_client(lambda *a, **kw: SimpleNamespace(value=[]))
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_no_value_attr_returns_unknown(self):
        ws, we = _window()
        mc = _monitor_client(lambda *a, **kw: SimpleNamespace())
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_value_none_returns_unknown(self):
        ws, we = _window()
        mc = _monitor_client(lambda *a, **kw: SimpleNamespace(value=None))
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_monitor_raises_returns_unknown(self):
        ws, we = _window()

        def _raise(*a, **kw):
            raise RuntimeError("monitor error")

        mc = _monitor_client(_raise)
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_series_without_metadata_skipped_returns_unknown(self):
        # Timeseries with no metadata_values -> not cluster-scoped -> UNKNOWN
        ws, we = _window()
        now = datetime.now(timezone.utc)
        dp = SimpleNamespace(timestamp=now - timedelta(days=1), maximum=0.0)
        ts_obj = SimpleNamespace(data=[dp])  # no metadata_values
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_series_with_wrong_cluster_name_returns_unknown(self):
        # Timeseries scoped to a different cluster -> UNKNOWN
        ws, we = _window()
        now = datetime.now(timezone.utc)
        dp = SimpleNamespace(timestamp=now - timedelta(days=1), maximum=0.0)
        ts_obj = SimpleNamespace(data=[dp], metadata_values=_make_cluster_metadata("wrong-cluster"))
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_non_numeric_maximum_returns_unknown(self):
        ws, we = _window()
        now = datetime.now(timezone.utc)
        dp = SimpleNamespace(timestamp=now - timedelta(days=1), maximum="not-a-number")
        ts_obj = self._ts_with_metadata([dp])
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_non_iterable_timeseries_returns_unknown(self):
        # timeseries is a string: characters are not cluster-scoped -> UNKNOWN
        ws, we = _window()
        metric_obj = SimpleNamespace(timeseries="malformed")
        mc = _monitor_client(lambda *a, **kw: SimpleNamespace(value=[metric_obj]))
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_none_maximum_reduces_coverage_toward_unknown(self):
        # Series is cluster-scoped but only datapoint has max=None -> no usable buckets -> UNKNOWN
        ws, we = _window()
        now = datetime.now(timezone.utc)
        dp = SimpleNamespace(timestamp=now - timedelta(days=1), maximum=None)
        ts_obj = self._ts_with_metadata([dp])
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_datapoints_outside_window_filtered(self):
        # All datapoints outside the window -> no observed buckets -> UNKNOWN
        ws, we = _window()
        now = datetime.now(timezone.utc)
        dp = SimpleNamespace(timestamp=now - timedelta(days=30), maximum=0.0)
        ts_obj = self._ts_with_metadata([dp])
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_none_timestamp_returns_unknown(self):
        ws, we = _window()
        dp = SimpleNamespace(timestamp=None, maximum=0.0)
        ts_obj = self._ts_with_metadata([dp])
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_non_datetime_timestamp_returns_unknown(self):
        ws, we = _window()
        dp = SimpleNamespace(timestamp="2025-01-01", maximum=0.0)
        ts_obj = self._ts_with_metadata([dp])
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_coverage_below_threshold_returns_unknown(self):
        # 1 bucket out of ~15 expected -> < 0.95 -> UNKNOWN
        ws, we = _window()
        now = datetime.now(timezone.utc)
        dp = SimpleNamespace(timestamp=now - timedelta(days=1), maximum=0.0)
        ts_obj = self._ts_with_metadata([dp])
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        assert _evaluate_metric(mc, "/ws/id", self._NAME, ws, we) == _MetricResult.UNKNOWN

    def test_no_interval_kwarg_sent(self):
        ws, we = _window()
        captured = {}

        def _capture(*a, **kw):
            captured.update(kw)
            return self._zero_response()

        mc = _monitor_client(_capture)
        _evaluate_metric(mc, "/ws/id", self._NAME, ws, we)
        assert "interval" not in captured

    def test_filter_kwarg_uses_cluster_name(self):
        ws, we = _window()
        captured = {}

        def _capture(*a, **kw):
            captured.update(kw)
            return self._zero_response()

        mc = _monitor_client(_capture)
        _evaluate_metric(mc, "/ws/id", self._NAME, ws, we)
        assert "ClusterName" in captured.get("filter", "")
        assert self._NAME in captured.get("filter", "")

    def test_workspace_id_passed_as_positional(self):
        ws, we = _window()
        captured_args = []

        def _capture(*a, **kw):
            captured_args.extend(a)
            return self._zero_response()

        mc = _monitor_client(_capture)
        _evaluate_metric(mc, "/workspaces/my-ws", self._NAME, ws, we)
        assert "/workspaces/my-ws" in captured_args

    def test_today_bucket_gap_does_not_cause_unknown(self):
        # Azure Monitor may not emit today's datapoint yet. The expected-bucket
        # formula excludes the current incomplete UTC day, so 14 complete
        # past days of zero data (none from today) must evaluate to ZERO, not UNKNOWN.
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=14)
        window_end = now
        first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
        midnight_today = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # One zero datapoint per complete past day; deliberately none from today.
        dps = []
        for i in range(14):
            noon = first_bucket + timedelta(days=i, hours=12)
            ts_dp = max(noon, window_start + timedelta(seconds=1))
            if ts_dp < midnight_today:
                dps.append(SimpleNamespace(timestamp=ts_dp, maximum=0.0))

        ts_obj = self._ts_with_metadata(dps)
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        result = _evaluate_metric(mc, "/ws/id", self._NAME, window_start, window_end)
        assert result == _MetricResult.ZERO

    def test_today_partial_data_does_not_mask_missing_past_day(self):
        # Today's partial-day bucket must NOT be counted toward observed coverage.
        # If it were, a today bucket + 13 past days could satisfy 14/14 coverage
        # even though one full past day is missing, producing a false ZERO emit.
        # With the fix both sides cap at last_complete_midnight: observed = 13,
        # expected = 14, coverage = 0.928 < 0.95 -> UNKNOWN.
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=14)
        window_end = now
        first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
        midnight_today = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # 13 complete past days (skip day 7 to create a gap) + one today datapoint
        dps = []
        for i in range(14):
            if i == 7:
                continue  # intentional gap in a complete past day
            noon = first_bucket + timedelta(days=i, hours=12)
            ts_dp = max(noon, window_start + timedelta(seconds=1))
            if ts_dp < midnight_today:
                dps.append(SimpleNamespace(timestamp=ts_dp, maximum=0.0))
        # Today's datapoint — should be filtered from observed, not mask the gap
        today_dp = midnight_today + timedelta(hours=1)
        if today_dp < window_end:
            dps.append(SimpleNamespace(timestamp=today_dp, maximum=0.0))

        ts_obj = self._ts_with_metadata(dps)
        mc = _monitor_client(
            lambda *a, **kw: SimpleNamespace(value=[SimpleNamespace(timeseries=[ts_obj])])
        )
        result = _evaluate_metric(mc, "/ws/id", self._NAME, window_start, window_end)
        assert result == _MetricResult.UNKNOWN


# ===========================================================================
# Unit: TestRuleMetadata
# ===========================================================================


class TestRuleMetadata:
    def test_id(self):
        assert RULE_METADATA["id"] == "azure.aml.compute.idle"

    def test_category(self):
        assert RULE_METADATA["category"] == "ai"

    def test_service(self):
        assert RULE_METADATA["service"] == "machinelearning"

    def test_cost_impact(self):
        assert RULE_METADATA["cost_impact"] == "high"
