from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cleancloud.providers.azure.rules.aml_compute_idle import find_idle_aml_compute


def _make_workspace(name="test-workspace", location="eastus", rg="rg-ml"):
    ws_id = (
        f"/subscriptions/sub-123/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{name}"
    )
    return SimpleNamespace(id=ws_id, name=name, location=location)


def _make_compute(
    name="test-cluster",
    vm_size="Standard_D4_v2",
    min_node_count=2,
    compute_type="AmlCompute",
    age_days=30,
    workspace="test-workspace",
    rg="rg-ml",
):
    compute_id = (
        f"/subscriptions/sub-123/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{workspace}/computes/{name}"
    )
    scale_settings = SimpleNamespace(min_node_count=min_node_count, max_node_count=10)
    aml_compute_props = SimpleNamespace(vm_size=vm_size, scale_settings=scale_settings)
    compute_obj = SimpleNamespace(
        compute_type=compute_type,
        properties=aml_compute_props,
    )
    now = datetime.now(timezone.utc)
    created_on = now - timedelta(days=age_days) if age_days is not None else None
    # created_on lives on AmlCompute (compute.properties), not on ComputeResource.system_data
    compute_obj.created_on = created_on
    return SimpleNamespace(
        id=compute_id,
        name=name,
        properties=compute_obj,
    )


def _make_metric_response(max_value: float = 0.0) -> SimpleNamespace:
    """Azure Monitor metrics.list() response with a single datapoint."""
    data_point = SimpleNamespace(maximum=max_value)
    timeseries = SimpleNamespace(data=[data_point])
    metric = SimpleNamespace(timeseries=[timeseries])
    return SimpleNamespace(value=[metric])


def _make_empty_metric_response() -> SimpleNamespace:
    """Azure Monitor returns no timeseries — metric never published (cluster never ran jobs)."""
    return SimpleNamespace(value=[])


def _make_clients(workspace, computes, metric_response):
    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [workspace]),
        compute=SimpleNamespace(list=lambda rg, ws_name: computes),
    )
    monitor_client = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: metric_response))
    return ml_client, monitor_client


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_cpu_cluster_detected():
    """Idle CPU cluster with min_node_count > 0 and zero active nodes should be flagged."""
    ws = _make_workspace()
    compute = _make_compute(vm_size="Standard_D4_v2", min_node_count=2, age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "azure.aml.compute.idle"
    assert f.resource_type == "azure.aml.compute"
    assert f.confidence.value == "high"
    assert f.risk.value == "medium"
    assert f.details["is_gpu"] is False
    assert f.details["vm_size"] == "Standard_D4_v2"
    assert f.details["min_node_count"] == 2
    assert f.details["age_days"] == 30


def test_idle_gpu_cluster_detected_high_risk():
    """Idle GPU cluster with min_node_count >= 2 should be flagged as HIGH risk."""
    ws = _make_workspace()
    compute = _make_compute(vm_size="Standard_NC6", min_node_count=2, age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.risk.value == "high"
    assert f.details["is_gpu"] is True
    assert f.details["vm_size"] == "Standard_NC6"
    assert f.estimated_monthly_cost_usd == 648.0 * 2


def test_idle_gpu_cluster_single_node_medium_risk():
    """Idle GPU cluster with min_node_count=1 should be MEDIUM risk (may be dev/test)."""
    ws = _make_workspace()
    compute = _make_compute(vm_size="Standard_NC6", min_node_count=1, age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.risk.value == "medium"
    assert f.details["is_gpu"] is True


def test_active_cluster_skipped():
    """Cluster with active nodes should NOT be flagged."""
    ws = _make_workspace()
    compute = _make_compute(age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(3.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_zero_min_node_count_skipped():
    """Cluster with min_node_count=0 should NOT be flagged — scales to zero, no idle cost."""
    ws = _make_workspace()
    compute = _make_compute(min_node_count=0, age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_non_aml_compute_skipped():
    """Compute instances that are not AmlCompute type (e.g. AKS, ComputeInstance) should be skipped."""
    ws = _make_workspace()
    compute = _make_compute(compute_type="ComputeInstance", age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_young_cluster_skipped():
    """Cluster younger than minimum threshold should NOT be flagged."""
    ws = _make_workspace()
    compute = _make_compute(age_days=3)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_no_computes_returns_empty():
    """No compute targets should return empty findings."""
    ws = _make_workspace()
    ml_client, mon_client = _make_clients(ws, [], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


# ---------------------------------------------------------------------------
# Empty metric series (cluster never ran any jobs)
# ---------------------------------------------------------------------------


def test_empty_metric_series_assumes_active():
    """Old cluster with no Azure Monitor data at all is assumed active (conservative).

    Without a dimension-filtered timeseries confirming zero activity, we cannot
    safely conclude the cluster is idle — metrics may simply not be published yet
    or the metric name may have changed. Skip to avoid false positives.
    """
    ws = _make_workspace()
    compute = _make_compute(age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_empty_metric_response())

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


# ---------------------------------------------------------------------------
# Effective window (age vs idle period)
# ---------------------------------------------------------------------------


def test_effective_window_capped_to_age():
    """For a cluster younger than days_idle, the effective window is capped to age."""
    ws = _make_workspace()
    compute = _make_compute(age_days=12)  # age < days_idle=14
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].details["idle_window_days"] == 12
    assert findings[0].details["idle_days_threshold"] == 14


def test_very_small_effective_window_skipped():
    """Effective window < 3 days is too narrow for a reliable conclusion.

    Setup: days_idle=2, age=8
    - Age guard: 8 >= max(2//2=1, 7) = 7 → passes
    - effective_window = min(2, 8) = 2 < 3 → skipped
    """
    ws = _make_workspace()
    compute = _make_compute(age_days=8)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
        idle_days=2,
    )

    assert findings == []


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence_for_old_cluster():
    """Cluster older than days_idle should be HIGH confidence."""
    ws = _make_workspace()
    compute = _make_compute(age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings[0].confidence.value == "high"


def test_medium_confidence_for_borderline_age():
    """Cluster at 75% of idle threshold should be MEDIUM confidence."""
    ws = _make_workspace()
    # age=11, int(14 * 0.75)=10 → 11 >= 10 → MEDIUM
    compute = _make_compute(age_days=11)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_borderline_age_below_threshold_skipped():
    """Cluster below the 75% confidence threshold should be skipped."""
    ws = _make_workspace()
    # age=8, int(14 * 0.75)=10 → 8 < 10 → skip
    compute = _make_compute(age_days=8)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_medium_confidence_when_no_creation_time():
    """Cluster with unknown age should be MEDIUM confidence — can't rule out recent creation."""
    ws = _make_workspace()
    compute = _make_compute(age_days=None)  # no creation time — created_on is None on properties
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"
    assert findings[0].details["age_days"] == "unknown"


# ---------------------------------------------------------------------------
# GPU family detection and cost estimation
# ---------------------------------------------------------------------------


def test_nc_series_detected_as_gpu():
    ws = _make_workspace()
    compute = _make_compute(vm_size="Standard_NC12", min_node_count=2, age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings[0].details["is_gpu"] is True
    assert findings[0].risk.value == "high"
    assert findings[0].estimated_monthly_cost_usd == 1_296.0 * 2


def test_nd_series_detected_as_gpu():
    """ND-series (deep learning) should be classified as GPU-class."""
    ws = _make_workspace()
    compute = _make_compute(vm_size="Standard_ND40rs_v2", min_node_count=1, age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings[0].details["is_gpu"] is True
    assert findings[0].estimated_monthly_cost_usd == 15_862.0


def test_cost_scales_with_min_node_count():
    """Cost estimate should be min_node_count × monthly cost per node."""
    ws = _make_workspace()
    # Standard_D4_v2 = $259/month, min_node_count=3 → $777/month
    compute = _make_compute(vm_size="Standard_D4_v2", min_node_count=3, age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings[0].estimated_monthly_cost_usd == 259.0 * 3


def test_unknown_vm_size_uses_default_cost():
    """Unknown VM size should use the default cost estimate, not crash."""
    ws = _make_workspace()
    compute = _make_compute(vm_size="Standard_FutureSeries_v99", min_node_count=2, age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == 200.0 * 2  # default × min_nodes


# ---------------------------------------------------------------------------
# Region filter
# ---------------------------------------------------------------------------


def test_region_filter_excludes_other_regions():
    """Clusters in a different location than region_filter should be skipped."""
    ws = _make_workspace(location="westeurope")
    compute = _make_compute(age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_region_filter_matches_normalised():
    """Region filter should match after normalisation (spaces/dashes stripped)."""
    ws = _make_workspace(location="East US")  # raw Azure location name
    compute = _make_compute(age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    # Original location string preserved in finding, not normalised
    assert findings[0].region == "East US"


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_monitor_failure_treated_as_active():
    """If Azure Monitor metrics fail, cluster should NOT be flagged (avoid false positives)."""

    def _raise(*args, **kwargs):
        raise RuntimeError("Monitor unavailable")

    ws = _make_workspace()
    compute = _make_compute(age_days=30)
    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
        compute=SimpleNamespace(list=lambda rg, ws_name: [compute]),
    )
    mon_client = SimpleNamespace(metrics=SimpleNamespace(list=_raise))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_permission_error_raised():
    """AuthorizationFailed should raise PermissionError with required permission names."""

    def _raise(*args, **kwargs):
        raise Exception("AuthorizationFailed: The client does not have authorization")

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=_raise),
    )
    mon_client = SimpleNamespace()

    try:
        find_idle_aml_compute(
            subscription_id="sub-123",
            credential=None,
            client=ml_client,
            monitor_client=mon_client,
        )
        assert False, "Expected PermissionError"
    except PermissionError as e:
        assert "Microsoft.MachineLearningServices/workspaces/read" in str(e)


# ---------------------------------------------------------------------------
# Metric fallback strategy
# ---------------------------------------------------------------------------


def test_idle_signal_includes_metric_name():
    """The winning metric name should appear in the evidence signal for debuggability."""
    ws = _make_workspace()
    compute = _make_compute(age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_metric_response(0.0))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "Active Nodes" in signal_text  # metric name surfaced for debuggability


def test_fallback_to_nodecount_when_active_nodes_unavailable():
    """If 'Active Nodes' returns no dimension-filtered timeseries, 'NodeCount' is tried.

    NodeCount with ComputeName filter returning all-zero is a reliable idle signal.
    """
    ws = _make_workspace()
    compute = _make_compute(age_days=30)

    call_args = []

    def _mock_metrics_list(*args, **kwargs):
        metric_name = kwargs.get("metricnames", "")
        has_filter = "filter" in kwargs
        call_args.append((metric_name, has_filter))
        if metric_name == "Active Nodes":
            return _make_empty_metric_response()  # not available (filtered or unfiltered)
        if metric_name == "NodeCount" and has_filter:
            return _make_metric_response(0.0)  # dimension-filtered zero → confirmed idle
        return _make_empty_metric_response()

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
        compute=SimpleNamespace(list=lambda rg, ws_name: [compute]),
    )
    mon_client = SimpleNamespace(metrics=SimpleNamespace(list=_mock_metrics_list))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1  # flagged via dimension-filtered NodeCount
    assert any("Active Nodes" in a[0] for a in call_args)
    assert any("NodeCount" in a[0] for a in call_args)


def test_dimension_filter_fallback_to_unfiltered():
    """If filtered query returns no timeseries, unfiltered retry should be attempted.

    Workspace-level zero is UNKNOWN (not idle) — one active cluster can hide idle ones.
    When all metrics return no reliable per-cluster signal, assume active (conservative).
    """
    ws = _make_workspace()
    compute = _make_compute(age_days=30)

    call_kwargs = []

    def _mock_metrics_list(*args, **kwargs):
        call_kwargs.append(dict(kwargs))
        if "filter" in kwargs:
            return _make_empty_metric_response()  # filter dimension not supported
        return _make_metric_response(0.0)  # unfiltered zero = unknown, not idle

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
        compute=SimpleNamespace(list=lambda rg, ws_name: [compute]),
    )
    mon_client = SimpleNamespace(metrics=SimpleNamespace(list=_mock_metrics_list))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    # Workspace-level zero is not enough — no reliable per-cluster signal → skipped
    assert findings == []
    # Verify both filtered and unfiltered calls were made
    assert any("filter" in kw for kw in call_kwargs)
    assert any("filter" not in kw for kw in call_kwargs)


def test_unfiltered_active_workspace_causes_skip():
    """If unfiltered fallback shows activity (other computes active), cluster should be skipped.

    When the dimension filter is unsupported and the unfiltered workspace query
    shows active nodes, we cannot determine if our specific cluster is idle.
    Conservative: skip (avoid false positive).
    """
    ws = _make_workspace()
    compute = _make_compute(age_days=30)

    def _mock_metrics_list(*args, **kwargs):
        if "filter" in kwargs:
            return _make_empty_metric_response()  # filter not supported
        return _make_metric_response(5.0)  # workspace-level activity detected

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
        compute=SimpleNamespace(list=lambda rg, ws_name: [compute]),
    )
    mon_client = SimpleNamespace(metrics=SimpleNamespace(list=_mock_metrics_list))

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []  # conservative: can't confirm this cluster is idle


def test_all_metrics_unavailable_assumes_active():
    """If no metric returns any timeseries at all, cluster is assumed active (conservative).

    No reliable per-cluster signal → cannot confirm idle → skip to avoid false positives.
    """
    ws = _make_workspace()
    compute = _make_compute(age_days=30)
    ml_client, mon_client = _make_clients(ws, [compute], _make_empty_metric_response())

    findings = find_idle_aml_compute(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        monitor_client=mon_client,
    )

    assert findings == []


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    """Rule must expose RULE_METADATA with correct fields."""
    from cleancloud.providers.azure.rules.aml_compute_idle import RULE_METADATA

    assert RULE_METADATA["id"] == "azure.aml.compute.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "machinelearning"
    assert RULE_METADATA["cost_impact"] == "high"
