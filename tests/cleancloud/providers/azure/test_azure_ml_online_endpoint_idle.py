from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.ml_online_endpoint_idle import find_idle_ml_online_endpoints

_SUB = "sub-123"
_WS_RG = "rg-ml"
_WS_NAME = "test-workspace"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_workspace(name=_WS_NAME, location="eastus", rg=_WS_RG):
    ws_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{name}"
    )
    return SimpleNamespace(id=ws_id, name=name, location=location, resource_group=rg)


def _make_endpoint(
    name="ep1",
    age_days=30,
    provisioning_state="Succeeded",
    rg=_WS_RG,
    ws_name=_WS_NAME,
):
    ep_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{ws_name}/onlineEndpoints/{name}"
    )
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=age_days) if age_days is not None else None
    system_data = SimpleNamespace(created_at=created_at)
    return SimpleNamespace(
        id=ep_id,
        name=name,
        provisioning_state=provisioning_state,
        system_data=system_data,
    )


def _make_deployment(instance_type=None, min_instances=None):
    """Matches azure-ai-ml ManagedOnlineDeployment: instance_type + scale_settings."""
    scale = SimpleNamespace(min_instances=min_instances) if min_instances is not None else None
    return SimpleNamespace(
        instance_type=instance_type,
        instance_count=min_instances,
        scale_settings=scale,
    )


def _make_total_metric_response(total: float = 0.0, has_timeseries: bool = True, count: int = 31):
    """Return a monitor metrics response.

    `count` controls how many datapoints are in the timeseries so the coverage
    check (seen_datapoints >= days * 0.5) is satisfied by default for any
    reasonable idle_days value.  Set has_timeseries=False for 'no data' cases.
    """
    if not has_timeseries:
        return SimpleNamespace(value=[])
    data_points = [SimpleNamespace(total=total) for _ in range(count)]
    timeseries = SimpleNamespace(data=data_points)
    metric = SimpleNamespace(timeseries=[timeseries])
    return SimpleNamespace(value=[metric])


def _make_clients(
    workspace,
    endpoints,
    metric_response=None,
    metric_fn=None,
    deployments_by_ep=None,
):
    """Build mock (ml_client, mon_client).

    The injected ml_client serves as both subscription-level (workspaces.list_by_subscription)
    and workspace-scoped (online_endpoints / online_deployments) client — matching
    the dual-mode pattern in the rule when a client is injected.
    """
    if deployments_by_ep is None:
        deployments_by_ep = {}

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [workspace]),
        online_endpoints=SimpleNamespace(list=lambda: endpoints),
        online_deployments=SimpleNamespace(list=lambda ep_name: deployments_by_ep.get(ep_name, [])),
    )
    if metric_fn is not None:
        mon_client = SimpleNamespace(
            metrics=SimpleNamespace(list=lambda *a, **kw: metric_fn(*a, **kw))
        )
    else:
        resp = metric_response if metric_response is not None else _make_total_metric_response(0.0)
        mon_client = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: resp))
    return ml_client, mon_client


def _call(client, monitor_client, **kwargs):
    return find_idle_ml_online_endpoints(
        subscription_id=_SUB,
        credential=None,
        client=client,
        monitor_client=monitor_client,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_endpoint_detected():
    """Endpoint with zero requests over the idle window should produce a finding."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "azure.ml.online_endpoint.idle"
    assert f.resource_type == "azure.ml.online_endpoint"
    assert f.provider == "azure"
    assert f.resource_id == ep.id
    assert f.region == "eastus"
    assert f.confidence.value in ("high", "medium")
    assert f.risk is not None
    assert f.details["endpoint_name"] == "ep1"
    assert f.details["workspace_name"] == _WS_NAME
    assert f.details["resource_group"] == _WS_RG


def test_active_endpoint_skipped():
    """Endpoint with non-zero requests must NOT be flagged."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep], metric_response=_make_total_metric_response(42.0))

    assert _call(ml, mon) == []


def test_no_endpoints_returns_empty():
    ws = _make_workspace()
    ml, mon = _make_clients(ws, [])
    assert _call(ml, mon) == []


def test_no_workspaces_returns_empty():
    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: []),
        online_endpoints=SimpleNamespace(list=lambda: []),
        online_deployments=SimpleNamespace(list=lambda ep_name: []),
    )
    mon_client = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_total_metric_response(0.0))
    )
    assert _call(ml_client, mon_client) == []


# ---------------------------------------------------------------------------
# Provisioning state
# ---------------------------------------------------------------------------


def test_non_succeeded_state_skipped():
    """Endpoints not in Succeeded state (e.g. Creating, Failed) must be skipped."""
    ws = _make_workspace()
    for state in ("Creating", "Deleting", "Failed", "Updating"):
        ep = _make_endpoint(age_days=30, provisioning_state=state)
        ml, mon = _make_clients(ws, [ep])
        assert _call(ml, mon) == [], f"Expected no findings for state={state}"


def test_provisioning_state_case_insensitive():
    """Provisioning state comparison must be case-insensitive (e.g. 'succeeded')."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, provisioning_state="succeeded")
    ml, mon = _make_clients(ws, [ep])
    assert len(_call(ml, mon)) == 1


def test_none_provisioning_state_skipped():
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, provisioning_state=None)
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


# ---------------------------------------------------------------------------
# Age filtering and effective window
# ---------------------------------------------------------------------------


def test_young_endpoint_skipped():
    """Endpoint younger than max(idle_days // 2, 3) days should be skipped."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=2)
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_endpoint_at_half_threshold_skipped():
    """age=3, idle_days=7: max(7//2=3, 3)=3 → age NOT < 3 → proceeds (borderline)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=3)
    ml, mon = _make_clients(ws, [ep])
    # age 3 < ceil(0.75*7)=6, so confidence ladder falls through → no finding
    assert _call(ml, mon) == []


def test_effective_window_capped_to_age():
    """For an endpoint younger than idle_days, effective_window = age_days (not idle_days)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=6)  # 6 == ceil(0.75 * 7)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["age_days"] == 6
    assert findings[0].details["idle_days_threshold"] == 7


def test_no_creation_time_uses_full_window():
    """Endpoint with unknown age should use full idle_days window and get MEDIUM confidence."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=None)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"
    assert findings[0].details["age_days"] is None


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence_age_ge_idle_days():
    """Endpoint with age >= idle_days and zero requests → HIGH confidence."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_medium_confidence_at_75_percent_age():
    """age = ceil(0.75 × idle_days), age < idle_days → MEDIUM confidence."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=6)  # ceil(0.75 * 7) = 6
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_below_75_percent_age_skipped():
    """age = 5 < ceil(0.75 * 7) = 6 → confidence ladder falls through → skipped."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=5)
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_medium_confidence_unknown_age():
    """Age unknown → MEDIUM confidence (can't rule out recent creation)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=None)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_workspace_level_signal_low_confidence():
    """Pass-2 (no EndpointName filter) zero traffic → workspace_level signal → LOW confidence."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    call_log = []

    def _mock_metrics(*args, **kwargs):
        has_filter = "filter" in kwargs
        call_log.append(has_filter)
        if has_filter:
            # Pass 1: has EndpointName filter — return no timeseries (dimension not emitted)
            return _make_total_metric_response(0.0, has_timeseries=False)
        # Pass 2: no filter — return enough zero datapoints to satisfy coverage
        return _make_total_metric_response(0.0, has_timeseries=True, count=31)

    ml, mon = _make_clients(ws, [ep], metric_fn=_mock_metrics)

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].confidence.value == "low"
    assert findings[0].details["idle_signal_scope"] == "workspace_level"


# ---------------------------------------------------------------------------
# Age-only fallback (no metric data)
# ---------------------------------------------------------------------------


def test_age_only_fallback_when_no_timeseries():
    """No timeseries returned from monitor + age >= 2× idle_days → age_only LOW finding."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=20)  # 20 >= 2 * 7 = 14
    ml, mon = _make_clients(
        ws, [ep], metric_response=_make_total_metric_response(0.0, has_timeseries=False)
    )

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].confidence.value == "low"
    assert findings[0].details["idle_signal_scope"] == "age_only"


def test_no_timeseries_young_endpoint_skipped():
    """No timeseries + age < 2× idle_days → not enough signal → skipped."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=10)  # 10 < 2 * 7 = 14
    ml, mon = _make_clients(
        ws, [ep], metric_response=_make_total_metric_response(0.0, has_timeseries=False)
    )
    assert _call(ml, mon) == []


def test_all_metric_calls_fail_skips_endpoint():
    """All monitor calls raising exceptions → None from _check_requests → endpoint skipped."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    def raise_transient(*a, **kw):
        raise RuntimeError("SDK timeout")

    ml, mon = _make_clients(ws, [ep], metric_fn=raise_transient)
    assert _call(ml, mon) == []


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------


def test_cpu_endpoint_medium_risk():
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert findings[0].risk.value == "medium"
    assert findings[0].details["is_gpu"] is False


def test_gpu_nc_series_high_risk():
    """GPU endpoint (NC series) with idle_ratio < 2.0 → HIGH risk."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=7)  # age/idle_days = 7/7 = 1.0 < 2.0
    dep = _make_deployment(instance_type="Standard_NC6", min_instances=1)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon, idle_days=7)

    assert len(findings) == 1
    assert findings[0].risk.value == "high"
    assert findings[0].details["is_gpu"] is True


def test_gpu_nd_series_detected():
    """ND-series (deep learning) must be classified as GPU."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="Standard_ND40rs_v2", min_instances=1)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon)

    assert findings[0].details["is_gpu"] is True


def test_gpu_critical_when_idle_ratio_ge_2():
    """GPU endpoint with age/idle_days >= 2.0 → CRITICAL risk."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)  # 30/7 > 2.0
    dep = _make_deployment(instance_type="Standard_NC6", min_instances=1)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon, idle_days=7)

    assert len(findings) == 1
    assert findings[0].risk.value == "critical"


def test_gpu_detection_case_insensitive():
    """GPU family check must be case-insensitive (Azure SDK returns mixed case)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="standard_nc6", min_instances=1)  # lowercase
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon)

    assert findings[0].details["is_gpu"] is True


# ---------------------------------------------------------------------------
# Scale-to-zero filtering
# ---------------------------------------------------------------------------


def test_scale_to_zero_endpoint_skipped():
    """Endpoint with min_instance_count=0 has no running instances → no cost → skip."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="Standard_NC6", min_instances=0)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    assert _call(ml, mon) == []


# ---------------------------------------------------------------------------
# Instance type and cost estimation
# ---------------------------------------------------------------------------


def test_known_sku_cost_applied():
    """Standard_NC6 → $657/month; 2 instances → $1,314/month."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="Standard_NC6", min_instances=2)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon)

    assert findings[0].estimated_monthly_cost_usd == 657.0 * 2
    assert findings[0].details["cost_source"] == "heuristic_sku_table"
    assert findings[0].details["instance_type"] == "Standard_NC6"
    assert findings[0].details["min_instance_count"] == 2


def test_unknown_sku_no_cost():
    """Unknown VM size → no cost estimate, cost_source='unknown'."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="Standard_FutureSeries_v99", min_instances=3)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon)

    assert findings[0].estimated_monthly_cost_usd is None
    assert findings[0].details["cost_source"] == "unknown"


def test_no_deployments_no_cost():
    """Endpoint with no deployments → None cost, is_gpu=False."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert findings[0].estimated_monthly_cost_usd is None
    assert findings[0].details["instance_type"] is None
    assert findings[0].details["is_gpu"] is False


def test_multiple_deployments_max_replicas_used():
    """With multiple deployments, the highest min_instance_count is used."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    deps = [
        _make_deployment(instance_type="Standard_NC6", min_instances=1),
        _make_deployment(instance_type="Standard_NC6", min_instances=3),
    ]
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": deps})

    findings = _call(ml, mon)

    assert findings[0].details["min_instance_count"] == 3
    assert findings[0].estimated_monthly_cost_usd == 657.0 * 3


def test_deployment_list_failure_still_produces_finding():
    """If deployment listing raises, finding is still produced (best-effort cost)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
        online_endpoints=SimpleNamespace(list=lambda: [ep]),
        online_deployments=SimpleNamespace(
            list=lambda ep_name: (_ for _ in ()).throw(RuntimeError("SDK error"))
        ),
    )
    mon_client = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_total_metric_response(0.0))
    )

    findings = find_idle_ml_online_endpoints(
        subscription_id=_SUB, credential=None, client=ml_client, monitor_client=mon_client
    )

    # Finding still produced, just without cost details
    assert len(findings) == 1
    assert findings[0].details["instance_type"] is None


# ---------------------------------------------------------------------------
# Resource group extraction
# ---------------------------------------------------------------------------


def test_rg_parsed_from_id_when_attribute_missing():
    """resource_group attribute missing → RG parsed from workspace ARM id."""
    ws = _make_workspace(rg="rg-from-id")
    del ws.resource_group  # force fall-through to id parsing
    ep = _make_endpoint(age_days=30, rg="rg-from-id")
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["resource_group"] == "rg-from-id"


def test_workspace_missing_resource_group_and_id_skipped():
    """Workspace with no resource_group attribute AND no parseable id is skipped."""
    ws = _make_workspace()
    ws.resource_group = None
    ws.id = None
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


# ---------------------------------------------------------------------------
# Region filter
# ---------------------------------------------------------------------------


def test_region_filter_excludes_other_regions():
    ws = _make_workspace(location="westeurope")
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])

    assert _call(ml, mon, region_filter="eastus") == []


def test_region_filter_matches_workspace_normalised():
    """'East US' (with space) should match region_filter='eastus'."""
    ws = _make_workspace(location="East US")
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon, region_filter="eastus")

    assert len(findings) == 1
    assert findings[0].region == "East US"


def test_no_region_filter_includes_all_regions():
    ws = _make_workspace(location="westeurope")
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])

    assert len(_call(ml, mon)) == 1


# ---------------------------------------------------------------------------
# Metric fallback (RequestCount → ModelEndpointRequests)
# ---------------------------------------------------------------------------


def test_falls_back_to_second_metric_when_first_has_no_data():
    """If RequestCount returns no timeseries, ModelEndpointRequests is tried."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    call_args = []

    def _mock_metrics(*args, **kwargs):
        metric_name = kwargs.get("metricnames", "")
        call_args.append(metric_name)
        if metric_name == "RequestCount":
            return _make_total_metric_response(0.0, has_timeseries=False)
        return _make_total_metric_response(0.0)  # ModelEndpointRequests → zero → idle

    ml, mon = _make_clients(ws, [ep], metric_fn=_mock_metrics)

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert "RequestCount" in call_args
    assert "ModelEndpointRequests" in call_args
    assert findings[0].details["idle_signal_scope"] == "per_endpoint"


def test_active_on_second_metric_skips_endpoint():
    """If first metric has no data but second shows traffic, endpoint is skipped."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    def _mock_metrics(*args, **kwargs):
        metric_name = kwargs.get("metricnames", "")
        if metric_name == "RequestCount":
            return _make_total_metric_response(0.0, has_timeseries=False)
        return _make_total_metric_response(100.0)  # active

    ml, mon = _make_clients(ws, [ep], metric_fn=_mock_metrics)
    assert _call(ml, mon) == []


# ---------------------------------------------------------------------------
# Monitor auth and transient errors
# ---------------------------------------------------------------------------


def test_monitor_403_raises_permission_error():
    """403/AuthorizationFailed from monitor must surface as PermissionError."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    def raise_403(*a, **kw):
        raise Exception("403 Forbidden")

    ml, mon = _make_clients(ws, [ep], metric_fn=raise_403)

    with pytest.raises(PermissionError) as exc_info:
        _call(ml, mon)

    assert "Microsoft.Insights/metrics/read" in str(exc_info.value)


def test_monitor_authorization_failed_raises_permission_error():
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    def raise_auth(*a, **kw):
        raise Exception("AuthorizationFailed: insufficient permissions")

    ml, mon = _make_clients(ws, [ep], metric_fn=raise_auth)

    with pytest.raises(PermissionError):
        _call(ml, mon)


# ---------------------------------------------------------------------------
# Per-workspace and workspace-level error handling
# ---------------------------------------------------------------------------


def test_workspace_missing_resource_group_skipped():
    """Workspace with resource_group=None but parseable id still produces a finding."""
    ws = _make_workspace(rg=_WS_RG)
    ws.resource_group = None  # cleared — rule falls back to id parsing
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])
    # id still contains rg-ml → finding is produced
    findings = _call(ml, mon)
    assert len(findings) == 1
    assert findings[0].details["resource_group"] == _WS_RG


def test_endpoint_list_transient_error_skips_workspace_preserves_others():
    """Transient error listing endpoints in one workspace must not abort others."""
    ws_good = _make_workspace(name="good-ws", rg="rg-good")
    ws_bad = _make_workspace(name="bad-ws", rg="rg-bad")
    ep_good = _make_endpoint(name="ep-good", ws_name="good-ws", rg="rg-good", age_days=30)

    ws_order = []

    def _endpoints_by_call():
        ws_order.append(len(ws_order))
        if len(ws_order) == 2:
            raise RuntimeError("transient SDK timeout")
        return [ep_good]

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws_good, ws_bad]),
        online_endpoints=SimpleNamespace(list=_endpoints_by_call),
        online_deployments=SimpleNamespace(list=lambda ep_name: []),
    )
    mon_client = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_total_metric_response(0.0))
    )

    findings = find_idle_ml_online_endpoints(
        subscription_id=_SUB, credential=None, client=ml_client, monitor_client=mon_client
    )

    assert len(findings) == 1
    assert findings[0].details["endpoint_name"] == "ep-good"


def test_workspace_auth_error_raises_permission_error():
    """AuthorizationFailed on workspace-level op must raise PermissionError."""

    def _raise_auth():
        raise Exception("AuthorizationFailed: workspaces/read missing")

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=_raise_auth),
    )
    mon_client = SimpleNamespace()

    with pytest.raises(PermissionError) as exc_info:
        find_idle_ml_online_endpoints(
            subscription_id=_SUB, credential=None, client=ml_client, monitor_client=mon_client
        )

    assert "Microsoft.MachineLearningServices/workspaces/read" in str(exc_info.value)


# ---------------------------------------------------------------------------
# idle_days clamping
# ---------------------------------------------------------------------------


def test_idle_days_clamped_to_3():
    """idle_days < 3 must be clamped to 3 — not silently suppress all findings."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=20)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon, idle_days=1)

    # idle_days clamped to 3; age=20 >= 3 → proceeds; HIGH confidence
    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 3


def test_idle_days_zero_clamped_same_as_3():
    ws = _make_workspace()
    ep = _make_endpoint(age_days=20)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon, idle_days=0)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Finding shape
# ---------------------------------------------------------------------------


def test_finding_shape_complete():
    """All required finding fields must be populated."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="Standard_NC6", min_instances=1)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    f = _call(ml, mon)[0]

    assert f.provider == "azure"
    assert f.rule_id == "azure.ml.online_endpoint.idle"
    assert f.resource_type == "azure.ml.online_endpoint"
    assert f.resource_id == ep.id
    assert f.region == "eastus"
    assert f.title
    assert f.summary
    assert f.reason
    assert f.confidence is not None
    assert f.risk is not None
    assert f.detected_at is not None
    assert f.evidence is not None
    assert f.evidence.signals_used
    assert f.evidence.time_window

    d = f.details
    assert d["endpoint_name"] == "ep1"
    assert d["workspace_name"] == _WS_NAME
    assert d["resource_group"] == _WS_RG
    assert d["instance_type"] == "Standard_NC6"
    assert d["min_instance_count"] == 1
    assert d["is_gpu"] is True
    assert d["age_days"] == 30
    assert d["idle_days_threshold"] == 7
    assert d["idle_signal_scope"] in ("per_endpoint", "age_only")
    assert d["cost_source"] in ("heuristic_sku_table", "unknown")
    assert "deployment_count" in d


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    from cleancloud.providers.azure.rules.ml_online_endpoint_idle import RULE_METADATA

    assert RULE_METADATA["id"] == "azure.ml.online_endpoint.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "machinelearningservices"
    assert RULE_METADATA["cost_impact"] == "high"
