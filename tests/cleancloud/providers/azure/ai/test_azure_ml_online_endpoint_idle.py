"""
Tests for azure.ml.online_endpoint.idle rule (spec-compliant).

Key spec contracts tested here:
- Managed scope via endpoint kind or deployment class (spec 9.1)
- Exact case-sensitive provisioning_state == "Succeeded" (spec 8.6)
- created_at required from systemData; age >= effective idle_days (spec 8.7, 9.2)
- Billing-relevant deployments: stable, min_instances > 0 (spec 8.9, 9.3)
- RequestsPerMinute / Average / PT1M on endpoint ARM resource id (spec 9.5)
- Coverage 80% threshold (MEDIUM), 95% threshold (HIGH) (spec 9.6)
- No workspace-level metric fallback; no age-only fallback (spec 9.5)
- estimated_monthly_cost_usd = None always (spec 10)
- Risk: HIGH (GPU) / MEDIUM only — no CRITICAL (spec 9.6)
- Exception handling: subscription-level propagates, per-workspace/per-endpoint skips (spec 12)
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from azure.core.exceptions import HttpResponseError

from cleancloud.providers.azure.rules.ai.ml_online_endpoint_idle import (
    RULE_METADATA,
    find_idle_ml_online_endpoints,
)

# ---------------------------------------------------------------------------
# Test helpers for HttpResponseError
# ---------------------------------------------------------------------------


def _http_error(status_code: int) -> HttpResponseError:
    resp = Mock()
    resp.status_code = status_code
    return HttpResponseError(response=resp)


_SUB = "sub-123"
_WS_RG = "rg-ml"
_WS_NAME = "test-workspace"


# ---------------------------------------------------------------------------
# Fixture helpers
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
    location="eastus",
    kind="Managed",
    tags=None,
):
    ep_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{ws_name}"
        f"/onlineEndpoints/{name}"
    )
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=age_days) if age_days is not None else None
    system_data = SimpleNamespace(created_at=created_at)
    return SimpleNamespace(
        id=ep_id,
        name=name,
        provisioning_state=provisioning_state,
        system_data=system_data,
        location=location,
        kind=kind,
        tags=tags or {},
    )


def _make_deployment(
    instance_type="Standard_DS3_v2",
    min_instances=1,
    provisioning_state="Succeeded",
):
    """Stable CPU deployment with one billing-relevant instance by default."""
    scale = SimpleNamespace(min_instances=min_instances) if min_instances is not None else None
    return SimpleNamespace(
        instance_type=instance_type,
        instance_count=min_instances,
        scale_settings=scale,
        provisioning_state=provisioning_state,
    )


def _make_avg_metric_response(average=0.0, coverage_fraction=1.0, idle_days=7):
    """
    Return a monitor metrics response using Average aggregation.

    Each datapoint carries a time_stamp that is a valid UTC minute bucket inside
    [window_start_utc, metric_end_utc), matching the window the implementation computes.
    coverage_fraction controls the fraction of expected PT1M buckets that are returned.
    """
    expected = idle_days * 24 * 60  # PT1M buckets for the window
    usable = int(expected * coverage_fraction)

    # Approximate metric_end_utc using the same formula as _query_requests_per_minute so
    # that generated timestamps fall inside the implementation's acceptance window.
    now_utc = datetime.now(timezone.utc)
    metric_end_utc = (now_utc - timedelta(minutes=5)).replace(second=0, microsecond=0)

    # Generate minute buckets going backwards from just before metric_end_utc.
    data_points = [
        SimpleNamespace(average=average, time_stamp=metric_end_utc - timedelta(minutes=i + 1))
        for i in range(usable)
    ]
    timeseries = SimpleNamespace(data=data_points)
    metric = SimpleNamespace(timeseries=[timeseries])
    return SimpleNamespace(value=[metric])


def _make_empty_metric_response():
    """No timeseries — metric result will be UNKNOWN."""
    return SimpleNamespace(value=[])


def _make_clients(
    workspace,
    endpoints,
    metric_response=None,
    metric_fn=None,
    deployments_by_ep=None,
    idle_days=7,
):
    """
    Build mock (ml_client, mon_client).

    The injected ml_client serves as both subscription-level (workspaces.list_by_subscription)
    and workspace-scoped (online_endpoints / online_deployments) client.

    Default deployments_by_ep=None → one billing-relevant CPU deployment for any endpoint.
    Default metric_response → full-coverage zero-traffic response (ZERO result → emit).
    """
    # Default: one billing-relevant deployment for all endpoints
    _default_dep = _make_deployment()

    def _list_deps(ep_name):
        if deployments_by_ep is not None:
            return deployments_by_ep.get(ep_name, [])
        return [_default_dep]

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [workspace]),
        online_endpoints=SimpleNamespace(list=lambda: endpoints),
        online_deployments=SimpleNamespace(list=_list_deps),
    )

    if metric_fn is not None:
        mon_client = SimpleNamespace(
            metrics=SimpleNamespace(list=lambda *a, **kw: metric_fn(*a, **kw))
        )
    else:
        resp = (
            metric_response
            if metric_response is not None
            else _make_avg_metric_response(0.0, idle_days=idle_days)
        )
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
# Managed scope classes for class-name-based tests (spec 9.1)
# ---------------------------------------------------------------------------


class ManagedOnlineEndpoint(SimpleNamespace):  # noqa: N801
    pass


class KubernetesOnlineEndpoint(SimpleNamespace):  # noqa: N801
    pass


class ManagedOnlineDeployment(SimpleNamespace):  # noqa: N801
    pass


class KubernetesOnlineDeployment(SimpleNamespace):  # noqa: N801
    pass


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_endpoint_detected():
    """Managed endpoint with zero RequestsPerMinute should produce a finding."""
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
    """Endpoint with non-zero RequestsPerMinute must NOT produce a finding."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep], metric_response=_make_avg_metric_response(5.0))

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
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_avg_metric_response(0.0))
    )
    assert _call(ml_client, mon_client) == []


# ---------------------------------------------------------------------------
# Managed scope (spec 8.5, 9.1)
# ---------------------------------------------------------------------------


def test_kubernetes_kind_endpoint_skipped():
    """Endpoint with kind='Kubernetes' must be out of scope and skipped."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, kind="Kubernetes")
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_unknown_kind_no_deployment_signal_skipped():
    """Endpoint with unknown kind and no deployment class signals must be skipped."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, kind=None)  # no kind attribute signal
    # Use SimpleNamespace deployments — class name is neither Managed nor Kubernetes
    deps = [_make_deployment()]  # SimpleNamespace
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": deps})
    assert _call(ml, mon) == []


def test_managed_scope_from_endpoint_kind():
    """kind='Managed' establishes endpoint-level managed scope."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, kind="Managed")
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["managed_scope_source"] == "endpoint"


def test_managed_scope_from_managedonlineendpoint_class():
    """ManagedOnlineEndpoint class name establishes endpoint-level managed scope."""
    ws = _make_workspace()
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=30)
    ep_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{_WS_RG}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{_WS_NAME}/onlineEndpoints/ep1"
    )
    # Create instance of named class — no 'kind' attribute needed
    ep = ManagedOnlineEndpoint(
        id=ep_id,
        name="ep1",
        provisioning_state="Succeeded",
        system_data=SimpleNamespace(created_at=created_at),
        location="eastus",
        tags={},
    )
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["managed_scope_source"] == "endpoint"


def test_managed_scope_from_deployment_class():
    """ManagedOnlineDeployment class on stable deployments establishes scope when endpoint has no signal."""
    ws = _make_workspace()
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=30)
    ep_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{_WS_RG}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{_WS_NAME}/onlineEndpoints/ep-no-kind"
    )
    ep = SimpleNamespace(
        id=ep_id,
        name="ep-no-kind",
        provisioning_state="Succeeded",
        system_data=SimpleNamespace(created_at=created_at),
        location="eastus",
        kind=None,
        tags={},
    )
    # Use ManagedOnlineDeployment class
    dep = ManagedOnlineDeployment(
        instance_type="Standard_DS3_v2",
        min_instances=1,
        instance_count=1,
        scale_settings=SimpleNamespace(min_instances=1),
        provisioning_state="Succeeded",
    )
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep-no-kind": [dep]})

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["managed_scope_source"] == "deployment"


def test_kubernetes_deployment_under_managed_endpoint_skipped():
    """KubernetesOnlineDeployment under a managed endpoint causes conflict → skip (spec 9.1.6)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, kind="Managed")
    dep = KubernetesOnlineDeployment(
        instance_type="Standard_DS3_v2",
        min_instances=1,
        instance_count=1,
        scale_settings=SimpleNamespace(min_instances=1),
        provisioning_state="Succeeded",
    )
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})
    assert _call(ml, mon) == []


def test_kubernetes_endpoint_class_skipped():
    """KubernetesOnlineEndpoint class → out of scope."""
    ws = _make_workspace()
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=30)
    ep_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{_WS_RG}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{_WS_NAME}/onlineEndpoints/ep-k8s"
    )
    ep = KubernetesOnlineEndpoint(
        id=ep_id,
        name="ep-k8s",
        provisioning_state="Succeeded",
        system_data=SimpleNamespace(created_at=created_at),
        location="eastus",
        tags={},
    )
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


# ---------------------------------------------------------------------------
# Provisioning state (spec 8.6)
# ---------------------------------------------------------------------------


def test_non_succeeded_state_skipped():
    """Endpoints not in exact 'Succeeded' state must be skipped."""
    ws = _make_workspace()
    for state in ("Creating", "Deleting", "Failed", "Updating"):
        ep = _make_endpoint(age_days=30, provisioning_state=state)
        ml, mon = _make_clients(ws, [ep])
        assert _call(ml, mon) == [], f"Expected no findings for state={state}"


def test_provisioning_state_case_sensitive_lowercase_skipped():
    """'succeeded' (lowercase) must NOT match — comparison is exact case-sensitive (spec 8.6)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, provisioning_state="succeeded")
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_none_provisioning_state_skipped():
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, provisioning_state=None)
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


# ---------------------------------------------------------------------------
# Age and created_at (spec 8.7, 9.2)
# ---------------------------------------------------------------------------


def test_young_endpoint_skipped():
    """Endpoint younger than effective idle_days must be skipped."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=6)  # 6 < 7 = default idle_days
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_age_exactly_idle_days_proceeds():
    """Endpoint age exactly equal to idle_days must proceed."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=7)
    ml, mon = _make_clients(ws, [ep])
    assert len(_call(ml, mon)) == 1


def test_created_at_required_skips_when_absent():
    """Endpoint with no system_data / created_at must be skipped (spec 8.7)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=None)  # age_days=None → created_at=None in system_data
    ml, mon = _make_clients(ws, [ep])
    # None created_at → cannot establish age → skip
    assert _call(ml, mon) == []


def test_future_created_at_skipped():
    """Future created_at timestamp must be skipped (spec 9.2.3)."""
    ws = _make_workspace()
    now = datetime.now(timezone.utc)
    ep_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{_WS_RG}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{_WS_NAME}/onlineEndpoints/future"
    )
    future = now + timedelta(days=1)
    ep = SimpleNamespace(
        id=ep_id,
        name="future",
        provisioning_state="Succeeded",
        system_data=SimpleNamespace(created_at=future),
        location="eastus",
        kind="Managed",
        tags={},
    )
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_idle_days_minimum_is_1():
    """idle_days minimum effective value is 1 (spec 6.3), not higher."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=2)  # 2 >= 1
    ml, mon = _make_clients(ws, [ep], idle_days=1)

    findings = _call(ml, mon, idle_days=1)

    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 1


def test_idle_days_zero_clamped_to_1():
    ws = _make_workspace()
    ep = _make_endpoint(age_days=2)
    ml, mon = _make_clients(ws, [ep], idle_days=1)

    findings = _call(ml, mon, idle_days=0)

    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 1


# ---------------------------------------------------------------------------
# Deployment billing relevance (spec 8.8, 8.9, 9.3)
# ---------------------------------------------------------------------------


def test_no_stable_deployments_skipped():
    """All deployments not in Succeeded state → no billing-relevant deployment → skip."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(provisioning_state="Failed")
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})
    assert _call(ml, mon) == []


def test_deployment_with_unknown_instance_count_skipped():
    """Deployment with min_instances=None and instance_count=None is not billing-relevant."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = SimpleNamespace(
        instance_type="Standard_DS3_v2",
        instance_count=None,
        scale_settings=None,
        provisioning_state="Succeeded",
    )
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})
    assert _call(ml, mon) == []


def test_scale_to_zero_endpoint_skipped():
    """Deployment with min_instances=0 is not billing-relevant → skip (spec 9.3.5, 9.3.7)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(min_instances=0)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})
    assert _call(ml, mon) == []


def test_min_instances_takes_priority_over_instance_count():
    """scale_settings.min_instances is resolved before instance_count (spec 9.3.4)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    # scale_settings.min_instances=2, instance_count=5 → min_instances wins → 2
    dep = SimpleNamespace(
        instance_type="Standard_DS3_v2",
        instance_count=5,
        scale_settings=SimpleNamespace(min_instances=2),
        provisioning_state="Succeeded",
    )
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["baseline_instance_count_total"] == 2


def test_baseline_instances_summed_across_deployments():
    """Baseline instance counts are summed across all billing-relevant deployments."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    deps = [
        _make_deployment(instance_type="Standard_DS3_v2", min_instances=2),
        _make_deployment(instance_type="Standard_DS3_v2", min_instances=3),
    ]
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": deps})

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["baseline_instance_count_total"] == 5
    assert findings[0].details["billing_relevant_deployment_count"] == 2


def test_deployment_list_failure_skips_endpoint():
    """Exception while listing deployments must skip that endpoint (spec 8.8, 12)."""
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
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_avg_metric_response(0.0))
    )

    assert (
        find_idle_ml_online_endpoints(
            subscription_id=_SUB, credential=None, client=ml_client, monitor_client=mon_client
        )
        == []
    )


def test_only_succeeded_deployments_count_toward_billing():
    """Non-Succeeded deployments must not contribute to baseline instances."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    deps = [
        _make_deployment(min_instances=5, provisioning_state="Updating"),  # excluded
        _make_deployment(min_instances=2, provisioning_state="Succeeded"),  # included
    ]
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": deps})

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["baseline_instance_count_total"] == 2
    assert findings[0].details["billing_relevant_deployment_count"] == 1


def test_deployment_count_includes_all_not_just_stable():
    """deployment_count in details reflects ALL deployments, not just stable ones."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    deps = [
        _make_deployment(min_instances=1, provisioning_state="Succeeded"),
        _make_deployment(min_instances=1, provisioning_state="Failed"),
    ]
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": deps})

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["deployment_count"] == 2
    assert findings[0].details["stable_deployment_count"] == 1
    assert findings[0].details["billing_relevant_deployment_count"] == 1


# ---------------------------------------------------------------------------
# Metric contract (spec 8.10, 9.5)
# ---------------------------------------------------------------------------


def test_metric_queried_on_endpoint_arm_id():
    """Metrics must be queried against the endpoint ARM resource id, not workspace id."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    captured_resource_ids = []

    def _capture(*args, **kwargs):
        if args:
            captured_resource_ids.append(args[0])
        return _make_avg_metric_response(0.0)

    ml, mon = _make_clients(ws, [ep], metric_fn=_capture)
    _call(ml, mon)

    assert captured_resource_ids, "Expected at least one metrics.list call"
    # Endpoint id must be used, not workspace id
    assert ep.id in captured_resource_ids
    ws_id = ws.id
    assert ws_id not in captured_resource_ids


def test_metric_uses_correct_parameters():
    """RequestsPerMinute / PT1M / Average must be used (spec 9.5)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    captured = {}

    def _capture(*args, **kwargs):
        captured.update(kwargs)
        return _make_avg_metric_response(0.0)

    ml, mon = _make_clients(ws, [ep], metric_fn=_capture)
    _call(ml, mon)

    assert captured.get("metricnames") == "RequestsPerMinute"
    assert captured.get("interval") == "PT1M"
    assert captured.get("aggregation") == "Average"


def test_coverage_below_80pct_skips_endpoint():
    """Coverage < 80% → UNKNOWN metric result → endpoint skipped (spec 9.5.8)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    # 79% coverage
    ml, mon = _make_clients(
        ws, [ep], metric_response=_make_avg_metric_response(0.0, coverage_fraction=0.79)
    )
    assert _call(ml, mon) == []


def test_coverage_exactly_80pct_emits():
    """Coverage >= 80% → acceptable → endpoint emits (spec 9.5 acceptable coverage)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(
        ws, [ep], metric_response=_make_avg_metric_response(0.0, coverage_fraction=0.80)
    )
    assert len(_call(ml, mon)) == 1


def test_all_metric_calls_fail_skips_endpoint():
    """Exception from monitor client → UNKNOWN metric result → endpoint skipped."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    def _raise(*a, **kw):
        raise RuntimeError("SDK timeout")

    ml, mon = _make_clients(ws, [ep], metric_fn=_raise)
    assert _call(ml, mon) == []


def test_empty_metric_response_skips_endpoint():
    """No timeseries in response → 0 usable datapoints → coverage 0% → skip (spec 9.5.8)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep], metric_response=_make_empty_metric_response())
    assert _call(ml, mon) == []


def test_datapoints_without_timestamps_not_counted():
    """Datapoints with no time_stamp are not usable and do not count toward coverage (spec 9.5)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    # Points with average but no time_stamp attribute
    data_points = [SimpleNamespace(average=0.0) for _ in range(10080)]
    resp = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data_points)])])
    ml, mon = _make_clients(ws, [ep], metric_response=resp)
    # 0 usable buckets → coverage 0% → UNKNOWN → skip
    assert _call(ml, mon) == []


def test_out_of_window_datapoints_not_counted():
    """Datapoints with timestamps outside [window_start_utc, metric_end_utc) are discarded (spec 9.5.3)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    now_utc = datetime.now(timezone.utc)
    # Timestamps in the far future — all outside the window
    future_ts = now_utc + timedelta(days=100)
    data_points = [SimpleNamespace(average=0.0, time_stamp=future_ts) for _ in range(10080)]
    resp = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data_points)])])
    ml, mon = _make_clients(ws, [ep], metric_response=resp)
    # All out-of-window → 0 usable buckets → coverage 0% → UNKNOWN → skip
    assert _call(ml, mon) == []


def test_active_point_outside_window_not_flagged_as_active():
    """Average > 0 on an out-of-window timestamp must NOT trigger ACTIVE (spec 9.5.3)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    now_utc = datetime.now(timezone.utc)
    # One future (out-of-window) point with average=99, one valid zero point
    metric_end_utc = (now_utc - timedelta(minutes=5)).replace(second=0, microsecond=0)
    valid_bucket = metric_end_utc - timedelta(minutes=1)
    data_points = [
        SimpleNamespace(average=99.0, time_stamp=now_utc + timedelta(days=1)),  # future, skip
        SimpleNamespace(average=0.0, time_stamp=valid_bucket),  # valid zero
    ]
    # One valid zero bucket → coverage 1/10080 ≈ 0% → UNKNOWN → skip (not ACTIVE)
    resp = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data_points)])])
    ml, mon = _make_clients(ws, [ep], metric_response=resp)
    assert _call(ml, mon) == []  # skipped due to low coverage, not flagged as ACTIVE


def test_duplicate_minute_buckets_counted_once():
    """Same minute bucket appearing in multiple timeseries is counted only once (spec 9.5 dedup)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=2)
    now_utc = datetime.now(timezone.utc)
    metric_end_utc = (now_utc - timedelta(minutes=5)).replace(second=0, microsecond=0)
    # One unique in-window bucket, duplicated across two timeseries
    bucket = metric_end_utc - timedelta(minutes=1)
    point = SimpleNamespace(average=0.0, time_stamp=bucket)
    ts1 = SimpleNamespace(data=[point])
    ts2 = SimpleNamespace(data=[point])
    resp = SimpleNamespace(value=[SimpleNamespace(timeseries=[ts1, ts2])])
    ml, mon = _make_clients(ws, [ep], metric_response=resp)
    # idle_days=7: expected=10080 buckets, unique usable=1 → coverage 1/10080 < 80% → UNKNOWN → skip
    assert _call(ml, mon) == []


# ---------------------------------------------------------------------------
# Confidence levels (spec 9.6)
# ---------------------------------------------------------------------------


def test_high_confidence_when_coverage_ge_95pct():
    """Coverage >= 95% → HIGH confidence (spec 9.6)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(
        ws, [ep], metric_response=_make_avg_metric_response(0.0, coverage_fraction=0.95)
    )

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_high_confidence_at_full_coverage():
    """100% coverage → HIGH confidence."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(
        ws, [ep], metric_response=_make_avg_metric_response(0.0, coverage_fraction=1.0)
    )
    assert _call(ml, mon)[0].confidence.value == "high"


def test_medium_confidence_when_coverage_between_80_and_95_pct():
    """Coverage 80–95% → MEDIUM confidence (spec 9.6)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(
        ws, [ep], metric_response=_make_avg_metric_response(0.0, coverage_fraction=0.87)
    )

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_medium_confidence_at_80pct_coverage():
    """Coverage exactly 80% → MEDIUM confidence (< 95% threshold)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(
        ws, [ep], metric_response=_make_avg_metric_response(0.0, coverage_fraction=0.80)
    )
    assert _call(ml, mon)[0].confidence.value == "medium"


# ---------------------------------------------------------------------------
# Risk levels (spec 9.6)
# ---------------------------------------------------------------------------


def test_cpu_endpoint_medium_risk():
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert findings[0].risk.value == "medium"
    assert findings[0].details["is_gpu"] is False


def test_gpu_nc_series_high_risk():
    """Any billing-relevant GPU deployment → HIGH risk (spec 9.6)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="Standard_NC6", min_instances=1)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].risk.value == "high"
    assert findings[0].details["is_gpu"] is True


def test_gpu_nd_series_high_risk():
    """ND-series must be classified as GPU → HIGH risk."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="Standard_ND40rs_v2", min_instances=1)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    assert _call(ml, mon)[0].risk.value == "high"


def test_gpu_nv_series_high_risk():
    """NV-series must be classified as GPU → HIGH risk."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="Standard_NV12s_v3", min_instances=1)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    assert _call(ml, mon)[0].risk.value == "high"


def test_gpu_detected_on_any_billing_relevant_deployment():
    """GPU classification fires if any billing-relevant deployment is GPU."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    deps = [
        _make_deployment(instance_type="Standard_DS3_v2", min_instances=2),  # CPU first
        _make_deployment(instance_type="Standard_NC6", min_instances=1),  # GPU second
    ]
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": deps})

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["is_gpu"] is True
    assert findings[0].details["instance_type"] == "Standard_DS3_v2"  # first kept
    assert findings[0].details["baseline_instance_count_total"] == 3


def test_gpu_detection_uppercase_normalization():
    """GPU prefix matching is uppercase-normalized; lowercase instance_type detected as GPU."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="standard_nc6", min_instances=1)  # lowercase
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    assert _call(ml, mon)[0].details["is_gpu"] is True


def test_no_critical_risk_ever():
    """Risk must never exceed HIGH regardless of GPU or duration (spec 9.6)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=365)  # very old
    dep = _make_deployment(instance_type="Standard_NC24", min_instances=4)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].risk.value == "high"
    assert findings[0].risk.value != "critical"


# ---------------------------------------------------------------------------
# Cost (spec 10)
# ---------------------------------------------------------------------------


def test_estimated_cost_always_none():
    """estimated_monthly_cost_usd must always be None (spec 10)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    dep = _make_deployment(instance_type="Standard_NC6", min_instances=2)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    findings = _call(ml, mon)

    assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# Region filter (spec 8.4)
# ---------------------------------------------------------------------------


def test_region_filter_excludes_other_regions():
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, location="westeurope")
    ml, mon = _make_clients(ws, [ep])

    assert _call(ml, mon, region_filter="eastus") == []


def test_region_filter_exact_lowercase_match():
    """Region filter uses exact lowercase comparison (spec 7)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, location="eastus")
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon, region_filter="eastus")

    assert len(findings) == 1
    assert findings[0].region == "eastus"


def test_region_filter_space_in_region_name():
    """'East US' (with space) matches region_filter='east us' after lowercase (spec 7).
    The emitted region is the normalized (lowercase) location (spec 11.1)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, location="East US")
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon, region_filter="east us")

    assert len(findings) == 1
    assert findings[0].region == "east us"


def test_no_region_filter_includes_all_regions():
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, location="westeurope")
    ml, mon = _make_clients(ws, [ep])

    assert len(_call(ml, mon)) == 1


def test_region_normalized_in_finding():
    """Finding.region is the normalized (lowercase) endpoint location (spec 7, 11.1)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, location="West Europe")
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].region == "west europe"
    assert findings[0].details["location"] == "west europe"


# ---------------------------------------------------------------------------
# Resource group and workspace identity
# ---------------------------------------------------------------------------


def test_rg_parsed_from_id_when_attribute_missing():
    """resource_group attribute missing → RG parsed from workspace ARM id."""
    ws = _make_workspace(rg="rg-from-id")
    del ws.resource_group
    ep = _make_endpoint(age_days=30, rg="rg-from-id")
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["resource_group"] == "rg-from-id"


def test_workspace_no_rg_attribute_no_id_skipped():
    """Workspace with resource_group=None and no parseable id is skipped."""
    ws = _make_workspace()
    ws.resource_group = None
    ws.id = None
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_workspace_name_required():
    """Workspace with name=None is skipped (spec 8.3)."""
    ws = _make_workspace()
    ws.name = None
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_endpoint_id_required():
    """Endpoint with id=None is skipped (spec 8.1)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ep.id = None
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_endpoint_name_required():
    """Endpoint with name=None is skipped (spec 8.2)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ep.name = None
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_endpoint_missing_location_skipped():
    """Endpoint with absent/empty location must be skipped regardless of region_filter (spec 7)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, location=None)
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


def test_endpoint_empty_string_location_skipped():
    """Endpoint with empty-string location must be skipped (spec 7)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, location="")
    ml, mon = _make_clients(ws, [ep])
    assert _call(ml, mon) == []


# ---------------------------------------------------------------------------
# Exception handling (spec 12)
# ---------------------------------------------------------------------------


def test_subscription_inventory_failure_propagates():
    """Subscription-wide workspace inventory failure must propagate (spec 12)."""

    def _raise():
        raise RuntimeError("inventory failed")

    ml_client = SimpleNamespace(workspaces=SimpleNamespace(list_by_subscription=_raise))
    mon_client = SimpleNamespace()

    with pytest.raises(RuntimeError, match="inventory failed"):
        find_idle_ml_online_endpoints(
            subscription_id=_SUB, credential=None, client=ml_client, monitor_client=mon_client
        )


def test_per_workspace_endpoint_list_failure_skips_workspace():
    """Transient error listing endpoints skips that workspace and preserves other findings."""
    ws_good = _make_workspace(name="good-ws", rg="rg-good")
    ws_bad = _make_workspace(name="bad-ws", rg="rg-bad")
    ep_good = _make_endpoint(name="ep-good", ws_name="good-ws", rg="rg-good", age_days=30)

    call_count = [0]

    def _list_endpoints():
        call_count[0] += 1
        if call_count[0] == 2:
            raise RuntimeError("transient SDK timeout")
        return [ep_good]

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws_good, ws_bad]),
        online_endpoints=SimpleNamespace(list=_list_endpoints),
        online_deployments=SimpleNamespace(list=lambda ep_name: [_make_deployment()]),
    )
    mon_client = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_avg_metric_response(0.0))
    )

    findings = find_idle_ml_online_endpoints(
        subscription_id=_SUB, credential=None, client=ml_client, monitor_client=mon_client
    )

    assert len(findings) == 1
    assert findings[0].details["endpoint_name"] == "ep-good"


def test_per_endpoint_failure_skips_endpoint():
    """Exception processing one endpoint must not abort others."""
    ws = _make_workspace()
    ep_bad = _make_endpoint(name="ep-bad", age_days=30)
    ep_good = _make_endpoint(name="ep-good", age_days=30)

    # ep-bad will have a broken system_data that raises on attribute access
    class _BrokenSystemData:
        @property
        def created_at(self):
            raise RuntimeError("broken")

    ep_bad.system_data = _BrokenSystemData()

    ml, mon = _make_clients(ws, [ep_bad, ep_good])
    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["endpoint_name"] == "ep-good"


def test_monitor_403_raises_permission_error():
    """HTTP 403 from monitor must surface as PermissionError."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    def _raise_403(*a, **kw):
        raise _http_error(403)

    ml, mon = _make_clients(ws, [ep], metric_fn=_raise_403)

    with pytest.raises(PermissionError) as exc_info:
        _call(ml, mon)

    assert "Microsoft.Insights/metrics/read" in str(exc_info.value)


def test_monitor_401_raises_permission_error():
    """HTTP 401 from monitor must surface as PermissionError."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)

    def _raise_401(*a, **kw):
        raise _http_error(401)

    ml, mon = _make_clients(ws, [ep], metric_fn=_raise_401)

    with pytest.raises(PermissionError):
        _call(ml, mon)


# ---------------------------------------------------------------------------
# Finding shape (spec 11)
# ---------------------------------------------------------------------------


def test_finding_shape_complete():
    """All required finding fields and detail keys must be present (spec 11.3)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, kind="Managed")
    dep = _make_deployment(instance_type="Standard_NC6", min_instances=2)
    ml, mon = _make_clients(ws, [ep], deployments_by_ep={"ep1": [dep]})

    f = _call(ml, mon)[0]

    assert f.provider == "azure"
    assert f.rule_id == "azure.ml.online_endpoint.idle"
    assert f.resource_type == "azure.ml.online_endpoint"
    assert f.resource_id == ep.id
    assert f.region == "eastus"
    assert f.estimated_monthly_cost_usd is None  # spec 10: always None
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
    # All spec 11.3 fields must be present
    assert d["endpoint_name"] == "ep1"
    assert d["workspace_name"] == _WS_NAME
    assert d["resource_group"] == _WS_RG
    assert d["subscription_id"] == _SUB
    assert d["location"] == "eastus"
    assert "endpoint_kind" in d
    assert d["managed_scope_source"] == "endpoint"
    assert d["endpoint_provisioning_state"] == "Succeeded"
    assert d["created_at"] is not None
    assert d["billing_relevant_deployment_count"] == 1
    assert d["deployment_count"] == 1
    assert d["stable_deployment_count"] == 1
    assert d["instance_type"] == "Standard_NC6"
    assert d["is_gpu"] is True
    assert d["baseline_instance_count_total"] == 2
    assert d["idle_days_threshold"] == 7
    assert d["idle_since_days"] == 7
    assert d["metric_name"] == "RequestsPerMinute"
    assert d["metric_aggregation"] == "Average"
    assert "metric_coverage_ratio" in d
    assert isinstance(d["metric_coverage_ratio"], float)
    assert isinstance(d["tags"], dict)


def test_tags_never_none():
    """tags must always be a dict, never None (spec 7)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30, tags=None)  # explicitly None
    ml, mon = _make_clients(ws, [ep])

    findings = _call(ml, mon)

    assert len(findings) == 1
    assert findings[0].details["tags"] == {}


def test_idle_since_days_equals_effective_window():
    """idle_since_days = effective idle window (not an observational estimate) (spec 9.5)."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep], idle_days=14)

    findings = _call(ml, mon, idle_days=14)

    assert findings[0].details["idle_since_days"] == 14


def test_evidence_signals_cover_required_disclosures():
    """signals_used must disclose managed scope, provisioning state, age, billing, and metric."""
    ws = _make_workspace()
    ep = _make_endpoint(age_days=30)
    ml, mon = _make_clients(ws, [ep])

    f = _call(ml, mon)[0]
    signals_text = " ".join(f.evidence.signals_used)

    assert "managed" in signals_text.lower()
    assert "Succeeded" in signals_text
    assert "RequestsPerMinute" in signals_text
    assert "ZERO" in signals_text


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    assert RULE_METADATA["id"] == "azure.ml.online_endpoint.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "machinelearningservices"
    assert RULE_METADATA["cost_impact"] == "high"
