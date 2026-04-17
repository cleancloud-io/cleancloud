from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.openai_provisioned_idle import (
    find_idle_openai_provisioned_deployments,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SUB = "sub-123"
_RG = "rg-openai"


def _make_account(name="oai-account", location="eastus", kind="OpenAI", rg=_RG, tags=None):
    acct_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{rg}"
        f"/providers/Microsoft.CognitiveServices/accounts/{name}"
    )
    return SimpleNamespace(
        id=acct_id,
        name=name,
        location=location,
        kind=kind,
        tags=tags or {},
    )


def _make_deployment(
    name="gpt4o-prod",
    sku_name="ProvisionedManaged",
    capacity=10,
    model_name="gpt-4o",
    age_days=30,
    rg=_RG,
    account="oai-account",
):
    dep_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{rg}"
        f"/providers/Microsoft.CognitiveServices/accounts/{account}/deployments/{name}"
    )
    sku = SimpleNamespace(name=sku_name, capacity=capacity)
    model = SimpleNamespace(name=model_name)
    properties = SimpleNamespace(model=model)
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=age_days) if age_days is not None else None
    system_data = SimpleNamespace(created_at=created_at)
    return SimpleNamespace(
        id=dep_id,
        name=name,
        sku=sku,
        properties=properties,
        system_data=system_data,
    )


def _make_total_metric_response(total: float = 0.0, has_timeseries: bool = True):
    """Azure Monitor metrics.list() response with Total aggregation."""
    if not has_timeseries:
        return SimpleNamespace(value=[])
    data_point = SimpleNamespace(total=total)
    timeseries = SimpleNamespace(data=[data_point])
    metric = SimpleNamespace(timeseries=[timeseries])
    return SimpleNamespace(value=[metric])


def _make_clients(account, deployments, metric_fn=None, metric_response=None):
    """Build mock CS and Monitor clients.

    metric_fn: callable(resource_uri, **kwargs) -> response (overrides metric_response)
    metric_response: static response for all metric calls
    """
    cs_client = SimpleNamespace(
        accounts=SimpleNamespace(list=lambda: [account]),
        deployments=SimpleNamespace(list=lambda rg, acct_name: deployments),
    )
    if metric_fn is not None:
        mon_client = SimpleNamespace(
            metrics=SimpleNamespace(list=lambda resource_uri, **kw: metric_fn(resource_uri, **kw))
        )
    else:
        resp = metric_response if metric_response is not None else _make_total_metric_response(0.0)
        mon_client = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: resp))
    return cs_client, mon_client


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_provisioned_deployment_detected():
    """Provisioned deployment with zero requests should be flagged."""
    account = _make_account()
    dep = _make_deployment(sku_name="ProvisionedManaged", capacity=10, age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "azure.openai.provisioned_deployment.idle"
    assert f.resource_type == "azure.openai.provisioned_deployment"
    assert f.provider == "azure"
    assert f.confidence.value == "high"
    assert f.details["sku_name"] == "ProvisionedManaged"
    assert f.details["ptu_capacity"] == 10
    assert f.details["model"] == "gpt-4o"
    assert f.details["age_days"] == 30
    assert f.estimated_monthly_cost_usd == 10 * 1_460.0


def test_global_provisioned_sku_detected():
    """GlobalProvisionedManaged SKU should also be flagged."""
    account = _make_account()
    dep = _make_deployment(sku_name="GlobalProvisionedManaged", capacity=50, age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].details["sku_name"] == "GlobalProvisionedManaged"
    assert findings[0].estimated_monthly_cost_usd == 50 * 1_460.0


def test_datazone_provisioned_sku_detected():
    """DataZoneProvisionedManaged SKU should be flagged."""
    account = _make_account()
    dep = _make_deployment(sku_name="DataZoneProvisionedManaged", capacity=25, age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].details["sku_name"] == "DataZoneProvisionedManaged"


def test_active_deployment_skipped():
    """Deployment with non-zero requests should NOT be flagged."""
    account = _make_account()
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(
        account, [dep], metric_response=_make_total_metric_response(500.0)
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_standard_sku_skipped():
    """Non-provisioned SKU (Standard) should NOT be flagged."""
    account = _make_account()
    dep = _make_deployment(sku_name="Standard", capacity=100, age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_non_openai_account_kind_skipped():
    """Cognitive Services accounts that are not OpenAI or AIServices should be skipped."""
    account = _make_account(kind="TextAnalytics")
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_aiservices_kind_detected():
    """AIServices kind (multi-service account that includes OpenAI) should be scanned."""
    account = _make_account(kind="AIServices")
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1


def test_young_deployment_skipped():
    """Deployment younger than min age guard should NOT be flagged."""
    account = _make_account()
    dep = _make_deployment(age_days=2)  # below max(idle_days//2, 3) = 3
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_no_deployments_returns_empty():
    """Account with no deployments should return empty findings."""
    account = _make_account()
    cs_client, mon_client = _make_clients(account, [])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence_per_deployment_old_enough():
    """Per-deployment zero confirmed AND age >= idle_days → HIGH confidence."""
    account = _make_account()
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].confidence.value == "high"
    assert findings[0].details["idle_signal_scope"] == "per_deployment"


def test_medium_confidence_per_deployment_borderline_age():
    """Per-deployment zero confirmed, age exactly at ceil(75%) of idle_days → MEDIUM."""
    account = _make_account()
    # idle_days=7, ceil(7*0.75)=ceil(5.25)=6 → age=6 is the minimum for MEDIUM
    dep = _make_deployment(age_days=6)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_below_75pct_age_skipped():
    """Deployment below the ceil(75%) threshold should be skipped entirely."""
    account = _make_account()
    # idle_days=7, ceil(7*0.75)=6 → age=4 < 6 → skip
    dep = _make_deployment(age_days=4)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_age_5_with_idle_days_7_skipped():
    """age=5 with idle_days=7: ceil(7*0.75)=6, so 5 < 6 must be skipped (not MEDIUM)."""
    account = _make_account()
    dep = _make_deployment(age_days=5)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_medium_confidence_when_age_unknown():
    """Unknown creation time → MEDIUM confidence (can't rule out recent creation)."""
    account = _make_account()
    dep = _make_deployment(age_days=None)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------


def test_high_risk_for_large_ptu_allocation():
    """≥ 7 PTUs (≥ $10K/month) should be HIGH risk."""
    account = _make_account()
    dep = _make_deployment(capacity=10, age_days=30)  # 10 × $1,460 = $14,600
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].risk.value == "high"


def test_medium_risk_for_small_ptu_allocation():
    """< 7 PTUs (< $10K/month) should be MEDIUM risk."""
    account = _make_account()
    dep = _make_deployment(capacity=4, age_days=30)  # 4 × $1,460 = $5,840
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].risk.value == "medium"


# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------


def test_cost_scales_with_ptu_capacity():
    """Estimated cost should be PTU count × $1,460/month."""
    account = _make_account()
    dep = _make_deployment(capacity=100, age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].estimated_monthly_cost_usd == 100 * 1_460.0


def test_zero_ptu_capacity_no_cost_estimate():
    """Deployment with capacity=0 should have no cost estimate (None)."""
    account = _make_account()
    dep = _make_deployment(capacity=0, age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# Metric fallback strategy
# ---------------------------------------------------------------------------


def test_per_deployment_dimension_filter_used():
    """ModelDeploymentName dimension filter must be used for per-deployment scoping."""
    account = _make_account()
    dep = _make_deployment(name="gpt4-prod", age_days=30)
    call_kwargs = []

    def _mock_metrics(resource_uri, **kwargs):
        call_kwargs.append(dict(kwargs))
        return _make_total_metric_response(0.0)

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    # First call must include the deployment name in the dimension filter
    assert any("gpt4-prod" in str(kw.get("filter", "")) for kw in call_kwargs)


def test_no_per_deployment_timeseries_falls_back_to_no_data():
    """If per-deployment dimension query returns no timeseries, account-level is NOT trusted.
    The deployment is treated as no_data — account-level zero is unsafe because it only
    covers deployments that emit the metric; those that don't are invisible to it."""
    account = _make_account()
    dep = _make_deployment(age_days=30)  # 30 >= 2×7=14 → age-only fallback applies

    def _mock_metrics(resource_uri, **kwargs):
        if "filter" in kwargs:
            return _make_total_metric_response(has_timeseries=False)  # dimension not supported
        return _make_total_metric_response(0.0)  # account-level zero — NOT used

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    # Finding produced via age-only fallback, not account-level
    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"
    assert findings[0].details["idle_signal_scope"] == "age_only"


def test_no_per_deployment_timeseries_young_deployment_skipped():
    """If per-deployment dimension unsupported AND deployment too young for age fallback → no finding."""
    account = _make_account()
    dep = _make_deployment(age_days=10)  # 10 < 2×7=14 — age fallback does not apply

    def _mock_metrics(resource_uri, **kwargs):
        if "filter" in kwargs:
            return _make_total_metric_response(has_timeseries=False)
        return _make_total_metric_response(0.0)  # account-level zero — NOT used

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_fallback_to_processed_prompt_tokens():
    """If AzureOpenAIRequests returns no timeseries, ProcessedPromptTokens should be tried."""
    account = _make_account()
    dep = _make_deployment(age_days=30)
    metrics_called = []

    def _mock_metrics(resource_uri, **kwargs):
        metric_name = kwargs.get("metricnames", "")
        metrics_called.append(metric_name)
        if metric_name == "AzureOpenAIRequests":
            return _make_total_metric_response(has_timeseries=False)
        if metric_name == "ProcessedPromptTokens":
            return _make_total_metric_response(0.0)  # confirmed zero
        return _make_total_metric_response(has_timeseries=False)

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert "ProcessedPromptTokens" in metrics_called
    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "ProcessedPromptTokens" in signal_text


def test_no_timeseries_young_deployment_skipped():
    """No timeseries + age < 2× idle_days → no finding (not enough signal)."""
    account = _make_account()
    dep = _make_deployment(age_days=10)  # 10 < 2×7=14 — age-only fallback does not apply
    cs_client, mon_client = _make_clients(
        account,
        [dep],
        metric_response=_make_total_metric_response(has_timeseries=False),
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_no_timeseries_old_deployment_age_only_medium():
    """No timeseries + age >= 2× idle_days → MEDIUM age-only finding."""
    account = _make_account()
    dep = _make_deployment(age_days=30)  # 30 >= 2×7=14 — age-only fallback applies
    cs_client, mon_client = _make_clients(
        account,
        [dep],
        metric_response=_make_total_metric_response(has_timeseries=False),
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"
    assert findings[0].details["idle_signal_scope"] == "age_only"
    assert "age" in findings[0].evidence.signals_used[0].lower()


# ---------------------------------------------------------------------------
# Effective window / idle_days clamping
# ---------------------------------------------------------------------------


def test_effective_window_capped_to_age():
    """For a deployment younger than idle_days, effective_window is capped to age."""
    account = _make_account()
    # age=6 < idle_days=7, and ceil(7*0.75)=6 so age=6 qualifies for MEDIUM
    dep = _make_deployment(age_days=6)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    # age=6 >= ceil(7*0.75)=6 → MEDIUM; effective_window=min(7,6)=6
    assert len(findings) == 1
    assert findings[0].evidence.time_window == "6 days"


def test_idle_days_clamped_to_minimum():
    """idle_days below 3 is clamped to 3."""
    account = _make_account()
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
        idle_days=1,
    )

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Region filter
# ---------------------------------------------------------------------------


def test_region_filter_excludes_other_regions():
    """Deployments in accounts outside region_filter should be skipped."""
    account = _make_account(location="westeurope")
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        region_filter="eastus",
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_region_filter_matches_normalised():
    """Region filter matches after normalisation (spaces/dashes stripped)."""
    account = _make_account(location="East US")
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        region_filter="eastus",
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].region == "East US"  # original location preserved


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_monitor_transient_failure_skipped():
    """Transient Azure Monitor errors (non-auth) should NOT produce a finding, even for old deployments."""

    def _raise(*args, **kwargs):
        raise RuntimeError("Monitor API unavailable")

    account = _make_account()
    dep = _make_deployment(age_days=30)
    cs_client = SimpleNamespace(
        accounts=SimpleNamespace(list=lambda: [account]),
        deployments=SimpleNamespace(list=lambda rg, acct: [dep]),
    )
    mon_client = SimpleNamespace(metrics=SimpleNamespace(list=_raise))

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_monitor_auth_failure_raises_permission_error():
    """AuthorizationFailed on metrics.list() should raise PermissionError, not silently return no findings."""

    def _raise(*args, **kwargs):
        raise Exception("AuthorizationFailed: missing Microsoft.Insights/metrics/read")

    account = _make_account()
    dep = _make_deployment(age_days=30)
    cs_client = SimpleNamespace(
        accounts=SimpleNamespace(list=lambda: [account]),
        deployments=SimpleNamespace(list=lambda rg, acct: [dep]),
    )
    mon_client = SimpleNamespace(metrics=SimpleNamespace(list=_raise))

    with pytest.raises(PermissionError) as exc_info:
        find_idle_openai_provisioned_deployments(
            subscription_id=_SUB,
            credential=None,
            client=cs_client,
            monitor_client=mon_client,
        )

    assert "Microsoft.Insights/metrics/read" in str(exc_info.value)


def test_permission_error_raised_on_auth_failure():
    """AuthorizationFailed at accounts.list() should raise PermissionError."""

    def _raise():
        raise Exception("AuthorizationFailed: client lacks CognitiveServices/accounts/read")

    cs_client = SimpleNamespace(accounts=SimpleNamespace(list=_raise))
    mon_client = SimpleNamespace()

    with pytest.raises(PermissionError) as exc_info:
        find_idle_openai_provisioned_deployments(
            subscription_id=_SUB,
            credential=None,
            client=cs_client,
            monitor_client=mon_client,
        )

    assert "Microsoft.CognitiveServices/accounts/read" in str(exc_info.value)


def test_account_auth_error_raises_permission_error():
    """AuthorizationFailed at deployments.list() should raise PermissionError."""
    account = _make_account()

    def _dep_list_raise(rg, acct):
        raise Exception("AuthorizationFailed: missing deployments/read")

    cs_client = SimpleNamespace(
        accounts=SimpleNamespace(list=lambda: [account]),
        deployments=SimpleNamespace(list=_dep_list_raise),
    )
    mon_client = SimpleNamespace()

    with pytest.raises(PermissionError) as exc_info:
        find_idle_openai_provisioned_deployments(
            subscription_id=_SUB,
            credential=None,
            client=cs_client,
            monitor_client=mon_client,
        )

    assert "Microsoft.CognitiveServices/accounts/deployments/read" in str(exc_info.value)


def test_transient_account_error_skipped_preserves_other_findings():
    """Transient error on one account should not abort findings from others."""
    account_good = _make_account(name="good-account", rg="rg-good")
    account_bad = _make_account(name="bad-account", rg="rg-bad")
    dep_good = _make_deployment(age_days=30, account="good-account", rg="rg-good")

    call_count = [0]

    def _dep_list(rg, acct_name):
        call_count[0] += 1
        if acct_name == "bad-account":
            raise RuntimeError("transient SDK timeout")
        return [dep_good]

    cs_client = SimpleNamespace(
        accounts=SimpleNamespace(list=lambda: [account_good, account_bad]),
        deployments=SimpleNamespace(list=_dep_list),
    )
    mon_client = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda *a, **kw: _make_total_metric_response(0.0))
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].details["account_name"] == "good-account"
    assert call_count[0] == 2  # both accounts attempted


# ---------------------------------------------------------------------------
# Evidence / signal surfacing
# ---------------------------------------------------------------------------


def test_idle_signal_metric_name_in_evidence():
    """The metric name used to confirm idle should appear in evidence signals."""
    account = _make_account()
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "AzureOpenAIRequests" in signal_text


def test_cost_warning_in_evidence_signals():
    """PTU cost estimate should appear in evidence signals."""
    account = _make_account()
    dep = _make_deployment(capacity=10, age_days=30)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "14,600" in signal_text  # 10 PTU × $1,460


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    """Rule must expose RULE_METADATA with correct fields."""
    from cleancloud.providers.azure.rules.openai_provisioned_idle import RULE_METADATA

    assert RULE_METADATA["id"] == "azure.openai.provisioned_deployment.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "cognitiveservices"
    assert RULE_METADATA["cost_impact"] == "high"
