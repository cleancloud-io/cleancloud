from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.ai.openai_provisioned_idle import (
    find_idle_openai_provisioned_deployments,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUB = "sub-123"
_RG = "rg-openai"
_ACCT_NAME = "oai-account"
_DEP_NAME = "gpt4o-prod"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_account(
    name=_ACCT_NAME,
    location="eastus",
    kind="OpenAI",
    rg=_RG,
    tags=None,
    provisioning_state="Succeeded",
):
    acct_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{rg}"
        f"/providers/Microsoft.CognitiveServices/accounts/{name}"
    )
    properties = SimpleNamespace(provisioning_state=provisioning_state)
    return SimpleNamespace(
        id=acct_id,
        name=name,
        location=location,
        kind=kind,
        properties=properties,
        tags=tags or {},
    )


def _make_deployment(
    name=_DEP_NAME,
    sku_name="ProvisionedManaged",
    capacity=10,
    model_format="OpenAI",
    model_name="gpt-4o",
    model_version="2024-05-13",
    age_days=30,
    provisioning_state="Succeeded",
    rg=_RG,
    account=_ACCT_NAME,
    tags=None,
):
    dep_id = (
        f"/subscriptions/{_SUB}/resourceGroups/{rg}"
        f"/providers/Microsoft.CognitiveServices/accounts/{account}/deployments/{name}"
    )
    sku = SimpleNamespace(name=sku_name, capacity=capacity)
    model = SimpleNamespace(format=model_format, name=model_name, version=model_version)
    properties = SimpleNamespace(model=model, provisioning_state=provisioning_state)
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=age_days) if age_days is not None else None
    system_data = SimpleNamespace(created_at=created_at)
    return SimpleNamespace(
        id=dep_id,
        name=name,
        sku=sku,
        properties=properties,
        system_data=system_data,
        tags=tags,  # None by default to test fallback
    )


def _make_total_metric_response(total=0.0, coverage_fraction=1.0, idle_days=7, num_series=1):
    """
    Build a mock AzureOpenAIRequests metric response with PT1M granularity.

    Each series gets (total / num_series) per datapoint so that bucket_total ==
    total when summed across all series in the same minute bucket.

    coverage_fraction: fraction of expected minute buckets to populate (1.0 = full coverage).
    num_series: number of separate dimension series (exercises cross-series aggregation).
    """
    expected = idle_days * 24 * 60
    usable = int(expected * coverage_fraction)
    now_utc = datetime.now(timezone.utc)
    metric_end_utc = (now_utc - timedelta(minutes=5)).replace(second=0, microsecond=0)

    total_per_series = (total / num_series) if num_series > 0 else 0.0

    timeseries_list = []
    for _ in range(num_series):
        data_points = [
            SimpleNamespace(
                total=total_per_series,
                time_stamp=metric_end_utc - timedelta(minutes=i + 1),
            )
            for i in range(usable)
        ]
        timeseries_list.append(SimpleNamespace(data=data_points))

    metric = SimpleNamespace(timeseries=timeseries_list)
    return SimpleNamespace(value=[metric])


def _make_clients(account, deployments, metric_fn=None, metric_response=None, idle_days=7):
    """Build mock CS and Monitor clients."""
    cs_client = SimpleNamespace(
        accounts=SimpleNamespace(list=lambda: [account]),
        deployments=SimpleNamespace(list=lambda rg, acct_name: deployments),
    )
    if metric_fn is not None:
        mon_client = SimpleNamespace(
            metrics=SimpleNamespace(list=lambda resource_uri, **kw: metric_fn(resource_uri, **kw))
        )
    else:
        resp = (
            metric_response
            if metric_response is not None
            else _make_total_metric_response(0.0, idle_days=idle_days)
        )
        mon_client = SimpleNamespace(metrics=SimpleNamespace(list=lambda *a, **kw: resp))
    return cs_client, mon_client


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_provisioned_deployment_detected():
    """Provisioned deployment with zero requests should be flagged."""
    account = _make_account()
    dep = _make_deployment()
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


def test_global_provisioned_sku_detected():
    """GlobalProvisionedManaged SKU should be flagged."""
    account = _make_account()
    dep = _make_deployment(sku_name="GlobalProvisionedManaged")
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].details["sku_name"] == "GlobalProvisionedManaged"


def test_datazone_provisioned_sku_detected():
    """DataZoneProvisionedManaged SKU should be flagged."""
    account = _make_account()
    dep = _make_deployment(sku_name="DataZoneProvisionedManaged")
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
    dep = _make_deployment()
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
    dep = _make_deployment(sku_name="Standard")
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_non_openai_model_format_skipped():
    """Deployment with model_format != 'OpenAI' must be skipped (spec 8.9)."""
    account = _make_account()
    dep = _make_deployment(model_format="AzureML")
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_model_format_case_sensitive_skipped():
    """model_format comparison is case-sensitive: 'openai' must not match."""
    account = _make_account()
    dep = _make_deployment(model_format="openai")
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_account_kind_does_not_gate_openai_scope():
    """Any account kind is scanned; only model_format establishes OpenAI scope (spec 9.1.4)."""
    account = _make_account(kind="AIServices")
    dep = _make_deployment(model_format="OpenAI")
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1


def test_account_kind_cognitive_services_scanned():
    """CognitiveServices kind is also scanned when model_format is 'OpenAI'."""
    account = _make_account(kind="CognitiveServices")
    dep = _make_deployment(model_format="OpenAI")
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1


def test_account_provisioning_state_not_succeeded_skipped():
    """Account with provisioning_state != 'Succeeded' must be skipped (spec 8.7)."""
    account = _make_account(provisioning_state="Creating")
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_deployment_provisioning_state_not_succeeded_skipped():
    """Deployment with provisioning_state != 'Succeeded' must be skipped (spec 8.8)."""
    account = _make_account()
    dep = _make_deployment(provisioning_state="Failed")
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_zero_ptu_capacity_skipped():
    """Deployment with capacity=0 is not billing-relevant and must be skipped (spec 8.11)."""
    account = _make_account()
    dep = _make_deployment(capacity=0)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_none_ptu_capacity_skipped():
    """Deployment with capacity=None must be skipped (spec 8.11)."""
    account = _make_account()
    dep = _make_deployment(capacity=None)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_young_deployment_skipped():
    """Deployment younger than effective idle_days must be skipped (spec 8.12)."""
    account = _make_account()
    dep = _make_deployment(age_days=3)  # 3 < 7 (default idle_days)
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
# Account / deployment ID and name guards
# ---------------------------------------------------------------------------


def test_missing_account_id_skipped():
    """Account with id=None must be skipped (spec 8.1)."""
    account = _make_account()
    account.id = None
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_missing_account_name_skipped():
    """Account with name=None must be skipped (spec 8.2)."""
    account = _make_account()
    account.name = None
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_missing_deployment_id_skipped():
    """Deployment with id=None must be skipped (spec 8.3)."""
    account = _make_account()
    dep = _make_deployment()
    dep.id = None
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_missing_deployment_name_skipped():
    """Deployment with name=None must be skipped (spec 8.4)."""
    account = _make_account()
    dep = _make_deployment()
    dep.name = None
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_unresolved_account_location_skipped():
    """Account with location=None must be skipped — unresolved location is a hard gate (spec 8.5)."""
    account = _make_account()
    account.location = None
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_empty_account_location_skipped():
    """Account with location='' must be skipped (spec 8.5)."""
    account = _make_account(location="")
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

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


def test_high_confidence_full_coverage():
    """Coverage >= 95% must produce HIGH confidence (spec 9.4)."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(
        account, [dep], metric_response=_make_total_metric_response(0.0, coverage_fraction=1.0)
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_medium_confidence_partial_coverage():
    """Coverage >= 80% but < 95% must produce MEDIUM confidence (spec 9.4)."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(
        account, [dep], metric_response=_make_total_metric_response(0.0, coverage_fraction=0.85)
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_low_coverage_skipped():
    """Coverage < 80% must produce UNKNOWN -> no finding (spec 9.3.11)."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(
        account, [dep], metric_response=_make_total_metric_response(0.0, coverage_fraction=0.79)
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------


def test_risk_always_high():
    """Risk must always be HIGH regardless of PTU capacity (spec 9.4)."""
    account = _make_account()
    dep = _make_deployment(capacity=1)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].risk.value == "high"


def test_risk_always_high_large_allocation():
    """Risk is HIGH even for large PTU allocations (spec 9.4)."""
    account = _make_account()
    dep = _make_deployment(capacity=100)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].risk.value == "high"


# ---------------------------------------------------------------------------
# Cost model
# ---------------------------------------------------------------------------


def test_estimated_monthly_cost_always_none():
    """estimated_monthly_cost_usd must always be None (spec 10)."""
    account = _make_account()
    dep = _make_deployment(capacity=100)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].estimated_monthly_cost_usd is None


def test_no_ptu_cost_constant():
    """No PTU price constant should be exported (spec 10)."""
    import cleancloud.providers.azure.rules.ai.openai_provisioned_idle as m

    assert not hasattr(
        m, "_PTU_MONTHLY_COST_USD"
    ), "Spec 10 forbids hardcoding a fixed PTU monthly estimate"


# ---------------------------------------------------------------------------
# Metric contract
# ---------------------------------------------------------------------------


def test_metric_queried_on_account_id():
    """AzureOpenAIRequests must be queried on the parent account ARM id (spec 9.3.1)."""
    account = _make_account()
    dep = _make_deployment()
    queried_ids = []

    def _mock_metrics(resource_uri, **kwargs):
        queried_ids.append(resource_uri)
        return _make_total_metric_response(0.0)

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(queried_ids) == 1
    assert queried_ids[0] == account.id
    assert "deployments" not in queried_ids[0].lower().split("/providers/")[1]


def test_metric_deployment_name_filter():
    """ModelDeploymentName dimension filter must scope the query to the deployment (spec 9.3.2)."""
    account = _make_account()
    dep = _make_deployment(name="my-gpt4o-deploy")
    call_kwargs = []

    def _mock_metrics(resource_uri, **kwargs):
        call_kwargs.append(dict(kwargs))
        return _make_total_metric_response(0.0)

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(call_kwargs) == 1
    assert "my-gpt4o-deploy" in call_kwargs[0].get("filter", "")
    assert "ModelDeploymentName" in call_kwargs[0].get("filter", "")


def test_metric_pt1m_granularity():
    """Metric query must use PT1M granularity (spec 9.3.3)."""
    account = _make_account()
    dep = _make_deployment()
    call_kwargs = []

    def _mock_metrics(resource_uri, **kwargs):
        call_kwargs.append(dict(kwargs))
        return _make_total_metric_response(0.0)

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert call_kwargs[0].get("interval") == "PT1M"


def test_metric_total_aggregation():
    """Metric query must use Total aggregation (spec 9.3.3)."""
    account = _make_account()
    dep = _make_deployment()
    call_kwargs = []

    def _mock_metrics(resource_uri, **kwargs):
        call_kwargs.append(dict(kwargs))
        return _make_total_metric_response(0.0)

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert call_kwargs[0].get("aggregation") == "Total"


def test_bucket_total_aggregates_across_series():
    """bucket_total must sum Total across all dimension series per minute bucket (spec 9.3.6.v)."""
    account = _make_account()
    dep = _make_deployment()
    # 2 series, each contributing 50/2=25 total per bucket; bucket_total=50 > 0 -> ACTIVE
    cs_client, mon_client = _make_clients(
        account, [dep], metric_response=_make_total_metric_response(50.0, num_series=2)
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []  # ACTIVE -> no finding


def test_multi_series_zero_is_idle():
    """Multiple zero-traffic series in same bucket must still produce ZERO (spec 9.3.12)."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(
        account, [dep], metric_response=_make_total_metric_response(0.0, num_series=3)
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1


def test_duplicate_timestamps_do_not_overstate_coverage():
    """Duplicate timestamps from multiple series must not inflate coverage count (spec 9.3.8)."""
    account = _make_account()
    dep = _make_deployment()
    # coverage_fraction=0.79 with num_series=2; correct coverage is still 0.79 (buckets deduped)
    # -> UNKNOWN -> no finding. Without deduplication the fake coverage would be 1.58 -> finding.
    cs_client, mon_client = _make_clients(
        account,
        [dep],
        metric_response=_make_total_metric_response(0.0, coverage_fraction=0.79, num_series=2),
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_no_timeseries_skipped():
    """Metric response with no timeseries produces UNKNOWN -> no finding."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep], metric_response=SimpleNamespace(value=[]))

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


# ---------------------------------------------------------------------------
# idle_days handling
# ---------------------------------------------------------------------------


def test_idle_days_minimum_is_1():
    """idle_days below 1 is clamped to 1 (spec 6.3)."""
    account = _make_account()
    dep = _make_deployment(age_days=1)
    cs_client, mon_client = _make_clients(account, [dep], idle_days=1)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
        idle_days=0,
    )

    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 1


def test_idle_days_age_gate_is_not_3():
    """idle_days minimum must be 1, not 3 — deployment aged 1 day with idle_days=1 must be flagged."""
    account = _make_account()
    dep = _make_deployment(age_days=1)
    cs_client, mon_client = _make_clients(account, [dep], idle_days=1)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
        idle_days=1,
    )

    assert len(findings) == 1


def test_deployment_exactly_at_idle_days_threshold():
    """Deployment aged exactly idle_days days must be flagged (age >= effective_idle_days)."""
    account = _make_account()
    dep = _make_deployment(age_days=7)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1


def test_idle_days_clamped_to_max():
    """idle_days above _MAX_IDLE_DAYS (30) must be clamped (large-window guard)."""
    account = _make_account()
    dep = _make_deployment(age_days=30)  # age == clamp ceiling
    cs_client, mon_client = _make_clients(account, [dep], idle_days=30)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
        idle_days=60,  # exceeds _MAX_IDLE_DAYS; clamped to 30
    )

    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 30


def test_idle_days_above_max_still_emits_when_age_matches_clamp():
    """Deployment aged exactly _MAX_IDLE_DAYS must emit when idle_days is clamped to that value."""
    account = _make_account()
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(account, [dep], idle_days=30)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
        idle_days=90,  # clamped to 30; age_days=30 >= 30
    )

    assert len(findings) == 1


def test_clamped_idle_days_visible_in_details():
    """When idle_days is clamped, details must expose both the original and applied values."""
    account = _make_account()
    dep = _make_deployment(age_days=30)
    cs_client, mon_client = _make_clients(account, [dep], idle_days=30)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
        idle_days=60,  # exceeds _MAX_IDLE_DAYS=30; clamped
    )

    assert len(findings) == 1
    d = findings[0].details
    assert d["idle_days_requested"] == 60  # user's original input preserved
    assert d["idle_days_threshold"] == 30  # effective value after clamping


def test_unclamped_idle_days_matches_requested():
    """When no clamping occurs, idle_days_requested and idle_days_threshold must be equal."""
    account = _make_account()
    dep = _make_deployment(age_days=14)
    cs_client, mon_client = _make_clients(account, [dep], idle_days=14)

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
        idle_days=14,
    )

    assert len(findings) == 1
    d = findings[0].details
    assert d["idle_days_requested"] == d["idle_days_threshold"] == 14


def test_deployment_one_day_under_threshold_skipped():
    """Deployment aged idle_days - 1 must be skipped."""
    account = _make_account()
    dep = _make_deployment(age_days=6)  # 6 < 7 (default idle_days)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


# ---------------------------------------------------------------------------
# Region filter
# ---------------------------------------------------------------------------


def test_region_filter_excludes_other_regions():
    """Accounts in other regions must be skipped when region_filter is set."""
    account = _make_account(location="westeurope")
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        region_filter="eastus",
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_region_filter_case_insensitive_match():
    """region_filter matches after lowercase normalization (spec 7)."""
    account = _make_account(location="East US")
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        region_filter="East US",
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].region == "east us"


def test_region_filter_spaces_preserved_in_normalization():
    """Spaces are preserved in normalized location (spec 7: do not remove spaces)."""
    account = _make_account(location="East US")
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    # "eastus" (no space) must NOT match "East US" -> "east us" (with space)
    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        region_filter="eastus",
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_region_is_normalized_location():
    """Finding region must be the normalized (lowercase) account location (spec 11.1)."""
    account = _make_account(location="East US")
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].region == "east us"


# ---------------------------------------------------------------------------
# Required details fields
# ---------------------------------------------------------------------------


def test_required_details_fields_present():
    """All required detail fields from spec 11.3 must be present."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    d = findings[0].details
    required = [
        "account_name",
        "resource_group",
        "subscription_id",
        "account_location",
        "account_kind",
        "deployment_name",
        "deployment_provisioning_state",
        "sku_name",
        "ptu_capacity",
        "model_format",
        "model_name",
        "model_version",
        "created_at",
        "age_days",
        "idle_days_requested",
        "idle_days_threshold",
        "idle_since_days",
        "metric_name",
        "metric_aggregation",
        "metric_result_reason",
        "metric_coverage_ratio",
        "metric_expected_bucket_count",
        "metric_observed_bucket_count",
        "metric_window_start_utc",
        "metric_end_utc",
        "tags",
    ]
    for field in required:
        assert field in d, f"Missing required detail field: {field}"


def test_details_values():
    """Detail fields must carry the correct values."""
    account = _make_account()
    dep = _make_deployment(capacity=20, model_name="gpt-4o", model_version="2024-05-13")
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    d = findings[0].details
    assert d["account_name"] == _ACCT_NAME
    assert d["resource_group"] == _RG
    assert d["subscription_id"] == _SUB
    assert d["account_location"] == "eastus"
    assert d["account_kind"] == "OpenAI"
    assert d["deployment_name"] == _DEP_NAME
    assert d["deployment_provisioning_state"] == "Succeeded"
    assert d["sku_name"] == "ProvisionedManaged"
    assert d["ptu_capacity"] == 20
    assert d["model_format"] == "OpenAI"
    assert d["model_name"] == "gpt-4o"
    assert d["model_version"] == "2024-05-13"
    assert d["idle_days_threshold"] == 7
    assert d["idle_since_days"] == 7
    assert d["metric_name"] == "AzureOpenAIRequests"
    assert d["metric_aggregation"] == "Total"
    assert d["metric_coverage_ratio"] is not None


def test_metric_result_reason_is_zero():
    """metric_result_reason must be 'ZERO' for emitted findings."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].details["metric_result_reason"] == "ZERO"


def test_metric_window_timestamps_are_iso_strings():
    """metric_window_start_utc and metric_end_utc must be ISO-format UTC strings."""
    from datetime import datetime

    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    d = findings[0].details
    for key in ("metric_window_start_utc", "metric_end_utc"):
        assert isinstance(d[key], str), f"{key} must be a string"
        parsed = datetime.fromisoformat(d[key])
        assert parsed.tzinfo is not None, f"{key} must be timezone-aware"


def test_metric_window_start_is_before_end():
    """metric_window_start_utc must be strictly before metric_end_utc."""
    from datetime import datetime

    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    d = findings[0].details
    start = datetime.fromisoformat(d["metric_window_start_utc"])
    end = datetime.fromisoformat(d["metric_end_utc"])
    assert start < end


def test_tags_never_none():
    """tags detail must never be None — defaults to {} (spec 7)."""
    account = _make_account()
    dep = _make_deployment(tags=None)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].details["tags"] is not None
    assert isinstance(findings[0].details["tags"], dict)


def test_deployment_tags_used_when_present():
    """Deployment tags must be preferred when present (spec 7)."""
    account = _make_account(tags={"env": "prod"})
    dep = _make_deployment(tags={"team": "ml"})
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].details["tags"] == {"team": "ml"}


def test_deployment_tags_empty_dict_when_none():
    """When deployment.tags is None, tags must be {} (spec 7)."""
    account = _make_account()
    dep = _make_deployment(tags=None)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].details["tags"] == {}


# ---------------------------------------------------------------------------
# Signals and evidence
# ---------------------------------------------------------------------------


def test_metric_name_in_signals():
    """AzureOpenAIRequests must appear in signals_used."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "AzureOpenAIRequests" in signal_text


def test_ptu_capacity_in_signals():
    """PTU capacity must appear in signals_used."""
    account = _make_account()
    dep = _make_deployment(capacity=15)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "15" in signal_text


def test_no_cost_estimate_in_signals():
    """No dollar cost estimate should appear in signals (spec 10)."""
    account = _make_account()
    dep = _make_deployment(capacity=10)
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    signal_text = " ".join(findings[0].evidence.signals_used)
    # No fixed per-PTU price should be stated
    assert "1,460" not in signal_text
    assert "14,600" not in signal_text


def test_no_processedprompt_fallback():
    """ProcessedPromptTokens must not be used as a fallback (spec 9.3.14)."""
    account = _make_account()
    dep = _make_deployment()
    metrics_called = []

    def _mock_metrics(resource_uri, **kwargs):
        metrics_called.append(kwargs.get("metricnames", ""))
        return SimpleNamespace(value=[])  # no timeseries

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert "ProcessedPromptTokens" not in metrics_called


def test_no_age_only_finding():
    """No finding must be emitted from age-only evidence (spec 9.2.5, 9.3.15)."""
    account = _make_account()
    dep = _make_deployment(age_days=365)  # very old deployment
    # Return empty metric response (UNKNOWN coverage)
    cs_client, mon_client = _make_clients(account, [dep], metric_response=SimpleNamespace(value=[]))

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    # Even a very old deployment must not produce a finding when metric is UNKNOWN
    assert findings == []


# ---------------------------------------------------------------------------
# Exception handling
# ---------------------------------------------------------------------------


def test_account_listing_failure_propagates():
    """Subscription-wide account inventory failure must propagate (spec 12)."""

    def _raise():
        raise RuntimeError("accounts.list() API unavailable")

    cs_client = SimpleNamespace(accounts=SimpleNamespace(list=_raise))
    mon_client = SimpleNamespace()

    with pytest.raises(RuntimeError):
        find_idle_openai_provisioned_deployments(
            subscription_id=_SUB,
            credential=None,
            client=cs_client,
            monitor_client=mon_client,
        )


def test_per_account_deployment_listing_failure_skipped():
    """Transient deployment listing failure must skip that account, not abort (spec 12)."""
    account_good = _make_account(name="good-account")
    account_bad = _make_account(name="bad-account")
    dep_good = _make_deployment(account="good-account")

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


def test_per_deployment_metric_failure_skipped():
    """Transient metric failure must skip that deployment, not produce a finding (spec 12)."""

    def _raise(*args, **kwargs):
        raise RuntimeError("Monitor API unavailable")

    account = _make_account()
    dep = _make_deployment()
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


def test_permission_error_propagates_from_metric():
    """PermissionError from metric query must propagate (not be swallowed)."""

    def _raise(*args, **kwargs):
        raise PermissionError("Missing Microsoft.Insights/metrics/read")

    account = _make_account()
    dep = _make_deployment()
    cs_client = SimpleNamespace(
        accounts=SimpleNamespace(list=lambda: [account]),
        deployments=SimpleNamespace(list=lambda rg, acct: [dep]),
    )
    mon_client = SimpleNamespace(metrics=SimpleNamespace(list=_raise))

    with pytest.raises(PermissionError):
        find_idle_openai_provisioned_deployments(
            subscription_id=_SUB,
            credential=None,
            client=cs_client,
            monitor_client=mon_client,
        )


def test_multiple_deployments_partial_failure():
    """One failing deployment must not prevent other deployments from being evaluated."""
    account = _make_account()
    dep_good = _make_deployment(name="good-dep")
    dep_bad = _make_deployment(name="bad-dep")

    call_count = [0]

    def _mock_metrics(resource_uri, **kwargs):
        call_count[0] += 1
        if "bad-dep" in kwargs.get("filter", ""):
            raise RuntimeError("transient error for bad-dep")
        return _make_total_metric_response(0.0)

    cs_client = SimpleNamespace(
        accounts=SimpleNamespace(list=lambda: [account]),
        deployments=SimpleNamespace(list=lambda rg, acct: [dep_good, dep_bad]),
    )
    mon_client = SimpleNamespace(
        metrics=SimpleNamespace(list=lambda resource_uri, **kw: _mock_metrics(resource_uri, **kw))
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1
    assert findings[0].details["deployment_name"] == "good-dep"


# ---------------------------------------------------------------------------
# Deployment provisioning_state camelCase fallback
# ---------------------------------------------------------------------------


def test_deployment_provisioning_state_camelcase_fallback():
    """provisioningState (camelCase) on deployment properties must be accepted as 'Succeeded'."""
    account = _make_account()
    dep = _make_deployment()
    # Replace properties with a shape that has only the camelCase field
    dep.properties = SimpleNamespace(
        model=SimpleNamespace(format="OpenAI", name="gpt-4o", version="2024-05-13"),
        provisioningState="Succeeded",
    )
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1


def test_deployment_provisioning_state_camelcase_failed_skipped():
    """provisioningState (camelCase) not 'Succeeded' on deployment must still skip."""
    account = _make_account()
    dep = _make_deployment()
    dep.properties = SimpleNamespace(
        model=SimpleNamespace(format="OpenAI", name="gpt-4o", version="2024-05-13"),
        provisioningState="Failed",
    )
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_deployment_provisioning_state_snake_case_preferred():
    """deployment provisioning_state (snake_case) takes precedence when both fields present."""
    account = _make_account()
    dep = _make_deployment()
    # snake_case says Succeeded, camelCase says Creating — snake_case wins
    dep.properties = SimpleNamespace(
        model=SimpleNamespace(format="OpenAI", name="gpt-4o", version="2024-05-13"),
        provisioning_state="Succeeded",
        provisioningState="Creating",
    )
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Tags dict enforcement
# ---------------------------------------------------------------------------


def test_tags_non_dict_normalized_to_empty_dict():
    """Non-dict tags value on deployment must be normalized to {} (not passed through)."""
    account = _make_account()
    dep = _make_deployment()
    dep.tags = "not-a-dict"  # e.g. malformed SDK shape
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings[0].details["tags"] == {}


# ---------------------------------------------------------------------------
# Bucket count observability
# ---------------------------------------------------------------------------


def test_bucket_counts_present_in_details():
    """metric_expected_bucket_count and metric_observed_bucket_count must be in details."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    d = findings[0].details
    assert "metric_expected_bucket_count" in d
    assert "metric_observed_bucket_count" in d
    assert isinstance(d["metric_expected_bucket_count"], int)
    assert isinstance(d["metric_observed_bucket_count"], int)


def test_bucket_counts_consistent_with_coverage_ratio():
    """observed / expected must equal metric_coverage_ratio exactly (within float precision)."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(
        account, [dep], metric_response=_make_total_metric_response(0.0, coverage_fraction=0.90)
    )

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    d = findings[0].details
    expected = d["metric_expected_bucket_count"]
    observed = d["metric_observed_bucket_count"]
    assert expected > 0
    assert observed <= expected
    assert abs(d["metric_coverage_ratio"] - observed / expected) < 1e-9


def test_bucket_counts_in_signal_string():
    """Signal string must include 'N/M minute buckets' for reviewer context."""
    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "minute buckets" in signal_text
    # Format: "<observed>/<expected> minute buckets"
    import re

    assert re.search(r"\d+/\d+ minute buckets", signal_text)


# ---------------------------------------------------------------------------
# _escape_odata_string unit tests
# ---------------------------------------------------------------------------


def test_escape_odata_string_single_quotes():
    """Single quotes must be doubled."""
    from cleancloud.providers.azure.rules.ai.openai_provisioned_idle import _escape_odata_string

    assert _escape_odata_string("it's") == "it''s"
    assert _escape_odata_string("a'b'c") == "a''b''c"
    assert _escape_odata_string("no quotes") == "no quotes"


def test_escape_odata_string_strips_control_chars():
    """ASCII control chars (< 0x20, except tab) must be removed."""
    from cleancloud.providers.azure.rules.ai.openai_provisioned_idle import _escape_odata_string

    assert _escape_odata_string("a\x00b") == "ab"
    assert _escape_odata_string("a\x1fb") == "ab"
    assert _escape_odata_string("a\nb") == "ab"  # LF stripped
    assert _escape_odata_string("a\tb") == "a\tb"  # tab preserved


def test_escape_odata_string_combined():
    """Quote-escaping and control-char stripping work together."""
    from cleancloud.providers.azure.rules.ai.openai_provisioned_idle import _escape_odata_string

    assert _escape_odata_string("it'\x00s") == "it''s"


# ---------------------------------------------------------------------------
# Coverage display precision
# ---------------------------------------------------------------------------


def test_coverage_signal_shows_two_decimal_places():
    """Both threshold and observed coverage in signals must use 2 decimal places."""
    import re

    account = _make_account()
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    signal_text = " ".join(findings[0].evidence.signals_used)
    # Both >=80.00% (threshold) and coverage: N.NN% must appear
    matches = re.findall(r"\d+\.\d{2}%", signal_text)
    assert (
        len(matches) >= 2
    ), f"Expected at least 2 two-decimal-place percentages in signal, got: {matches}"


# ---------------------------------------------------------------------------
# Filter injection / OData escaping
# ---------------------------------------------------------------------------


def test_deployment_name_single_quote_escaped_in_filter():
    """Single quotes in deployment name must be escaped as '' in the OData filter."""
    account = _make_account()
    dep = _make_deployment(name="team's-gpt4")
    call_kwargs = []

    def _mock_metrics(resource_uri, **kwargs):
        call_kwargs.append(dict(kwargs))
        return _make_total_metric_response(0.0)

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(call_kwargs) == 1
    odata_filter = call_kwargs[0].get("filter", "")
    # Escaped form: ModelDeploymentName eq 'team''s-gpt4'
    assert "team''s-gpt4" in odata_filter
    # The unescaped form must not appear (it would break OData parsing)
    assert "team's-gpt4" not in odata_filter.replace("team''s-gpt4", "")


def test_deployment_name_control_chars_stripped_from_filter():
    """ASCII control characters in deployment name must be stripped before building the filter."""
    account = _make_account()
    dep = _make_deployment(name="gpt4\x00-prod\x1f")  # NUL and US control chars
    call_kwargs = []

    def _mock_metrics(resource_uri, **kwargs):
        call_kwargs.append(dict(kwargs))
        return _make_total_metric_response(0.0)

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    odata_filter = call_kwargs[0].get("filter", "")
    assert "\x00" not in odata_filter
    assert "\x1f" not in odata_filter
    # The printable portion of the name must still be present
    assert "gpt4-prod" in odata_filter


def test_deployment_name_no_quotes_filter_unchanged():
    """Deployment names without single quotes must pass through unchanged."""
    account = _make_account()
    dep = _make_deployment(name="gpt4o-prod")
    call_kwargs = []

    def _mock_metrics(resource_uri, **kwargs):
        call_kwargs.append(dict(kwargs))
        return _make_total_metric_response(0.0)

    cs_client, mon_client = _make_clients(account, [dep], metric_fn=_mock_metrics)

    find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    odata_filter = call_kwargs[0].get("filter", "")
    assert "gpt4o-prod" in odata_filter


# ---------------------------------------------------------------------------
# Account provisioning state field name fallback
# ---------------------------------------------------------------------------


def test_account_provisioning_state_camelcase_fallback():
    """provisioningState (camelCase) on the properties object must be accepted as 'Succeeded'."""
    account = _make_account()
    # Replace properties with a shape that has only the camelCase field
    account.properties = SimpleNamespace(provisioningState="Succeeded")
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1


def test_account_provisioning_state_camelcase_failed_skipped():
    """provisioningState (camelCase) not 'Succeeded' must still be skipped."""
    account = _make_account()
    account.properties = SimpleNamespace(provisioningState="Failed")
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert findings == []


def test_account_provisioning_state_snake_case_preferred():
    """provisioning_state (snake_case) takes precedence when both fields are present."""
    account = _make_account()
    # snake_case says Succeeded but camelCase says Creating — snake_case wins
    account.properties = SimpleNamespace(
        provisioning_state="Succeeded",
        provisioningState="Creating",
    )
    dep = _make_deployment()
    cs_client, mon_client = _make_clients(account, [dep])

    findings = find_idle_openai_provisioned_deployments(
        subscription_id=_SUB,
        credential=None,
        client=cs_client,
        monitor_client=mon_client,
    )

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    """Rule must expose RULE_METADATA with correct fields."""
    from cleancloud.providers.azure.rules.ai.openai_provisioned_idle import RULE_METADATA

    assert RULE_METADATA["id"] == "azure.openai.provisioned_deployment.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "cognitiveservices"
    assert RULE_METADATA["cost_impact"] == "high"
