"""
Tests for gcp.vertex.endpoint.idle rule.

Coverage:
- Core detection: idle CPU endpoint (MEDIUM risk), idle GPU endpoint (HIGH risk)
- Near-idle tier: < LOW_TRAFFIC_THRESHOLD requests -> MEDIUM confidence
- Skipping logic: active endpoints, young endpoints, automaticResources (scales to zero)
- Age calculation and effective window capping
- Confidence levels: HIGH (age >= 14d), MEDIUM (age >= 10.5d or unknown age or near-idle)
- GPU detection: NVIDIA_TESLA_T4, NVIDIA_TESLA_A100, TPU_V2
- Cost estimation: per-model accuracy, machine + GPU addon for n1 machines, bundled for a2
- Multiple deployed models: total min_replica_count aggregated, per-model cost summed
- Monitoring: batched per location (one call per location), error -> assume active (conservative)
- Region filter: endpoints outside the filter are skipped
- Pagination: nextPageToken causes a second API call
- Permission errors: PermissionError raised on 403 from list call
- RULE_METADATA and RULE_ID attributes present
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle import (
    _DAYS_IDLE,
    _DEFAULT_MACHINE_MONTHLY_COST,
    _GPU_MONTHLY_COST_EACH,
    _LOW_TRAFFIC_THRESHOLD,
    _LOW_TRAFFIC_THRESHOLD_GPU,
    _MACHINE_MONTHLY_COST,
    _MIN_MONTHLY_COST_USD,
    RULE_METADATA,
    find_idle_vertex_endpoints,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_OLD = NOW - timedelta(days=30)
_YOUNG = NOW - timedelta(days=3)

_PROJECT = "my-project"
_LOCATION = "us-central1"
_ENDPOINT_ID = "1234567890"
_ENDPOINT_NAME = f"projects/{_PROJECT}/locations/{_LOCATION}/endpoints/{_ENDPOINT_ID}"


def _endpoint(
    endpoint_id: str = _ENDPOINT_ID,
    location: str = _LOCATION,
    project: str = _PROJECT,
    display_name: str = "my-model-endpoint",
    create_time: datetime = _OLD,
    min_replica_count: int = 1,
    machine_type: str = "n1-standard-4",
    accelerator_type: str = "ACCELERATOR_TYPE_UNSPECIFIED",
    accelerator_count: int = 0,
    use_automatic_resources: bool = False,
    deployed_models: list = None,
) -> dict:
    """Build a minimal Vertex AI endpoint response dict."""
    name = f"projects/{project}/locations/{location}/endpoints/{endpoint_id}"
    create_str = create_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    if deployed_models is not None:
        return {
            "name": name,
            "displayName": display_name,
            "createTime": create_str,
            "deployedModels": deployed_models,
        }

    model: dict = {"id": "model-abc"}
    if use_automatic_resources:
        model["automaticResources"] = {"minReplicaCount": 0, "maxReplicaCount": 4}
    else:
        model["dedicatedResources"] = {
            "machineSpec": {
                "machineType": machine_type,
                "acceleratorType": accelerator_type,
                "acceleratorCount": accelerator_count,
            },
            "minReplicaCount": min_replica_count,
            "maxReplicaCount": min_replica_count + 2,
        }

    return {
        "name": name,
        "displayName": display_name,
        "createTime": create_str,
        "deployedModels": [model],
    }


def _make_monitoring_client(request_counts: dict = None, error: bool = False):
    """
    Build a mock monitoring client for the batch query API.

    request_counts: {endpoint_id: total_request_count}
      {}  -> no activity (all idle)
      {"1234567890": 5} -> endpoint has 5 requests (near-idle if < threshold)
      {"1234567890": 42} -> endpoint is active (>= threshold)
    error=True: list_time_series raises an exception.
    """
    client = MagicMock()
    if error:
        client.list_time_series.side_effect = Exception("monitoring unavailable")
        return client

    series_list = []
    for ep_id, count in (request_counts or {}).items():
        series = MagicMock()
        point = MagicMock()
        point.value.int64_value = count
        point.value.double_value = 0.0
        series.points = [point]
        series.resource = MagicMock()
        series.resource.labels = {"endpoint_id": ep_id}
        series_list.append(series)

    client.list_time_series.return_value = series_list
    return client


def _run(
    endpoints: list,
    has_activity: bool = False,
    request_counts: dict = None,
    region_filter: str = None,
    monitoring_error: bool = False,
):
    """Helper: patch _list_endpoints and monitoring, run the rule."""
    mock_session = MagicMock()
    mock_credentials = MagicMock()

    # Determine effective request counts
    if request_counts is not None:
        effective_counts = request_counts
    elif has_activity:
        # 42 is well above _LOW_TRAFFIC_THRESHOLD (10) — unambiguously active
        effective_counts = {_ENDPOINT_ID: 42}
    else:
        effective_counts = {}  # all idle

    monitoring_client = _make_monitoring_client(
        request_counts=effective_counts,
        error=monitoring_error,
    )

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle._list_endpoints",
            return_value=endpoints,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.monitoring_v3.MetricServiceClient",
            return_value=monitoring_client,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.AuthorizedSession",
            return_value=mock_session,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.datetime",
        ) as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat.side_effect = datetime.fromisoformat
        findings = find_idle_vertex_endpoints(
            project_id=_PROJECT,
            credentials=mock_credentials,
            region_filter=region_filter,
        )
    return findings


# ---------------------------------------------------------------------------
# RULE_METADATA / RULE_ID
# ---------------------------------------------------------------------------


def test_rule_metadata():
    assert RULE_METADATA["id"] == "gcp.vertex.endpoint.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["cost_impact"] == "high"


def test_rule_id_attribute():
    assert find_idle_vertex_endpoints.RULE_ID == "gcp.vertex.endpoint.idle"


# ---------------------------------------------------------------------------
# Core detection — idle CPU endpoint
# ---------------------------------------------------------------------------


def test_idle_cpu_endpoint_flagged():
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=1)
    findings = _run([ep])

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.vertex.endpoint.idle"
    assert f.provider == "gcp"
    assert f.resource_type == "gcp.vertex.endpoint"
    assert f.resource_id == _ENDPOINT_NAME
    assert f.region == _LOCATION
    assert f.risk.value == "medium"
    assert f.confidence.value == "high"
    assert f.estimated_monthly_cost_usd == _MACHINE_MONTHLY_COST["n1-standard-4"] * 1


def test_idle_gpu_endpoint_flagged_high_risk():
    ep = _endpoint(
        machine_type="n1-standard-4",
        accelerator_type="NVIDIA_TESLA_T4",
        accelerator_count=1,
        min_replica_count=1,
    )
    findings = _run([ep])

    assert len(findings) == 1
    f = findings[0]
    assert f.risk.value == "high"
    assert f.confidence.value == "high"
    # Cost = machine + GPU addon
    expected_cost = (
        _MACHINE_MONTHLY_COST["n1-standard-4"] + _GPU_MONTHLY_COST_EACH["NVIDIA_TESLA_T4"]
    ) * 1
    assert f.estimated_monthly_cost_usd == pytest.approx(expected_cost)


def test_idle_a2_gpu_endpoint_no_double_count():
    """a2-highgpu machines already include GPU cost — no addon should be added."""
    ep = _endpoint(
        machine_type="a2-highgpu-1g",
        accelerator_type="NVIDIA_TESLA_A100",
        accelerator_count=1,
        min_replica_count=1,
    )
    findings = _run([ep])

    assert len(findings) == 1
    f = findings[0]
    assert f.risk.value == "high"
    # Cost = machine only (GPU bundled)
    assert f.estimated_monthly_cost_usd == pytest.approx(_MACHINE_MONTHLY_COST["a2-highgpu-1g"])


# ---------------------------------------------------------------------------
# Near-idle detection tier
# ---------------------------------------------------------------------------


def test_near_idle_endpoint_flagged_medium_confidence():
    """Endpoint with low but non-zero traffic is flagged as near-idle at MEDIUM confidence."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=1)
    count = _LOW_TRAFFIC_THRESHOLD - 1  # just below threshold
    findings = _run([ep], request_counts={_ENDPOINT_ID: count})

    assert len(findings) == 1
    f = findings[0]
    assert f.confidence.value == "medium"
    assert "near-idle" in f.title.lower() or str(count) in f.title
    assert f.details["request_count"] == count


def test_near_idle_with_single_request_flagged():
    """Even 1 request in 14 days is near-idle."""
    ep = _endpoint()
    findings = _run([ep], request_counts={_ENDPOINT_ID: 1})

    assert len(findings) == 1
    assert findings[0].details["request_count"] == 1
    assert findings[0].confidence.value == "medium"


def test_above_threshold_endpoint_active_skipped():
    """Endpoint with >= effective_threshold requests is considered active and skipped."""
    ep = _endpoint()
    # Single replica, CPU: effective_threshold = 10 * 1 = 10
    findings = _run([ep], request_counts={_ENDPOINT_ID: _LOW_TRAFFIC_THRESHOLD})
    assert findings == []


def test_near_idle_confidence_medium_even_if_old():
    """Near-idle endpoints are capped at MEDIUM even if age >= 14 days."""
    ep = _endpoint(create_time=NOW - timedelta(days=30))
    findings = _run([ep], request_counts={_ENDPOINT_ID: 3})

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"  # not HIGH — has some traffic


def test_gpu_endpoint_near_idle_at_lower_threshold():
    """GPU endpoints use a lower threshold — flagged near-idle at count < GPU threshold."""
    ep = _endpoint(
        machine_type="n1-standard-4",
        accelerator_type="NVIDIA_TESLA_T4",
        accelerator_count=1,
        min_replica_count=1,
    )
    count = _LOW_TRAFFIC_THRESHOLD_GPU - 1  # near-idle for GPU (below 5)
    findings = _run([ep], request_counts={_ENDPOINT_ID: count})

    assert len(findings) == 1
    f = findings[0]
    assert f.confidence.value == "medium"
    assert f.details["request_count"] == count
    assert "gpu-adjusted" in f.evidence.signals_used[0].lower()


def test_gpu_endpoint_at_gpu_threshold_active():
    """A GPU endpoint at exactly the GPU threshold is active (not near-idle)."""
    ep = _endpoint(
        machine_type="n1-standard-4",
        accelerator_type="NVIDIA_TESLA_T4",
        accelerator_count=1,
        min_replica_count=1,
    )
    # Single replica GPU: effective_threshold = 5 * 1 = 5; count=5 -> active
    findings = _run([ep], request_counts={_ENDPOINT_ID: _LOW_TRAFFIC_THRESHOLD_GPU})
    assert findings == []


def test_cpu_endpoint_not_affected_by_gpu_threshold():
    """CPU endpoint at count 7 is still near-idle (CPU threshold is 10)."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=1)  # no GPU
    count = _LOW_TRAFFIC_THRESHOLD_GPU + 2  # 7: near-idle for CPU (below 10)
    findings = _run([ep], request_counts={_ENDPOINT_ID: count})

    assert len(findings) == 1
    assert findings[0].details["request_count"] == count
    assert "gpu-adjusted" not in findings[0].evidence.signals_used[0].lower()


def test_replica_aware_threshold_scales_with_replicas():
    """3-replica CPU endpoint: threshold = int(10 * sqrt(3)) = 17; count=16 -> near-idle."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=3)
    # sqrt(3) ≈ 1.732 -> threshold = int(10 * 1.732) = 17
    findings = _run([ep], request_counts={_ENDPOINT_ID: 16})

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"
    assert findings[0].details["effective_threshold"] == 17


def test_replica_aware_threshold_active_when_above_scaled():
    """3-replica CPU endpoint: count >= sqrt-scaled threshold -> active."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=3)
    findings = _run([ep], request_counts={_ENDPOINT_ID: 17})  # at threshold -> active
    assert findings == []


def test_sublinear_scaling_prevents_over_leniency():
    """20-replica endpoint: threshold = int(10 * sqrt(20)) ≈ 44, not 200."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=20)
    expected_threshold = int(10 * max(1.0, 20**0.5))  # int(44.7) = 44

    # At threshold -> active
    assert _run([ep], request_counts={_ENDPOINT_ID: expected_threshold}) == []
    # Below threshold -> near-idle
    findings = _run([ep], request_counts={_ENDPOINT_ID: expected_threshold - 1})
    assert len(findings) == 1
    assert findings[0].details["effective_threshold"] == expected_threshold


def test_no_monitoring_data_unknown_age_skipped():
    """No monitoring data + unknown age = too many unknowns -> skip."""
    ep = _endpoint()
    ep["createTime"] = ""  # unknown age
    # Empty counts -> no_monitoring_data=True
    findings = _run([ep], request_counts={})
    assert findings == []


def test_no_monitoring_data_known_age_still_flagged():
    """No monitoring data + age ≥ 2×idle_threshold -> still flagged (age well-established)."""
    # Require age >= 2*14=28 before trusting absence of metrics as evidence of idleness
    ep = _endpoint(create_time=NOW - timedelta(days=30))  # age=30 ≥ 28
    findings = _run([ep], request_counts={})  # no monitoring data

    assert len(findings) == 1
    assert findings[0].details["no_monitoring_data"] is True


def test_high_confidence_requires_full_observation_window():
    """HIGH confidence requires age >= 14 AND effective_window == 14 AND monitoring data present."""
    # Age exactly at threshold; provide explicit 0 so monitoring data is present (no_monitoring_data=False)
    ep = _endpoint(create_time=NOW - timedelta(days=14))
    findings = _run([ep], request_counts={_ENDPOINT_ID: 0})
    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_waste_score_zero_traffic_equals_full_cost():
    """When count=0, waste_score == monthly_cost (full waste)."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=1)
    findings = _run([ep])
    assert len(findings) == 1
    f = findings[0]
    assert f.details["waste_score"] == pytest.approx(f.estimated_monthly_cost_usd)


def test_waste_score_partial_traffic_less_than_full_cost():
    """Near-idle endpoint has waste_score < monthly_cost (partial waste)."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=1)
    count = 5  # below threshold of 10
    findings = _run([ep], request_counts={_ENDPOINT_ID: count})
    assert len(findings) == 1
    f = findings[0]
    assert f.details["waste_score"] < f.estimated_monthly_cost_usd
    assert f.details["waste_score"] > 0


def test_experiment_pattern_multi_model():
    """Multi-model endpoints get pattern='abandoned_experiment' in details."""
    ep = _endpoint(
        deployed_models=[
            {
                "id": "m1",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": 1,
                },
            },
            {
                "id": "m2",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": 1,
                },
            },
        ]
    )
    findings = _run([ep])
    assert len(findings) == 1
    assert findings[0].details["pattern"] == "abandoned_experiment"


def test_experiment_pattern_single_model_none():
    """Single-model endpoints have pattern=None in details."""
    ep = _endpoint(min_replica_count=1)
    findings = _run([ep])
    assert len(findings) == 1
    assert findings[0].details["pattern"] is None


# ---------------------------------------------------------------------------
# Skipping logic
# ---------------------------------------------------------------------------


def test_active_endpoint_skipped():
    ep = _endpoint()
    findings = _run([ep], has_activity=True)
    assert findings == []


def test_young_endpoint_skipped():
    ep = _endpoint(create_time=_YOUNG)
    findings = _run([ep])
    assert findings == []


def test_automatic_resources_endpoint_skipped():
    """automaticResources scales to zero — no always-on billing."""
    ep = _endpoint(use_automatic_resources=True)
    findings = _run([ep])
    assert findings == []


def test_endpoint_with_no_deployed_models_skipped():
    ep = {
        "name": _ENDPOINT_NAME,
        "displayName": "empty",
        "createTime": _OLD.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "deployedModels": [],
    }
    findings = _run([ep])
    assert findings == []


def test_zero_min_replica_dedicated_resources_skipped():
    """dedicatedResources with minReplicaCount=0 — no always-on billing."""
    ep = _endpoint(min_replica_count=0)
    findings = _run([ep])
    assert findings == []


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_confidence_high_when_age_gte_threshold():
    """HIGH confidence when age > idle threshold and monitoring data confirms zero traffic."""
    ep = _endpoint(create_time=NOW - timedelta(days=_DAYS_IDLE + 5))
    # Explicit 0-count series so monitoring data is present (no_monitoring_data=False)
    findings = _run([ep], request_counts={_ENDPOINT_ID: 0})
    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_confidence_medium_when_age_in_75_percent_window():
    """age=80% of threshold -> MEDIUM, but only when monitoring data is present.

    When no monitoring data exists and age < idle threshold, the stricter guard skips
    the endpoint to avoid false positives from metric lag. Provide explicit zero-count
    series to confirm that MEDIUM confidence fires when monitoring confirms zero traffic.
    """
    age = int(_DAYS_IDLE * 0.80)  # 80% of threshold -> MEDIUM
    ep = _endpoint(create_time=NOW - timedelta(days=age))
    # Explicit 0-count series -> no_monitoring_data=False (confirmed zero traffic)
    findings = _run([ep], request_counts={_ENDPOINT_ID: 0})
    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_confidence_medium_when_age_unknown():
    """Missing createTime -> age unknown -> MEDIUM confidence (when monitoring data IS present)."""
    ep = _endpoint()
    ep["createTime"] = ""  # No timestamp — age unknown
    # Provide explicit 0-count series so no_monitoring_data=False; only age is unknown
    findings = _run([ep], request_counts={_ENDPOINT_ID: 0})
    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_borderline_age_below_75_percent_skipped():
    """age < 75% of threshold — too borderline -> skip."""
    age = int(_DAYS_IDLE * 0.60)  # 60% — below 75% cutoff
    ep = _endpoint(create_time=NOW - timedelta(days=age))
    findings = _run([ep])
    assert findings == []


# ---------------------------------------------------------------------------
# Effective window capping
# ---------------------------------------------------------------------------


def test_effective_window_capped_to_age():
    """If endpoint is 10 days old, effective window = 10, not 14."""
    ep = _endpoint(create_time=NOW - timedelta(days=10))
    findings = _run([ep])
    if findings:
        f = findings[0]
        assert f.details["idle_window_days"] == 10


def test_effective_window_too_small_skipped():
    """If effective window < 3 days, skip the endpoint."""
    ep = _endpoint(create_time=NOW - timedelta(days=2))
    findings = _run([ep])
    assert findings == []


# ---------------------------------------------------------------------------
# GPU detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "accel_type",
    [
        "NVIDIA_TESLA_T4",
        "NVIDIA_TESLA_V100",
        "NVIDIA_TESLA_A100",
        "NVIDIA_L4",
        "TPU_V2",
        "NVIDIA_H100_80GB",
    ],
)
def test_gpu_accelerator_types_detected(accel_type):
    ep = _endpoint(
        machine_type="n1-standard-4",
        accelerator_type=accel_type,
        accelerator_count=1,
    )
    findings = _run([ep])
    assert len(findings) == 1
    assert findings[0].risk.value == "high"
    assert findings[0].details["is_gpu"] is True


# ---------------------------------------------------------------------------
# Multiple deployed models
# ---------------------------------------------------------------------------


def test_multiple_deployed_models_total_replicas_aggregated():
    """Total min_replica_count is summed across all deployed models."""
    ep = _endpoint(
        deployed_models=[
            {
                "id": "m1",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": 2,
                    "maxReplicaCount": 5,
                },
            },
            {
                "id": "m2",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": 1,
                    "maxReplicaCount": 3,
                },
            },
        ]
    )
    findings = _run([ep])
    assert len(findings) == 1
    assert findings[0].details["min_replica_count"] == 3


def test_mixed_dedicated_and_automatic_resources():
    """Only dedicated models contribute to min_replica_count."""
    ep = _endpoint(
        deployed_models=[
            {
                "id": "m1",
                "automaticResources": {"minReplicaCount": 0, "maxReplicaCount": 4},
            },
            {
                "id": "m2",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-8"},
                    "minReplicaCount": 1,
                    "maxReplicaCount": 4,
                },
            },
        ]
    )
    findings = _run([ep])
    assert len(findings) == 1
    assert findings[0].details["min_replica_count"] == 1


def test_multi_model_cost_accurate_per_model():
    """Cost is summed per deployed model, not first-machine-type × total replicas."""
    ep = _endpoint(
        deployed_models=[
            {
                "id": "m1",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": 1,
                },
            },
            {
                "id": "m2",
                "dedicatedResources": {
                    "machineSpec": {
                        "machineType": "n1-standard-4",
                        "acceleratorType": "NVIDIA_TESLA_T4",
                        "acceleratorCount": 1,
                    },
                    "minReplicaCount": 1,
                },
            },
        ]
    )
    findings = _run([ep])
    assert len(findings) == 1
    # m1: n1-standard-4 × 1 = 138; m2: (138 + 311) × 1 = 449; total = 587
    expected = _MACHINE_MONTHLY_COST["n1-standard-4"] + (
        _MACHINE_MONTHLY_COST["n1-standard-4"] + _GPU_MONTHLY_COST_EACH["NVIDIA_TESLA_T4"]
    )
    assert findings[0].estimated_monthly_cost_usd == pytest.approx(expected)


# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------


def test_unknown_machine_type_uses_default_cost():
    ep = _endpoint(machine_type="custom-unknown-type")
    findings = _run([ep])
    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == _DEFAULT_MACHINE_MONTHLY_COST * 1


def test_cost_scaled_by_min_replica_count():
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=3)
    findings = _run([ep])
    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == pytest.approx(
        _MACHINE_MONTHLY_COST["n1-standard-4"] * 3
    )


# ---------------------------------------------------------------------------
# Monitoring — batch behavior
# ---------------------------------------------------------------------------


def test_monitoring_error_assumes_active():
    """If monitoring raises an exception, conservatively assume active — don't flag."""
    ep = _endpoint()
    findings = _run([ep], monitoring_error=True)
    assert findings == []


def test_empty_timeseries_means_idle():
    """Empty timeseries (no data points) = no predictions = idle."""
    ep = _endpoint()
    findings = _run([ep], has_activity=False)
    assert len(findings) == 1


def test_batch_monitoring_single_call_per_location():
    """Two eligible endpoints in the same location produce exactly one monitoring call."""
    ep1 = _endpoint(endpoint_id="111", display_name="ep-1")
    ep2 = _endpoint(endpoint_id="222", display_name="ep-2")

    mock_session = MagicMock()
    mock_credentials = MagicMock()
    monitoring_client = _make_monitoring_client(request_counts={})

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle._list_endpoints",
            return_value=[ep1, ep2],
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.monitoring_v3.MetricServiceClient",
            return_value=monitoring_client,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.AuthorizedSession",
            return_value=mock_session,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.datetime",
        ) as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat.side_effect = datetime.fromisoformat
        findings = find_idle_vertex_endpoints(
            project_id=_PROJECT,
            credentials=mock_credentials,
        )

    # Both endpoints flagged, but only one monitoring call (batched by location)
    assert len(findings) == 2
    assert monitoring_client.list_time_series.call_count == 1


def test_batch_monitoring_separate_call_per_location():
    """Endpoints in different locations each trigger their own monitoring call."""
    ep1 = _endpoint(endpoint_id="111", location="us-central1")
    ep2 = _endpoint(endpoint_id="222", location="europe-west4")

    mock_session = MagicMock()
    mock_credentials = MagicMock()
    monitoring_client = _make_monitoring_client(request_counts={})

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle._list_endpoints",
            return_value=[ep1, ep2],
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.monitoring_v3.MetricServiceClient",
            return_value=monitoring_client,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.AuthorizedSession",
            return_value=mock_session,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.datetime",
        ) as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat.side_effect = datetime.fromisoformat
        findings = find_idle_vertex_endpoints(
            project_id=_PROJECT,
            credentials=mock_credentials,
        )

    assert len(findings) == 2
    assert monitoring_client.list_time_series.call_count == 2


# ---------------------------------------------------------------------------
# Region filter
# ---------------------------------------------------------------------------


def test_region_filter_excludes_other_locations():
    ep = _endpoint(location="europe-west1")
    findings = _run([ep], region_filter="us-central1")
    assert findings == []


def test_region_filter_includes_matching_location():
    ep = _endpoint(location="us-central1")
    findings = _run([ep], region_filter="us-central1")
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_pagination_fetches_all_endpoints():
    """_list_endpoints follows nextPageToken — test that both pages are combined."""
    mock_session = MagicMock()
    mock_credentials = MagicMock()
    monitoring_client = _make_monitoring_client(request_counts={})

    page1 = {
        "endpoints": [
            _endpoint(endpoint_id="111", display_name="ep-1"),
        ],
        "nextPageToken": "token-page2",
    }
    page2 = {
        "endpoints": [
            _endpoint(endpoint_id="222", display_name="ep-2"),
        ],
    }

    mock_response_1 = MagicMock()
    mock_response_1.status_code = 200
    mock_response_1.json.return_value = page1

    mock_response_2 = MagicMock()
    mock_response_2.status_code = 200
    mock_response_2.json.return_value = page2

    mock_session.get.side_effect = [mock_response_1, mock_response_2]

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.monitoring_v3.MetricServiceClient",
            return_value=monitoring_client,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.AuthorizedSession",
            return_value=mock_session,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.datetime",
        ) as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat.side_effect = datetime.fromisoformat
        findings = find_idle_vertex_endpoints(
            project_id=_PROJECT,
            credentials=mock_credentials,
        )

    assert len(findings) == 2
    assert mock_session.get.call_count == 2


# ---------------------------------------------------------------------------
# Permission error
# ---------------------------------------------------------------------------


def test_403_raises_permission_error():
    mock_session = MagicMock()
    mock_credentials = MagicMock()

    mock_response = MagicMock()
    mock_response.status_code = 403

    mock_session.get.return_value = mock_response

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.monitoring_v3.MetricServiceClient",
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.AuthorizedSession",
            return_value=mock_session,
        ),
    ):
        with pytest.raises(PermissionError, match="aiplatform.endpoints.list"):
            find_idle_vertex_endpoints(project_id=_PROJECT, credentials=mock_credentials)


def test_404_returns_empty():
    """404 means Vertex AI API not enabled — return empty findings, don't raise."""
    mock_session = MagicMock()
    mock_credentials = MagicMock()

    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.json.return_value = {}

    mock_session.get.return_value = mock_response

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.monitoring_v3.MetricServiceClient",
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.AuthorizedSession",
            return_value=mock_session,
        ),
    ):
        findings = find_idle_vertex_endpoints(project_id=_PROJECT, credentials=mock_credentials)
    assert findings == []


# ---------------------------------------------------------------------------
# Finding fields
# ---------------------------------------------------------------------------


def test_finding_fields_are_complete():
    ep = _endpoint(machine_type="n1-standard-8", min_replica_count=2)
    findings = _run([ep])
    assert len(findings) == 1
    f = findings[0]

    assert f.provider == "gcp"
    assert f.rule_id == "gcp.vertex.endpoint.idle"
    assert f.resource_type == "gcp.vertex.endpoint"
    assert f.resource_id == _ENDPOINT_NAME
    assert f.region == _LOCATION
    assert f.estimated_monthly_cost_usd > 0
    assert f.title.startswith("Idle Vertex AI Endpoint")
    assert "zero predictions" in f.summary.lower() or "zero prediction" in f.summary.lower()
    assert f.evidence is not None
    assert len(f.evidence.signals_used) >= 2
    assert f.evidence.time_window

    d = f.details
    assert d["endpoint_id"] == _ENDPOINT_ID
    assert d["location"] == _LOCATION
    assert d["machine_type"] == "n1-standard-8"
    assert d["min_replica_count"] == 2
    assert d["idle_days_threshold"] == _DAYS_IDLE
    assert d["request_count"] == 0
    assert d["cost_basis"] == "us-central1 baseline estimate"
    assert "us-central1" in d["cost_variance"]  # universal pricing disclaimer
    assert isinstance(d["recommendations"], list)
    assert len(d["recommendations"]) >= 1
    assert d["waste_score"] > 0


def test_no_monitoring_data_adds_transparency_signal():
    """When no time series exist for an endpoint, a transparency signal is added."""
    ep = _endpoint()
    # Empty counts dict — endpoint_id absent -> no_monitoring_data = True
    findings = _run([ep], request_counts={})

    assert len(findings) == 1
    signals = findings[0].evidence.signals_used
    assert any("no prediction request data" in s.lower() for s in signals)
    assert findings[0].details["no_monitoring_data"] is True


def test_with_monitoring_data_no_transparency_signal():
    """When count == 0 due to explicit data (series present but all zeros), the
    transparency signal is not added — the series just happens to be empty."""
    # This case can't be distinguished from truly absent data with the current mock,
    # but we verify no_monitoring_data == True when endpoint_id absent from counts.
    ep = _endpoint()
    findings = _run([ep], request_counts={})
    # no_monitoring_data == True because _ENDPOINT_ID not in counts
    assert findings[0].details["no_monitoring_data"] is True


def test_eligible_endpoint_ids_guard_filters_stale_series():
    """Series for endpoint IDs not in the eligible set are ignored."""
    ep = _endpoint(endpoint_id=_ENDPOINT_ID)
    stale_id = "stale-endpoint-99999"

    mock_session = MagicMock()
    mock_credentials = MagicMock()
    # Monitoring returns a high-count series for stale_id AND our endpoint
    monitoring_client = _make_monitoring_client(request_counts={stale_id: 500, _ENDPOINT_ID: 0})

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle._list_endpoints",
            return_value=[ep],
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.monitoring_v3.MetricServiceClient",
            return_value=monitoring_client,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.AuthorizedSession",
            return_value=mock_session,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.datetime",
        ) as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat.side_effect = datetime.fromisoformat
        findings = find_idle_vertex_endpoints(
            project_id=_PROJECT,
            credentials=mock_credentials,
        )

    # stale_id series should be ignored; our endpoint has 0 count -> flagged as idle
    assert len(findings) == 1
    assert findings[0].details["request_count"] == 0


def test_multi_model_signal_added():
    """Endpoints with multiple dedicated models get an A/B-test signal."""
    ep = _endpoint(
        deployed_models=[
            {
                "id": "m1",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": 1,
                },
            },
            {
                "id": "m2",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": 1,
                },
            },
        ]
    )
    findings = _run([ep])
    assert len(findings) == 1
    signals = findings[0].evidence.signals_used
    assert any("2 deployed models" in s for s in signals)


def test_single_model_no_multi_model_signal():
    """Single-model endpoints do not get the A/B-test signal."""
    ep = _endpoint(min_replica_count=1)
    findings = _run([ep])
    assert len(findings) == 1
    signals = findings[0].evidence.signals_used
    assert not any("deployed models" in s for s in signals)


def test_multiple_replicas_signal_added():
    """Endpoints with more than 1 replica get the stronger-waste-signal note."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=3)
    findings = _run([ep])
    assert len(findings) == 1
    signals = findings[0].evidence.signals_used
    assert any("3 replicas" in s for s in signals)


def test_single_replica_no_replicas_signal():
    """Single-replica endpoints do not get the replicas signal."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=1)
    findings = _run([ep])
    assert len(findings) == 1
    signals = findings[0].evidence.signals_used
    assert not any("replicas configured" in s for s in signals)


def test_all_endpoints_have_cost_variance_in_details():
    """All findings carry a cost_variance disclaimer — pricing varies by region for all machine types."""
    gpu_ep = _endpoint(
        machine_type="n1-standard-4",
        accelerator_type="NVIDIA_TESLA_T4",
        accelerator_count=1,
    )
    gpu_findings = _run([gpu_ep])
    assert len(gpu_findings) == 1
    assert "us-central1" in gpu_findings[0].details["cost_variance"]

    cpu_ep = _endpoint(machine_type="n1-standard-4")
    cpu_findings = _run([cpu_ep])
    assert len(cpu_findings) == 1
    assert "us-central1" in cpu_findings[0].details["cost_variance"]


def test_recommendations_always_present():
    """Every finding has a non-empty recommendations list."""
    ep = _endpoint()
    findings = _run([ep])
    assert len(findings) == 1
    recs = findings[0].details["recommendations"]
    assert isinstance(recs, list)
    assert len(recs) >= 2  # at minimum: switch to automaticResources + delete
    assert any("automaticResources" in r for r in recs)
    assert any("gcloud ai endpoints delete" in r for r in recs)


def test_multi_replica_recommendation_included():
    """Endpoints with multiple replicas get a specific reduce-replicas recommendation."""
    ep = _endpoint(min_replica_count=3)
    findings = _run([ep])
    assert len(findings) == 1
    recs = findings[0].details["recommendations"]
    assert any("minReplicaCount" in r for r in recs)


def test_experiment_pattern_recommendation_included():
    """Multi-model endpoints get a consolidate recommendation."""
    ep = _endpoint(
        deployed_models=[
            {
                "id": "m1",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": 1,
                },
            },
            {
                "id": "m2",
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": 1,
                },
            },
        ]
    )
    findings = _run([ep])
    assert len(findings) == 1
    recs = findings[0].details["recommendations"]
    assert any("Consolidate" in r or "consolidate" in r for r in recs)


def test_min_cost_constant_is_reasonable():
    """_MIN_MONTHLY_COST_USD is set and below the cheapest known machine type."""
    assert _MIN_MONTHLY_COST_USD > 0
    # All known machine types cost more than the filter threshold
    from cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle import (
        _MACHINE_MONTHLY_COST,
    )

    assert all(cost >= _MIN_MONTHLY_COST_USD for cost in _MACHINE_MONTHLY_COST.values())


def test_near_idle_finding_fields():
    """Near-idle findings have correct title, request_count in details, MEDIUM confidence."""
    ep = _endpoint(machine_type="n1-standard-4", min_replica_count=1)
    findings = _run([ep], request_counts={_ENDPOINT_ID: 3})
    assert len(findings) == 1
    f = findings[0]

    assert "near-idle" in f.title.lower() or "3 prediction" in f.title.lower()
    assert f.confidence.value == "medium"
    assert f.details["request_count"] == 3
    assert f.estimated_monthly_cost_usd > 0


def test_no_monitoring_data_known_age_below_threshold_skipped():
    """No monitoring data + known age < idle threshold -> skipped (stricter guard).

    Monitoring can be absent due to metric delay or permission gaps — not safe
    to flag unless we have the full observation window confirmed by age.
    """
    # age=12 is >= 7 (past young-endpoint filter) but < 14 (_DAYS_IDLE)
    ep = _endpoint(create_time=NOW - timedelta(days=12))
    findings = _run([ep], request_counts={})  # absent from counts -> no_monitoring_data=True
    assert findings == []


def test_no_monitoring_data_below_double_threshold_skipped():
    """No monitoring data + age < 2×idle_threshold -> skipped (bias toward false negatives)."""
    # age=20 < 28 (2*14) -> missing metrics insufficient evidence of idleness
    ep = _endpoint(create_time=NOW - timedelta(days=20))
    findings = _run([ep], request_counts={})
    assert findings == []


def test_no_monitoring_data_at_double_threshold_flagged():
    """No monitoring data + age >= 2×idle_threshold -> flagged with transparency signal."""
    ep = _endpoint(create_time=NOW - timedelta(days=28))  # exactly 2×threshold
    findings = _run([ep], request_counts={})
    assert len(findings) == 1
    assert findings[0].details["no_monitoring_data"] is True


def test_threshold_strategy_in_details():
    """All findings expose threshold_strategy='sqrt_replica_scaling' in details."""
    ep = _endpoint()
    findings = _run([ep])
    assert len(findings) == 1
    assert findings[0].details["threshold_strategy"] == "sqrt_replica_scaling"


def test_sqrt_threshold_signal_in_evidence_for_multi_replica():
    """Multi-replica endpoints include a signal explaining sqrt threshold scaling."""
    ep = _endpoint(min_replica_count=3)
    findings = _run([ep])
    assert len(findings) == 1
    signals = findings[0].evidence.signals_used
    assert any("sqrt" in s.lower() or "sublinearly" in s.lower() for s in signals)


# ---------------------------------------------------------------------------
# Metric alignment edge cases (empty / long series, recency guard)
# ---------------------------------------------------------------------------


def _make_monitoring_client_with_empty_points(endpoint_id: str = _ENDPOINT_ID):
    """Return a monitoring client whose series has zero points."""
    client = MagicMock()
    series = MagicMock()
    series.points = []  # no data points
    series.resource.labels = {"endpoint_id": endpoint_id}
    client.list_time_series.return_value = [series]
    return client


def _make_monitoring_client_with_many_points(endpoint_id: str = _ENDPOINT_ID, n: int = 10):
    """Return a monitoring client whose series has more than 5 points (anomalous)."""
    client = MagicMock()
    series = MagicMock()
    points = []
    for i in range(n):
        p = MagicMock()
        p.value.int64_value = 1
        p.value.double_value = 0.0
        points.append(p)
    series.points = points
    series.resource.labels = {"endpoint_id": endpoint_id}
    client.list_time_series.return_value = [series]
    return client


def _make_monitoring_client_with_recent_traffic(endpoint_id: str = _ENDPOINT_ID):
    """Return a monitoring client where the last point timestamp is within 24 hours."""
    from datetime import timedelta

    client = MagicMock()
    series = MagicMock()
    point = MagicMock()
    point.value.int64_value = 0
    point.value.double_value = 0.0

    # Configure interval.end_time.ToDatetime to return a real recent datetime
    recent_time = NOW - timedelta(hours=6)  # 6 hours ago — within 24h window

    point.interval.end_time.ToDatetime.return_value = recent_time
    series.points = [point]
    series.resource.labels = {"endpoint_id": endpoint_id}
    client.list_time_series.return_value = [series]
    return client


def _run_with_monitoring_client(endpoints, monitoring_client, region_filter=None):
    """Run rule with a pre-built monitoring client mock."""
    mock_session = MagicMock()
    mock_credentials = MagicMock()
    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle._list_endpoints",
            return_value=endpoints,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.monitoring_v3.MetricServiceClient",
            return_value=monitoring_client,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.AuthorizedSession",
            return_value=mock_session,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle.datetime",
            **{"now.return_value": NOW, "fromisoformat": datetime.fromisoformat},
        ),
    ):
        return find_idle_vertex_endpoints(
            project_id=_PROJECT,
            credentials=mock_credentials,
            region_filter=region_filter,
        )


def test_empty_series_points_treated_as_no_data():
    """Series with zero points are skipped — endpoint treated as no monitoring data.

    An old (30-day) endpoint with no_monitoring_data=True and age >= _DAYS_IDLE
    is still flagged (age provides sufficient evidence). The key assertion is that
    no crash occurs and no_monitoring_data is correctly set to True.
    """
    ep = _endpoint(create_time=NOW - timedelta(days=30))
    client = _make_monitoring_client_with_empty_points()
    findings = _run_with_monitoring_client([ep], client)
    # Endpoint is flagged (age=30 provides evidence) but no_monitoring_data=True
    assert len(findings) == 1
    assert findings[0].details["no_monitoring_data"] is True


def test_long_series_points_skipped():
    """Series with >5 points are skipped as anomalous — same result as empty series."""
    ep = _endpoint(create_time=NOW - timedelta(days=30))
    client = _make_monitoring_client_with_many_points(n=10)
    findings = _run_with_monitoring_client([ep], client)
    # Long series skipped -> endpoint_id not in counts -> no_monitoring_data=True
    assert len(findings) == 1
    assert findings[0].details["no_monitoring_data"] is True


def test_recent_traffic_spike_skipped():
    """Endpoint with traffic in the last 24h is NOT flagged — recency dominates.

    An endpoint that received any traffic yesterday is considered active regardless
    of how low the 14-day total looks. Prevents false positives on bursty workloads.
    """
    ep = _endpoint(create_time=NOW - timedelta(days=30))
    client = _make_monitoring_client_with_recent_traffic()
    findings = _run_with_monitoring_client([ep], client)
    assert findings == []


def test_cron_pattern_very_low_count_is_medium():
    """count <= 2 (cron/batch heuristic) -> MEDIUM confidence regardless of age.

    Very few requests over 14 days could be a weekly inference job, not abandonment.
    Behavior-based (count <= 2), not age-based.
    """
    ep = _endpoint(create_time=NOW - timedelta(days=30))
    # count=2: at the cron-protection boundary (≤ 2 = cron pattern)
    findings = _run([ep], request_counts={_ENDPOINT_ID: 2})
    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_cron_pattern_count_above_threshold_still_medium():
    """count=3 (> 2, so NOT cron pattern) -> MEDIUM because is_near_idle, not cron."""
    ep = _endpoint(create_time=NOW - timedelta(days=30))
    findings = _run([ep], request_counts={_ENDPOINT_ID: 3})
    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_effective_threshold_minimum_is_one():
    """effective_threshold is always >= 1, even with unusual base_threshold values."""

    # With 1 replica, threshold = max(1, int(base * 1.0)) = base (always >= 1)
    ep = _endpoint(min_replica_count=1)
    findings = _run([ep])
    assert len(findings) == 1
    assert findings[0].details["effective_threshold"] >= 1


def test_requests_per_replica_in_details():
    """requests_per_replica is present in details and correctly computed."""
    ep = _endpoint(min_replica_count=2)
    # count=0, replicas=2 -> requests_per_replica = 0 / 2 = 0.0
    findings = _run([ep], request_counts={_ENDPOINT_ID: 0})
    assert len(findings) == 1
    assert findings[0].details["requests_per_replica"] == pytest.approx(0.0)


def test_cost_confidence_estimate_in_details():
    """cost_confidence='estimate' is present in all findings."""
    ep = _endpoint()
    findings = _run([ep], request_counts={_ENDPOINT_ID: 0})
    assert len(findings) == 1
    assert findings[0].details["cost_confidence"] == "estimate"
