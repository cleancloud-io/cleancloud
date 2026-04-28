"""
Tests for gcp.vertex.endpoint.idle rule.

Coverage:
- _parse_location: valid name, missing segment, empty segment
- _parse_endpoint_id: valid name, empty string
- _parse_rfc3339_utc: Z suffix, +00:00 suffix, empty, invalid
- _classify_deployed_models: dedicated in-scope, automatic in-scope (spec 3.4),
  shared-only, floor-0, malformed minReplicaCount, bad createTime, GPU detection,
  mixed resource modes, multiple models
- _evaluate_endpoint_telemetry: no points, leading/trailing/interior gap > window/2
  -> unresolved, gap exactly at threshold -> complete, dense zero points, dense
  nonzero points, float double_value not truncated to int
- find_idle_vertex_endpoints integration: idle CPU (MEDIUM risk), idle GPU (HIGH risk),
  automatic resources in-scope (spec 3.4), scale-to-zero skipped, sharedResources skipped,
  active endpoint skipped, telemetry unresolved skipped, monitoring client failure,
  monitoring query failure, young endpoint skipped, region filter, pagination,
  estimated_monthly_cost_usd is None, confidence always HIGH, details fields,
  RULE_METADATA, RULE_ID attribute
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle import (
    _DEFAULT_IDLE_DAYS,
    _REQUEST_METRIC_RESOURCE_TYPE,
    _REQUEST_METRIC_TYPE,
    RULE_METADATA,
    _classify_deployed_models,
    _evaluate_endpoint_telemetry,
    _parse_endpoint_id,
    _parse_location,
    _parse_rfc3339_utc,
    find_idle_vertex_endpoints,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
_WINDOW_START = NOW - timedelta(days=_DEFAULT_IDLE_DAYS)

_PROJECT = "my-project"
_LOCATION = "us-central1"
_ENDPOINT_ID = "1234567890"
_ENDPOINT_NAME = f"projects/{_PROJECT}/locations/{_LOCATION}/endpoints/{_ENDPOINT_ID}"

# A timestamp well before the observation window (endpoint and models are "old")
_OLD = NOW - timedelta(days=30)
_OLD_STR = _OLD.strftime("%Y-%m-%dT%H:%M:%SZ")

# A timestamp inside the observation window (endpoint is too young)
_YOUNG = NOW - timedelta(days=5)
_YOUNG_STR = _YOUNG.strftime("%Y-%m-%dT%H:%M:%SZ")

# Telemetry: dense 3-point fixtures that satisfy all gap checks for a 14-day window.
# Gap threshold = window/2 = 7 days. Points:
#   P1 at _WINDOW_START+1h  (leading gap = 1h  << 7d)
#   P2 at NOW-7d             (P1→P2 gap ≈ 6d23h  < 7d)
#   P3 at NOW-1h             (P2→P3 gap ≈ 6d23h  < 7d; trailing gap = 1h << 7d)
_ZERO_POINTS = [
    (0, _WINDOW_START + timedelta(hours=1)),
    (0, NOW - timedelta(days=7)),
    (0, NOW - timedelta(hours=1)),
]
_ACTIVE_POINTS = [
    (0, _WINDOW_START + timedelta(hours=1)),
    (42, NOW - timedelta(days=7)),
    (0, NOW - timedelta(hours=1)),
]


# ---------------------------------------------------------------------------
# Endpoint / deployed-model builders
# ---------------------------------------------------------------------------


def _endpoint(
    endpoint_id: str = _ENDPOINT_ID,
    location: str = _LOCATION,
    project: str = _PROJECT,
    display_name: str = "my-endpoint",
    create_time_str: str = _OLD_STR,
    deployed_models: list = None,
) -> dict:
    """Build a minimal Vertex AI endpoint response dict."""
    name = f"projects/{project}/locations/{location}/endpoints/{endpoint_id}"
    return {
        "name": name,
        "displayName": display_name,
        "createTime": create_time_str,
        "deployedModels": deployed_models if deployed_models is not None else [],
    }


def _dedicated(
    min_replica: int = 1,
    machine_type: str = "n1-standard-4",
    accel_type: str = "ACCELERATOR_TYPE_UNSPECIFIED",
    accel_count: int = 0,
    create_time_str: str = _OLD_STR,
) -> dict:
    return {
        "id": "m1",
        "createTime": create_time_str,
        "dedicatedResources": {
            "machineSpec": {
                "machineType": machine_type,
                "acceleratorType": accel_type,
                "acceleratorCount": accel_count,
            },
            "minReplicaCount": min_replica,
            "maxReplicaCount": max(min_replica, 1) + 2,
        },
    }


def _automatic(min_replica: int = 1, create_time_str: str = _OLD_STR) -> dict:
    return {
        "id": "m2",
        "createTime": create_time_str,
        "automaticResources": {
            "minReplicaCount": min_replica,
            "maxReplicaCount": min_replica + 3,
        },
    }


def _shared(create_time_str: str = _OLD_STR) -> dict:
    return {
        "id": "m3",
        "createTime": create_time_str,
        "sharedResources": "projects/p/locations/l/deploymentResourcePools/pool1",
    }


# ---------------------------------------------------------------------------
# Integration test runner
# ---------------------------------------------------------------------------


def _run(
    endpoints: list,
    telemetry: dict = None,
    query_fails: bool = False,
    client_fails: bool = False,
    region_filter: str = None,
    idle_days: int = _DEFAULT_IDLE_DAYS,
) -> list:
    """
    Run find_idle_vertex_endpoints with mocked dependencies.

    telemetry: {endpoint_id: [(value, timestamp), ...]}
        None  -> no series returned (telemetry_coverage_state = unresolved)
        {}    -> empty dict (same)
        {id: _ZERO_POINTS} -> zero requests, coverage complete
        {id: _ACTIVE_POINTS} -> nonzero requests, coverage complete -> not idle
    query_fails: True -> _query_location_request_counts returns None (query failure)
    client_fails: True -> MetricServiceClient() raises (all endpoints skip)
    """

    def _mock_query(client, project_id, location, ws, we, eids):
        if query_fails:
            return None
        if telemetry is None:
            return {}
        return {eid: pts for eid, pts in telemetry.items() if eid in eids}

    client_factory = (
        MagicMock(side_effect=Exception("client init failed"))
        if client_fails
        else MagicMock(return_value=MagicMock())
    )

    module = "cleancloud.providers.gcp.rules.ai.vertex_endpoint_idle"
    with (
        patch(f"{module}._list_endpoints", return_value=endpoints),
        patch(f"{module}.monitoring_v3.MetricServiceClient", client_factory),
        patch(f"{module}.AuthorizedSession", return_value=MagicMock()),
        patch(f"{module}._query_location_request_counts", side_effect=_mock_query),
        patch(f"{module}.datetime") as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat.side_effect = datetime.fromisoformat
        findings = find_idle_vertex_endpoints(
            project_id=_PROJECT,
            credentials=MagicMock(),
            region_filter=region_filter,
            idle_days=idle_days,
        )
    return findings


# ===========================================================================
# Unit tests: _parse_location
# ===========================================================================


def test_parse_location_valid_name():
    name = "projects/p/locations/us-central1/endpoints/123"
    assert _parse_location(name) == "us-central1"


def test_parse_location_missing_segment_returns_none():
    assert _parse_location("projects/p/endpoints/123") is None


def test_parse_location_empty_string_returns_none():
    assert _parse_location("") is None


def test_parse_location_segment_present_but_empty_returns_none():
    # "locations/" with no value after it -> parts has "" after "locations"
    assert _parse_location("projects/p/locations/") is None


# ===========================================================================
# Unit tests: _parse_endpoint_id
# ===========================================================================


def test_parse_endpoint_id_valid():
    name = "projects/p/locations/us-central1/endpoints/9876"
    assert _parse_endpoint_id(name) == "9876"


def test_parse_endpoint_id_empty_string():
    assert _parse_endpoint_id("") == ""


# ===========================================================================
# Unit tests: _parse_rfc3339_utc
# ===========================================================================


def test_parse_rfc3339_utc_z_suffix():
    dt = _parse_rfc3339_utc("2026-01-01T00:00:00Z")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert dt.year == 2026


def test_parse_rfc3339_utc_plus00():
    dt = _parse_rfc3339_utc("2026-01-01T00:00:00+00:00")
    assert dt is not None
    assert dt.tzinfo == timezone.utc


def test_parse_rfc3339_utc_empty_string_returns_none():
    assert _parse_rfc3339_utc("") is None


def test_parse_rfc3339_utc_invalid_string_returns_none():
    assert _parse_rfc3339_utc("not-a-timestamp") is None


def test_parse_rfc3339_utc_none_returns_none():
    assert _parse_rfc3339_utc(None) is None


# ===========================================================================
# Unit tests: _classify_deployed_models
# ===========================================================================


def test_classify_empty_list():
    result = _classify_deployed_models([], now=NOW)
    assert result["skip"] is False
    assert result["provisioned_floor"] == 0
    assert result["in_scope_count"] == 0
    assert result["has_accelerator"] is False


def test_classify_dedicated_min_replica_one_in_scope():
    models = [_dedicated(min_replica=1)]
    result = _classify_deployed_models(models, now=NOW)
    assert result["skip"] is False
    assert result["provisioned_floor"] == 1
    assert result["in_scope_count"] == 1
    assert result["capacity_floor_start"] is not None


def test_classify_dedicated_min_replica_zero_out_of_scope():
    models = [_dedicated(min_replica=0)]
    result = _classify_deployed_models(models, now=NOW)
    assert result["provisioned_floor"] == 0
    assert result["in_scope_count"] == 0


def test_classify_automatic_min_replica_one_in_scope():
    """automaticResources.minReplicaCount >= 1 is in scope (spec 3.4)."""
    models = [_automatic(min_replica=1)]
    result = _classify_deployed_models(models, now=NOW)
    assert result["skip"] is False
    assert result["provisioned_floor"] == 1
    assert result["in_scope_count"] == 1
    assert result["capacity_floor_start"] is not None


def test_classify_automatic_min_replica_zero_out_of_scope():
    """automaticResources.minReplicaCount == 0 is scale-to-zero -- out of scope."""
    models = [_automatic(min_replica=0)]
    result = _classify_deployed_models(models, now=NOW)
    assert result["provisioned_floor"] == 0
    assert result["in_scope_count"] == 0


def test_classify_shared_resources_only():
    models = [_shared()]
    result = _classify_deployed_models(models, now=NOW)
    assert result["provisioned_floor"] == 0
    assert result["shared_only"] is True
    assert "sharedResources" in result["resource_modes"]


def test_classify_unrecognized_resource_union_skips_endpoint():
    """Model with no recognized resource union (dedicated/automatic/shared) -> skip=True (spec 9)."""
    models = [
        {
            "id": "m1",
            "createTime": _OLD_STR,
            "unknownResources": {"someField": "someValue"},
        }
    ]
    result = _classify_deployed_models(models, now=NOW)
    assert result["skip"] is True


def test_classify_malformed_min_replica_count_skips_endpoint():
    models = [
        {
            "id": "m1",
            "createTime": _OLD_STR,
            "dedicatedResources": {
                "machineSpec": {"machineType": "n1-standard-4"},
                "minReplicaCount": "not-a-number",
            },
        }
    ]
    result = _classify_deployed_models(models, now=NOW)
    assert result["skip"] is True


def test_classify_bad_create_time_skips_endpoint():
    """In-scope model with unparsable createTime -> skip=True (spec 7, 9)."""
    models = [_dedicated(min_replica=1, create_time_str="bad-timestamp")]
    result = _classify_deployed_models(models, now=NOW)
    assert result["skip"] is True


def test_classify_future_create_time_skips_endpoint():
    """In-scope model with future createTime -> skip=True (spec 7, 9)."""
    future = (NOW + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    models = [_dedicated(min_replica=1, create_time_str=future)]
    result = _classify_deployed_models(models, now=NOW)
    assert result["skip"] is True


def test_classify_dedicated_min_replica_count_missing_skips_endpoint():
    """Missing minReplicaCount on dedicatedResources is malformed -> skip=True (spec 9)."""
    models = [
        {
            "id": "m1",
            "createTime": _OLD_STR,
            "dedicatedResources": {
                "machineSpec": {"machineType": "n1-standard-4"},
                # minReplicaCount absent
            },
        }
    ]
    result = _classify_deployed_models(models, now=NOW)
    assert result["skip"] is True


def test_classify_automatic_min_replica_count_missing_skips_endpoint():
    """Missing minReplicaCount on automaticResources is malformed -> skip=True (spec 9)."""
    models = [
        {
            "id": "m1",
            "createTime": _OLD_STR,
            "automaticResources": {
                # minReplicaCount absent
            },
        }
    ]
    result = _classify_deployed_models(models, now=NOW)
    assert result["skip"] is True


def test_classify_shared_only_false_when_dedicated_zero_present():
    """dedicated(min=0) + shared: floor=0 but shared_only=False (there IS a dedicated model)."""
    models = [_dedicated(min_replica=0), _shared()]
    result = _classify_deployed_models(models, now=NOW)
    assert result["provisioned_floor"] == 0
    assert result["shared_only"] is False  # dedicated model present, even if out-of-scope


def test_classify_shared_only_true_when_only_shared():
    """Only sharedResources models -> shared_only=True."""
    models = [_shared(), _shared()]
    result = _classify_deployed_models(models, now=NOW)
    assert result["provisioned_floor"] == 0
    assert result["shared_only"] is True


def test_classify_gpu_accelerator_recognized_type():
    models = [_dedicated(min_replica=1, accel_type="NVIDIA_TESLA_T4", accel_count=1)]
    result = _classify_deployed_models(models, now=NOW)
    assert result["has_accelerator"] is True


def test_classify_gpu_unrecognized_type_no_accelerator():
    models = [_dedicated(min_replica=1, accel_type="CUSTOM_CHIP_XYZ", accel_count=1)]
    result = _classify_deployed_models(models, now=NOW)
    assert result["has_accelerator"] is False


def test_classify_gpu_zero_count_no_accelerator():
    models = [_dedicated(min_replica=1, accel_type="NVIDIA_TESLA_T4", accel_count=0)]
    result = _classify_deployed_models(models, now=NOW)
    assert result["has_accelerator"] is False


def test_classify_unspecified_accel_type_no_accelerator():
    models = [_dedicated(min_replica=1, accel_type="ACCELERATOR_TYPE_UNSPECIFIED", accel_count=2)]
    result = _classify_deployed_models(models, now=NOW)
    assert result["has_accelerator"] is False


def test_classify_multiple_dedicated_models_summed():
    m1 = _dedicated(min_replica=2, create_time_str=_OLD_STR)
    m2 = _dedicated(min_replica=3, create_time_str=_OLD_STR)
    result = _classify_deployed_models([m1, m2], now=NOW)
    assert result["provisioned_floor"] == 5
    assert result["in_scope_count"] == 2


def test_classify_multiple_models_capacity_floor_start_is_max():
    older = (NOW - timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    newer = (NOW - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    m1 = _dedicated(min_replica=1, create_time_str=older)
    m2 = _dedicated(min_replica=1, create_time_str=newer)
    result = _classify_deployed_models([m1, m2], now=NOW)
    expected = NOW - timedelta(days=10)
    assert abs((result["capacity_floor_start"] - expected).total_seconds()) < 2


def test_classify_mixed_dedicated_and_automatic():
    m1 = _dedicated(min_replica=1)
    m2 = _automatic(min_replica=1)
    result = _classify_deployed_models([m1, m2], now=NOW)
    assert result["provisioned_floor"] == 2
    assert result["in_scope_count"] == 2
    assert "dedicatedResources" in result["resource_modes"]
    assert "automaticResources" in result["resource_modes"]


def test_classify_resource_modes_none_when_no_models():
    result = _classify_deployed_models([], now=NOW)
    assert result["resource_modes"] == "none"


# ===========================================================================
# Unit tests: _evaluate_endpoint_telemetry
# ===========================================================================


def test_evaluate_no_points_returns_unresolved():
    cs, ts, mr = _evaluate_endpoint_telemetry([], _WINDOW_START, NOW)
    assert cs == "unresolved"
    assert ts == "unresolved"
    assert mr == 0


def test_evaluate_large_leading_gap_unresolved():
    """Single late-window point: leading gap >> window/2 -> unresolved (spec 8.3.6, 8.3.8)."""
    # Only one point near NOW; gap from window_start is ~14d >> 7d threshold
    points = [(0, NOW - timedelta(hours=1))]
    cs, ts, mr = _evaluate_endpoint_telemetry(points, _WINDOW_START, NOW)
    assert cs == "unresolved"
    assert ts == "unresolved"


def test_evaluate_large_trailing_gap_unresolved():
    """Single early-window point: trailing gap >> window/2 -> unresolved (spec 8.3.6, 8.3.8)."""
    # Only one point near window_start; gap to window_end is ~14d >> 7d threshold
    points = [(0, _WINDOW_START + timedelta(hours=1))]
    cs, ts, mr = _evaluate_endpoint_telemetry(points, _WINDOW_START, NOW)
    assert cs == "unresolved"
    assert ts == "unresolved"


def test_evaluate_large_interior_gap_unresolved():
    """Two points with huge gap between them -> unresolved (spec 8.3.6, 8.3.8)."""
    # P1 near start (leading gap small), P2 near end (trailing gap small)
    # But the P1->P2 interior gap is ~14d >> 7d threshold
    points = [
        (0, _WINDOW_START + timedelta(hours=1)),
        (0, NOW - timedelta(hours=1)),
    ]
    cs, ts, mr = _evaluate_endpoint_telemetry(points, _WINDOW_START, NOW)
    assert cs == "unresolved"
    assert ts == "unresolved"


def test_evaluate_dense_zero_points_complete():
    """Three points spanning window with all gaps < window/2 -> complete, no requests."""
    cs, ts, mr = _evaluate_endpoint_telemetry(_ZERO_POINTS, _WINDOW_START, NOW)
    assert cs == "complete"
    assert ts == "no_observed_prediction_requests"
    assert mr == 0


def test_evaluate_dense_nonzero_point_observed():
    """Dense points with nonzero value -> complete, observed requests."""
    cs, ts, mr = _evaluate_endpoint_telemetry(_ACTIVE_POINTS, _WINDOW_START, NOW)
    assert cs == "complete"
    assert ts == "observed_prediction_requests"
    assert mr == 42


def test_evaluate_gap_exactly_at_threshold_is_complete():
    """Gaps exactly equal to threshold (not strictly greater) -> coverage complete."""
    # Window: 6h, threshold = 3h
    # P1 at window_start+0s (leading gap = 0), P2 at window_end (trailing gap = 0)
    # Interior gap = 6h = 2 * threshold; strictly > threshold -> unresolved
    # Use 3 evenly spaced points instead: gaps exactly = 3h each
    short_start = NOW - timedelta(hours=6)
    p1 = (0, short_start)  # leading gap = 0
    p2 = (0, short_start + timedelta(hours=3))  # interior gap = 3h = threshold
    p3 = (0, NOW)  # interior gap = 3h, trailing = 0
    cs, ts, mr = _evaluate_endpoint_telemetry([p1, p2, p3], short_start, NOW)
    assert cs == "complete"  # gaps == threshold, not > threshold


def test_evaluate_float_value_above_zero_observed():
    """A double_value of 0.7 (not truncated to int 0) -> observed_prediction_requests."""
    points = [
        (0, _WINDOW_START + timedelta(hours=1)),
        (0.7, NOW - timedelta(days=7)),
        (0, NOW - timedelta(hours=1)),
    ]
    cs, ts, mr = _evaluate_endpoint_telemetry(points, _WINDOW_START, NOW)
    assert cs == "complete"
    assert ts == "observed_prediction_requests"
    assert mr == pytest.approx(0.7)


# ===========================================================================
# Integration tests: RULE_METADATA / RULE_ID
# ===========================================================================


def test_rule_metadata_id():
    assert RULE_METADATA["id"] == "gcp.vertex.endpoint.idle"


def test_rule_metadata_category():
    assert RULE_METADATA["category"] == "ai"


def test_rule_id_attribute():
    assert find_idle_vertex_endpoints.RULE_ID == "gcp.vertex.endpoint.idle"


# ===========================================================================
# Integration tests: idle endpoint detection
# ===========================================================================


def test_idle_cpu_endpoint_emits_finding():
    """Dedicated CPU endpoint with minReplica=1, zero requests -> MEDIUM risk finding."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.vertex.endpoint.idle"
    assert f.provider == "gcp"
    assert f.resource_type == "gcp.vertex.endpoint"
    assert f.resource_id == _ENDPOINT_NAME
    assert f.region == _LOCATION
    assert f.risk.value == "medium"
    assert f.confidence.value == "high"


def test_idle_gpu_endpoint_emits_high_risk():
    """Dedicated GPU endpoint -> HIGH risk."""
    ep = _endpoint(
        deployed_models=[_dedicated(min_replica=1, accel_type="NVIDIA_TESLA_T4", accel_count=1)]
    )
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})

    assert len(findings) == 1
    assert findings[0].risk.value == "high"
    assert findings[0].confidence.value == "high"


def test_estimated_monthly_cost_is_none():
    """spec 6.4: pricing varies; estimated_monthly_cost_usd must be None always."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd is None


def test_confidence_always_high():
    """spec 10.2: confidence is HIGH for all emitted findings; no tiered fallback."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_automatic_resources_min_replica_one_emits_finding():
    """spec 3.4: automaticResources.minReplicaCount >= 1 is in scope -> finding emitted."""
    ep = _endpoint(deployed_models=[_automatic(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.vertex.endpoint.idle"
    assert "automaticResources" in f.details["resource_modes"]


def test_automatic_resources_scale_to_zero_skipped():
    """automaticResources.minReplicaCount == 0 -> no always-deployed floor -> skipped."""
    ep = _endpoint(deployed_models=[_automatic(min_replica=0)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_dedicated_scale_to_zero_skipped():
    """dedicatedResources.minReplicaCount == 0 -> skipped."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=0)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_shared_resources_only_skipped():
    """sharedResources only -> provisioned_floor=0 -> skipped."""
    ep = _endpoint(deployed_models=[_shared()])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_no_deployed_models_skipped():
    ep = _endpoint(deployed_models=[])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_active_endpoint_skipped():
    """Any max_rate > 0 -> observed prediction requests -> skipped."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ACTIVE_POINTS})
    assert findings == []


def test_telemetry_unresolved_no_points_skipped():
    """No telemetry series at all -> telemetry_coverage_state=unresolved -> skipped."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={})  # no series for endpoint
    assert findings == []


def test_telemetry_unresolved_large_gap_skipped():
    """Single late-window point: leading gap >> window/2 -> unresolved -> skipped (spec 8.3.6)."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    # Only one point near window_end; leading gap ≈ idle_days - 1h >> window/2 threshold
    sparse_points = [(0, NOW - timedelta(hours=1))]
    findings = _run([ep], telemetry={_ENDPOINT_ID: sparse_points})
    assert findings == []


def test_no_near_idle_findings_emitted():
    """Non-zero requests always produces no finding (no near-idle tier; spec 8.5)."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    # Low but non-zero traffic should NOT emit a finding
    low_traffic_points = [(3, NOW - timedelta(hours=1))]
    findings = _run([ep], telemetry={_ENDPOINT_ID: low_traffic_points})
    assert findings == []


def test_no_missing_telemetry_fallback():
    """Missing telemetry (None dict) must not emit findings (no fallback; spec 8.5)."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry=None)
    assert findings == []


def test_monitoring_client_failure_returns_empty():
    """MetricServiceClient() raises -> no fallback -> empty findings list."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], client_fails=True)
    assert findings == []


def test_monitoring_query_failure_skips_location():
    """Query returns None -> skip all endpoints in that location."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], query_fails=True)
    assert findings == []


def test_young_endpoint_capacity_floor_start_too_late_skipped():
    """capacity_floor_start > window_start -> full window not coverable -> skipped."""
    ep = _endpoint(
        create_time_str=_YOUNG_STR,
        deployed_models=[_dedicated(min_replica=1, create_time_str=_YOUNG_STR)],
    )
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_young_deployed_model_skips_even_if_endpoint_is_old():
    """capacity_floor_start = max(endpoint, model createTimes). Young model -> skip."""
    young_model_str = _YOUNG.strftime("%Y-%m-%dT%H:%M:%SZ")
    ep = _endpoint(
        create_time_str=_OLD_STR,
        deployed_models=[_dedicated(min_replica=1, create_time_str=young_model_str)],
    )
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_endpoint_missing_name_skipped():
    ep = {
        "name": "",
        "createTime": _OLD_STR,
        "deployedModels": [_dedicated(min_replica=1)],
    }
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_endpoint_bad_create_time_skipped():
    ep = _endpoint(
        create_time_str="not-a-timestamp",
        deployed_models=[_dedicated(min_replica=1)],
    )
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_endpoint_future_create_time_skipped():
    future_str = (NOW + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ep = _endpoint(
        create_time_str=future_str,
        deployed_models=[_dedicated(min_replica=1)],
    )
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_deployed_model_bad_create_time_skips_endpoint():
    """In-scope model with unparsable createTime -> capacity_floor_start=None -> skip."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1, create_time_str="bad")])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_malformed_min_replica_count_skips_endpoint():
    """Malformed minReplicaCount -> skip=True -> endpoint skipped."""
    ep = _endpoint(
        deployed_models=[
            {
                "id": "m1",
                "createTime": _OLD_STR,
                "dedicatedResources": {
                    "machineSpec": {"machineType": "n1-standard-4"},
                    "minReplicaCount": "bad",
                },
            }
        ]
    )
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings == []


def test_region_filter_matches_location():
    ep = _endpoint(location=_LOCATION, deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS}, region_filter=_LOCATION)
    assert len(findings) == 1


def test_region_filter_non_matching_skipped():
    ep = _endpoint(location=_LOCATION, deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS}, region_filter="europe-west1")
    assert findings == []


def test_empty_endpoints_list_returns_empty():
    findings = _run([])
    assert findings == []


def test_two_endpoints_same_location_both_idle():
    ep1 = _endpoint(endpoint_id="111", deployed_models=[_dedicated(min_replica=1)])
    ep2 = _endpoint(endpoint_id="222", deployed_models=[_dedicated(min_replica=1)])
    ep1["name"] = f"projects/{_PROJECT}/locations/{_LOCATION}/endpoints/111"
    ep2["name"] = f"projects/{_PROJECT}/locations/{_LOCATION}/endpoints/222"
    telemetry = {
        "111": _ZERO_POINTS,
        "222": _ZERO_POINTS,
    }
    findings = _run([ep1, ep2], telemetry=telemetry)
    assert len(findings) == 2


def test_two_endpoints_one_active_one_idle():
    ep1 = _endpoint(endpoint_id="111", deployed_models=[_dedicated(min_replica=1)])
    ep2 = _endpoint(endpoint_id="222", deployed_models=[_dedicated(min_replica=1)])
    ep1["name"] = f"projects/{_PROJECT}/locations/{_LOCATION}/endpoints/111"
    ep2["name"] = f"projects/{_PROJECT}/locations/{_LOCATION}/endpoints/222"
    telemetry = {
        "111": _ACTIVE_POINTS,
        "222": _ZERO_POINTS,
    }
    findings = _run([ep1, ep2], telemetry=telemetry)
    assert len(findings) == 1
    assert "222" in findings[0].details["endpoint_id"]


def test_details_fields_present():
    """All required details keys must be present in emitted finding."""
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert len(findings) == 1
    d = findings[0].details

    required = {
        "endpoint_id",
        "location",
        "provisioned_serving_floor",
        "in_scope_model_count",
        "resource_modes",
        "has_accelerator",
        "capacity_floor_start",
        "idle_days_threshold",
        "max_observed_request_rate_per_replica",
        "telemetry_coverage_state",
        "telemetry_state",
    }
    for key in required:
        assert key in d, f"Missing details key: {key}"


def test_details_telemetry_coverage_state_complete():
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings[0].details["telemetry_coverage_state"] == "complete"


def test_details_telemetry_state_no_requests():
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings[0].details["telemetry_state"] == "no_observed_prediction_requests"


def test_details_max_observed_request_rate_per_replica_zero():
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings[0].details["max_observed_request_rate_per_replica"] == 0


def test_details_provisioned_serving_floor_correct():
    ep = _endpoint(deployed_models=[_dedicated(min_replica=3)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings[0].details["provisioned_serving_floor"] == 3


def test_details_has_accelerator_false_for_cpu():
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings[0].details["has_accelerator"] is False


def test_details_has_accelerator_true_for_gpu():
    ep = _endpoint(
        deployed_models=[_dedicated(min_replica=1, accel_type="NVIDIA_TESLA_T4", accel_count=1)]
    )
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert findings[0].details["has_accelerator"] is True


def test_details_idle_days_threshold_matches_param():
    ep = _endpoint(deployed_models=[_dedicated(min_replica=1)])
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS}, idle_days=21)
    # idle_days=21 -> window_start = NOW-21d, threshold=10.5d.
    # _ZERO_POINTS: P1 at NOW-14d+1h (leading gap ≈7d < 10.5d), gaps ~7d < 10.5d. Complete.
    # _OLD (30d ago) < window_start (21d ago) -> endpoint is eligible.
    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 21


@pytest.mark.parametrize(
    "accel_type",
    [
        "NVIDIA_TESLA_T4",
        "NVIDIA_TESLA_V100",
        "NVIDIA_TESLA_A100",
        "NVIDIA_L4",
        "NVIDIA_H100_80GB",
        "TPU_V2",
        "TPU_V3",
    ],
)
def test_known_accelerator_types_produce_high_risk(accel_type):
    ep = _endpoint(
        deployed_models=[_dedicated(min_replica=1, accel_type=accel_type, accel_count=1)]
    )
    findings = _run([ep], telemetry={_ENDPOINT_ID: _ZERO_POINTS})
    assert len(findings) == 1
    assert findings[0].risk.value == "high"


def test_request_metric_type_constant():
    assert _REQUEST_METRIC_TYPE == "aiplatform.googleapis.com/prediction/online/request_count"


def test_request_metric_resource_type_constant():
    assert _REQUEST_METRIC_RESOURCE_TYPE == "aiplatform.googleapis.com/Endpoint"
