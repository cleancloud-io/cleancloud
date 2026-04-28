"""
Rule: gcp.vertex.endpoint.idle

    (spec -- docs/specs/gcp/ai/vertex_endpoint_idle.md)

Intent:
    Detect Vertex AI Endpoints with a documented always-deployed serving floor
    and no observed online prediction request activity over a conservative review
    window, using documented Cloud Monitoring request-count telemetry.

    This is a precision-first review-candidate rule. It is not proof that the
    endpoint is safe to delete, not proof that all endpoint verbs are unused,
    and not proof of a specific monthly saving.

Covered resource families:
    - Vertex AI Endpoint (projects.locations.endpoints, aiplatform v1 REST API)

In-scope deployed models (spec 3.3, 3.4):
    - dedicatedResources.minReplicaCount >= 1  (always-deployed serving floor)
    - automaticResources.minReplicaCount >= 1  (always-deployed serving floor)

Out-of-scope:
    - sharedResources deployments (shared pool cost not directly attributable; spec 11.4)
    - dedicatedResources.minReplicaCount == 0  (scale-to-zero preview; no always-deployed floor)
    - automaticResources.minReplicaCount == 0  (scale-to-zero; no always-deployed floor)
    - endpoints with no deployed models
    - shared-resource-only endpoints (spec 11.4)

Exclusions:
    - endpoint name or location malformed (spec 7)
    - location filter set and location does not exactly match (spec 9)
    - no in-scope deployed models; provisioned_serving_floor < 1 (spec 9)
    - shared-resource-only endpoint (spec 9, 11.4)
    - any in-scope deployed model createTime missing, future, or unparsable (spec 7)
    - endpoint createTime missing, future, or unparsable (spec 7)
    - capacity_floor_start > evaluation_window_start (window not fully coverable; spec 9)
    - monitoring client creation failure -- all endpoints skip; no fallback (spec 11.2)
    - monitoring query failure for a location (spec 11.2)
    - telemetry_coverage_state != "complete" (spec 8.3, 9)
    - max_observed_request_rate_per_replica > 0 (spec 9)

Detection (all must be true to emit):
    - provisioned_serving_floor >= 1
    - capacity_floor_start_utc <= evaluation_window_start_utc
    - telemetry_coverage_state == "complete"
    - max_observed_request_rate_per_replica == 0

Cost model (spec 6.4):
    estimated_monthly_cost_usd = None
    Pricing varies by machine type, accelerator, region, and usage option;
    a flat estimate would be misleading.

APIs:
    - aiplatform.googleapis.com/v1: projects/{project}/locations/-/endpoints
    - monitoring.googleapis.com: aiplatform.googleapis.com/prediction/online/request_count
      on aiplatform.googleapis.com/Endpoint
"""

import warnings
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from google.auth.transport.requests import AuthorizedSession
from google.cloud import monitoring_v3
from google.protobuf import timestamp_pb2

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "gcp.vertex.endpoint.idle",
    "category": "ai",
    "service": "aiplatform",
    "cost_impact": "high",
}

_DEFAULT_IDLE_DAYS = 14

# Canonical metric and resource type (spec 8.1, 8.2)
_REQUEST_METRIC_TYPE = "aiplatform.googleapis.com/prediction/online/request_count"
_REQUEST_METRIC_RESOURCE_TYPE = "aiplatform.googleapis.com/Endpoint"

# Accelerator types for risk classification (spec 10.2).
# Risk is HIGH when any in-scope dedicated model has a nonzero accelerator count/type.
_GPU_ACCELERATORS = frozenset(
    {
        "NVIDIA_TESLA_T4",
        "NVIDIA_TESLA_V100",
        "NVIDIA_TESLA_P100",
        "NVIDIA_TESLA_K80",
        "NVIDIA_TESLA_A100",
        "NVIDIA_A100_80GB",
        "NVIDIA_L4",
        "NVIDIA_H100_80GB",
        "TPU_V2",
        "TPU_V3",
        "TPU_V4_POD",
    }
)


def _parse_location(name: str) -> Optional[str]:
    """Extract location from endpoint resource name.

    Resolves from the exact 'locations/{location}' segment (spec 7).
    Returns None if the segment is absent or empty.
    """
    parts = name.split("/")
    try:
        idx = parts.index("locations")
        loc = parts[idx + 1]
        return loc if loc else None
    except (ValueError, IndexError):
        return None


def _parse_endpoint_id(name: str) -> str:
    """Extract endpoint ID from the final segment of the resource name."""
    return name.rsplit("/", 1)[-1] if name else ""


def _parse_rfc3339_utc(ts: str) -> Optional[datetime]:
    """Parse an RFC3339 timestamp string into a timezone-aware UTC datetime."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def _classify_deployed_models(
    deployed_models: list,
    now: datetime,
) -> dict:
    """
    Classify deployed models on an endpoint per spec 3.3, 3.4, 7, 9.

    In-scope (spec 3.3, 3.4):
        dedicatedResources.minReplicaCount >= 1
        automaticResources.minReplicaCount >= 1

    Out-of-scope (skip model, not endpoint):
        sharedResources (shared pool; not endpoint-attributable; spec 11.4)
        any resource mode with minReplicaCount == 0

    skip=True cases (caller must skip entire endpoint per spec 9):
        malformed or missing minReplicaCount on any model
        unrecognized prediction-resource union on any model
        unusable createTime (missing, future, unparsable) on any in-scope model

    Returns a dict:
        skip (bool): True -> caller must skip the endpoint (malformed record).
        provisioned_floor (int): sum of minReplicaCount across in-scope models;
            0 means no always-deployed serving floor.
        shared_only (bool): True only when all models use sharedResources and
            none use dedicatedResources or automaticResources (spec 11.4).
        has_accelerator (bool): any in-scope dedicated model has a nonzero
            GPU/TPU accelerator count and a recognized accelerator type (spec 10.2).
        capacity_floor_start (datetime | None): max createTime across in-scope
            models; None when provisioned_floor == 0 (no in-scope models).
        resource_modes (str): resource mode types seen on the endpoint.
        in_scope_count (int): number of in-scope deployed models.
    """
    _skip = {
        "skip": True,
        "provisioned_floor": 0,
        "shared_only": False,
        "has_accelerator": False,
        "capacity_floor_start": None,
        "resource_modes": "malformed",
        "in_scope_count": 0,
    }

    if not deployed_models:
        return {
            "skip": False,
            "provisioned_floor": 0,
            "shared_only": False,
            "has_accelerator": False,
            "capacity_floor_start": None,
            "resource_modes": "none",
            "in_scope_count": 0,
        }

    provisioned_floor = 0
    has_accelerator = False
    in_scope_create_times: List[datetime] = []
    seen_modes: List[str] = []
    in_scope_count = 0

    for model in deployed_models:
        dedicated = model.get("dedicatedResources")
        automatic = model.get("automaticResources")
        shared = model.get("sharedResources")

        if dedicated is not None:
            if "dedicatedResources" not in seen_modes:
                seen_modes.append("dedicatedResources")
            raw = dedicated.get("minReplicaCount")
            if raw is None:
                # minReplicaCount is required; missing is malformed (spec 9)
                return _skip
            try:
                min_rep = int(raw)
            except (TypeError, ValueError):
                return _skip
            if min_rep >= 1:
                in_scope_count += 1
                provisioned_floor += min_rep
                spec = dedicated.get("machineSpec") or {}
                at = spec.get("acceleratorType", "ACCELERATOR_TYPE_UNSPECIFIED")
                try:
                    ac = int(spec.get("acceleratorCount") or 0)
                except (TypeError, ValueError):
                    ac = 0
                if (
                    at
                    and at != "ACCELERATOR_TYPE_UNSPECIFIED"
                    and ac > 0
                    and at in _GPU_ACCELERATORS
                ):
                    has_accelerator = True
                ct = _parse_rfc3339_utc(model.get("createTime") or "")
                if ct is None or ct > now:
                    # Unusable createTime on in-scope model -> skip endpoint (spec 7, 9)
                    return _skip
                in_scope_create_times.append(ct)

        elif automatic is not None:
            if "automaticResources" not in seen_modes:
                seen_modes.append("automaticResources")
            raw = automatic.get("minReplicaCount")
            if raw is None:
                # minReplicaCount is required; missing is malformed (spec 9)
                return _skip
            try:
                min_rep = int(raw)
            except (TypeError, ValueError):
                return _skip
            if min_rep >= 1:
                # automaticResources does not expose machineSpec; no accelerator check (spec 10.2)
                in_scope_count += 1
                provisioned_floor += min_rep
                ct = _parse_rfc3339_utc(model.get("createTime") or "")
                if ct is None or ct > now:
                    # Unusable createTime on in-scope model -> skip endpoint (spec 7, 9)
                    return _skip
                in_scope_create_times.append(ct)

        elif shared is not None:
            if "sharedResources" not in seen_modes:
                seen_modes.append("sharedResources")
        else:
            # Unrecognized prediction-resource union -> malformed record; skip endpoint (spec 9)
            return _skip

    resource_modes = ", ".join(seen_modes) if seen_modes else "none"

    # shared_only: endpoint has sharedResources models and no dedicated or automatic models at all
    shared_only = (
        provisioned_floor == 0
        and "sharedResources" in seen_modes
        and "dedicatedResources" not in seen_modes
        and "automaticResources" not in seen_modes
    )

    if provisioned_floor == 0:
        return {
            "skip": False,
            "provisioned_floor": 0,
            "shared_only": shared_only,
            "has_accelerator": False,
            "capacity_floor_start": None,
            "resource_modes": resource_modes,
            "in_scope_count": 0,
        }

    # provisioned_floor >= 1 and all in-scope createTimes are valid (fail-fast above catches bad ones)
    return {
        "skip": False,
        "provisioned_floor": provisioned_floor,
        "shared_only": False,
        "has_accelerator": has_accelerator,
        "capacity_floor_start": max(in_scope_create_times),
        "resource_modes": resource_modes,
        "in_scope_count": in_scope_count,
    }


def _query_location_request_counts(
    client: monitoring_v3.MetricServiceClient,
    project_id: str,
    location: str,
    window_start: datetime,
    window_end: datetime,
    eligible_endpoint_ids: set,
) -> Optional[Dict[str, List[Tuple[float, datetime]]]]:
    """
    Query request-count telemetry for all eligible endpoints in a location.

    Issues a single monitoring call for the location (spec 8.2: batching allowed).
    Exact endpoint attribution is enforced from resource.labels.endpoint_id (spec 8.2).
    No cross_series_reducer -- per-endpoint series identity is preserved (spec 8.2).
    No per-series aligner -- raw request-count values are preserved for zero/nonzero
    evaluation without any transform step (spec 8.2.7).

    Returns a dict mapping endpoint_id -> list of (value, timestamp) tuples for
    in-window usable datapoints, or None if the query fails (caller must skip all
    endpoints in this location; spec 11.2).

    In-window: point.interval.end_time falls within [window_start, window_end].
    Value extraction: int64_value first, else double_value kept as float -- a
    positive non-integer double (e.g. 0.7) must not be truncated to zero (spec 8.4.3).
    Null, NaN, and unsupported value shapes are ignored.
    """
    try:
        results = client.list_time_series(
            request={
                "name": f"projects/{project_id}",
                "filter": (
                    f'metric.type="{_REQUEST_METRIC_TYPE}"'
                    f' AND resource.type="{_REQUEST_METRIC_RESOURCE_TYPE}"'
                    f' AND resource.labels.location="{location}"'
                ),
                "interval": monitoring_v3.TimeInterval(
                    start_time=timestamp_pb2.Timestamp(seconds=int(window_start.timestamp())),
                    end_time=timestamp_pb2.Timestamp(seconds=int(window_end.timestamp())),
                ),
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                # No aggregation: preserves raw request-count values per spec 8.2.7.
                # No cross_series_reducer: preserves per-endpoint series identity per spec 8.2.
            }
        )

        per_endpoint: Dict[str, List[Tuple[float, datetime]]] = {}

        for series in results:
            ep_id = series.resource.labels.get("endpoint_id", "")
            if not ep_id or ep_id not in eligible_endpoint_ids:
                continue  # not in eligible set; exact attribution required (spec 8.2)

            if ep_id not in per_endpoint:
                per_endpoint[ep_id] = []

            for point in series.points:
                # Get point end timestamp (spec 8.4.1: use monitoring timestamps)
                try:
                    if point.interval and point.interval.end_time:
                        pt_ts = point.interval.end_time.ToDatetime(tzinfo=timezone.utc)
                    else:
                        continue
                except (AttributeError, TypeError):
                    continue

                # Ignore points outside the full observation window (spec 8.4.2)
                if pt_ts < window_start or pt_ts > window_end:
                    continue

                # Extract value: int64_value first, else double_value as float (spec 8.4.3).
                # Keep double as float -- do not truncate to int; 0.7 must remain 0.7 > 0.
                val: float = float(point.value.int64_value)
                if val == 0.0:
                    try:
                        dval = point.value.double_value
                        if dval and dval == dval:  # truthy and not NaN
                            val = float(dval)
                    except (AttributeError, TypeError):
                        pass

                per_endpoint[ep_id].append((val, pt_ts))

        return per_endpoint

    except Exception:
        return None  # conservative: caller skips all endpoints in this location (spec 11.2)


def _evaluate_endpoint_telemetry(
    points: List[Tuple[float, datetime]],
    window_start: datetime,
    window_end: datetime,
) -> Tuple[str, str, float]:
    """
    Evaluate telemetry coverage and activity state from collected in-window datapoints.

    Returns (telemetry_coverage_state, telemetry_state, max_observed_rate):
        telemetry_coverage_state: "complete" or "unresolved"
        telemetry_state: "no_observed_prediction_requests",
            "observed_prediction_requests", or "unresolved"
        max_observed_rate: maximum usable in-window value; 0.0 when unresolved

    Coverage rules (spec 8.3):
        - No in-window points -> unresolved (spec 8.3.1).
        - Gap-based coverage checks (spec 8.3.6, 8.3.8):
            Threshold: (window_end - window_start).total_seconds() / 2.
            Leading gap (window_start to first point): > threshold -> unresolved.
            Interior gap (between consecutive points): > threshold -> unresolved.
            Trailing gap (last point to window_end): > threshold -> unresolved.
            A gap larger than half the observation window cannot be proven to
            preserve sufficient observation across the full window. The threshold
            is relative to the window -- not a fixed cadence assumption -- consistent
            with the spec prohibition on inventing a sampling cadence or mandatory
            trailing ingestion buffer (spec 8.3).
        - All gaps within threshold -> coverage complete.

    Activity rules (spec 8.4):
        - max value > 0 -> observed_prediction_requests (spec 8.4.5)
        - max value == 0 -> no_observed_prediction_requests (spec 8.4.6)
    """
    if not points:
        return "unresolved", "unresolved", 0.0

    threshold_s = (window_end - window_start).total_seconds() / 2

    # Sort by timestamp to check gaps in chronological order
    sorted_pts = sorted(points, key=lambda x: x[1])
    timestamps = [ts for _, ts in sorted_pts]

    # Leading gap: window_start to first observed point (spec 8.3.6, 8.3.8)
    if (timestamps[0] - window_start).total_seconds() > threshold_s:
        return "unresolved", "unresolved", 0.0

    # Interior gaps: between consecutive observed points (spec 8.3.6, 8.3.8)
    for i in range(1, len(timestamps)):
        if (timestamps[i] - timestamps[i - 1]).total_seconds() > threshold_s:
            return "unresolved", "unresolved", 0.0

    # Trailing gap: last observed point to window_end (spec 8.3.6, 8.3.8)
    if (window_end - timestamps[-1]).total_seconds() > threshold_s:
        return "unresolved", "unresolved", 0.0

    max_val = max(v for v, _ in points)
    if max_val > 0:
        return "complete", "observed_prediction_requests", max_val
    return "complete", "no_observed_prediction_requests", 0.0


def find_idle_vertex_endpoints(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    idle_days: int = _DEFAULT_IDLE_DAYS,
) -> List[Finding]:
    """
    Find Vertex AI endpoints with an always-deployed serving floor and zero observed
    prediction requests over the full observation window.

    Emits a finding only when all of the following are true (spec 9):
        1. at least one deployed model is in scope with provisioned_serving_floor >= 1
        2. capacity_floor_start_utc <= evaluation_window_start_utc (full window coverable)
        3. telemetry_coverage_state == "complete"
        4. max_observed_request_rate_per_replica == 0

    No age-only, traffic-split, or missing-telemetry fallback is performed (spec 8.5).

    IAM permissions required:
        aiplatform.endpoints.list  (roles/aiplatform.viewer)
        monitoring.timeSeries.list (roles/monitoring.viewer)
    """
    idle_days = max(1, idle_days)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    window_end = now
    window_start = window_end - timedelta(seconds=idle_days * 86400)

    session = AuthorizedSession(credentials)
    endpoints = _list_endpoints(session, project_id)
    if not endpoints:
        return []

    try:
        monitoring_client: Optional[monitoring_v3.MetricServiceClient] = (
            monitoring_v3.MetricServiceClient(credentials=credentials)
        )
    except Exception as exc:
        warnings.warn(
            f"gcp.vertex.endpoint.idle: monitoring client creation failed "
            f"({type(exc).__name__}: {exc}) -- all endpoints will be skipped (no fallback)",
            UserWarning,
            stacklevel=2,
        )
        return []

    # -------------------------------------------------------------------------
    # Phase 1: pre-check each endpoint; group eligible ones by location
    # -------------------------------------------------------------------------
    eligible_by_location: Dict[str, List[dict]] = defaultdict(list)

    for endpoint in endpoints:
        name = (endpoint.get("name") or "").strip()
        if not name:
            continue

        endpoint_id = _parse_endpoint_id(name)
        if not endpoint_id:
            continue

        location = _parse_location(name)
        if not location:
            continue

        if region_filter and location != region_filter:
            continue

        # Parse endpoint createTime (spec 7)
        endpoint_create_time = _parse_rfc3339_utc(endpoint.get("createTime") or "")
        if endpoint_create_time is None or endpoint_create_time > now:
            continue

        # Classify deployed models (spec 3.3, 3.4, 7)
        deployed_models = endpoint.get("deployedModels") or []
        mc = _classify_deployed_models(deployed_models, now)

        if mc["skip"]:
            continue  # malformed minReplicaCount

        if mc["provisioned_floor"] < 1:
            continue  # no always-deployed serving floor (covers shared_only too)

        if mc["capacity_floor_start"] is None:
            continue  # in-scope deployed model createTime unusable (spec 7)

        # capacity_floor_start = max(endpoint createTime, in-scope model createTimes) (spec 7)
        capacity_floor_start = max(endpoint_create_time, mc["capacity_floor_start"])

        if capacity_floor_start > window_start:
            continue  # full observation window not coverable (spec 9)

        eligible_by_location[location].append(
            {
                "name": name,
                "endpoint_id": endpoint_id,
                "location": location,
                "display_name": (endpoint.get("displayName") or "").strip(),
                "endpoint_create_time": endpoint_create_time,
                "capacity_floor_start": capacity_floor_start,
                "provisioned_floor": mc["provisioned_floor"],
                "has_accelerator": mc["has_accelerator"],
                "resource_modes": mc["resource_modes"],
                "in_scope_count": mc["in_scope_count"],
            }
        )

    # -------------------------------------------------------------------------
    # Phase 2: batch monitoring query per location; evaluate; build findings
    # -------------------------------------------------------------------------
    findings: List[Finding] = []

    for location, ep_list in eligible_by_location.items():
        eligible_ids = {ep["endpoint_id"] for ep in ep_list}
        telemetry_data = _query_location_request_counts(
            monitoring_client,
            project_id,
            location,
            window_start,
            window_end,
            eligible_ids,
        )

        if telemetry_data is None:
            # Query failure -- skip all endpoints in this location (spec 11.2)
            warnings.warn(
                f"gcp.vertex.endpoint.idle: monitoring query failed for location "
                f"'{location}' -- all endpoints in this location will be skipped",
                UserWarning,
                stacklevel=2,
            )
            continue

        for ep_info in ep_list:
            ep_id = ep_info["endpoint_id"]
            points = telemetry_data.get(ep_id, [])

            coverage_state, telemetry_state, max_rate = _evaluate_endpoint_telemetry(
                points, window_start, window_end
            )

            if coverage_state != "complete":
                continue  # telemetry not sufficiently observed (spec 8.3, 9)

            if max_rate > 0:
                continue  # observed prediction requests (spec 9)

            # All conditions satisfied -- build finding
            name = ep_info["name"]
            endpoint_id = ep_info["endpoint_id"]
            display_name = ep_info["display_name"]
            provisioned_floor = ep_info["provisioned_floor"]
            has_accelerator = ep_info["has_accelerator"]
            resource_modes = ep_info["resource_modes"]
            in_scope_count = ep_info["in_scope_count"]
            capacity_floor_start = ep_info["capacity_floor_start"]
            endpoint_create_time = ep_info["endpoint_create_time"]

            # Confidence always HIGH: emits only on full-window zero request-count
            # telemetry with no heuristic fallback (spec 10.2)
            confidence = ConfidenceLevel.HIGH
            # Risk HIGH if any in-scope dedicated model has nonzero accelerator (spec 10.2)
            risk = RiskLevel.HIGH if has_accelerator else RiskLevel.MEDIUM

            node_display = display_name or endpoint_id

            signals = [
                f"Location: {location}",
                f"Endpoint createTime: {endpoint_create_time.isoformat()}",
                (
                    f"Capacity floor start (max of endpoint createTime and in-scope "
                    f"deployed model createTimes): {capacity_floor_start.isoformat()}"
                ),
                (
                    f"Observation window: {window_start.isoformat()} to "
                    f"{window_end.isoformat()} ({idle_days}d)"
                ),
                (
                    f"Provisioned serving floor: {provisioned_floor} total min replica(s) "
                    f"across {in_scope_count} in-scope deployed model(s)"
                ),
                f"Resource modes present on endpoint: {resource_modes}",
                (
                    f"Request metric: {_REQUEST_METRIC_TYPE} "
                    f"(resource: {_REQUEST_METRIC_RESOURCE_TYPE})"
                ),
                (
                    f"Max observed request-count value over full window: {max_rate} "
                    f"(telemetry_coverage_state: {coverage_state})"
                ),
                (
                    "Endpoint-scoped request-count telemetry showed no datapoint above 0 "
                    f"over the full {idle_days}d observation window"
                ),
            ]
            if has_accelerator:
                signals.append(
                    "Accelerator-backed in-scope dedicated model detected -- "
                    "risk is HIGH (nonzero accelerator count and recognized type)"
                )

            not_checked = [
                "Explain-only, health-check, or non-prediction endpoint usage",
                "Shared DeploymentResourcePool cost attributable to this endpoint",
                "Scheduled or batch traffic outside the observation window",
                "Planned future usage or upcoming model promotion",
                "Endpoints intentionally kept warm for latency-sensitive production traffic",
            ]

            findings.append(
                Finding(
                    provider="gcp",
                    rule_id="gcp.vertex.endpoint.idle",
                    resource_type="gcp.vertex.endpoint",
                    resource_id=name,
                    region=location,
                    title=(
                        f"Idle Vertex AI Endpoint "
                        f"({provisioned_floor} replica(s) always on, zero requests)"
                    ),
                    summary=(
                        f"Vertex AI endpoint '{node_display}' in '{location}' has "
                        f"{provisioned_floor} always-deployed replica(s) but "
                        f"endpoint-scoped request-count telemetry showed no prediction "
                        f"activity over the full {idle_days}d observation window."
                    ),
                    reason=(
                        f"Endpoint has provisioned serving floor of {provisioned_floor} "
                        f"replica(s); endpoint-scoped request-count telemetry "
                        f"(coverage: complete) shows max observed rate == 0 over "
                        f"{idle_days}d window"
                    ),
                    risk=risk,
                    confidence=confidence,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals,
                        signals_not_checked=not_checked,
                        time_window=f"{idle_days}d",
                    ),
                    estimated_monthly_cost_usd=None,  # spec 6.4: pricing varies; no flat estimate
                    details={
                        "endpoint_id": endpoint_id,
                        "display_name": display_name or None,
                        "location": location,
                        "provisioned_serving_floor": provisioned_floor,
                        "in_scope_model_count": in_scope_count,
                        "resource_modes": resource_modes,
                        "has_accelerator": has_accelerator,
                        "capacity_floor_start": capacity_floor_start.isoformat(),
                        "idle_days_threshold": idle_days,
                        "max_observed_request_rate_per_replica": max_rate,
                        "telemetry_coverage_state": coverage_state,
                        "telemetry_state": telemetry_state,
                    },
                )
            )

    return findings


find_idle_vertex_endpoints.RULE_ID = "gcp.vertex.endpoint.idle"


_VERTEX_LOCATIONS = [
    "global",
    "us-central1",
    "us-east1",
    "us-east4",
    "us-west1",
    "us-west4",
    "northamerica-northeast1",
    "southamerica-east1",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-north1",
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast3",
    "asia-south1",
    "asia-southeast1",
    "australia-southeast1",
    "me-west1",
]


def _list_endpoints(session: AuthorizedSession, project_id: str) -> list:
    """
    List all Vertex AI Online Prediction endpoints across all locations.

    Attempts the locations/- wildcard (AIP-131) first -- a single paginated call
    covering every region. Falls back to querying each known location individually
    when the wildcard returns 400 (some projects only support specific locations
    such as 'global').

    Raises PermissionError on 403. Returns [] on 404 (API not enabled).
    """
    base_url = f"https://aiplatform.googleapis.com/v1/projects/{project_id}/locations"

    def _paginate(url: str) -> list:
        results = []
        params: dict = {"pageSize": 100}
        while True:
            resp = session.get(url, params=params)
            if resp.status_code == 403:
                raise PermissionError(
                    "aiplatform.endpoints.list permission required (roles/aiplatform.viewer)"
                )
            if resp.status_code == 404:
                return []
            if resp.status_code == 400:
                return None  # signal fallback to per-location queries
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("endpoints", []))
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            params["pageToken"] = next_token
        return results

    result = _paginate(f"{base_url}/-/endpoints")
    if result is not None:
        return result

    all_endpoints = []
    seen_names: set = set()
    for location in _VERTEX_LOCATIONS:
        loc_result = _paginate(f"{base_url}/{location}/endpoints")
        if loc_result is None:
            continue
        for ep in loc_result:
            ep_name = ep.get("name", "")
            if ep_name and ep_name not in seen_names:
                seen_names.add(ep_name)
                all_endpoints.append(ep)
    return all_endpoints
