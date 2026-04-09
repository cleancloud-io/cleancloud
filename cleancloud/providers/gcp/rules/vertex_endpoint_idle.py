from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from google.auth.transport.requests import AuthorizedSession
from google.cloud import monitoring_v3
from google.protobuf import duration_pb2, timestamp_pb2

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

# Accelerator types treated as GPU/high-cost
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

# Monthly cost per node for the machine type alone (on-demand, us-central1, 730 h/month)
# Source: https://cloud.google.com/vertex-ai/pricing (Online Prediction node hours)
_MACHINE_MONTHLY_COST = {
    "n1-standard-2": 69.0,
    "n1-standard-4": 138.0,
    "n1-standard-8": 277.0,
    "n1-standard-16": 554.0,
    "n1-standard-32": 1_107.0,
    "n1-highmem-2": 93.0,
    "n1-highmem-4": 187.0,
    "n1-highmem-8": 374.0,
    "n1-highmem-16": 748.0,
    "n2-standard-2": 78.0,
    "n2-standard-4": 157.0,
    "n2-standard-8": 314.0,
    "n2-standard-16": 628.0,
    "c2-standard-4": 166.0,
    "c2-standard-8": 332.0,
    "c2-standard-16": 665.0,
    # a2-* and g2-* include accelerator cost — no separate GPU add-on
    "a2-highgpu-1g": 2_933.0,
    "a2-highgpu-2g": 5_866.0,
    "a2-highgpu-4g": 11_732.0,
    "a2-highgpu-8g": 23_464.0,
    "a2-ultragpu-1g": 5_103.0,
    "a2-ultragpu-2g": 10_206.0,
    "g2-standard-4": 706.0,
    "g2-standard-8": 1_060.0,
    "g2-standard-12": 1_414.0,
    "g2-standard-16": 2_120.0,
    "g2-standard-24": 3_181.0,
    "g2-standard-32": 4_241.0,
    "g2-standard-48": 6_361.0,
    "g2-standard-96": 12_722.0,
}
_DEFAULT_MACHINE_MONTHLY_COST = 150.0

# Additional monthly cost per GPU when attached to n1-*/n2-* machines.
# a2-* and g2-* already include GPU cost in the machine price above.
_GPU_MONTHLY_COST_EACH = {
    "NVIDIA_TESLA_T4": 311.0,
    "NVIDIA_TESLA_V100": 1_385.0,
    "NVIDIA_TESLA_P100": 1_022.0,
    "NVIDIA_TESLA_K80": 392.0,
    "NVIDIA_TESLA_A100": 2_933.0,
    "NVIDIA_L4": 680.0,
    "NVIDIA_H100_80GB": 8_000.0,
}

_DAYS_IDLE = 14

# Endpoints with fewer than this many prediction requests in the idle window are
# flagged as "near-idle" (MEDIUM confidence). Zero requests -> fully idle.
# GPU endpoints use a lower threshold — higher cost justifies more aggressive flagging.
# Threshold is then scaled by sqrt(replicas) so large deployments can't hide inefficiency
# behind a linearly growing bar (20 replicas -> ×4.5, not ×20).
_LOW_TRAFFIC_THRESHOLD = 10
_LOW_TRAFFIC_THRESHOLD_GPU = 5

# Findings below this estimated cost are suppressed — avoids noise from cheap endpoints
# and builds user trust by keeping findings actionable.
_MIN_MONTHLY_COST_USD = 50


def find_idle_vertex_endpoints(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
) -> List[Finding]:
    """
    Find Vertex AI Online Prediction endpoints with zero or near-zero predictions
    for 14 days.

    Vertex AI endpoints with dedicatedResources.minReplicaCount > 0 keep instances
    running continuously regardless of traffic — billing is per node-hour regardless
    of prediction volume. GPU-backed endpoints (T4, V100, A100) cost $300–$8K/month
    per GPU plus machine cost. Endpoints created for experiments are frequently
    abandoned after the model demo or prototype phase.

    Detection tiers:
    - IDLE: Zero prediction requests over the idle window -> HIGH/MEDIUM confidence
    - NEAR-IDLE: < 10 requests over the idle window -> MEDIUM confidence

    Endpoints using automaticResources (auto-scaling to zero) are excluded — they
    incur no compute cost when idle.

    Monitoring queries are batched per location — one API call per region rather
    than one call per endpoint.

    IAM permissions:
    - aiplatform.endpoints.list (roles/aiplatform.viewer)
    - monitoring.timeSeries.list (roles/monitoring.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    session = AuthorizedSession(credentials)

    try:
        monitoring_client: Optional[monitoring_v3.MetricServiceClient] = (
            monitoring_v3.MetricServiceClient(credentials=credentials)
        )
    except Exception:
        monitoring_client = None

    try:
        endpoints = _list_endpoints(session, project_id)
    except PermissionError:
        raise

    # -----------------------------------------------------------------------
    # Phase 1: collect eligible endpoints, grouped by location for batching
    # -----------------------------------------------------------------------
    eligible_by_location: Dict[str, List[dict]] = defaultdict(list)

    for endpoint in endpoints:
        endpoint_name = endpoint.get("name", "")
        display_name = endpoint.get("displayName", "")

        # Extract location and numeric ID from resource name:
        # projects/{proj}/locations/{loc}/endpoints/{id}
        parts = endpoint_name.split("/")
        location = parts[3] if len(parts) > 3 else ""
        endpoint_id = parts[-1] if parts else ""

        if region_filter and location != region_filter:
            continue

        # Aggregate dedicated resources across all deployed models
        total_min_replicas, machine_type, accel_type, accel_count, is_gpu = _parse_deployed_models(
            endpoint.get("deployedModels", [])
        )

        # Skip endpoints with no always-on dedicated capacity — automaticResources
        # scale to zero and incur no idle compute cost
        if total_min_replicas == 0:
            continue

        # Age calculation — use endpoint createTime, not deployed model createTime
        age_days: Optional[int] = None
        create_time_str = endpoint.get("createTime", "")
        if create_time_str:
            try:
                created_at = datetime.fromisoformat(create_time_str.replace("Z", "+00:00"))
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                age_days = (now - created_at).days
                # Skip endpoints younger than half the idle threshold —
                # too new to reliably classify as abandoned
                if age_days < max(_DAYS_IDLE // 2, 7):
                    continue
            except ValueError:
                pass

        # Effective window: cap to age so we don't look back before the endpoint existed
        effective_window = min(_DAYS_IDLE, age_days) if age_days is not None else _DAYS_IDLE

        # Accurate cost: sum per deployed model (handles mixed machine types correctly)
        deployed_models = endpoint.get("deployedModels", [])
        monthly_cost = _compute_multi_model_cost(deployed_models)
        num_dedicated_models = sum(1 for m in deployed_models if m.get("dedicatedResources"))

        eligible_by_location[location].append(
            {
                "endpoint_name": endpoint_name,
                "endpoint_id": endpoint_id,
                "display_name": display_name,
                "location": location,
                "total_min_replicas": total_min_replicas,
                "machine_type": machine_type,
                "accel_type": accel_type,
                "accel_count": accel_count,
                "is_gpu": is_gpu,
                "age_days": age_days,
                "effective_window": effective_window,
                "monthly_cost": monthly_cost,
                "num_dedicated_models": num_dedicated_models,
            }
        )

    # -----------------------------------------------------------------------
    # Phase 2: batch monitoring query per location, then build findings
    # -----------------------------------------------------------------------
    if monitoring_client is None:
        return findings  # conservative: skip all if monitoring unavailable

    for location, ep_list in eligible_by_location.items():
        # One monitoring call covers all endpoints in this location.
        # Pass eligible IDs so results from stale/unrelated series are ignored.
        eligible_ids = {ep["endpoint_id"] for ep in ep_list}
        result = _get_prediction_counts_batch(
            monitoring_client, project_id, location, _DAYS_IDLE, eligible_ids
        )

        for ep_info in ep_list:
            if result is None:
                # Monitoring error for this location — assume active (conservative)
                continue

            counts, recently_active_ids = result

            # Suppress noise from very cheap endpoints early — avoids wasting
            # confidence/signal computation on findings below the noise floor.
            if ep_info["monthly_cost"] < _MIN_MONTHLY_COST_USD:
                continue

            endpoint_id_key = ep_info["endpoint_id"]
            is_recently_active = endpoint_id_key in recently_active_ids
            # Endpoints in recently_active_ids have monitoring data — they were detected
            # as recently active and excluded from counts intentionally, not because
            # metrics are missing.
            no_monitoring_data = endpoint_id_key not in counts and not is_recently_active
            count = counts.get(endpoint_id_key, 0)

            # GPU endpoints are flagged more aggressively — higher cost warrants it.
            # Sqrt scaling by replica count prevents large deployments from hiding
            # inefficiency behind a linearly growing bar.
            is_gpu = ep_info["is_gpu"]
            total_min_replicas_ep = ep_info["total_min_replicas"]
            # Recency dominates: endpoint with traffic in the last 24h is considered active
            # regardless of how low the 14-day total looks.
            if is_recently_active:
                continue

            base_threshold = _LOW_TRAFFIC_THRESHOLD_GPU if is_gpu else _LOW_TRAFFIC_THRESHOLD
            # Sqrt scaling is sublinear so large deployments can't hide inefficiency.
            # Cap at 50 to keep the threshold intuitive — 100-node endpoints still only
            # need 50+ requests to be considered "active" at the detection level.
            effective_threshold = min(
                50,
                max(1, int(base_threshold * max(1.0, total_min_replicas_ep**0.5))),
            )
            if count >= effective_threshold:
                continue  # genuinely active endpoint

            is_near_idle = count > 0
            age_days = ep_info["age_days"]
            effective_window = ep_info["effective_window"]

            # Safety guard: missing monitoring data ≠ zero traffic.
            # Monitoring can be absent due to metric delays, permission gaps, or
            # misconfiguration. Require 2× the idle window before trusting absence
            # as evidence of idleness — CleanCloud biases toward false negatives
            # over false positives to maintain enterprise trust.
            if no_monitoring_data and (age_days is None or age_days < _DAYS_IDLE * 2):
                continue

            # Cron/batch pattern protection: counts at or below 20% of the capacity-adjusted
            # threshold suggest periodic (e.g. weekly) usage rather than abandonment.
            # Scales with effective_threshold so large deployments are handled consistently.
            is_low_frequency_use = is_near_idle and count <= max(2, int(effective_threshold * 0.2))

            # Confidence based on traffic and age.
            # HIGH requires: zero traffic, full observation window, established age.
            if is_low_frequency_use:
                # Very low count — could be weekly/cron job; cap at MEDIUM
                confidence = ConfidenceLevel.MEDIUM
            elif is_near_idle:
                # Some traffic exists (> 2 requests) — cap at MEDIUM regardless of age
                confidence = ConfidenceLevel.MEDIUM
            elif age_days is not None and age_days >= _DAYS_IDLE and effective_window == _DAYS_IDLE:
                confidence = ConfidenceLevel.HIGH
            elif age_days is None or age_days >= int(_DAYS_IDLE * 0.75):
                confidence = ConfidenceLevel.MEDIUM
            else:
                continue  # too borderline

            endpoint_name = ep_info["endpoint_name"]
            endpoint_id = ep_info["endpoint_id"]
            display_name = ep_info["display_name"]
            total_min_replicas = total_min_replicas_ep
            machine_type = ep_info["machine_type"]
            accel_type = ep_info["accel_type"]
            accel_count = ep_info["accel_count"]
            monthly_cost = ep_info["monthly_cost"]
            num_dedicated_models = ep_info["num_dedicated_models"]

            risk = RiskLevel.HIGH if is_gpu else RiskLevel.MEDIUM

            # Waste score: full cost when count=0; scales down as traffic approaches threshold.
            # Useful for future sorting / prioritization — not yet exposed in UI.
            waste_fraction = (
                1.0 - min(count / effective_threshold, 1.0) if effective_threshold > 0 else 1.0
            )
            waste_score = round(monthly_cost * waste_fraction, 2)

            is_experiment_pattern = num_dedicated_models > 1

            # Context-aware action recommendations
            recommendations: List[str] = []
            if total_min_replicas > 1:
                recommendations.append(
                    "Reduce minReplicaCount to 1 if high availability is not required"
                )
            recommendations.append(
                "Switch to automaticResources (minReplicaCount=0) to eliminate idle compute cost "
                "if the workload is not latency-critical — scales to zero when idle"
            )
            if is_experiment_pattern:
                recommendations.append(
                    "Consolidate deployed models or delete unused A/B test deployments"
                )
            recommendations.append(
                f"Delete endpoint if no longer needed: "
                f"gcloud ai endpoints delete {endpoint_id} "
                f"--region={location} --project=PROJECT_ID"
            )

            if is_near_idle:
                title = (
                    f"Near-Idle Vertex AI Endpoint "
                    f"({count} Prediction{'s' if count != 1 else ''} in {effective_window} Days)"
                )
                traffic_signal = (
                    f"{count} prediction request(s) in {effective_window} days — "
                    f"near-idle (capacity-adjusted threshold: {effective_threshold} requests"
                    f"{', GPU-adjusted' if is_gpu else ''})"
                )
            else:
                title = f"Idle Vertex AI Endpoint (No Predictions for {effective_window} Days)"
                traffic_signal = (
                    f"Zero prediction requests for {effective_window} days "
                    "(Cloud Monitoring: aiplatform.googleapis.com/prediction/online/request_count)"
                )

            # Pricing is region-dependent — always flag estimate as approximate
            cost_note = f"~${monthly_cost:,.0f}/month (us-central1 baseline)"
            gpu_prefix = "GPU-backed endpoint — " if is_gpu else ""

            if is_near_idle:
                summary = (
                    f"{gpu_prefix}Vertex AI endpoint '{display_name or endpoint_id}' in '{location}' "
                    f"had only {count} prediction request(s) in {effective_window} days but keeps "
                    f"{total_min_replicas} dedicated node(s) running continuously, "
                    f"incurring an estimated {cost_note} in compute charges."
                )
            else:
                summary = (
                    f"{gpu_prefix}Vertex AI endpoint '{display_name or endpoint_id}' in '{location}' "
                    f"has received zero predictions for {effective_window} days but keeps "
                    f"{total_min_replicas} dedicated node(s) running continuously, "
                    f"incurring an estimated {cost_note} in compute charges."
                )

            requests_per_replica = count / max(total_min_replicas, 1)
            signals = [
                traffic_signal,
                f"Dedicated capacity configured: minReplicaCount={total_min_replicas} "
                "(always-on compute — billed continuously regardless of traffic)",
                f"Requests per replica: {requests_per_replica:.2f} over {effective_window} days"
                + (
                    " — effectively unused"
                    if requests_per_replica < 0.1
                    else " — extremely low utilization" if requests_per_replica < 1.0 else ""
                ),
            ]
            if no_monitoring_data and not is_near_idle:
                signals.append(
                    "No prediction request data found in Cloud Monitoring — "
                    "may indicate metrics are not enabled; classification less reliable. "
                    "Verify roles/monitoring.viewer and metrics ingestion before acting."
                )
            if age_days is not None:
                signals.append(f"Endpoint age: {age_days} days")
            if machine_type:
                signals.append(f"Machine type: {machine_type}")
            if accel_type and accel_type != "ACCELERATOR_TYPE_UNSPECIFIED":
                signals.append(f"Accelerator: {accel_type} × {accel_count}")
            if is_gpu:
                signals.append(f"GPU-backed endpoint — high continuous cost ({cost_note})")
            if num_dedicated_models > 1:
                signals.append(
                    f"{num_dedicated_models} deployed models with low aggregate traffic "
                    "— possible abandoned A/B test or failed experiment"
                )
            if total_min_replicas > 1:
                signals.append(
                    f"{total_min_replicas} replicas configured — stronger waste signal "
                    "than single warm-endpoint pattern"
                )
                signals.append(
                    f"Traffic threshold scaled sublinearly with replica count "
                    f"(sqrt({total_min_replicas}) × {base_threshold} = {effective_threshold} requests) "
                    "— prevents large deployments from masking inefficiency behind a linearly growing bar"
                )
            if display_name and display_name != endpoint_id:
                signals.append(f"Display name: {display_name}")

            evidence = Evidence(
                signals_used=signals,
                signals_not_checked=[
                    "Scheduled or batch prediction requests outside the observation window",
                    "Internal health-check or canary traffic not tracked by Cloud Monitoring",
                    "Planned future usage or upcoming model promotion",
                    "Shadow mode or A/B test routing with low traffic share",
                    "Endpoints kept warm for latency-sensitive production traffic",
                ],
                time_window=f"{effective_window} days",
            )

            findings.append(
                Finding(
                    provider="gcp",
                    rule_id="gcp.vertex.endpoint.idle",
                    resource_type="gcp.vertex.endpoint",
                    resource_id=endpoint_name,
                    region=location,
                    estimated_monthly_cost_usd=monthly_cost,
                    title=title,
                    summary=summary,
                    reason=(
                        f"Vertex AI endpoint has {count} prediction(s) in {effective_window} days "
                        f"with dedicated capacity (minReplicaCount={total_min_replicas})"
                    ),
                    risk=risk,
                    confidence=confidence,
                    detected_at=now,
                    evidence=evidence,
                    details={
                        "endpoint_id": endpoint_id,
                        "display_name": display_name,
                        "location": location,
                        "machine_type": machine_type,
                        "accelerator_type": accel_type,
                        "accelerator_count": accel_count,
                        "is_gpu": is_gpu,
                        "min_replica_count": total_min_replicas,
                        "age_days": age_days if age_days is not None else "unknown",
                        "idle_window_days": effective_window,
                        "idle_days_threshold": _DAYS_IDLE,
                        "request_count": count,
                        "effective_threshold": effective_threshold,
                        "threshold_strategy": "sqrt_replica_scaling",
                        "no_monitoring_data": no_monitoring_data,
                        "waste_score": waste_score,
                        "requests_per_replica": round(requests_per_replica, 4),
                        "pattern": "abandoned_experiment" if is_experiment_pattern else None,
                        "cost_confidence": "estimate",
                        "cost_basis": "us-central1 baseline estimate",
                        "cost_variance": (
                            "Estimated based on us-central1 on-demand pricing; "
                            "varies by region and discounts."
                        ),
                        "estimated_monthly_cost": f"~${monthly_cost:,.0f}/month",
                        "recommendations": recommendations,
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

    Attempts the locations/- wildcard (AIP-131) first — a single paginated call
    covering every region. Falls back to querying each known location individually
    when the wildcard returns 400 (some projects only support specific locations
    such as 'global').

    Raises PermissionError on 403. Returns [] on 404 (API not enabled).
    """
    base_url = f"https://aiplatform.googleapis.com/v1/projects/{project_id}/locations"

    def _paginate(url: str) -> list:
        """Paginate a single location URL and return all endpoints."""
        results = []
        params: dict = {"pageSize": 100}
        while True:
            resp = session.get(url, params=params)
            if resp.status_code == 403:
                raise PermissionError(
                    "aiplatform.endpoints.list permission required (roles/aiplatform.viewer)"
                )
            if resp.status_code == 404:
                return []  # Vertex AI API not enabled for this project
            if resp.status_code == 400:
                return None  # signal to caller to try fallback
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("endpoints", []))
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            params["pageToken"] = next_token
        return results

    # Fast path: wildcard covers all regions in one call sequence
    result = _paginate(f"{base_url}/-/endpoints")
    if result is not None:
        return result

    # Fallback: wildcard not supported (e.g. project only has 'global' endpoints).
    # Query each known location; skip 400s for unsupported regions.
    all_endpoints = []
    seen_names: set = set()
    for location in _VERTEX_LOCATIONS:
        loc_result = _paginate(f"{base_url}/{location}/endpoints")
        if loc_result is None:
            continue  # 400 = unsupported location, skip
        for ep in loc_result:
            name = ep.get("name", "")
            if name and name not in seen_names:
                seen_names.add(name)
                all_endpoints.append(ep)
    return all_endpoints


def _parse_deployed_models(
    deployed_models: list,
) -> Tuple[int, Optional[str], Optional[str], int, bool]:
    """
    Aggregate dedicated resources across all deployed models on an endpoint.

    Only models with dedicatedResources are counted — automaticResources scale
    to zero and do not incur idle compute cost.

    Returns (total_min_replicas, machine_type, accel_type, accel_count, is_gpu).
    machine_type / accel_type are taken from the first dedicated model found
    (used for display/reporting; cost is computed separately by
    _compute_multi_model_cost for accuracy).
    """
    total_min_replicas = 0
    machine_type: Optional[str] = None
    accel_type: Optional[str] = None
    accel_count = 0
    is_gpu = False

    for model in deployed_models:
        dr = model.get("dedicatedResources")
        if not dr:
            continue  # automaticResources / sharedResources — scales to zero

        min_replicas = dr.get("minReplicaCount", 0) or 0
        total_min_replicas += min_replicas

        spec = dr.get("machineSpec", {})
        if machine_type is None:
            machine_type = spec.get("machineType")

        at = spec.get("acceleratorType", "ACCELERATOR_TYPE_UNSPECIFIED")
        ac = int(spec.get("acceleratorCount", 0) or 0)

        if at and at != "ACCELERATOR_TYPE_UNSPECIFIED":
            if accel_type is None:
                accel_type = at
                accel_count = ac
            if at in _GPU_ACCELERATORS:
                is_gpu = True

    return total_min_replicas, machine_type, accel_type, accel_count, is_gpu


def _compute_multi_model_cost(deployed_models: list) -> float:
    """
    Compute total monthly cost by summing cost per deployed model accurately.

    Unlike the single-model estimate, this handles endpoints with multiple deployed
    models of different machine types — each model's replicas are costed at their
    own machine/GPU rate and summed.
    """
    total = 0.0
    for model in deployed_models:
        dr = model.get("dedicatedResources")
        if not dr:
            continue
        min_replicas = dr.get("minReplicaCount", 0) or 0
        if min_replicas == 0:
            continue
        spec = dr.get("machineSpec", {})
        machine_type = spec.get("machineType")
        at = spec.get("acceleratorType", "ACCELERATOR_TYPE_UNSPECIFIED")
        ac = int(spec.get("acceleratorCount", 0) or 0)
        accel_type = at if at and at != "ACCELERATOR_TYPE_UNSPECIFIED" else None
        total += _estimate_cost(machine_type, accel_type, ac, min_replicas)
    return total


def _estimate_cost(
    machine_type: Optional[str],
    accel_type: Optional[str],
    accel_count: int,
    min_replicas: int,
) -> float:
    """
    Estimate total monthly cost for min_replicas always-on dedicated nodes.

    For a2-* and g2-* machines the GPU cost is already included in the machine price.
    For n1-*/n2-* machines with attached GPUs, add the per-GPU cost separately.
    """
    machine_cost = _MACHINE_MONTHLY_COST.get(machine_type or "", _DEFAULT_MACHINE_MONTHLY_COST)

    gpu_addon_cost = 0.0
    if accel_type and accel_type in _GPU_MONTHLY_COST_EACH:
        # a2-* and g2-* bundle GPU cost — don't double-count
        is_gpu_machine = (machine_type or "").startswith(("a2-", "g2-"))
        if not is_gpu_machine:
            gpu_addon_cost = _GPU_MONTHLY_COST_EACH[accel_type] * max(accel_count, 1)

    return (machine_cost + gpu_addon_cost) * min_replicas


def _get_prediction_counts_batch(
    monitoring_client: monitoring_v3.MetricServiceClient,
    project_id: str,
    location: str,
    days: int,
    eligible_endpoint_ids: Optional[set] = None,
) -> Optional[Tuple[Dict[str, int], set]]:
    """
    Batch query prediction counts for all Vertex AI endpoints in a location.

    Issues a single Cloud Monitoring call for the entire location (filtered by
    metric type and location label) rather than one call per endpoint.

    eligible_endpoint_ids: if provided, series for endpoint IDs not in this set
    are ignored — guards against stale or misattributed series from Cloud Monitoring.

    Returns (counts, recently_active_ids):
    - counts: {endpoint_id: total_request_count} — endpoints with no data points
      are absent from the dict (caller treats absence as "no monitoring data").
    - recently_active_ids: set of endpoint_ids that had traffic in the last 24 hours
      — kept separate from counts to preserve clean signal semantics.

    Returns None on any error; callers should skip all endpoints in the location
    (conservative fallback).
    """
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=max(days, 1))

        end_ts = timestamp_pb2.Timestamp()
        end_ts.FromDatetime(now)
        start_ts = timestamp_pb2.Timestamp()
        start_ts.FromDatetime(start)

        interval = monitoring_v3.TimeInterval(start_time=start_ts, end_time=end_ts)

        # ALIGN_SUM over the full window collapses all data points into one per
        # series, preventing double-counting from overlapping metric intervals.
        aggregation = monitoring_v3.Aggregation(
            alignment_period=duration_pb2.Duration(seconds=max(days, 1) * 86400),
            per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
        )

        results = monitoring_client.list_time_series(
            request={
                "name": f"projects/{project_id}",
                "filter": (
                    'metric.type="aiplatform.googleapis.com/prediction/online/request_count"'
                    f' AND resource.labels.location="{location}"'
                ),
                "interval": interval,
                "aggregation": aggregation,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )

        now_ts = datetime.now(timezone.utc)
        counts: Dict[str, int] = {}
        recently_active_ids: set = set()
        for series in results:
            ep_id = series.resource.labels.get("endpoint_id", "")
            if not ep_id:
                continue
            # Ignore series for endpoints not in our eligible set — guards against
            # stale metrics or partial aggregation from unrelated endpoints
            if eligible_endpoint_ids is not None and ep_id not in eligible_endpoint_ids:
                continue
            if not series.points:
                # No data points — treat as absent (caller handles no_monitoring_data)
                continue
            # Sanity guard: ALIGN_SUM should yield ≤1 point per series; >5 suggests
            # unexpected partial windows or aggregation edge cases — skip to be safe
            if len(series.points) > 5:
                continue
            # Recency guard: if any traffic landed in the last 24 hours, the endpoint
            # is recently active — tracked separately to keep count semantics clean
            try:
                timestamps = [
                    p.interval.end_time.ToDatetime(tzinfo=timezone.utc)
                    for p in series.points
                    if p.interval and p.interval.end_time
                ]
                if timestamps:
                    latest_ts = max(timestamps)
                    # Arithmetic raises TypeError if latest_ts is not a real datetime
                    # (e.g. an unexpected protobuf type) — caught below
                    if now_ts - latest_ts < timedelta(hours=24):
                        recently_active_ids.add(ep_id)
                        continue
            except (TypeError, AttributeError):
                pass  # no usable timestamp — fall through to normal count
            # ALIGN_SUM over the full window should produce exactly one point per
            # series. Sum across points defensively; duplicate/split points are
            # accumulated rather than double-counted because each represents a
            # distinct aligned window (non-overlapping by GCP guarantee).
            series_total = sum(
                point.value.int64_value or int(point.value.double_value or 0)
                for point in series.points
            )
            counts[ep_id] = counts.get(ep_id, 0) + series_total

        return counts, recently_active_ids

    except Exception:
        return None  # conservative: caller skips all endpoints in this location
