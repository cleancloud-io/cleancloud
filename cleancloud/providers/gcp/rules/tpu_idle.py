import warnings
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from google.api_core.exceptions import (
    BadGateway,
    DeadlineExceeded,
    GatewayTimeout,
    InternalServerError,
    ResourceExhausted,
    ServiceUnavailable,
    TooManyRequests,
)
from google.auth.transport.requests import AuthorizedSession
from google.cloud import monitoring_v3
from google.protobuf import duration_pb2, timestamp_pb2

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "gcp.tpu.idle",
    "category": "ai",
    "service": "tpu",
    "cost_impact": "high",
}

# Default idle window — 7 days of near-zero duty_cycle = confidently idle
_DEFAULT_IDLE_DAYS = 7

# duty_cycle fraction at or below which a node is considered idle.
# 2% allows for brief health-check spikes without masking genuine utilization.
# max() is used (not mean/p95) so that any single active sample keeps the node
# out of the idle bucket — this avoids flagging intermittently-used nodes.
_DUTY_CYCLE_IDLE_THRESHOLD = 0.02

# TPU node states that incur compute charges.
# NOTE: If GCP adds new billable states (e.g. HIBERNATED), update this set.
# Source: https://cloud.google.com/tpu/docs/managing-tpus-tpu-vm
_BILLABLE_STATES = {"READY"}

# Per-chip hourly cost — us-central1 on-demand reference rates.
# All values are per chip-hour. Actual cost varies by region and commitment.
_CHIP_HOURLY_COST: dict[str, float] = {
    "V2": 1.50,  # $1.50/chip-hr (v2 pod, published GCP rate)
    "V3": 2.20,  # $2.20/chip-hr (v3 device; v3 pod is $2.00 — use higher)
    "V4": 3.22,  # $3.22/chip-hr (published GCP rate, us-central1)
    "V5LITE_POD": 1.20,  # $1.20/chip-hr (TPU v5e litepod, published)
    "V5P": 4.20,  # $4.20/chip-hr (TPU v5p, published)
    "V6E": 2.40,  # $2.40/chip-hr [est] — no confirmed published rate as of 2025
}
_DEFAULT_CHIP_HOURLY_COST = 2.00  # conservative fallback for unknown/future types

# Types whose per-chip pricing is estimated (not yet officially published).
_PRICING_ESTIMATED_TYPES = frozenset({"V6E"})

# Types where topology-based chip counting is unreliable: for V5+/V6E pod slices,
# topology encodes the full pod shape rather than the per-node slice count.
_TOPOLOGY_UNRELIABLE_TYPES = frozenset({"V5LITE_POD", "V5P", "V6E"})

_HOURS_PER_MONTH = 730.0


def _parse_location(name: str) -> Optional[str]:
    """Extract zone from node name: projects/.../locations/{zone}/nodes/..."""
    parts = name.split("/")
    try:
        idx = parts.index("locations")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None


def _parse_node_id(name: str) -> str:
    """Extract node ID from resource name (.../nodes/{node_id})."""
    return name.rsplit("/", 1)[-1] if name else ""


def _zone_to_region(zone: str) -> str:
    """Derive GCP region from zone (e.g. 'us-central1-f' → 'us-central1').

    Uses split/join rather than rsplit to handle multi-hyphen region prefixes
    (e.g. 'northamerica-northeast1-a' → 'northamerica-northeast1') correctly.
    Falls back to the zone itself if it has no hyphen.
    """
    parts = zone.split("-")
    return "-".join(parts[:-1]) if len(parts) > 1 else zone


def _tpu_type_from_legacy(accel_type: str) -> str:
    """Map legacy acceleratorType string to acceleratorConfig.type key.

    Examples: "v2-8" → "V2", "v4-8" → "V4", "v5litepod-4" → "V5LITE_POD".
    Returns "" if the type is unrecognised.
    """
    lower = accel_type.lower()
    if lower.startswith("v2"):
        return "V2"
    if lower.startswith("v3"):
        return "V3"
    if lower.startswith("v4"):
        return "V4"
    if "litepod" in lower or lower.startswith("v5e"):
        return "V5LITE_POD"
    if lower.startswith("v5p"):
        return "V5P"
    if lower.startswith("v6e"):
        return "V6E"
    return ""


def _chip_count(
    accel_type_legacy: str, topology: Optional[str], tpu_type: str = ""
) -> tuple[int, bool]:
    """Derive chip count for a TPU node.

    Returns (chips, is_approximate). is_approximate is True when the count was
    derived from pod-shape topology for V5+/V6E types (may overstate slice count)
    or when no usable information was found at all.

    Priority differs by type:

    V2–V4 (topology is reliable slice geometry):
      1. topology multiplication  → exact
      2. legacy acceleratorType suffix → exact
      3. fallback 1 → approximate

    V5+/V6E (topology may encode pod shape, not slice count):
      1. legacy acceleratorType suffix → exact (encodes slice count directly)
      2. topology multiplication → approximate (pod shape, may overstate)
      3. fallback 1 → approximate
    """

    def _from_topology(t: str) -> Optional[int]:
        try:
            parts = [int(x) for x in t.lower().split("x") if x]
            count = 1
            for p in parts:
                count *= p
            return count if count > 0 else None
        except (ValueError, AttributeError):
            return None

    def _from_legacy(s: str) -> Optional[int]:
        try:
            return max(1, int(s.rsplit("-", 1)[-1]))
        except (ValueError, IndexError):
            return None

    if tpu_type in _TOPOLOGY_UNRELIABLE_TYPES:
        # Legacy suffix encodes the per-node slice count directly; prefer it.
        if accel_type_legacy:
            v = _from_legacy(accel_type_legacy)
            if v is not None:
                return v, False
        # Fall back to topology — may reflect pod shape, so mark approximate.
        if topology:
            v = _from_topology(topology)
            if v is not None:
                return v, True
    else:
        # For V2–V4, topology gives the exact slice geometry.
        if topology:
            v = _from_topology(topology)
            if v is not None:
                return v, False
        if accel_type_legacy:
            v = _from_legacy(accel_type_legacy)
            if v is not None:
                return v, False

    return 1, True


def _hourly_cost(
    tpu_type: str, chips: int, chip_count_approximate: bool = False
) -> tuple[float, str]:
    """Return (hourly_cost_usd, pricing_confidence) for a TPU node.

    pricing_confidence is "estimated" when any of:
    - The type has no entry in _CHIP_HOURLY_COST (unknown type, uses fallback rate)
    - The type is in _PRICING_ESTIMATED_TYPES (rate not officially published)
    - chip_count_approximate is True (chip count may be wrong; cost inherits uncertainty)
    """
    rate = _CHIP_HOURLY_COST.get(tpu_type, _DEFAULT_CHIP_HOURLY_COST)
    estimated = (
        tpu_type not in _CHIP_HOURLY_COST
        or tpu_type in _PRICING_ESTIMATED_TYPES
        or chip_count_approximate
    )
    return rate * chips, ("estimated" if estimated else "published")


def _compute_risk(confidence: ConfidenceLevel, hourly_cost: float) -> RiskLevel:
    """Map (confidence, hourly_cost) to a RiskLevel.

    HIGH confidence + expensive (≥$10/hr) → CRITICAL
    HIGH confidence + cheaper          → HIGH
    LOW confidence (age-only fallback) → MEDIUM
    """
    if confidence == ConfidenceLevel.HIGH:
        return RiskLevel.CRITICAL if hourly_cost >= 10.0 else RiskLevel.HIGH
    return RiskLevel.MEDIUM


def _list_tpu_nodes(session: AuthorizedSession, project_id: str) -> list:
    """List all TPU nodes across all zones for a project.

    Uses the locations/- wildcard. Returns [] if the TPU API is not enabled.
    Raises PermissionError on 403.
    """
    url = f"https://tpu.googleapis.com/v2/projects/{project_id}/locations/-/nodes"
    nodes: list = []
    page_token: Optional[str] = None
    while True:
        params: dict = {"pageSize": 100}
        if page_token:
            params["pageToken"] = page_token
        resp = session.get(url, params=params)
        if resp.status_code == 403:
            # Distinguish SERVICE_DISABLED (API not enabled) from true 403 (IAM).
            try:
                reason = resp.json().get("error", {}).get("details", [{}])[0].get("reason", "")
            except Exception:
                reason = ""
            if reason == "SERVICE_DISABLED":
                return []
            raise PermissionError(
                f"tpu.nodes.list permission denied for project {project_id}. "
                "Grant roles/tpu.viewer to the scanning identity."
            )
        if resp.status_code == 404:
            # TPU API not enabled or no nodes in any zone — treat as empty.
            return []
        resp.raise_for_status()
        data = resp.json()
        nodes.extend(data.get("nodes", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return nodes


def _fetch_duty_cycles(credentials, project_id: str, idle_days: int) -> dict[str, float]:
    """Fetch max duty_cycle per TPU node over the past idle_days days.

    Returns a dict mapping canonical node short-name → max_duty_cycle (0.0–1.0).
    The canonical key is the last path segment of whichever label is populated
    (resource_name or node_id), normalised via rsplit("/", 1)[-1].

    A single retry is attempted on transient errors before falling back to the
    age-based detection path. Permanent errors (auth, quota) are not retried.

    Returns {} on failure — monitoring is optional; callers fall back to age.

    Note on scale: list_time_series is paginated by the Python client iterator;
    large projects with many TPU nodes may incur multiple API calls.
    """

    def _is_transient(exc: Exception) -> bool:
        """True for errors likely to succeed on retry (network/timeout/throttle)."""
        return isinstance(
            exc,
            (
                DeadlineExceeded,  # timeout
                ResourceExhausted,  # 429 quota
                TooManyRequests,  # 429 rate limit
                ServiceUnavailable,  # 503
                BadGateway,  # 502
                GatewayTimeout,  # 504
                InternalServerError,  # 500 (transient backend errors)
            ),
        )

    last_exc: Optional[Exception] = None
    for attempt in range(2):
        try:
            client = monitoring_v3.MetricServiceClient(credentials=credentials)
            now = datetime.now(timezone.utc)
            start = now - timedelta(days=idle_days)
            interval = monitoring_v3.TimeInterval(
                start_time=timestamp_pb2.Timestamp(seconds=int(start.timestamp())),
                end_time=timestamp_pb2.Timestamp(seconds=int(now.timestamp())),
            )
            results = client.list_time_series(
                request={
                    "name": f"projects/{project_id}",
                    # tpu_worker is the monitored resource type for this metric.
                    # Do not use resource.type="tpu_node" — not valid for this metric.
                    # If GCP changes this schema, the query returns {} and the rule
                    # falls back to age-based detection rather than erroring out.
                    "filter": (
                        'metric.type="tpu.googleapis.com/node/accelerator/duty_cycle"'
                        ' AND resource.type="tpu_worker"'
                    ),
                    "interval": interval,
                    "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                    "aggregation": monitoring_v3.Aggregation(
                        alignment_period=duration_pb2.Duration(seconds=3600),
                        per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_MAX,
                        cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_MAX,
                        # Group by both labels: resource_name (full path, preferred)
                        # and node_id (short name, documented for tpu_worker).
                        group_by_fields=[
                            "resource.labels.resource_name",
                            "resource.labels.node_id",
                        ],
                    ),
                }
            )
            duty_cycles: dict[str, float] = {}
            for ts in results:
                if not ts.points:
                    continue
                labels = ts.resource.labels
                # Normalise to the last path segment as the canonical key so
                # "projects/.../nodes/my-tpu" and "my-tpu" map to the same entry.
                raw_label = labels.get("resource_name") or labels.get("node_id", "")
                if not raw_label:
                    continue
                canonical = raw_label.rsplit("/", 1)[-1]
                # max() is intentional: any single active sample keeps the node
                # out of the idle bucket. mean/p95 would mask intermittent usage.
                max_val = max((p.value.double_value for p in ts.points), default=0.0)
                duty_cycles[canonical] = max(duty_cycles.get(canonical, 0.0), max_val)
            return duty_cycles
        except Exception as exc:
            last_exc = exc
            if attempt == 0 and _is_transient(exc):
                continue  # retry once for transient errors only
            break  # permanent error (auth, permission, quota) — don't retry
    warnings.warn(
        f"gcp.tpu.idle: monitoring query failed ({type(last_exc).__name__}: {last_exc}) "
        "— falling back to age-based detection",
        stacklevel=2,
    )
    return {}


def find_idle_tpu_nodes(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    idle_days: int = _DEFAULT_IDLE_DAYS,
) -> List[Finding]:
    """
    Find Cloud TPU nodes that have been idle for an extended period.

    TPU nodes in READY state incur compute charges regardless of utilization.
    An idle TPU v4 node (4 chips) costs ~$12.88/hr; a v5p-8 costs ~$33.60/hr.
    Forgetting to delete a TPU after a training run is a common cause of runaway cost.

    Detection logic:
    - Lists all TPU nodes in READY state via the Cloud TPU v2 REST API
    - Queries Cloud Monitoring for tpu.googleapis.com/node/accelerator/duty_cycle
      over the past idle_days days (7 days by default)
    - Nodes with max duty_cycle ≤ 2% AND age ≥ idle_days are flagged HIGH confidence
    - Nodes with max duty_cycle ≤ 2% but age < idle_days are skipped (not yet idle)
    - If monitoring data is unavailable, nodes older than idle_days are flagged
      at LOW confidence (existence duration is not a reliable idle proxy)

    IAM permissions required:
    - tpu.nodes.list (roles/tpu.viewer)
    - monitoring.timeSeries.list (roles/monitoring.viewer) — optional; fallback to age
    """
    idle_days = max(1, idle_days)
    session = AuthorizedSession(credentials)
    now = datetime.now(timezone.utc)

    nodes = _list_tpu_nodes(session, project_id)
    if not nodes:
        return []

    ready_nodes = [n for n in nodes if n.get("state") in _BILLABLE_STATES]
    if not ready_nodes:
        return []

    # Batch monitoring query — one call covers all nodes in the project.
    duty_cycles = _fetch_duty_cycles(credentials, project_id, idle_days)

    findings: List[Finding] = []
    unmatched_node_ids: List[str] = []

    for node in ready_nodes:
        name = node.get("name", "")
        node_id = _parse_node_id(name)
        zone = _parse_location(name) or "unknown"

        if region_filter and not zone.startswith(region_filter):
            continue

        # Prefer acceleratorConfig (new API); fall back to legacy acceleratorType.
        accel_config = node.get("acceleratorConfig") or {}
        tpu_type = (accel_config.get("type") or "").upper()
        topology = (accel_config.get("topology") or "").strip()
        accel_type_legacy = (node.get("acceleratorType") or "").strip()

        if not tpu_type and accel_type_legacy:
            tpu_type = _tpu_type_from_legacy(accel_type_legacy)

        chips, chip_count_approximate = _chip_count(accel_type_legacy, topology or None, tpu_type)
        hourly, pricing_confidence = _hourly_cost(tpu_type, chips, chip_count_approximate)
        monthly = hourly * _HOURS_PER_MONTH

        create_str = node.get("createTime", "")
        age_days: Optional[float] = None
        if create_str:
            try:
                create_dt = datetime.fromisoformat(create_str.replace("Z", "+00:00"))
                if create_dt.tzinfo is None:
                    create_dt = create_dt.replace(tzinfo=timezone.utc)
                age_days = (now - create_dt).total_seconds() / 86400
            except (ValueError, AttributeError):
                pass

        # Idle detection — monitoring first, age fallback.
        # Canonical lookup key (short name) matches _fetch_duty_cycles normalisation.
        node_duty_cycle: Optional[float] = duty_cycles.get(node_id)
        if node_duty_cycle is None and duty_cycles:
            # duty_cycles is non-empty but this node has no entry — collect for
            # a single aggregated warning rather than one warning per node.
            unmatched_node_ids.append(node_id)

        if node_duty_cycle is not None:
            if node_duty_cycle > _DUTY_CYCLE_IDLE_THRESHOLD:
                continue  # Active — skip
            # Enforce the idle_days minimum: nodes younger than the window
            # cannot have been idle for idle_days by definition. Skip them
            # regardless of what duty_cycle reports — the rule contract is
            # "idle for 7+ days", not "low utilisation at time of scan".
            if age_days is None or age_days < idle_days:
                continue
            confidence = ConfidenceLevel.HIGH
            idle_signal = (
                f"max duty_cycle={node_duty_cycle:.1%} over {idle_days}d window "
                f"(threshold: {_DUTY_CYCLE_IDLE_THRESHOLD:.0%})"
            )
        elif age_days is not None and age_days >= idle_days:
            # Age-only fallback: createTime tells us when the node was created,
            # NOT when it was last used. LOW confidence.
            confidence = ConfidenceLevel.LOW
            idle_signal = (
                f"no monitoring data; node exists for {age_days:.0f}d with no "
                f"observed activity (≥ {idle_days}d threshold) — existence "
                "duration is not a reliable idle proxy"
            )
        else:
            continue  # Too new or no age data — not enough signal

        risk = _compute_risk(confidence, hourly)

        runtime = (node.get("runtimeVersion") or "").strip()
        scheduling = node.get("schedulingConfig") or {}
        preemptible = scheduling.get("preemptible", False)
        spot = scheduling.get("spot", False)

        type_str = accel_type_legacy or tpu_type or "unknown"
        hw_parts = [type_str]
        if topology:
            hw_parts.append(f"[{topology}]")
        hw_parts.append(f"{chips} chip{'s' if chips != 1 else ''}")
        hardware_label = ", ".join(hw_parts)

        age_str = f"{age_days:.1f}d" if age_days is not None else "unknown"
        node_region = _zone_to_region(zone) if zone != "unknown" else "unknown"
        # Pricing is a baseline estimate: us-central1 on-demand rate, not
        # adjusted for actual region, committed use, or customer agreements.
        pricing_note = (
            f"baseline estimate, us-central1 on-demand (region: {node_region}, zone: {zone})"
        )

        scheduling_note: Optional[str] = None
        if spot:
            scheduling_note = (
                "Scheduling: spot — cost NOT adjusted for spot discount (~60–70% lower); "
                "node may have been preempted rather than left idle"
            )
        elif preemptible:
            scheduling_note = (
                "Scheduling: preemptible — cost NOT adjusted for preemptible discount "
                "(~30% lower); node may have been interrupted rather than left idle"
            )

        signals = [
            f"Node state: READY (billable) — age: {age_str}",
            f"Idle signal: {idle_signal}",
            f"Hardware: {hardware_label}",
            f"Burn rate: ~${hourly:.2f}/hr ({chips} chip{'s' if chips != 1 else ''} "
            f"× ${hourly / chips:.4g}/chip-hr; {pricing_note})",
        ]
        if runtime:
            signals.append(f"Runtime: {runtime}")
        if scheduling_note:
            signals.append(scheduling_note)

        not_checked = [
            "Batch or scheduled jobs — duty_cycle captures real-time utilization only; "
            "a node running nightly jobs may appear idle between runs; consider "
            "increasing idle_days for batch workloads",
            "Cost shown is a us-central1 on-demand baseline estimate; actual cost "
            f"varies by region ({node_region}), committed use, spot/preemptible "
            "discounts, and customer pricing agreements",
            "duty_cycle metric not always emitted for newer TPU types (V5+, V6E) "
            "or nodes that have never had a workload submitted — no data ≠ idle",
            "Nodes shared across teams where utilization is tracked externally",
        ]

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=not_checked,
            time_window=f"{idle_days}d",
        )

        node_display = (node.get("description") or "").strip() or node_id
        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.tpu.idle",
                resource_type="gcp.tpu.node",
                resource_id=name or node_id,
                region=zone,
                title=f"Idle Cloud TPU Node ({hardware_label})",
                summary=(
                    (
                        f"Cloud TPU node '{node_display}' ({hardware_label}) has "
                        f"near-zero utilization (max duty_cycle={node_duty_cycle:.1%}) "
                        f"over the past {idle_days} days in READY state, "
                        f"costing ~${hourly:.2f}/hr (~${monthly:,.0f}/mo)."
                    )
                    if node_duty_cycle is not None
                    else (
                        f"Cloud TPU node '{node_display}' ({hardware_label}) has existed "
                        f"for ≥{idle_days} days in READY state with no utilization data "
                        f"(heuristic: existence duration only — utilization unknown), "
                        f"costing ~${hourly:.2f}/hr (~${monthly:,.0f}/mo)."
                    )
                ),
                reason=(
                    (
                        f"TPU node in READY state with near-zero utilization "
                        f"(duty_cycle ≤ {_DUTY_CYCLE_IDLE_THRESHOLD:.0%}) "
                        f"for {idle_days} days"
                    )
                    if node_duty_cycle is not None
                    else (
                        f"TPU node in READY state for ≥{idle_days} days "
                        f"(heuristic: age only — no utilization data available)"
                    )
                ),
                risk=risk,
                confidence=confidence,
                detected_at=now,
                evidence=evidence,
                estimated_monthly_cost_usd=round(monthly, 2),
                details={
                    "node_name": name,
                    "node_id": node_id,
                    "zone": zone,
                    "region": node_region,
                    "tpu_type": tpu_type or accel_type_legacy or None,
                    "topology": topology or None,
                    "chip_count": chips,
                    "chip_count_approximate": chip_count_approximate,
                    "runtime_version": runtime or None,
                    "preemptible": preemptible,
                    "spot": spot,
                    "age_days": round(age_days, 1) if age_days is not None else None,
                    "max_duty_cycle": node_duty_cycle,
                    "idle_days_threshold": idle_days,
                    "hourly_cost_usd": round(hourly, 4),
                    "pricing_confidence": pricing_confidence,
                    "pricing_scope": "us_central1_reference_not_region_adjusted",
                },
            )
        )

    if unmatched_node_ids:
        warnings.warn(
            f"gcp.tpu.idle: {len(unmatched_node_ids)} node(s) in project '{project_id}' "
            f"had no duty_cycle data in monitoring — key may not match monitoring label; "
            f"fell back to age-based detection. Node IDs: {', '.join(unmatched_node_ids)}",
            stacklevel=2,
        )

    return findings
