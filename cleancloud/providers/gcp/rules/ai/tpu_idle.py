"""
Rule: gcp.tpu.idle

    (spec — docs/specs/gcp/ai/tpu_idle.md)

Intent:
    Detect standalone Cloud TPU Nodes in documented billable READY state that
    show no observed accelerator-processing activity above a conservative
    threshold over a buffered review window, using documented Cloud Monitoring
    duty-cycle telemetry.

    This is a precision-first review-candidate rule. It is not proof that the
    TPU-backed job is abandoned, not proof the node is safe to stop or delete,
    and not proof of a specific monthly saving.

Covered resource families:
    - Cloud TPU Node (projects.locations.nodes, TPU v2 REST API)

Exclusions:
    - node name malformed, node ID or zone absent / unresolvable (spec 7)
    - region filter set and derived region does not exactly match (spec 7)
    - state not exactly READY (spec 3.1, 9)
    - createTime absent, unparsable, future, or node younger than full buffered
      window — create_time_utc > evaluation_window_start_utc (spec 7, 9)
    - queuedResource non-empty string — queued-resource-managed node (spec 3.5, 9)
    - multisliceNode == true — multislice node (spec 3.5, 9)
    - malformed queuedResource (non-string/non-null) or multisliceNode
      (non-bool/non-null) (spec 7)
    - monitoring client creation failure — all nodes skip; no age-only fallback
      (spec 8.6, 11.2)
    - monitoring query failure for a node — that node skips, warning issued
      (spec 11.1)
    - telemetry join state not confirmed "complete" (spec 8.3, 9) — currently
      always the case; see Current status below

Detection (pre-checks currently applied; emission blocked — see Current status):
    - state == "READY"
    - queuedResource absent/empty and not malformed
    - multisliceNode != true and not malformed
    - create_time_utc <= evaluation_window_start_utc
    - telemetry join state confirmed "complete" (spec 8.3) [blocked — see Current status]

Current status — join barrier (spec 8.3):
    The duty-cycle metric (tpu.googleapis.com/accelerator/duty_cycle) is
    published on the tpu.googleapis.com/GceTpuWorker monitored resource with
    labels resource_container, location, and worker_id. These labels do not
    include a TPU Node name. No documented first-party Google Cloud surface maps
    worker_id to the owning TPU Node, so telemetry_join_state cannot be proven
    "complete". The rule currently emits no findings. When Google publishes a
    documented worker-to-node identity surface, implement the join in
    _run_zone_diagnostic().

Cost model (spec 3.2, 10.1):
    estimated_monthly_cost_usd = None
    Pricing varies by TPU type, region, and usage option (on-demand, spot,
    committed-use); no flat estimate is appropriate.

APIs:
    - tpu.googleapis.com/v2: projects/{project}/locations/-/nodes
    - monitoring.googleapis.com: tpu.googleapis.com/accelerator/duty_cycle
      on tpu.googleapis.com/GceTpuWorker
"""

import warnings
from datetime import datetime, timedelta, timezone
from typing import List, Optional

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

# 180-second monitoring visibility buffer (spec 3.4)
_MONITORING_BUFFER_SECONDS = 180

# Idle threshold in percent units [0,100] (spec 6.4); values are percent not fraction.
# Referenced in the unreachable finding block below; not yet in a live decision path.
_DUTY_CYCLE_THRESHOLD_PCT = 2.0

# Monitoring alignment period for the non-semantic placeholder aggregation in
# _run_zone_diagnostic; not yet in a live decision path (spec 8.4, 8.5).
_ALIGNMENT_PERIOD_SECONDS = 3600

# Canonical metric and resource type (spec 8.1)
_DUTY_CYCLE_METRIC = "tpu.googleapis.com/accelerator/duty_cycle"
_DUTY_CYCLE_RESOURCE_TYPE = "tpu.googleapis.com/GceTpuWorker"


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


def _zone_to_region(zone: str) -> Optional[str]:
    """Derive GCP region from zone (e.g. 'us-central1-f' -> 'us-central1').

    Returns None when the zone string has no hyphen and region cannot be derived.
    """
    parts = zone.split("-")
    if len(parts) < 2:
        return None
    return "-".join(parts[:-1])


def _parse_rfc3339_utc(ts: str) -> Optional[datetime]:
    """Parse an RFC3339 timestamp string into a timezone-aware UTC datetime."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def _tpu_type_from_legacy(accel_type: str) -> str:
    """Map legacy acceleratorType string to acceleratorConfig.type key (context only)."""
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


def _list_tpu_nodes(session: AuthorizedSession, project_id: str) -> list[dict]:
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
            return []
        resp.raise_for_status()
        data = resp.json()
        nodes.extend(data.get("nodes", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return nodes


def _run_zone_diagnostic(
    client: monitoring_v3.MetricServiceClient,
    project_id: str,
    zone: str,
    window_start: datetime,
    window_end: datetime,
) -> None:
    """Zone-scoped diagnostic query; side-effect only — returns None.

    Called exclusively to surface permission and API-availability errors for the zone
    (spec 11.1). The query result is intentionally discarded and MUST NOT be attributed
    to any specific TPU Node: the zone filter cannot distinguish workers belonging to
    different nodes in the same zone, so no emission decision is derivable here.

    Callers: invoke at most once per zone (see zone_ok / zone_errors cache in
    find_idle_tpu_nodes). Do not call per-node and attempt to attribute results.

    When Google publishes a documented worker-to-node identity surface, replace this
    function body with join (8.3) -> coverage (8.4) -> activity (8.5) and change
    the return type to a structured result (see TODO below) so find_idle_tpu_nodes
    can derive an emission verdict from the return value.

    RPC exceptions propagate to the caller (no outer try/except here).

    TODO (structured return): When the join is implemented, return a dataclass or dict
    with discrete join_state, coverage_state, and activity_state fields so each
    dimension is independently modelled and surfaced in finding details.
    """
    # Zone-scoped diagnostic — surfaces permission / availability errors only.
    # Results MUST NOT be attributed to any specific TPU Node: zone filter alone does
    # not prove ownership; only a documented join surface would (spec 8.3).
    _ = list(
        client.list_time_series(
            request={
                "name": f"projects/{project_id}",
                "filter": (
                    f'metric.type="{_DUTY_CYCLE_METRIC}"'
                    f' AND resource.type="{_DUTY_CYCLE_RESOURCE_TYPE}"'
                    f' AND resource.labels.location="{zone}"'
                ),
                "interval": monitoring_v3.TimeInterval(
                    start_time=timestamp_pb2.Timestamp(seconds=int(window_start.timestamp())),
                    end_time=timestamp_pb2.Timestamp(seconds=int(window_end.timestamp())),
                ),
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": monitoring_v3.Aggregation(
                    # Non-semantic placeholder shape matching the intended join-aware query.
                    # alignment_period / ALIGN_MAX not used in any emission decision today.
                    alignment_period=duration_pb2.Duration(seconds=_ALIGNMENT_PERIOD_SECONDS),
                    per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_MAX,
                    # No cross_series_reducer — preserves per-worker/accelerator granularity
                    # for when the join is implementable (spec 8.2, 8.3).
                ),
            }
        )
    )


def find_idle_tpu_nodes(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    idle_days: int = _DEFAULT_IDLE_DAYS,
) -> List[Finding]:
    """
    Find Cloud TPU nodes that have been idle for an extended period.

    Currently emits no findings: the worker-to-node telemetry join (spec 8.3) cannot
    be proven with documented GCP surfaces; every node passes pre-checks but is blocked
    at the telemetry gate. See module docstring — "Current status" section.

    When the join is implemented, emits a finding only when the node is in documented
    READY state, is standalone (not queued-resource-managed or multislice), and complete
    joined duty-cycle telemetry confirms no accelerator activity above 2% over the
    buffered idle window. No age-only or monitoring-absent fallback is performed.

    IAM permissions required:
    - tpu.nodes.list (roles/tpu.viewer)
    - monitoring.timeSeries.list (roles/monitoring.viewer)
    """
    idle_days = max(1, idle_days)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    window_end = now - timedelta(seconds=_MONITORING_BUFFER_SECONDS)
    window_start = window_end - timedelta(seconds=idle_days * 86400)

    session = AuthorizedSession(credentials)
    nodes = _list_tpu_nodes(session, project_id)
    if not nodes:
        return []

    try:
        monitoring_client = monitoring_v3.MetricServiceClient(credentials=credentials)
    except Exception as e:
        warnings.warn(
            f"gcp.tpu.idle: monitoring client creation failed "
            f"({type(e).__name__}: {e}) — all nodes will be skipped (no age-only fallback)",
            UserWarning,
            stacklevel=2,
        )
        monitoring_client = None

    findings: List[Finding] = []
    # Per-zone diagnostic query cache: _run_zone_diagnostic is zone-scoped (spec 11.1);
    # caching avoids redundant API calls when multiple nodes share a zone.
    zone_ok: set[str] = set()
    zone_errors: set[str] = set()

    for node in nodes:
        # --- Identity ---
        name = node.get("name") or ""
        if not name:
            continue
        node_id = _parse_node_id(name)
        if not node_id:
            continue
        zone = _parse_location(name)
        if not zone:
            continue
        region = _zone_to_region(zone)
        if not region:
            continue

        # --- Region filter: exact match on derived region (spec 7) ---
        if region_filter and region != region_filter:
            continue

        # --- State: must be exactly READY (spec 3.1, 4) ---
        if node.get("state") != "READY":
            continue

        # --- createTime: absent/unparsable/future -> skip (spec 7) ---
        create_time = _parse_rfc3339_utc(node.get("createTime") or "")
        if create_time is None:
            continue
        if create_time > now:
            continue

        # --- Full window coverable (spec 7) ---
        if create_time > window_start:
            continue

        # --- Standalone: queuedResource absent/empty (spec 3.5, 9) ---
        queued_resource = node.get("queuedResource")
        if queued_resource is None or queued_resource == "":
            pass  # standalone
        elif isinstance(queued_resource, str):
            continue  # non-empty string -> managed by queued resource
        else:
            continue  # malformed non-string/non-null -> skip

        # --- Standalone: multisliceNode not true (spec 3.5, 9) ---
        multislice = node.get("multisliceNode")
        if multislice is None or multislice is False:
            pass  # standalone
        elif multislice is True:
            continue  # explicitly multislice
        else:
            continue  # malformed non-bool/non-null -> skip

        # --- Monitoring (no age-only fallback, spec 8.6) ---
        if monitoring_client is None:
            continue

        # Zone-level diagnostic query — one call per zone is sufficient;
        # _run_zone_diagnostic filters by location only and results are not
        # attributed to any specific node, so caching across nodes in the same
        # zone is safe (spec 11.1).
        if zone in zone_errors:
            continue
        if zone not in zone_ok:
            try:
                _run_zone_diagnostic(
                    monitoring_client,
                    project_id,
                    zone,
                    window_start,
                    window_end,
                )
                zone_ok.add(zone)
            except Exception as e:
                warnings.warn(
                    f"gcp.tpu.idle: monitoring query failed for zone '{zone}' "
                    f"({type(e).__name__}: {e}) — nodes in this zone will be skipped",
                    UserWarning,
                    stacklevel=2,
                )
                zone_errors.add(zone)
                continue

        # This rule currently emits no findings (join barrier, spec 8.3).
        # _run_zone_diagnostic returns None (side-effect only); the telemetry verdict is
        # not derived from it. "unresolved" is the single hardcoded source of truth here.
        # When the join is implemented: replace this assignment with the structured
        # verdict from a node-attributed call to _run_zone_diagnostic (see its docstring).
        telemetry = "unresolved"
        if telemetry != "confirmed_idle":
            continue

        # --- Build finding ---
        # UNREACHABLE TODAY: the guard above always skips this block because
        # _run_zone_diagnostic always returns "unresolved" (join barrier, spec 8.3).
        # When the join is implemented, ALL signal strings and detail values below must
        # be verified and updated — in particular:
        #   - The "Worker join:" signal must use actual proven joined/expected counts,
        #     not the static "complete (expected == joined workers)" string below.
        #   - "telemetry_join_state" in details must be set to the actual proven state
        #     (e.g. "complete") rather than the placeholder "unresolved" below.
        # Do NOT bypass the join barrier to reach this block without first proving
        # telemetry_join_state == "complete" per spec 8.3.
        accel_config = node.get("acceleratorConfig") or {}
        tpu_type = (accel_config.get("type") or "").strip()
        topology = (accel_config.get("topology") or "").strip()
        accel_type_legacy = (node.get("acceleratorType") or "").strip()

        if not tpu_type and accel_type_legacy:
            tpu_type = _tpu_type_from_legacy(accel_type_legacy)

        scheduling = node.get("schedulingConfig") or {}
        preemptible = bool(scheduling.get("preemptible", False))
        spot = bool(scheduling.get("spot", False))
        reserved = bool(scheduling.get("reserved", False))
        runtime = (node.get("runtimeVersion") or "").strip()

        age_days_val = (now - create_time).total_seconds() / 86400
        accel_context = tpu_type or accel_type_legacy or "unknown"
        hw_parts = [accel_context]
        if topology:
            hw_parts.append(f"topology={topology}")
        hw_label = " ".join(hw_parts)

        scheduling_parts = []
        if spot:
            scheduling_parts.append("spot")
        if preemptible:
            scheduling_parts.append("preemptible")
        if reserved:
            scheduling_parts.append("reserved")
        scheduling_context = ", ".join(scheduling_parts) or "on-demand"

        # TODO (join barrier, spec 8.3): The last four signals are aspirational
        # templates. Replace each [TODO: ...] entry with dynamically constructed
        # strings derived from actual proven join/coverage/activity values when
        # the join is implemented.
        signals = [
            f"State: READY (billable); zone: {zone}; region: {region}",
            f"createTime: {create_time.isoformat()}; node age: {age_days_val:.1f}d",
            f"Standalone: queuedResource={queued_resource!r}, multisliceNode={multislice!r}",
            f"Accelerator: {hw_label}",
            f"Scheduling: {scheduling_context}",
            f"[TODO: Worker join — actual joined/expected worker counts; "
            f"metric: {_DUTY_CYCLE_METRIC}]",
            f"Metric: {_DUTY_CYCLE_METRIC} on {_DUTY_CYCLE_RESOURCE_TYPE}",
            f"Idle window: {window_start.isoformat()} - {window_end.isoformat()} ({idle_days}d)",
            f"Threshold: {_DUTY_CYCLE_THRESHOLD_PCT}% max duty cycle",
            f"[TODO: telemetry confirmed no duty-cycle datapoint above "
            f"{_DUTY_CYCLE_THRESHOLD_PCT}% over the full buffered window]",
        ]
        if runtime:
            signals.append(f"Runtime: {runtime}")

        not_checked = [
            "Batch or scheduled jobs — duty_cycle captures real-time accelerator activity; "
            "a node used only for nightly jobs may appear idle between runs",
            "Cost impact — pricing varies by TPU type, region, and usage option; "
            "no flat estimate is appropriate",
            "Nodes shared across teams where utilization is tracked externally",
        ]

        node_display = (node.get("description") or "").strip() or node_id

        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.tpu.idle",
                resource_type="gcp.tpu.node",
                resource_id=name,
                region=region,
                title=f"Idle Cloud TPU Node ({accel_context})",
                # TODO (join barrier): replace summary/reason with telemetry-confirmed
                # text once the join is implemented (spec 8.3).
                summary=(
                    f"Cloud TPU node '{node_display}' ({accel_context}) has been in "
                    f"READY state for {age_days_val:.0f}d. "
                    f"[TODO: add joined duty-cycle telemetry confirmation (spec 8.3)]"
                ),
                reason=(
                    f"TPU node in READY state "
                    f"[TODO: add duty-cycle verdict — max <= {_DUTY_CYCLE_THRESHOLD_PCT}% "
                    f"over {idle_days}d window (spec 8.3)]"
                ),
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=Evidence(
                    signals_used=signals,
                    signals_not_checked=not_checked,
                    time_window=f"{idle_days}d",
                ),
                estimated_monthly_cost_usd=None,
                details={
                    "node_name": name,
                    "node_id": node_id,
                    "zone": zone,
                    "region": region,
                    "tpu_type": tpu_type or accel_type_legacy or None,
                    "topology": topology or None,
                    "runtime_version": runtime or None,
                    "preemptible": preemptible,
                    "spot": spot,
                    "reserved": reserved,
                    "age_days": round(age_days_val, 1),
                    "idle_days_threshold": idle_days,
                    "duty_cycle_threshold_pct": _DUTY_CYCLE_THRESHOLD_PCT,
                    "monitoring_buffer_seconds": _MONITORING_BUFFER_SECONDS,
                    # All three telemetry state fields are "unresolved" today (join barrier,
                    # spec 8.3). When the join is implemented, set each dynamically:
                    #   telemetry_join_state     — proven join state, e.g. "complete"
                    #   telemetry_coverage_state — coverage verdict from 8.4, e.g. "complete"
                    #   telemetry_state          — overall verdict, e.g. "confirmed_idle"
                    "telemetry_join_state": "unresolved",
                    "telemetry_coverage_state": "unresolved",
                    "telemetry_state": "unresolved",
                },
            )
        )

    return findings


find_idle_tpu_nodes.RULE_ID = "gcp.tpu.idle"
