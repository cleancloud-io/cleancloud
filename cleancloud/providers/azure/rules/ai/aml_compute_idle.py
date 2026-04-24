"""
Rule: azure.aml.compute.idle

Intent:
    Detect managed Azure Machine Learning compute clusters (AmlCompute) that retain
    billable baseline capacity while showing no observed per-cluster job activity over
    a fixed 14-day observation window.

    This rule is deliberately precision-first. It requires BOTH confirmed positive
    baseline node allocation (min_node_count > 0 with current nodes allocated) AND
    confirmed zero per-cluster activity (Active Nodes metric at zero for the cluster)
    before emitting. It is a conservative review-candidate rule only and does not
    prove that deleting the cluster is safe.

Exclusions:
    - id absent or empty
    - name absent or empty
    - workspace.name absent or empty
    - outside optional region filter (compute resource location, exact lowercase match;
      spaces and hyphens preserved)
    - compute_type does not resolve to exactly "AmlCompute" (SDK+nested, conflict -> skip)
    - provisioning_state does not resolve to exactly "Succeeded" (SDK+nested, conflict -> skip)
    - allocation_state does not resolve to exactly "Steady" (SDK+nested, conflict -> skip)
    - created_at absent, invalid, in the future, or cluster age < 14 days
    - min_node_count <= 0 or unresolvable
    - current_node_count negative, unresolvable, or < min_node_count
    - Active Nodes metric cannot be resolved reliably for the target cluster
      (no ClusterName-scoped series, < 95% daily-bucket coverage, unusable shape)
    - Active Nodes metric is non-zero over the 14-day window
    - per-compute record resolution or metric retrieval fails
    - per-workspace compute listing fails (skip that workspace)

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)
    Risk = MEDIUM (always)
    Confidence = HIGH (always, when all conditions met)

APIs:
    - Microsoft.MachineLearningServices/workspaces/read
    - Microsoft.MachineLearningServices/workspaces/computes/read
    - Microsoft.Insights/metrics/read
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Optional

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces
from azure.mgmt.monitor import MonitorManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.aml.compute.idle"
_RESOURCE_TYPE = "azure.aml.compute"
_IDLE_WINDOW_DAYS = 14  # fixed per spec 6.3
_MIN_AGE_DAYS = 14  # spec 8.8
_MIN_COVERAGE = 0.95  # spec 9.3

RULE_METADATA = {
    "id": _RULE_ID,
    "category": "ai",
    "service": "machinelearning",
    "cost_impact": "high",
}


class _MetricResult(Enum):
    ACTIVE = "ACTIVE"
    ZERO = "ZERO"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def _norm_location(s: str) -> str:
    """Lowercase only — exact lowercase match per spec 7."""
    return s.lower() if s else ""


def _extract_resource_group(resource_id: Optional[str]) -> Optional[str]:
    """Extract resource group name from Azure ARM resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        return parts[idx + 1]
    except (StopIteration, IndexError):
        return None


# ---------------------------------------------------------------------------
# State resolvers (spec 9.1)
# ---------------------------------------------------------------------------


def _resolve_str_field(obj, snake: str, camel: str) -> Optional[str]:
    """
    Resolve a string field from SDK snake_case then raw camelCase.
    Returns None on conflict or absent.
    """
    if obj is None:
        return None
    sdk_val = getattr(obj, snake, None)
    raw_val = getattr(obj, camel, None)
    if sdk_val is not None and raw_val is not None and sdk_val != raw_val:
        return None  # conflict -> skip
    val = sdk_val if sdk_val is not None else raw_val
    return val if isinstance(val, str) else None


def _resolve_int_field(obj, snake: str, camel: str) -> Optional[int]:
    """
    Resolve an integer field from SDK snake_case then raw camelCase.
    Tries snake first; falls back to camel. Returns parsed int or None.
    Range checks (>0, >=0) are the caller's responsibility.
    """
    if obj is None:
        return None
    val = getattr(obj, snake, None)
    if val is None:
        val = getattr(obj, camel, None)
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _to_detail_str(v) -> Optional[str]:
    """Serialize any SDK value to a JSON-safe string for finding details."""
    return str(v) if v is not None else None


def _resolve_compute_type(compute) -> Optional[str]:
    """
    Resolve compute_type from compute.properties (SDK+nested, spec 9.1).
    Only "AmlCompute" is eligible; conflict or absent -> None.
    """
    outer = getattr(compute, "properties", None)
    return _resolve_str_field(outer, "compute_type", "computeType")


def _resolve_provisioning_state(compute) -> Optional[str]:
    """
    Resolve provisioning_state from compute.properties (SDK+nested, spec 9.1).
    Only "Succeeded" is eligible; conflict or absent -> None.
    """
    outer = getattr(compute, "properties", None)
    return _resolve_str_field(outer, "provisioning_state", "provisioningState")


def _resolve_allocation_state(compute) -> Optional[str]:
    """
    Resolve allocation_state from compute.properties.properties (SDK+nested, spec 9.1).
    Only "Steady" is eligible; conflict or absent -> None.
    """
    outer = getattr(compute, "properties", None)
    inner = getattr(outer, "properties", None) if outer is not None else None
    return _resolve_str_field(inner, "allocation_state", "allocationState")


def _resolve_created_at(compute) -> Optional[datetime]:
    """
    Resolve creation timestamp from compute.properties.created_on (spec 7).
    Returns UTC-aware datetime, or None if absent, invalid, or in the future.
    """
    outer = getattr(compute, "properties", None)
    if outer is None:
        return None
    raw = getattr(outer, "created_on", None)
    if raw is None:
        raw = getattr(outer, "createdOn", None)
    if raw is None:
        return None

    if isinstance(raw, datetime):
        ts = raw if raw.tzinfo is not None else raw.replace(tzinfo=timezone.utc)
    elif isinstance(raw, str):
        try:
            ts = datetime.fromisoformat(raw.rstrip("Z"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    else:
        return None

    if ts > datetime.now(timezone.utc):
        return None  # future timestamp -> invalid -> skip
    return ts


def _resolve_min_node_count(compute) -> Optional[int]:
    """
    Resolve min_node_count from scale_settings (spec 9.2).

    Tries SDK snake_case first, then raw camelCase for both the scale_settings
    container and the min_node_count field itself. Returns a known positive
    integer, or None (absent, zero, negative, invalid).
    """
    outer = getattr(compute, "properties", None)
    inner = getattr(outer, "properties", None) if outer is not None else None
    if inner is None:
        return None
    # scale_settings container: SDK snake_case or raw camelCase
    scale = getattr(inner, "scale_settings", None)
    if scale is None:
        scale = getattr(inner, "scaleSettings", None)
    if scale is None:
        return None
    n = _resolve_int_field(scale, "min_node_count", "minNodeCount")
    return n if n is not None and n > 0 else None


def _resolve_current_node_count(compute) -> Optional[int]:
    """
    Resolve current_node_count from AmlComputeProperties (spec 9.2).

    Tries SDK snake_case first, then raw camelCase. Returns non-negative
    integer, or None (absent, negative, invalid).
    """
    outer = getattr(compute, "properties", None)
    inner = getattr(outer, "properties", None) if outer is not None else None
    if inner is None:
        return None
    n = _resolve_int_field(inner, "current_node_count", "currentNodeCount")
    return n if n is not None and n >= 0 else None


# ---------------------------------------------------------------------------
# Activity-metric contract (spec 9.3)
# ---------------------------------------------------------------------------


def _series_is_cluster_scoped(ts, compute_name: str) -> bool:
    """
    Return True only when timeseries metadata confirms ClusterName == compute_name.

    Spec 9.3.2 requires per-cluster scoping via the documented ClusterName
    dimension. Spec 9.3.3 prohibits workspace-level fallback to prove idleness.
    A series without verified ClusterName metadata cannot be trusted as
    cluster-specific and must be skipped (spec 9.3.7 "no valid series").

    The dimension key is matched case-insensitively ("ClusterName" / "clusterName");
    the dimension value is matched exactly (same case as the compute name).

    Two metadata shapes are tolerated:
    - mv.name.value  (LocalizableString — standard SDK object)
    - mv.name        (plain str — surfaced by some SDK versions / REST responses)
    """
    metadata_values = getattr(ts, "metadata_values", None) or []
    try:
        for mv in metadata_values:
            # Dimension key: try LocalizableString shape first, then plain string fallback.
            name_obj = getattr(mv, "name", None)
            dim_name = getattr(name_obj, "value", None)
            if not isinstance(dim_name, str):
                dim_name = name_obj if isinstance(name_obj, str) else None
            # Dimension value
            dim_value = getattr(mv, "value", None)
            if (
                isinstance(dim_name, str)
                and dim_name.lower() == "clustername"
                and isinstance(dim_value, str)
                and dim_value == compute_name
            ):
                return True
    except (AttributeError, TypeError):
        pass
    return False


def _evaluate_metric(
    monitor_client,
    workspace_id: str,
    compute_name: str,
    window_start: datetime,
    window_end: datetime,
) -> _MetricResult:
    """
    Evaluate the Active Nodes metric for the target cluster per spec 9.3.

    Queries with ClusterName dimension filter (spec 9.3.2). No unfiltered workspace-
    level fallback permitted (spec 9.3.3). No fixed interval so Azure Monitor auto-
    selects the finest available granularity; activity is evaluated at each returned
    source bucket before any UTC-day normalization (spec 9.3.4). >= 95% UTC-day
    coverage is required.

    Each returned timeseries is verified against the ClusterName dimension
    metadata before any datapoints are consumed. Series without confirmed
    ClusterName == compute_name metadata are skipped entirely (spec 9.3.2,
    9.3.3). If no series can be verified as cluster-specific, UNKNOWN is
    returned (spec 9.3.7 "no valid series").

    Coverage is evaluated over fully-elapsed UTC day buckets only. Both expected_buckets
    and the datapoint acceptance window are capped symmetrically at midnight(window_end).
    This excludes the current partial UTC day from both sides so it cannot overstate
    coverage and cannot mask a missing complete past day.

    Fail-closed on unusable response shapes (spec 9.3.7):
    - absent or non-datetime timestamp  -> UNKNOWN (entire metric)
    - non-numeric Maximum value         -> UNKNOWN (entire metric)
    - malformed series element          -> UNKNOWN (entire metric)

    Datapoints with no Maximum value reduce bucket coverage toward the threshold,
    driving toward UNKNOWN via the coverage check (not fail-close).
    """
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{window_start.strftime(fmt)}/{window_end.strftime(fmt)}"

    first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
    # Both expected_buckets and the datapoint acceptance window are capped at
    # last_complete_midnight so they are consistent. The current partial UTC day
    # (window_end = now, mid-day) is excluded from both sides: including it in
    # expected_buckets would cause spurious UNKNOWN (Azure Monitor may not have
    # emitted today's datapoint yet); including it in observed but not expected
    # would let today's partial bucket mask a missing prior day, allowing a false
    # emit on a rule that must be fail-closed.
    last_complete_midnight = window_end.replace(hour=0, minute=0, second=0, microsecond=0)
    expected_buckets = int((last_complete_midnight - first_bucket).total_seconds() // 86400)
    if expected_buckets == 0:
        return _MetricResult.UNKNOWN

    try:
        response = monitor_client.metrics.list(
            workspace_id,
            metricnames="Active Nodes",
            timespan=timespan,
            # No interval= parameter: Azure Monitor auto-selects the finest available
            # granularity. This preserves source-bucket granularity so short-lived
            # activity is not diluted away (spec 9.3.4).
            aggregation="Maximum",
            filter=f"ClusterName eq '{compute_name}'",
        )
    except Exception:
        return _MetricResult.UNKNOWN

    if not hasattr(response, "value") or response.value is None:
        return _MetricResult.UNKNOWN

    # Per-bucket maximum across all returned timeseries for the target cluster.
    # Coverage is tracked per UTC day bucket (spec 9.3 definitions).
    bucket_max: dict = {}

    try:
        for metric in response.value:
            for ts in getattr(metric, "timeseries", None) or []:
                if not _series_is_cluster_scoped(ts, compute_name):
                    continue  # not verified as cluster-specific; skip per spec 9.3.2/9.3.3
                for data in getattr(ts, "data", None) or []:
                    if data.timestamp is None:
                        return _MetricResult.UNKNOWN  # unparseable -> fail-closed

                    ts_dt = data.timestamp
                    if not isinstance(ts_dt, datetime):
                        return _MetricResult.UNKNOWN  # unparseable timestamp -> fail-closed

                    val = getattr(data, "maximum", None)
                    if val is None:
                        continue  # sparse/missing -> reduces coverage, not fail-close
                    if not isinstance(val, (int, float)):
                        return _MetricResult.UNKNOWN  # non-numeric -> fail-closed

                    ts_utc = (
                        ts_dt if ts_dt.tzinfo is not None else ts_dt.replace(tzinfo=timezone.utc)
                    )
                    if not (window_start <= ts_utc < last_complete_midnight):
                        continue  # outside eligible bucket range; today's partial day excluded

                    key = ts_utc.strftime("%Y-%m-%dT00:00:00Z")
                    existing = bucket_max.get(key)
                    bucket_max[key] = max(existing, val) if existing is not None else val
    except (AttributeError, TypeError, ValueError):
        return _MetricResult.UNKNOWN  # malformed response shape -> fail-closed

    observed = len(bucket_max)
    if observed == 0:
        return _MetricResult.UNKNOWN
    if observed / expected_buckets < _MIN_COVERAGE:
        return _MetricResult.UNKNOWN

    signal = sum(bucket_max.values())
    return _MetricResult.ACTIVE if signal > 0 else _MetricResult.ZERO


# ---------------------------------------------------------------------------
# Main rule function
# ---------------------------------------------------------------------------


def find_idle_aml_compute(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client=None,
    monitor_client=None,
) -> List[Finding]:
    """
    Find AML compute clusters with min_node_count > 0 and no observed active nodes
    for 14 days.

    IAM permissions:
    - Microsoft.MachineLearningServices/workspaces/read
    - Microsoft.MachineLearningServices/workspaces/computes/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []

    ml_client = client or AzureMachineLearningWorkspaces(
        credential=credential, subscription_id=subscription_id
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=_IDLE_WINDOW_DAYS)

    # Subscription-wide workspace inventory (spec 12: propagate if this fails)
    for workspace in ml_client.workspaces.list_by_subscription():
        # spec 8.3: workspace name guard
        ws_name = getattr(workspace, "name", None)
        if not ws_name:
            continue

        rg = _extract_resource_group(getattr(workspace, "id", None))
        if not rg:
            continue

        try:
            for compute in ml_client.machine_learning_compute.list_by_workspace(rg, ws_name):
                try:
                    # spec 8.1: id guard
                    compute_id = getattr(compute, "id", None)
                    if not compute_id:
                        continue

                    # spec 8.2: name guard
                    compute_name = getattr(compute, "name", None)
                    if not compute_name:
                        continue

                    # spec 8.4: region filter on compute resource location (not workspace)
                    compute_location = _norm_location(getattr(compute, "location", "") or "")
                    if region_filter and compute_location != _norm_location(region_filter):
                        continue

                    # spec 8.5: compute_type must resolve to exactly "AmlCompute"
                    if _resolve_compute_type(compute) != "AmlCompute":
                        continue

                    # spec 8.6: provisioning_state must resolve to exactly "Succeeded"
                    if _resolve_provisioning_state(compute) != "Succeeded":
                        continue

                    # spec 8.7: allocation_state must resolve to exactly "Steady"
                    if _resolve_allocation_state(compute) != "Steady":
                        continue

                    # spec 8.8: created_at must be present, valid, and cluster age >= 14 days
                    created_at = _resolve_created_at(compute)
                    if created_at is None:
                        continue
                    age_days = (now - created_at).days
                    if age_days < _MIN_AGE_DAYS:
                        continue

                    # spec 8.9: min_node_count must be a known positive integer
                    min_node_count = _resolve_min_node_count(compute)
                    if min_node_count is None:
                        continue

                    # spec 8.10: current_node_count must be known and >= min_node_count
                    current_node_count = _resolve_current_node_count(compute)
                    if current_node_count is None:
                        continue
                    if current_node_count < min_node_count:
                        continue

                    # spec 8.11-8.12: Active Nodes metric must evaluate to ZERO
                    result = _evaluate_metric(
                        mon_client,
                        getattr(workspace, "id", "") or "",
                        compute_name,
                        window_start,
                        now,
                    )
                    if result != _MetricResult.ZERO:
                        continue

                    # --- Enrichment fields (best-effort; never gate emission) ---
                    outer = getattr(compute, "properties", None)
                    inner = getattr(outer, "properties", None) if outer is not None else None
                    scale = getattr(inner, "scale_settings", None) if inner is not None else None

                    vm_size = getattr(inner, "vm_size", None) if inner is not None else None
                    vm_priority = getattr(inner, "vm_priority", None) if inner is not None else None
                    max_node_count = (
                        getattr(scale, "max_node_count", None) if scale is not None else None
                    )
                    target_node_count = (
                        getattr(inner, "target_node_count", None) if inner is not None else None
                    )
                    node_idle_time = (
                        getattr(scale, "node_idle_time_before_scale_down", None)
                        if scale is not None
                        else None
                    )
                    tags = getattr(compute, "tags", None) or {}  # spec 7: never None in output

                    signals_used = [
                        "Resource is exact compute type 'AmlCompute'",
                        "Provisioning state is 'Succeeded'",
                        "Allocation state is 'Steady'",
                        f"Cluster age is {age_days} days (>= {_MIN_AGE_DAYS} days)",
                        (
                            f"min_node_count={min_node_count} (positive baseline confirmed), "
                            f"current_node_count={current_node_count} (>= min_node_count)"
                        ),
                        (
                            f"Active Nodes metric for cluster '{compute_name}' resolved to "
                            f"no observed active nodes over {_IDLE_WINDOW_DAYS} days with "
                            f">= {int(_MIN_COVERAGE * 100)}% daily-bucket coverage "
                            f"(ClusterName dimension, Maximum aggregation)"
                        ),
                    ]

                    findings.append(
                        Finding(
                            provider="azure",
                            rule_id=_RULE_ID,
                            resource_type=_RESOURCE_TYPE,
                            resource_id=compute_id,
                            region=compute_location,
                            estimated_monthly_cost_usd=None,  # spec 10: always None
                            title=f"Idle AML Compute Cluster with Retained Baseline Capacity: {compute_name}",
                            summary=(
                                f"AML compute cluster '{compute_name}' in workspace '{ws_name}' "
                                f"is configured to keep {min_node_count} node(s) running "
                                f"(min_node_count={min_node_count}) with no observed active nodes "
                                f"over {_IDLE_WINDOW_DAYS} days"
                            ),
                            reason=(
                                f"Cluster retains {min_node_count} baseline node(s) "
                                f"(min_node_count={min_node_count}) with no documented job "
                                f"activity for {_IDLE_WINDOW_DAYS} days; baseline nodes incur "
                                f"ongoing cost regardless of job activity"
                            ),
                            risk=RiskLevel.MEDIUM,  # spec 11.1: always MEDIUM
                            confidence=ConfidenceLevel.HIGH,  # spec 11.1: always HIGH
                            detected_at=now,
                            evidence=Evidence(
                                signals_used=signals_used,
                                signals_not_checked=[
                                    "Future or scheduled training intent",
                                    "Business-owner intent not visible in Azure control plane",
                                    "Warm baseline retained intentionally for startup latency, quota reservation, or sporadic experimentation",
                                    "Exact VM and infrastructure pricing after discounts, reservations, or special commercial terms",
                                ],
                                time_window=f"{_IDLE_WINDOW_DAYS} days",
                            ),
                            details={
                                "cluster_name": compute_name,
                                "workspace_name": ws_name,
                                "resource_group": rg,
                                "subscription_id": subscription_id,
                                "vm_size": vm_size,
                                "vm_priority": _to_detail_str(vm_priority),
                                "min_node_count": min_node_count,
                                "max_node_count": max_node_count,
                                "current_node_count": current_node_count,
                                "target_node_count": target_node_count,
                                "allocation_state": "Steady",
                                "provisioning_state": "Succeeded",
                                "created_at": created_at.isoformat(),
                                "node_idle_time_before_scale_down": _to_detail_str(node_idle_time),
                                "idle_window_days": _IDLE_WINDOW_DAYS,
                                "metrics_used": ["Active Nodes"],
                                "tags": tags,
                            },
                        )
                    )

                except (HttpResponseError, ServiceRequestError, ServiceResponseError):
                    continue  # per-compute retrieval failure -> skip (spec 12)

        except (HttpResponseError, ServiceRequestError, ServiceResponseError):
            continue  # per-workspace compute list failure -> skip workspace (spec 12)

    return findings
