from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

# Azure SDK (top-level imports for CI fail-fast)
from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces
from azure.mgmt.monitor import MonitorManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "azure.aml.compute.idle",
    "category": "ai",
    "service": "machinelearning",
    "cost_impact": "high",
}

# GPU VM size prefixes — significantly more expensive than CPU
_GPU_VM_PREFIXES = ("Standard_NC", "Standard_ND", "Standard_NV")

# Approximate monthly cost per node (on-demand, East US, 730 h/month)
# Cost for min_node_count nodes that run continuously regardless of job activity
_MONTHLY_COST_PER_NODE = {
    "Standard_D2_v2": 130.0,
    "Standard_D4_v2": 259.0,
    "Standard_D8_v2": 518.0,
    "Standard_D2s_v3": 96.0,
    "Standard_D4s_v3": 192.0,
    "Standard_D8s_v3": 384.0,
    "Standard_NC6": 648.0,
    "Standard_NC12": 1_296.0,
    "Standard_NC24": 2_592.0,
    "Standard_NC6s_v3": 2_203.0,
    "Standard_NC12s_v3": 4_406.0,
    "Standard_NC24s_v3": 8_812.0,
    "Standard_ND6s": 2_203.0,
    "Standard_ND12s": 4_406.0,
    "Standard_ND24s": 8_812.0,
    "Standard_ND40rs_v2": 15_862.0,
    "Standard_NV6": 1_094.0,
    "Standard_NV12": 2_189.0,
    "Standard_NV24": 4_378.0,
}
_DEFAULT_MONTHLY_COST_PER_NODE = 200.0

# Metric names to try in order — Azure ML metrics have drifted across API versions
# and regions. Try all known names before giving up.
_ACTIVE_NODE_METRICS = ("Active Nodes", "NodeCount", "CurrentNodeCount")


def find_idle_aml_compute(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[Any] = None,
    monitor_client: Optional[Any] = None,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find Azure ML compute clusters with min_node_count > 0 and no active nodes.

    AML compute clusters with min_node_count > 0 keep instances running continuously
    regardless of whether any jobs are submitted — identical billing model to SageMaker
    InService endpoints. GPU clusters (NC/ND series) cost $600–$15K/month at minimum
    node count.

    Detection logic:
    - Compute type is AmlCompute
    - min_node_count > 0 (instances always running, always billing)
    - Azure Monitor active-node metric maximum is 0 over the effective idle window

    Metric strategy (Azure Monitor metrics are inconsistent across regions/API versions):
    - Tries "Active Nodes" first, falls back to "NodeCount"
    - For each metric, tries with ComputeName dimension filter first,
      then falls back to unfiltered workspace-level query if no timeseries returned

    Confidence:
    - HIGH: Zero active nodes over the full idle window (age >= idle_days)
    - MEDIUM: Zero active nodes, age >= 75% of idle_days threshold, or age unknown

    IAM permissions:
    - Microsoft.MachineLearningServices/workspaces/read
    - Microsoft.MachineLearningServices/workspaces/computes/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    idle_days = max(idle_days, 3)  # effective_window < 3 skips all clusters; clamp to match

    # Instantiate Azure SDK clients (top-level imports ensure CI fails fast if SDKs missing)
    ml_client = client or AzureMachineLearningWorkspaces(
        credential=credential, subscription_id=subscription_id
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    def _norm(s: str) -> str:
        return s.lower().replace(" ", "").replace("-", "")

    try:
        for workspace in ml_client.workspaces.list_by_subscription():
            # Normalise only for filter comparison; preserve original for output
            location_raw = workspace.location or ""
            if region_filter and _norm(location_raw) != _norm(region_filter):
                continue

            rg = _parse_resource_group(workspace.id)
            if not rg:
                continue

            try:
                for compute in ml_client.machine_learning_compute.list_by_workspace(
                    rg, workspace.name
                ):
                    compute_obj = compute.properties
                    if (
                        not compute_obj
                        or getattr(compute_obj, "compute_type", None) != "AmlCompute"
                    ):
                        continue

                    # AmlComputeProperties lives under compute_obj.properties
                    aml_props = getattr(compute_obj, "properties", None)
                    scale_settings = getattr(aml_props, "scale_settings", None)
                    min_node_count = getattr(scale_settings, "min_node_count", 0) or 0
                    vm_size = getattr(aml_props, "vm_size", None)

                    # Only flag clusters with min_node_count > 0 — those billing continuously
                    if min_node_count == 0:
                        continue

                    # Age from compute properties — created_on is on AmlCompute (compute.properties),
                    # not on ComputeResource.system_data as one might expect
                    age_days: Optional[int] = None
                    created_at = getattr(compute_obj, "created_on", None)
                    if created_at is not None:
                        if created_at.tzinfo is None:
                            created_at = created_at.replace(tzinfo=timezone.utc)
                        age_days = (now - created_at).days
                        # Skip clusters younger than half the idle threshold —
                        # too new to reliably classify as abandoned
                        if age_days < max(idle_days // 2, 7):
                            continue

                    # Effective window: cap to age if known; otherwise use full idle_days
                    effective_window = (
                        min(idle_days, age_days) if age_days is not None else idle_days
                    )

                    if effective_window < 3:
                        continue

                    # Check for active nodes over the effective window.
                    # Returns the metric name that confirmed idle, or None if active/unknown.
                    idle_metric = _check_active_nodes(
                        mon_client,
                        workspace.id,
                        compute.name,
                        effective_window,
                    )
                    if idle_metric is None:
                        continue

                    # Confidence based on age relative to idle threshold.
                    # Unknown age -> MEDIUM: we can't rule out a recently-created cluster.
                    if age_days is not None and age_days >= idle_days:
                        confidence = ConfidenceLevel.HIGH
                    elif age_days is not None and age_days >= int(idle_days * 0.75):
                        confidence = ConfidenceLevel.MEDIUM
                    elif age_days is None:
                        confidence = ConfidenceLevel.MEDIUM
                    else:
                        continue  # too borderline for a confident finding

                    is_gpu = bool(
                        any((vm_size or "").lower().startswith(p.lower()) for p in _GPU_VM_PREFIXES)
                    )
                    if is_gpu and min_node_count >= 2:
                        risk = RiskLevel.HIGH
                    elif is_gpu or min_node_count >= 2:
                        risk = RiskLevel.MEDIUM
                    else:
                        risk = RiskLevel.LOW

                    # Normalize casing for lookup — Azure ML can return "STANDARD_NC6" or "standard_nc6"
                    vm_size_key = next(
                        (k for k in _MONTHLY_COST_PER_NODE if k.lower() == (vm_size or "").lower()),
                        None,
                    )
                    cost_per_node = (
                        _MONTHLY_COST_PER_NODE[vm_size_key]
                        if vm_size_key
                        else _DEFAULT_MONTHLY_COST_PER_NODE
                    )
                    monthly_cost = cost_per_node * min_node_count

                    signals = [
                        f"Cluster configured with non-zero baseline capacity but no workload observed for {effective_window} days (Azure Monitor: {idle_metric})",
                        f"Baseline cost driver: min_node_count={min_node_count} (always-on compute — billed continuously)",
                        "Compute type: AmlCompute",
                    ]
                    if age_days is not None:
                        signals.append(f"Cluster age: {age_days} days")
                    if vm_size:
                        signals.append(f"VM size: {vm_size}")
                    if is_gpu:
                        signals.append("GPU cluster with no workload — high-cost idle state")
                    if min_node_count == 1:
                        signals.append("Single-node baseline — may be intentional for dev/test")

                    evidence = Evidence(
                        signals_used=signals,
                        signals_not_checked=[
                            "Scheduled or periodic training jobs",
                            "Jobs submitted outside the observation window",
                            "Planned future usage",
                            "Cluster configured with min_node_count for warm-start latency",
                            "Cluster reserved for interactive development",
                        ],
                        time_window=f"{effective_window} days",
                    )

                    age_for_details = age_days if age_days is not None else "unknown"

                    findings.append(
                        Finding(
                            provider="azure",
                            rule_id="azure.aml.compute.idle",
                            resource_type="azure.aml.compute",
                            resource_id=compute.id,
                            region=location_raw,
                            estimated_monthly_cost_usd=monthly_cost,
                            title=f"Idle Azure ML Compute Cluster (Baseline Capacity Waste for {effective_window} Days)",
                            summary=(
                                f"AML compute cluster '{compute.name}' in workspace '{workspace.name}' "
                                f"is configured to keep {min_node_count} node(s) always running "
                                f"(min_node_count={min_node_count}) but no workload activity was "
                                f"observed for {effective_window} days — baseline capacity waste."
                            ),
                            reason=(
                                f"AML compute cluster has min_node_count={min_node_count} "
                                f"with no workload activity for {effective_window} days"
                            ),
                            risk=risk,
                            confidence=confidence,
                            detected_at=now,
                            evidence=evidence,
                            details={
                                "cluster_name": compute.name,
                                "workspace_name": workspace.name,
                                "resource_group": rg,
                                "vm_size": vm_size,
                                "min_node_count": min_node_count,
                                "is_gpu": is_gpu,
                                "age_days": age_for_details,
                                "idle_window_days": effective_window,
                                "idle_days_threshold": idle_days,
                                "estimated_monthly_cost": f"~${monthly_cost:,.0f}/month",
                                "cost_estimate_type": "mapped" if vm_size_key else "approximate",
                            },
                        )
                    )
            except Exception as ws_err:
                ws_msg = str(ws_err)
                if "AuthorizationFailed" in ws_msg or "Forbidden" in ws_msg or "403" in ws_msg:
                    raise PermissionError(
                        "Missing required permissions: "
                        "Microsoft.MachineLearningServices/workspaces/read, "
                        "Microsoft.MachineLearningServices/workspaces/computes/read, "
                        "Microsoft.Insights/metrics/read"
                    ) from ws_err
                continue  # skip this workspace on transient error; preserve findings so far

    except Exception as e:
        msg = str(e)
        if "AuthorizationFailed" in msg or "Forbidden" in msg or "403" in msg:
            raise PermissionError(
                "Missing required permissions: "
                "Microsoft.MachineLearningServices/workspaces/read, "
                "Microsoft.MachineLearningServices/workspaces/computes/read, "
                "Microsoft.Insights/metrics/read"
            ) from e
        raise

    return findings


def _check_active_nodes(
    monitor_client: Any,
    workspace_id: str,
    compute_name: str,
    days: int,
) -> Optional[str]:
    """Check whether the cluster had any active nodes in the past `days` days.

    Returns the metric name that confirmed idle (e.g. "Active Nodes"), or None
    if the cluster appears active or no reliable per-cluster signal was found.

    Azure Monitor metrics for ML workspaces are inconsistent: the metric name
    ("Active Nodes" vs "NodeCount" vs "CurrentNodeCount") and available dimensions
    (ComputeName vs ClusterName vs none) vary by API version, region, and workspace type.

    Strategy — for each candidate metric name:
      1. Query with ComputeName dimension filter (only reliable signal)
         - active  -> return None (skip this cluster)
         - idle    -> return metric name (confirmed idle — dimension-filtered zero is trustworthy)
         - no data -> filter unsupported; fall back to workspace-level query
      2. Workspace-level fallback (unfiltered):
         - active  -> return None (something active somewhere; skip conservatively)
         - idle/no data -> UNKNOWN, not idle (one active cluster can hide many idle ones)
      3. If no metric yields a reliable per-cluster signal -> return None (assume active)

    Returns None (assume active) on any API exception to avoid false positives.
    """
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=max(days, 1))
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{start_time.strftime(fmt)}/{now.strftime(fmt)}"

    def _query(metric_name: str, dimension_filter: Optional[str]) -> Optional[bool]:
        """Query one metric.

        Returns True  -> activity found (cluster was active)
        Returns False -> timeseries returned, all values zero (cluster confirmed idle)
        Returns None  -> no timeseries returned (metric/dimension unavailable)
        Raises        -> API error (caller handles)
        """
        kwargs = dict(
            metricnames=metric_name,
            timespan=timespan,
            interval="P1D",
            aggregation="Maximum",
        )
        if dimension_filter:
            kwargs["filter"] = dimension_filter

        response = monitor_client.metrics.list(workspace_id, **kwargs)

        has_real_data = False
        for metric in response.value:
            for ts in metric.timeseries:
                for data in ts.data:
                    if data.maximum is not None:
                        has_real_data = True
                        if data.maximum > 0:
                            return True  # confirmed active

        # Only treat as confirmed idle when at least one non-None datapoint was seen.
        # All-None maximums (metric publishing gap / throttled ingestion) are treated
        # as unknown — same as no timeseries — to avoid false positives.
        return False if has_real_data else None

    try:
        for metric_name in _ACTIVE_NODE_METRICS:
            # Step 1: try with ComputeName dimension filter
            result = _query(metric_name, f"ComputeName eq '{compute_name}'")
            if result is True:
                return None  # confirmed active
            if result is False:
                return metric_name  # confirmed idle — dimension-filtered zero is trustworthy

            # Step 2: filter returned no timeseries — dimension may not be supported.
            # Fall back to unfiltered workspace-level query.
            result = _query(metric_name, None)
            if result is True:
                return None  # something active in the workspace — skip conservatively

            # False or None at workspace level is UNKNOWN, not idle:
            # one active cluster can mask multiple idle ones — never confirm idle here.
            # Continue to the next metric name.

        # No metric returned a reliable per-cluster signal — assume active.
        # This avoids flagging clusters whose metrics are simply not published yet.
        return None

    except Exception:
        return None  # conservative: assume active if metrics unavailable


def _parse_resource_group(resource_id: Optional[str]) -> Optional[str]:
    """Extract the resource group name from an Azure resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None
