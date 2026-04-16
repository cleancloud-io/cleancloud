import math
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

# Azure SDK (top-level imports for CI fail-fast)
from azure.ai.ml import MLClient
from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces
from azure.mgmt.monitor import MonitorManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "azure.ml.online_endpoint.idle",
    "category": "ai",
    "service": "machinelearningservices",
    "cost_impact": "high",
}

# Metrics to try in order
_REQUEST_METRICS = ("RequestCount", "ModelEndpointRequests")

# Example VM SKU cost table (monthly per instance). Extend as needed.
_VM_SKU_COSTS = {
    "Standard_NC6": 657.0,
    "Standard_NC6s_v2": 900.0,
    "Standard_NC12": 1300.0,
    "Standard_NC24": 2600.0,
}

_GPU_FAMILIES = (
    "standard_nc",
    "standard_nd",
    "standard_nv",
    "standard_ncv2",
    "standard_ncv3",
    "standard_ndv2",
    "standard_nd40rs",
    "standard_nc4as_t4",
    "standard_nc8as_t4",
    "standard_nc16as_t4",
    "standard_nc64as_t4",
)


def find_idle_ml_online_endpoints(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[Any] = None,
    monitor_client: Optional[Any] = None,
    idle_days: int = 7,
) -> List[Finding]:
    """Find AML managed online endpoints with zero scoring requests over `idle_days`.

    Uses azure-mgmt-machinelearningservices for workspace enumeration (ARM) and
    azure-ai-ml MLClient for per-workspace endpoint and deployment listing.
    When `client` is injected (tests), it serves as both.
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)
    idle_days = max(idle_days, 3)

    arm_client = client or AzureMachineLearningWorkspaces(
        credential=credential, subscription_id=subscription_id
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    def _norm(s: str) -> str:
        return "".join(c for c in (s or "").lower() if c.isalnum())

    def _ws_client(rg: str, ws_name: str) -> Any:
        # Tests inject a single mock client that covers all operations.
        # Production creates a workspace-scoped MLClient for endpoint/deployment ops.
        if client is not None:
            return client
        return MLClient(
            credential=credential,
            subscription_id=subscription_id,
            resource_group_name=rg,
            workspace_name=ws_name,
        )

    try:
        for ws in arm_client.workspaces.list_by_subscription():
            location_raw = getattr(ws, "location", "") or ""
            if region_filter and _norm(location_raw) != _norm(region_filter):
                continue

            # Resource group: prefer the attribute, fall back to parsing the ARM id
            rg = getattr(ws, "resource_group", None)
            if not rg and getattr(ws, "id", None):
                parts = ws.id.split("/")
                rg_idx = next(
                    (i for i, p in enumerate(parts) if p.lower() == "resourcegroups"), None
                )
                rg = parts[rg_idx + 1] if rg_idx is not None and rg_idx + 1 < len(parts) else None
            if not rg:
                continue

            # ARM resource ID for Azure Monitor metrics (workspace scope)
            ws_id = getattr(ws, "id", None) or (
                f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
                f"/providers/Microsoft.MachineLearningServices/workspaces/{ws.name}"
            )

            ep_client = _ws_client(rg, ws.name)

            try:
                for ep in ep_client.online_endpoints.list():
                    prov = getattr(ep, "provisioning_state", None)
                    if (prov or "").lower() != "succeeded":
                        continue

                    # Age — azure-ai-ml uses creation_context; fall back to system_data
                    age_days: Optional[int] = None
                    ctx = getattr(ep, "creation_context", None) or getattr(ep, "system_data", None)
                    created_at = getattr(ctx, "created_at", None) if ctx is not None else None
                    if created_at is not None:
                        if getattr(created_at, "tzinfo", None) is None:
                            created_at = created_at.replace(tzinfo=timezone.utc)
                        age_days = max((now - created_at).days, 0)
                        if age_days < max(idle_days // 2, 3):
                            continue

                    effective_window = (
                        min(idle_days, age_days) if age_days is not None else idle_days
                    )
                    if effective_window < 3:
                        continue

                    # Metric checks scoped to workspace resource with EndpointName dimension
                    idle_signal = _check_requests(mon_client, ws_id, ep.name, effective_window)

                    if idle_signal is None or idle_signal[0] == "active":
                        continue

                    signal_scope, idle_metric = idle_signal

                    if signal_scope == "no_data":
                        if age_days is not None and age_days >= idle_days * 2:
                            signal_scope = "age_only"
                            idle_metric = "none"
                            confidence = ConfidenceLevel.LOW
                        else:
                            continue
                    elif signal_scope == "workspace_level":
                        # Pass-2 signal: zero traffic at workspace level — endpoint likely idle
                        # but cannot be confirmed per-endpoint; keep at LOW confidence.
                        confidence = ConfidenceLevel.LOW
                    elif (
                        signal_scope == "per_endpoint"
                        and age_days is not None
                        and age_days >= idle_days
                    ):
                        confidence = ConfidenceLevel.HIGH
                    elif (
                        signal_scope == "per_endpoint"
                        and age_days is not None
                        and age_days >= math.ceil(idle_days * 0.75)
                    ):
                        confidence = ConfidenceLevel.MEDIUM
                    elif signal_scope == "per_endpoint" and age_days is None:
                        confidence = ConfidenceLevel.MEDIUM
                    else:
                        continue

                    # Deployment details via online_deployments.list (azure-ai-ml)
                    instance_type = None
                    min_instance_count = None
                    is_gpu = False
                    deployment_count = 0
                    try:
                        for d in ep_client.online_deployments.list(ep.name):
                            deployment_count += 1
                            it = (
                                getattr(d, "instance_type", None)
                                or getattr(getattr(d, "sku", None), "name", None)
                                or getattr(getattr(d, "properties", None), "instanceType", None)
                            )
                            if it:
                                instance_type = it
                            scale = getattr(d, "scale_settings", None)
                            # Use explicit is-not-None checks: 0 is a valid (scale-to-zero) count
                            _candidates = [
                                (
                                    getattr(scale, "min_instances", None)
                                    if scale is not None
                                    else None
                                ),
                                getattr(d, "instance_count", None),
                                getattr(scale, "min_replicas", None) if scale is not None else None,
                                getattr(getattr(d, "properties", None), "minReplicaCount", None),
                            ]
                            cnt = next((v for v in _candidates if v is not None), None)
                            if cnt is not None:
                                min_instance_count = max(min_instance_count or 0, int(cnt))
                    except Exception:
                        pass

                    # Scale-to-zero endpoints have no running instances and no cost
                    if min_instance_count is not None and min_instance_count == 0:
                        continue

                    if instance_type:
                        it_norm = instance_type.lower()
                        is_gpu = any(it_norm.startswith(f) for f in _GPU_FAMILIES)

                    # Cost lookup — only emit a cost when we have a known SKU price;
                    # guessing an unknown SKU's cost erodes trust in the findings.
                    monthly_cost = None
                    if instance_type and min_instance_count:
                        base = _VM_SKU_COSTS.get(instance_type)
                        if base is not None:
                            monthly_cost = base * min_instance_count

                    idle_ratio = (
                        (age_days / idle_days) if (age_days is not None and idle_days) else None
                    )

                    # Risk
                    if is_gpu and idle_ratio is not None and idle_ratio >= 2.0:
                        risk = RiskLevel.CRITICAL
                    elif is_gpu:
                        risk = RiskLevel.HIGH
                    else:
                        risk = RiskLevel.MEDIUM

                    signals = [
                        (
                            f"No Azure Monitor metric data available; endpoint age ({age_days} days) "
                            f"exceeds {idle_days * 2} days"
                            if signal_scope == "age_only"
                            else f"Zero scoring requests for {effective_window} days (Azure Monitor: {idle_metric}, scope: {signal_scope})"
                        ),
                        f"Provisioning state: {prov}",
                    ]
                    if age_days is not None:
                        signals.append(f"Endpoint age: {age_days} days")
                    if monthly_cost:
                        signals.append(f"Estimated cost: ~${monthly_cost:,.0f}/month")

                    evidence = Evidence(
                        signals_used=signals,
                        signals_not_checked=[
                            "Batch scoring pipelines or scheduled external callers",
                            "Failover/shadow deployments",
                            "A/B test traffic splits",
                        ],
                        time_window=f"{effective_window} days",
                    )

                    details = {
                        "endpoint_name": ep.name,
                        "workspace_name": ws.name,
                        "resource_group": rg,
                        "instance_type": instance_type,
                        "min_instance_count": min_instance_count,
                        "deployment_count": deployment_count,
                        "is_gpu": is_gpu,
                        "age_days": age_days,
                        "idle_days_threshold": idle_days,
                        "idle_signal_scope": signal_scope,
                        "estimated_monthly_cost": monthly_cost,
                        "cost_source": (
                            "heuristic_sku_table" if (instance_type in _VM_SKU_COSTS) else "unknown"
                        ),
                    }

                    title = f"Idle Azure ML Online Endpoint: {ep.name}"
                    summary = (
                        f"Azure ML online endpoint '{ep.name}' in workspace '{ws.name}' has received "
                        f"no scoring requests for {effective_window}+ days and continues to bill per-instance."
                    )
                    reason = signals[0]

                    findings.append(
                        Finding(
                            provider="azure",
                            rule_id="azure.ml.online_endpoint.idle",
                            resource_type="azure.ml.online_endpoint",
                            resource_id=ep.id,
                            region=location_raw,
                            title=title,
                            summary=summary,
                            reason=reason,
                            risk=risk,
                            confidence=confidence,
                            detected_at=now,
                            evidence=evidence,
                            details=details,
                            estimated_monthly_cost_usd=monthly_cost,
                        )
                    )

            except PermissionError:
                raise
            except Exception:
                continue

    except PermissionError:
        raise
    except Exception as e:
        msg = str(e)
        if "AuthorizationFailed" in msg or "Forbidden" in msg or "403" in msg:
            raise PermissionError(
                "Missing required permissions: Microsoft.MachineLearningServices/workspaces/read, "
                "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read, "
                "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read, "
                "Microsoft.Insights/metrics/read"
            ) from e
        raise

    return findings


def _check_requests(
    monitor_client: Any,
    workspace_id: str,
    endpoint_name: str,
    days: int,
) -> Optional[tuple]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=max(days, 1))
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{start.strftime(fmt)}/{now.strftime(fmt)}"
    coverage_threshold = max(int(days * 0.7), 3)

    had_successful_call = False

    for metric_name in _REQUEST_METRICS:
        try:
            # Pass 1: filter by EndpointName dimension
            response = monitor_client.metrics.list(
                workspace_id,
                metricnames=metric_name,
                timespan=timespan,
                interval="P1D",
                aggregation="Total",
                filter=f"EndpointName eq '{endpoint_name}'",
            )
            had_successful_call = True
            has_timeseries = False
            seen_datapoints = 0
            for metric in response.value:
                for ts in metric.timeseries:
                    has_timeseries = True
                    for point in ts.data:
                        if point.total is not None:
                            seen_datapoints += 1
                            if point.total > 0:
                                return ("active", None)

            if has_timeseries and seen_datapoints >= coverage_threshold:
                return ("per_endpoint", metric_name)

            # Pass 2: no filter — dimension may not be emitted for this endpoint
            response2 = monitor_client.metrics.list(
                workspace_id,
                metricnames=metric_name,
                timespan=timespan,
                interval="P1D",
                aggregation="Total",
            )
            seen2 = 0
            for metric in response2.value:
                for ts in metric.timeseries:
                    for point in ts.data:
                        if point.total is not None:
                            seen2 += 1
                            if point.total > 0:
                                return ("active", None)
            if seen2 >= coverage_threshold:
                return ("workspace_level", metric_name)

        except PermissionError:
            raise
        except Exception as e:
            msg = str(e)
            if "AuthorizationFailed" in msg or "Forbidden" in msg or "403" in msg:
                raise PermissionError(
                    "Missing required permissions: Microsoft.Insights/metrics/read"
                ) from e
            continue

    return ("no_data", None) if had_successful_call else None
