import math
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from azure.mgmt.monitor import MonitorManagementClient

# Azure SDK (top-level imports for CI fail-fast)
from azure.mgmt.search import SearchManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "azure.ai_search.idle",
    "category": "ai",
    "service": "search",
    "cost_impact": "high",
}

# Metric names for Azure Monitor queries — constants for easy update if Microsoft renames them
_METRIC_QPS = "SearchQueriesPerSecond"
_METRIC_TOTAL = "TotalSearchRequestCount"

# Monthly cost per 1 replica × 1 partition (USD). Azure Search bills per unit = replica × partition.
_SKU_COSTS = {
    "basic": 73.0,
    "standard": 261.0,
    "standard2": 523.0,
    "standard3": 1047.0,
    "storage_optimized_l1": 2014.0,
    "storage_optimized_l2": 4028.0,
}

_WATCHED_SKUS = {
    "standard",
    "standard2",
    "standard3",
    "storage_optimized_l1",
    "storage_optimized_l2",
}

# Azure SDK returns SKU names in various formats (camelCase, underscores, etc.).
# Map stripped-lowercase variants to the canonical _SKU_COSTS keys.
_SKU_ALIASES = {
    "storageoptimizedl1": "storage_optimized_l1",
    "storageoptimizedl2": "storage_optimized_l2",
}


def _normalize_sku(raw: str) -> str:
    """Normalize an Azure Search SKU name to the canonical key used in _SKU_COSTS.

    Azure returns names like "Standard", "StorageOptimizedL1", or "storage_optimized_l1".
    We lowercase, strip non-alphanumeric chars, then resolve known aliases.
    """
    stripped = "".join(c for c in (raw or "").lower() if c.isalnum())
    return _SKU_ALIASES.get(stripped, stripped)


def find_idle_ai_search_services(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[Any] = None,
    monitor_client: Optional[Any] = None,
    idle_days: int = 30,
) -> List[Finding]:
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    # Instantiate Azure SDK clients (top-level imports ensure CI fails fast if SDKs missing)
    search_client = client or SearchManagementClient(
        credential=credential, subscription_id=subscription_id
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    def _norm(s: str) -> str:
        return "".join(c for c in (s or "").lower() if c.isalnum())

    try:
        for svc in search_client.services.list_by_subscription():
            sku = getattr(svc, "sku", None)
            sku_raw = getattr(sku, "name", None)
            if not sku_raw and isinstance(sku, dict):
                sku_raw = sku.get("name")
            sku_name = _normalize_sku(sku_raw)
            if sku_name not in _WATCHED_SKUS:
                continue

            location_raw = getattr(svc, "location", "") or ""
            if region_filter and _norm(location_raw) != _norm(region_filter):
                continue

            # Replica and partition counts
            props = getattr(svc, "properties", None)
            replica_count = (
                getattr(svc, "replica_count", None)
                or getattr(props, "replica_count", None)
                or getattr(props, "replicaCount", None)
                or 1
            )
            partition_count = (
                getattr(svc, "partition_count", None)
                or getattr(props, "partition_count", None)
                or getattr(props, "partitionCount", None)
                or 1
            )

            # Age
            age_days: Optional[int] = None
            created_at = getattr(svc, "system_data", None) and getattr(
                svc.system_data, "created_at", None
            )
            if created_at is not None:
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                age_days = max((now - created_at).days, 0)
                if age_days < max(idle_days // 2, 3):
                    continue

            effective_window = min(idle_days, age_days) if age_days is not None else idle_days
            if effective_window < 3:
                continue

            if not svc.id:
                continue

            # Metric check over effective_window days.
            # Age gates (idle_days // 2 minimum, 75% for MEDIUM, 100% for HIGH) are heuristics:
            # they balance catching genuinely idle services early while avoiding false positives
            # on recently-deployed services that haven't had time to build query history.
            idle_signal = _check_search_queries(mon_client, svc.id, effective_window)
            if idle_signal is None or idle_signal[0] == "active":
                continue

            signal_scope, idle_metric, average_value = idle_signal

            if signal_scope == "no_data":
                if age_days is not None and age_days >= idle_days * 2:
                    confidence = ConfidenceLevel.LOW
                    signal_scope = "age_only"
                else:
                    continue
            elif signal_scope == "metric_zero" and age_days is not None and age_days >= idle_days:
                confidence = ConfidenceLevel.HIGH
            elif (
                signal_scope == "metric_zero"
                and age_days is not None
                and age_days >= math.ceil(idle_days * 0.75)
            ):
                confidence = ConfidenceLevel.MEDIUM
            elif signal_scope == "metric_zero" and age_days is None:
                confidence = ConfidenceLevel.MEDIUM
            else:
                continue

            base = _SKU_COSTS.get(sku_name, None)
            if base is None:
                continue

            replicas = int(replica_count or 1)
            partitions = int(partition_count or 1)
            est_cost = base * replicas * partitions

            if est_cost < 100:
                continue

            if est_cost >= 3000:
                risk = RiskLevel.CRITICAL
            elif est_cost >= 1000:
                risk = RiskLevel.HIGH
            else:
                risk = RiskLevel.MEDIUM

            signals = [
                (
                    f"No search traffic detected for {effective_window} days (metric: {idle_metric})"
                    if signal_scope != "age_only"
                    else f"No metric data available; service age {age_days} days >= {idle_days * 2} days"
                ),
                f"SKU: {sku_name}, replicas: {replicas}, partitions: {partitions}",
            ]

            evidence = Evidence(
                signals_used=signals,
                signals_not_checked=[
                    "Indexing-only services with no search queries",
                    "Services used as failover",
                    "Scheduled batch re-indexing",
                ],
                time_window=f"{effective_window} days",
            )

            rg = None
            if svc.id:
                _parts = svc.id.split("/")
                _rg_idx = next(
                    (i for i, p in enumerate(_parts) if p.lower() == "resourcegroups"), None
                )
                rg = (
                    _parts[_rg_idx + 1]
                    if _rg_idx is not None and _rg_idx + 1 < len(_parts)
                    else None
                )

            details = {
                "service_name": svc.name,
                "resource_group": rg,
                "sku": sku_name,
                "location": location_raw,
                "replica_count": replicas,
                "partition_count": partitions,
                "age_days": age_days,
                "idle_days_threshold": idle_days,
                "idle_signal": signal_scope,
                "idle_metric": idle_metric or "none",
                "estimated_monthly_cost": est_cost,
                "cost_source": "heuristic_sku_table" if base is not None else "unknown",
            }

            title = f"Idle Azure AI Search Service: {svc.name}"
            summary = f"Azure AI Search service '{svc.name}' ({sku_name}) has near-zero search traffic for {effective_window}+ days and continues to incur monthly charges."
            reason = signals[0]

            findings.append(
                Finding(
                    provider="azure",
                    rule_id="azure.ai_search.idle",
                    resource_type="azure.ai.search_service",
                    resource_id=svc.id,
                    region=location_raw,
                    title=title,
                    summary=summary,
                    reason=reason,
                    risk=risk,
                    confidence=confidence,
                    detected_at=now,
                    evidence=evidence,
                    details=details,
                    estimated_monthly_cost_usd=est_cost,
                )
            )

    except Exception as e:
        msg = str(e)
        if "AuthorizationFailed" in msg or "Forbidden" in msg or "403" in msg:
            raise PermissionError(
                "Missing required permissions: Microsoft.Search/searchServices/read, Microsoft.Insights/metrics/read"
            ) from e
        raise

    return findings


def _check_search_queries(monitor_client: Any, resource_id: str, days: int) -> Optional[tuple]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=max(days, 1))
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{start.strftime(fmt)}/{now.strftime(fmt)}"

    had_successful = False

    # Try SearchQueriesPerSecond (Average) first
    try:
        response = monitor_client.metrics.list(
            resource_id,
            metricnames=_METRIC_QPS,
            timespan=timespan,
            interval="PT24H",
            aggregation="Average",
        )
        had_successful = True
        seen_datapoints = 0
        for metric in getattr(response, "value", []):
            for ts in getattr(metric, "timeseries", []):
                vals = [
                    p.average
                    for p in getattr(ts, "data", [])
                    if getattr(p, "average", None) is not None
                ]
                if vals:
                    seen_datapoints += len(vals)
                    avg = sum(vals) / len(vals)
                    if avg > 0:
                        return ("active", _METRIC_QPS, avg)
        if seen_datapoints > 0:
            return ("metric_zero", _METRIC_QPS, 0)
    except PermissionError:
        raise
    except Exception as e:
        msg = str(e)
        if "AuthorizationFailed" in msg or "Forbidden" in msg or "403" in msg:
            raise PermissionError(
                "Missing required permissions: Microsoft.Insights/metrics/read"
            ) from e

    # Fallback: TotalSearchRequestCount (Total)
    try:
        response = monitor_client.metrics.list(
            resource_id,
            metricnames=_METRIC_TOTAL,
            timespan=timespan,
            interval="PT24H",
            aggregation="Total",
        )
        had_successful = True
        seen_datapoints = 0
        for metric in getattr(response, "value", []):
            for ts in getattr(metric, "timeseries", []):
                vals = [
                    p.total
                    for p in getattr(ts, "data", [])
                    if getattr(p, "total", None) is not None
                ]
                if vals:
                    seen_datapoints += len(vals)
                    total = sum(vals)
                    if total > 0:
                        return ("active", _METRIC_TOTAL, total)
        if seen_datapoints > 0:
            return ("metric_zero", _METRIC_TOTAL, 0)
        # Both metrics called and neither returned datapoints
        if had_successful and seen_datapoints == 0:
            return ("no_data", None, None)
    except PermissionError:
        raise
    except Exception:
        pass

    return None
