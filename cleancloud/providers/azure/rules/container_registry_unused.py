from datetime import datetime, timedelta, timezone
from typing import List, Optional

from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.monitor import MonitorManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Approximate monthly costs by ACR SKU
_SKU_COST_USD = {
    "Basic": 5.0,
    "Standard": 20.0,
    "Premium": 50.0,
}


def _get_metric_sum(
    monitor_client: MonitorManagementClient,
    resource_uri: str,
    metric_name: str,
    start_time: datetime,
    end_time: datetime,
) -> int:
    """
    Query Azure Monitor for the total of a metric over the time period.

    Returns 1 (non-zero) on any failure to avoid false positives.
    """
    try:
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        timespan = f"{start_time.strftime(fmt)}/{end_time.strftime(fmt)}"
        response = monitor_client.metrics.list(
            resource_uri,
            metricnames=metric_name,
            timespan=timespan,
            interval="P1D",
            aggregation="Total",
        )
        for metric in response.value:
            for ts in metric.timeseries:
                if any((d.total or 0) > 0 for d in ts.data):
                    return 1
        return 0
    except Exception:
        return 1  # conservative: assume active if metrics unavailable


def find_unused_container_registries(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[ContainerRegistryManagementClient] = None,
    monitor_client: Optional[MonitorManagementClient] = None,
    days_unused: int = 90,
) -> List[Finding]:
    """
    Find Azure Container Registries with no pull activity for `days_unused` days.

    Container registries accrue storage and per-operation charges regardless of
    usage. A registry with no pulls for 90+ days is a strong signal of abandonment
    — the images it holds may have moved elsewhere, or the project consuming them
    has been retired.

    Detection logic:
    - Registry is in Succeeded provisioning state
    - Azure Monitor `SuccessfulPullCount` metric sum is 0 over `days_unused` days
    - Azure Monitor `SuccessfulPushCount` metric sum is 0 over `days_unused` days

    Both pull and push activity are checked. A registry receiving pushes (e.g. a
    CI build pipeline) but no pulls is NOT flagged — it is actively in use.

    IAM permissions:
    - Microsoft.ContainerRegistry/registries/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []

    acr_client = client or ContainerRegistryManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)

    def _norm(s: str) -> str:
        return s.lower().replace(" ", "").replace("-", "")

    for registry in acr_client.registries.list():
        location = _norm(registry.location or "")
        if region_filter and location != _norm(region_filter):
            continue

        if str(getattr(registry, "provisioning_state", "")).lower() != "succeeded":
            continue

        sku_name = registry.sku.name if registry.sku else "unknown"
        tags = registry.tags or {}

        start_time = now - timedelta(days=days_unused)

        # Build fully-qualified ARM URI for Azure Monitor — registry.id should already
        # include the provider segment, but guard defensively for older SDK versions or
        # API version overrides that may return a partial path.
        resource_uri = (registry.id or "").rstrip("/")
        if "/providers/" not in resource_uri:
            resource_uri = (
                f"{resource_uri}/providers/Microsoft.ContainerRegistry"
                f"/registries/{registry.name}"
            )

        total_pulls = _get_metric_sum(
            mon_client,
            resource_uri,
            "SuccessfulPullCount",
            start_time,
            now,
        )
        if total_pulls > 0:
            continue

        total_pushes = _get_metric_sum(
            mon_client,
            resource_uri,
            "SuccessfulPushCount",
            start_time,
            now,
        )
        if total_pushes > 0:
            continue

        cost_usd = _SKU_COST_USD.get(sku_name)

        signals = [
            f"Zero successful image pulls for {days_unused} days (Azure Monitor: SuccessfulPullCount)",
            f"Zero successful image pushes for {days_unused} days (Azure Monitor: SuccessfulPushCount)",
            f"No push or pull activity detected across the entire {days_unused}-day window",
            f"Registry SKU: {sku_name}",
        ]
        if sku_name == "Basic":
            signals.append("Basic SKU: metrics may be sparse; conservative assumption applied")
        if cost_usd:
            signals.append(f"ACR {sku_name} tier costs ~${cost_usd}/month plus storage")

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=[
                "Geo-replication pull activity in other regions",
                "Planned reactivation or migration",
                "Images referenced by stopped but not deleted workloads",
            ],
            time_window=f"{days_unused} days",
        )

        details = {
            "registry_name": registry.name,
            "sku": sku_name,
            "location": location,
            "days_unused_threshold": days_unused,
        }
        if tags:
            details["tags"] = tags

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.container_registry.unused",
                resource_type="azure.container_registry",
                resource_id=registry.id,
                region=location,
                title=f"Unused Container Registry ({days_unused}+ Days No Pulls)",
                summary=(
                    f"Container Registry '{registry.name}' ({sku_name}) has had no image pulls "
                    f"for {days_unused}+ days."
                ),
                reason=f"Container registry has zero pull activity for {days_unused}+ days",
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details=details,
                estimated_monthly_cost_usd=cost_usd,
            )
        )

    return findings
