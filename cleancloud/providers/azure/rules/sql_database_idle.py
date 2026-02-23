from datetime import datetime, timedelta, timezone
from typing import List, Optional

from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.sql import SqlManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Approximate monthly costs for Azure SQL Database Standard/Premium tiers (DTU model)
_SKU_COST_MAP = {
    # Standard tier
    "S0": 15,
    "S1": 30,
    "S2": 75,
    "S3": 150,
    "S4": 300,
    "S6": 600,
    "S7": 1200,
    "S9": 2400,
    "S12": 4800,
    # Premium tier
    "P1": 465,
    "P2": 930,
    "P4": 1860,
    "P6": 3720,
    "P11": 5521,
    "P15": 7446,
}


def _extract_resource_group(resource_id: str) -> str:
    """Extract resource group name from an Azure resource ID."""
    parts = resource_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    raise ValueError(f"Cannot extract resource group from resource ID: {resource_id}")


def _get_metric_sum(
    monitor_client: MonitorManagementClient,
    resource_uri: str,
    metric_name: str,
    start_time: datetime,
    end_time: datetime,
) -> int:
    """
    Query Azure Monitor for the sum of a metric over the time period.

    Returns 1 (non-zero) on any failure to avoid false positives.
    """
    try:
        # Use strftime to produce clean UTC timestamps without '+00:00' suffix,
        # which Azure Monitor rejects (the '+' gets mangled in the REST URL).
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
                for data in ts.data:
                    if data.total is not None and data.total > 0:
                        return 1
        return 0

    except Exception:
        # If we can't get metrics, assume there might be connections
        # to avoid false positives
        return 1


def find_idle_sql_databases(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[SqlManagementClient] = None,
    monitor_client: Optional[MonitorManagementClient] = None,
    days_idle: int = 14,
) -> List[Finding]:
    """
    Find Azure SQL databases with zero connections for `days_idle` days.

    Azure SQL databases in Standard/Premium tiers cost $15-$7,500+/month.
    Databases with zero connections over 14+ days are a strong idle signal.
    Excludes Basic tier (<$5/month) to reduce noise.
    Excludes system databases (master).

    IAM permissions:
    - Microsoft.Sql/servers/read
    - Microsoft.Sql/servers/databases/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []

    sql_client = client or SqlManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)

    for server in sql_client.servers.list():
        server_location = (server.location or "").lower()
        if region_filter and server_location != region_filter.lower():
            continue

        resource_group = _extract_resource_group(server.id)

        for db in sql_client.databases.list_by_server(resource_group, server.name):
            # Skip system databases
            if db.name == "master":
                continue

            # Skip Basic tier (< $5/month, not worth flagging)
            sku_tier = getattr(db.sku, "tier", "") if db.sku else ""
            if sku_tier.lower() == "basic":
                continue

            # Azure returns the service objective (S0, P1, etc.) in
            # current_service_objective_name, not sku.name (which is the tier).
            sku_name = getattr(db, "current_service_objective_name", None) or (
                getattr(db.sku, "name", "") if db.sku else ""
            )

            # Build resource URI for Azure Monitor
            resource_uri = db.id

            # Query 14-day connection metrics
            total_connections = _get_metric_sum(
                mon_client,
                resource_uri,
                "connection_successful",
                now - timedelta(days=days_idle),
                now,
            )

            if total_connections > 0:
                continue

            # Estimate monthly cost from SKU
            estimated_monthly_cost = _estimate_monthly_cost(sku_name)
            cost_usd = _estimate_monthly_cost_usd(sku_name)

            signals = [
                f"Zero successful connections for {days_idle} days (Azure Monitor metrics)",
                f"Connections (14d sum): {total_connections}",
                f"SKU: {sku_name} ({sku_tier})",
                f"Server: {server.name}",
            ]

            signals_not_checked = [
                "Planned future usage",
                "Disaster recovery intent",
                "Seasonal traffic patterns",
                "Application deployment cycles",
            ]

            evidence = Evidence(
                signals_used=signals,
                signals_not_checked=signals_not_checked,
                time_window=f"{days_idle} days",
            )

            findings.append(
                Finding(
                    provider="azure",
                    rule_id="azure.sql_database.idle",
                    resource_type="azure.sql_database",
                    resource_id=db.id,
                    region=db.location,
                    estimated_monthly_cost_usd=cost_usd,
                    title=f"Idle Azure SQL Database (No Connections for {days_idle}+ Days)",
                    summary=(
                        f"Azure SQL database '{db.name}' on server '{server.name}' "
                        f"({sku_name}, {sku_tier}) has had zero connections for {days_idle}+ days."
                    ),
                    reason=f"Azure SQL database has zero connections for {days_idle}+ days",
                    risk=RiskLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=evidence,
                    details={
                        "db_name": db.name,
                        "server_name": server.name,
                        "sku_name": sku_name,
                        "sku_tier": sku_tier,
                        "max_size_bytes": getattr(db, "max_size_bytes", None),
                        "location": db.location,
                        "connections_14d": total_connections,
                        "estimated_monthly_cost": estimated_monthly_cost,
                        "tags": db.tags,
                    },
                )
            )

    return findings


def _estimate_monthly_cost(sku_name: str) -> str:
    """Rough monthly cost estimate based on SKU name."""
    if not sku_name:
        return "Cost varies by SKU (region dependent)"
    cost = _SKU_COST_MAP.get(sku_name.upper())
    if cost:
        return f"~${cost}/month (region dependent)"
    return "Cost varies by SKU (region dependent)"


def _estimate_monthly_cost_usd(sku_name: str) -> Optional[float]:
    """Numeric monthly cost estimate for aggregation."""
    if not sku_name:
        return None
    cost = _SKU_COST_MAP.get(sku_name.upper())
    return float(cost) if cost else None
