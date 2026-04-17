from datetime import datetime, timedelta, timezone
from typing import List, Optional

from azure.core.exceptions import AzureError, HttpResponseError
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.web import WebSiteManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Approximate monthly cost per App Service tier (single instance, Standard S1)
# App Service Plans bill even when apps receive no traffic.
_TIER_COST_USD = {
    "Basic": 55.0,
    "Standard": 73.0,
    "Premium": 146.0,
    "PremiumV2": 146.0,
    "PremiumV3": 146.0,
    "Isolated": 298.0,
    "IsolatedV2": 298.0,
}

_SKIP_TIERS = {
    "Free",
    "Shared",
    "Dynamic",
}  # Dynamic = Consumption/serverless, no idle cost


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
                for data in ts.data:
                    if data.total is not None and data.total > 0:
                        return 1
        return 0
    except Exception:
        return 1  # conservative: assume active if metrics unavailable


def find_idle_app_services(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[WebSiteManagementClient] = None,
    monitor_client: Optional[MonitorManagementClient] = None,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find Azure App Service web apps with zero HTTP requests for `idle_days` days.

    App Services on paid plans (Basic and above) incur compute charges regardless
    of traffic. An app with zero requests for 14+ days is a strong signal of
    abandonment — dev/staging apps that were never decommissioned, or features
    that were turned off without removing the hosting.

    Only apps on paid App Service Plans are flagged. Free/Shared/Consumption
    tiers are excluded — no meaningful idle cost.

    Detection logic:
    - App is in a Running state
    - Hosted on a paid App Service Plan (Basic or above)
    - Azure Monitor `Requests` metric sum is 0 over `idle_days` days

    IAM permissions:
    - Microsoft.Web/sites/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []

    web_client = client or WebSiteManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)

    # Build plan tier lookup once — web_apps.list() does not populate app.sku,
    # so we resolve tiers from the App Service Plans directly.
    plan_tiers: dict = {}
    try:
        for plan in web_client.app_service_plans.list():
            tier = getattr(plan.sku, "tier", None) if plan.sku else None
            if plan.id and tier:
                plan_tiers[plan.id.lower()] = tier
    except (AzureError, HttpResponseError):
        pass  # conservative: fall back to per-app tier detection below

    def _norm(s: str) -> str:
        return s.lower().replace(" ", "").replace("-", "")

    for app in web_client.web_apps.list():
        # Normalize location
        location = _norm(app.location or "")
        if region_filter and location != _norm(region_filter):
            continue

        # Only check running apps
        if getattr(app, "state", None) != "Running":
            continue

        # Determine App Service Plan tier — prefer plan lookup, fall back to app object
        server_farm_id = getattr(app, "server_farm_id", None) or ""
        sku_tier = plan_tiers.get(server_farm_id.lower()) or _get_plan_tier(app)
        if sku_tier in _SKIP_TIERS or sku_tier is None:
            continue

        # Query request count over the idle window
        total_requests = _get_metric_sum(
            mon_client,
            app.id,
            "Requests",
            now - timedelta(days=idle_days),
            now,
        )

        if total_requests > 0:
            continue

        kind = getattr(app, "kind", "app") or "app"
        tags = app.tags or {}

        cost_usd = _TIER_COST_USD.get(sku_tier)

        signals = [
            f"Zero HTTP requests for {idle_days} days (Azure Monitor: Requests metric)",
            "App state: Running",
            f"App Service Plan tier: {sku_tier}",
            f"Kind: {kind}",
        ]
        if cost_usd:
            signals.append(
                f"App Service Plan tier '{sku_tier}' costs ~${cost_usd}/month per instance"
            )

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=[
                "Non-HTTP workloads (WebJobs, background services)",
                "Planned reactivation or seasonal use",
                "IaC-managed placeholder deployment",
                "Blue/green deployment staging slot",
            ],
            time_window=f"{idle_days} days",
        )

        details = {
            "app_name": app.name,
            "kind": kind,
            "sku_tier": sku_tier,
            "location": location,
            "idle_days_threshold": idle_days,
        }
        if tags:
            details["tags"] = tags

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.app_service.idle",
                resource_type="azure.app_service",
                resource_id=app.id,
                region=location,
                title=f"Idle App Service (No Requests for {idle_days}+ Days)",
                summary=(
                    f"App Service '{app.name}' ({sku_tier}) has received zero HTTP requests "
                    f"for {idle_days}+ days but continues to accrue compute charges."
                ),
                reason=f"App Service has zero HTTP requests for {idle_days}+ days",
                risk=RiskLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details=details,
                estimated_monthly_cost_usd=cost_usd,
            )
        )

    return findings


def _get_plan_tier(app) -> Optional[str]:
    """Extract the App Service Plan tier from the app object."""
    # The web_apps.list() response doesn't always include the full plan SKU,
    # but server_farm_id and the app's kind give enough signal.
    # We use app_service_plan_id to look it up if needed, but for simplicity
    # rely on the sku info embedded in the app object when available.
    try:
        sku = getattr(app, "sku", None)
        if sku:
            return getattr(sku, "tier", None)
    except (AzureError, AttributeError):
        pass

    # Fallback: infer from kind — "functionapp" on Consumption = Dynamic (skip)
    kind = (getattr(app, "kind", "") or "").lower()
    if "functionapp" in kind:
        return "Dynamic"  # will be skipped

    return None
