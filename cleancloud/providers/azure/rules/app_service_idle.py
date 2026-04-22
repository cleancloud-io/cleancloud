"""
Rule: azure.app_service.idle

Intent:
    Detect top-level Azure App Service apps on paid plans that have shown no
    meaningful site activity over the configured idle window.

Exclusions:
    - resource_id absent
    - outside region filter
    - state != Running
    - enabled == false
    - deployment slot (ARM id contains /slots/, or slotName/parentSiteName present)
    - kind contains functionapp or workflowapp
    - plan tier is Free, Shared, Dynamic, or unknown
    - WebJobs exist or WebJobs enumeration fails
    - any required activity metric is non-zero or unavailable

Detection:
    - All four activity metrics zero over the idle window:
      Requests, CpuTime, BytesReceived, BytesSent
    - Zero WebJobs

APIs:
    - Microsoft.Web/sites/read
    - Microsoft.Web/serverfarms/read
    - Microsoft.Web/sites/webJobs/read
    - Microsoft.Insights/metrics/read
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from azure.core.exceptions import AzureError, HttpResponseError
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.web import WebSiteManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.app_service.idle"
_RESOURCE_TYPE = "azure.app_service"

# Spec 8.8: skip Free, Shared, Dynamic, or unusable/unknown tier.
# Allowlist of known paid dedicated-compute tiers; anything not recognized
# is treated as unknown and skipped (conservative, low-noise contract).
_PAID_TIERS = {
    "basic",
    "standard",
    "premium",
    "premiumv2",
    "premiumv3",
    "isolated",
    "isolatedv2",
}

# Required activity metrics (spec 9) — all must be zero for emission
_ACTIVITY_METRICS = ("Requests", "CpuTime", "BytesReceived", "BytesSent")

# Plan cost floor for informational context (single-instance, approx $/month)
# Not used as estimated_monthly_cost_usd (which must be None per spec 11)
_TIER_COST_FLOOR_USD: Dict[str, float] = {
    "basic": 55.0,
    "standard": 73.0,
    "premium": 146.0,
    "premiumv2": 146.0,
    "premiumv3": 146.0,
    "isolated": 298.0,
    "isolatedv2": 298.0,
}


def _norm_region(s: str) -> str:
    """Normalize region: lowercase, remove spaces and hyphens."""
    return s.lower().replace(" ", "").replace("-", "") if s else ""


def _norm_arm_id(arm_id: str) -> str:
    """Normalize an ARM id for consistent key matching: lowercase, strip whitespace and trailing slashes."""
    return arm_id.lower().strip().rstrip("/") if arm_id else ""


def _get_metric_total(
    monitor_client: MonitorManagementClient,
    resource_uri: str,
    metric_name: str,
    start_time: datetime,
    end_time: datetime,
) -> Optional[int]:
    """
    Query Azure Monitor for the total of a metric over the time period.

    Returns:
        None  — unavailable / query failed / response unusable → caller must skip
        0     — all datapoints are 0 or absent (metric is zero for the window)
        1     — at least one non-zero datapoint found (app is active)
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
        if not hasattr(response, "value") or response.value is None:
            return None  # unusable response shape
        for metric in response.value:
            for ts in metric.timeseries or []:
                for data in ts.data or []:
                    if data.total is not None and data.total > 0:
                        return 1  # non-zero found → active
        return 0
    except Exception:
        return None  # unavailable → caller must skip


def _is_deployment_slot(app) -> bool:
    """True if the app is a deployment slot rather than a top-level site."""
    arm_id = (getattr(app, "id", "") or "").lower()
    if "/slots/" in arm_id:
        return True
    if getattr(app, "slot_name", None) or getattr(app, "parent_site_name", None):
        return True
    return False


def _kind_tokens(app) -> frozenset:
    """Return lowercase kind tokens split on comma."""
    kind = (getattr(app, "kind", "") or "").lower()
    return frozenset(t.strip() for t in kind.split(",")) if kind else frozenset()


def _resource_group_from_id(arm_id: str) -> str:
    """Extract the resource group name from an ARM id, preserving original casing."""
    parts = arm_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


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
    Find Azure App Service web apps with no meaningful activity for `idle_days` days.

    Detection requires all four activity metrics to be zero over the idle window:
    Requests, CpuTime, BytesReceived, BytesSent — plus zero WebJobs.

    Only top-level apps (not deployment slots) on paid App Service Plans are
    evaluated. Function Apps, Workflow Apps, disabled apps, and apps with
    WebJobs are excluded to minimize false positives.

    IAM permissions:
    - Microsoft.Web/sites/read
    - Microsoft.Web/serverfarms/read
    - Microsoft.Web/sites/webJobs/read
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
    window_start = now - timedelta(days=idle_days)

    # Build plan tier + site count lookup once.
    # If the plan list call fails mid-iteration, clear any partial data so
    # that all apps fall back to their embedded SKU attribute consistently
    # rather than some apps using cached plan tier and others not.
    plan_tiers: Dict[str, str] = {}
    plan_site_counts: Dict[str, int] = {}
    _plan_list_complete = False
    try:
        for plan in web_client.app_service_plans.list():
            if not getattr(plan, "id", None):
                continue
            pid = _norm_arm_id(plan.id)
            tier = getattr(plan.sku, "tier", None) if plan.sku else None
            if tier:
                plan_tiers[pid] = tier
            count = getattr(plan, "number_of_sites", None)
            if count is not None:
                plan_site_counts[pid] = count
        _plan_list_complete = True
    except (AzureError, HttpResponseError):
        pass
    if not _plan_list_complete:
        plan_tiers.clear()
        plan_site_counts.clear()

    for app in web_client.web_apps.list():
        # spec 8.1: resource_id must be present
        app_id = getattr(app, "id", None)
        if not app_id:
            continue

        # spec 8.2: region filter
        location = _norm_region(getattr(app, "location", "") or "")
        if region_filter and location != _norm_region(region_filter):
            continue

        # spec 8.3: must be Running
        if getattr(app, "state", None) != "Running":
            continue

        # spec 8.4: must be enabled
        if getattr(app, "enabled", True) is False:
            continue

        # spec 8.5: skip deployment slots
        if _is_deployment_slot(app):
            continue

        # spec 8.6 + 8.7: skip Function Apps and Workflow Apps
        tokens = _kind_tokens(app)
        if "functionapp" in tokens or "workflowapp" in tokens:
            continue

        # spec 8.8: skip free/shared/dynamic and unknown tiers
        server_farm_id = getattr(app, "server_farm_id", None) or ""
        sku_tier_raw = plan_tiers.get(_norm_arm_id(server_farm_id))
        if sku_tier_raw is None:
            # Fallback to sku embedded in app object
            sku = getattr(app, "sku", None)
            sku_tier_raw = getattr(sku, "tier", None) if sku else None
        if sku_tier_raw is None or sku_tier_raw.lower() not in _PAID_TIERS:
            continue

        # spec 9: all four activity metrics must be zero
        metrics_all_zero = True
        for metric_name in _ACTIVITY_METRICS:
            v = _get_metric_total(mon_client, app_id, metric_name, window_start, now)
            if v is None:
                metrics_all_zero = False  # unavailable → skip (spec 8.11)
                break
            if v > 0:
                metrics_all_zero = False  # active → skip (spec 8.12)
                break

        if not metrics_all_zero:
            continue

        # spec 10: enumerate WebJobs — skip if call fails or any exist
        # Extract resource group first; an empty result means we cannot form a
        # reliable query, so the inventory would be unusable (spec 10).
        resource_group = _resource_group_from_id(app_id)
        if not resource_group:
            continue  # can't form reliable WebJobs query → skip (spec 10)

        # spec 10: inventory is only trustworthy if iteration completes cleanly.
        # An exception at any point (including mid-page) leaves inventory_complete
        # False, which means we cannot assert zero WebJobs and must skip.
        inventory_complete = False
        webjobs: list = []
        try:
            for _job in web_client.web_apps.list_web_jobs(
                resource_group_name=resource_group,
                name=app.name,
            ):
                webjobs.append(_job)
            inventory_complete = True
        except Exception:
            pass

        if not inventory_complete:
            continue  # spec 10: partial/incomplete/failed inventory → skip (spec 8.9)

        if webjobs:
            continue  # spec 10: WebJobs exist → skip (spec 8.10)

        # --- EMIT ---
        kind_str = ",".join(sorted(tokens)) or "app"
        plan_id_norm = _norm_arm_id(server_farm_id) if server_farm_id else None
        plan_site_count = plan_site_counts.get(plan_id_norm) if plan_id_norm else None
        cost_floor = _TIER_COST_FLOOR_USD.get(sku_tier_raw.lower())
        tags = app.tags or {}

        signals_used = [
            "app state: Running",
            f"app kind: {kind_str}",
            f"App Service Plan tier: {sku_tier_raw} (paid, not Free/Shared/Dynamic)",
            "zero WebJobs detected",
            f"Requests == 0 over {idle_days}-day window",
            f"CpuTime == 0 over {idle_days}-day window",
            f"BytesReceived == 0 over {idle_days}-day window",
            f"BytesSent == 0 over {idle_days}-day window",
        ]
        if cost_floor is not None:
            signals_used.append(
                f"App Service billing is plan-scoped; plan cost floor "
                f"~${cost_floor:.0f}/month per instance (informational only)"
            )

        evidence = Evidence(
            signals_used=signals_used,
            signals_not_checked=[
                "Planned seasonal or reactivation intent not checked",
                "Undeclared business intent not checked",
                "Workload activity outside documented App Service / Azure Monitor signals not checked",
            ],
            time_window=f"{idle_days} days",
        )

        details: dict = {
            "app_name": app.name,
            "kind": kind_str,
            "sku_tier": sku_tier_raw,
            "location": location,
            "idle_days_threshold": idle_days,
        }
        if server_farm_id:
            details["server_farm_id"] = server_farm_id
        if plan_site_count is not None:
            details["app_service_plan_site_count"] = plan_site_count
        if cost_floor is not None:
            details["plan_monthly_cost_floor_usd"] = cost_floor
        if tags:
            details["tags"] = tags

        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type=_RESOURCE_TYPE,
                resource_id=app_id,
                region=location,
                title=f"Idle App Service: no activity for {idle_days}+ days",
                summary=(
                    f"App Service '{app.name}' ({sku_tier_raw}) has had zero "
                    f"Requests, CpuTime, BytesReceived, and BytesSent "
                    f"for {idle_days}+ days"
                ),
                reason=(
                    f"All four activity metrics (Requests, CpuTime, BytesReceived, "
                    f"BytesSent) are zero over a {idle_days}-day window with zero WebJobs"
                ),
                risk=RiskLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details=details,
                estimated_monthly_cost_usd=None,  # spec 11: plan-level billing, not app-level
            )
        )

    return findings
