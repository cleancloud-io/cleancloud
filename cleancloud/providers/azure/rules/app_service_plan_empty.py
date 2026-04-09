from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.web import WebSiteManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

SKIP_TIERS = {"Free", "Shared", "Dynamic"}  # Dynamic = Consumption/serverless, no idle cost

# Approximate monthly costs by tier (single instance)
_TIER_COST_USD = {
    "Basic": 55.0,
    "Standard": 73.0,
    "Premium": 146.0,
    "PremiumV2": 146.0,
    "PremiumV3": 146.0,
    "Isolated": 298.0,
    "IsolatedV2": 298.0,
}


def _extract_resource_group(resource_id: str) -> Optional[str]:
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return None


def find_empty_app_service_plans(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[WebSiteManagementClient] = None,
) -> List[Finding]:
    """
    Find paid Azure App Service Plans with zero hosted apps.

    Conservative rule:
    - Only flags paid tiers (Free/Shared excluded — no cost signal)
    - number_of_sites == 0 is used as a pre-filter only (unreliable from list API)
    - Confirmed with a secondary list_web_apps() call before flagging
    - Skips plans not in Succeeded provisioning state
    - Skips conservatively if list_web_apps() raises

    IAM permissions:
    - Microsoft.Web/serverfarms/read
    - Microsoft.Web/serverfarms/sites/read
    """
    findings: List[Finding] = []

    web_client = client or WebSiteManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    for plan in web_client.app_service_plans.list():
        # Azure Web SDK returns display names ("West Europe") not short names ("westeurope")
        # Normalize to short name format for consistent output and filtering
        location = (plan.location or "").lower().replace(" ", "")

        if region_filter and location != region_filter.lower().replace(" ", ""):
            continue

        # Skip plans still being provisioned
        if getattr(plan, "provisioning_state", None) not in (None, "Succeeded"):
            continue

        # Skip free/shared tiers — no cost signal
        tier = plan.sku.tier if plan.sku else None
        if tier in SKIP_TIERS:
            continue

        # number_of_sites from the list API is unreliable — use as pre-filter only
        # Treat None the same as 0 (Azure can return None for empty plans)
        if plan.number_of_sites not in (0, None):
            continue

        # Confirm with a secondary API call before flagging
        resource_group = _extract_resource_group(plan.id)
        if not resource_group:
            continue

        try:
            web_apps = list(web_client.app_service_plans.list_web_apps(resource_group, plan.name))
        except Exception:
            # Skip conservatively if the secondary call fails
            continue

        if web_apps:
            continue

        sku_name = plan.sku.name if plan.sku else "unknown"
        sku_tier = tier or "unknown"
        capacity = plan.sku.capacity if plan.sku else None

        evidence = Evidence(
            signals_used=[
                "number_of_sites reported as 0 or None on plan list response",
                "Confirmed via list_web_apps(): 0 apps found on plan",
                f"SKU tier is {sku_tier} (paid tier)",
            ],
            signals_not_checked=[
                "Planned app deployment",
                "IaC-managed intent",
                "Reserved capacity for scaling",
                "Blue/green deployment staging",
            ],
            time_window=None,
        )

        cost_usd = _TIER_COST_USD.get(sku_tier)
        if cost_usd and capacity:
            cost_usd *= capacity

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.app_service_plan.empty",
                resource_type="azure.app_service_plan",
                resource_id=plan.id,
                region=location,
                estimated_monthly_cost_usd=cost_usd,
                title=f"Empty App Service Plan ({sku_tier})",
                summary=(f"Paid App Service Plan '{plan.name}' has no hosted apps"),
                reason=f"number_of_sites reported as 0/None and confirmed empty via list_web_apps() on a {sku_tier} tier plan",
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": plan.name,
                    "subscription_id": subscription_id,
                    "sku_name": sku_name,
                    "sku_tier": sku_tier,
                    "capacity": capacity,
                    "confirmed_web_apps": len(web_apps),
                    "tags": plan.tags,
                },
            )
        )

    return findings
