from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.web import WebSiteManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

SKIP_TIERS = {"Free", "Shared"}

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


def find_empty_app_service_plans(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[WebSiteManagementClient] = None,
) -> List[Finding]:
    """
    Find paid Azure App Service Plans with zero hosted apps.

    Conservative rule (review-only):
    - Only flags paid tiers (Free/Shared excluded — no cost signal)
    - Checks number_of_sites == 0
    - Skips plans not in Succeeded provisioning state

    IAM permissions:
    - Microsoft.Web/serverfarms/read
    """
    findings: List[Finding] = []

    web_client = client or WebSiteManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    for plan in web_client.app_service_plans.list():
        # Azure Web SDK returns display names ("West Europe") not short names ("westeurope")
        # Normalize to short name format for consistent output and filtering
        location = plan.location.lower().replace(" ", "")

        if region_filter and location != region_filter.lower().replace(" ", ""):
            continue

        # Skip plans still being provisioned
        if getattr(plan, "provisioning_state", None) not in (None, "Succeeded"):
            continue

        # Skip free/shared tiers — no cost signal
        tier = plan.sku.tier if plan.sku else None
        if tier in SKIP_TIERS:
            continue

        if plan.number_of_sites == 0:
            sku_name = plan.sku.name if plan.sku else "unknown"
            sku_tier = tier or "unknown"
            capacity = plan.sku.capacity if plan.sku else None

            evidence = Evidence(
                signals_used=[
                    "App Service Plan has 0 hosted apps (number_of_sites=0)",
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
                    reason=f"number_of_sites is 0 on a {sku_tier} tier plan",
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
                        "number_of_sites": 0,
                        "tags": plan.tags,
                    },
                )
            )

    return findings
