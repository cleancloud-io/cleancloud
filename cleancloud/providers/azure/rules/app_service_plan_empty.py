"""
Rule: azure.app_service_plan.empty

Intent:
    Find paid Azure App Service Plans with zero hosted apps.
    Such plans are candidates for plan-level spend review because
    App Service plans can continue to incur charges depending on
    tier and configured capacity.

Exclusions:
    - plan.id absent or empty
    - outside region filter (normalized location)
    - provisioning_state != "Succeeded" (includes None)
    - plan.sku is None
    - plan.sku.tier is None, empty, or not in known paid tier allowlist
    - number_of_sites > 0 (pre-filter only; not final signal)
    - resource group not extractable from plan.id (case-insensitive segment match)
    - list_web_apps() raises any exception (skip conservatively)
    - list_web_apps() returns one or more apps

Detection:
    - provisioning_state == "Succeeded"
    - plan.sku.tier (lowercased) in known paid tier allowlist
    - number_of_sites == 0 or None (pre-filter)
    - list_web_apps() completes fully with zero apps returned

Tier allowlist (case-insensitive match on sku.tier):
    basic, standard, premium, premiumv2, premiumv3, premiumv4,
    isolated, isolatedv2

Cost model:
    estimated_monthly_cost_usd = TIER_BASE_COST_USD[tier.lower()] * capacity
    None when capacity is None or 0, or tier not in cost table

APIs:
    - Microsoft.Web/serverfarms/read       (app_service_plans.list)
    - Microsoft.Web/serverfarms/sites/read (app_service_plans.list_web_apps)
"""

from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.web import WebSiteManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.app_service_plan.empty"
_RESOURCE_TYPE = "azure.app_service_plan"

# Allowlist of known paid dedicated-compute and isolated tiers.
# Anything not in this set is treated as unknown and skipped.
_PAID_TIERS = {
    "basic",
    "standard",
    "premium",
    "premiumv2",
    "premiumv3",
    "premiumv4",
    "isolated",
    "isolatedv2",
}

# Approximate single-instance monthly cost by normalized tier (East US, list price).
_TIER_COST_USD = {
    "basic": 55.0,
    "standard": 73.0,
    "premium": 146.0,
    "premiumv2": 146.0,
    "premiumv3": 146.0,
    "premiumv4": 146.0,
    "isolated": 298.0,
    "isolatedv2": 298.0,
}


def _norm_region(s: str) -> str:
    """Normalize region: lowercase, remove spaces."""
    return s.lower().replace(" ", "") if s else ""


def _extract_resource_group(resource_id: str) -> Optional[str]:
    """Extract the resource group from an ARM id using a case-insensitive segment match."""
    parts = resource_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
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

    Detection requires:
    - provisioningState == "Succeeded"
    - SKU tier in known paid tier allowlist
    - number_of_sites == 0 or None (pre-filter)
    - list_web_apps() confirms zero apps (authoritative)

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
        # spec 8.1: plan.id must be present
        if not getattr(plan, "id", None):
            continue

        # spec 8.2: region filter
        location = _norm_region(getattr(plan, "location", "") or "")
        if region_filter and location != _norm_region(region_filter):
            continue

        # spec 8.3: must be Succeeded (None is not Succeeded)
        if getattr(plan, "provisioning_state", None) != "Succeeded":
            continue

        # spec 8.4: sku must be present
        sku = getattr(plan, "sku", None)
        if sku is None:
            continue

        # spec 8.5: tier must be in known paid allowlist
        tier_raw = getattr(sku, "tier", None)
        if not tier_raw or tier_raw.lower() not in _PAID_TIERS:
            continue

        # spec 8.6: pre-filter on number_of_sites (unreliable cache; 0/None proceeds to phase 2)
        num_sites = getattr(plan, "number_of_sites", None)
        if num_sites is not None and num_sites > 0:
            continue

        # spec 8.7: resource group must be extractable for the secondary API call
        resource_group = _extract_resource_group(plan.id)
        if not resource_group:
            continue

        # spec 10 phase 2: confirm emptiness via list_web_apps() — full iteration required.
        # inventory_complete is only set True after the loop finishes without exception.
        # A mid-iteration exception leaves it False, which causes a conservative skip.
        inventory_complete = False
        web_apps: list = []
        try:
            for app in web_client.app_service_plans.list_web_apps(resource_group, plan.name):
                web_apps.append(app)
            inventory_complete = True
        except Exception:
            pass

        if not inventory_complete:
            continue  # spec 8.8: enumeration failed or incomplete — skip

        if web_apps:
            continue  # spec 8.9: apps exist — skip

        # --- EMIT ---
        sku_name = getattr(sku, "name", None)
        capacity = getattr(sku, "capacity", None)
        tags = plan.tags or {}

        tier_key = tier_raw.lower()
        tier_base = _TIER_COST_USD.get(tier_key)
        if tier_base is not None and capacity is not None and capacity > 0:
            cost_usd = tier_base * capacity
        else:
            cost_usd = None

        if num_sites == 0:
            sites_signal = "number_of_sites reported as 0 on plan list response"
            sites_reason_prefix = "number_of_sites is 0 (strong empty-plan indicator)"
        else:
            sites_signal = (
                "number_of_sites was None on plan list response; "
                "emptiness confirmed only via list_web_apps()"
            )
            sites_reason_prefix = (
                "number_of_sites was None (treated as unknown, not evidence of emptiness by itself)"
            )

        signals_used = [
            sites_signal,
            "Confirmed via list_web_apps(): 0 apps found on plan",
            f"SKU tier is {tier_raw} (paid dedicated tier — in known paid tier allowlist)",
        ]
        if capacity is not None and capacity > 0:
            signals_used.append(
                f"Plan has {capacity} provisioned instance(s) reserved and typically billed "
                f"at the {tier_raw} tier rate"
            )
        elif capacity == 0:
            signals_used.append("capacity is 0; no current worker cost inferred")

        evidence = Evidence(
            signals_used=signals_used,
            signals_not_checked=[
                "Planned app deployment — plan may be created before apps in an IaC pipeline",
                "IaC-managed intent — plan may be managed by Terraform, Bicep, or ARM templates",
                "Reserved capacity for upcoming scaling or blue/green deployment staging",
                "App Service Environment stamp fee (for Isolated/IsolatedV2) not included in estimated cost",
            ],
            time_window=None,
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type=_RESOURCE_TYPE,
                resource_id=plan.id,
                region=location,
                estimated_monthly_cost_usd=cost_usd,
                title=f"Empty App Service Plan ({tier_raw})",
                summary=f"Paid App Service Plan '{plan.name}' has no hosted apps",
                reason=(
                    f"{sites_reason_prefix} and confirmed empty via "
                    f"list_web_apps() on a {tier_raw} tier plan"
                ),
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": plan.name,
                    "subscription_id": subscription_id,
                    "sku_name": sku_name,
                    "sku_tier": tier_raw,
                    "capacity": capacity,
                    "confirmed_web_apps": 0,
                    "tags": tags,
                },
            )
        )

    return findings
