from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.network import NetworkManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def _pool_has_targets(pool) -> bool:
    """Check if a backend pool has any targets (IP addresses, FQDNs, or NIC refs)."""
    # Check direct backend addresses (IP or FQDN)
    addresses = getattr(pool, "backend_addresses", None)
    if addresses and len(addresses) > 0:
        return True

    # Check NIC-based backend IP configurations
    ip_configs = getattr(pool, "backend_ip_configurations", None)
    if ip_configs and len(ip_configs) > 0:
        return True

    return False


def find_app_gateway_no_backends(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[NetworkManagementClient] = None,
) -> List[Finding]:
    """
    Find Azure Application Gateways with no backend pool targets.

    Conservative rule (review-only):
    - Flags only if ALL backend pools have zero targets
    - Checks backend_addresses and backend_ip_configurations in each pool
    - Skips non-Succeeded provisioning state
    - Includes SKU info (Standard_v2, WAF_v2 cost $150-300+/month)

    IAM permissions:
    - Microsoft.Network/applicationGateways/read
    """
    findings: List[Finding] = []

    net_client = client or NetworkManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    for gw in net_client.application_gateways.list_all():
        if region_filter and gw.location != region_filter:
            continue

        # Skip non-Succeeded provisioning state
        if getattr(gw, "provisioning_state", None) not in (None, "Succeeded"):
            continue

        # Check all backend pools for targets
        pools = gw.backend_address_pools or []
        has_any_targets = any(_pool_has_targets(pool) for pool in pools)

        if has_any_targets:
            continue

        pool_count = len(pools)
        sku_name = gw.sku.name if gw.sku else "unknown"
        sku_tier = gw.sku.tier if gw.sku else "unknown"
        sku_capacity = gw.sku.capacity if gw.sku else None

        signals = []
        if pool_count == 0:
            signals.append("Application Gateway has no backend address pools")
        else:
            signals.append(
                f"All {pool_count} backend pool(s) have zero targets "
                f"(checked backend_addresses and backend_ip_configurations)"
            )
        signals.append(f"SKU is {sku_tier} (incurs significant charges regardless of backends)")

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=[
                "Planned backend attachment",
                "IaC-managed intent",
                "Migration or teardown in progress",
                "Disaster recovery or failover standby",
                "WAF-only deployment (inspection without backends)",
            ],
            time_window=None,
        )

        # Estimate monthly cost based on SKU
        cost_estimate = None
        cost_usd = None
        if sku_tier in ("Standard_v2", "WAF_v2"):
            cost_estimate = "$150-300+/month (v2 SKU)"
            cost_usd = 225.0
        elif sku_tier in ("Standard", "WAF"):
            cost_estimate = "$20-50/month (v1 SKU)"
            cost_usd = 35.0

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.application_gateway.no_backends",
                resource_type="azure.application_gateway",
                resource_id=gw.id,
                region=gw.location,
                estimated_monthly_cost_usd=cost_usd,
                title="Application Gateway Has No Backend Targets",
                summary=(
                    f"Application Gateway '{gw.name}' appears to have no backend targets configured "
                    f"and may be incurring charges without serving application traffic."
                ),
                reason=(
                    "All backend pools empty on Application Gateway"
                    if pool_count > 0
                    else "No backend pools configured on Application Gateway"
                ),
                risk=RiskLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": gw.name,
                    "subscription_id": subscription_id,
                    "sku_name": sku_name,
                    "sku_tier": sku_tier,
                    "sku_capacity": sku_capacity,
                    "backend_pool_count": pool_count,
                    "http_listener_count": len(gw.http_listeners or []),
                    "request_routing_rule_count": len(gw.request_routing_rules or []),
                    "cost_estimate": cost_estimate,
                    "tags": gw.tags,
                },
            )
        )

    return findings
