from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.network import NetworkManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def _pool_has_members(pool) -> bool:
    """Check if a backend pool has any members via NIC-based or IP-based backends."""
    if getattr(pool, "backend_ip_configurations", None):
        return True
    if getattr(pool, "load_balancer_backend_addresses", None):
        return True
    return False


def find_lb_no_backends(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[NetworkManagementClient] = None,
) -> List[Finding]:
    """
    Find Standard Azure Load Balancers with no backend pool members.

    Conservative rule (review-only):
    - Only flags Standard SKU (Basic has no cost signal post-retirement)
    - Checks both NIC-based and IP-based backend representations
    - Flags only if ALL pools have zero members, or LB has no pools at all
    - Skips non-Succeeded provisioning state

    IAM permissions:
    - Microsoft.Network/loadBalancers/read
    """
    findings: List[Finding] = []

    net_client = client or NetworkManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    for lb in net_client.load_balancers.list_all():
        if region_filter and lb.location != region_filter:
            continue

        # Skip non-Succeeded provisioning state
        if getattr(lb, "provisioning_state", None) not in (None, "Succeeded"):
            continue

        # Only flag Standard SKU (Basic is retired, no cost signal)
        sku_name = lb.sku.name if lb.sku else None
        if sku_name != "Standard":
            continue

        # Check all backend pools for members
        pools = lb.backend_address_pools or []
        has_any_members = any(_pool_has_members(pool) for pool in pools)

        if has_any_members:
            continue

        pool_count = len(pools)
        signals = []
        if pool_count == 0:
            signals.append("Load Balancer has no backend address pools")
        else:
            signals.append(
                f"All {pool_count} backend pool(s) have no members "
                f"(checked backend_ip_configurations and load_balancer_backend_addresses)"
            )
        signals.append("SKU is Standard (incurs base charges regardless of backends)")

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=[
                "Planned backend attachment",
                "IaC-managed intent",
                "Migration or teardown in progress",
                "Disaster recovery or failover standby",
            ],
            time_window=None,
        )

        sku_tier = lb.sku.tier if lb.sku else None

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.load_balancer.no_backends",
                resource_type="azure.load_balancer",
                resource_id=lb.id,
                region=lb.location,
                title="Standard Load Balancer Has No Backend Members",
                summary=(
                    f"This Standard Load Balancer '{lb.name}' currently has no backend "
                    f"pool members. Review whether it is still required or was left "
                    f"behind after a teardown or migration."
                ),
                reason=(
                    f"All backend pools empty on Standard SKU load balancer"
                    if pool_count > 0
                    else "No backend pools configured on Standard SKU load balancer"
                ),
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": lb.name,
                    "subscription_id": subscription_id,
                    "sku_name": sku_name,
                    "sku_tier": sku_tier,
                    "backend_pool_count": pool_count,
                    "frontend_ip_count": len(lb.frontend_ip_configurations or []),
                    "rule_count": len(lb.load_balancing_rules or []),
                    "tags": lb.tags,
                },
            )
        )

    return findings
