from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# VNet Gateway SKU monthly costs (approximate)
SKU_COSTS = {
    # VPN Gateway SKUs
    "Basic": "$27/month",
    "VpnGw1": "$140/month",
    "VpnGw1AZ": "$195/month",
    "VpnGw2": "$360/month",
    "VpnGw2AZ": "$505/month",
    "VpnGw3": "$930/month",
    "VpnGw3AZ": "$1,115/month",
    "VpnGw4": "$1,680/month",
    "VpnGw4AZ": "$1,845/month",
    "VpnGw5": "$3,360/month",
    "VpnGw5AZ": "$3,525/month",
    # ExpressRoute Gateway SKUs
    "Standard": "$125/month",
    "HighPerformance": "$335/month",
    "UltraPerformance": "$670/month",
    "ErGw1AZ": "$195/month",
    "ErGw2AZ": "$505/month",
    "ErGw3AZ": "$1,115/month",
    "ErGwScale": "Usage-based",
}

# Numeric costs for aggregation
_SKU_COST_USD = {
    "Basic": 27,
    "VpnGw1": 140,
    "VpnGw1AZ": 195,
    "VpnGw2": 360,
    "VpnGw2AZ": 505,
    "VpnGw3": 930,
    "VpnGw3AZ": 1115,
    "VpnGw4": 1680,
    "VpnGw4AZ": 1845,
    "VpnGw5": 3360,
    "VpnGw5AZ": 3525,
    "Standard": 125,
    "HighPerformance": 335,
    "UltraPerformance": 670,
    "ErGw1AZ": 195,
    "ErGw2AZ": 505,
    "ErGw3AZ": 1115,
}


def _extract_resource_group(resource_id: str) -> Optional[str]:
    """Extract resource group name from Azure resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        rg_idx = parts.index("resourceGroups")
        return parts[rg_idx + 1]
    except (ValueError, IndexError):
        return None


def find_idle_vnet_gateways(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[NetworkManagementClient] = None,
    resource_client: Optional[ResourceManagementClient] = None,
) -> List[Finding]:
    """
    Find Azure VNet Gateways (VPN/ExpressRoute) with no active connections.

    Conservative rule (review-only):
    - Flags VPN gateways with zero Site-to-Site or Point-to-Site connections
    - Flags ExpressRoute gateways with no circuits
    - Skips non-Succeeded provisioning state
    - Includes SKU cost estimates ($140-3500+/month)

    IAM permissions:
    - Microsoft.Network/virtualNetworkGateways/read
    - Microsoft.Network/connections/read
    """
    findings: List[Finding] = []

    net_client = client or NetworkManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    res_client = resource_client or ResourceManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    # List all VNet gateways across the subscription using resource filter
    gateway_resources = list(
        res_client.resources.list(
            filter="resourceType eq 'Microsoft.Network/virtualNetworkGateways'"
        )
    )

    for gw_resource in gateway_resources:
        resource_group = _extract_resource_group(gw_resource.id)
        if not resource_group:
            continue

        # Get full gateway details
        try:
            gw = net_client.virtual_network_gateways.get(resource_group, gw_resource.name)
        except Exception:
            continue

        if region_filter and gw.location != region_filter:
            continue

        # Skip non-Succeeded provisioning state
        if getattr(gw, "provisioning_state", None) not in (None, "Succeeded"):
            continue

        gateway_type = getattr(gw, "gateway_type", None)

        # Only handle known gateway types
        if gateway_type not in ("Vpn", "ExpressRoute"):
            continue

        sku_name = gw.sku.name if gw.sku else "unknown"
        sku_tier = gw.sku.tier if gw.sku else "unknown"

        # Get connections for this gateway
        try:
            connections = list(
                net_client.virtual_network_gateways.list_connections(resource_group, gw.name)
            )
        except Exception:
            connections = []

        # Check for active connections.
        # The list_connections() API returns summary entities where connection_status
        # is often None even for live connections. Treat None/unknown status as
        # potentially active (conservative). Only treat as inactive when explicitly
        # NotConnected or Disconnected.
        _inactive_statuses = {"NotConnected", "Disconnected"}
        active_connections = []
        for c in connections:
            status = getattr(c, "connection_status", None)
            # Treat unknown status as active (conservative assumption)
            if status not in _inactive_statuses:
                active_connections.append(c)

        # For VPN gateways, also check VPN client configuration (P2S)
        vpn_client_config = getattr(gw, "vpn_client_configuration", None)
        has_p2s_config = (
            vpn_client_config is not None
            and getattr(vpn_client_config, "vpn_client_address_pool", None) is not None
        )

        # Determine if gateway is idle
        is_idle = False
        signals = []

        if gateway_type == "Vpn":
            if len(active_connections) == 0 and not has_p2s_config:
                is_idle = True
                signals.append("No active Site-to-Site connections detected")
                signals.append("No Point-to-Site configuration found")
            elif len(active_connections) == 0 and has_p2s_config:
                # Has P2S config but we can't check active P2S clients without
                # additional API calls, so we'll note it as a signal not checked
                pass
        elif gateway_type == "ExpressRoute":
            if len(active_connections) == 0:
                is_idle = True
                signals.append("No active ExpressRoute circuit connections detected")

        if not is_idle:
            continue

        signals.append(f"Gateway SKU is {sku_name} ({SKU_COSTS.get(sku_name, 'significant cost')})")

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=[
                "Active Point-to-Site VPN clients",
                "Connection status not always populated by Azure list API (connections with unknown status treated as active)",
                "Planned connection setup",
                "IaC-managed intent",
                "Migration or teardown in progress",
                "Disaster recovery or failover standby",
                "Test/dev environment gateway",
            ],
            time_window=None,
        )

        cost_estimate = SKU_COSTS.get(sku_name, "Unknown")
        cost_usd = float(_SKU_COST_USD[sku_name]) if sku_name in _SKU_COST_USD else None

        title = (
            "VPN Gateway Has No Active Connections"
            if gateway_type == "Vpn"
            else "ExpressRoute Gateway Has No Active Connections"
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.virtual_network_gateway.idle",
                resource_type="azure.virtual_network_gateway",
                resource_id=gw.id,
                region=gw.location,
                estimated_monthly_cost_usd=cost_usd,
                title=title,
                summary=(
                    f"{gateway_type} Gateway '{gw.name}' appears to have no active connections "
                    f"and may be incurring significant charges ({cost_estimate}) without serving traffic."
                ),
                reason=f"No active connections on {gateway_type} Gateway",
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.MEDIUM,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": gw.name,
                    "resource_group": resource_group,
                    "subscription_id": subscription_id,
                    "gateway_type": gateway_type,
                    "sku_name": sku_name,
                    "sku_tier": sku_tier,
                    "sku_capacity": gw.sku.capacity if gw.sku else None,
                    "total_connections": len(connections),
                    "active_connections": len(active_connections),
                    "has_p2s_config": has_p2s_config,
                    "cost_estimate": cost_estimate,
                    "tags": gw.tags,
                },
            )
        )

    return findings
