"""
Rule: azure.network.public_ip.unused

Intent:
    Detect Azure Public IP Address resources that are fully unattached across
    known Azure control-plane linkage surfaces and therefore represent
    conservative cleanup review candidates.

    This is a conservative review-candidate rule only. It does not prove the
    Public IP is delete-safe, unused at the DNS/firewall layer, or guaranteed
    to produce a specific monthly saving.

Exclusions:
    - id absent or empty
    - name absent or empty
    - outside optional region filter (exact lowercase match)
    - provisioning state does not resolve to "Succeeded"
    - any attachment linkage resolves to a non-empty reference
    - unattached dynamic placeholder with no assigned ip_address

Detection:
    - provisioning state is Succeeded
    - all four attachment linkages resolve to absent:
      ip_configuration, nat_gateway, service_public_ip_address, linked_public_ip_address
    - dynamic-placeholder contract is not triggered

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)
    Azure Public IP pricing varies by SKU/type; no flat estimate is appropriate.

APIs:
    - Microsoft.Network/publicIPAddresses/read (public_ip_addresses.list_all)
"""

from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.network import NetworkManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.network.public_ip.unused"
_RESOURCE_TYPE = "azure.network.public_ip"


def _norm_location(s: str) -> str:
    """Lowercase only — exact lowercase match per spec section 7."""
    return s.lower() if s else ""


# ---------------------------------------------------------------------------
# SDK-first / nested-fallback resolvers (spec 9.1–9.2)
# ---------------------------------------------------------------------------


def _resolve_provisioning_state(pip) -> Optional[str]:
    """
    Resolve provisioning state per spec 9.1:
    1. SDK projection (pip.provisioning_state)
    2. Nested snake_case (pip.properties.provisioning_state)
    3. Nested ARM camelCase (pip.properties.provisioningState)
    4. Otherwise None (unknown → caller must skip)
    """
    state = getattr(pip, "provisioning_state", None)
    if state is not None:
        return state
    props = getattr(pip, "properties", None)
    if props is not None:
        state = getattr(props, "provisioning_state", None)
        if state is not None:
            return state
        return getattr(props, "provisioningState", None)
    return None


def _resolve_linkage(pip, sdk_attr: str, arm_attr: str):
    """
    Resolve a single attachment linkage field per spec 9.2:
    1. SDK projection (pip.<sdk_attr>)
    2. Nested ARM camelCase (pip.properties.<arm_attr>)
    Returns the reference object if present, or None.
    """
    ref = getattr(pip, sdk_attr, None)
    if ref is None:
        props = getattr(pip, "properties", None)
        if props is not None:
            ref = getattr(props, arm_attr, None)
    return ref


def _is_attached(pip) -> Optional[bool]:
    """
    Resolve attachment state across all known control-plane linkage fields.

    Returns:
      True  — at least one linkage has a non-empty id (attached)
      False — all linkages are cleanly absent (not attached)
      None  — at least one linkage object is present but has no resolvable id
               (unresolvable → caller must skip rather than emit)

    Canonical linkage map (SDK field → ARM camelCase fallback):
      ip_configuration          → ipConfiguration
      nat_gateway               → natGateway
      service_public_ip_address → servicePublicIPAddress
      linked_public_ip_address  → linkedPublicIPAddress
    """
    for sdk_attr, arm_attr in (
        ("ip_configuration", "ipConfiguration"),
        ("nat_gateway", "natGateway"),
        ("service_public_ip_address", "servicePublicIPAddress"),
        ("linked_public_ip_address", "linkedPublicIPAddress"),
    ):
        ref = _resolve_linkage(pip, sdk_attr, arm_attr)
        if ref is None:
            continue
        if getattr(ref, "id", None):
            return True
        # ref is present but id is absent/empty — cannot resolve reliably
        return None
    return False


def _resolve_allocation_method(pip) -> Optional[str]:
    """
    Resolve allocation method:
    SDK pip.public_ip_allocation_method
    → pip.properties.public_ip_allocation_method
    → pip.properties.publicIPAllocationMethod
    """
    v = getattr(pip, "public_ip_allocation_method", None)
    if v is None:
        props = getattr(pip, "properties", None)
        if props is not None:
            v = getattr(props, "public_ip_allocation_method", None)
            if v is None:
                v = getattr(props, "publicIPAllocationMethod", None)
    return v


def _resolve_ip_address(pip) -> Optional[str]:
    """
    Resolve assigned ip_address:
    SDK pip.ip_address
    → pip.properties.ip_address
    → pip.properties.ipAddress
    """
    v = getattr(pip, "ip_address", None)
    if v is None:
        props = getattr(pip, "properties", None)
        if props is not None:
            v = getattr(props, "ip_address", None)
            if v is None:
                v = getattr(props, "ipAddress", None)
    return v


def find_unused_public_ips(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[NetworkManagementClient] = None,
) -> List[Finding]:
    """
    Find Azure Public IP addresses that are fully unattached across all known
    Azure control-plane linkage surfaces.

    Detection requires:
    - provisioning state resolves to "Succeeded"
    - ip_configuration, nat_gateway, service_public_ip_address, and
      linked_public_ip_address all resolve to absent
    - not an unattached dynamic placeholder with no assigned ip_address

    IAM permissions:
    - Microsoft.Network/publicIPAddresses/read
    """
    findings: List[Finding] = []

    net_client = client or NetworkManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)

    for pip in net_client.public_ip_addresses.list_all():
        # spec 8.1: id must be present and non-empty
        pip_id = getattr(pip, "id", None)
        if not pip_id:
            continue

        # spec 8.2: name must be present and non-empty
        pip_name = getattr(pip, "name", None)
        if not pip_name:
            continue

        # spec 8.3: region filter — exact lowercase match
        location = _norm_location(getattr(pip, "location", "") or "")
        if region_filter and location != _norm_location(region_filter):
            continue

        # spec 8.4 / 9.1: provisioning state must resolve to exactly "Succeeded"
        if _resolve_provisioning_state(pip) != "Succeeded":
            continue

        # spec 8.5 / 9.2: any attachment linkage present → skip;
        # unresolvable linkage (object present, id absent) → also skip
        attached = _is_attached(pip)
        if attached is None or attached:
            continue

        # spec 8.6 / 9.3: dynamic-placeholder contract —
        # unattached Dynamic IP with no assigned address is low-signal noise
        allocation = _resolve_allocation_method(pip)
        ip_address = _resolve_ip_address(pip)
        if allocation == "Dynamic" and not ip_address:
            continue

        # --- context-only details (spec 9.4) ---
        sku = getattr(pip, "sku", None)
        sku_name = getattr(sku, "name", None) if sku else None
        ip_version = getattr(pip, "public_ip_address_version", None)
        if ip_version is None:
            props = getattr(pip, "properties", None)
            if props is not None:
                ip_version = getattr(props, "public_ip_address_version", None)
                if ip_version is None:
                    ip_version = getattr(props, "publicIPAddressVersion", None)
        ip_tags = getattr(pip, "ip_tags", None)
        tags = getattr(pip, "tags", None) or {}

        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type=_RESOURCE_TYPE,
                resource_id=pip_id,
                region=location,
                estimated_monthly_cost_usd=None,  # spec 10: always None
                title="Unused Azure Public IP Address",
                summary=f"Public IP '{pip_name}' is not attached to any Azure resource",
                reason=(
                    "No attachment found via ip_configuration, nat_gateway, "
                    "service_public_ip_address, or linked_public_ip_address"
                ),
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=Evidence(
                    signals_used=[
                        "Provisioning state is Succeeded",
                        "Public IP has no resolved attachment via ip_configuration, nat_gateway, service_public_ip_address, or linked_public_ip_address",
                        "Dynamic-placeholder contract not triggered",
                    ],
                    signals_not_checked=[
                        "Planned future association or reserved intent",
                        "DNS records or firewall allowlist references",
                        "Application-level reachability or traffic history",
                        "Exact Azure billing amount for this Public IP",
                    ],
                    time_window=None,
                ),
                details={
                    "resource_name": pip_name,
                    "subscription_id": subscription_id,
                    "allocation_method": allocation,
                    "ip_address": ip_address,
                    "sku": sku_name,
                    "ip_version": ip_version,
                    "ip_tags": ip_tags,
                    "attached": False,
                    "tags": tags,
                },
            )
        )

    return findings
