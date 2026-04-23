"""
Rule: azure.load_balancer.no_backends

Intent:
    Detect Standard Azure Load Balancers whose billable load-balancing
    configuration points to backend pools with no members.

    This is a conservative review-candidate rule only. It does not prove the
    load balancer is unused, safe to delete, or guaranteed to save cost.

Exclusions:
    - id absent or empty
    - name absent or empty
    - outside optional region filter (exact lowercase match)
    - provisioning state does not resolve to "Succeeded" (SDK then nested fallback)
    - SKU does not resolve to lowercase "standard"
    - no billable rules (no load-balancing rules and no outbound rules)
    - relevant backend-pool set cannot be resolved reliably
    - billable rules exist but resolved relevant backend-pool set is empty
    - any relevant backend pool has one or more members

Detection:
    - SKU is Standard
    - provisioning state is Succeeded
    - at least one billable rule exists
    - all relevant backend pools resolve and are empty

Cost model (spec 11):
    estimated_monthly_cost_usd = None (always)
    Standard Load Balancer pricing depends on configured billable rules and
    processed data; no flat monthly estimate is appropriate.

APIs:
    - Microsoft.Network/loadBalancers/read (load_balancers.list_all)
"""

from datetime import datetime, timezone
from typing import List, Optional, Set

from azure.mgmt.network import NetworkManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.load_balancer.no_backends"
_RESOURCE_TYPE = "azure.load_balancer"


def _norm_location(s: str) -> str:
    """Lowercase only — exact lowercase match per spec section 7."""
    return s.lower() if s else ""


def _norm_pool_id(s: str) -> str:
    """Lowercase and strip trailing slash — ARM id normalization per spec section 7."""
    return s.lower().rstrip("/") if s else ""


def _safe_list(v) -> list:
    """
    Coerce v to a list safely.
    Returns [] for None or any non-iterable shape, preventing TypeError on
    malformed ARM response fields that are truthy but not iterable.
    """
    if v is None:
        return []
    try:
        return list(v)
    except TypeError:
        return []


# ---------------------------------------------------------------------------
# SDK-first / nested-fallback resolvers (spec 9.1–9.4)
# ---------------------------------------------------------------------------


def _resolve_provisioning_state(lb) -> Optional[str]:
    """
    Resolve provisioning state per spec 9.1:
    1. SDK projection (lb.provisioning_state)
    2. Nested snake_case (lb.properties.provisioning_state)
    3. Nested ARM camelCase (lb.properties.provisioningState)
    4. Otherwise None (unknown → caller must skip)
    """
    state = getattr(lb, "provisioning_state", None)
    if state is not None:
        return state
    props = getattr(lb, "properties", None)
    if props is not None:
        state = getattr(props, "provisioning_state", None)
        if state is not None:
            return state
        return getattr(props, "provisioningState", None)
    return None


def _get_lb_rules(lb) -> list:
    """
    Get load-balancing rules per spec 9.2:
    SDK lb.load_balancing_rules → nested snake_case → nested ARM camelCase → []
    """
    rules = getattr(lb, "load_balancing_rules", None)
    if rules is None:
        props = getattr(lb, "properties", None)
        if props is not None:
            rules = getattr(props, "load_balancing_rules", None)
            if rules is None:
                rules = getattr(props, "loadBalancingRules", None)
    return _safe_list(rules)


def _get_outbound_rules(lb) -> list:
    """
    Get outbound rules per spec 9.2:
    SDK lb.outbound_rules → nested snake_case → nested ARM camelCase → []
    """
    rules = getattr(lb, "outbound_rules", None)
    if rules is None:
        props = getattr(lb, "properties", None)
        if props is not None:
            rules = getattr(props, "outbound_rules", None)
            if rules is None:
                rules = getattr(props, "outboundRules", None)
    return _safe_list(rules)


def _get_backend_pools(lb) -> list:
    """
    Get backend address pools per spec 9.3 / spec 6:
    SDK lb.backend_address_pools → nested snake_case → nested ARM camelCase → []
    """
    pools = getattr(lb, "backend_address_pools", None)
    if pools is None:
        props = getattr(lb, "properties", None)
        if props is not None:
            pools = getattr(props, "backend_address_pools", None)
            if pools is None:
                pools = getattr(props, "backendAddressPools", None)
    return _safe_list(pools)


def _get_frontend_ip_configs(lb) -> list:
    """
    Get frontend IP configurations (detail-only, not used for detection):
    SDK lb.frontend_ip_configurations → nested snake_case → nested ARM camelCase → []
    """
    cfgs = getattr(lb, "frontend_ip_configurations", None)
    if cfgs is None:
        props = getattr(lb, "properties", None)
        if props is not None:
            cfgs = getattr(props, "frontend_ip_configurations", None)
            if cfgs is None:
                cfgs = getattr(props, "frontendIPConfigurations", None)
    return _safe_list(cfgs)


def _rule_single_pool_ref(rule):
    """
    Get a rule's single backend_address_pool reference per spec 9.3:
    SDK rule.backend_address_pool → nested snake_case → nested ARM camelCase → None
    """
    ref = getattr(rule, "backend_address_pool", None)
    if ref is None:
        props = getattr(rule, "properties", None)
        if props is not None:
            ref = getattr(props, "backend_address_pool", None)
            if ref is None:
                ref = getattr(props, "backendAddressPool", None)
    return ref


def _rule_multi_pool_refs(rule) -> list:
    """
    Get a rule's backend_address_pools list per spec 9.3:
    SDK rule.backend_address_pools → nested snake_case → nested ARM camelCase → []
    """
    refs = getattr(rule, "backend_address_pools", None)
    if refs is None:
        props = getattr(rule, "properties", None)
        if props is not None:
            refs = getattr(props, "backend_address_pools", None)
            if refs is None:
                refs = getattr(props, "backendAddressPools", None)
    return _safe_list(refs)


def _pool_has_members(pool) -> bool:
    """
    A pool has members when either NIC-based or IP-based membership contains
    at least one entry, per spec 9.4.

    SDK projections are checked first; nested snake_case and then ARM camelCase
    are used as fallback if the SDK attribute is absent (None).
    """
    props = getattr(pool, "properties", None)

    # NIC-based: SDK first, nested snake_case, nested camelCase
    nic = getattr(pool, "backend_ip_configurations", None)
    if nic is None and props is not None:
        nic = getattr(props, "backend_ip_configurations", None)
        if nic is None:
            nic = getattr(props, "backendIpConfigurations", None)

    # IP-based: SDK first, nested snake_case, nested camelCase
    ip_based = getattr(pool, "load_balancer_backend_addresses", None)
    if ip_based is None and props is not None:
        ip_based = getattr(props, "load_balancer_backend_addresses", None)
        if ip_based is None:
            ip_based = getattr(props, "loadBalancerBackendAddresses", None)

    return bool(nic or []) or bool(ip_based or [])


def _collect_referenced_pool_ids(lb) -> Optional[Set[str]]:
    """
    Collect normalized ARM ids of backend pools referenced by billable rules
    (load-balancing rules and outbound rules), per spec 9.3.

    Uses SDK-first with nested/raw fallback for both rule collections and
    individual pool references within each rule.

    Returns None if any reference cannot be resolved — a pool reference object
    that lacks an id, or a billable rule with no pool reference at all.
    Callers must skip the load balancer when None is returned.

    Returns a set of normalized pool ids (possibly empty) otherwise.
    """
    referenced: Set[str] = set()

    for rule in list(_get_lb_rules(lb)) + list(_get_outbound_rules(lb)):
        rule_pool_ids: Set[str] = set()

        # Single pool reference: SDK first, nested fallback
        single = _rule_single_pool_ref(rule)
        if single is not None:
            pid = getattr(single, "id", None)
            if not pid:
                return None  # reference object present but no id → unresolvable
            rule_pool_ids.add(_norm_pool_id(pid))

        # Multi pool references: SDK first, nested fallback
        for ref in _rule_multi_pool_refs(rule):
            pid = getattr(ref, "id", None)
            if not pid:
                return None  # reference object present but no id → unresolvable
            rule_pool_ids.add(_norm_pool_id(pid))

        if not rule_pool_ids:
            # Billable rule has no pool reference at all — incomplete config → skip
            return None

        referenced |= rule_pool_ids

    return referenced


def find_lb_no_backends(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[NetworkManagementClient] = None,
) -> List[Finding]:
    """
    Find Standard Azure Load Balancers with billable rules pointing to
    backend pools that have no members.

    Detection requires:
    - SKU resolves to "Standard"
    - provisioning state resolves to exactly "Succeeded" (SDK then nested fallback)
    - at least one billable rule (load-balancing rule or outbound rule)
    - all relevant backend pools resolve and are empty

    IAM permissions:
    - Microsoft.Network/loadBalancers/read
    """
    findings: List[Finding] = []

    net_client = client or NetworkManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)

    for lb in net_client.load_balancers.list_all():
        # spec 8.1: id must be present and non-empty
        lb_id = getattr(lb, "id", None)
        if not lb_id:
            continue

        # spec 8.2: name must be present and non-empty
        lb_name = getattr(lb, "name", None)
        if not lb_name:
            continue

        # spec 8.3: region filter — exact lowercase match
        location = _norm_location(getattr(lb, "location", "") or "")
        if region_filter and location != _norm_location(region_filter):
            continue

        # spec 8.4 / 9.1: provisioning state must resolve to exactly "Succeeded"
        if _resolve_provisioning_state(lb) != "Succeeded":
            continue

        # spec 8.5: SKU must resolve to lowercase "standard"
        sku = getattr(lb, "sku", None)
        sku_name = getattr(sku, "name", None) if sku else None
        if not sku_name or sku_name.lower() != "standard":
            continue

        # spec 8.6 / 9.2: at least one billable rule must exist (SDK + nested fallback)
        lb_rules = _get_lb_rules(lb)
        outbound_rules = _get_outbound_rules(lb)
        lb_rule_count = len(lb_rules)
        outbound_rule_count = len(outbound_rules)
        billable_rule_count = lb_rule_count + outbound_rule_count
        if billable_rule_count == 0:
            continue

        # spec 9.3: collect pool ids referenced by billable rules (SDK + nested fallback)
        referenced_ids = _collect_referenced_pool_ids(lb)
        if referenced_ids is None:
            continue  # unresolvable reference → skip

        # spec 8.8: resolved relevant pool set is empty → skip
        if not referenced_ids:
            continue

        # spec 9.3: build normalized pool inventory (SDK + nested fallback)
        pool_inventory = {}
        for pool in _get_backend_pools(lb):
            pool_id = getattr(pool, "id", None)
            if pool_id:
                pool_inventory[_norm_pool_id(pool_id)] = pool

        # spec 9.3: resolve referenced ids against inventory; skip if any unresolvable
        relevant_pools = []
        skip_lb = False
        for norm_id in referenced_ids:
            pool = pool_inventory.get(norm_id)
            if pool is None:
                skip_lb = True
                break
            relevant_pools.append(pool)
        if skip_lb:
            continue

        # spec 8.9 / 9.4: any relevant pool with members → skip (SDK + nested fallback)
        if any(_pool_has_members(pool) for pool in relevant_pools):
            continue

        # --- EMIT ---
        sku_tier = getattr(sku, "tier", None) if sku else None
        tags = getattr(lb, "tags", None) or {}
        relevant_pool_count = len(relevant_pools)
        all_pool_count = len(_get_backend_pools(lb))
        frontend_count = len(_get_frontend_ip_configs(lb))

        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type=_RESOURCE_TYPE,
                resource_id=lb_id,
                region=location,
                estimated_monthly_cost_usd=None,  # spec 11: always None
                title="Standard Load Balancer Has No Backend Members",
                summary=(
                    f"Standard Load Balancer '{lb_name}' has {billable_rule_count} billable "
                    f"rule(s) but all {relevant_pool_count} relevant backend pool(s) are empty"
                ),
                reason=(
                    f"All {relevant_pool_count} relevant backend pool(s) referenced by "
                    f"{billable_rule_count} billable rule(s) have zero members"
                ),
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=Evidence(
                    signals_used=[
                        "Load Balancer SKU is Standard",
                        f"Billable rule count is {billable_rule_count}",
                        "All relevant backend pools evaluated to empty using NIC-based and IP-based membership checks",
                    ],
                    signals_not_checked=[
                        "Planned backend attachment or cutover intent",
                        "IaC-managed placeholder or staged deployment intent",
                        "Traffic history or future activation plans",
                        "Frontend public IP cost or attachment evaluated by other rules",
                    ],
                    time_window=None,
                ),
                details={
                    "resource_name": lb_name,
                    "subscription_id": subscription_id,
                    "sku_name": sku_name,
                    "sku_tier": sku_tier,
                    "backend_pool_count": all_pool_count,
                    "relevant_backend_pool_count": relevant_pool_count,
                    "frontend_ip_count": frontend_count,
                    "load_balancing_rule_count": lb_rule_count,
                    "outbound_rule_count": outbound_rule_count,
                    "tags": tags,
                },
            )
        )

    return findings
