"""
Rule: azure.application_gateway.no_backends

    (spec — docs/specs/azure/app_gateway_no_backends.md)

Intent:
    Detect active Application Gateway routing paths that resolve to backend pools
    with no explicit backend targets.

Exclusions:
    - application_gateway_id absent
    - backend_pool_id absent
    - pool not reached from active top-level routing rules
    - backend_target_count > 0

Detection:
    - referenced_by_active_routes == true
    - backend_target_count == 0

Key rules:
    - Traverse from active requestRoutingRules and routingRules only.
    - Deduplicate top-level active rules by normalized rule id.
    - urlPathMaps are not active by themselves.
    - loadDistributionPolicies are not active by themselves.
    - Redirect-only rules are skipped when they have redirectConfiguration and no backend selection path.
    - Use management-plane configuration only.
    - Runtime backend health is out of scope for emission.
    - Treat optional legacy backendIPConfigurations as explicit targets only when present in the gateway read payload.
    - Unresolved or malformed nested references produce diagnostics, not findings.

APIs:
    - Microsoft.Network/applicationGateways/read
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from azure.core.exceptions import HttpResponseError
from azure.mgmt.network import NetworkManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Module constants  (spec §17)
# ---------------------------------------------------------------------------

_EVALUATION_PATH = "app-gateway-no-backends"
_FINDING_TITLE = "Application Gateway active route points to empty backend pool"
_FINDING_REASON = (
    "An active Application Gateway routing path resolves to a backend pool "
    "with no explicit backend targets in management-plane configuration"
)

_BLIND_SPOTS = [
    "Runtime backend health (Healthy / Unhealthy / Unknown) not checked for detection",
    "External DNS or application-level service discovery outside ARM-managed backend "
    "pool targets not checked",
    "Rewrite logic does not create new backend pool references; only configured "
    "route-to-pool links are evaluated",
    "If legacy/read-only backendIPConfigurations is absent from the API response, "
    "the rule relies on documented backendAddresses plus whatever active route structure is present",
    "Unresolved references inside malformed gateway configuration are not promoted "
    "to findings; they are only diagnostics",
]


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def _norm_id(raw) -> Optional[str]:
    """Return normalized lowercase ARM id, or None if unusable."""
    if raw is None:
        return None
    if isinstance(raw, str):
        s = raw.strip()
        return s.lower() if s else None
    if isinstance(raw, dict):
        v = raw.get("id")
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return None
    # SDK typed object
    v = getattr(raw, "id", None)
    if isinstance(v, str) and v.strip():
        return v.strip().lower()
    return None


def _get_str(obj, attr: str) -> Optional[str]:
    """Get a string attribute from a dict or SDK object, or None."""
    v = obj.get(attr) if isinstance(obj, dict) else getattr(obj, attr, None)
    if isinstance(v, str) and v.strip():
        return v.strip()
    return None


def _get_list(obj, attr: str) -> list:
    """Get a list attribute from a dict or SDK object, or []."""
    v = obj.get(attr) if isinstance(obj, dict) else getattr(obj, attr, None)
    return v if isinstance(v, list) else []


def _name_from_id(arm_id: str) -> Optional[str]:
    """Last non-empty segment of a normalized ARM id."""
    parts = [p for p in arm_id.strip("/").split("/") if p]
    return parts[-1] if parts else None


# ---------------------------------------------------------------------------
# Pool normalization
# ---------------------------------------------------------------------------


def _normalize_pool(pool) -> Optional[dict]:
    """Normalize a backend pool SDK object to canonical dict. Returns None if id absent."""
    pool_id = _norm_id(pool)
    if not pool_id:
        return None

    raw_name = _get_str(pool, "name")
    pool_name = raw_name or _name_from_id(pool_id)

    # backendAddresses — canonical target source (spec §2)
    backend_addresses = _get_list(pool, "backend_addresses") or _get_list(pool, "backendAddresses")
    backend_addresses = [a for a in backend_addresses if a is not None]

    # backendIPConfigurations — optional legacy/read-only field (spec §2)
    legacy_cfgs = _get_list(pool, "backend_ip_configurations") or _get_list(
        pool, "backendIPConfigurations"
    )
    legacy_cfgs = [c for c in legacy_cfgs if c is not None]

    return {
        "backend_pool_id": pool_id,
        "backend_pool_name": pool_name,
        "backend_addresses": backend_addresses,
        "legacy_backend_ip_configurations": legacy_cfgs,
        "backend_target_count": len(backend_addresses) + len(legacy_cfgs),
    }


# ---------------------------------------------------------------------------
# Lookup table builders
# ---------------------------------------------------------------------------


def _build_pool_lookup(pools_raw: list) -> tuple[dict, list]:
    """Build {pool_id: normalized_pool}. Returns (lookup, diagnostics)."""
    lookup: dict = {}
    diags: list = []
    for pool in pools_raw:
        norm = _normalize_pool(pool)
        if norm is None:
            diags.append(
                {
                    "kind": "malformed_object",
                    "scope": "backend_pool",
                    "object_id": None,
                    "parent_id": None,
                    "reason": "missing_id",
                }
            )
        else:
            lookup[norm["backend_pool_id"]] = norm
    return lookup, diags


def _build_path_map_lookup(maps_raw: list, gw_id: str) -> tuple[dict, list]:
    """Build {path_map_id: raw_path_map}. Returns (lookup, diagnostics)."""
    lookup: dict = {}
    diags: list = []
    for pm in maps_raw:
        pm_id = _norm_id(pm)
        if pm_id is None:
            name = _get_str(pm, "name")
            if name:
                pm_id = f"{gw_id}/urlpathmaps/{name}".lower()
            else:
                diags.append(
                    {
                        "kind": "malformed_object",
                        "scope": "url_path_map",
                        "object_id": None,
                        "parent_id": gw_id,
                        "reason": "missing_name_and_id",
                    }
                )
                continue
        lookup[pm_id] = pm
    return lookup, diags


def _build_policy_lookup(policies_raw: list, gw_id: str) -> tuple[dict, list]:
    """Build {policy_id: raw_policy}. Returns (lookup, diagnostics)."""
    lookup: dict = {}
    diags: list = []
    for policy in policies_raw:
        pol_id = _norm_id(policy)
        if pol_id is None:
            name = _get_str(policy, "name")
            if name:
                pol_id = f"{gw_id}/loaddistributionpolicies/{name}".lower()
            else:
                diags.append(
                    {
                        "kind": "malformed_object",
                        "scope": "load_distribution_policy",
                        "object_id": None,
                        "parent_id": gw_id,
                        "reason": "missing_name_and_id",
                    }
                )
                continue
        lookup[pol_id] = policy
    return lookup, diags


def _record_pool_route(
    *,
    pool_id: str,
    top_rule_id: str,
    route_id: str,
    pool_route_refs: Dict[str, set],
    pool_rule_ids: Dict[str, set],
) -> None:
    """Record a successful top-level-route-to-pool traversal."""
    pool_route_refs.setdefault(pool_id, set()).add(route_id)
    pool_rule_ids.setdefault(pool_id, set()).add(top_rule_id)


# ---------------------------------------------------------------------------
# Load distribution policy traversal
# ---------------------------------------------------------------------------


def _traverse_load_distribution_policy(
    policy_ref,
    policy_lookup: dict,
    pool_lookup: dict,
    top_rule_id: str,
    hop_prefix: str,
    pool_route_refs: dict,
    pool_rule_ids: dict,
    diags: list,
    ldp_keyword: str = "loadDistributionPolicy",
) -> None:
    """
    Resolve a loadDistributionPolicy reference and add route refs for each
    usable target's backendAddressPool.
    """
    pol_id = _norm_id(policy_ref)
    if pol_id is None:
        return
    if pol_id not in policy_lookup:
        diags.append(
            {
                "kind": "unresolved_reference",
                "scope": "traversal_edge",
                "object_id": pol_id,
                "parent_id": top_rule_id,
                "reason": "referenced_policy_not_found",
            }
        )
        return

    policy = policy_lookup[pol_id]
    targets = _get_list(policy, "load_distribution_targets") or _get_list(
        policy, "loadDistributionTargets"
    )

    for i, target in enumerate(targets):
        if target is None:
            continue
        target_name = _get_str(target, "name")
        target_key = target_name if target_name else f"index-{i}"

        pool_ref = (
            target.get("backend_address_pool")
            if isinstance(target, dict)
            else getattr(target, "backend_address_pool", None)
            or getattr(target, "backendAddressPool", None)
        )
        if pool_ref is None:
            diags.append(
                {
                    "kind": "malformed_object",
                    "scope": "load_distribution_target",
                    "object_id": None,
                    "parent_id": pol_id,
                    "reason": "missing_backend_address_pool",
                }
            )
            continue

        pool_id = _norm_id(pool_ref)
        if pool_id is None:
            diags.append(
                {
                    "kind": "malformed_object",
                    "scope": "load_distribution_target",
                    "object_id": None,
                    "parent_id": pol_id,
                    "reason": "missing_subresource_id",
                }
            )
            continue
        if pool_id not in pool_lookup:
            diags.append(
                {
                    "kind": "unresolved_reference",
                    "scope": "traversal_edge",
                    "object_id": pool_id,
                    "parent_id": pol_id,
                    "reason": "referenced_pool_not_found",
                }
            )
            continue

        hop = f"{hop_prefix}{ldp_keyword}:{pol_id}:target:{target_key}"
        route_id = f"{top_rule_id}::{hop}::{pool_id}"
        _record_pool_route(
            pool_id=pool_id,
            top_rule_id=top_rule_id,
            route_id=route_id,
            pool_route_refs=pool_route_refs,
            pool_rule_ids=pool_rule_ids,
        )


# ---------------------------------------------------------------------------
# URL path map traversal
# ---------------------------------------------------------------------------


def _traverse_url_path_map(
    path_map_ref,
    path_map_lookup: dict,
    policy_lookup: dict,
    pool_lookup: dict,
    top_rule_id: str,
    pool_route_refs: dict,
    pool_rule_ids: dict,
    diags: list,
) -> None:
    """Traverse a urlPathMap and register route refs for all reachable backend pools."""
    map_id = _norm_id(path_map_ref)
    if map_id is None:
        return
    if map_id not in path_map_lookup:
        diags.append(
            {
                "kind": "unresolved_reference",
                "scope": "url_path_map",
                "object_id": map_id,
                "parent_id": top_rule_id,
                "reason": "referenced_url_path_map_not_found",
            }
        )
        return

    pm = path_map_lookup[map_id]

    # Default backend pool
    default_pool_ref = (
        pm.get("default_backend_address_pool")
        if isinstance(pm, dict)
        else getattr(pm, "default_backend_address_pool", None)
        or getattr(pm, "defaultBackendAddressPool", None)
    )
    if default_pool_ref is not None:
        pool_id = _norm_id(default_pool_ref)
        if pool_id is None:
            diags.append(
                {
                    "kind": "malformed_object",
                    "scope": "url_path_map",
                    "object_id": map_id,
                    "parent_id": top_rule_id,
                    "reason": "missing_subresource_id",
                }
            )
        elif pool_id not in pool_lookup:
            diags.append(
                {
                    "kind": "unresolved_reference",
                    "scope": "traversal_edge",
                    "object_id": pool_id,
                    "parent_id": map_id,
                    "reason": "referenced_pool_not_found",
                }
            )
        else:
            route_id = f"{top_rule_id}::urlPathMap:{map_id}:default::{pool_id}"
            _record_pool_route(
                pool_id=pool_id,
                top_rule_id=top_rule_id,
                route_id=route_id,
                pool_route_refs=pool_route_refs,
                pool_rule_ids=pool_rule_ids,
            )

    # Default load distribution policy
    default_pol_ref = (
        pm.get("default_load_distribution_policy")
        if isinstance(pm, dict)
        else getattr(pm, "default_load_distribution_policy", None)
        or getattr(pm, "defaultLoadDistributionPolicy", None)
    )
    if default_pol_ref is not None:
        _traverse_load_distribution_policy(
            default_pol_ref,
            policy_lookup,
            pool_lookup,
            top_rule_id,
            f"urlPathMap:{map_id}:default",
            pool_route_refs,
            pool_rule_ids,
            diags,
            ldp_keyword="LoadDistributionPolicy",  # spec §4 canonical
        )

    # Path rules
    path_rules = _get_list(pm, "path_rules") or _get_list(pm, "pathRules")
    for i, pr in enumerate(path_rules):
        if pr is None:
            continue
        pr_name = _get_str(pr, "name")
        pr_key = pr_name if pr_name else f"index-{i}"

        # Path rule direct pool
        pr_pool_ref = (
            pr.get("backend_address_pool")
            if isinstance(pr, dict)
            else getattr(pr, "backend_address_pool", None)
            or getattr(pr, "backendAddressPool", None)
        )
        if pr_pool_ref is not None:
            pool_id = _norm_id(pr_pool_ref)
            if pool_id is None:
                diags.append(
                    {
                        "kind": "malformed_object",
                        "scope": "path_rule",
                        "object_id": None,
                        "parent_id": map_id,
                        "reason": "missing_subresource_id",
                    }
                )
            elif pool_id not in pool_lookup:
                diags.append(
                    {
                        "kind": "unresolved_reference",
                        "scope": "traversal_edge",
                        "object_id": pool_id,
                        "parent_id": map_id,
                        "reason": "referenced_pool_not_found",
                    }
                )
            else:
                route_id = f"{top_rule_id}::urlPathMap:{map_id}:pathRule:{pr_key}::{pool_id}"
                _record_pool_route(
                    pool_id=pool_id,
                    top_rule_id=top_rule_id,
                    route_id=route_id,
                    pool_route_refs=pool_route_refs,
                    pool_rule_ids=pool_rule_ids,
                )

        # Path rule load distribution policy
        pr_pol_ref = (
            pr.get("load_distribution_policy")
            if isinstance(pr, dict)
            else getattr(pr, "load_distribution_policy", None)
            or getattr(pr, "loadDistributionPolicy", None)
        )
        if pr_pol_ref is not None:
            _traverse_load_distribution_policy(
                pr_pol_ref,
                policy_lookup,
                pool_lookup,
                top_rule_id,
                f"urlPathMap:{map_id}:pathRule:{pr_key}:",
                pool_route_refs,
                pool_rule_ids,
                diags,
            )


# ---------------------------------------------------------------------------
# Top-level rule traversal
# ---------------------------------------------------------------------------


def _traverse_gateway(
    gw,
    gw_id: str,
    gw_name: Optional[str],
    region: Optional[str],
    subscription_id: str,
) -> List[Finding]:
    """
    Normalize and traverse one Application Gateway. Returns all findings.
    """
    gateway_diags: list = []

    # --- Normalize top-level collections ---
    pools_raw = _get_list(gw, "backend_address_pools") or _get_list(gw, "backendAddressPools")
    rrr_raw = _get_list(gw, "request_routing_rules") or _get_list(gw, "requestRoutingRules")
    rr_raw = _get_list(gw, "routing_rules") or _get_list(gw, "routingRules")
    upm_raw = _get_list(gw, "url_path_maps") or _get_list(gw, "urlPathMaps")
    ldp_raw = _get_list(gw, "load_distribution_policies") or _get_list(
        gw, "loadDistributionPolicies"
    )

    # --- Build lookup tables ---
    pool_lookup, pool_diags = _build_pool_lookup(pools_raw)
    gateway_diags.extend(pool_diags)

    path_map_lookup, pm_diags = _build_path_map_lookup(upm_raw, gw_id)
    gateway_diags.extend(pm_diags)

    policy_lookup, pol_diags = _build_policy_lookup(ldp_raw, gw_id)
    gateway_diags.extend(pol_diags)

    # --- Collect top-level rules (requestRoutingRules + routingRules), deduped by id ---
    top_rules_by_id: dict = {}
    for coll_name, rules_raw in [
        ("requestRoutingRules", rrr_raw),
        ("routingRules", rr_raw),
    ]:
        for rule in rules_raw:
            if rule is None:
                continue
            rule_id = _norm_id(rule)
            if rule_id is None:
                name = _get_str(rule, "name")
                if name:
                    rule_id = f"{gw_id}/{coll_name.lower()}/{name}".lower()
                else:
                    gateway_diags.append(
                        {
                            "kind": "malformed_object",
                            "scope": "top_level_rule",
                            "object_id": None,
                            "parent_id": gw_id,
                            "reason": "missing_name_and_id",
                        }
                    )
                    continue
            if rule_id not in top_rules_by_id:
                top_rules_by_id[rule_id] = rule

    # --- Traverse each top-level rule ---
    # pool_id -> set of formatted route-id strings that reach it
    pool_route_refs: Dict[str, set] = {}
    pool_rule_ids: Dict[str, set] = {}
    rule_diags_by_id: Dict[str, list] = {}

    for top_rule_id, rule in top_rules_by_id.items():
        rule_diags: list = []

        # Determine rule_type
        rule_type = (
            rule.get("rule_type")
            if isinstance(rule, dict)
            else getattr(rule, "rule_type", None) or getattr(rule, "ruleType", None)
        )
        if isinstance(rule_type, str):
            rule_type = rule_type.strip()

        # Determine path-based status
        url_path_map_ref = (
            rule.get("url_path_map")
            if isinstance(rule, dict)
            else getattr(rule, "url_path_map", None) or getattr(rule, "urlPathMap", None)
        )
        url_path_map_id = _norm_id(url_path_map_ref)

        # urlPathMap ref present but has no usable id — malformed subresource
        if url_path_map_ref is not None and url_path_map_id is None:
            rule_diags.append(
                {
                    "kind": "malformed_object",
                    "scope": "top_level_rule",
                    "object_id": None,
                    "parent_id": top_rule_id,
                    "reason": "missing_subresource_id",
                }
            )

        is_path_based = rule_type == "PathBasedRouting"
        if not is_path_based and url_path_map_id is not None:
            # urlPathMap present but ruleType not PathBasedRouting — inconsistency
            is_path_based = True
            rule_diags.append(
                {
                    "kind": "unsupported_inconsistent_rule_shape",
                    "scope": "top_level_rule",
                    "object_id": top_rule_id,
                    "parent_id": gw_id,
                    "reason": "url_path_map_present_without_pathbased_ruletype",
                }
            )

        # Check redirect-only
        redirect_ref = (
            rule.get("redirect_configuration")
            if isinstance(rule, dict)
            else getattr(rule, "redirect_configuration", None)
            or getattr(rule, "redirectConfiguration", None)
        )
        direct_pool_ref = (
            rule.get("backend_address_pool")
            if isinstance(rule, dict)
            else getattr(rule, "backend_address_pool", None)
            or getattr(rule, "backendAddressPool", None)
        )
        ldp_ref = (
            rule.get("load_distribution_policy")
            if isinstance(rule, dict)
            else getattr(rule, "load_distribution_policy", None)
            or getattr(rule, "loadDistributionPolicy", None)
        )

        # Redirect presence: spec §6 — presence of the field is sufficient; a malformed
        # (non-null, non-resolvable) redirectConfiguration ref still counts as present.
        redirect_present = redirect_ref is not None
        if redirect_present and _norm_id(redirect_ref) is None:
            rule_diags.append(
                {
                    "kind": "malformed_object",
                    "scope": "top_level_rule",
                    "object_id": None,
                    "parent_id": top_rule_id,
                    "reason": "missing_subresource_id",
                }
            )
        no_backend_paths = (
            _norm_id(direct_pool_ref) is None
            and url_path_map_id is None
            and _norm_id(ldp_ref) is None
        )
        if redirect_present and no_backend_paths:
            continue  # redirect-only rule — skip

        # --- Independent backend-selection paths ---

        # 1. Direct backendAddressPool
        if direct_pool_ref is not None:
            pool_id = _norm_id(direct_pool_ref)
            if pool_id is None:
                rule_diags.append(
                    {
                        "kind": "malformed_object",
                        "scope": "top_level_rule",
                        "object_id": None,
                        "parent_id": top_rule_id,
                        "reason": "missing_subresource_id",
                    }
                )
            elif pool_id not in pool_lookup:
                rule_diags.append(
                    {
                        "kind": "unresolved_reference",
                        "scope": "traversal_edge",
                        "object_id": pool_id,
                        "parent_id": top_rule_id,
                        "reason": "referenced_pool_not_found",
                    }
                )
            else:
                route_id = f"{top_rule_id}::direct::{pool_id}"
                _record_pool_route(
                    pool_id=pool_id,
                    top_rule_id=top_rule_id,
                    route_id=route_id,
                    pool_route_refs=pool_route_refs,
                    pool_rule_ids=pool_rule_ids,
                )

        # 2. Direct loadDistributionPolicy
        if ldp_ref is not None:
            if _norm_id(ldp_ref) is None:
                rule_diags.append(
                    {
                        "kind": "malformed_object",
                        "scope": "top_level_rule",
                        "object_id": None,
                        "parent_id": top_rule_id,
                        "reason": "missing_subresource_id",
                    }
                )
            else:
                _traverse_load_distribution_policy(
                    ldp_ref,
                    policy_lookup,
                    pool_lookup,
                    top_rule_id,
                    "",
                    pool_route_refs,
                    pool_rule_ids,
                    rule_diags,
                )

        # 3. urlPathMap (path-based)
        if is_path_based and url_path_map_id is not None:
            _traverse_url_path_map(
                url_path_map_ref,
                path_map_lookup,
                policy_lookup,
                pool_lookup,
                top_rule_id,
                pool_route_refs,
                pool_rule_ids,
                rule_diags,
            )

        if rule_diags:
            rule_diags_by_id[top_rule_id] = rule_diags

    # --- Evaluate each pool ---
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    # Build signals_not_checked: blind-spot strings + structured diagnostic dicts
    # (spec §5 diagnostics contract requires minimum structured shape)
    def _diag_key(diag) -> tuple:
        if isinstance(diag, dict):
            return (
                diag.get("kind"),
                diag.get("scope"),
                diag.get("object_id"),
                diag.get("parent_id"),
                diag.get("reason"),
            )
        return ("text", diag)

    def _build_snc(pool_id: str, contributing_rule_ids: set) -> list:
        snc: list = list(_BLIND_SPOTS)
        seen = {_diag_key(item) for item in snc}

        for diag in gateway_diags:
            if diag.get("object_id") != pool_id and diag.get("parent_id") != pool_id:
                continue
            key = _diag_key(diag)
            if key in seen:
                continue
            snc.append(diag)
            seen.add(key)

        for rule_id in sorted(contributing_rule_ids):
            for diag in rule_diags_by_id.get(rule_id, []):
                key = _diag_key(diag)
                if key in seen:
                    continue
                snc.append(diag)
                seen.add(key)

        return snc

    for pool_id, pool in pool_lookup.items():
        refs = pool_route_refs.get(pool_id, set())
        contributing_rule_ids = pool_rule_ids.get(pool_id, set())
        referenced_by_active_routes = len(refs) > 0

        # EXCLUSION: not reached by active routes
        if not referenced_by_active_routes:
            continue

        # EXCLUSION: has targets
        if pool["backend_target_count"] > 0:
            continue

        # EMIT
        referencing_route_ids = sorted(refs)

        evidence = Evidence(
            signals_used=[
                f"Backend pool {pool['backend_pool_name'] or pool_id!r} has "
                f"backend_target_count == 0 per management-plane configuration",
                f"Pool is reachable from {len(referencing_route_ids)} active "
                f"routing path(s): {referencing_route_ids}",
            ],
            signals_not_checked=_build_snc(pool_id, contributing_rule_ids),
            time_window=None,
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.application_gateway.no_backends",
                resource_type="azure.application_gateway",
                resource_id=pool_id,
                region=region,
                title=_FINDING_TITLE,
                summary=(
                    f"Application Gateway '{gw_name or gw_id}' has an active routing path "
                    f"that points to backend pool "
                    f"'{pool['backend_pool_name'] or pool_id}' which has no explicit "
                    f"backend targets configured"
                ),
                reason=_FINDING_REASON,
                risk=RiskLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                estimated_monthly_cost_usd=None,
                evidence=evidence,
                details={
                    "evaluation_path": _EVALUATION_PATH,
                    "application_gateway_id": gw_id,
                    "application_gateway_name": gw_name,
                    "region": region,
                    "backend_pool_id": pool_id,
                    "backend_pool_name": pool["backend_pool_name"],
                    "backend_target_count": 0,
                    "referencing_route_ids": referencing_route_ids,
                    "backend_addresses": pool["backend_addresses"],
                    "legacy_backend_ip_configurations": pool["legacy_backend_ip_configurations"],
                    "subscription_id": subscription_id,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def find_app_gateway_no_backends(
    *,
    subscription_id: str,
    credential,
    region_filter: Optional[str] = None,
    client=None,
) -> List[Finding]:
    """
    Find Azure Application Gateways with active routing paths pointing to
    backend pools with no explicit backend targets.

    IAM permissions:
    - Microsoft.Network/applicationGateways/read
    """
    net_client = client or NetworkManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    try:
        gateways = list(net_client.application_gateways.list_all())
    except HttpResponseError as exc:
        if exc.status_code == 403:
            raise PermissionError(
                "Missing required permission: Microsoft.Network/applicationGateways/read"
            ) from exc
        raise

    findings: List[Finding] = []

    for gw in gateways:
        gw_id = _norm_id(gw)
        if gw_id is None:
            continue  # SKIP: malformed gateway (no id)

        gw_name = _get_str(gw, "name")
        region = _get_str(gw, "location")

        if region_filter and region != region_filter:
            continue

        gw_findings = _traverse_gateway(gw, gw_id, gw_name, region, subscription_id)
        findings.extend(gw_findings)

    return findings
