"""
Spec-driven tests for azure.application_gateway.no_backends rule.

Spec: docs/specs/azure/app_gateway_no_backends.md

Detection intent:
    An Application Gateway backend pool is in scope for a finding when:
      1. It is reachable from at least one active top-level routing rule
         (requestRoutingRules OR routingRules), and
      2. backend_target_count == 0  (no backendAddresses AND no
         backendIPConfigurations in the management-plane configuration).

Exclusions enforced by the rule:
    - pool not reached by any active routing rule
    - pool with backend_target_count > 0
    - redirect-only rules (redirectConfiguration present, no pool/urlPathMap/LDP)
    - standalone urlPathMaps / loadDistributionPolicies not referenced by a rule
    - malformed / unresolved objects → diagnostic only, not finding
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import HttpResponseError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.azure.rules.app_gateway_no_backends import (
    _norm_id,
    _normalize_pool,
    _traverse_gateway,
    find_app_gateway_no_backends,
)

# ---------------------------------------------------------------------------
# Shared ARM-id constants
# ---------------------------------------------------------------------------

SUB = "sub-1"
GW_BASE = (
    f"/subscriptions/{SUB}/resourceGroups/rg/providers"
    "/Microsoft.Network/applicationGateways/gw-1"
)
GW_ID = GW_BASE.lower()
GW_NAME = "gw-1"
REGION = "eastus"


def _pool_id(name: str) -> str:
    return f"{GW_BASE}/backendAddressPools/{name}".lower()


def _rule_id(name: str) -> str:
    return f"{GW_BASE}/requestRoutingRules/{name}".lower()


def _routing_rule_id(name: str) -> str:
    return f"{GW_BASE}/routingRules/{name}".lower()


def _path_map_id(name: str) -> str:
    return f"{GW_BASE}/urlPathMaps/{name}".lower()


def _policy_id(name: str) -> str:
    return f"{GW_BASE}/loadDistributionPolicies/{name}".lower()


# ---------------------------------------------------------------------------
# Object builders (SimpleNamespace mimics the Azure SDK model shape)
# ---------------------------------------------------------------------------

def _ns(**kw):
    return SimpleNamespace(**kw)


def _subref(id_str: str):
    """Minimal SubResource reference with an .id attribute."""
    return _ns(id=id_str)


def _make_pool(name, addresses=None, ip_configs=None):
    return _ns(
        id=_pool_id(name),
        name=name,
        backend_addresses=addresses if addresses is not None else [],
        backend_ip_configurations=ip_configs if ip_configs is not None else [],
    )


def _make_rule(
    name,
    pool_ref=None,
    ldp_ref=None,
    redirect_ref=None,
    rule_type="Basic",
    url_path_map_ref=None,
):
    return _ns(
        id=_rule_id(name),
        name=name,
        rule_type=rule_type,
        backend_address_pool=pool_ref,
        load_distribution_policy=ldp_ref,
        redirect_configuration=redirect_ref,
        url_path_map=url_path_map_ref,
    )


def _make_path_map(name, default_pool_ref=None, default_pol_ref=None, path_rules=None):
    return _ns(
        id=_path_map_id(name),
        name=name,
        default_backend_address_pool=default_pool_ref,
        default_load_distribution_policy=default_pol_ref,
        path_rules=path_rules if path_rules is not None else [],
    )


def _make_path_rule(name, pool_ref=None, pol_ref=None):
    return _ns(
        name=name,
        backend_address_pool=pool_ref,
        load_distribution_policy=pol_ref,
    )


def _make_policy(name, targets=None):
    return _ns(
        id=_policy_id(name),
        name=name,
        load_distribution_targets=targets if targets is not None else [],
    )


def _make_target(pool_ref, name=None):
    return _ns(name=name, backend_address_pool=pool_ref)


def _make_gateway(
    name=GW_NAME,
    pools=None,
    rules=None,
    routing_rules=None,
    path_maps=None,
    policies=None,
    location=REGION,
):
    return _ns(
        id=f"/subscriptions/{SUB}/resourceGroups/rg/providers"
           f"/Microsoft.Network/applicationGateways/{name}",
        name=name,
        location=location,
        backend_address_pools=pools if pools is not None else [],
        request_routing_rules=rules if rules is not None else [],
        routing_rules=routing_rules if routing_rules is not None else [],
        url_path_maps=path_maps if path_maps is not None else [],
        load_distribution_policies=policies if policies is not None else [],
    )


def _make_client(gateways):
    client = MagicMock()
    client.application_gateways.list_all.return_value = gateways
    return client


# ---------------------------------------------------------------------------
# TestMustEmit — one finding per (gateway, active-route, empty-pool) pair
# ---------------------------------------------------------------------------

class TestMustEmit:
    def test_direct_route_to_empty_pool(self):
        """Basic rule with backendAddressPool → empty pool → EMIT."""
        pool = _make_pool("pool-empty")
        rule = _make_rule("rule-1", pool_ref=_subref(_pool_id("pool-empty")))
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        f = findings[0]
        assert f.details["backend_pool_id"] == _pool_id("pool-empty")
        assert f.details["backend_target_count"] == 0

    def test_url_path_map_default_pool_empty(self):
        """PathBasedRouting → urlPathMap default backend pool is empty → EMIT."""
        pool = _make_pool("pool-default")
        pm = _make_path_map(
            "map-1",
            default_pool_ref=_subref(_pool_id("pool-default")),
        )
        rule = _make_rule(
            "rule-1",
            rule_type="PathBasedRouting",
            url_path_map_ref=_subref(_path_map_id("map-1")),
        )
        gw = _make_gateway(pools=[pool], rules=[rule], path_maps=[pm])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        assert findings[0].details["backend_pool_id"] == _pool_id("pool-default")

    def test_url_path_map_path_rule_pool_empty(self):
        """PathBasedRouting → urlPathMap pathRule backendAddressPool is empty → EMIT."""
        pool = _make_pool("pool-pr")
        pr = _make_path_rule("pr-1", pool_ref=_subref(_pool_id("pool-pr")))
        pm = _make_path_map("map-1", path_rules=[pr])
        rule = _make_rule(
            "rule-1",
            rule_type="PathBasedRouting",
            url_path_map_ref=_subref(_path_map_id("map-1")),
        )
        gw = _make_gateway(pools=[pool], rules=[rule], path_maps=[pm])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        assert findings[0].details["backend_pool_id"] == _pool_id("pool-pr")

    def test_load_distribution_policy_target_empty_pool(self):
        """Rule with LDP → target points to empty pool → EMIT."""
        pool = _make_pool("pool-ldp")
        target = _make_target(
            pool_ref=_subref(_pool_id("pool-ldp")),
            name="target-1",
        )
        policy = _make_policy("policy-1", targets=[target])
        rule = _make_rule("rule-1", ldp_ref=_subref(_policy_id("policy-1")))
        gw = _make_gateway(pools=[pool], rules=[rule], policies=[policy])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        assert findings[0].details["backend_pool_id"] == _pool_id("pool-ldp")

    def test_path_based_rule_via_default_ldp(self):
        """PathBasedRouting → urlPathMap defaultLoadDistributionPolicy → empty pool → EMIT."""
        pool = _make_pool("pool-ldp-default")
        target = _make_target(
            pool_ref=_subref(_pool_id("pool-ldp-default")),
            name="t-1",
        )
        policy = _make_policy("policy-1", targets=[target])
        pm = _make_path_map(
            "map-1",
            default_pol_ref=_subref(_policy_id("policy-1")),
        )
        rule = _make_rule(
            "rule-1",
            rule_type="PathBasedRouting",
            url_path_map_ref=_subref(_path_map_id("map-1")),
        )
        gw = _make_gateway(pools=[pool], rules=[rule], path_maps=[pm], policies=[policy])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        assert findings[0].details["backend_pool_id"] == _pool_id("pool-ldp-default")

    def test_one_finding_per_pool_not_per_route(self):
        """Two routing rules pointing to the same empty pool → exactly ONE finding."""
        pool = _make_pool("pool-shared")
        rule1 = _make_rule("rule-1", pool_ref=_subref(_pool_id("pool-shared")))
        rule2 = _make_rule("rule-2", pool_ref=_subref(_pool_id("pool-shared")))
        gw = _make_gateway(pools=[pool], rules=[rule1, rule2])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        # Both route-ids must appear in referencing_route_ids
        route_ids = findings[0].details["referencing_route_ids"]
        assert any("rule-1" in r for r in route_ids)
        assert any("rule-2" in r for r in route_ids)

    def test_multiple_empty_pools_reached_by_routes(self):
        """Two distinct empty pools each reached by their own rule → TWO findings."""
        pool_a = _make_pool("pool-a")
        pool_b = _make_pool("pool-b")
        rule_a = _make_rule("rule-a", pool_ref=_subref(_pool_id("pool-a")))
        rule_b = _make_rule("rule-b", pool_ref=_subref(_pool_id("pool-b")))
        gw = _make_gateway(pools=[pool_a, pool_b], rules=[rule_a, rule_b])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 2
        found_pool_ids = {f.details["backend_pool_id"] for f in findings}
        assert _pool_id("pool-a") in found_pool_ids
        assert _pool_id("pool-b") in found_pool_ids

    def test_routingRules_collection_also_traversed(self):
        """Pools reachable from routingRules (not requestRoutingRules) must also be flagged."""
        pool = _make_pool("pool-rr")
        routing_rule = _ns(
            id=_routing_rule_id("rr-1"),
            name="rr-1",
            rule_type="Basic",
            backend_address_pool=_subref(_pool_id("pool-rr")),
            load_distribution_policy=None,
            redirect_configuration=None,
            url_path_map=None,
        )
        gw = _make_gateway(pools=[pool], routing_rules=[routing_rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        assert findings[0].details["backend_pool_id"] == _pool_id("pool-rr")


# ---------------------------------------------------------------------------
# TestMustSkip — scenarios that must produce zero findings
# ---------------------------------------------------------------------------

class TestMustSkip:
    def test_orphaned_pool_not_reached_by_any_route(self):
        """Pool defined in the gateway but unreachable from any routing rule → SKIP."""
        pool = _make_pool("pool-orphaned")
        # No rules reference this pool
        gw = _make_gateway(pools=[pool], rules=[])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert findings == []

    def test_standalone_url_path_map_not_referenced_by_rule(self):
        """urlPathMap with an empty default pool defined but not referenced by any rule → SKIP."""
        pool = _make_pool("pool-pm-default")
        pm = _make_path_map(
            "map-1",
            default_pool_ref=_subref(_pool_id("pool-pm-default")),
        )
        # No rule references this path map
        gw = _make_gateway(pools=[pool], path_maps=[pm])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert findings == []

    def test_standalone_load_distribution_policy_not_referenced(self):
        """LDP defined but no rule references it → SKIP."""
        pool = _make_pool("pool-ldp-orphaned")
        target = _make_target(pool_ref=_subref(_pool_id("pool-ldp-orphaned")), name="t-1")
        policy = _make_policy("policy-1", targets=[target])
        # No rule references this policy
        gw = _make_gateway(pools=[pool], policies=[policy])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert findings == []

    def test_pool_with_backend_addresses_not_flagged(self):
        """Pool reached by an active rule but backendAddresses is non-empty → SKIP."""
        pool = _make_pool("pool-populated", addresses=[{"fqdn": "backend.example.com"}])
        rule = _make_rule("rule-1", pool_ref=_subref(_pool_id("pool-populated")))
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert findings == []

    def test_pool_with_legacy_ip_configurations_not_flagged(self):
        """Pool with non-empty backendIPConfigurations has targets → SKIP."""
        nic_ref = _ns(
            id="/subscriptions/sub/resourceGroups/rg/providers"
               "/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ip1"
        )
        pool = _make_pool("pool-nic", ip_configs=[nic_ref])
        rule = _make_rule("rule-1", pool_ref=_subref(_pool_id("pool-nic")))
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert findings == []

    def test_redirect_only_rule_is_skipped(self):
        """Rule has redirectConfiguration and no backend selection path → SKIP."""
        pool = _make_pool("pool-redir")
        redirect_ref = _subref(
            f"{GW_BASE}/redirectConfigurations/redir-1".lower()
        )
        rule = _ns(
            id=_rule_id("rule-redir"),
            name="rule-redir",
            rule_type="Basic",
            backend_address_pool=None,
            load_distribution_policy=None,
            redirect_configuration=redirect_ref,
            url_path_map=None,
        )
        # Pool is defined but the only rule is redirect-only → pool unreachable
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert findings == []

    def test_empty_pool_reachable_only_if_other_pool_has_targets(self):
        """
        Gateway with two pools: one empty (reached by rule-1) and one populated
        (reached by rule-2). Only the empty pool should be flagged, not suppressed.
        Verifies that populated pool never gets a finding.
        """
        pool_empty = _make_pool("pool-empty")
        pool_full = _make_pool("pool-full", addresses=[{"fqdn": "be.example.com"}])
        rule1 = _make_rule("rule-1", pool_ref=_subref(_pool_id("pool-empty")))
        rule2 = _make_rule("rule-2", pool_ref=_subref(_pool_id("pool-full")))
        gw = _make_gateway(pools=[pool_empty, pool_full], rules=[rule1, rule2])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        assert findings[0].details["backend_pool_id"] == _pool_id("pool-empty")

    def test_empty_gateway_no_findings(self):
        """Gateway with no pools and no rules → no findings."""
        gw = _make_gateway()
        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert findings == []

    def test_ldp_target_pool_has_targets_skipped(self):
        """Rule → LDP → target → pool with backend addresses → SKIP."""
        pool = _make_pool("pool-ldp-full", addresses=[{"ipAddress": "10.0.0.5"}])
        target = _make_target(pool_ref=_subref(_pool_id("pool-ldp-full")), name="t-1")
        policy = _make_policy("policy-1", targets=[target])
        rule = _make_rule("rule-1", ldp_ref=_subref(_policy_id("policy-1")))
        gw = _make_gateway(pools=[pool], rules=[rule], policies=[policy])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert findings == []

    def test_duplicate_rule_ids_deduplicated(self):
        """If requestRoutingRules and routingRules contain the same rule id, only traverse once."""
        pool = _make_pool("pool-dedup")
        # Construct rule with same normalized id in both collections
        rule_rrr = _ns(
            id=_rule_id("rule-same"),
            name="rule-same",
            rule_type="Basic",
            backend_address_pool=_subref(_pool_id("pool-dedup")),
            load_distribution_policy=None,
            redirect_configuration=None,
            url_path_map=None,
        )
        rule_rr = _ns(
            id=_rule_id("rule-same"),
            name="rule-same",
            rule_type="Basic",
            backend_address_pool=_subref(_pool_id("pool-dedup")),
            load_distribution_policy=None,
            redirect_configuration=None,
            url_path_map=None,
        )
        gw = _make_gateway(pools=[pool], rules=[rule_rrr], routing_rules=[rule_rr])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        # One finding, one route-id (deduplicated traversal)
        assert len(findings) == 1
        assert len(findings[0].details["referencing_route_ids"]) == 1


# ---------------------------------------------------------------------------
# TestMustFail — public API surfaces errors correctly
# ---------------------------------------------------------------------------

class TestMustFail:
    def test_403_on_list_all_raises_permission_error(self):
        """list_all returning 403 must surface as PermissionError, not HttpResponseError."""
        exc = HttpResponseError(message="AuthorizationFailed")
        exc.status_code = 403
        client = MagicMock()
        client.application_gateways.list_all.side_effect = exc

        with pytest.raises(PermissionError, match="applicationGateways/read"):
            find_app_gateway_no_backends(
                subscription_id=SUB,
                credential=None,
                client=client,
            )

    def test_non_403_http_error_propagates(self):
        """Non-403 HttpResponseError (e.g., 500) must propagate as-is."""
        exc = HttpResponseError(message="InternalServerError")
        exc.status_code = 500
        client = MagicMock()
        client.application_gateways.list_all.side_effect = exc

        with pytest.raises(HttpResponseError):
            find_app_gateway_no_backends(
                subscription_id=SUB,
                credential=None,
                client=client,
            )

    def test_empty_subscription_returns_empty_list(self):
        """list_all returning [] must produce [] findings, no exception."""
        client = _make_client([])
        findings = find_app_gateway_no_backends(
            subscription_id=SUB,
            credential=None,
            client=client,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# TestNormalization — _norm_id and _normalize_pool
# ---------------------------------------------------------------------------

class TestNormalization:
    def test_norm_id_from_string(self):
        raw = "/subscriptions/SUB/resourceGroups/RG/providers/Microsoft.Network/applicationGateways/GW"
        assert _norm_id(raw) == raw.lower()

    def test_norm_id_from_dict(self):
        raw = {"id": "/subscriptions/SUB/foo"}
        assert _norm_id(raw) == "/subscriptions/sub/foo"

    def test_norm_id_from_sdk_object(self):
        obj = _ns(id="/Subscriptions/SUB/foo")
        assert _norm_id(obj) == "/subscriptions/sub/foo"

    def test_norm_id_none_input(self):
        assert _norm_id(None) is None

    def test_norm_id_empty_string(self):
        assert _norm_id("") is None
        assert _norm_id("   ") is None

    def test_norm_id_dict_missing_id_key(self):
        assert _norm_id({"name": "foo"}) is None

    def test_norm_id_sdk_object_missing_id_attr(self):
        obj = _ns(name="foo")
        assert _norm_id(obj) is None

    def test_normalize_pool_name_from_id_when_name_absent(self):
        """When pool has no name attribute, derive it from the last ARM segment."""
        pool = _ns(
            id=_pool_id("my-pool"),
            name=None,
            backend_addresses=[],
            backend_ip_configurations=[],
        )
        norm = _normalize_pool(pool)
        assert norm is not None
        assert norm["backend_pool_name"] == "my-pool"

    def test_normalize_pool_returns_none_for_missing_id(self):
        pool = _ns(
            id=None,
            name="pool-no-id",
            backend_addresses=[],
            backend_ip_configurations=[],
        )
        assert _normalize_pool(pool) is None

    def test_normalize_pool_backend_target_count(self):
        pool = _ns(
            id=_pool_id("pool-mixed"),
            name="pool-mixed",
            backend_addresses=[{"fqdn": "a.example.com"}, {"fqdn": "b.example.com"}],
            backend_ip_configurations=[_ns(id="nic-cfg")],
        )
        norm = _normalize_pool(pool)
        assert norm["backend_target_count"] == 3

    def test_synthetic_rule_id_from_name_when_id_absent(self):
        """If a routing rule has no .id but has .name, a synthetic id must be generated."""
        pool = _make_pool("pool-x")
        rule = _ns(
            id=None,
            name="rule-synthetic",
            rule_type="Basic",
            backend_address_pool=_subref(_pool_id("pool-x")),
            load_distribution_policy=None,
            redirect_configuration=None,
            url_path_map=None,
        )
        gw = _make_gateway(pools=[pool], rules=[rule])
        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        route_ids = findings[0].details["referencing_route_ids"]
        assert len(route_ids) == 1
        # The synthetic rule id must contain the rule name
        assert "rule-synthetic" in route_ids[0]

    def test_case_insensitive_id_matching(self):
        """Mixed-case ARM ids must normalize and match correctly."""
        pool_id_raw = f"{GW_BASE}/backendAddressPools/Pool-Upper"
        pool = _ns(
            id=pool_id_raw,
            name="Pool-Upper",
            backend_addresses=[],
            backend_ip_configurations=[],
        )
        # Reference with different casing
        rule = _make_rule("rule-1", pool_ref=_ns(id=pool_id_raw.upper()))
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestRouteIdFormat — canonical route-id strings for each hop type
# ---------------------------------------------------------------------------

class TestRouteIdFormat:
    def test_direct_route_id_format(self):
        """Direct backendAddressPool: {rule_id}::direct::{pool_id}"""
        pool = _make_pool("pool-d")
        rule = _make_rule("rule-d", pool_ref=_subref(_pool_id("pool-d")))
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1

        expected = f"{_rule_id('rule-d')}::direct::{_pool_id('pool-d')}"
        assert findings[0].details["referencing_route_ids"] == [expected]

    def test_url_path_map_default_route_id_format(self):
        """urlPathMap default pool: {rule_id}::urlPathMap:{map_id}:default::{pool_id}"""
        pool = _make_pool("pool-pm-d")
        pm = _make_path_map("map-1", default_pool_ref=_subref(_pool_id("pool-pm-d")))
        rule = _make_rule(
            "rule-pm",
            rule_type="PathBasedRouting",
            url_path_map_ref=_subref(_path_map_id("map-1")),
        )
        gw = _make_gateway(pools=[pool], rules=[rule], path_maps=[pm])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1

        mid = _path_map_id("map-1")
        rid = _rule_id("rule-pm")
        pid = _pool_id("pool-pm-d")
        expected = f"{rid}::urlPathMap:{mid}:default::{pid}"
        assert findings[0].details["referencing_route_ids"] == [expected]

    def test_url_path_map_path_rule_route_id_format(self):
        """urlPathMap pathRule pool: {rule_id}::urlPathMap:{map_id}:pathRule:{pr_name}::{pool_id}"""
        pool = _make_pool("pool-pr-f")
        pr = _make_path_rule("pr-alpha", pool_ref=_subref(_pool_id("pool-pr-f")))
        pm = _make_path_map("map-2", path_rules=[pr])
        rule = _make_rule(
            "rule-pr",
            rule_type="PathBasedRouting",
            url_path_map_ref=_subref(_path_map_id("map-2")),
        )
        gw = _make_gateway(pools=[pool], rules=[rule], path_maps=[pm])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1

        mid = _path_map_id("map-2")
        rid = _rule_id("rule-pr")
        pid = _pool_id("pool-pr-f")
        expected = f"{rid}::urlPathMap:{mid}:pathRule:pr-alpha::{pid}"
        assert findings[0].details["referencing_route_ids"] == [expected]

    def test_ldp_direct_route_id_format(self):
        """Direct LDP: {rule_id}::loadDistributionPolicy:{pol_id}:target:{target_name}::{pool_id}"""
        pool = _make_pool("pool-ldp-fmt")
        target = _make_target(pool_ref=_subref(_pool_id("pool-ldp-fmt")), name="tgt-1")
        policy = _make_policy("policy-fmt", targets=[target])
        rule = _make_rule("rule-ldp", ldp_ref=_subref(_policy_id("policy-fmt")))
        gw = _make_gateway(pools=[pool], rules=[rule], policies=[policy])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1

        pol = _policy_id("policy-fmt")
        rid = _rule_id("rule-ldp")
        pid = _pool_id("pool-ldp-fmt")
        expected = f"{rid}::loadDistributionPolicy:{pol}:target:tgt-1::{pid}"
        assert findings[0].details["referencing_route_ids"] == [expected]

    def test_url_path_map_default_ldp_route_id_format(self):
        """
        urlPathMap defaultLoadDistributionPolicy (spec §4 canonical):
        {rule_id}::urlPathMap:{map_id}:defaultLoadDistributionPolicy:{pol_id}:target:{target_key}::{pool_id}

        Note capital 'L' in defaultLoadDistributionPolicy — this is the canonical
        format mandated by the spec to distinguish the default-LDP hop from a
        pathRule-LDP hop.
        """
        pool = _make_pool("pool-def-ldp")
        target = _make_target(pool_ref=_subref(_pool_id("pool-def-ldp")), name="tgt-def")
        policy = _make_policy("policy-def", targets=[target])
        pm = _make_path_map(
            "map-def",
            default_pol_ref=_subref(_policy_id("policy-def")),
        )
        rule = _make_rule(
            "rule-def-ldp",
            rule_type="PathBasedRouting",
            url_path_map_ref=_subref(_path_map_id("map-def")),
        )
        gw = _make_gateway(pools=[pool], rules=[rule], path_maps=[pm], policies=[policy])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1

        mid = _path_map_id("map-def")
        rid = _rule_id("rule-def-ldp")
        pol = _policy_id("policy-def")
        pid = _pool_id("pool-def-ldp")
        # Capital 'L' in defaultLoadDistributionPolicy (spec §4)
        expected = f"{rid}::urlPathMap:{mid}:defaultLoadDistributionPolicy:{pol}:target:tgt-def::{pid}"
        assert findings[0].details["referencing_route_ids"] == [expected]

    def test_url_path_map_path_rule_ldp_route_id_format(self):
        """
        urlPathMap pathRule loadDistributionPolicy (spec §4 canonical):
        {rule_id}::urlPathMap:{map_id}:pathRule:{pr_key}:loadDistributionPolicy:{pol_id}:target:{target_key}::{pool_id}

        Note lowercase 'l' in loadDistributionPolicy for pathRule context.
        """
        pool = _make_pool("pool-pr-ldp")
        target = _make_target(pool_ref=_subref(_pool_id("pool-pr-ldp")), name="tgt-pr")
        policy = _make_policy("policy-pr", targets=[target])
        pr = _make_path_rule("pr-beta", pol_ref=_subref(_policy_id("policy-pr")))
        pm = _make_path_map("map-pr", path_rules=[pr])
        rule = _make_rule(
            "rule-pr-ldp",
            rule_type="PathBasedRouting",
            url_path_map_ref=_subref(_path_map_id("map-pr")),
        )
        gw = _make_gateway(pools=[pool], rules=[rule], path_maps=[pm], policies=[policy])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1

        mid = _path_map_id("map-pr")
        rid = _rule_id("rule-pr-ldp")
        pol = _policy_id("policy-pr")
        pid = _pool_id("pool-pr-ldp")
        # Lowercase 'l' in loadDistributionPolicy for pathRule context (spec §4)
        expected = f"{rid}::urlPathMap:{mid}:pathRule:pr-beta:loadDistributionPolicy:{pol}:target:tgt-pr::{pid}"
        assert findings[0].details["referencing_route_ids"] == [expected]

    def test_referencing_route_ids_are_sorted(self):
        """referencing_route_ids must be lexicographically sorted."""
        pool = _make_pool("pool-sort")
        rule_z = _make_rule("rule-z", pool_ref=_subref(_pool_id("pool-sort")))
        rule_a = _make_rule("rule-a", pool_ref=_subref(_pool_id("pool-sort")))
        rule_m = _make_rule("rule-m", pool_ref=_subref(_pool_id("pool-sort")))
        gw = _make_gateway(pools=[pool], rules=[rule_z, rule_a, rule_m])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1

        route_ids = findings[0].details["referencing_route_ids"]
        assert route_ids == sorted(route_ids)


# ---------------------------------------------------------------------------
# TestFindingShape — title, reason, risk, confidence, cost, provider fields
# ---------------------------------------------------------------------------

class TestFindingShape:
    def _get_single_finding(self):
        pool = _make_pool("pool-shape")
        rule = _make_rule("rule-shape", pool_ref=_subref(_pool_id("pool-shape")))
        gw = _make_gateway(pools=[pool], rules=[rule])
        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1
        return findings[0]

    def test_provider(self):
        assert self._get_single_finding().provider == "azure"

    def test_rule_id(self):
        assert self._get_single_finding().rule_id == "azure.application_gateway.no_backends"

    def test_resource_type(self):
        assert self._get_single_finding().resource_type == "azure.application_gateway"

    def test_title(self):
        f = self._get_single_finding()
        assert f.title == "Application Gateway active route points to empty backend pool"

    def test_reason(self):
        f = self._get_single_finding()
        assert "active Application Gateway routing path" in f.reason
        assert "backend pool" in f.reason
        assert "no explicit backend targets" in f.reason

    def test_risk_is_medium(self):
        assert self._get_single_finding().risk == RiskLevel.MEDIUM

    def test_confidence_is_high(self):
        assert self._get_single_finding().confidence == ConfidenceLevel.HIGH

    def test_estimated_monthly_cost_is_none(self):
        """Spec §9: no cost model; estimated_monthly_cost_usd must be None."""
        assert self._get_single_finding().estimated_monthly_cost_usd is None

    def test_resource_id_is_pool_id(self):
        """resource_id must be the backend pool ARM id (lower-cased)."""
        f = self._get_single_finding()
        assert f.resource_id == _pool_id("pool-shape")

    def test_region_is_set(self):
        assert self._get_single_finding().region == REGION

    def test_detected_at_is_not_none(self):
        assert self._get_single_finding().detected_at is not None


# ---------------------------------------------------------------------------
# TestEvidenceContract — details dict and Evidence fields
# ---------------------------------------------------------------------------

class TestEvidenceContract:
    def _get_finding_with_details(self):
        pool = _make_pool("pool-ev")
        rule = _make_rule("rule-ev", pool_ref=_subref(_pool_id("pool-ev")))
        gw = _make_gateway(pools=[pool], rules=[rule])
        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1
        return findings[0]

    def test_evaluation_path(self):
        f = self._get_finding_with_details()
        assert f.details["evaluation_path"] == "app-gateway-no-backends"

    def test_application_gateway_id(self):
        f = self._get_finding_with_details()
        assert f.details["application_gateway_id"] == GW_ID

    def test_backend_pool_id(self):
        f = self._get_finding_with_details()
        assert f.details["backend_pool_id"] == _pool_id("pool-ev")

    def test_backend_pool_name(self):
        f = self._get_finding_with_details()
        assert f.details["backend_pool_name"] == "pool-ev"

    def test_backend_target_count_is_zero(self):
        f = self._get_finding_with_details()
        assert f.details["backend_target_count"] == 0

    def test_referencing_route_ids_list(self):
        f = self._get_finding_with_details()
        assert isinstance(f.details["referencing_route_ids"], list)
        assert len(f.details["referencing_route_ids"]) >= 1

    def test_backend_addresses_present(self):
        f = self._get_finding_with_details()
        assert "backend_addresses" in f.details
        assert f.details["backend_addresses"] == []

    def test_legacy_backend_ip_configurations_present(self):
        f = self._get_finding_with_details()
        assert "legacy_backend_ip_configurations" in f.details
        assert f.details["legacy_backend_ip_configurations"] == []

    def test_subscription_id_present(self):
        f = self._get_finding_with_details()
        assert f.details["subscription_id"] == SUB

    def test_signals_used_mentions_pool_and_count(self):
        f = self._get_finding_with_details()
        signals = f.evidence.signals_used
        assert any("backend_target_count" in s and "== 0" in s for s in signals)

    def test_signals_not_checked_contains_blind_spots(self):
        f = self._get_finding_with_details()
        snc = f.evidence.signals_not_checked
        # Blind spots are emitted as plain strings; diagnostics are structured dicts.
        # Only check string items for blind-spot content.
        strings = [s for s in snc if isinstance(s, str)]
        assert any("Runtime backend health" in s for s in strings)
        assert any("DNS" in s or "service discovery" in s for s in strings)


# ---------------------------------------------------------------------------
# TestDiagnostics — malformed objects produce diagnostics, not findings
# ---------------------------------------------------------------------------

class TestDiagnostics:
    def test_pool_with_no_id_produces_diagnostic_not_finding(self):
        """An unrelated malformed pool should not pollute another pool's finding diagnostics."""
        pool_bad = _ns(id=None, name="pool-bad", backend_addresses=[], backend_ip_configurations=[])
        pool_good = _make_pool("pool-good")
        rule = _make_rule("rule-1", pool_ref=_subref(_pool_id("pool-good")))
        gw = _make_gateway(pools=[pool_bad, pool_good], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        # pool-good is reachable and empty → finding; pool-bad is skipped
        assert len(findings) == 1
        snc = findings[0].evidence.signals_not_checked
        assert not any(
            isinstance(s, dict) and s.get("kind") == "malformed_object" and s.get("scope") == "backend_pool"
            for s in snc
        )

    def test_unresolved_pool_reference_in_rule_produces_diagnostic(self):
        """An unrelated unresolved pool reference should not leak into another pool's finding."""
        pool = _make_pool("pool-real")
        rule_bad = _make_rule(
            "rule-bad",
            pool_ref=_subref(_pool_id("pool-does-not-exist")),
        )
        rule_good = _make_rule("rule-good", pool_ref=_subref(_pool_id("pool-real")))
        gw = _make_gateway(pools=[pool], rules=[rule_bad, rule_good])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        # Only pool-real via rule-good triggers a finding
        assert len(findings) == 1
        snc = findings[0].evidence.signals_not_checked
        assert not any(
            isinstance(s, dict) and s.get("kind") == "unresolved_reference"
            for s in snc
        )

    def test_malformed_gateway_skipped_in_public_api(self):
        """A gateway with no .id should be silently skipped; other gateways still processed."""
        pool = _make_pool("pool-ok")
        rule = _make_rule("rule-ok", pool_ref=_subref(_pool_id("pool-ok")))

        gw_bad = _ns(id=None, name=None, location=REGION)
        gw_good = _make_gateway(pools=[pool], rules=[rule])

        client = _make_client([gw_bad, gw_good])
        findings = find_app_gateway_no_backends(
            subscription_id=SUB,
            credential=None,
            client=client,
        )

        # gw_bad skipped; gw_good yields a finding
        assert len(findings) == 1

    def test_malformed_path_rule_produces_diagnostic_not_finding(self):
        """A path rule with a malformed (None) pool SubResource ref → diagnostic, no finding."""
        pool = _make_pool("pool-main")
        pr_bad = _ns(
            name="pr-bad",
            backend_address_pool=_ns(id=None),  # malformed ref
            load_distribution_policy=None,
        )
        pm = _make_path_map("map-1", path_rules=[pr_bad])
        rule = _make_rule(
            "rule-1",
            rule_type="PathBasedRouting",
            url_path_map_ref=_subref(_path_map_id("map-1")),
        )
        # pool-main is defined but not reached via any non-malformed path
        gw = _make_gateway(pools=[pool], rules=[rule], path_maps=[pm])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        # No pool is reached successfully → no finding
        assert findings == []

    def test_malformed_direct_pool_ref_produces_diagnostic(self):
        """
        A malformed direct pool ref on an unrelated top-level rule must not leak into
        another pool's finding diagnostics.
        """
        pool = _make_pool("pool-good")
        rule_malformed = _make_rule("rule-bad", pool_ref=_ns(id=None))  # SubResource with no id
        rule_good = _make_rule("rule-good", pool_ref=_subref(_pool_id("pool-good")))
        gw = _make_gateway(pools=[pool], rules=[rule_malformed, rule_good])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1  # only rule-good succeeds
        snc = findings[0].evidence.signals_not_checked
        assert not any(
            isinstance(s, dict)
            and s.get("kind") == "malformed_object"
            and s.get("scope") == "top_level_rule"
            and s.get("reason") == "missing_subresource_id"
            for s in snc
        )

    def test_malformed_direct_ldp_ref_produces_diagnostic(self):
        """
        A malformed direct loadDistributionPolicy ref on the same top-level rule that
        reaches the emitted pool must stay attached to that finding.
        """
        pool = _make_pool("pool-direct")
        rule = _make_rule(
            "rule-direct",
            pool_ref=_subref(_pool_id("pool-direct")),
            ldp_ref=_ns(id=None),
        )
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        snc = findings[0].evidence.signals_not_checked
        assert any(
            isinstance(s, dict)
            and s.get("kind") == "malformed_object"
            and s.get("scope") == "top_level_rule"
            and s.get("reason") == "missing_subresource_id"
            for s in snc
        )

    def test_malformed_url_path_map_ref_produces_diagnostic(self):
        """
        A malformed urlPathMap ref on the same top-level rule that reaches the emitted
        pool must stay attached to that finding.
        """
        pool = _make_pool("pool-pm-diag")
        rule = _ns(
            id=_rule_id("rule-pm"),
            name="rule-pm",
            rule_type="PathBasedRouting",
            backend_address_pool=_subref(_pool_id("pool-pm-diag")),
            load_distribution_policy=None,
            redirect_configuration=None,
            url_path_map=_ns(id=None),  # malformed urlPathMap ref
        )
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)

        assert len(findings) == 1
        snc = findings[0].evidence.signals_not_checked
        assert any(
            isinstance(s, dict)
            and s.get("kind") == "malformed_object"
            and s.get("scope") == "top_level_rule"
            and s.get("reason") == "missing_subresource_id"
            for s in snc
        )

    def test_synthetic_ids_are_lowercase(self):
        """Fallback synthetic ids (for objects with name but no id) must be lowercase (spec §5)."""
        pool = _make_pool("pool-synth")
        # Routing rule with no id but mixed-case name
        rule = _ns(
            id=None,
            name="RuleWithMixedCase",
            rule_type="Basic",
            backend_address_pool=_subref(_pool_id("pool-synth")),
            load_distribution_policy=None,
            redirect_configuration=None,
            url_path_map=None,
        )
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1

        route_ids = findings[0].details["referencing_route_ids"]
        assert len(route_ids) == 1
        # The synthetic rule id embedded in route_id must be all lowercase
        assert route_ids[0] == route_ids[0].lower(), (
            f"route_id contains uppercase characters: {route_ids[0]!r}"
        )

    def test_unresolved_policy_ref_scope_is_traversal_edge(self):
        """
        An unresolved loadDistributionPolicy ref on the same top-level rule that reaches
        the emitted pool must use traversal_edge scope.
        """
        pool = _make_pool("pool-no-pol")
        rule = _make_rule(
            "rule-no-pol",
            pool_ref=_subref(_pool_id("pool-no-pol")),
            ldp_ref=_subref(_policy_id("policy-missing")),
        )
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1
        snc = findings[0].evidence.signals_not_checked
        assert any(
            isinstance(s, dict)
            and s.get("kind") == "unresolved_reference"
            and s.get("scope") == "traversal_edge"
            and s.get("reason") == "referenced_policy_not_found"
            for s in snc
        )

    def test_malformed_redirect_ref_counts_as_redirect_present(self):
        """
        A rule with a redirectConfiguration that has no usable id but no backend selection
        path must still be treated as redirect-only and skipped (spec §6).
        Presence of the field is sufficient — a malformed id does not fall through.
        """
        pool = _make_pool("pool-redir-bad")
        rule = _ns(
            id=_rule_id("rule-redir-bad"),
            name="rule-redir-bad",
            rule_type="Basic",
            backend_address_pool=None,
            load_distribution_policy=None,
            redirect_configuration=_ns(id=None),  # present but malformed
            url_path_map=None,
        )
        gw = _make_gateway(pools=[pool], rules=[rule])
        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        # Rule is redirect-only (malformed ref still counts as present) → pool unreachable → no finding
        assert findings == []

    def test_malformed_redirect_ref_emits_diagnostic(self):
        """
        A malformed redirectConfiguration ref on the same top-level rule that reaches
        the emitted pool must stay attached to that finding.
        """
        pool = _make_pool("pool-redir-diag")
        rule = _ns(
            id=_rule_id("rule-redir"),
            name="rule-redir",
            rule_type="Basic",
            backend_address_pool=_subref(_pool_id("pool-redir-diag")),
            load_distribution_policy=None,
            redirect_configuration=_ns(id=None),  # present but malformed
            url_path_map=None,
        )
        gw = _make_gateway(pools=[pool], rules=[rule])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        assert len(findings) == 1

        snc = findings[0].evidence.signals_not_checked
        assert any(
            isinstance(s, dict)
            and s.get("kind") == "malformed_object"
            and s.get("scope") == "top_level_rule"
            and s.get("reason") == "missing_subresource_id"
            for s in snc
        )

    def test_unresolved_ldp_in_target_produces_diagnostic(self):
        """LDP target with pool ref that doesn't exist → diagnostic only."""
        pool = _make_pool("pool-ldp-real")
        target = _make_target(pool_ref=_subref(_pool_id("pool-ghost")), name="t-ghost")
        policy = _make_policy("policy-1", targets=[target])
        rule = _make_rule("rule-1", ldp_ref=_subref(_policy_id("policy-1")))
        # pool-ldp-real is defined but the LDP target points to pool-ghost
        gw = _make_gateway(pools=[pool], rules=[rule], policies=[policy])

        findings = _traverse_gateway(gw, GW_ID, GW_NAME, REGION, SUB)
        # pool-ldp-real unreachable (only pool-ghost is referenced, which doesn't exist in lookup)
        # pool-ghost not in pool_lookup → unresolved reference diagnostic, no finding
        assert findings == []


# ---------------------------------------------------------------------------
# TestRegionFilter — public API region_filter behaviour
# ---------------------------------------------------------------------------

class TestRegionFilter:
    def test_region_filter_excludes_other_regions(self):
        pool = _make_pool("pool-east")
        rule = _make_rule("rule-east", pool_ref=_subref(_pool_id("pool-east")))
        gw_east = _make_gateway("gw-east", pools=[pool], rules=[rule], location="eastus")

        pool2 = _make_pool("pool-west")
        rule2 = _make_rule("rule-west", pool_ref=_subref(_pool_id("pool-west")))
        gw_west = _make_gateway("gw-west", pools=[pool2], rules=[rule2], location="westus")

        client = _make_client([gw_east, gw_west])
        findings = find_app_gateway_no_backends(
            subscription_id=SUB,
            credential=None,
            region_filter="eastus",
            client=client,
        )

        assert len(findings) == 1
        assert findings[0].region == "eastus"

    def test_no_region_filter_scans_all(self):
        pool_e = _make_pool("pool-e")
        rule_e = _make_rule("rule-e", pool_ref=_subref(_pool_id("pool-e")))
        gw_east = _make_gateway("gw-east", pools=[pool_e], rules=[rule_e], location="eastus")

        pool_w = _make_pool("pool-w")
        rule_w = _make_rule("rule-w", pool_ref=_subref(_pool_id("pool-w")))
        gw_west = _make_gateway("gw-west", pools=[pool_w], rules=[rule_w], location="westus")

        client = _make_client([gw_east, gw_west])
        findings = find_app_gateway_no_backends(
            subscription_id=SUB,
            credential=None,
            client=client,
        )

        assert len(findings) == 2
