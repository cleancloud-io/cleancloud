"""
Tests for azure.load_balancer.no_backends — spec-aligned.

Covers: must-emit, must-skip, billable-rule contract, relevant-pool contract,
        membership contract, finding shape, evidence contract, region filter,
        failure behavior.
"""

from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.lb_no_backends import find_lb_no_backends

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_SUB = "sub-123"
_RG = "rg"


def _pool_arm_id(pool_name: str, lb_name: str = "lb") -> str:
    return (
        f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/"
        f"Microsoft.Network/loadBalancers/{lb_name}/backendAddressPools/{pool_name}"
    )


def _make_pool(name: str, lb_name: str = "lb", nic_backends=None, ip_backends=None):
    """Backend address pool with an ARM id and optional members."""
    return SimpleNamespace(
        id=_pool_arm_id(name, lb_name),
        backend_ip_configurations=nic_backends,
        load_balancer_backend_addresses=ip_backends,
    )


def _pool_ref(pool_name: str, lb_name: str = "lb"):
    """SubResource-style pool reference (as returned from a rule's backendAddressPool)."""
    return SimpleNamespace(id=_pool_arm_id(pool_name, lb_name))


def _make_lb_rule(pool_name: str = None, pool_names=None, lb_name: str = "lb"):
    """Load-balancing rule referencing one pool (single) or multiple pools (multi)."""
    return SimpleNamespace(
        backend_address_pool=_pool_ref(pool_name, lb_name) if pool_name else None,
        backend_address_pools=([_pool_ref(n, lb_name) for n in pool_names] if pool_names else []),
    )


def _make_outbound_rule(pool_name: str, lb_name: str = "lb"):
    """Outbound rule with a single backend pool reference."""
    return SimpleNamespace(
        backend_address_pool=_pool_ref(pool_name, lb_name),
        backend_address_pools=[],
    )


def _make_lb(
    name: str = "lb",
    sku_name: str = "Standard",
    pools=None,
    location: str = "eastus",
    tags=None,
    provisioning_state: str = "Succeeded",
    frontend_ips=None,
    lb_rules=None,
    outbound_rules=None,
    lb_id: str = None,
):
    return SimpleNamespace(
        id=(
            lb_id
            or f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/"
            f"Microsoft.Network/loadBalancers/{name}"
        ),
        name=name,
        location=location,
        sku=SimpleNamespace(name=sku_name, tier="Regional"),
        backend_address_pools=pools if pools is not None else [],
        frontend_ip_configurations=frontend_ips or [],
        load_balancing_rules=lb_rules if lb_rules is not None else [],
        outbound_rules=outbound_rules if outbound_rules is not None else [],
        provisioning_state=provisioning_state,
        tags=tags,
    )


def _run(lbs, region_filter=None):
    client = SimpleNamespace(load_balancers=SimpleNamespace(list_all=lambda: lbs))
    return find_lb_no_backends(
        subscription_id=_SUB,
        credential=None,
        region_filter=region_filter,
        client=client,
    )


# ---------------------------------------------------------------------------
# TestMustEmit — spec 14.1
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_one_lb_rule_one_empty_pool(self):
        """Standard, Succeeded, 1 LB rule → 1 empty pool → EMIT."""
        pool = _make_pool("p1")
        lb = _make_lb(
            pools=[pool],
            lb_rules=[_make_lb_rule("p1")],
        )
        findings = _run([lb])
        assert len(findings) == 1

    def test_one_outbound_rule_one_empty_pool(self):
        """Standard, Succeeded, 1 outbound rule → 1 empty pool → EMIT."""
        pool = _make_pool("p1")
        lb = _make_lb(
            pools=[pool],
            outbound_rules=[_make_outbound_rule("p1")],
        )
        findings = _run([lb])
        assert len(findings) == 1

    def test_two_lb_rules_two_distinct_empty_pools(self):
        """Two LB rules referencing two different empty pools → EMIT."""
        pool_a = _make_pool("pa")
        pool_b = _make_pool("pb")
        lb = _make_lb(
            pools=[pool_a, pool_b],
            lb_rules=[_make_lb_rule("pa"), _make_lb_rule("pb")],
        )
        findings = _run([lb])
        assert len(findings) == 1
        assert findings[0].details["relevant_backend_pool_count"] == 2

    def test_lb_rule_using_multi_pool_ref(self):
        """LB rule using backend_address_pools (list form) → EMIT."""
        pool_a = _make_pool("pa")
        pool_b = _make_pool("pb")
        lb = _make_lb(
            pools=[pool_a, pool_b],
            lb_rules=[_make_lb_rule(pool_names=["pa", "pb"])],
        )
        findings = _run([lb])
        assert len(findings) == 1

    def test_mixed_lb_and_outbound_rules_both_empty(self):
        """One LB rule + one outbound rule both referencing the same empty pool → EMIT."""
        pool = _make_pool("p1")
        lb = _make_lb(
            pools=[pool],
            lb_rules=[_make_lb_rule("p1")],
            outbound_rules=[_make_outbound_rule("p1")],
        )
        findings = _run([lb])
        assert len(findings) == 1
        assert findings[0].details["load_balancing_rule_count"] == 1
        assert findings[0].details["outbound_rule_count"] == 1


# ---------------------------------------------------------------------------
# TestMustSkip — spec 14.2
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_basic_sku_skipped(self):
        pool = _make_pool("p1")
        lb = _make_lb(sku_name="Basic", pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []

    def test_gateway_sku_skipped(self):
        pool = _make_pool("p1")
        lb = _make_lb(sku_name="Gateway", pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []

    def test_provisioning_state_creating_skipped(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], provisioning_state="Creating")
        assert _run([lb]) == []

    def test_provisioning_state_none_skipped(self):
        """None provisioning state must skip — not treated as Succeeded."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], provisioning_state=None)
        assert _run([lb]) == []

    def test_no_billable_rules_skipped(self):
        """No load-balancing rules and no outbound rules → skip even if pools are empty."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool])  # no lb_rules, no outbound_rules
        assert _run([lb]) == []

    def test_only_inbound_nat_rules_not_billable(self):
        """Inbound NAT rules are not billable — LB with only NAT rules must skip."""
        pool = _make_pool("p1")
        inbound_nat_rule = SimpleNamespace(
            backend_address_pool=_pool_ref("p1"), backend_address_pools=[]
        )
        lb = SimpleNamespace(
            id="/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb",
            name="lb",
            location="eastus",
            sku=SimpleNamespace(name="Standard", tier="Regional"),
            backend_address_pools=[pool],
            frontend_ip_configurations=[],
            load_balancing_rules=[],
            outbound_rules=[],
            inbound_nat_rules=[inbound_nat_rule],
            provisioning_state="Succeeded",
            tags=None,
        )
        assert _run([lb]) == []

    def test_referenced_pool_has_nic_members_skipped(self):
        pool = _make_pool("p1", nic_backends=[{"id": "nic-1"}])
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []

    def test_referenced_pool_has_ip_members_skipped(self):
        pool = _make_pool("p1", ip_backends=[SimpleNamespace(ip_address="10.0.0.1")])
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []

    def test_pool_ref_with_no_id_skipped(self):
        """LB rule referencing a pool object whose id is None → unresolvable → skip."""
        pool = _make_pool("p1")
        bad_rule = SimpleNamespace(
            backend_address_pool=SimpleNamespace(id=None),
            backend_address_pools=[],
        )
        lb = _make_lb(pools=[pool], lb_rules=[bad_rule])
        assert _run([lb]) == []

    def test_referenced_pool_not_in_inventory_skipped(self):
        """Rule references a pool id not present in LB's backend_address_pools → skip."""
        pool_in_inventory = _make_pool("p1")
        rule_refs_unknown = _make_lb_rule("p-unknown")  # references "p-unknown", not "p1"
        lb = _make_lb(pools=[pool_in_inventory], lb_rules=[rule_refs_unknown])
        assert _run([lb]) == []

    def test_lb_rule_with_no_pool_reference_skipped(self):
        """Billable rule with neither backend_address_pool nor backend_address_pools → skip."""
        pool = _make_pool("p1")
        empty_rule = SimpleNamespace(
            backend_address_pool=None,
            backend_address_pools=[],
        )
        lb = _make_lb(pools=[pool], lb_rules=[empty_rule])
        assert _run([lb]) == []

    def test_absent_id_skipped(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], lb_id=None)
        # Override id to None
        lb.id = None
        assert _run([lb]) == []

    def test_absent_name_skipped(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        lb.name = None
        assert _run([lb]) == []

    def test_region_filter_mismatch_skipped(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], location="westus")
        assert _run([lb], region_filter="eastus") == []


# ---------------------------------------------------------------------------
# TestBillableRuleContract — spec 9.2
# ---------------------------------------------------------------------------


class TestBillableRuleContract:
    def test_lb_rule_counts_as_billable(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert len(_run([lb])) == 1

    def test_outbound_rule_counts_as_billable(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], outbound_rules=[_make_outbound_rule("p1")])
        assert len(_run([lb])) == 1

    def test_billable_rule_count_in_signal(self):
        """signals_used must include exact billable rule count."""
        pool_a = _make_pool("pa")
        pool_b = _make_pool("pb")
        lb = _make_lb(
            pools=[pool_a, pool_b],
            lb_rules=[_make_lb_rule("pa")],
            outbound_rules=[_make_outbound_rule("pb")],
        )
        findings = _run([lb])
        assert len(findings) == 1
        signals = findings[0].evidence.signals_used
        assert any("Billable rule count is 2" in s for s in signals)


# ---------------------------------------------------------------------------
# TestRelevantPoolContract — spec 9.3
# ---------------------------------------------------------------------------


class TestRelevantPoolContract:
    def test_unreferenced_pool_with_members_does_not_suppress(self):
        """Pool not referenced by any billable rule must not affect the finding."""
        empty_pool = _make_pool("empty")
        unreferenced = _make_pool("unreferenced", nic_backends=[{"id": "nic-1"}])
        lb = _make_lb(
            pools=[empty_pool, unreferenced],
            lb_rules=[_make_lb_rule("empty")],  # only references "empty"
        )
        findings = _run([lb])
        assert len(findings) == 1
        assert findings[0].details["relevant_backend_pool_count"] == 1

    def test_two_rules_same_pool_deduped(self):
        """Two billable rules referencing the same pool → pool evaluated once."""
        pool = _make_pool("p1")
        lb = _make_lb(
            pools=[pool],
            lb_rules=[_make_lb_rule("p1"), _make_lb_rule("p1")],
        )
        findings = _run([lb])
        assert len(findings) == 1
        # pool should appear exactly once in relevant set
        assert findings[0].details["relevant_backend_pool_count"] == 1

    def test_partial_pool_missing_from_inventory_skips_lb(self):
        """Two rules: one referenced pool is in inventory, one is not → skip."""
        pool_a = _make_pool("pa")
        # "pb" referenced but not in inventory
        lb = _make_lb(
            pools=[pool_a],
            lb_rules=[_make_lb_rule("pa"), _make_lb_rule("pb")],
        )
        assert _run([lb]) == []

    def test_pool_id_trailing_slash_normalized(self):
        """Pool id with trailing slash in inventory still resolves correctly."""
        # Manually build a pool whose id has a trailing slash
        pool = SimpleNamespace(
            id=_pool_arm_id("p1") + "/",  # trailing slash
            backend_ip_configurations=None,
            load_balancer_backend_addresses=None,
        )
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        findings = _run([lb])
        assert len(findings) == 1

    def test_pool_id_uppercase_normalized(self):
        """Pool id with uppercase letters in inventory matches lowercase reference."""
        pool = SimpleNamespace(
            id=_pool_arm_id("p1").upper(),  # uppercase
            backend_ip_configurations=None,
            load_balancer_backend_addresses=None,
        )
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        findings = _run([lb])
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestMembershipContract — spec 9.4
# ---------------------------------------------------------------------------


class TestMembershipContract:
    def test_pool_with_nic_members_not_empty(self):
        pool = _make_pool("p1", nic_backends=[{"id": "nic-1"}])
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []

    def test_pool_with_ip_members_not_empty(self):
        pool = _make_pool("p1", ip_backends=[SimpleNamespace(ip_address="10.0.0.1")])
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []

    def test_pool_with_empty_nic_list_is_empty(self):
        pool = _make_pool("p1", nic_backends=[])
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert len(_run([lb])) == 1

    def test_pool_with_none_members_is_empty(self):
        pool = _make_pool("p1", nic_backends=None, ip_backends=None)
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert len(_run([lb])) == 1

    def test_any_relevant_pool_with_members_skips(self):
        """Two relevant pools — one empty, one has members → skip."""
        empty_pool = _make_pool("pa")
        full_pool = _make_pool("pb", nic_backends=[{"id": "nic-1"}])
        lb = _make_lb(
            pools=[empty_pool, full_pool],
            lb_rules=[_make_lb_rule("pa"), _make_lb_rule("pb")],
        )
        assert _run([lb]) == []


# ---------------------------------------------------------------------------
# TestFindingShape — spec 12.1-12.3
# ---------------------------------------------------------------------------


class TestFindingShape:
    def _emit_one(self):
        pool = _make_pool("p1")
        lb = _make_lb(
            name="lb-test",
            pools=[pool],
            lb_rules=[_make_lb_rule("p1")],
            tags={"env": "test"},
        )
        findings = _run([lb])
        assert len(findings) == 1
        return findings[0]

    def test_provider(self):
        assert self._emit_one().provider == "azure"

    def test_rule_id(self):
        assert self._emit_one().rule_id == "azure.load_balancer.no_backends"

    def test_resource_type(self):
        assert self._emit_one().resource_type == "azure.load_balancer"

    def test_resource_id_is_arm_id(self):
        f = self._emit_one()
        assert "Microsoft.Network/loadBalancers/lb-test" in f.resource_id

    def test_region_is_normalized(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], location="EastUS")
        findings = _run([lb])
        assert len(findings) == 1
        assert findings[0].region == "eastus"

    def test_estimated_cost_is_none(self):
        """Spec 11 mandates None — must not be $18 or any hardcoded value."""
        assert self._emit_one().estimated_monthly_cost_usd is None

    def test_confidence_high(self):
        assert self._emit_one().confidence == pytest.approx(self._emit_one().confidence)
        assert self._emit_one().confidence.value == "high"

    def test_risk_low(self):
        assert self._emit_one().risk.value == "low"

    def test_details_resource_name(self):
        assert self._emit_one().details["resource_name"] == "lb-test"

    def test_details_subscription_id(self):
        assert self._emit_one().details["subscription_id"] == _SUB

    def test_details_sku_name(self):
        assert self._emit_one().details["sku_name"] == "Standard"

    def test_details_sku_tier(self):
        assert self._emit_one().details["sku_tier"] == "Regional"

    def test_details_backend_pool_count(self):
        assert self._emit_one().details["backend_pool_count"] == 1

    def test_details_relevant_backend_pool_count(self):
        assert self._emit_one().details["relevant_backend_pool_count"] == 1

    def test_details_load_balancing_rule_count(self):
        assert self._emit_one().details["load_balancing_rule_count"] == 1

    def test_details_outbound_rule_count(self):
        assert self._emit_one().details["outbound_rule_count"] == 0

    def test_details_frontend_ip_count(self):
        assert self._emit_one().details["frontend_ip_count"] == 0

    def test_details_tags_normalized_to_dict(self):
        assert self._emit_one().details["tags"] == {"env": "test"}

    def test_details_tags_none_becomes_empty_dict(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], tags=None)
        findings = _run([lb])
        assert findings[0].details["tags"] == {}


# ---------------------------------------------------------------------------
# TestEvidenceContract — spec 12.2
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def _emit_one(self, billable_count=1):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        findings = _run([lb])
        assert len(findings) == 1
        return findings[0].evidence

    def test_signals_used_sku(self):
        assert "Load Balancer SKU is Standard" in self._emit_one().signals_used

    def test_signals_used_billable_count(self):
        assert "Billable rule count is 1" in self._emit_one().signals_used

    def test_signals_used_membership_check(self):
        assert (
            "All relevant backend pools evaluated to empty using NIC-based and IP-based membership checks"
            in self._emit_one().signals_used
        )

    def test_signals_not_checked_planned_backend(self):
        assert (
            "Planned backend attachment or cutover intent" in self._emit_one().signals_not_checked
        )

    def test_signals_not_checked_iac(self):
        assert (
            "IaC-managed placeholder or staged deployment intent"
            in self._emit_one().signals_not_checked
        )

    def test_signals_not_checked_traffic(self):
        assert "Traffic history or future activation plans" in self._emit_one().signals_not_checked

    def test_signals_not_checked_frontend(self):
        assert (
            "Frontend public IP cost or attachment evaluated by other rules"
            in self._emit_one().signals_not_checked
        )

    def test_billable_count_reflects_two_rules(self):
        pool_a = _make_pool("pa")
        pool_b = _make_pool("pb")
        lb = _make_lb(
            pools=[pool_a, pool_b],
            lb_rules=[_make_lb_rule("pa")],
            outbound_rules=[_make_outbound_rule("pb")],
        )
        findings = _run([lb])
        evidence = findings[0].evidence
        assert "Billable rule count is 2" in evidence.signals_used


# ---------------------------------------------------------------------------
# TestRegionFilter — spec 8.3 / 7
# ---------------------------------------------------------------------------


class TestRegionFilter:
    def test_exact_match_emits(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], location="eastus")
        assert len(_run([lb], region_filter="eastus")) == 1

    def test_case_insensitive_region_filter(self):
        """Region filter is lowercased before comparison."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], location="eastus")
        assert len(_run([lb], region_filter="EastUS")) == 1

    def test_location_stored_lowercase(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], location="WestEurope")
        findings = _run([lb])
        assert findings[0].region == "westeurope"

    def test_region_mismatch_skips(self):
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")], location="westus")
        assert _run([lb], region_filter="eastus") == []

    def test_no_region_filter_includes_all(self):
        pool = _make_pool("p1")
        lb_east = _make_lb("east", pools=[pool], lb_rules=[_make_lb_rule("p1")], location="eastus")
        lb_west = _make_lb("west", pools=[pool], lb_rules=[_make_lb_rule("p1")], location="westus")
        assert len(_run([lb_east, lb_west])) == 2


# ---------------------------------------------------------------------------
# TestFailureBehavior — spec 13
# ---------------------------------------------------------------------------


class TestFailureBehavior:
    def test_list_exception_propagates(self):
        """If list_all() raises, the exception must propagate."""
        client = SimpleNamespace(
            load_balancers=SimpleNamespace(
                list_all=lambda: (_ for _ in ()).throw(RuntimeError("API down"))
            )
        )
        with pytest.raises(RuntimeError, match="API down"):
            find_lb_no_backends(subscription_id=_SUB, credential=None, client=client)

    def test_malformed_lb_skipped(self):
        """An LB record with no id is skipped; scan continues for the next one."""
        good_pool = _make_pool("p1")
        good_lb = _make_lb("good", pools=[good_pool], lb_rules=[_make_lb_rule("p1")])
        bad_lb = SimpleNamespace(
            id=None,  # missing id
            name="bad",
            location="eastus",
            sku=SimpleNamespace(name="Standard", tier="Regional"),
            backend_address_pools=[good_pool],
            frontend_ip_configurations=[],
            load_balancing_rules=[_make_lb_rule("p1")],
            outbound_rules=[],
            provisioning_state="Succeeded",
            tags=None,
        )
        findings = _run([bad_lb, good_lb])
        assert len(findings) == 1
        assert findings[0].details["resource_name"] == "good"


# ---------------------------------------------------------------------------
# TestSDKFallbacks — spec 9.1-9.4 nested/raw ARM-style fallback paths
# ---------------------------------------------------------------------------


class TestSDKFallbacks:
    """
    Each test removes the SDK-level attribute (sets to None) and asserts that
    the implementation falls back to lb.properties.* / rule.properties.* /
    pool.properties.* as required by spec 9.1-9.4.
    """

    # -- Gap 1: Provisioning state (spec 9.1) --

    def test_provisioning_state_from_nested_properties_emits(self):
        """lb.provisioning_state absent → lb.properties.provisioning_state='Succeeded' used."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        lb.provisioning_state = None
        lb.properties = SimpleNamespace(provisioning_state="Succeeded")
        assert len(_run([lb])) == 1

    def test_provisioning_state_nested_not_succeeded_skips(self):
        """lb.provisioning_state absent, nested is 'Creating' → skip."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        lb.provisioning_state = None
        lb.properties = SimpleNamespace(provisioning_state="Creating")
        assert _run([lb]) == []

    def test_provisioning_state_both_absent_skips(self):
        """Neither lb.provisioning_state nor lb.properties.provisioning_state → skip."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        lb.provisioning_state = None
        lb.properties = SimpleNamespace()  # no provisioning_state attribute
        assert _run([lb]) == []

    # -- Gap 2: Billable rule collections (spec 9.2) --

    def test_lb_rules_from_nested_properties(self):
        """lb.load_balancing_rules absent → lb.properties.load_balancing_rules used."""
        pool = _make_pool("p1")
        rule = _make_lb_rule("p1")
        lb = _make_lb(pools=[pool])
        lb.load_balancing_rules = None
        lb.properties = SimpleNamespace(
            load_balancing_rules=[rule],
            outbound_rules=[],
        )
        assert len(_run([lb])) == 1

    def test_outbound_rules_from_nested_properties(self):
        """lb.outbound_rules absent → lb.properties.outbound_rules used."""
        pool = _make_pool("p1")
        rule = _make_outbound_rule("p1")
        lb = _make_lb(pools=[pool])
        lb.outbound_rules = None
        lb.properties = SimpleNamespace(
            load_balancing_rules=[],
            outbound_rules=[rule],
        )
        assert len(_run([lb])) == 1

    def test_no_billable_rules_in_nested_skips(self):
        """Both rule collections absent at SDK and nested level → skip (count = 0)."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool])
        lb.load_balancing_rules = None
        lb.outbound_rules = None
        lb.properties = SimpleNamespace(load_balancing_rules=[], outbound_rules=[])
        assert _run([lb]) == []

    # -- Gap 3: Rule-to-backend reference (spec 9.3) --

    def test_single_pool_ref_from_rule_properties(self):
        """rule.backend_address_pool absent → rule.properties.backend_address_pool used."""
        pool = _make_pool("p1")
        rule = SimpleNamespace(
            backend_address_pool=None,
            backend_address_pools=[],
            properties=SimpleNamespace(
                backend_address_pool=_pool_ref("p1"),
                backend_address_pools=[],
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[rule])
        assert len(_run([lb])) == 1

    def test_multi_pool_refs_from_rule_properties(self):
        """rule.backend_address_pools absent → rule.properties.backend_address_pools used."""
        pool = _make_pool("p1")
        rule = SimpleNamespace(
            backend_address_pool=None,
            backend_address_pools=None,
            properties=SimpleNamespace(
                backend_address_pool=None,
                backend_address_pools=[_pool_ref("p1")],
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[rule])
        assert len(_run([lb])) == 1

    def test_rule_nested_ref_with_no_id_skips(self):
        """Nested pool reference object present but id is None → unresolvable → skip."""
        pool = _make_pool("p1")
        rule = SimpleNamespace(
            backend_address_pool=None,
            backend_address_pools=[],
            properties=SimpleNamespace(
                backend_address_pool=SimpleNamespace(id=None),
                backend_address_pools=[],
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[rule])
        assert _run([lb]) == []

    # -- Gap 4a: Pool membership (spec 9.4) --

    def test_nic_members_from_pool_properties(self):
        """pool.backend_ip_configurations absent → pool.properties.backend_ip_configurations used."""
        pool = SimpleNamespace(
            id=_pool_arm_id("p1"),
            backend_ip_configurations=None,
            load_balancer_backend_addresses=None,
            properties=SimpleNamespace(
                backend_ip_configurations=[{"id": "nic-1"}],
                load_balancer_backend_addresses=None,
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []  # members detected via fallback → skip

    def test_ip_members_from_pool_properties(self):
        """pool.load_balancer_backend_addresses absent → pool.properties.* used."""
        pool = SimpleNamespace(
            id=_pool_arm_id("p1"),
            backend_ip_configurations=None,
            load_balancer_backend_addresses=None,
            properties=SimpleNamespace(
                backend_ip_configurations=None,
                load_balancer_backend_addresses=[SimpleNamespace(ip_address="10.0.0.1")],
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []  # members detected via fallback → skip

    def test_pool_nested_both_empty_still_emits(self):
        """pool.properties has both membership attrs, both empty → pool is empty → emit."""
        pool = SimpleNamespace(
            id=_pool_arm_id("p1"),
            backend_ip_configurations=None,
            load_balancer_backend_addresses=None,
            properties=SimpleNamespace(
                backend_ip_configurations=[],
                load_balancer_backend_addresses=[],
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert len(_run([lb])) == 1

    # -- Gap 4b: Pool inventory (spec 9.3 / spec 6) --

    def test_pool_inventory_from_lb_nested_properties(self):
        """lb.backend_address_pools absent → lb.properties.backend_address_pools used."""
        pool = _make_pool("p1")
        rule = _make_lb_rule("p1")
        lb = _make_lb(lb_rules=[rule])
        lb.backend_address_pools = None  # make SDK attribute absent
        lb.properties = SimpleNamespace(backend_address_pools=[pool])
        assert len(_run([lb])) == 1

    def test_pool_inventory_from_nested_has_members_skips(self):
        """Pool found via nested fallback and it has members → skip."""
        pool = SimpleNamespace(
            id=_pool_arm_id("p1"),
            backend_ip_configurations=[{"id": "nic-1"}],
            load_balancer_backend_addresses=None,
        )
        rule = _make_lb_rule("p1")
        lb = _make_lb(lb_rules=[rule])
        lb.backend_address_pools = None
        lb.properties = SimpleNamespace(backend_address_pools=[pool])
        assert _run([lb]) == []


class TestArmCamelCaseFallbacks:
    """
    Verify that each resolver falls back to ARM camelCase field names when
    both the SDK projection and the nested snake_case field are absent.
    """

    # -- provisioningState --

    def test_provisioning_state_camel_case_succeeded_emits(self):
        """lb.provisioningState and lb.properties.provisioning_state absent → lb.properties.provisioningState used."""
        pool = _make_pool("p1")
        rule = _make_lb_rule("p1")
        lb = _make_lb(pools=[pool], lb_rules=[rule])
        lb.provisioning_state = None
        lb.properties = SimpleNamespace(provisioning_state=None, provisioningState="Succeeded")
        assert len(_run([lb])) == 1

    def test_provisioning_state_camel_case_not_succeeded_skips(self):
        """lb.properties.provisioningState='Updating' → skip."""
        pool = _make_pool("p1")
        rule = _make_lb_rule("p1")
        lb = _make_lb(pools=[pool], lb_rules=[rule])
        lb.provisioning_state = None
        lb.properties = SimpleNamespace(provisioning_state=None, provisioningState="Updating")
        assert _run([lb]) == []

    # -- loadBalancingRules --

    def test_lb_rules_from_camel_case_nested(self):
        """lb.load_balancing_rules absent and lb.properties.load_balancing_rules absent → lb.properties.loadBalancingRules used."""
        pool = _make_pool("p1")
        rule = _make_lb_rule("p1")
        lb = _make_lb(pools=[pool], lb_rules=[rule])
        lb.load_balancing_rules = None
        lb.properties = SimpleNamespace(load_balancing_rules=None, loadBalancingRules=[rule])
        assert len(_run([lb])) == 1

    # -- outboundRules --

    def test_outbound_rules_from_camel_case_nested(self):
        """lb.outbound_rules absent and lb.properties.outbound_rules absent → lb.properties.outboundRules used."""
        pool = _make_pool("p1")
        rule = _make_outbound_rule("p1")
        lb = _make_lb(pools=[pool], outbound_rules=[rule])
        lb.outbound_rules = None
        lb.properties = SimpleNamespace(outbound_rules=None, outboundRules=[rule])
        assert len(_run([lb])) == 1

    # -- backendAddressPools (inventory) --

    def test_pool_inventory_from_camel_case_nested(self):
        """lb.backend_address_pools absent and lb.properties.backend_address_pools absent → lb.properties.backendAddressPools used."""
        pool = _make_pool("p1")
        rule = _make_lb_rule("p1")
        lb = _make_lb(lb_rules=[rule])
        lb.backend_address_pools = None
        lb.properties = SimpleNamespace(backend_address_pools=None, backendAddressPools=[pool])
        assert len(_run([lb])) == 1

    # -- backendAddressPool (single rule ref) --

    def test_single_pool_ref_from_camel_case_rule_properties(self):
        """rule.backend_address_pool absent and rule.properties.backend_address_pool absent → rule.properties.backendAddressPool used."""
        pool = _make_pool("p1")
        ref = _pool_ref("p1")
        rule = SimpleNamespace(
            backend_address_pool=None,
            backend_address_pools=[],
            properties=SimpleNamespace(
                backend_address_pool=None,
                backendAddressPool=ref,
                backend_address_pools=None,
                backendAddressPools=None,
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[rule])
        assert len(_run([lb])) == 1

    # -- backendAddressPools (multi rule refs) --

    def test_multi_pool_refs_from_camel_case_rule_properties(self):
        """rule.backend_address_pools absent and rule.properties.backend_address_pools absent → rule.properties.backendAddressPools used."""
        pool = _make_pool("p1")
        ref = _pool_ref("p1")
        rule = SimpleNamespace(
            backend_address_pool=None,
            backend_address_pools=None,
            properties=SimpleNamespace(
                backend_address_pool=None,
                backendAddressPool=None,
                backend_address_pools=None,
                backendAddressPools=[ref],
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[rule])
        assert len(_run([lb])) == 1

    # -- backendIpConfigurations (NIC membership) --

    def test_nic_members_from_camel_case_pool_properties(self):
        """pool.backend_ip_configurations absent and pool.properties.backend_ip_configurations absent → pool.properties.backendIpConfigurations used."""
        pool = SimpleNamespace(
            id=_pool_arm_id("p1"),
            backend_ip_configurations=None,
            load_balancer_backend_addresses=None,
            properties=SimpleNamespace(
                backend_ip_configurations=None,
                backendIpConfigurations=[{"id": "nic-1"}],
                load_balancer_backend_addresses=None,
                loadBalancerBackendAddresses=None,
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []  # members found via camelCase → skip

    # -- loadBalancerBackendAddresses (IP membership) --

    def test_ip_members_from_camel_case_pool_properties(self):
        """pool.load_balancer_backend_addresses absent and pool.properties.load_balancer_backend_addresses absent → pool.properties.loadBalancerBackendAddresses used."""
        pool = SimpleNamespace(
            id=_pool_arm_id("p1"),
            backend_ip_configurations=None,
            load_balancer_backend_addresses=None,
            properties=SimpleNamespace(
                backend_ip_configurations=None,
                backendIpConfigurations=None,
                load_balancer_backend_addresses=None,
                loadBalancerBackendAddresses=[SimpleNamespace(ip_address="10.0.0.2")],
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert _run([lb]) == []  # members found via camelCase → skip

    def test_camel_case_pool_both_empty_still_emits(self):
        """pool.properties has camelCase membership attrs, both empty → pool is empty → emit."""
        pool = SimpleNamespace(
            id=_pool_arm_id("p1"),
            backend_ip_configurations=None,
            load_balancer_backend_addresses=None,
            properties=SimpleNamespace(
                backend_ip_configurations=None,
                backendIpConfigurations=[],
                load_balancer_backend_addresses=None,
                loadBalancerBackendAddresses=[],
            ),
        )
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        assert len(_run([lb])) == 1


class TestRobustnessAndFrontendDetails:
    """
    Covers the two minor concerns:
      1. frontend_ip_count uses nested/raw fallback (detail field consistency).
      2. Non-iterable rule collections are skipped, not raised.
    """

    # -- Concern 1: frontend_ip_count fallback --

    def test_frontend_count_from_nested_snake_case(self):
        """lb.frontend_ip_configurations absent → lb.properties.frontend_ip_configurations used."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        lb.frontend_ip_configurations = None
        lb.properties = SimpleNamespace(
            frontend_ip_configurations=[SimpleNamespace(id="fe-1"), SimpleNamespace(id="fe-2")],
            frontendIPConfigurations=None,
        )
        findings = _run([lb])
        assert len(findings) == 1
        assert findings[0].details["frontend_ip_count"] == 2

    def test_frontend_count_from_nested_camel_case(self):
        """Both SDK and snake_case nested absent → lb.properties.frontendIPConfigurations used."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        lb.frontend_ip_configurations = None
        lb.properties = SimpleNamespace(
            frontend_ip_configurations=None,
            frontendIPConfigurations=[SimpleNamespace(id="fe-1")],
        )
        findings = _run([lb])
        assert len(findings) == 1
        assert findings[0].details["frontend_ip_count"] == 1

    def test_frontend_count_zero_when_all_absent(self):
        """All three sources absent → frontend_ip_count is 0, not an error."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool], lb_rules=[_make_lb_rule("p1")])
        lb.frontend_ip_configurations = None
        lb.properties = SimpleNamespace(
            frontend_ip_configurations=None,
            frontendIPConfigurations=None,
        )
        findings = _run([lb])
        assert len(findings) == 1
        assert findings[0].details["frontend_ip_count"] == 0

    # -- Concern 2: non-iterable rule collections don't raise --

    def test_non_iterable_lb_rules_treated_as_no_rules(self):
        """lb.load_balancing_rules is a truthy non-iterable object → treated as empty → skip (no billable rules)."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool])
        lb.load_balancing_rules = object()  # truthy, non-iterable
        lb.outbound_rules = []
        # No billable rules resolved → must skip, not raise
        assert _run([lb]) == []

    def test_non_iterable_outbound_rules_treated_as_no_rules(self):
        """lb.outbound_rules is a truthy non-iterable object → treated as empty → skip."""
        pool = _make_pool("p1")
        lb = _make_lb(pools=[pool])
        lb.load_balancing_rules = []
        lb.outbound_rules = object()  # truthy, non-iterable
        assert _run([lb]) == []

    def test_non_iterable_backend_pools_treated_as_empty_inventory(self):
        """lb.backend_address_pools is a truthy non-iterable → pool inventory is empty → unresolvable reference → skip."""
        rule = _make_lb_rule("p1")
        lb = _make_lb(lb_rules=[rule])
        lb.backend_address_pools = object()  # truthy, non-iterable
        assert _run([lb]) == []
