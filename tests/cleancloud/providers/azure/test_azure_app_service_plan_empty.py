"""
Spec-driven tests for azure.app_service_plan.empty rule.

Spec: docs/specs/azure/app_service_plan_empty.md

Detection intent:
    Emit only when ALL of the following are true:
      1. plan.id is present
      2. provisioningState == "Succeeded"
      3. plan.sku is not None
      4. plan.sku.tier (lowercased) is in the known paid tier allowlist
      5. number_of_sites == 0 or None (pre-filter)
      6. resource group extractable from plan.id
      7. list_web_apps() completes fully with zero apps
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.azure.rules.app_service_plan_empty import (
    find_empty_app_service_plans,
)

# ---------------------------------------------------------------------------
# Test data builders
# ---------------------------------------------------------------------------

SUB = "sub-123"
RG = "rg-test"
PLAN_BASE = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/serverfarms"


def _plan_id(name: str) -> str:
    return f"{PLAN_BASE}/{name}"


def _make_plan(
    name: str = "test-plan",
    tier: str = "Standard",
    sku_name: str = "S1",
    capacity: int = 1,
    number_of_sites: int = 0,
    location: str = "eastus",
    provisioning_state: str = "Succeeded",
    tags: dict = None,
    plan_id: str = None,
    sku: object = None,
) -> SimpleNamespace:
    pid = plan_id or _plan_id(name)
    if sku is None:
        sku = SimpleNamespace(name=sku_name, tier=tier, capacity=capacity)
    return SimpleNamespace(
        id=pid,
        name=name,
        location=location,
        sku=sku,
        number_of_sites=number_of_sites,
        provisioning_state=provisioning_state,
        tags=tags,
    )


def _make_client(plans=None, web_apps=None) -> MagicMock:
    client = MagicMock()
    client.app_service_plans.list.return_value = plans or []
    client.app_service_plans.list_web_apps.return_value = web_apps if web_apps is not None else []
    return client


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_basic_empty_standard_plan_emits(self):
        """Standard tier, zero sites, list_web_apps empty -> EMIT."""
        plan = _make_plan("empty-plan", tier="Standard")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        assert "empty-plan" in findings[0].resource_id

    def test_basic_tier_emits(self):
        plan = _make_plan("basic-plan", tier="Basic", sku_name="B1")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1

    def test_premiumv3_emits(self):
        plan = _make_plan("pv3-plan", tier="PremiumV3", sku_name="P1v3")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1

    def test_premiumv4_emits(self):
        """PremiumV4 is in the paid tier allowlist -> EMIT."""
        plan = _make_plan("pv4-plan", tier="PremiumV4", sku_name="P1v4")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1

    def test_isolatedv2_emits(self):
        plan = _make_plan("isolated-plan", tier="IsolatedV2", sku_name="I1v2")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1

    def test_number_of_sites_none_treated_as_empty(self):
        """Azure can return None for number_of_sites -> treated as potentially empty."""
        plan = _make_plan("none-sites-plan", number_of_sites=None)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1

    def test_empty_subscription_returns_no_findings(self):
        client = _make_client([])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []


# ---------------------------------------------------------------------------
# TestMustSkip — mandatory exclusions from spec section 8
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_missing_plan_id_skipped(self):
        """spec 8.1: plan.id absent -> SKIP."""
        plan = _make_plan("no-id")
        plan.id = None
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_empty_plan_id_skipped(self):
        """spec 8.1: plan.id empty string -> SKIP."""
        plan = _make_plan("empty-id")
        plan.id = ""  # set directly to bypass helper fallback
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_provisioning_state_not_succeeded_skipped(self):
        """spec 8.3: provisioningState != Succeeded -> SKIP."""
        for state in ("Creating", "Failed", "Canceled", "Deleting", "InProgress"):
            plan = _make_plan(f"plan-{state}", provisioning_state=state)
            client = _make_client([plan])
            findings = find_empty_app_service_plans(
                subscription_id=SUB, credential=None, client=client
            )
            assert findings == [], f"Expected skip for provisioningState={state}"

    def test_provisioning_state_none_skipped(self):
        """spec 8.3: provisioningState == None is not Succeeded -> SKIP."""
        plan = _make_plan("plan-none-state", provisioning_state=None)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_sku_none_skipped(self):
        """spec 8.4: plan.sku is None -> SKIP."""
        plan = _make_plan("no-sku")
        plan.sku = None
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_tier_none_skipped(self):
        """spec 8.5: tier is None -> SKIP."""
        plan = _make_plan("no-tier")
        plan.sku = SimpleNamespace(name="S1", tier=None, capacity=1)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_free_tier_skipped(self):
        plan = _make_plan("free-plan", tier="Free", sku_name="F1")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_shared_tier_skipped(self):
        plan = _make_plan("shared-plan", tier="Shared", sku_name="D1")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_dynamic_tier_skipped(self):
        plan = _make_plan("dynamic-plan", tier="Dynamic", sku_name="Y1")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_elasticpremium_tier_skipped(self):
        plan = _make_plan("ep-plan", tier="ElasticPremium", sku_name="EP1")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_workflowstandard_tier_skipped(self):
        plan = _make_plan("ws-plan", tier="WorkflowStandard", sku_name="WS1")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_unrecognized_tier_skipped(self):
        """Any unrecognized tier string -> SKIP (allowlist contract)."""
        plan = _make_plan("mystery-plan", tier="FlexConsumption")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_number_of_sites_nonzero_skipped(self):
        """spec 8.6: number_of_sites > 0 -> SKIP (pre-filter; no secondary call)."""
        plan = _make_plan("has-apps-plan", number_of_sites=3)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []
        client.app_service_plans.list_web_apps.assert_not_called()

    def test_resource_group_not_extractable_skipped(self):
        """spec 8.7: malformed ARM id yields no resource group -> SKIP."""
        plan = _make_plan("bad-id-plan", plan_id="/malformed/id/no/rg/segment")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_list_web_apps_exception_skipped(self):
        """spec 8.8: list_web_apps() raises -> SKIP (conservative)."""
        plan = _make_plan("api-error-plan")
        client = _make_client([plan])
        client.app_service_plans.list_web_apps.side_effect = Exception("403 Forbidden")
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_list_web_apps_returns_apps_skipped(self):
        """spec 8.9: list_web_apps() returns apps -> SKIP (not empty)."""
        plan = _make_plan("has-apps-cached")
        app_obj = SimpleNamespace(name="some-app")
        client = _make_client([plan], web_apps=[app_obj])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_number_of_sites_zero_but_apps_found_skipped(self):
        """number_of_sites=0 is unreliable; secondary call reveals apps -> SKIP."""
        plan = _make_plan("stale-cache-plan", number_of_sites=0)
        client = _make_client([plan], web_apps=[SimpleNamespace(name="app-1")])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []


# ---------------------------------------------------------------------------
# TestRegionFilter
# ---------------------------------------------------------------------------


class TestRegionFilter:
    def test_region_filter_excludes_other_regions(self):
        plan_east = _make_plan("east-plan", location="eastus")
        plan_west = _make_plan("west-plan", location="westus")
        client = _make_client([plan_east, plan_west])
        findings = find_empty_app_service_plans(
            subscription_id=SUB, credential=None, client=client, region_filter="eastus"
        )
        assert len(findings) == 1
        assert "east-plan" in findings[0].resource_id

    def test_region_filter_display_name_normalized(self):
        """Azure returns display names like 'West Europe'; filter uses short name 'westeurope'."""
        plan = _make_plan("eu-plan", location="West Europe")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(
            subscription_id=SUB, credential=None, client=client, region_filter="westeurope"
        )
        assert len(findings) == 1
        assert findings[0].region == "westeurope"

    def test_no_region_filter_scans_all(self):
        plans = [
            _make_plan("plan-east", location="eastus"),
            _make_plan("plan-west", location="westus"),
        ]
        client = _make_client(plans)
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# TestFindingShape — required fields per spec section 12.1
# ---------------------------------------------------------------------------


class TestFindingShape:
    def _get_finding(self):
        plan = _make_plan("shape-plan", tier="Standard")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        return findings[0]

    def test_provider(self):
        assert self._get_finding().provider == "azure"

    def test_rule_id(self):
        assert self._get_finding().rule_id == "azure.app_service_plan.empty"

    def test_resource_type(self):
        assert self._get_finding().resource_type == "azure.app_service_plan"

    def test_resource_id_is_arm_id(self):
        assert self._get_finding().resource_id == _plan_id("shape-plan")

    def test_region_is_normalized(self):
        assert self._get_finding().region == "eastus"

    def test_risk_is_low(self):
        assert self._get_finding().risk == RiskLevel.LOW

    def test_confidence_is_high(self):
        assert self._get_finding().confidence == ConfidenceLevel.HIGH


# ---------------------------------------------------------------------------
# TestEvidenceContract — signals_used, signals_not_checked, details
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def _get_finding(self, **kwargs):
        plan = _make_plan("ev-plan", **kwargs)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        return findings[0]

    def test_signals_used_number_of_sites_zero_message(self):
        """number_of_sites == 0 -> specific 'reported as 0' signal."""
        plan = _make_plan("sites-zero", number_of_sites=0)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        assert any(
            "number_of_sites" in s and "0" in s and "None" not in s
            for s in findings[0].evidence.signals_used
        )

    def test_signals_used_number_of_sites_none_message(self):
        """number_of_sites == None -> distinct signal noting emptiness confirmed only via list_web_apps()."""
        plan = _make_plan("sites-none", number_of_sites=None)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        assert any("None" in s and "list_web_apps" in s for s in findings[0].evidence.signals_used)

    def test_signals_used_contains_list_web_apps_confirmation(self):
        f = self._get_finding()
        assert any("list_web_apps" in s and "0" in s for s in f.evidence.signals_used)

    def test_signals_used_contains_tier(self):
        f = self._get_finding(tier="Standard")
        assert any("Standard" in s and "allowlist" in s for s in f.evidence.signals_used)

    def test_signals_used_contains_capacity_when_present(self):
        f = self._get_finding(capacity=2)
        assert any("2" in s and "instance" in s for s in f.evidence.signals_used)

    def test_reason_reflects_number_of_sites_zero(self):
        """reason must not say 0/None when number_of_sites == 0."""
        plan = _make_plan("reason-zero", number_of_sites=0)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        assert "0" in findings[0].reason
        assert "None" not in findings[0].reason

    def test_reason_reflects_number_of_sites_none(self):
        """reason must not say 0/None when number_of_sites is None."""
        plan = _make_plan("reason-none", number_of_sites=None)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        assert "None" in findings[0].reason
        assert "0/None" not in findings[0].reason

    def test_signals_used_capacity_zero_signal(self):
        """capacity == 0 -> explicit 'no current worker cost inferred' signal."""
        plan = _make_plan("cap-zero-signal")
        plan.sku = SimpleNamespace(name="S1", tier="Standard", capacity=0)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        assert any("capacity" in s and "0" in s for s in findings[0].evidence.signals_used)

    def test_signals_not_checked_contains_iac_intent(self):
        f = self._get_finding()
        assert any(
            "IaC" in s or "Terraform" in s or "Bicep" in s for s in f.evidence.signals_not_checked
        )

    def test_signals_not_checked_contains_planned_deployment(self):
        f = self._get_finding()
        assert any(
            "deployment" in s.lower() or "pipeline" in s.lower()
            for s in f.evidence.signals_not_checked
        )

    def test_details_resource_name(self):
        assert self._get_finding().details["resource_name"] == "ev-plan"

    def test_details_subscription_id(self):
        assert self._get_finding().details["subscription_id"] == SUB

    def test_details_sku_tier(self):
        assert self._get_finding(tier="Standard").details["sku_tier"] == "Standard"

    def test_details_sku_tier_original_casing_preserved(self):
        """Output must use original casing from API, not lowercased."""
        assert self._get_finding(tier="PremiumV3").details["sku_tier"] == "PremiumV3"

    def test_details_confirmed_web_apps_zero(self):
        assert self._get_finding().details["confirmed_web_apps"] == 0

    def test_details_tags_when_present(self):
        f = self._get_finding(tags={"env": "staging"})
        assert f.details["tags"] == {"env": "staging"}

    def test_details_tags_normalized_to_empty_dict_when_none(self):
        """tags=None from API must be normalized to {} in details (spec 15.5)."""
        f = self._get_finding(tags=None)
        assert f.details["tags"] == {}

    def test_details_capacity(self):
        f = self._get_finding(capacity=3)
        assert f.details["capacity"] == 3


# ---------------------------------------------------------------------------
# TestCostModel — spec section 11
# ---------------------------------------------------------------------------


class TestCostModel:
    def _get_cost(self, tier, capacity):
        plan = _make_plan("cost-plan", tier=tier, capacity=capacity)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        return findings[0].estimated_monthly_cost_usd

    def test_standard_single_instance_cost(self):
        assert self._get_cost("Standard", 1) == 73.0

    def test_standard_two_instances_cost_multiplied(self):
        """Cost reflects instance count: 2x Standard = 146.0."""
        assert self._get_cost("Standard", 2) == 146.0

    def test_basic_cost(self):
        assert self._get_cost("Basic", 1) == 55.0

    def test_premium_cost(self):
        assert self._get_cost("Premium", 1) == 146.0

    def test_premiumv4_cost(self):
        assert self._get_cost("PremiumV4", 1) == 146.0

    def test_isolated_cost(self):
        assert self._get_cost("Isolated", 1) == 298.0

    def test_isolatedv2_cost(self):
        assert self._get_cost("IsolatedV2", 1) == 298.0

    def test_cost_none_when_capacity_none(self):
        """spec 11.3: capacity=None -> estimated_monthly_cost_usd=None."""
        plan = _make_plan("no-cap")
        plan.sku = SimpleNamespace(name="S1", tier="Standard", capacity=None)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd is None

    def test_capacity_zero_still_emits_with_null_cost(self):
        """spec 11 + 14.1 item 7: capacity=0 -> EMIT but estimated_monthly_cost_usd=None."""
        plan = _make_plan("zero-cap")
        plan.sku = SimpleNamespace(name="S1", tier="Standard", capacity=0)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd is None

    def test_cost_tier_lookup_normalizes_casing(self):
        """Tier lookup normalizes API casing: 'standard' (lowercase from API) still matches."""
        assert self._get_cost("standard", 1) == 73.0


# ---------------------------------------------------------------------------
# TestEmptinessConfirmation — two-phase emptiness test (spec section 10)
# ---------------------------------------------------------------------------


class TestEmptinessConfirmation:
    def test_secondary_call_is_always_made_for_zero_sites(self):
        """list_web_apps() must be called to confirm emptiness."""
        plan = _make_plan("needs-confirm", number_of_sites=0)
        client = _make_client([plan])
        find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        client.app_service_plans.list_web_apps.assert_called_once()

    def test_secondary_call_not_made_when_sites_nonzero(self):
        """Pre-filter: list_web_apps() NOT called when number_of_sites > 0."""
        plan = _make_plan("skip-early", number_of_sites=5)
        client = _make_client([plan])
        find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        client.app_service_plans.list_web_apps.assert_not_called()

    def test_mid_iteration_failure_skips(self):
        """Exception mid-iteration of list_web_apps() -> inventory_complete=False -> SKIP."""
        plan = _make_plan("mid-iter-fail")
        client = _make_client([plan])

        def _failing_iter(*args, **kwargs):
            raise Exception("pager failed mid-iteration")
            yield

        client.app_service_plans.list_web_apps.side_effect = _failing_iter
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []

    def test_secondary_call_uses_correct_resource_group(self):
        """list_web_apps() must receive the resource group from the ARM id."""
        plan = _make_plan("rg-check-plan")
        client = _make_client([plan])
        find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        call_args = client.app_service_plans.list_web_apps.call_args
        rg_arg = (
            call_args.args[0] if call_args.args else call_args.kwargs.get("resource_group_name")
        )
        assert rg_arg == RG


# ---------------------------------------------------------------------------
# TestResourceGroupExtraction — case-insensitive ARM id parsing (spec 7.2)
# ---------------------------------------------------------------------------


class TestResourceGroupExtraction:
    def test_lowercase_resourcegroups_segment_matches(self):
        """Case-insensitive extraction: 'resourcegroups' (all lower) -> correct RG."""
        arm_id = (
            f"/subscriptions/{SUB}/resourcegroups/{RG}/providers/Microsoft.Web/serverfarms/plan-1"
        )
        plan = _make_plan("lower-rg", plan_id=arm_id)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1

    def test_mixed_case_resourcegroups_segment_matches(self):
        """Case-insensitive extraction: 'ResourceGroups' -> correct RG."""
        arm_id = (
            f"/subscriptions/{SUB}/ResourceGroups/{RG}/providers/Microsoft.Web/serverfarms/plan-2"
        )
        plan = _make_plan("mixed-rg", plan_id=arm_id)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1

    def test_no_resourcegroups_segment_skips(self):
        """No 'resourcegroups' segment -> resource group not extractable -> SKIP."""
        plan = _make_plan("no-rg-plan", plan_id="/malformed/arm/id")
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == []


# ---------------------------------------------------------------------------
# TestTierAllowlist — allowlist contract (spec section 9)
# ---------------------------------------------------------------------------


class TestTierAllowlist:
    @pytest.mark.parametrize(
        "tier",
        [
            "Basic",
            "Standard",
            "Premium",
            "PremiumV2",
            "PremiumV3",
            "PremiumV4",
            "Isolated",
            "IsolatedV2",
        ],
    )
    def test_known_paid_tier_emits(self, tier):
        plan = _make_plan(f"plan-{tier.lower()}", tier=tier)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert len(findings) == 1, f"Expected emission for tier={tier}"

    @pytest.mark.parametrize(
        "tier",
        [
            "Free",
            "Shared",
            "Dynamic",
            "ElasticPremium",
            "WorkflowStandard",
            "FlexConsumption",
            "LinuxDynamic",
            "LinuxFree",
            "UnknownFutureValue",
        ],
    )
    def test_non_paid_or_unrecognized_tier_skipped(self, tier):
        plan = _make_plan(f"plan-{tier.lower()}", tier=tier)
        client = _make_client([plan])
        findings = find_empty_app_service_plans(subscription_id=SUB, credential=None, client=client)
        assert findings == [], f"Expected skip for tier={tier}"
