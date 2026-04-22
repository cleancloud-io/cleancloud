"""
Spec-driven tests for azure.app_service.idle rule.

Spec: docs/specs/azure/app_service_idle.md

Detection intent:
    Emit only when ALL of the following are true:
      1. top-level app (not deployment slot)
      2. state == Running
      3. enabled == true
      4. kind does not contain functionapp or workflowapp
      5. paid App Service Plan (not Free/Shared/Dynamic/unknown)
      6. zero WebJobs (and WebJobs call succeeds)
      7. all four Azure Monitor metrics are zero over the idle window:
         Requests, CpuTime, BytesReceived, BytesSent
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import AzureError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.azure.rules.app_service_idle import find_idle_app_services

# ---------------------------------------------------------------------------
# Test data builders
# ---------------------------------------------------------------------------

SUB = "sub-123"
RG = "rg-test"
APP_BASE = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites"


def _app_id(name: str) -> str:
    return f"{APP_BASE}/{name}"


def _make_app(
    name: str = "test-app",
    location: str = "eastus",
    state: str = "Running",
    enabled: bool = True,
    sku_tier: str = "Standard",
    kind: str = "app",
    server_farm_id: str = None,
    slot_name: str = None,
    parent_site_name: str = None,
    tags: dict = None,
    app_id: str = None,
) -> SimpleNamespace:
    aid = app_id or _app_id(name)
    sku = SimpleNamespace(tier=sku_tier) if sku_tier else None
    return SimpleNamespace(
        id=aid,
        name=name,
        location=location,
        state=state,
        enabled=enabled,
        sku=sku,
        kind=kind,
        server_farm_id=server_farm_id,
        slot_name=slot_name,
        parent_site_name=parent_site_name,
        tags=tags or {},
    )


def _zero_metric_response() -> SimpleNamespace:
    """Azure Monitor response with a single zero datapoint."""
    data_point = SimpleNamespace(total=0.0)
    timeseries = SimpleNamespace(data=[data_point])
    metric = SimpleNamespace(timeseries=[timeseries])
    return SimpleNamespace(value=[metric])


def _nonzero_metric_response(value: float = 100.0) -> SimpleNamespace:
    data_point = SimpleNamespace(total=value)
    timeseries = SimpleNamespace(data=[data_point])
    metric = SimpleNamespace(timeseries=[timeseries])
    return SimpleNamespace(value=[metric])


def _make_client(apps, plans=None, webjobs=None):
    """Build a mock WebSiteManagementClient."""
    client = MagicMock()
    client.web_apps.list.return_value = apps
    client.app_service_plans.list.return_value = plans or []
    client.web_apps.list_web_jobs.return_value = webjobs if webjobs is not None else []
    return client


def _make_monitor(metric_response=None):
    """Build a mock MonitorManagementClient returning a given metric response."""
    client = MagicMock()
    client.metrics.list.return_value = metric_response or _zero_metric_response()
    return client


# ---------------------------------------------------------------------------
# TestMustEmit — scenarios that must produce a finding
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_basic_idle_app_emits(self):
        """Standard idle app on paid plan with all metrics zero → EMIT."""
        app = _make_app("idle-app", sku_tier="Standard")
        web = _make_client([app])
        mon = _make_monitor(_zero_metric_response())

        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "azure.app_service.idle"
        assert f.provider == "azure"
        assert f.resource_type == "azure.app_service"
        assert f.resource_id == _app_id("idle-app")

    def test_idle_app_premium_tier(self):
        app = _make_app("prem-app", sku_tier="Premium")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert len(findings) == 1

    def test_idle_app_basic_tier(self):
        app = _make_app("basic-app", sku_tier="Basic")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert len(findings) == 1

    def test_plan_lookup_used_when_server_farm_id_matches(self):
        """When server_farm_id resolves in plan_tiers lookup, app is evaluated correctly."""
        farm_id = (
            f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/serverfarms/plan-1"
        )
        plan = SimpleNamespace(
            id=farm_id,
            sku=SimpleNamespace(tier="Standard"),
            number_of_sites=3,
        )
        app = _make_app("plan-app", sku_tier=None, server_farm_id=farm_id)
        # Remove sku from app so it relies on plan lookup
        app.sku = None
        web = _make_client([app], plans=[plan])
        mon = _make_monitor()

        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert len(findings) == 1
        assert findings[0].details.get("app_service_plan_site_count") == 3

    def test_plan_lookup_tolerates_trailing_slash_in_server_farm_id(self):
        """ARM ID normalization: trailing slash in server_farm_id does not cause a cache miss."""
        farm_id = (
            f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/serverfarms/plan-1"
        )
        plan = SimpleNamespace(id=farm_id, sku=SimpleNamespace(tier="Standard"), number_of_sites=1)
        app = _make_app("slash-app", sku_tier=None, server_farm_id=farm_id + "/")
        app.sku = None
        web = _make_client([app], plans=[plan])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert len(findings) == 1

    def test_partial_plan_list_failure_clears_cache_uses_embedded_sku(self):
        """Mid-iteration plan list failure clears partial cache; all apps use embedded SKU.

        If partial cache is kept, an app whose plan was cached with a non-paid tier
        (e.g. Free) would be skipped even though the app's own embedded SKU says Standard.
        Clearing ensures consistent evaluation: either all apps use the plan cache or none do.
        """
        farm_id = (
            f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/serverfarms/plan-1"
        )
        # Plan cache would record this farm_id as "Free" (non-paid)
        partial_plan = SimpleNamespace(
            id=farm_id, sku=SimpleNamespace(tier="Free"), number_of_sites=1
        )
        # App has Standard in its embedded sku — the correct tier
        app = _make_app("partial-cache-app", sku_tier="Standard", server_farm_id=farm_id)

        web = _make_client([app])

        # Plan list yields the Free-tier plan then raises mid-iteration
        def _partial_iter():
            yield partial_plan
            raise AzureError("pager failed on page 2")

        web.app_service_plans.list.side_effect = _partial_iter
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        # Partial cache cleared → embedded sku "Standard" used → emits
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestMustSkip — mandatory exclusions from spec 8
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_missing_resource_id_skipped(self):
        """spec 8.1: resource_id absent → SKIP."""
        app = _make_app("no-id-app")
        app.id = None
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_stopped_app_skipped(self):
        """spec 8.3: state != Running → SKIP."""
        app = _make_app("stopped-app", state="Stopped")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_disabled_app_skipped(self):
        """spec 8.4: enabled == false → SKIP."""
        app = _make_app("disabled-app", enabled=False)
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_deployment_slot_arm_id_skipped(self):
        """spec 8.5: ARM id contains /slots/ → SKIP."""
        slot_id = f"{APP_BASE}/parent-app/slots/staging"
        app = _make_app("staging", app_id=slot_id)
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_deployment_slot_slot_name_field_skipped(self):
        """spec 8.5: slot_name field present → SKIP."""
        app = _make_app("slot-field-app", slot_name="production")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_deployment_slot_parent_site_name_skipped(self):
        """spec 8.5: parent_site_name field present → SKIP."""
        app = _make_app("parent-slot-app", parent_site_name="main-app")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_function_app_kind_skipped(self):
        """spec 8.6: kind contains functionapp → SKIP."""
        app = _make_app("func-app", kind="functionapp")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_function_app_on_paid_plan_skipped(self):
        """spec 8.6: Function App on Premium plan (not consumption) still skipped by kind."""
        app = _make_app("func-premium", kind="functionapp", sku_tier="PremiumV2")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_workflow_app_skipped(self):
        """spec 8.7: kind contains workflowapp → SKIP."""
        app = _make_app("logic-app", kind="app,workflowapp")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_free_tier_skipped(self):
        """spec 8.8: Free tier → SKIP."""
        app = _make_app("free-app", sku_tier="Free")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_shared_tier_skipped(self):
        """spec 8.8: Shared tier → SKIP."""
        app = _make_app("shared-app", sku_tier="Shared")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_dynamic_tier_skipped(self):
        """spec 8.8: Dynamic (Consumption/serverless) tier → SKIP."""
        app = _make_app("consumption-app", sku_tier="Dynamic")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_unknown_tier_skipped(self):
        """spec 8.8: tier unknown (None) → SKIP."""
        app = _make_app("no-tier-app", sku_tier=None)
        app.sku = None
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_unrecognized_tier_string_skipped(self):
        """spec 8.8: unrecognized non-empty tier string → SKIP.

        Any tier not in the known paid-tier allowlist is treated as unknown/unusable.
        This is the conservative contract: if we cannot confirm the tier is a known
        paid dedicated-compute plan, we do not emit.
        """
        app = _make_app("unknown-tier-app", sku_tier="FlexConsumption")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_nonzero_requests_skipped(self):
        """spec 8.12: Requests > 0 → SKIP."""
        app = _make_app("active-requests")
        web = _make_client([app])
        mon = _make_monitor(_nonzero_metric_response())
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_nonzero_cputime_skipped(self):
        """spec 13.2 item 5: zero Requests but non-zero CpuTime → SKIP."""
        app = _make_app("cpu-active")
        web = _make_client([app])
        mon = MagicMock()

        # Requests = 0, CpuTime = non-zero, others irrelevant
        def metric_side_effect(resource_uri, metricnames, **kwargs):
            if metricnames == "Requests":
                return _zero_metric_response()
            if metricnames == "CpuTime":
                return _nonzero_metric_response(50.0)
            return _zero_metric_response()

        mon.metrics.list.side_effect = metric_side_effect
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_nonzero_bytes_sent_skipped(self):
        """spec 13.2 item 6: zero Requests but non-zero BytesSent → SKIP."""
        app = _make_app("bytes-active")
        web = _make_client([app])
        mon = MagicMock()

        def metric_side_effect(resource_uri, metricnames, **kwargs):
            if metricnames == "BytesSent":
                return _nonzero_metric_response(1024.0)
            return _zero_metric_response()

        mon.metrics.list.side_effect = metric_side_effect
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_nonzero_bytes_received_skipped(self):
        """spec 13.2 item 6: non-zero BytesReceived → SKIP."""
        app = _make_app("bytes-rx-active")
        web = _make_client([app])
        mon = MagicMock()

        def metric_side_effect(resource_uri, metricnames, **kwargs):
            if metricnames == "BytesReceived":
                return _nonzero_metric_response(512.0)
            return _zero_metric_response()

        mon.metrics.list.side_effect = metric_side_effect
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_metric_failure_causes_skip(self):
        """spec 8.11 / 13.2 item 7: any metric query fails → SKIP (conservative)."""
        app = _make_app("metric-fail")
        web = _make_client([app])
        mon = MagicMock()
        mon.metrics.list.side_effect = Exception("monitor unavailable")
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_webjobs_enumeration_failure_causes_skip(self):
        """spec 10 / 13.2 item 8: WebJobs list call fails → SKIP."""
        app = _make_app("webjob-fail")
        web = _make_client([app])
        web.web_apps.list_web_jobs.side_effect = Exception("403 Forbidden")
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_app_with_one_webjob_skipped(self):
        """spec 10 / 13.2 item 4: one WebJob present → SKIP."""
        app = _make_app("webjob-app")
        webjob = SimpleNamespace(name="background-worker", type="Triggered")
        web = _make_client([app], webjobs=[webjob])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_empty_subscription_no_findings(self):
        """No apps → no findings."""
        web = _make_client([])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []


# ---------------------------------------------------------------------------
# TestRegionFilter
# ---------------------------------------------------------------------------


class TestRegionFilter:
    def test_region_filter_excludes_other_regions(self):
        app_east = _make_app("app-east", location="eastus")
        app_west = _make_app("app-west", location="westus")
        web = _make_client([app_east, app_west])
        mon = _make_monitor()

        findings = find_idle_app_services(
            subscription_id=SUB,
            credential=None,
            region_filter="westus",
            client=web,
            monitor_client=mon,
        )
        assert len(findings) == 1
        assert "app-west" in findings[0].resource_id

    def test_no_region_filter_scans_all(self):
        app_east = _make_app("app-east", location="eastus")
        app_west = _make_app("app-west", location="westus")
        web = _make_client([app_east, app_west])
        mon = _make_monitor()

        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# TestFindingShape — required finding fields per spec 12.1
# ---------------------------------------------------------------------------


class TestFindingShape:
    def _get_finding(self):
        app = _make_app("shape-app", sku_tier="Standard")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert len(findings) == 1
        return findings[0]

    def test_provider(self):
        assert self._get_finding().provider == "azure"

    def test_rule_id(self):
        assert self._get_finding().rule_id == "azure.app_service.idle"

    def test_resource_type(self):
        assert self._get_finding().resource_type == "azure.app_service"

    def test_risk_is_medium(self):
        assert self._get_finding().risk == RiskLevel.MEDIUM

    def test_confidence_is_high(self):
        assert self._get_finding().confidence == ConfidenceLevel.HIGH

    def test_estimated_monthly_cost_is_none(self):
        """spec 11: plan-level billing → estimated_monthly_cost_usd must be None."""
        assert self._get_finding().estimated_monthly_cost_usd is None

    def test_resource_id_is_arm_id(self):
        assert self._get_finding().resource_id == _app_id("shape-app")

    def test_region_is_normalized(self):
        assert self._get_finding().region == "eastus"


# ---------------------------------------------------------------------------
# TestEvidenceContract — signals_used, signals_not_checked, details
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def _get_finding_with_details(self, tags=None, server_farm_id=None):
        app = _make_app(
            "ev-app",
            sku_tier="Standard",
            tags=tags,
            server_farm_id=server_farm_id,
        )
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert len(findings) == 1
        return findings[0]

    def test_signals_used_contains_state(self):
        f = self._get_finding_with_details()
        assert any("Running" in s for s in f.evidence.signals_used)

    def test_signals_used_contains_kind(self):
        f = self._get_finding_with_details()
        assert any("kind" in s.lower() for s in f.evidence.signals_used)

    def test_signals_used_contains_plan_tier(self):
        f = self._get_finding_with_details()
        assert any("Standard" in s for s in f.evidence.signals_used)

    def test_signals_used_contains_zero_webjobs(self):
        f = self._get_finding_with_details()
        assert any("WebJob" in s for s in f.evidence.signals_used)

    def test_signals_used_contains_requests_zero(self):
        f = self._get_finding_with_details()
        assert any("Requests" in s and "0" in s for s in f.evidence.signals_used)

    def test_signals_used_contains_cputime_zero(self):
        f = self._get_finding_with_details()
        assert any("CpuTime" in s and "0" in s for s in f.evidence.signals_used)

    def test_signals_used_contains_bytes_received_zero(self):
        f = self._get_finding_with_details()
        assert any("BytesReceived" in s and "0" in s for s in f.evidence.signals_used)

    def test_signals_used_contains_bytes_sent_zero(self):
        f = self._get_finding_with_details()
        assert any("BytesSent" in s and "0" in s for s in f.evidence.signals_used)

    def test_signals_used_contains_billing_note_for_paid_tier(self):
        """Informational billing context note must appear for paid tiers with cost data."""
        f = self._get_finding_with_details()
        assert any(
            "plan-scoped" in s.lower() or "informational" in s.lower()
            for s in f.evidence.signals_used
        )

    def test_signals_not_checked_present(self):
        f = self._get_finding_with_details()
        assert len(f.evidence.signals_not_checked) >= 1

    def test_details_app_name(self):
        assert self._get_finding_with_details().details["app_name"] == "ev-app"

    def test_details_sku_tier(self):
        assert self._get_finding_with_details().details["sku_tier"] == "Standard"

    def test_details_location(self):
        assert self._get_finding_with_details().details["location"] == "eastus"

    def test_details_idle_days_threshold(self):
        assert self._get_finding_with_details().details["idle_days_threshold"] == 14

    def test_details_kind(self):
        assert "kind" in self._get_finding_with_details().details

    def test_details_tags_when_present(self):
        f = self._get_finding_with_details(tags={"env": "staging"})
        assert f.details["tags"] == {"env": "staging"}

    def test_details_server_farm_id_when_present(self):
        farm_id = (
            "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Web/serverfarms/plan-1"
        )
        f = self._get_finding_with_details(server_farm_id=farm_id)
        assert f.details.get("server_farm_id") == farm_id

    def test_details_plan_cost_floor_for_known_tier(self):
        """plan_monthly_cost_floor_usd present for known paid tiers."""
        app = _make_app("cost-app", sku_tier="Standard")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert "plan_monthly_cost_floor_usd" in findings[0].details

    def test_details_no_tags_key_when_no_tags(self):
        """tags should be omitted from details when the app has no tags."""
        f = self._get_finding_with_details(tags={})
        assert "tags" not in f.details

    def test_time_window_in_evidence(self):
        f = self._get_finding_with_details()
        assert "14" in f.evidence.time_window


# ---------------------------------------------------------------------------
# TestAllFourMetricsRequired — spec 9: all four must be zero
# ---------------------------------------------------------------------------


class TestAllFourMetricsRequired:
    @pytest.mark.parametrize(
        "nonzero_metric", ["Requests", "CpuTime", "BytesReceived", "BytesSent"]
    )
    def test_single_nonzero_metric_prevents_emission(self, nonzero_metric):
        """Each metric independently gates emission — one non-zero metric = skip."""
        app = _make_app("metric-gate")
        web = _make_client([app])
        mon = MagicMock()

        def side_effect(resource_uri, metricnames, **kwargs):
            if metricnames == nonzero_metric:
                return _nonzero_metric_response(42.0)
            return _zero_metric_response()

        mon.metrics.list.side_effect = side_effect
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == [], f"Expected skip when {nonzero_metric} is non-zero"

    @pytest.mark.parametrize(
        "failing_metric", ["Requests", "CpuTime", "BytesReceived", "BytesSent"]
    )
    def test_single_failing_metric_prevents_emission(self, failing_metric):
        """Each metric failure independently gates emission — one failure = skip."""
        app = _make_app("metric-fail-gate")
        web = _make_client([app])
        mon = MagicMock()

        def side_effect(resource_uri, metricnames, **kwargs):
            if metricnames == failing_metric:
                raise Exception("monitor error")
            return _zero_metric_response()

        mon.metrics.list.side_effect = side_effect
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == [], f"Expected skip when {failing_metric} metric fails"

    def test_all_four_zero_emits(self):
        """All four zero → EMIT exactly once."""
        app = _make_app("all-zero")
        web = _make_client([app])
        mon = _make_monitor(_zero_metric_response())
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestWebJobs — spec 10
# ---------------------------------------------------------------------------


class TestWebJobs:
    def test_zero_webjobs_allows_emission(self):
        """Zero WebJobs → continue to emission."""
        app = _make_app("zero-wj")
        web = _make_client([app], webjobs=[])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert len(findings) == 1

    def test_one_webjob_prevents_emission(self):
        """One WebJob → SKIP."""
        app = _make_app("one-wj")
        wj = SimpleNamespace(name="scheduled-job")
        web = _make_client([app], webjobs=[wj])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_multiple_webjobs_prevents_emission(self):
        wj1 = SimpleNamespace(name="job-1")
        wj2 = SimpleNamespace(name="job-2")
        app = _make_app("multi-wj")
        web = _make_client([app], webjobs=[wj1, wj2])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_webjobs_list_exception_prevents_emission(self):
        """WebJobs enumeration failure → SKIP (conservative)."""
        app = _make_app("wj-fail")
        web = _make_client([app])
        web.web_apps.list_web_jobs.side_effect = Exception("permission denied")
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_webjobs_called_with_correct_resource_group(self):
        """WebJobs call must use the resource group extracted from the ARM id."""
        app = _make_app("wj-rg-test")
        web = _make_client([app])
        mon = _make_monitor()
        find_idle_app_services(subscription_id=SUB, credential=None, client=web, monitor_client=mon)
        call_kwargs = web.web_apps.list_web_jobs.call_args
        assert call_kwargs is not None
        # resource_group_name must be the RG from the ARM id
        rg_arg = call_kwargs.kwargs.get("resource_group_name") or (
            call_kwargs.args[0] if call_kwargs.args else None
        )
        assert rg_arg == RG, f"Expected resource_group_name={RG!r}, got {rg_arg!r}"

    def test_mid_iteration_failure_skips(self):
        """Exception raised mid-iteration → inventory_complete stays False → SKIP.

        Spec 10: partial/incomplete/truncated inventory must skip.
        This covers pagers that yield some items then fail on a later page.
        """
        app = _make_app("mid-iter-fail")
        web = _make_client([app])
        mon = _make_monitor()

        def _failing_iter(*args, **kwargs):
            # Yield nothing, then raise — simulates a pager that fails before
            # returning any results (first page network error, etc.)
            raise Exception("pager failed mid-iteration")
            yield  # noqa: unreachable — makes this a generator

        web.web_apps.list_web_jobs.side_effect = _failing_iter
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []

    def test_malformed_arm_id_skips_before_webjobs_call(self):
        """ARM id that yields no resource group → skip without calling list_web_jobs.

        Spec 10: if WebJobs inventory cannot be formed reliably, skip.
        An ARM id without a 'resourcegroups' segment means _resource_group_from_id
        returns '' — calling list_web_jobs with an empty resource group would not
        be a reliable inventory, so the app must be skipped.
        """
        app = _make_app(
            "malformed-rg",
            app_id="/malformed/id/missing/resource/groups/segment",
        )
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB, credential=None, client=web, monitor_client=mon
        )
        assert findings == []
        web.web_apps.list_web_jobs.assert_not_called()


# ---------------------------------------------------------------------------
# TestCustomIdleDays
# ---------------------------------------------------------------------------


class TestCustomIdleDays:
    def test_custom_idle_days_in_details(self):
        app = _make_app("custom-days")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB,
            credential=None,
            client=web,
            monitor_client=mon,
            idle_days=30,
        )
        assert len(findings) == 1
        assert findings[0].details["idle_days_threshold"] == 30

    def test_custom_idle_days_in_evidence_time_window(self):
        app = _make_app("custom-tw")
        web = _make_client([app])
        mon = _make_monitor()
        findings = find_idle_app_services(
            subscription_id=SUB,
            credential=None,
            client=web,
            monitor_client=mon,
            idle_days=7,
        )
        assert "7" in findings[0].evidence.time_window
