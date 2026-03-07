from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.app_service_plan_empty import (
    find_empty_app_service_plans,
)


def _make_plan(
    name,
    tier,
    sku_name,
    number_of_sites,
    location="eastus",
    tags=None,
    provisioning_state="Succeeded",
):
    return SimpleNamespace(
        id=f"/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Web/serverfarms/{name}",
        name=name,
        location=location,
        sku=SimpleNamespace(name=sku_name, tier=tier, capacity=1),
        number_of_sites=number_of_sites,
        provisioning_state=provisioning_state,
        tags=tags,
    )


@pytest.fixture
def mock_web_client(mocker):
    plans = [
        # Paid + empty → should be flagged
        _make_plan("plan-empty-standard", "Standard", "S1", 0),
        # Paid + has apps → skip
        _make_plan("plan-with-apps", "Premium", "P1", 3),
        # Free + empty → skip (no cost signal)
        _make_plan("plan-free-empty", "Free", "F1", 0),
        # Shared + empty → skip (no cost signal)
        _make_plan("plan-shared-empty", "Shared", "D1", 0),
        # Paid + empty but still provisioning → skip
        _make_plan("plan-provisioning", "Standard", "S1", 0, provisioning_state="Creating"),
    ]
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = plans
    # Secondary API call confirms no apps
    client.app_service_plans.list_web_apps.return_value = []
    return client


def test_find_empty_app_service_plans(mock_web_client):
    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=mock_web_client,
    )
    resource_ids = [f.resource_id for f in findings]

    # Only the paid empty plan should be flagged
    assert len(findings) == 1
    assert "plan-empty-standard" in resource_ids[0]

    finding = findings[0]
    assert finding.provider == "azure"
    assert finding.rule_id == "azure.app_service_plan.empty"
    assert finding.confidence.value == "high"
    assert finding.risk.value == "low"
    assert finding.details["sku_tier"] == "Standard"
    assert finding.details["confirmed_web_apps"] == 0
    assert finding.estimated_monthly_cost_usd == 73.0  # Standard tier


def test_find_empty_app_service_plans_empty_subscription(mocker):
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = []
    client.app_service_plans.list_web_apps.return_value = []

    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert findings == []


def test_find_empty_app_service_plans_region_filter(mocker):
    plans = [
        _make_plan("plan-east", "Standard", "S1", 0, location="eastus"),
        _make_plan("plan-west", "Standard", "S1", 0, location="westus"),
    ]
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = plans
    client.app_service_plans.list_web_apps.return_value = []

    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=client,
    )
    assert len(findings) == 1
    assert "plan-east" in findings[0].resource_id


def test_find_empty_app_service_plans_region_filter_display_name(mocker):
    """Azure Web SDK returns display names ('West Europe') not short names ('westeurope')."""
    plans = [
        _make_plan("plan-west-eu", "Standard", "S1", 0, location="West Europe"),
    ]
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = plans
    client.app_service_plans.list_web_apps.return_value = []

    # Short name should match display name
    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        region_filter="westeurope",
        client=client,
    )
    assert len(findings) == 1
    # Region in output should be normalized to short name
    assert findings[0].region == "westeurope"

    # Non-matching region
    findings2 = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=client,
    )
    assert len(findings2) == 0


def test_find_empty_app_service_plans_premium_tiers(mocker):
    """Verify various paid tiers are all flagged when empty."""
    plans = [
        _make_plan("plan-basic", "Basic", "B1", 0),
        _make_plan("plan-premiumv2", "PremiumV2", "P1v2", 0),
        _make_plan("plan-isolated", "Isolated", "I1", 0),
    ]
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = plans
    client.app_service_plans.list_web_apps.return_value = []

    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert len(findings) == 3
    tiers = [f.details["sku_tier"] for f in findings]
    assert "Basic" in tiers
    assert "PremiumV2" in tiers
    assert "Isolated" in tiers


def test_number_of_sites_zero_but_apps_exist_not_flagged(mocker):
    """number_of_sites=0 from list API is unreliable — must be confirmed by list_web_apps()."""
    plans = [_make_plan("plan-has-apps", "Standard", "S1", 0)]
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = plans
    # Secondary call reveals apps actually exist
    client.app_service_plans.list_web_apps.return_value = [object()]

    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert findings == []


def test_number_of_sites_none_treated_as_empty(mocker):
    """Azure can return None for number_of_sites — should be treated as potentially empty."""
    plans = [_make_plan("plan-sites-none", "Standard", "S1", None)]
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = plans
    client.app_service_plans.list_web_apps.return_value = []

    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert len(findings) == 1


def test_dynamic_tier_skipped(mocker):
    """Consumption/serverless plans (Dynamic tier) have no idle cost — should be skipped."""
    plans = [_make_plan("plan-consumption", "Dynamic", "Y1", 0)]
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = plans
    client.app_service_plans.list_web_apps.return_value = []

    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert findings == []


def test_cost_multiplied_by_capacity(mocker):
    """Cost should reflect instance count — 2x Standard = ~$146, not ~$73."""
    plan = SimpleNamespace(
        id="/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Web/serverfarms/plan-scaled",
        name="plan-scaled",
        location="eastus",
        sku=SimpleNamespace(name="S1", tier="Standard", capacity=2),
        number_of_sites=0,
        provisioning_state="Succeeded",
        tags=None,
    )
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = [plan]
    client.app_service_plans.list_web_apps.return_value = []

    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == 146.0  # 73.0 * 2


def test_list_web_apps_exception_skips_conservatively(mocker):
    """If list_web_apps() raises, skip the plan rather than risk a false positive."""
    plans = [_make_plan("plan-api-error", "Standard", "S1", 0)]
    client = mocker.MagicMock()
    client.app_service_plans.list.return_value = plans
    client.app_service_plans.list_web_apps.side_effect = Exception("API error")

    findings = find_empty_app_service_plans(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert findings == []
