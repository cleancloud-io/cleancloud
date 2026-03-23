from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.app_service_idle import find_idle_app_services


def _make_app(
    name: str,
    location: str = "eastus",
    state: str = "Running",
    sku_tier: str = "Standard",
    kind: str = "app",
    tags: dict = None,
) -> SimpleNamespace:
    app_id = f"/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Web/sites/{name}"
    sku = SimpleNamespace(tier=sku_tier) if sku_tier else None
    return SimpleNamespace(
        id=app_id,
        name=name,
        location=location,
        state=state,
        sku=sku,
        kind=kind,
        tags=tags or {},
    )


def _make_metric_response(total_value: float = 0.0) -> SimpleNamespace:
    data_point = SimpleNamespace(total=total_value)
    timeseries = SimpleNamespace(data=[data_point])
    metric = SimpleNamespace(timeseries=[timeseries])
    return SimpleNamespace(value=[metric])


@pytest.fixture
def mock_web_client(mocker):
    return mocker.MagicMock()


@pytest.fixture
def mock_monitor_client(mocker):
    return mocker.MagicMock()


class TestFindIdleAppServices:
    def test_idle_app_flagged(self, mock_web_client, mock_monitor_client):
        app = _make_app("idle-app", sku_tier="Standard")
        mock_web_client.web_apps.list.return_value = [app]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "azure.app_service.idle"
        assert f.provider == "azure"
        assert f.resource_type == "azure.app_service"
        assert "idle-app" in f.resource_id

    def test_active_app_not_flagged(self, mock_web_client, mock_monitor_client):
        app = _make_app("active-app", sku_tier="Standard")
        mock_web_client.web_apps.list.return_value = [app]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(100)

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_free_tier_skipped(self, mock_web_client, mock_monitor_client):
        app = _make_app("free-app", sku_tier="Free")
        mock_web_client.web_apps.list.return_value = [app]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_shared_tier_skipped(self, mock_web_client, mock_monitor_client):
        app = _make_app("shared-app", sku_tier="Shared")
        mock_web_client.web_apps.list.return_value = [app]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_consumption_function_app_skipped(self, mock_web_client, mock_monitor_client):
        app = _make_app("func-app", sku_tier=None, kind="functionapp")
        mock_web_client.web_apps.list.return_value = [app]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_stopped_app_skipped(self, mock_web_client, mock_monitor_client):
        app = _make_app("stopped-app", state="Stopped", sku_tier="Standard")
        mock_web_client.web_apps.list.return_value = [app]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_region_filter(self, mock_web_client, mock_monitor_client):
        app_east = _make_app("app-east", location="eastus", sku_tier="Standard")
        app_west = _make_app("app-west", location="westus", sku_tier="Standard")
        mock_web_client.web_apps.list.return_value = [app_east, app_west]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            region_filter="westus",
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert len(findings) == 1
        assert "app-west" in findings[0].resource_id

    def test_cost_estimate_standard(self, mock_web_client, mock_monitor_client):
        app = _make_app("app-cost", sku_tier="Standard")
        mock_web_client.web_apps.list.return_value = [app]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert findings[0].estimated_monthly_cost_usd == 73.0

    def test_details_populated(self, mock_web_client, mock_monitor_client):
        app = _make_app("detail-app", sku_tier="Premium", tags={"env": "staging"})
        mock_web_client.web_apps.list.return_value = [app]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        d = findings[0].details
        assert d["app_name"] == "detail-app"
        assert d["sku_tier"] == "Premium"
        assert d["tags"] == {"env": "staging"}

    def test_metrics_failure_conservative(self, mock_web_client, mock_monitor_client):
        """If monitor metrics fail, app should NOT be flagged (avoid false positives)."""
        app = _make_app("app-metricfail", sku_tier="Standard")
        mock_web_client.web_apps.list.return_value = [app]
        mock_monitor_client.metrics.list.side_effect = Exception("monitor unavailable")

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_empty_subscription(self, mock_web_client, mock_monitor_client):
        mock_web_client.web_apps.list.return_value = []

        findings = find_idle_app_services(
            subscription_id="sub-123",
            credential=None,
            client=mock_web_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []
