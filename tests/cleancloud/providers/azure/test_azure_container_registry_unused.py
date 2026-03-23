from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.container_registry_unused import (
    find_unused_container_registries,
)


def _make_registry(
    name: str,
    location: str = "eastus",
    sku_name: str = "Standard",
    provisioning_state: str = "Succeeded",
    tags: dict = None,
) -> SimpleNamespace:
    registry_id = (
        f"/subscriptions/sub-123/resourceGroups/rg-test"
        f"/providers/Microsoft.ContainerRegistry/registries/{name}"
    )
    sku = SimpleNamespace(name=sku_name)
    return SimpleNamespace(
        id=registry_id,
        name=name,
        location=location,
        sku=sku,
        provisioning_state=provisioning_state,
        tags=tags or {},
    )


def _make_metric_response(total_value: float = 0.0) -> SimpleNamespace:
    data_point = SimpleNamespace(total=total_value)
    timeseries = SimpleNamespace(data=[data_point])
    metric = SimpleNamespace(timeseries=[timeseries])
    return SimpleNamespace(value=[metric])


@pytest.fixture
def mock_acr_client(mocker):
    return mocker.MagicMock()


@pytest.fixture
def mock_monitor_client(mocker):
    return mocker.MagicMock()


class TestFindUnusedContainerRegistries:
    def test_unused_registry_flagged(self, mock_acr_client, mock_monitor_client):
        registry = _make_registry("unused-acr")
        mock_acr_client.registries.list.return_value = [registry]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "azure.container_registry.unused"
        assert f.provider == "azure"
        assert f.resource_type == "azure.container_registry"
        assert "unused-acr" in f.resource_id

    def test_active_registry_not_flagged(self, mock_acr_client, mock_monitor_client):
        registry = _make_registry("active-acr")
        mock_acr_client.registries.list.return_value = [registry]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(50)

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_push_only_registry_not_flagged(self, mock_acr_client, mock_monitor_client):
        """Registry with zero pulls but active pushes (CI build pipeline) should not be flagged."""
        registry = _make_registry("ci-push-acr")
        mock_acr_client.registries.list.return_value = [registry]
        # First call (pulls) returns 0, second call (pushes) returns active
        mock_monitor_client.metrics.list.side_effect = [
            _make_metric_response(0),  # SuccessfulPullCount = 0
            _make_metric_response(120),  # SuccessfulPushCount = 120
        ]

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_non_succeeded_registry_skipped(self, mock_acr_client, mock_monitor_client):
        registry = _make_registry("provisioning-acr", provisioning_state="Creating")
        mock_acr_client.registries.list.return_value = [registry]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_region_filter(self, mock_acr_client, mock_monitor_client):
        acr_east = _make_registry("acr-east", location="eastus")
        acr_west = _make_registry("acr-west", location="westus")
        mock_acr_client.registries.list.return_value = [acr_east, acr_west]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            region_filter="eastus",
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert len(findings) == 1
        assert "acr-east" in findings[0].resource_id

    def test_cost_estimate_standard(self, mock_acr_client, mock_monitor_client):
        registry = _make_registry("acr-cost", sku_name="Standard")
        mock_acr_client.registries.list.return_value = [registry]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert findings[0].estimated_monthly_cost_usd == 20.0

    def test_cost_estimate_premium(self, mock_acr_client, mock_monitor_client):
        registry = _make_registry("acr-premium", sku_name="Premium")
        mock_acr_client.registries.list.return_value = [registry]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert findings[0].estimated_monthly_cost_usd == 50.0

    def test_details_populated(self, mock_acr_client, mock_monitor_client):
        registry = _make_registry("detail-acr", sku_name="Premium", tags={"team": "platform"})
        mock_acr_client.registries.list.return_value = [registry]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        d = findings[0].details
        assert d["registry_name"] == "detail-acr"
        assert d["sku"] == "Premium"
        assert d["tags"] == {"team": "platform"}
        assert d["days_unused_threshold"] == 90

    def test_custom_threshold(self, mock_acr_client, mock_monitor_client):
        registry = _make_registry("acr-threshold")
        mock_acr_client.registries.list.return_value = [registry]
        mock_monitor_client.metrics.list.return_value = _make_metric_response(0)

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            days_unused=30,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert findings[0].details["days_unused_threshold"] == 30

    def test_metrics_failure_conservative(self, mock_acr_client, mock_monitor_client):
        """If monitor metrics fail, registry should NOT be flagged."""
        registry = _make_registry("acr-metricfail")
        mock_acr_client.registries.list.return_value = [registry]
        mock_monitor_client.metrics.list.side_effect = Exception("monitor unavailable")

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []

    def test_empty_subscription(self, mock_acr_client, mock_monitor_client):
        mock_acr_client.registries.list.return_value = []

        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=mock_acr_client,
            monitor_client=mock_monitor_client,
        )

        assert findings == []
