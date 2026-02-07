from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.vnet_gateway_idle import (
    find_idle_vnet_gateways,
)


def _make_gateway_resource(name, resource_group="rg-test"):
    return SimpleNamespace(
        id=f"/subscriptions/sub-123/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworkGateways/{name}",
        name=name,
    )


def _make_gateway(
    name,
    gateway_type="Vpn",
    sku_name="VpnGw1",
    sku_tier="VpnGw1",
    location="eastus",
    tags=None,
    provisioning_state="Succeeded",
    vpn_client_configuration=None,
):
    return SimpleNamespace(
        id=f"/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworkGateways/{name}",
        name=name,
        location=location,
        gateway_type=gateway_type,
        sku=SimpleNamespace(name=sku_name, tier=sku_tier, capacity=2),
        provisioning_state=provisioning_state,
        vpn_client_configuration=vpn_client_configuration,
        tags=tags,
    )


def _make_connection(name, status="Connected"):
    return SimpleNamespace(
        name=name,
        connection_status=status,
    )


@pytest.fixture
def mock_clients(mocker):
    """Create mock network and resource clients."""
    # Gateway resources (from ResourceManagementClient)
    gateway_resources = [
        _make_gateway_resource("vpn-idle"),
        _make_gateway_resource("vpn-active"),
        _make_gateway_resource("er-idle"),
        _make_gateway_resource("vpn-provisioning"),
        _make_gateway_resource("vpn-with-p2s"),
    ]

    # Full gateway details (from NetworkManagementClient.get)
    gateways = {
        "vpn-idle": _make_gateway("vpn-idle", gateway_type="Vpn"),
        "vpn-active": _make_gateway("vpn-active", gateway_type="Vpn"),
        "er-idle": _make_gateway(
            "er-idle",
            gateway_type="ExpressRoute",
            sku_name="Standard",
            sku_tier="Standard",
        ),
        "vpn-provisioning": _make_gateway(
            "vpn-provisioning",
            gateway_type="Vpn",
            provisioning_state="Updating",
        ),
        "vpn-with-p2s": _make_gateway(
            "vpn-with-p2s",
            gateway_type="Vpn",
            vpn_client_configuration=SimpleNamespace(
                vpn_client_address_pool=SimpleNamespace(address_prefixes=["10.0.0.0/24"])
            ),
        ),
    }

    # Connections per gateway
    connections = {
        "vpn-idle": [],  # No connections - should be flagged
        "vpn-active": [_make_connection("conn1", "Connected")],  # Active - skip
        "er-idle": [],  # No connections - should be flagged
        "vpn-provisioning": [],  # Provisioning - skip
        "vpn-with-p2s": [],  # Has P2S config - skip
    }

    # Mock resource client
    resource_client = mocker.MagicMock()
    resource_client.resources.list.return_value = gateway_resources

    # Mock network client
    network_client = mocker.MagicMock()
    network_client.virtual_network_gateways.get.side_effect = lambda rg, name: gateways[name]
    network_client.virtual_network_gateways.list_connections.side_effect = (
        lambda rg, name: connections[name]
    )

    return network_client, resource_client


def test_find_idle_vnet_gateways(mock_clients):
    network_client, resource_client = mock_clients

    findings = find_idle_vnet_gateways(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=network_client,
        resource_client=resource_client,
    )
    names = [f.details["resource_name"] for f in findings]

    # Should flag idle gateways
    assert len(findings) == 2
    assert "vpn-idle" in names
    assert "er-idle" in names

    # Not flagged
    assert "vpn-active" not in names
    assert "vpn-provisioning" not in names
    assert "vpn-with-p2s" not in names

    # Verify finding fields
    for f in findings:
        assert f.provider == "azure"
        assert f.rule_id == "azure.virtual_network_gateway.idle"
        assert f.confidence.value == "medium"
        assert f.risk.value == "high"


def test_find_idle_vnet_gateways_empty_subscription(mocker):
    resource_client = mocker.MagicMock()
    resource_client.resources.list.return_value = []

    network_client = mocker.MagicMock()

    findings = find_idle_vnet_gateways(
        subscription_id="sub-123",
        credential=None,
        client=network_client,
        resource_client=resource_client,
    )
    assert findings == []


def test_find_idle_vnet_gateways_region_filter(mocker):
    gateway_resources = [
        _make_gateway_resource("vpn-east"),
        _make_gateway_resource("vpn-west"),
    ]

    gateways = {
        "vpn-east": _make_gateway("vpn-east", location="eastus"),
        "vpn-west": _make_gateway("vpn-west", location="westus"),
    }

    resource_client = mocker.MagicMock()
    resource_client.resources.list.return_value = gateway_resources

    network_client = mocker.MagicMock()
    network_client.virtual_network_gateways.get.side_effect = lambda rg, name: gateways[name]
    network_client.virtual_network_gateways.list_connections.return_value = []

    findings = find_idle_vnet_gateways(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=network_client,
        resource_client=resource_client,
    )

    assert len(findings) == 1
    assert "vpn-east" in findings[0].resource_id


def test_find_idle_vnet_gateways_expressroute_with_connection(mocker):
    """ExpressRoute gateway with active connection should NOT be flagged."""
    gateway_resources = [_make_gateway_resource("er-active")]

    gateways = {
        "er-active": _make_gateway(
            "er-active",
            gateway_type="ExpressRoute",
            sku_name="HighPerformance",
        ),
    }

    resource_client = mocker.MagicMock()
    resource_client.resources.list.return_value = gateway_resources

    network_client = mocker.MagicMock()
    network_client.virtual_network_gateways.get.side_effect = lambda rg, name: gateways[name]
    network_client.virtual_network_gateways.list_connections.return_value = [
        _make_connection("circuit1", "Connected")
    ]

    findings = find_idle_vnet_gateways(
        subscription_id="sub-123",
        credential=None,
        client=network_client,
        resource_client=resource_client,
    )

    assert len(findings) == 0


def test_find_idle_vnet_gateways_cost_estimates(mocker):
    """Verify cost estimates are included for different SKUs."""
    gateway_resources = [
        _make_gateway_resource("vpn-basic"),
        _make_gateway_resource("vpn-gw3"),
        _make_gateway_resource("er-ultra"),
    ]

    gateways = {
        "vpn-basic": _make_gateway("vpn-basic", sku_name="Basic", sku_tier="Basic"),
        "vpn-gw3": _make_gateway("vpn-gw3", sku_name="VpnGw3", sku_tier="VpnGw3"),
        "er-ultra": _make_gateway(
            "er-ultra",
            gateway_type="ExpressRoute",
            sku_name="UltraPerformance",
            sku_tier="UltraPerformance",
        ),
    }

    resource_client = mocker.MagicMock()
    resource_client.resources.list.return_value = gateway_resources

    network_client = mocker.MagicMock()
    network_client.virtual_network_gateways.get.side_effect = lambda rg, name: gateways[name]
    network_client.virtual_network_gateways.list_connections.return_value = []

    findings = find_idle_vnet_gateways(
        subscription_id="sub-123",
        credential=None,
        client=network_client,
        resource_client=resource_client,
    )

    assert len(findings) == 3

    by_name = {f.details["resource_name"]: f for f in findings}
    assert "$27" in by_name["vpn-basic"].details["cost_estimate"]
    assert "$930" in by_name["vpn-gw3"].details["cost_estimate"]
    assert "$670" in by_name["er-ultra"].details["cost_estimate"]


def test_find_idle_vnet_gateways_disconnected_connection(mocker):
    """Gateway with disconnected connection should be flagged."""
    gateway_resources = [_make_gateway_resource("vpn-disconnected")]

    gateways = {
        "vpn-disconnected": _make_gateway("vpn-disconnected"),
    }

    resource_client = mocker.MagicMock()
    resource_client.resources.list.return_value = gateway_resources

    network_client = mocker.MagicMock()
    network_client.virtual_network_gateways.get.side_effect = lambda rg, name: gateways[name]
    # Connection exists but is disconnected
    network_client.virtual_network_gateways.list_connections.return_value = [
        _make_connection("conn1", "Disconnected")
    ]

    findings = find_idle_vnet_gateways(
        subscription_id="sub-123",
        credential=None,
        client=network_client,
        resource_client=resource_client,
    )

    assert len(findings) == 1
    assert findings[0].details["total_connections"] == 1
    assert findings[0].details["active_connections"] == 0
