from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.app_gateway_no_backends import (
    find_app_gateway_no_backends,
)


def _make_pool(addresses=None, ip_configurations=None):
    return SimpleNamespace(
        backend_addresses=addresses,
        backend_ip_configurations=ip_configurations,
    )


def _make_app_gateway(
    name,
    sku_name="Standard_v2",
    sku_tier="Standard_v2",
    pools=None,
    location="eastus",
    tags=None,
    provisioning_state="Succeeded",
    http_listeners=None,
    request_routing_rules=None,
):
    return SimpleNamespace(
        id=f"/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/{name}",
        name=name,
        location=location,
        sku=SimpleNamespace(name=sku_name, tier=sku_tier, capacity=2),
        backend_address_pools=pools,
        http_listeners=http_listeners or [],
        request_routing_rules=request_routing_rules or [],
        provisioning_state=provisioning_state,
        tags=tags,
    )


@pytest.fixture
def mock_network_client(mocker):
    gateways = [
        # Empty backend pools - should be flagged
        _make_app_gateway("gw-empty", pools=[_make_pool()]),
        # Has backend targets - skip
        _make_app_gateway(
            "gw-with-backends",
            pools=[_make_pool(addresses=[{"ipAddress": "10.0.0.1"}])],
        ),
        # No pools at all - should be flagged
        _make_app_gateway("gw-no-pools", pools=[]),
        # WAF_v2 with empty pools - should be flagged
        _make_app_gateway(
            "gw-waf-empty",
            sku_name="WAF_v2",
            sku_tier="WAF_v2",
            pools=[_make_pool()],
        ),
        # Still provisioning - skip
        _make_app_gateway(
            "gw-provisioning",
            pools=[_make_pool()],
            provisioning_state="Creating",
        ),
    ]
    client = mocker.MagicMock()
    client.application_gateways.list_all.return_value = gateways
    return client


def test_find_app_gateway_no_backends(mock_network_client):
    findings = find_app_gateway_no_backends(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=mock_network_client,
    )
    names = [f.details["resource_name"] for f in findings]

    # Should flag empty and no-pools gateways
    assert len(findings) == 3
    assert "gw-empty" in names
    assert "gw-no-pools" in names
    assert "gw-waf-empty" in names

    # Not flagged
    assert "gw-with-backends" not in names
    assert "gw-provisioning" not in names

    # Verify finding fields
    for f in findings:
        assert f.provider == "azure"
        assert f.rule_id == "azure.application_gateway.no_backends"
        assert f.confidence.value == "high"
        assert f.risk.value == "medium"
        assert f.title == "Application Gateway Has No Backend Targets"


def test_find_app_gateway_no_backends_empty_subscription(mocker):
    client = mocker.MagicMock()
    client.application_gateways.list_all.return_value = []

    findings = find_app_gateway_no_backends(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert findings == []


def test_find_app_gateway_no_backends_region_filter(mocker):
    gateways = [
        _make_app_gateway("gw-east", location="eastus", pools=[_make_pool()]),
        _make_app_gateway("gw-west", location="westus", pools=[_make_pool()]),
    ]
    client = mocker.MagicMock()
    client.application_gateways.list_all.return_value = gateways

    findings = find_app_gateway_no_backends(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=client,
    )
    assert len(findings) == 1
    assert "gw-east" in findings[0].resource_id


def test_find_app_gateway_no_backends_mixed_pools(mocker):
    """Gateway with multiple pools where one has targets - should NOT be flagged."""
    gateways = [
        _make_app_gateway(
            "gw-mixed",
            pools=[
                _make_pool(),  # empty pool
                _make_pool(addresses=[{"fqdn": "backend.example.com"}]),  # has target
            ],
        ),
    ]
    client = mocker.MagicMock()
    client.application_gateways.list_all.return_value = gateways

    findings = find_app_gateway_no_backends(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert len(findings) == 0


def test_find_app_gateway_no_backends_cost_estimate(mocker):
    """Verify cost estimates are included for different SKUs."""
    gateways = [
        _make_app_gateway(
            "gw-v2",
            sku_tier="Standard_v2",
            pools=[_make_pool()],
        ),
        _make_app_gateway(
            "gw-waf-v2",
            sku_tier="WAF_v2",
            pools=[_make_pool()],
        ),
        _make_app_gateway(
            "gw-v1",
            sku_tier="Standard",
            pools=[_make_pool()],
        ),
    ]
    client = mocker.MagicMock()
    client.application_gateways.list_all.return_value = gateways

    findings = find_app_gateway_no_backends(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert len(findings) == 3

    # Check cost estimates
    by_name = {f.details["resource_name"]: f for f in findings}
    assert "v2 SKU" in by_name["gw-v2"].details["cost_estimate"]
    assert "v2 SKU" in by_name["gw-waf-v2"].details["cost_estimate"]
    assert "v1 SKU" in by_name["gw-v1"].details["cost_estimate"]


def test_find_app_gateway_no_backends_nic_based_backends(mocker):
    """Gateway with NIC-based backend_ip_configurations should NOT be flagged."""
    nic_ref = SimpleNamespace(
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1"
    )
    gateways = [
        # Has NIC-based backends via backend_ip_configurations - should NOT be flagged
        _make_app_gateway(
            "gw-with-nic-backends",
            pools=[_make_pool(ip_configurations=[nic_ref])],
        ),
        # Empty pool (no addresses, no ip_configurations) - should be flagged
        _make_app_gateway(
            "gw-empty-pool",
            pools=[_make_pool()],
        ),
    ]
    client = mocker.MagicMock()
    client.application_gateways.list_all.return_value = gateways

    findings = find_app_gateway_no_backends(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )

    names = [f.details["resource_name"] for f in findings]
    assert len(findings) == 1
    assert "gw-empty-pool" in names
    assert "gw-with-nic-backends" not in names
