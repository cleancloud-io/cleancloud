from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.lb_no_backends import find_lb_no_backends


def _make_pool(nic_backends=None, ip_backends=None):
    return SimpleNamespace(
        backend_ip_configurations=nic_backends,
        load_balancer_backend_addresses=ip_backends,
    )


def _make_lb(
    name,
    sku_name="Standard",
    pools=None,
    location="eastus",
    tags=None,
    provisioning_state="Succeeded",
    frontend_ips=None,
    rules=None,
):
    return SimpleNamespace(
        id=f"/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/{name}",
        name=name,
        location=location,
        sku=SimpleNamespace(name=sku_name, tier="Regional"),
        backend_address_pools=pools,
        frontend_ip_configurations=frontend_ips or [],
        load_balancing_rules=rules or [],
        provisioning_state=provisioning_state,
        tags=tags,
    )


@pytest.fixture
def mock_network_client(mocker):
    lbs = [
        # Standard + all pools empty -> should be flagged
        _make_lb("lb-empty", pools=[_make_pool()]),
        # Standard + has NIC-based backend -> skip
        _make_lb("lb-with-nic-backend", pools=[_make_pool(nic_backends=[{"id": "nic-1"}])]),
        # Standard + has IP-based backend -> skip (Private Link / hybrid)
        _make_lb("lb-with-ip-backend", pools=[_make_pool(ip_backends=[{"ip": "10.0.0.1"}])]),
        # Standard + no pools at all -> should be flagged
        _make_lb("lb-no-pools", pools=[]),
        # Basic SKU + empty -> skip (no cost signal)
        _make_lb("lb-basic-empty", sku_name="Basic", pools=[_make_pool()]),
        # Standard + still provisioning -> skip
        _make_lb("lb-provisioning", pools=[_make_pool()], provisioning_state="Creating"),
    ]
    client = mocker.MagicMock()
    client.load_balancers.list_all.return_value = lbs
    return client


def test_find_lb_no_backends(mock_network_client):
    findings = find_lb_no_backends(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=mock_network_client,
    )
    names = [f.details["resource_name"] for f in findings]

    # Only the two empty Standard LBs should be flagged
    assert len(findings) == 2
    assert "lb-empty" in names
    assert "lb-no-pools" in names

    # Verify finding fields
    for f in findings:
        assert f.provider == "azure"
        assert f.rule_id == "azure.load_balancer.no_backends"
        assert f.confidence.value == "high"
        assert f.risk.value == "low"
        assert f.title == "Standard Load Balancer Has No Backend Members"
        assert f.details["sku_name"] == "Standard"
        assert f.estimated_monthly_cost_usd == 18.0

    # Not flagged
    assert "lb-with-nic-backend" not in names
    assert "lb-with-ip-backend" not in names
    assert "lb-basic-empty" not in names
    assert "lb-provisioning" not in names


def test_find_lb_no_backends_empty_subscription(mocker):
    client = mocker.MagicMock()
    client.load_balancers.list_all.return_value = []

    findings = find_lb_no_backends(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert findings == []


def test_find_lb_no_backends_region_filter(mocker):
    lbs = [
        _make_lb("lb-east", location="eastus", pools=[_make_pool()]),
        _make_lb("lb-west", location="westus", pools=[_make_pool()]),
    ]
    client = mocker.MagicMock()
    client.load_balancers.list_all.return_value = lbs

    findings = find_lb_no_backends(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=client,
    )
    assert len(findings) == 1
    assert "lb-east" in findings[0].resource_id


def test_find_lb_no_backends_mixed_pools(mocker):
    """LB with multiple pools where one has members — should NOT be flagged."""
    lbs = [
        _make_lb(
            "lb-mixed",
            pools=[
                _make_pool(),  # empty pool
                _make_pool(nic_backends=[{"id": "nic-1"}]),  # pool with member
            ],
        ),
    ]
    client = mocker.MagicMock()
    client.load_balancers.list_all.return_value = lbs

    findings = find_lb_no_backends(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert len(findings) == 0


def test_find_lb_no_backends_multiple_empty_pools(mocker):
    """LB with multiple pools all empty — should be flagged."""
    lbs = [
        _make_lb(
            "lb-all-empty",
            pools=[_make_pool(), _make_pool(), _make_pool()],
        ),
    ]
    client = mocker.MagicMock()
    client.load_balancers.list_all.return_value = lbs

    findings = find_lb_no_backends(
        subscription_id="sub-123",
        credential=None,
        client=client,
    )
    assert len(findings) == 1
    assert findings[0].details["backend_pool_count"] == 3
