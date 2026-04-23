"""
Tests for azure.virtual_network_gateway.idle -- spec-aligned.

Covers: must-emit (VPN, ER standard, ER scalable), must-skip for all
        exclusion conditions, failure behavior, finding shape, and unit
        tests for all resolver and helper functions.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

from cleancloud.providers.azure.rules.vnet_gateway_idle import (
    _connections_gate,
    _er_metric_family,
    _evaluate_metric,
    _gateway_admin_state_disabled,
    _gateway_has_virtual_wan_traffic,
    _MetricResult,
    _resolve_connection_type,
    _resolve_express_route_bypass,
    _resolve_gateway_type,
    _resolve_p2s_configured,
    _resolve_provisioning_state,
    find_idle_vnet_gateways,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_SUB = "sub-123"
_RG = "rg-test"
_GW_NAME = "my-vpn-gw"
_GW_ID = (
    f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
    f"/providers/Microsoft.Network/virtualNetworkGateways/{_GW_NAME}"
)
_ER_GW_NAME = "my-er-gw"
_ER_GW_ID = (
    f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
    f"/providers/Microsoft.Network/virtualNetworkGateways/{_ER_GW_NAME}"
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_gw_resource(name=_GW_NAME, gw_id=_GW_ID):
    """Stub returned by res_client.resources.list()."""
    return SimpleNamespace(id=gw_id, name=name)


def _make_gw(
    name=_GW_NAME,
    gw_id=_GW_ID,
    location="eastus",
    provisioning_state="Succeeded",
    gateway_type="Vpn",
    sku_name="VpnGw1",
    sku_tier="VpnGw1",
    tags=None,
    vpn_client_configuration=None,
    allow_virtual_wan_traffic=None,
    admin_state=None,
    properties=None,
):
    """Full gateway stub returned by net_client.virtual_network_gateways.get()."""
    return SimpleNamespace(
        id=gw_id,
        name=name,
        location=location,
        provisioning_state=provisioning_state,
        gateway_type=gateway_type,
        sku=SimpleNamespace(name=sku_name, tier=sku_tier),
        tags=tags,
        vpn_client_configuration=vpn_client_configuration,
        allow_virtual_wan_traffic=allow_virtual_wan_traffic,
        admin_state=admin_state,
        properties=properties,
    )


def _make_er_gw(
    name=_ER_GW_NAME,
    gw_id=_ER_GW_ID,
    sku_tier="HighPerformance",
    admin_state="Enabled",  # confirmed non-Disabled so ER gateways pass the fail-closed check
    **kwargs,
):
    """Convenience builder for an ExpressRoute gateway."""
    return _make_gw(
        name=name,
        gw_id=gw_id,
        gateway_type="ExpressRoute",
        sku_name=sku_tier,
        sku_tier=sku_tier,
        admin_state=admin_state,
        **kwargs,
    )


def _make_connection(connection_type="IPsec", express_route_gateway_bypass=None):
    """Connection stub for list_connections()."""
    return SimpleNamespace(
        connection_type=connection_type,
        express_route_gateway_bypass=express_route_gateway_bypass,
        properties=None,
    )


def _zero_metric_response(num_buckets=30):
    """Monitor metric response: 30 daily zero-total buckets, sufficient coverage."""
    now_utc = datetime.now(timezone.utc)
    window_start = now_utc - timedelta(days=30)
    data = [
        SimpleNamespace(
            timestamp=window_start + timedelta(days=i, hours=12),
            total=0.0,
        )
        for i in range(num_buckets)
    ]
    ts = SimpleNamespace(data=data)
    metric = SimpleNamespace(timeseries=[ts])
    return SimpleNamespace(value=[metric])


def _active_metric_response():
    """Monitor metric response: non-zero totals."""
    now_utc = datetime.now(timezone.utc)
    window_start = now_utc - timedelta(days=30)
    data = [
        SimpleNamespace(
            timestamp=window_start + timedelta(days=i, hours=12),
            total=float(i + 1),
        )
        for i in range(30)
    ]
    ts = SimpleNamespace(data=data)
    metric = SimpleNamespace(timeseries=[ts])
    return SimpleNamespace(value=[metric])


def _sparse_metric_response():
    """Monitor metric response: only 5 buckets -- below 80% coverage threshold."""
    return _zero_metric_response(num_buckets=5)


def _make_clients(
    gw=None,
    connections=None,
    metric_response=None,
    gw_resource=None,
):
    """
    Build (net_client, res_client, mon_client) mock triple.
    Defaults to a VPN happy-path: Succeeded, no connections, zero metrics.
    """
    if gw is None:
        gw = _make_gw()
    if connections is None:
        connections = []
    if metric_response is None:
        metric_response = _zero_metric_response()
    if gw_resource is None:
        gw_resource = _make_gw_resource()

    net = MagicMock()
    net.virtual_network_gateways.get.return_value = gw
    net.virtual_network_gateways.list_connections.return_value = iter(connections)

    res = MagicMock()
    res.resources.list.return_value = [gw_resource]

    mon = MagicMock()
    mon.metrics.list.return_value = metric_response

    return net, res, mon


def _run(net, res, mon, region_filter=None):
    return find_idle_vnet_gateways(
        subscription_id=_SUB,
        credential=None,
        region_filter=region_filter,
        client=net,
        resource_client=res,
        monitor_client=mon,
    )


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_vpn_gateway_no_connections_zero_metrics(self):
        net, res, mon = _make_clients()
        findings = _run(net, res, mon)
        assert len(findings) == 1
        assert findings[0].details["resource_name"] == _GW_NAME

    def test_er_standard_gateway_emits(self):
        gw = _make_er_gw()
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        findings = _run(net, res, mon)
        assert len(findings) == 1
        assert findings[0].details["gateway_type"] == "ExpressRoute"

    def test_er_scalable_gateway_emits(self):
        gw = _make_er_gw(sku_tier="ErGwScale")
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        findings = _run(net, res, mon)
        assert len(findings) == 1

    def test_tags_passed_through(self):
        gw = _make_gw(tags={"env": "test"})
        net, res, mon = _make_clients(gw=gw)
        findings = _run(net, res, mon)
        assert findings[0].details["tags"] == {"env": "test"}

    def test_tags_none_becomes_empty_dict(self):
        net, res, mon = _make_clients(gw=_make_gw(tags=None))
        findings = _run(net, res, mon)
        assert findings[0].details["tags"] == {}

    def test_empty_subscription_returns_no_findings(self):
        net, res, mon = _make_clients()
        res.resources.list.return_value = []
        findings = _run(net, res, mon)
        assert findings == []

    def test_multiple_vpn_gateways_both_idle(self):
        gw1 = _make_gw(name="gw1", gw_id=f"{_GW_ID}-1")
        gw2 = _make_gw(name="gw2", gw_id=f"{_GW_ID}-2")

        r1 = _make_gw_resource(name="gw1", gw_id=f"{_GW_ID}-1")
        r2 = _make_gw_resource(name="gw2", gw_id=f"{_GW_ID}-2")

        net = MagicMock()
        net.virtual_network_gateways.get.side_effect = lambda rg, n: {"gw1": gw1, "gw2": gw2}[n]
        net.virtual_network_gateways.list_connections.return_value = iter([])

        res = MagicMock()
        res.resources.list.return_value = [r1, r2]

        mon = MagicMock()
        mon.metrics.list.return_value = _zero_metric_response()

        findings = find_idle_vnet_gateways(
            subscription_id=_SUB,
            credential=None,
            client=net,
            resource_client=res,
            monitor_client=mon,
        )
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# TestIdNameGuards
# ---------------------------------------------------------------------------


class TestIdNameGuards:
    def test_id_none_skips(self):
        r = _make_gw_resource()
        r.id = None
        net, res, mon = _make_clients(gw_resource=r)
        assert _run(net, res, mon) == []

    def test_id_empty_skips(self):
        r = _make_gw_resource()
        r.id = ""
        net, res, mon = _make_clients(gw_resource=r)
        assert _run(net, res, mon) == []

    def test_name_none_skips(self):
        r = _make_gw_resource()
        r.name = None
        net, res, mon = _make_clients(gw_resource=r)
        assert _run(net, res, mon) == []

    def test_name_empty_skips(self):
        r = _make_gw_resource()
        r.name = ""
        net, res, mon = _make_clients(gw_resource=r)
        assert _run(net, res, mon) == []

    def test_malformed_id_no_resource_group_skips(self):
        r = _make_gw_resource(gw_id="/invalid/path/no/resourceGroups")
        net, res, mon = _make_clients(gw_resource=r)
        assert _run(net, res, mon) == []


# ---------------------------------------------------------------------------
# TestRegionFilter
# ---------------------------------------------------------------------------


class TestRegionFilter:
    def test_no_filter_emits(self):
        net, res, mon = _make_clients(gw=_make_gw(location="westus"))
        assert len(_run(net, res, mon)) == 1

    def test_matching_region_emits(self):
        net, res, mon = _make_clients(gw=_make_gw(location="eastus"))
        assert len(_run(net, res, mon, region_filter="eastus")) == 1

    def test_matching_region_case_insensitive(self):
        net, res, mon = _make_clients(gw=_make_gw(location="eastus"))
        assert len(_run(net, res, mon, region_filter="EastUS")) == 1

    def test_mismatched_region_skips(self):
        net, res, mon = _make_clients(gw=_make_gw(location="westus"))
        assert _run(net, res, mon, region_filter="eastus") == []


# ---------------------------------------------------------------------------
# TestProvisioningStateContract
# ---------------------------------------------------------------------------


class TestProvisioningStateContract:
    def test_succeeded_emits(self):
        net, res, mon = _make_clients(gw=_make_gw(provisioning_state="Succeeded"))
        assert len(_run(net, res, mon)) == 1

    def test_creating_skips(self):
        net, res, mon = _make_clients(gw=_make_gw(provisioning_state="Creating"))
        assert _run(net, res, mon) == []

    def test_updating_skips(self):
        net, res, mon = _make_clients(gw=_make_gw(provisioning_state="Updating"))
        assert _run(net, res, mon) == []

    def test_failed_skips(self):
        net, res, mon = _make_clients(gw=_make_gw(provisioning_state="Failed"))
        assert _run(net, res, mon) == []

    def test_none_state_skips(self):
        net, res, mon = _make_clients(gw=_make_gw(provisioning_state=None))
        assert _run(net, res, mon) == []

    def test_conflict_state_skips(self):
        gw = _make_gw(provisioning_state="Succeeded")
        gw.properties = SimpleNamespace(provisioningState="Failed")
        net, res, mon = _make_clients(gw=gw)
        assert _run(net, res, mon) == []

    def test_nested_only_succeeded_emits(self):
        gw = _make_gw(provisioning_state=None)
        gw.properties = SimpleNamespace(provisioningState="Succeeded")
        net, res, mon = _make_clients(gw=gw)
        assert len(_run(net, res, mon)) == 1


# ---------------------------------------------------------------------------
# TestGatewayTypeContract
# ---------------------------------------------------------------------------


class TestGatewayTypeContract:
    def test_vpn_type_emits(self):
        net, res, mon = _make_clients(gw=_make_gw(gateway_type="Vpn"))
        assert len(_run(net, res, mon)) == 1

    def test_expressroute_type_emits(self):
        gw = _make_er_gw()
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        assert len(_run(net, res, mon)) == 1

    def test_local_network_gateway_type_skips(self):
        net, res, mon = _make_clients(gw=_make_gw(gateway_type="LocalNetworkGateway"))
        assert _run(net, res, mon) == []

    def test_none_gateway_type_skips(self):
        net, res, mon = _make_clients(gw=_make_gw(gateway_type=None))
        assert _run(net, res, mon) == []

    def test_conflict_gateway_type_skips(self):
        gw = _make_gw(gateway_type="Vpn")
        gw.properties = SimpleNamespace(gatewayType="ExpressRoute")
        net, res, mon = _make_clients(gw=gw)
        assert _run(net, res, mon) == []

    def test_nested_only_vpn_emits(self):
        gw = _make_gw(gateway_type=None)
        gw.properties = SimpleNamespace(gatewayType="Vpn")
        net, res, mon = _make_clients(gw=gw)
        assert len(_run(net, res, mon)) == 1


# ---------------------------------------------------------------------------
# TestVirtualWanContract
# ---------------------------------------------------------------------------


class TestVirtualWanContract:
    def test_allow_virtual_wan_true_skips(self):
        net, res, mon = _make_clients(gw=_make_gw(allow_virtual_wan_traffic=True))
        assert _run(net, res, mon) == []

    def test_allow_virtual_wan_false_emits(self):
        net, res, mon = _make_clients(gw=_make_gw(allow_virtual_wan_traffic=False))
        assert len(_run(net, res, mon)) == 1

    def test_allow_virtual_wan_none_emits(self):
        net, res, mon = _make_clients(gw=_make_gw(allow_virtual_wan_traffic=None))
        assert len(_run(net, res, mon)) == 1

    def test_allow_virtual_wan_camel_case_true_skips(self):
        gw = _make_gw(allow_virtual_wan_traffic=None)
        # Inject via camelCase attribute directly
        gw.allowVirtualWanTraffic = True
        net, res, mon = _make_clients(gw=gw)
        assert _run(net, res, mon) == []


# ---------------------------------------------------------------------------
# TestExpressRouteAdminStateContract
# ---------------------------------------------------------------------------


class TestExpressRouteAdminStateContract:
    def test_er_admin_state_disabled_skips(self):
        gw = _make_er_gw(admin_state="Disabled")
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        assert _run(net, res, mon) == []

    def test_er_admin_state_enabled_emits(self):
        gw = _make_er_gw(admin_state="Enabled")
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        assert len(_run(net, res, mon)) == 1

    def test_er_admin_state_none_value_skips(self):
        # admin_state attribute present but value is None -> unresolvable -> skip
        gw = _make_er_gw(admin_state=None)
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        assert _run(net, res, mon) == []

    def test_er_admin_state_unexpected_value_skips(self):
        # Non-string value -> unresolvable -> skip (fail-closed)
        gw = _make_er_gw(admin_state=0)
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        assert _run(net, res, mon) == []

    def test_vpn_admin_state_disabled_does_not_skip(self):
        # adminState only gates ER gateways
        net, res, mon = _make_clients(gw=_make_gw(admin_state="Disabled"))
        assert len(_run(net, res, mon)) == 1


# ---------------------------------------------------------------------------
# TestConnectionsContract
# ---------------------------------------------------------------------------


class TestConnectionsContract:
    def test_ipsec_connection_skips(self):
        net, res, mon = _make_clients(connections=[_make_connection("IPsec")])
        assert _run(net, res, mon) == []

    def test_vnet2vnet_connection_skips(self):
        net, res, mon = _make_clients(connections=[_make_connection("Vnet2Vnet")])
        assert _run(net, res, mon) == []

    def test_expressroute_connection_skips(self):
        net, res, mon = _make_clients(connections=[_make_connection("ExpressRoute")])
        assert _run(net, res, mon) == []

    def test_connection_type_none_unresolvable_skips(self):
        # Connection with no connection_type field -> _resolve_connection_type returns None -> skip
        conn = SimpleNamespace(properties=None)  # no connection_type attr
        net, res, mon = _make_clients(connections=[conn])
        assert _run(net, res, mon) == []

    def test_connection_type_conflict_skips(self):
        conn = SimpleNamespace(
            connection_type="IPsec",
            properties=SimpleNamespace(connectionType="ExpressRoute"),
        )
        net, res, mon = _make_clients(connections=[conn])
        assert _run(net, res, mon) == []

    def test_out_of_scope_connection_type_emits(self):
        # "MicrosoftPeering" is not in IN_SCOPE, and on VPN gateway bypass check is skipped
        conn = _make_connection("MicrosoftPeering")
        net, res, mon = _make_clients(connections=[conn])
        assert len(_run(net, res, mon)) == 1

    def test_er_out_of_scope_connection_with_bypass_true_skips(self):
        # On ER gateway: non-in-scope connection with bypass=True -> skip
        conn = SimpleNamespace(
            connection_type="MicrosoftPeering",
            express_route_gateway_bypass=True,
            properties=None,
        )
        gw = _make_er_gw()
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, connections=[conn], gw_resource=gw_resource)
        assert _run(net, res, mon) == []

    def test_er_out_of_scope_connection_with_bypass_false_emits(self):
        conn = SimpleNamespace(
            connection_type="MicrosoftPeering",
            express_route_gateway_bypass=False,
            properties=None,
        )
        gw = _make_er_gw()
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, connections=[conn], gw_resource=gw_resource)
        assert len(_run(net, res, mon)) == 1

    def test_notconnected_ipsec_connection_still_skips(self):
        # spec 9.2.3: NotConnected status is still a configured connection
        conn = SimpleNamespace(
            connection_type="IPsec",
            express_route_gateway_bypass=None,
            properties=None,
        )
        net, res, mon = _make_clients(connections=[conn])
        assert _run(net, res, mon) == []

    def test_list_connections_http_error_skips_gateway(self):
        net, res, mon = _make_clients()
        net.virtual_network_gateways.list_connections.side_effect = HttpResponseError()
        assert _run(net, res, mon) == []

    def test_list_connections_service_request_error_skips_gateway(self):
        net, res, mon = _make_clients()
        net.virtual_network_gateways.list_connections.side_effect = ServiceRequestError("err")
        assert _run(net, res, mon) == []


# ---------------------------------------------------------------------------
# TestP2SContract
# ---------------------------------------------------------------------------


class TestP2SContract:
    def test_vpn_vcc_explicit_null_emits(self):
        # vpn_client_configuration attribute IS present, value is explicitly None -> confirmed no P2S
        net, res, mon = _make_clients(gw=_make_gw(vpn_client_configuration=None))
        assert len(_run(net, res, mon)) == 1

    def test_vpn_vcc_absent_from_all_sources_skips(self):
        # vpn_client_configuration attribute absent entirely -> unresolvable -> skip
        gw = SimpleNamespace(
            id=_GW_ID,
            name=_GW_NAME,
            location="eastus",
            provisioning_state="Succeeded",
            gateway_type="Vpn",
            sku=SimpleNamespace(name="VpnGw1", tier="VpnGw1"),
            tags=None,
            allow_virtual_wan_traffic=None,
            admin_state=None,
            properties=None,
            # deliberately no vpn_client_configuration attribute
        )
        net, res, mon = _make_clients(gw=gw)
        assert _run(net, res, mon) == []

    def test_vpn_p2s_address_pool_configured_skips(self):
        vcc = SimpleNamespace(vpn_client_address_pool=["10.0.0.0/24"])
        net, res, mon = _make_clients(gw=_make_gw(vpn_client_configuration=vcc))
        assert _run(net, res, mon) == []

    def test_vpn_p2s_aad_tenant_configured_skips(self):
        vcc = SimpleNamespace(aad_tenant="https://login.microsoftonline.com/tenant-id")
        net, res, mon = _make_clients(gw=_make_gw(vpn_client_configuration=vcc))
        assert _run(net, res, mon) == []

    def test_vpn_p2s_protocols_configured_skips(self):
        vcc = SimpleNamespace(vpn_client_protocols=["OpenVPN"])
        net, res, mon = _make_clients(gw=_make_gw(vpn_client_configuration=vcc))
        assert _run(net, res, mon) == []

    def test_vpn_p2s_conflict_unresolvable_skips(self):
        # sdk says non-empty, camelCase says empty -> conflict -> None -> skip
        vcc = SimpleNamespace(
            vpn_client_address_pool=["10.0.0.0/24"],
            vpnClientAddressPool=[],  # camelCase disagrees
        )
        net, res, mon = _make_clients(gw=_make_gw(vpn_client_configuration=vcc))
        assert _run(net, res, mon) == []

    def test_er_gateway_p2s_config_does_not_skip(self):
        # P2S check is VPN-only; ER gateways ignore vpn_client_configuration
        vcc = SimpleNamespace(vpn_client_address_pool=["10.0.0.0/24"])
        gw = _make_er_gw()
        gw.vpn_client_configuration = vcc
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        assert len(_run(net, res, mon)) == 1


# ---------------------------------------------------------------------------
# TestMetricContract
# ---------------------------------------------------------------------------


class TestMetricContract:
    def test_vpn_all_metrics_zero_emits(self):
        net, res, mon = _make_clients(metric_response=_zero_metric_response())
        assert len(_run(net, res, mon)) == 1

    def test_vpn_any_metric_active_skips(self):
        net, res, mon = _make_clients(metric_response=_active_metric_response())
        assert _run(net, res, mon) == []

    def test_vpn_metric_sparse_unknown_skips(self):
        # < 80% coverage -> UNKNOWN -> not ZERO -> skip
        net, res, mon = _make_clients(metric_response=_sparse_metric_response())
        assert _run(net, res, mon) == []

    def test_vpn_metric_exception_unknown_skips(self):
        net, res, mon = _make_clients()
        mon.metrics.list.side_effect = HttpResponseError()
        assert _run(net, res, mon) == []

    def test_er_standard_uses_er_metrics(self):
        gw = _make_er_gw(sku_tier="HighPerformance")
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        findings = _run(net, res, mon)
        assert len(findings) == 1
        used = findings[0].details["metrics_used"]
        assert "ExpressRouteGatewayBitsPerSecond" in used

    def test_er_scalable_uses_scalable_metrics(self):
        gw = _make_er_gw(sku_tier="ErGwScale")
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        findings = _run(net, res, mon)
        assert len(findings) == 1
        used = findings[0].details["metrics_used"]
        assert "ScalableExpressRouteGatewayBitsPerSecond" in used

    def test_er_unknown_sku_tier_skips(self):
        gw = _make_er_gw(sku_tier=None)
        gw.sku = SimpleNamespace(name=None, tier=None)
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        assert _run(net, res, mon) == []

    def test_vpn_calls_three_metrics(self):
        net, res, mon = _make_clients()
        _run(net, res, mon)
        assert mon.metrics.list.call_count == 3

    def test_er_standard_calls_three_metrics(self):
        gw = _make_er_gw(sku_tier="Standard")
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        _run(net, res, mon)
        assert mon.metrics.list.call_count == 3

    def test_average_only_active_metric_skips(self):
        # total is None for all datapoints; only average is populated and non-zero
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(
                timestamp=window_start + timedelta(days=i, hours=12),
                total=None,
                average=float(i + 1),
                maximum=None,
            )
            for i in range(30)
        ]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        net, res, mon = _make_clients(metric_response=response)
        assert _run(net, res, mon) == []

    def test_average_only_zero_metric_emits(self):
        # total absent; average=0.0 for all -> ZERO -> emits
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(
                timestamp=window_start + timedelta(days=i, hours=12),
                total=None,
                average=0.0,
                maximum=None,
            )
            for i in range(30)
        ]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        net, res, mon = _make_clients(metric_response=response)
        assert len(_run(net, res, mon)) == 1

    def test_maximum_only_active_metric_skips(self):
        # Only maximum is populated and non-zero
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(
                timestamp=window_start + timedelta(days=i, hours=12),
                total=None,
                average=None,
                maximum=1000.0,
            )
            for i in range(30)
        ]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        net, res, mon = _make_clients(metric_response=response)
        assert _run(net, res, mon) == []

    def test_metric_with_timestamp_none_datapoint_skips(self):
        # 29 valid zero datapoints + 1 with timestamp=None -> fail-closed -> skip
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(timestamp=window_start + timedelta(days=i, hours=12), total=0.0)
            for i in range(29)
        ] + [SimpleNamespace(timestamp=None, total=0.0)]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        net, res, mon = _make_clients(metric_response=response)
        assert _run(net, res, mon) == []

    def test_metric_with_non_datetime_timestamp_skips(self):
        # One datapoint has a string timestamp instead of datetime -> fail-closed -> skip
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(timestamp=window_start + timedelta(days=i, hours=12), total=0.0)
            for i in range(29)
        ] + [SimpleNamespace(timestamp="2024-01-15T00:00:00Z", total=0.0)]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        net, res, mon = _make_clients(metric_response=response)
        assert _run(net, res, mon) == []

    def test_all_aggregations_none_skips(self):
        # total, average, maximum all None -> no observed buckets -> UNKNOWN -> skip
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(
                timestamp=window_start + timedelta(days=i, hours=12),
                total=None,
                average=None,
                maximum=None,
            )
            for i in range(30)
        ]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        net, res, mon = _make_clients(metric_response=response)
        assert _run(net, res, mon) == []


# ---------------------------------------------------------------------------
# TestFailureBehavior
# ---------------------------------------------------------------------------


class TestFailureBehavior:
    def test_http_error_on_get_skips_gateway(self):
        net, res, mon = _make_clients()
        net.virtual_network_gateways.get.side_effect = HttpResponseError()
        assert _run(net, res, mon) == []

    def test_service_request_error_on_get_skips_gateway(self):
        net, res, mon = _make_clients()
        net.virtual_network_gateways.get.side_effect = ServiceRequestError("transport err")
        assert _run(net, res, mon) == []

    def test_service_response_error_on_get_skips_gateway(self):
        net, res, mon = _make_clients()
        net.virtual_network_gateways.get.side_effect = ServiceResponseError("stream closed")
        assert _run(net, res, mon) == []

    def test_runtime_error_on_get_propagates(self):
        net, res, mon = _make_clients()
        net.virtual_network_gateways.get.side_effect = RuntimeError("unexpected")
        with pytest.raises(RuntimeError):
            _run(net, res, mon)

    def test_http_error_on_list_connections_skips_gateway(self):
        net, res, mon = _make_clients()
        net.virtual_network_gateways.list_connections.side_effect = HttpResponseError()
        assert _run(net, res, mon) == []

    def test_service_request_error_on_list_connections_skips_gateway(self):
        net, res, mon = _make_clients()
        net.virtual_network_gateways.list_connections.side_effect = ServiceRequestError("err")
        assert _run(net, res, mon) == []

    def test_one_gateway_http_error_other_still_emits(self):
        gw2 = _make_gw(name="gw2", gw_id=f"{_GW_ID}-2")
        r1 = _make_gw_resource(name="gw1", gw_id=f"{_GW_ID}-1")
        r2 = _make_gw_resource(name="gw2", gw_id=f"{_GW_ID}-2")

        def _get(rg, name):
            if name == "gw1":
                raise HttpResponseError()
            return gw2

        net = MagicMock()
        net.virtual_network_gateways.get.side_effect = _get
        net.virtual_network_gateways.list_connections.return_value = iter([])

        res = MagicMock()
        res.resources.list.return_value = [r1, r2]

        mon = MagicMock()
        mon.metrics.list.return_value = _zero_metric_response()

        findings = find_idle_vnet_gateways(
            subscription_id=_SUB,
            credential=None,
            client=net,
            resource_client=res,
            monitor_client=mon,
        )
        assert len(findings) == 1
        assert findings[0].details["resource_name"] == "gw2"


# ---------------------------------------------------------------------------
# TestFindingShape
# ---------------------------------------------------------------------------


class TestFindingShape:
    def setup_method(self):
        net, res, mon = _make_clients()
        findings = _run(net, res, mon)
        assert findings
        self.f = findings[0]

    def test_provider(self):
        assert self.f.provider == "azure"

    def test_rule_id(self):
        assert self.f.rule_id == "azure.virtual_network_gateway.idle"

    def test_resource_type(self):
        assert self.f.resource_type == "azure.virtual_network_gateway"

    def test_resource_id_is_arm_id(self):
        assert self.f.resource_id == _GW_ID

    def test_region_normalized(self):
        assert self.f.region == "eastus"

    def test_confidence_high(self):
        assert self.f.confidence.value == "high"

    def test_risk_high(self):
        assert self.f.risk.value == "high"

    def test_estimated_cost_none(self):
        assert self.f.estimated_monthly_cost_usd is None

    def test_details_resource_name(self):
        assert self.f.details["resource_name"] == _GW_NAME

    def test_details_resource_group(self):
        assert self.f.details["resource_group"] == _RG

    def test_details_subscription_id(self):
        assert self.f.details["subscription_id"] == _SUB

    def test_details_gateway_type(self):
        assert self.f.details["gateway_type"] == "Vpn"

    def test_details_provisioning_state(self):
        assert self.f.details["provisioning_state"] == "Succeeded"

    def test_details_sku_name(self):
        assert self.f.details["sku_name"] == "VpnGw1"

    def test_details_sku_tier(self):
        assert self.f.details["sku_tier"] == "VpnGw1"

    def test_details_tags_empty_dict(self):
        assert self.f.details["tags"] == {}

    def test_details_p2s_configured_false_for_vpn(self):
        assert self.f.details["p2s_configured"] is False

    def test_details_idle_window_days(self):
        assert self.f.details["idle_window_days"] == 30

    def test_details_metrics_used_vpn(self):
        used = self.f.details["metrics_used"]
        assert "AverageBandwidth" in used
        assert "InboundFlowsCount" in used
        assert "OutboundFlowsCount" in used

    def test_evidence_has_signals_used(self):
        assert self.f.evidence.signals_used

    def test_evidence_has_signals_not_checked(self):
        assert self.f.evidence.signals_not_checked

    def test_er_p2s_configured_is_none(self):
        gw = _make_er_gw()
        gw_resource = _make_gw_resource(name=_ER_GW_NAME, gw_id=_ER_GW_ID)
        net, res, mon = _make_clients(gw=gw, gw_resource=gw_resource)
        findings = _run(net, res, mon)
        assert findings[0].details["p2s_configured"] is None


# ---------------------------------------------------------------------------
# TestResolveProvisioningState (unit)
# ---------------------------------------------------------------------------


class TestResolveProvisioningState:
    def test_sdk_only(self):
        gw = SimpleNamespace(provisioning_state="Succeeded")
        assert _resolve_provisioning_state(gw) == "Succeeded"

    def test_nested_only(self):
        gw = SimpleNamespace(
            provisioning_state=None,
            properties=SimpleNamespace(provisioningState="Succeeded"),
        )
        assert _resolve_provisioning_state(gw) == "Succeeded"

    def test_nested_snake_case(self):
        gw = SimpleNamespace(
            provisioning_state=None,
            properties=SimpleNamespace(provisioning_state="Succeeded", provisioningState=None),
        )
        assert _resolve_provisioning_state(gw) == "Succeeded"

    def test_both_match(self):
        gw = SimpleNamespace(
            provisioning_state="Succeeded",
            properties=SimpleNamespace(provisioningState="Succeeded"),
        )
        assert _resolve_provisioning_state(gw) == "Succeeded"

    def test_conflict_returns_none(self):
        gw = SimpleNamespace(
            provisioning_state="Succeeded",
            properties=SimpleNamespace(provisioningState="Failed"),
        )
        assert _resolve_provisioning_state(gw) is None

    def test_both_absent_returns_none(self):
        gw = SimpleNamespace(provisioning_state=None, properties=None)
        assert _resolve_provisioning_state(gw) is None


# ---------------------------------------------------------------------------
# TestResolveGatewayType (unit)
# ---------------------------------------------------------------------------


class TestResolveGatewayType:
    def test_sdk_vpn(self):
        gw = SimpleNamespace(gateway_type="Vpn")
        assert _resolve_gateway_type(gw) == "Vpn"

    def test_nested_expressroute(self):
        gw = SimpleNamespace(
            gateway_type=None,
            properties=SimpleNamespace(gatewayType="ExpressRoute"),
        )
        assert _resolve_gateway_type(gw) == "ExpressRoute"

    def test_conflict_returns_none(self):
        gw = SimpleNamespace(
            gateway_type="Vpn",
            properties=SimpleNamespace(gatewayType="ExpressRoute"),
        )
        assert _resolve_gateway_type(gw) is None

    def test_both_absent_returns_none(self):
        gw = SimpleNamespace(gateway_type=None, properties=None)
        assert _resolve_gateway_type(gw) is None


# ---------------------------------------------------------------------------
# TestResolveConnectionType (unit)
# ---------------------------------------------------------------------------


class TestResolveConnectionType:
    def test_sdk_ipsec(self):
        conn = SimpleNamespace(connection_type="IPsec", properties=None)
        assert _resolve_connection_type(conn) == "IPsec"

    def test_nested_vnet2vnet(self):
        conn = SimpleNamespace(
            connection_type=None,
            properties=SimpleNamespace(connectionType="Vnet2Vnet"),
        )
        assert _resolve_connection_type(conn) == "Vnet2Vnet"

    def test_conflict_returns_none(self):
        conn = SimpleNamespace(
            connection_type="IPsec",
            properties=SimpleNamespace(connectionType="Vnet2Vnet"),
        )
        assert _resolve_connection_type(conn) is None

    def test_both_absent_returns_none(self):
        conn = SimpleNamespace(connection_type=None, properties=None)
        assert _resolve_connection_type(conn) is None


# ---------------------------------------------------------------------------
# TestResolveExpressRouteBypass (unit)
# ---------------------------------------------------------------------------


class TestResolveExpressRouteBypass:
    def test_bypass_true(self):
        conn = SimpleNamespace(express_route_gateway_bypass=True, properties=None)
        assert _resolve_express_route_bypass(conn) is True

    def test_bypass_false(self):
        conn = SimpleNamespace(express_route_gateway_bypass=False, properties=None)
        assert _resolve_express_route_bypass(conn) is False

    def test_bypass_non_bool_returns_none(self):
        conn = SimpleNamespace(express_route_gateway_bypass="true", properties=None)
        assert _resolve_express_route_bypass(conn) is None

    def test_sdk_nested_conflict_returns_none(self):
        conn = SimpleNamespace(
            express_route_gateway_bypass=True,
            properties=SimpleNamespace(expressRouteGatewayBypass=False),
        )
        assert _resolve_express_route_bypass(conn) is None

    def test_nested_true(self):
        conn = SimpleNamespace(properties=SimpleNamespace(expressRouteGatewayBypass=True))
        # No sdk attr (getattr returns _SENTINEL)
        assert _resolve_express_route_bypass(conn) is True


# ---------------------------------------------------------------------------
# TestResolveP2SConfigured (unit)
# ---------------------------------------------------------------------------


class TestResolveP2SConfigured:
    def test_vcc_absent_from_all_sources_returns_none(self):
        # Attribute not present anywhere -> P2S state unresolvable -> None
        gw = SimpleNamespace()  # no vpn_client_configuration attr, no properties
        assert _resolve_p2s_configured(gw) is None

    def test_vpn_client_configuration_explicit_null_returns_false(self):
        # SDK explicitly returns null for the field -> confirmed no P2S
        gw = SimpleNamespace(vpn_client_configuration=None)
        assert _resolve_p2s_configured(gw) is False

    def test_address_pool_nonempty_returns_true(self):
        vcc = SimpleNamespace(vpn_client_address_pool=["10.0.0.0/24"])
        gw = SimpleNamespace(vpn_client_configuration=vcc)
        assert _resolve_p2s_configured(gw) is True

    def test_all_fields_empty_returns_false(self):
        vcc = SimpleNamespace(
            vpn_client_address_pool=[],
            vng_client_connection_configurations=[],
            vpn_client_root_certificates=[],
            vpn_client_revoked_certificates=[],
            vpn_authentication_types=[],
            vpn_client_protocols=[],
            aad_tenant=None,
            aad_audience=None,
            aad_issuer=None,
        )
        gw = SimpleNamespace(vpn_client_configuration=vcc)
        assert _resolve_p2s_configured(gw) is False

    def test_aad_tenant_nonempty_returns_true(self):
        vcc = SimpleNamespace(aad_tenant="https://login.microsoftonline.com/tenant")
        gw = SimpleNamespace(vpn_client_configuration=vcc)
        assert _resolve_p2s_configured(gw) is True

    def test_field_conflict_returns_none(self):
        vcc = SimpleNamespace(
            vpn_client_address_pool=["10.0.0.0/24"],
            vpnClientAddressPool=[],  # camelCase says empty
        )
        gw = SimpleNamespace(vpn_client_configuration=vcc)
        assert _resolve_p2s_configured(gw) is None

    def test_vcc_conflict_sdk_present_nested_absent_returns_none(self):
        # SDK says vcc is non-None, nested says None -> conflict
        gw = SimpleNamespace(
            vpn_client_configuration=SimpleNamespace(aad_tenant=None),
            properties=SimpleNamespace(vpnClientConfiguration=None),
        )
        assert _resolve_p2s_configured(gw) is None


# ---------------------------------------------------------------------------
# TestErMetricFamily (unit)
# ---------------------------------------------------------------------------


class TestErMetricFamily:
    def test_none_tier_returns_none(self):
        assert _er_metric_family(None) is None

    def test_er_gw_scale_returns_scalable(self):
        result = _er_metric_family("ErGwScale")
        assert "ScalableExpressRouteGatewayBitsPerSecond" in result

    def test_standard_returns_standard(self):
        result = _er_metric_family("Standard")
        assert "ExpressRouteGatewayBitsPerSecond" in result

    def test_high_performance_returns_standard(self):
        result = _er_metric_family("HighPerformance")
        assert "ExpressRouteGatewayBitsPerSecond" in result

    def test_ultra_performance_returns_standard(self):
        result = _er_metric_family("UltraPerformance")
        assert "ExpressRouteGatewayBitsPerSecond" in result

    def test_er_gw1_az_returns_standard(self):
        result = _er_metric_family("ErGw1AZ")
        assert "ExpressRouteGatewayBitsPerSecond" in result


# ---------------------------------------------------------------------------
# TestGatewayAdminStateDisabled (unit)
# ---------------------------------------------------------------------------


class TestGatewayAdminStateDisabled:
    def test_disabled_snake_case(self):
        gw = SimpleNamespace(admin_state="Disabled")
        assert _gateway_admin_state_disabled(gw) is True

    def test_enabled_snake_case(self):
        gw = SimpleNamespace(admin_state="Enabled")
        assert _gateway_admin_state_disabled(gw) is False

    def test_absent_from_all_sources_returns_none(self):
        # Field not present anywhere -> unresolvable -> None (fail-closed)
        gw = SimpleNamespace()
        assert _gateway_admin_state_disabled(gw) is None

    def test_none_value_returns_none(self):
        # Attribute present but value is None -> unresolvable
        gw = SimpleNamespace(admin_state=None)
        assert _gateway_admin_state_disabled(gw) is None

    def test_non_string_value_returns_none(self):
        gw = SimpleNamespace(admin_state=42)
        assert _gateway_admin_state_disabled(gw) is None

    def test_conflict_returns_none(self):
        gw = SimpleNamespace(
            admin_state="Enabled",
            properties=SimpleNamespace(adminState="Disabled"),
        )
        assert _gateway_admin_state_disabled(gw) is None

    def test_disabled_camel_case(self):
        gw = SimpleNamespace(adminState="Disabled")
        assert _gateway_admin_state_disabled(gw) is True

    def test_disabled_in_properties(self):
        gw = SimpleNamespace(properties=SimpleNamespace(admin_state="Disabled"))
        assert _gateway_admin_state_disabled(gw) is True

    def test_enabled_in_properties(self):
        gw = SimpleNamespace(properties=SimpleNamespace(adminState="Enabled"))
        assert _gateway_admin_state_disabled(gw) is False


# ---------------------------------------------------------------------------
# TestGatewayHasVirtualWanTraffic (unit)
# ---------------------------------------------------------------------------


class TestGatewayHasVirtualWanTraffic:
    def test_true_snake_case(self):
        gw = SimpleNamespace(allow_virtual_wan_traffic=True)
        assert _gateway_has_virtual_wan_traffic(gw) is True

    def test_false_returns_false(self):
        gw = SimpleNamespace(allow_virtual_wan_traffic=False)
        assert _gateway_has_virtual_wan_traffic(gw) is False

    def test_none_returns_false(self):
        gw = SimpleNamespace()
        assert _gateway_has_virtual_wan_traffic(gw) is False

    def test_true_camel_case(self):
        gw = SimpleNamespace(allowVirtualWanTraffic=True)
        assert _gateway_has_virtual_wan_traffic(gw) is True

    def test_true_in_properties(self):
        gw = SimpleNamespace(properties=SimpleNamespace(allow_virtual_wan_traffic=True))
        assert _gateway_has_virtual_wan_traffic(gw) is True


# ---------------------------------------------------------------------------
# TestConnectionsGate (unit)
# ---------------------------------------------------------------------------


class TestConnectionsGate:
    def _net(self, connections):
        net = MagicMock()
        net.virtual_network_gateways.list_connections.return_value = iter(connections)
        return net

    def test_no_connections_returns_true(self):
        result = _connections_gate(self._net([]), "rg", "gw", "Vpn")
        assert result is True

    def test_ipsec_connection_returns_false(self):
        result = _connections_gate(self._net([_make_connection("IPsec")]), "rg", "gw", "Vpn")
        assert result is False

    def test_vnet2vnet_returns_false(self):
        result = _connections_gate(self._net([_make_connection("Vnet2Vnet")]), "rg", "gw", "Vpn")
        assert result is False

    def test_expressroute_returns_false(self):
        result = _connections_gate(
            self._net([_make_connection("ExpressRoute")]), "rg", "gw", "ExpressRoute"
        )
        assert result is False

    def test_unknown_type_returns_false(self):
        conn = SimpleNamespace(properties=None)  # no connection_type
        result = _connections_gate(self._net([conn]), "rg", "gw", "Vpn")
        assert result is False

    def test_out_of_scope_type_vpn_returns_true(self):
        # "MicrosoftPeering" is not in-scope; no bypass check for VPN
        result = _connections_gate(
            self._net([_make_connection("MicrosoftPeering")]), "rg", "gw", "Vpn"
        )
        assert result is True

    def test_out_of_scope_er_bypass_true_returns_false(self):
        conn = SimpleNamespace(
            connection_type="MicrosoftPeering",
            express_route_gateway_bypass=True,
            properties=None,
        )
        result = _connections_gate(self._net([conn]), "rg", "gw", "ExpressRoute")
        assert result is False

    def test_out_of_scope_er_bypass_false_returns_true(self):
        conn = SimpleNamespace(
            connection_type="MicrosoftPeering",
            express_route_gateway_bypass=False,
            properties=None,
        )
        result = _connections_gate(self._net([conn]), "rg", "gw", "ExpressRoute")
        assert result is True


# ---------------------------------------------------------------------------
# TestEvaluateMetric (unit)
# ---------------------------------------------------------------------------


class TestEvaluateMetric:
    def _mon(self, response=None, side_effect=None):
        mon = MagicMock()
        if side_effect is not None:
            mon.metrics.list.side_effect = side_effect
        else:
            mon.metrics.list.return_value = response
        return mon

    def _window(self):
        now = datetime.now(timezone.utc)
        return now - timedelta(days=30), now

    def test_zero_totals_returns_zero(self):
        start, end = self._window()
        result = _evaluate_metric(
            self._mon(_zero_metric_response()), "resource_id", "Metric", start, end
        )
        assert result == _MetricResult.ZERO

    def test_nonzero_totals_returns_active(self):
        start, end = self._window()
        result = _evaluate_metric(
            self._mon(_active_metric_response()), "resource_id", "Metric", start, end
        )
        assert result == _MetricResult.ACTIVE

    def test_sparse_data_returns_unknown(self):
        start, end = self._window()
        result = _evaluate_metric(
            self._mon(_sparse_metric_response()), "resource_id", "Metric", start, end
        )
        assert result == _MetricResult.UNKNOWN

    def test_exception_returns_unknown(self):
        start, end = self._window()
        result = _evaluate_metric(
            self._mon(side_effect=HttpResponseError()),
            "resource_id",
            "Metric",
            start,
            end,
        )
        assert result == _MetricResult.UNKNOWN

    def test_empty_value_list_returns_unknown(self):
        start, end = self._window()
        mon = self._mon(SimpleNamespace(value=[]))
        result = _evaluate_metric(mon, "resource_id", "Metric", start, end)
        assert result == _MetricResult.UNKNOWN

    def test_no_value_attr_returns_unknown(self):
        start, end = self._window()
        mon = self._mon(SimpleNamespace())  # no .value attribute
        result = _evaluate_metric(mon, "resource_id", "Metric", start, end)
        assert result == _MetricResult.UNKNOWN

    def test_average_only_nonzero_returns_active(self):
        start, end = self._window()
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(
                timestamp=window_start + timedelta(days=i, hours=12),
                total=None,
                average=42.0,
                maximum=None,
            )
            for i in range(30)
        ]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        result = _evaluate_metric(self._mon(response), "res", "Metric", start, end)
        assert result == _MetricResult.ACTIVE

    def test_average_only_zero_returns_zero(self):
        start, end = self._window()
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(
                timestamp=window_start + timedelta(days=i, hours=12),
                total=None,
                average=0.0,
                maximum=None,
            )
            for i in range(30)
        ]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        result = _evaluate_metric(self._mon(response), "res", "Metric", start, end)
        assert result == _MetricResult.ZERO

    def test_all_aggregations_none_returns_unknown(self):
        start, end = self._window()
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(
                timestamp=window_start + timedelta(days=i, hours=12),
                total=None,
                average=None,
                maximum=None,
            )
            for i in range(30)
        ]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        result = _evaluate_metric(self._mon(response), "res", "Metric", start, end)
        assert result == _MetricResult.UNKNOWN

    def test_max_takes_highest_aggregation(self):
        # average=0 but maximum=5 -> ACTIVE (maximum wins)
        start, end = self._window()
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(
                timestamp=window_start + timedelta(days=i, hours=12),
                total=0.0,
                average=0.0,
                maximum=5.0,
            )
            for i in range(30)
        ]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        result = _evaluate_metric(self._mon(response), "res", "Metric", start, end)
        assert result == _MetricResult.ACTIVE

    def test_timestamp_none_returns_unknown(self):
        # Even 29 valid zero datapoints + 1 with timestamp=None -> fail-closed -> UNKNOWN
        start, end = self._window()
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(timestamp=window_start + timedelta(days=i, hours=12), total=0.0)
            for i in range(29)
        ] + [SimpleNamespace(timestamp=None, total=0.0)]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        result = _evaluate_metric(self._mon(response), "res", "Metric", start, end)
        assert result == _MetricResult.UNKNOWN

    def test_timestamp_not_datetime_returns_unknown(self):
        # String timestamp instead of datetime object -> fail-closed -> UNKNOWN
        start, end = self._window()
        now_utc = datetime.now(timezone.utc)
        window_start = now_utc - timedelta(days=30)
        data = [
            SimpleNamespace(timestamp=window_start + timedelta(days=i, hours=12), total=0.0)
            for i in range(29)
        ] + [SimpleNamespace(timestamp="2024-01-15T00:00:00Z", total=0.0)]
        response = SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data)])])
        result = _evaluate_metric(self._mon(response), "res", "Metric", start, end)
        assert result == _MetricResult.UNKNOWN

    def test_datapoints_outside_window_ignored(self):
        start, end = self._window()
        # All datapoints before the window
        data = [SimpleNamespace(timestamp=start - timedelta(days=1), total=100.0)]
        ts = SimpleNamespace(data=data)
        metric = SimpleNamespace(timeseries=[ts])
        response = SimpleNamespace(value=[metric])
        # Coverage: 0/31 buckets -> UNKNOWN
        result = _evaluate_metric(self._mon(response), "resource_id", "Metric", start, end)
        assert result == _MetricResult.UNKNOWN
