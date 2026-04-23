"""
Rule: azure.virtual_network_gateway.idle

Intent:
    Detect Azure virtual network gateways (VPN and ExpressRoute) that have no
    configured in-scope connection resources and no applicable gateway activity
    over a 30-day observation window, making them review candidates for cleanup
    or rightsizing.

    This is a review-candidate rule only. It does not prove the gateway should
    be deleted, that a standby topology is unnecessary, or that a specific
    monthly saving exists.

Exclusions:
    - id absent or empty
    - name absent or empty
    - outside optional region filter (exact lowercase match)
    - provisioning state does not resolve to exactly "Succeeded"
    - gateway type does not resolve to exactly "Vpn" or "ExpressRoute"
    - allowVirtualWanTraffic resolves to True
    - ExpressRoute: adminState is "Disabled" or any connection has bypass enabled
    - VPN: any P2S field group resolves to a present, non-empty configured value
    - any configured in-scope connection resource present (IPsec, Vnet2Vnet, ExpressRoute)
    - any connection has unknown or conflicting type resolution
    - connection listing fails, is partial, or unresolvable
    - any applicable idle metric is unknown, below coverage threshold, or non-zero
    - per-gateway get/list_connections/metric retrieval raises an expected SDK error

Detection:
    - provisioning state is "Succeeded" (SDK-first, nested fallback, conflict -> skip)
    - gateway type is "Vpn" or "ExpressRoute"
    - allowVirtualWanTraffic is not True
    - no ExpressRoute standby/bypass signals present
    - no P2S configuration for VPN gateways
    - no configured in-scope connection resources
    - all applicable idle metrics zero over 30 days with >= 80% daily bucket coverage

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)
    Gateway billing varies by SKU, type, and transfer topology. No flat estimate.

APIs:
    - Microsoft.Resources/resources/read  (resources.list, subscription-wide inventory)
    - Microsoft.Network/virtualNetworkGateways/read  (get, list_connections)
    - Microsoft.Insights/metrics/read  (metrics.list)
"""

import math
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Optional, Tuple

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.virtual_network_gateway.idle"
_RESOURCE_TYPE = "azure.virtual_network_gateway"
_IDLE_WINDOW_DAYS = 30
_MIN_COVERAGE = 0.80

# In-scope connection types per spec 7 / 9.2
_IN_SCOPE_CONNECTION_TYPES = frozenset({"IPsec", "Vnet2Vnet", "ExpressRoute"})

# Idle metrics per gateway type / SKU family (spec 9.6)
_VPN_METRICS: Tuple[str, ...] = (
    "AverageBandwidth",
    "InboundFlowsCount",
    "OutboundFlowsCount",
)
_ER_STANDARD_METRICS: Tuple[str, ...] = (
    "ExpressRouteGatewayBitsPerSecond",
    "ExpressRouteGatewayPacketsPerSecond",
    "ExpressRouteGatewayActiveFlows",
)
_ER_SCALABLE_METRICS: Tuple[str, ...] = (
    "ScalableExpressRouteGatewayBitsPerSecond",
    "ScalableExpressRouteGatewayPacketsPerSecond",
    "ScalableExpressRouteGatewayActiveFlows",
)

# ExpressRoute SKU tiers that use the scalable metric family
_ER_SCALABLE_TIERS = frozenset({"ErGwScale"})

# P2S field groups to check: (snake_case, camelCase) per spec 9.3
_P2S_FIELD_PAIRS = (
    ("vpn_client_address_pool", "vpnClientAddressPool"),
    ("vng_client_connection_configurations", "vngClientConnectionConfigurations"),
    ("vpn_client_root_certificates", "vpnClientRootCertificates"),
    ("vpn_client_revoked_certificates", "vpnClientRevokedCertificates"),
    ("vpn_authentication_types", "vpnAuthenticationTypes"),
    ("vpn_client_protocols", "vpnClientProtocols"),
    ("aad_tenant", "aadTenant"),
    ("aad_audience", "aadAudience"),
    ("aad_issuer", "aadIssuer"),
)

_SENTINEL = object()


class _MetricResult(Enum):
    ACTIVE = "ACTIVE"
    ZERO = "ZERO"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _norm_location(s: str) -> str:
    """Lowercase only -- exact lowercase match per spec 7."""
    return s.lower() if s else ""


def _extract_resource_group(resource_id: str) -> Optional[str]:
    """Extract resource group name from Azure ARM resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = parts.index("resourceGroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None


def _is_field_nonempty(val) -> bool:
    """True if val represents a present, non-empty configured value."""
    if val is None:
        return False
    if isinstance(val, str):
        return bool(val.strip())
    try:
        return len(val) > 0
    except TypeError:
        return bool(val)


# ---------------------------------------------------------------------------
# Gateway-state resolvers (spec 9.1)
# ---------------------------------------------------------------------------


def _resolve_provisioning_state(gateway) -> Optional[str]:
    """
    SDK-first / nested fallback. Returns None on conflict or both absent.
    Only "Succeeded" is eligible; caller skips on anything else.
    """
    sdk_val = getattr(gateway, "provisioning_state", None)
    props = getattr(gateway, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, "provisioning_state", None)
        if nested_val is None:
            nested_val = getattr(props, "provisioningState", None)
    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None  # conflict -> skip
    return sdk_val or nested_val


def _resolve_gateway_type(gateway) -> Optional[str]:
    """
    SDK-first / nested fallback. Returns None on conflict or both absent.
    Only "Vpn" and "ExpressRoute" are in scope; caller skips on anything else.
    """
    sdk_val = getattr(gateway, "gateway_type", None)
    props = getattr(gateway, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, "gateway_type", None)
        if nested_val is None:
            nested_val = getattr(props, "gatewayType", None)
    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None  # conflict -> skip
    return sdk_val or nested_val


# ---------------------------------------------------------------------------
# Connection-surface resolver (spec 9.2)
# ---------------------------------------------------------------------------


def _resolve_connection_type(connection) -> Optional[str]:
    """
    Resolve connectionType from a connection resource.
    Returns None if absent from all sources or conflicting.
    """
    sdk_val = getattr(connection, "connection_type", None)
    props = getattr(connection, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, "connection_type", None)
        if nested_val is None:
            nested_val = getattr(props, "connectionType", None)
    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None  # conflict -> unresolvable
    return sdk_val or nested_val


def _connections_gate(
    net_client: NetworkManagementClient,
    resource_group: str,
    gw_name: str,
    gateway_type: str,
) -> bool:
    """
    Enumerate connections and apply the connection-surface contract (spec 9.2).

    Returns True (gate passed: no in-scope connections and no bypass issues).
    Returns False (skip: in-scope connection present, unresolvable type, or bypass enabled).
    Raises on list_connections() failure -- propagates to caller's per-gateway try-except.
    """
    for conn in net_client.virtual_network_gateways.list_connections(resource_group, gw_name):
        conn_type = _resolve_connection_type(conn)
        if conn_type is None:
            return False  # spec 9.2.5: unknown/conflicting type -> skip gateway

        if conn_type in _IN_SCOPE_CONNECTION_TYPES:
            return False  # spec 9.2.7: in-scope connection present -> skip

        # spec 9.4: ExpressRoute bypass / FastPath check
        if gateway_type == "ExpressRoute":
            bypass = _resolve_express_route_bypass(conn)
            if bypass is None or bypass is True:
                return False  # unresolvable or bypass enabled -> skip

    return True  # no in-scope connections and no bypass issues


def _resolve_express_route_bypass(connection) -> Optional[bool]:
    """
    Resolve expressRouteGatewayBypass from a connection resource.
    Returns True (bypass enabled), False (confirmed not enabled), None (unresolvable).
    """
    sdk_raw = getattr(connection, "express_route_gateway_bypass", _SENTINEL)
    props = getattr(connection, "properties", None)
    nested_raw = _SENTINEL
    if props is not None:
        nested_raw = getattr(props, "express_route_gateway_bypass", _SENTINEL)
        if nested_raw is _SENTINEL:
            nested_raw = getattr(props, "expressRouteGatewayBypass", _SENTINEL)

    sdk_found = sdk_raw is not _SENTINEL
    nested_found = nested_raw is not _SENTINEL

    def _to_bool(v):
        return v if isinstance(v, bool) else None

    sdk_b = _to_bool(sdk_raw) if sdk_found else None
    nested_b = _to_bool(nested_raw) if nested_found else None

    # Present but not a bool -> unresolvable
    if sdk_found and sdk_raw is not _SENTINEL and sdk_b is None:
        return None
    if nested_found and nested_raw is not _SENTINEL and nested_b is None:
        return None

    if sdk_b is not None and nested_b is not None and sdk_b != nested_b:
        return None  # conflict -> unresolvable

    result = sdk_b if sdk_b is not None else nested_b
    return result  # None if absent = field absent = not bypassed


# ---------------------------------------------------------------------------
# P2S configuration resolver (spec 9.3)
# ---------------------------------------------------------------------------


def _resolve_p2s_configured(gateway) -> Optional[bool]:
    """
    Resolve P2S configuration presence for VPN gateways per spec 9.3.

    Returns:
    - True:  P2S is configured (any field group non-empty)
    - False: confirmed not configured (all field groups empty / vpnClientConfiguration absent)
    - None:  unresolvable (conflicting vpnClientConfiguration presence, or conflicting
             field group values) -> caller must skip
    """
    sdk_vcc = getattr(gateway, "vpn_client_configuration", _SENTINEL)
    props = getattr(gateway, "properties", None)
    nested_vcc = _SENTINEL
    if props is not None:
        nested_vcc = getattr(props, "vpn_client_configuration", _SENTINEL)
        if nested_vcc is _SENTINEL:
            nested_vcc = getattr(props, "vpnClientConfiguration", _SENTINEL)

    sdk_found = sdk_vcc is not _SENTINEL
    nested_found = nested_vcc is not _SENTINEL

    if sdk_found and nested_found:
        sdk_none = sdk_vcc is None
        nested_none = nested_vcc is None
        if sdk_none != nested_none:
            return None  # one says present, other says absent -> conflict -> skip
        if sdk_none:
            return False  # both confirm absent
        vcc = sdk_vcc  # both present; use SDK as primary
    elif sdk_found:
        if sdk_vcc is None:
            return False  # SDK explicitly confirms absent (null)
        vcc = sdk_vcc
    elif nested_found:
        if nested_vcc is None:
            return False  # nested explicitly confirms absent (null)
        vcc = nested_vcc
    else:
        return None  # field absent from all sources -> P2S state unresolvable -> skip

    # vcc is a non-None object -- check each of the 9 field groups
    for snake, camel in _P2S_FIELD_PAIRS:
        sdk_f = getattr(vcc, snake, None)
        camel_f = getattr(vcc, camel, None)
        sdk_ne = _is_field_nonempty(sdk_f)
        camel_ne = _is_field_nonempty(camel_f)
        # Conflict: one says non-empty, the other says empty (and both are present)
        if sdk_f is not None and camel_f is not None and sdk_ne != camel_ne:
            return None  # conflicting field group -> unresolvable -> skip
        if sdk_ne or camel_ne:
            return True  # P2S configured

    return False  # all field groups empty -> not configured


# ---------------------------------------------------------------------------
# Unsupported topology / bypass signals (spec 9.4, 9.5)
# ---------------------------------------------------------------------------


def _gateway_has_virtual_wan_traffic(gateway) -> bool:
    """Returns True only when allowVirtualWanTraffic is confirmed True (spec 9.5)."""
    for attr in ("allow_virtual_wan_traffic", "allowVirtualWanTraffic"):
        if getattr(gateway, attr, None) is True:
            return True
    props = getattr(gateway, "properties", None)
    if props is not None:
        for attr in ("allow_virtual_wan_traffic", "allowVirtualWanTraffic"):
            if getattr(props, attr, None) is True:
                return True
    return False


def _gateway_admin_state_disabled(gateway) -> Optional[bool]:
    """
    Resolve adminState for ExpressRoute gateways per spec 9.4.

    Returns:
    - True:  adminState is confirmed "Disabled" -> caller must skip
    - False: adminState is a non-empty string other than "Disabled" -> proceed
    - None:  absent from all sources, conflict, None value, or unrecognized type
             -> state unresolvable -> caller must skip (fail-closed)
    """

    def _find(obj) -> object:
        for attr in ("admin_state", "adminState"):
            v = getattr(obj, attr, _SENTINEL)
            if v is not _SENTINEL:
                return v
        return _SENTINEL

    sdk_val = _find(gateway)
    props = getattr(gateway, "properties", None)
    nested_val = _find(props) if props is not None else _SENTINEL

    sdk_found = sdk_val is not _SENTINEL
    nested_found = nested_val is not _SENTINEL

    if not sdk_found and not nested_found:
        return None  # absent from all sources -> unresolvable -> skip

    if sdk_found and nested_found and sdk_val != nested_val:
        return None  # conflict -> unresolvable -> skip

    val = sdk_val if sdk_found else nested_val

    if val == "Disabled":
        return True
    if isinstance(val, str) and val:
        return False  # confirmed non-Disabled (e.g., "Enabled")
    return None  # None value, non-string, or empty string -> unresolvable -> skip


# ---------------------------------------------------------------------------
# ExpressRoute metric family selection (spec 9.6.2)
# ---------------------------------------------------------------------------


def _er_metric_family(sku_tier: Optional[str]) -> Optional[Tuple[str, ...]]:
    """
    Return the applicable ExpressRoute metric tuple for the given SKU tier.
    Returns None if sku_tier is absent (unresolvable -> caller skips).
    """
    if sku_tier is None:
        return None  # unknown -> unresolvable -> skip
    if sku_tier in _ER_SCALABLE_TIERS:
        return _ER_SCALABLE_METRICS
    return _ER_STANDARD_METRICS  # Standard/HighPerformance/UltraPerformance/AZ family


# ---------------------------------------------------------------------------
# Metric evaluation (spec 9.6)
# ---------------------------------------------------------------------------


def _evaluate_metric(
    monitor_client: MonitorManagementClient,
    resource_uri: str,
    metric_name: str,
    window_start: datetime,
    window_end: datetime,
) -> _MetricResult:
    """
    Evaluate a single Azure Monitor metric over the 30-day window per spec 9.6.

    Uses daily (P1D) buckets with a >= 80% coverage requirement.
    Returns ACTIVE, ZERO, or UNKNOWN.
    UNKNOWN covers: query failure, unusable response shape, no valid series,
    insufficient bucket coverage, or any unparseable datapoint (fail-closed).

    Fail-closed on unparseable datapoints (spec 9.6.1): if any datapoint within
    the response has an absent or non-datetime timestamp, the entire metric
    evaluation returns UNKNOWN rather than silently discarding the datapoint and
    continuing with the remaining series.

    Datapoints with no populated aggregation value (total, average, maximum all
    None) are treated as sparse/missing -- they do not contribute to observed
    bucket coverage, which drives the result toward UNKNOWN through the coverage
    threshold rather than triggering an immediate UNKNOWN.

    Datapoints that fall outside the requested window are legitimate edge returns
    from the Azure Monitor API and are silently filtered out.
    """
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{window_start.strftime(fmt)}/{window_end.strftime(fmt)}"

    first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
    expected_buckets = math.ceil((window_end - first_bucket).total_seconds() / 86400)
    if expected_buckets == 0:
        return _MetricResult.UNKNOWN

    try:
        response = monitor_client.metrics.list(
            resource_uri,
            metricnames=metric_name,
            timespan=timespan,
            interval="P1D",
            aggregation="Total,Average,Maximum",
        )
    except Exception:
        return _MetricResult.UNKNOWN

    if not hasattr(response, "value") or response.value is None:
        return _MetricResult.UNKNOWN

    # Per-bucket maximum across all populated aggregation types (Total, Average, Maximum).
    # Using max rather than sum avoids double-counting when multiple aggregation fields
    # are populated for the same datapoint.
    bucket_max: dict = {}
    for metric in response.value:
        for ts in metric.timeseries or []:
            for data in ts.data or []:
                if data.timestamp is None:
                    return _MetricResult.UNKNOWN  # unparseable datapoint -> fail-closed
                ts_dt = data.timestamp
                if not isinstance(ts_dt, datetime):
                    return _MetricResult.UNKNOWN  # unparseable timestamp type -> fail-closed
                # Accept any of Total / Average / Maximum -- take the max of what is present.
                agg_val = None
                for agg_attr in ("total", "average", "maximum"):
                    v = getattr(data, agg_attr, None)
                    if v is not None:
                        agg_val = max(agg_val, v) if agg_val is not None else v
                if agg_val is None:
                    continue  # sparse/missing aggregation -> reduces coverage, does not fail-close
                ts_utc = ts_dt if ts_dt.tzinfo is not None else ts_dt.replace(tzinfo=timezone.utc)
                if not (window_start <= ts_utc < window_end):
                    continue
                key = ts_utc.strftime("%Y-%m-%dT00:00:00Z")
                existing = bucket_max.get(key)
                bucket_max[key] = max(existing, agg_val) if existing is not None else agg_val

    observed = len(bucket_max)
    if observed == 0:
        return _MetricResult.UNKNOWN
    if observed / expected_buckets < _MIN_COVERAGE:
        return _MetricResult.UNKNOWN

    signal = sum(bucket_max.values())
    return _MetricResult.ACTIVE if signal > 0 else _MetricResult.ZERO


# ---------------------------------------------------------------------------
# Main rule function
# ---------------------------------------------------------------------------


def find_idle_vnet_gateways(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[NetworkManagementClient] = None,
    resource_client: Optional[ResourceManagementClient] = None,
    monitor_client: Optional[MonitorManagementClient] = None,
) -> List[Finding]:
    """
    Find Azure VNet Gateways (VPN or ExpressRoute) with no configured in-scope
    connections and no applicable gateway activity over 30 days.

    IAM permissions:
    - Microsoft.Resources/resources/read
    - Microsoft.Network/virtualNetworkGateways/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []

    net_client = client or NetworkManagementClient(
        credential=credential, subscription_id=subscription_id
    )
    res_client = resource_client or ResourceManagementClient(
        credential=credential, subscription_id=subscription_id
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=_IDLE_WINDOW_DAYS)

    # Subscription-wide gateway inventory (spec 12: propagate if this fails)
    gateway_resources = list(
        res_client.resources.list(
            filter="resourceType eq 'Microsoft.Network/virtualNetworkGateways'"
        )
    )

    for gw_resource in gateway_resources:
        # spec 8.1: id guard
        gw_id = getattr(gw_resource, "id", None)
        if not gw_id:
            continue

        # spec 8.2: name guard
        gw_name = getattr(gw_resource, "name", None)
        if not gw_name:
            continue

        # Extract resource group before the per-gateway try block (no API call)
        resource_group = _extract_resource_group(gw_id)
        if not resource_group:
            continue

        # Per-gateway: get full details, list connections, evaluate metrics.
        # Expected SDK retrieval failures -> skip this gateway (spec 12).
        # HttpResponseError: HTTP-level failure (404, 403, 429, 5xx).
        # ServiceRequestError: transport failure before a response.
        # ServiceResponseError: transport failure while reading the response.
        try:
            gw = net_client.virtual_network_gateways.get(resource_group, gw_name)

            # spec 8.3: region filter -- exact lowercase match
            location = _norm_location(getattr(gw, "location", "") or "")
            if region_filter and location != _norm_location(region_filter):
                continue

            # spec 8.4 / 9.1: provisioning state must resolve to exactly "Succeeded"
            if _resolve_provisioning_state(gw) != "Succeeded":
                continue

            # spec 8.5 / 9.1: gateway type must resolve to "Vpn" or "ExpressRoute"
            gateway_type = _resolve_gateway_type(gw)
            if gateway_type not in ("Vpn", "ExpressRoute"):
                continue

            sku = getattr(gw, "sku", None)
            sku_name = getattr(sku, "name", None) if sku else None
            sku_tier = getattr(sku, "tier", None) if sku else None

            # spec 8.9 / 9.5: Virtual WAN / hub-managed topology signal
            if _gateway_has_virtual_wan_traffic(gw):
                continue

            # spec 8.10 / 9.4: ExpressRoute standby / bypass -- adminState
            # None (unresolvable) is also a skip: fail-closed per spec 9.4.4
            if gateway_type == "ExpressRoute":
                admin_disabled = _gateway_admin_state_disabled(gw)
                if admin_disabled is None or admin_disabled:
                    continue

            # spec 8.8 / 9.3: P2S configuration (VPN gateways only)
            if gateway_type == "Vpn":
                p2s_result = _resolve_p2s_configured(gw)
                if p2s_result is None or p2s_result:
                    continue  # unresolvable or P2S configured -> skip

            # spec 8.7 / 9.2: connection-surface contract
            # list_connections() failure propagates to the outer except and skips this gateway
            if not _connections_gate(net_client, resource_group, gw_name, gateway_type):
                continue

            # spec 8.11-8.13 / 9.6: idle metrics
            if gateway_type == "Vpn":
                metrics_to_check = _VPN_METRICS
            else:
                metrics_to_check = _er_metric_family(sku_tier)
                if metrics_to_check is None:
                    continue  # unknown ER SKU tier -> unresolvable -> skip

            resource_uri = gw.id or gw_id
            all_zero = True
            for metric_name in metrics_to_check:
                result = _evaluate_metric(mon_client, resource_uri, metric_name, window_start, now)
                if result != _MetricResult.ZERO:
                    all_zero = False
                    break

            if not all_zero:
                continue

            # --- EMIT ---
            tags = getattr(gw, "tags", None) or {}  # spec 7: never None in output

            type_label = "VPN" if gateway_type == "Vpn" else "ExpressRoute"
            signals_used = [
                "Provisioning state is 'Succeeded'",
                f"Gateway type is '{gateway_type}'",
                "No configured in-scope connection resources "
                "(IPsec, Vnet2Vnet, ExpressRoute) -- list_connections() exhausted",
            ]
            if gateway_type == "Vpn":
                signals_used.append("No P2S (point-to-site) configuration present")
            else:
                signals_used.append(
                    "No ExpressRoute standby/bypass topology detected "
                    "(adminState not Disabled, no bypass-enabled connections)"
                )
            signals_used.append("allowVirtualWanTraffic signal is not True")
            signals_used.append(
                f"All applicable idle metrics ({', '.join(metrics_to_check)}) "
                f"resolved to zero over {_IDLE_WINDOW_DAYS} days "
                f"with >= {int(_MIN_COVERAGE * 100)}% daily bucket coverage"
            )

            findings.append(
                Finding(
                    provider="azure",
                    rule_id=_RULE_ID,
                    resource_type=_RESOURCE_TYPE,
                    resource_id=resource_uri,
                    region=location,
                    estimated_monthly_cost_usd=None,  # spec 10: always None
                    title=f"Idle Azure {type_label} Gateway",
                    summary=(
                        f"{gateway_type} gateway '{gw_name}' has no configured "
                        f"connections and zero applicable gateway activity "
                        f"over {_IDLE_WINDOW_DAYS} days"
                    ),
                    reason=(
                        f"No in-scope connections, no applicable bypass topology, "
                        f"and all idle metrics zero over {_IDLE_WINDOW_DAYS} days"
                    ),
                    risk=RiskLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=[
                            "Planned future connectivity rollout",
                            "DR / failover intent not visible in Azure control plane",
                            "Organizational ownership or IaC intent",
                            "Exact monthly billing amount",
                        ],
                        time_window=f"{_IDLE_WINDOW_DAYS} days",
                    ),
                    details={
                        "resource_name": gw_name,
                        "resource_group": resource_group,
                        "subscription_id": subscription_id,
                        "gateway_type": gateway_type,
                        "provisioning_state": "Succeeded",
                        "sku_name": sku_name,
                        "sku_tier": sku_tier,
                        "tags": tags,
                        "p2s_configured": False if gateway_type == "Vpn" else None,
                        "idle_window_days": _IDLE_WINDOW_DAYS,
                        "metrics_used": list(metrics_to_check),
                    },
                )
            )

        except (HttpResponseError, ServiceRequestError, ServiceResponseError):
            continue  # per-gateway retrieval failure -> skip this gateway (spec 12)

    return findings
