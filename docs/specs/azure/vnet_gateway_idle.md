# Azure Rule Spec — `azure.virtual_network_gateway.idle`

## 1. Rule Identity

- **Rule ID:** `azure.virtual_network_gateway.idle`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.Network/virtualNetworkGateways`
- **Finding resource_type:** `azure.virtual_network_gateway`

---

## 2. Intent

Detect Azure virtual network gateways that appear to have **no configured or active connectivity surfaces** and **no applicable gateway activity** over a conservative observation window, making them review candidates for cleanup or rightsizing.

This rule is deliberately **low-noise**. It is a **review-candidate** rule only, not proof that the gateway should be deleted, not proof that a standby topology is unnecessary, and not proof of a specific monthly saving.

---

## 3. Azure Documentation Grounding

### 3.1 VPN Gateway supports multiple connection modes and has ongoing compute cost

Microsoft documents that a VPN gateway can support:

- site-to-site connections
- VNet-to-VNet connections
- point-to-site connections
- coexisting ExpressRoute + VPN topologies

Microsoft also documents that multiple connections can exist on the same VPN gateway and that all VPN tunnels share the available gateway bandwidth.

Microsoft further documents that VPN gateways have hourly compute cost in addition to applicable data-transfer charges.

Source: *About VPN Gateway*
URL: https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways

Rule consequence:

1. A VPN gateway with configured connection surfaces is not equivalent to an unconfigured orphaned resource.
2. Idle evaluation must consider both S2S/VNet-to-VNet and P2S connectivity surfaces.
3. Exact monthly savings must not be inferred from SKU alone.

### 3.2 ExpressRoute gateways exchange routes and can bypass the gateway data path

Microsoft documents that an ExpressRoute virtual network gateway serves two key purposes:

1. exchanging IP routes between networks
2. routing network traffic between them

Microsoft also documents that **FastPath** allows on-premises traffic to bypass the virtual network gateway for improved performance.

Source: *About ExpressRoute virtual network gateways*
URL: https://learn.microsoft.com/en-us/azure/expressroute/expressroute-about-virtual-network-gateways

Rule consequence:

1. Zero gateway traffic alone is **not** sufficient proof of ExpressRoute idleness when bypass/FastPath is enabled.
2. A conservative rule should skip ExpressRoute topologies that can bypass the gateway data path.
3. ExpressRoute gateways may still have operational value through route exchange even when traffic is low.

### 3.3 Gateway control-plane resource shape

Microsoft ARM/Bicep and SDK documentation for `Microsoft.Network/virtualNetworkGateways` exposes fields including:

- `gatewayType`
- `provisioningState`
- `sku`
- `vpnClientConfiguration`
- `bgpSettings`
- `adminState`
- `allowRemoteVnetTraffic`
- `allowVirtualWanTraffic`
- `tags`

Sources:

- *Microsoft.Network/virtualNetworkGateways ARM / Bicep reference*
- *azure.mgmt.network.models.VirtualNetworkGateway*

URLs:

- https://learn.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworkgateways
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-network/azure.mgmt.network.models.virtualnetworkgateway?view=azure-python

Rule consequence:

These fields provide the canonical control-plane inputs for gateway type, provisioning stability, P2S configuration presence, ExpressRoute standby/bypass-related context, and unsupported Virtual WAN / hybrid-topology signals.

### 3.4 Connection resource shape

Microsoft ARM/Bicep and SDK documentation for `Microsoft.Network/connections` exposes fields including:

- `connectionType`
- `connectionStatus`
- `provisioningState`
- `ingressBytesTransferred`
- `egressBytesTransferred`
- `expressRouteGatewayBypass`

Microsoft documents `connectionStatus` known values as:

- `Unknown`
- `Connecting`
- `Connected`
- `NotConnected`

Sources:

- *Microsoft.Network/connections ARM / Bicep reference*
- *azure.mgmt.network.models.VirtualNetworkGatewayConnection*

URLs:

- https://learn.microsoft.com/en-us/azure/templates/microsoft.network/connections
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-network/azure.mgmt.network.models.virtualnetworkgatewayconnection?view=azure-python

Rule consequence:

1. Connection presence is a meaningful operational signal.
2. `Unknown`, `Connecting`, or missing connection status are not safe to treat as idle.
3. ExpressRoute gateway bypass / FastPath on any connection must be treated conservatively.

### 3.5 Azure Monitor exposes authoritative gateway and connection activity metrics

Microsoft documents Azure Monitor metrics for:

- `Microsoft.Network/virtualNetworkGateways`
- `Microsoft.Network/connections`
- VPN gateway monitoring reference metrics for P2S and tunnel activity

Documented metrics include:

- `AverageBandwidth`
- `InboundFlowsCount`
- `OutboundFlowsCount`
- `P2SConnectionCount`
- `P2SBandwidth`
- `ExpressRouteGatewayBitsPerSecond`
- `ExpressRouteGatewayPacketsPerSecond`
- `ExpressRouteGatewayActiveFlows`
- `ScalableExpressRouteGatewayBitsPerSecond`
- `ScalableExpressRouteGatewayPacketsPerSecond`
- `ScalableExpressRouteGatewayActiveFlows`
- `BitsInPerSecond`
- `BitsOutPerSecond`

Sources:

- *Supported metrics for microsoft.network/virtualnetworkgateways*
- *Monitor VPN Gateway reference*
- *Supported metrics for Microsoft.Network/connections*

URLs:

- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-network-virtualnetworkgateways-metrics
- https://learn.microsoft.com/en-us/azure/vpn-gateway/monitor-vpn-gateway-reference
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-network-connections-metrics

Rule consequence:

1. Idle evaluation should use documented Azure Monitor platform metrics rather than only ad-hoc control-plane heuristics.
2. P2S activity must be evaluated with P2S-specific metrics when P2S configuration exists.
3. Connection-level traffic metrics can be used as context or reinforcing evidence, but unresolved metrics should never be guessed.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `gateway.id` is present and non-empty
2. `gateway.name` is present and non-empty
3. the optional region filter matches the normalized location
4. `gateway.provisioning_state` resolves to exactly `"Succeeded"`
5. `gateway.gateway_type` resolves to exactly `"Vpn"` or `"ExpressRoute"`
6. `virtual_network_gateways.list_connections(...)` resolves reliably
7. no configured in-scope connection resource with type `IPsec`, `Vnet2Vnet`, or `ExpressRoute` is present
8. documented `allowVirtualWanTraffic` is not `True`
9. all applicable idle metrics resolve reliably for the same observation window
10. all applicable idle metrics satisfy the minimum coverage threshold
11. all applicable idle metrics are zero for that window

If any required signal cannot be established reliably, skip rather than emit.

This rule intentionally prioritizes **precision over recall** and skips unresolved or bypassed gateway topologies by design.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the gateway is safe
- that the topology has no disaster-recovery or failover purpose
- that no future branch/on-premises/VNet user will connect
- that a gateway with configured but quiet connections is unnecessary
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required control-plane surfaces

The implementation may use:

- subscription-wide gateway inventory
- per-gateway `get(...)`
- `virtual_network_gateways.list_connections(...)`
- Azure Monitor platform metrics on gateway and, if needed, connection resource IDs

It must not require:

- packet capture
- guest inspection
- external CMDB / ticketing data

### 6.2 Idle window

- Configurable parameter: none
- Fixed idle window: `30 days`

Reason:

- network gateways are high-impact infrastructure
- gateways may be intentionally quiet for DR or infrequent connectivity
- a longer window reduces false positives from short-lived outages, maintenance, or infrequent administrative access

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase ARM location string; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `provisioning_state` | Compare case-sensitively to exact `"Succeeded"` after SDK/raw resolution. |
| `gateway_type` | Compare case-sensitively to exact `"Vpn"` or `"ExpressRoute"` after SDK/raw resolution. |
| `connection_status` | Compare case-sensitively to documented values such as `"Connected"`, `"Connecting"`, `"Unknown"`, and `"NotConnected"`. Unknown or missing is not equivalent to inactive. |
| `in_scope_connection_resource` | A `Microsoft.Network/connections` resource returned by `virtual_network_gateways.list_connections(...)` whose resolved `connectionType` is exactly `IPsec`, `Vnet2Vnet`, or `ExpressRoute`. |
| `p2s_configured` | `True` when the resolved `vpnClientConfiguration` object contains any supported P2S field defined in section 9.3; otherwise `False` only when all listed P2S fields are confirmed absent or empty. |
| `express_route_gateway_bypass` | Treat `True` as FastPath/bypass enabled for the connection. |
| `virtual_wan_signal` | `True` only when the documented gateway field `allowVirtualWanTraffic` resolves to `True`; `False` when it resolves to `False`; otherwise unknown. This specification does not infer Virtual WAN or hub-managed topology from undocumented fields. |
| `metric_coverage_ratio` | `observed_parseable_buckets / expected_buckets` for the defined 30-day daily-bucket query. |
| `no_configured_connection_resources` | `True` only when `list_connections(...)` completes successfully, pagination is exhausted, and zero in-scope connection resources remain after type resolution. |
| `tags` | `gateway.tags or {}` — never `None` in output. Tags are contextual only for this rule. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `id` absent, `None`, or empty | Skip |
| 8.2 | `name` absent, `None`, or empty | Skip |
| 8.3 | Region filter set and normalized location does not match | Skip |
| 8.4 | `provisioning_state` does not resolve to `"Succeeded"` | Skip |
| 8.5 | `gateway_type` does not resolve to `"Vpn"` or `"ExpressRoute"` | Skip |
| 8.6 | Any required control-plane surface is missing, conflicting, or unresolvable | Skip |
| 8.7 | Any configured `in_scope_connection_resource` is present | Skip |
| 8.8 | VPN gateway has confirmed P2S configuration present | Skip |
| 8.9 | Documented Virtual WAN signal is present (`allowVirtualWanTraffic == True`) | Skip |
| 8.10 | ExpressRoute standby/bypass topology is present (`adminState == "Disabled"` or any bypass-enabled connection) | Skip |
| 8.11 | Any applicable idle metric cannot be resolved reliably for the idle window | Skip |
| 8.12 | Any applicable idle metric fails the minimum coverage threshold for the idle window | Skip |
| 8.13 | Any applicable idle metric is non-zero over the idle window | Skip |
| 8.14 | All required signals resolve, no configured `in_scope_connection_resource` remains, no P2S configuration remains, documented Virtual WAN signal is absent, and applicable idle metrics are zero with sufficient coverage for 30 days | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Gateway-state contract

Resolve gateway provisioning state in this order:

1. SDK projection such as `gateway.provisioning_state`
2. nested/raw properties projection such as `properties.provisioningState`
3. otherwise unknown

Resolve gateway type in this order:

1. SDK projection such as `gateway.gateway_type`
2. nested/raw properties projection such as `properties.gatewayType`
3. otherwise unknown

Required behavior:

1. Only exact `"Succeeded"` is eligible.
2. Only exact `"Vpn"` and `"ExpressRoute"` are in scope.
3. Unknown, conflicting, or any other values must skip.

### 9.2 Connection-surface contract

Resolve configured gateway connections using the gateway’s authoritative `virtual_network_gateways.list_connections(...)` surface.

Canonical definition:

- **In-scope connection resource:** a `Microsoft.Network/connections` resource returned by `virtual_network_gateways.list_connections(...)` whose resolved `connectionType` is exactly `IPsec`, `Vnet2Vnet`, or `ExpressRoute`

Required behavior:

1. Resolve connection type in this order:
   - SDK projection such as `connection.connection_type`
   - nested/raw properties projection such as `properties.connectionType`
   - otherwise unknown
2. Treat any returned `in_scope_connection_resource` as configured connection presence.
3. Do **not** treat `connection_status == "NotConnected"` as equivalent to “no configured connection”.
4. An empty connection result is authoritative only when enumeration completes successfully, pagination is exhausted, and no partial-response ambiguity remains.
5. If any returned connection has unknown or conflicting type resolution, skip.
6. If connection listing fails, is partial, or cannot be resolved reliably, skip.
7. If any configured `in_scope_connection_resource` is present, the gateway must skip.

Scope boundary:

- This specification treats `virtual_network_gateways.list_connections(...)` as the sole authoritative ExpressRoute linkage surface.
- It does **not** infer ExpressRoute linkage from separate circuit inventory, peering inventory, route tables, or undocumented cross-resource associations outside that connection-listing surface.

Rationale:

Configured gateway connections represent intentional network topology. A conservative enterprise-quality rule should not emit merely because a configured connection is currently quiet or disconnected.

### 9.3 P2S configuration contract

For VPN gateways:

1. Resolve `vpnClientConfiguration` in this order:
   - SDK projection such as `gateway.vpn_client_configuration`
   - nested/raw properties projection such as `properties.vpnClientConfiguration`
   - otherwise unknown
2. For every supported P2S field group, resolve values using the same precedence rule:
   - SDK projection on the resolved `vpnClientConfiguration` object
   - raw camelCase property on the resolved `vpnClientConfiguration` object
   - raw snake_case property on the resolved `vpnClientConfiguration` object
   - otherwise unknown
3. Supported P2S field groups are:
   - address pool: `vpn_client_address_pool` / `vpnClientAddressPool`
   - client connection configurations: `vng_client_connection_configurations` / `vngClientConnectionConfigurations`
   - root certificates: `vpn_client_root_certificates` / `vpnClientRootCertificates`
   - revoked certificates: `vpn_client_revoked_certificates` / `vpnClientRevokedCertificates`
   - authentication types: `vpn_authentication_types` / `vpnAuthenticationTypes`
   - client protocols: `vpn_client_protocols` / `vpnClientProtocols`, including documented protocol selections such as `OpenVPN` and `IkeV2`
   - AAD / Entra auth tenant: `aad_tenant` / `aadTenant`
   - AAD / Entra auth audience: `aad_audience` / `aadAudience`
   - AAD / Entra auth issuer: `aad_issuer` / `aadIssuer`
4. If any field group resolves to a present, non-empty configured value, treat P2S as configured.
5. If any field group has conflicting resolved values across the precedence chain, skip.
6. If P2S configuration presence cannot be resolved reliably, skip.
7. If any P2S configuration is present, skip rather than infer idleness from current client count alone.

Rationale:

Configured P2S gateways can be intentionally retained for remote access even when current client count is zero.

### 9.4 ExpressRoute standby / bypass contract

For ExpressRoute gateways:

1. If `adminState == "Disabled"`, skip.
2. If any connection exposes `expressRouteGatewayBypass == True`, skip.
3. If `list_connections(...)` returns any `in_scope_connection_resource` whose resolved `connectionType` is exactly `ExpressRoute`, skip even when all observed traffic metrics are zero.
4. If bypass/standby-related state cannot be resolved reliably, skip.

Rationale:

Microsoft documents that ExpressRoute FastPath can bypass gateway data forwarding, so zero gateway traffic does not prove idleness in bypassed topologies.

### 9.5 Unsupported Virtual WAN / hybrid-topology contract

This specification does **not** define idle semantics for Virtual WAN / hub-managed / hybrid attachment patterns beyond the documented gateway field `allowVirtualWanTraffic`.

Required behavior:

1. Resolve the documented field `allowVirtualWanTraffic` from SDK/raw gateway payload.
2. If `allowVirtualWanTraffic == True`, skip.
3. If `allowVirtualWanTraffic` is absent or unresolved, do **not** infer Virtual WAN or hub-managed topology from undocumented fields.

Rationale:

Microsoft documents `allowVirtualWanTraffic` on the gateway resource shape, but this specification does not claim broader authoritative Virtual WAN linkage detection beyond that documented field.

### 9.6 Idle-metrics contract

All applicable metrics must be queried over the same window:

- `window_end = now`
- `window_start = now - 30 days`
- `time_grain = 1 day`

Required behavior:

1. Metric absence, retrieval failure, empty/unusable series, or unparseable datapoints -> skip
2. Use platform metrics only; do not infer zero from missing data
3. For each required metric, compute coverage using daily buckets across the 30-day window
4. Minimum required coverage per metric: `>= 80%` of expected daily buckets
5. If any required metric falls below the coverage threshold, skip
6. Emit only when every parseable datapoint in every required metric is exactly zero over the window
7. Sparse or partially populated time series are not equivalent to zero usage

#### 9.6.1 VPN gateways

For VPN gateways, require all of the following gateway metrics to resolve and be zero:

- `AverageBandwidth`
- `InboundFlowsCount`
- `OutboundFlowsCount`

If the gateway family exposes P2S metrics despite no configured P2S surface, they may be included as reinforcing context only; they must not override the control-plane contract.

#### 9.6.2 ExpressRoute gateways

For ExpressRoute gateways, use the applicable metric family based on SKU / scale model:

1. Standard / HighPerformance / UltraPerformance / AZ gateway family:
   - `ExpressRouteGatewayBitsPerSecond`
   - `ExpressRouteGatewayPacketsPerSecond`
   - `ExpressRouteGatewayActiveFlows`
2. Scalable gateway family:
   - `ScalableExpressRouteGatewayBitsPerSecond`
   - `ScalableExpressRouteGatewayPacketsPerSecond`
   - `ScalableExpressRouteGatewayActiveFlows`

All applicable metrics must resolve and be zero for the window.

### 9.7 Connection metrics as reinforcing diagnostics

If connection resources are inspected before exclusion, `Microsoft.Network/connections` metrics such as:

- `BitsInPerSecond`
- `BitsOutPerSecond`

may be included as reinforcing diagnostics.

However:

1. connection metrics must not override the no-configured-connections contract
2. a configured connection with zero traffic is still a skip, not an emit

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** use flat hardcoded monthly SKU estimates
2. Do **not** infer cost from SKU alone
3. Do **not** infer cost from current traffic alone
4. State only that gateways have meaningful ongoing gateway compute cost and may also incur transfer-related charges depending on service and topology

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.virtual_network_gateway.idle"` |
| `resource_type` | `"azure.virtual_network_gateway"` |
| `resource_id` | original ARM id from `gateway.id` |
| `region` | normalized location |
| `risk` | `HIGH` |
| `confidence` | `HIGH` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required evidence

`signals_used` must clearly disclose:

1. provisioning state is `"Succeeded"`
2. gateway type is `"Vpn"` or `"ExpressRoute"`
3. no configured `in_scope_connection_resource` was present
4. no P2S configuration was present for VPN gateways
5. no standby/bypass topology was present for ExpressRoute gateways
6. documented `allowVirtualWanTraffic` signal was not `True`
7. applicable idle metrics resolved to zero over 30 days with sufficient coverage

`signals_not_checked` should include remaining blind spots such as:

1. planned future connectivity rollout
2. DR / failover intent not visible in Azure control plane
3. organizational ownership / IaC intent
4. exact monthly billing amount

### 11.3 Required details

Details should include at least:

- `resource_name`
- `resource_group`
- `subscription_id`
- `gateway_type`
- `provisioning_state`
- `sku_name`
- `sku_tier`
- `tags`

May also include:

- `p2s_configured`
- `configured_connection_count`
- `admin_state`
- `idle_window_days`
- `metric_coverage_ratio_by_metric`
- names of the gateway metrics used

---

## 12. Failure Behavior

- If subscription-wide gateway inventory fails, let the exception propagate
- If per-gateway `get(...)`, `list_connections(...)`, unsupported-topology resolution, or metric retrieval fails for a specific gateway, skip that gateway
- If a gateway record is malformed or missing required fields, skip that gateway
- Do not emit on partial or unresolved connection, P2S, bypass, unsupported-topology, or metric state
