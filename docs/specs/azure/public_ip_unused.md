# Azure Rule Spec — `azure.network.public_ip.unused`

## 1. Rule Identity

- **Rule ID:** `azure.network.public_ip.unused`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.Network/publicIPAddresses`
- **Finding resource_type:** `azure.network.public_ip`

---

## 2. Intent

Detect **Azure Public IP Address resources that are fully unattached across known Azure control-plane
linkage surfaces** and therefore represent conservative cleanup review candidates.

This rule is deliberately **low-noise**. It is a **review-candidate** rule only, not proof that the
Public IP is delete-safe, not proof that no future attachment is intended, and not proof of a specific
monthly saving.

---

## 3. Azure Documentation Grounding

### 3.1 Public IP association meaning

Microsoft documents that Azure Public IP resources can be associated with many Azure resource types,
including:

- virtual machine network interfaces
- virtual machine scale sets
- public load balancers
- virtual network gateways
- NAT gateways
- application gateways
- Azure Firewalls
- Bastion Hosts
- Route Servers
- API Management

Source: *Public IP addresses*
URL: https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses

Rule consequence:

1. Checking only VM/NIC-style linkage is incomplete.
2. This rule must treat Public IP attachment as a broader Azure platform concept, not just a NIC concept.

### 3.2 SKU and allocation meaning

Microsoft documents:

- Public IP SKU can be **Standard (v1 or v2)** or **Basic**
- Standard Public IPs are **static only**
- Basic Public IPs may be dynamic or static depending on IP version
- dynamic Public IPs receive an address when associated with a resource

Source: *Public IP addresses*
URL: https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses#at-a-glance

Rule consequence:

1. An unattached **dynamic** Public IP without an assigned `ipAddress` is a weak placeholder-style signal.
2. To reduce noise, the rule should skip unattached dynamic Public IP resources that do not currently hold
   an assigned IP address.

### 3.3 Pricing meaning

Microsoft pricing documentation states that Public IP pricing varies by SKU and type, including:

- Basic (ARM)
- Standard (ARM)
- Standard v2 (ARM)
- Global (ARM)

The same pricing page also explains that billing behavior differs between static and other Public IP types.

Source: *IP Addresses pricing*
URL: https://azure.microsoft.com/en-us/pricing/details/ip-addresses/

Rule consequence:

1. This rule must **not** use a single flat estimate such as `$3.60/month`.
2. `estimated_monthly_cost_usd` should remain `None` unless a future implementation has a documented,
   region-aware pricing source with SKU/allocation specificity.

### 3.4 SDK control-plane shape used by implementations

The Azure Python SDK `PublicIPAddress` model exposes control-plane linkage fields including:

- `ip_configuration`
- `nat_gateway`
- `service_public_ip_address`
- `linked_public_ip_address`
- `provisioning_state`
- `public_ip_allocation_method`
- `ip_address`

This model is generated from the Azure Network control-plane schema and is the implementation surface
used by this rule.

Rule consequence:

The rule should resolve attachment by evaluating these linkage fields, using SDK projections first and
nested/raw fallback only if needed, including ARM-style nested properties fields when present.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `public_ip.id` is present and non-empty
2. `public_ip.name` is present and non-empty
3. optional region filter matches the normalized location
4. provisioning state resolves to exactly `"Succeeded"`
5. the Public IP is **not attached** under the canonical attachment contract
6. the Public IP is **not** an unattached dynamic placeholder with no assigned `ipAddress`

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the Public IP is safe to delete
- that DNS references no longer exist
- that firewall allowlists will not break
- that no future attachment is planned
- that the resource is currently billed at a specific monthly amount

---

## 6. Canonical Inputs

| API / signal | SDK method / source | Required permission |
|---|---|---|
| Public IP inventory | `network_client.public_ip_addresses.list_all()` | `Microsoft.Network/publicIPAddresses/read` |
| Public IP fields | SDK projections for `id`, `name`, `location`, `sku`, `public_ip_allocation_method`, `ip_address`, `ip_configuration`, `nat_gateway`, `service_public_ip_address`, `linked_public_ip_address`, `provisioning_state`, `ip_tags`, `zones`, `tags`; raw/nested fallback only if needed | `Microsoft.Network/publicIPAddresses/read` |

No Azure Monitor metrics are required by this rule.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase ARM location string; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `public_ip_allocation_method` | Compare case-sensitively to canonical Azure values such as `"Static"` or `"Dynamic"` after SDK/raw resolution. |
| `provisioning_state` | Compare case-sensitively to canonical Azure value `"Succeeded"` after SDK/raw resolution. |
| attachment references | Treat `None` as absent. A reference with a non-empty `id` is attached. |
| `tags` | `public_ip.tags or {}` — never `None` in output |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `id` absent, `None`, or empty | Skip |
| 8.2 | `name` absent, `None`, or empty | Skip |
| 8.3 | Region filter set and normalized location does not match | Skip |
| 8.4 | Provisioning state does not resolve to `"Succeeded"` | Skip |
| 8.5 | Any attachment linkage is present under the attachment contract | Skip |
| 8.6 | Dynamic-placeholder contract is triggered | Skip |
| 8.7 | All required signals resolve, all known attachment linkages are absent, and the dynamic-placeholder contract is not triggered | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Provisioning-state contract

Resolve provisioning state in this order:

1. SDK projection such as `public_ip.provisioning_state`
2. nested/raw properties projection if present
3. otherwise unknown

Only `"Succeeded"` is eligible for evaluation. Unknown or any other value must skip.

### 9.2 Attachment contract

Treat the Public IP as **attached** when any one of the following resolves to a non-empty reference:

1. `ip_configuration`
2. `nat_gateway`
3. `service_public_ip_address`
4. `linked_public_ip_address`

Required behavior:

1. Prefer SDK projections first.
2. Fall back to the matching ARM-style `properties.*` field only if needed.
3. When a reference object is present, a non-empty `id` counts as attached.
4. If attachment linkage cannot be resolved reliably, skip rather than emit.

Canonical SDK-to-ARM linkage mapping:

| SDK field | Raw ARM fallback |
|---|---|
| `ip_configuration` | `properties.ipConfiguration` |
| `nat_gateway` | `properties.natGateway` |
| `service_public_ip_address` | `properties.servicePublicIPAddress` |
| `linked_public_ip_address` | `properties.linkedPublicIPAddress` |

Rationale:

- Azure documents many valid Public IP association targets beyond NICs.
- Azure SDK exposes multiple control-plane linkage fields beyond `ip_configuration`.
- A Public IP with any known control-plane attachment should not be emitted as unused.

### 9.3 Dynamic-placeholder contract

If the Public IP is unattached under the attachment contract:

- and `public_ip_allocation_method == "Dynamic"`
- and `ip_address` is absent or empty

then skip rather than emit.

Rationale:

Microsoft documents that dynamic Public IPs receive an address when associated. An unattached dynamic
resource without an assigned IP is a weaker placeholder/provisioning signal and would create more noise
than value in this rule.

### 9.4 Context-only fields

The following may appear in details/evidence but must not create or suppress findings directly:

- `sku`
- `public_ip_address_version`
- `public_ip_prefix`
- `dns_settings`
- `delete_option`
- `ip_tags`
- `zones`

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** use a fixed monthly estimate such as `$3.60`
2. Do **not** infer cost from attachment absence alone
3. Do **not** infer cost from SKU without a region-aware pricing source
4. Document that Azure Public IP pricing varies by SKU/type and billing semantics

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.network.public_ip.unused"` |
| `resource_type` | `"azure.network.public_ip"` |
| `resource_id` | Original ARM id from `public_ip.id` |
| `region` | Normalized location |
| `risk` | `LOW` |
| `confidence` | `HIGH` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required evidence

`signals_used` must include:

1. `"Provisioning state is Succeeded"`
2. `"Public IP has no resolved attachment via ip_configuration, nat_gateway, service_public_ip_address, or linked_public_ip_address"`
3. `"Dynamic-placeholder contract not triggered"`

`signals_not_checked` should include:

1. `"Planned future association or reserved intent"`
2. `"DNS records or firewall allowlist references"`
3. `"Application-level reachability or traffic history"`
4. `"Exact Azure billing amount for this Public IP"`

### 11.3 Required details

| Key | Nullable |
|---|---|
| `resource_name` | No |
| `subscription_id` | No |
| `allocation_method` | Yes |
| `ip_address` | Yes |
| `sku` | Yes |
| `ip_version` | Yes |
| `ip_tags` | Yes |
| `attached` | No |
| `tags` | No (`{}` when absent) |

---

## 12. Failure Behavior

- If the Public IP list call raises, let the exception propagate
- If an individual Public IP record is malformed or missing required fields, skip that record
- If attachment linkage or provisioning state cannot be resolved reliably, skip that record
- Do not silently emit on incomplete control-plane attachment data

---

## 13. Acceptance Examples

### 13.1 Must emit

1. `provisioning_state == "Succeeded"`, all four attachment linkages absent, allocation `"Static"` -> **EMIT**
2. `provisioning_state == "Succeeded"`, all four attachment linkages absent, allocation `"Dynamic"`, `ip_address` present -> **EMIT**

### 13.2 Must skip

1. `ip_configuration` present -> **SKIP**
2. `nat_gateway` present -> **SKIP**
3. `service_public_ip_address` present -> **SKIP**
4. `linked_public_ip_address` present -> **SKIP**
5. allocation `"Dynamic"` and `ip_address == None` -> **SKIP**
6. `provisioning_state != "Succeeded"` -> **SKIP**
7. region filter mismatch -> **SKIP**
8. `id == None` or `name == None` -> **SKIP**

---

## 14. Anti-Goals

Implementations must **not**:

1. treat `ip_configuration is None` as sufficient proof of unused by itself
2. use a fixed Public IP monthly cost estimate
3. emit on unattached dynamic placeholder-style Public IPs with no assigned address
4. infer delete safety from attachment absence
5. require Azure Monitor metrics for this rule

---

## 15. Rule Summary

Rule: `azure.network.public_ip.unused`

- **Signal:** fully unattached Public IP across known Azure control-plane linkage fields
- **Type:** conservative review candidate
- **Confidence:** `HIGH`
- **Risk:** `LOW`
- **Cost:** `None` (pricing varies by SKU/type and is not estimated by this rule)
