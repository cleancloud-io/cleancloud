# Azure Rule Spec — `azure.load_balancer.no_backends`

## 1. Rule Identity

- **Rule ID:** `azure.load_balancer.no_backends`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.Network/loadBalancers`
- **Finding resource_type:** `azure.load_balancer`

---

## 2. Intent

Detect **Standard Azure Load Balancers whose billable load-balancing configuration points to backend pools with no members**.

This rule is deliberately **conservative**. It is a **review-candidate** rule, not proof that
the load balancer is unused, safe to delete, or guaranteed to create savings if removed.

---

## 3. Azure Documentation Grounding

### 3.1 SKU and platform scope

Microsoft documents three Azure Load Balancer SKUs:

| SKU | Relevant behavior |
|---|---|
| Standard | Main production SKU; supports both NIC-based and IP-based backends |
| Basic (retired) | Retired legacy SKU |
| Gateway | Separate SKU for third-party NVAs / service chaining |

Source: *Azure Load Balancer SKUs*
URL: https://learn.microsoft.com/en-us/azure/load-balancer/skus

Rule consequence:

1. This rule should evaluate **Standard** SKU only.
2. Basic is out of scope.
3. Gateway is out of scope; its service-chaining semantics are different from ordinary
   frontend-to-backend load balancing.

### 3.2 Backend-pool membership models

Microsoft documents two ways of configuring Azure Load Balancer backend pools:

1. **NIC-based**
2. **IP address-based**

Microsoft also documents:

- IP-based backend pools are supported only for **Standard** Load Balancer
- the same load balancer can have NIC-based and IP-based backend pools
- a single backend pool must not mix NIC-targeted members and direct IP-address members

Source: *Backend pool management*
URL: https://learn.microsoft.com/en-us/azure/load-balancer/backend-pool-management

Rule consequence:

1. Membership checks must consider **both** backend models.
2. A pool is populated when it has either NIC-based members or IP-based backend addresses.
3. Checking only one backend representation is incomplete.

### 3.3 Load balancer resource shape

Microsoft's ARM/Bicep reference for `Microsoft.Network/loadBalancers` documents the control-plane
fields relevant to this rule, including:

- `id`
- `name`
- `location`
- `sku.name`
- `backendAddressPools`
- `frontendIPConfigurations`
- `loadBalancingRules`
- `outboundRules`
- `probes`
- `tags`

The same reference documents:

- `backendAddressPools[].properties.loadBalancerBackendAddresses`
- `loadBalancingRules[].properties.backendAddressPool`
- `loadBalancingRules[].properties.backendAddressPools`
- `outboundRules[].properties.backendAddressPool`

Source: *Microsoft.Network/loadBalancers template reference*
URL: https://learn.microsoft.com/en-us/azure/templates/microsoft.network/2024-10-01/loadbalancers

Rule consequence:

1. Load-balancing and outbound rules can reference backend pools explicitly.
2. Detection should be based on the pools referenced by billable rule surfaces, not on arbitrary
   unrelated pools attached to the resource.

### 3.4 Pricing meaning

Microsoft pricing documentation states:

- Azure Standard Load Balancer pricing depends on the number of configured
  **load-balancing rules** and **outbound rules**
- **Inbound NAT rules are free**
- there is **no hourly charge** for Standard Load Balancer when **no rules are configured**
- data processing charges are separate and usage-based

Source: *Azure Load Balancer pricing*
URL: https://azure.microsoft.com/en-us/pricing/details/load-balancer/

Rule consequence:

1. A Standard Load Balancer with **no load-balancing rules and no outbound rules** is not a strong
   direct cost signal for this rule and should be skipped.
2. This rule must **not** use a fixed flat monthly estimate such as `~$18/month`.
3. `estimated_monthly_cost_usd` should remain `None` unless a future implementation has a
   documented and region-aware pricing source.

### 3.5 Diagnostics are out of scope

Microsoft documents Azure Monitor diagnostics for Standard Load Balancer, including health-probe,
data-path, byte-count, packet-count, and SNAT-related metrics.

Source: *Standard Load Balancer diagnostics*
URL: https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-standard-diagnostics

Rule consequence:

This rule does **not** require metrics. Backend emptiness is a deterministic control-plane
condition and should not depend on Azure Monitor setup.

---

## 4. Detection Goal

Emit a finding when **all** of the following are true:

1. `lb.id` is present and non-empty
2. `lb.name` is present and non-empty
3. optional region filter matches the normalized location
4. provisioning state resolves to exactly `"Succeeded"`
5. SKU resolves to exactly `"Standard"`
6. at least one **billable rule** exists (`loadBalancingRules` or `outboundRules`)
7. all **relevant backend pools** referenced by those billable rules resolve successfully
8. every relevant backend pool has **zero members** under the backend-membership contract

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the load balancer is safe to delete
- that no future backend attachment is intended
- that a frontend public IP is unused
- that the load balancer has no traffic history
- that removing the load balancer will produce a specific monthly saving

---

## 6. Canonical Inputs

| API / signal | SDK method / source | Required permission |
|---|---|---|
| Load balancer inventory | `network_client.load_balancers.list_all()` | `Microsoft.Network/loadBalancers/read` |
| Load balancer fields | SDK projections for `id`, `name`, `location`, `sku`, `backend_address_pools`, `load_balancing_rules`, `outbound_rules`, `tags`, and provisioning state; raw/nested ARM-style fields only as fallback when needed | `Microsoft.Network/loadBalancers/read` |

No Azure Monitor metrics are required by this rule.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase ARM location string; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `sku_name` | Lowercase only for comparison. Only exact `standard` is eligible. |
| `tags` | `lb.tags or {}` — never `None` in output |
| `backend pool id` | Compare backend pool ARM ids after lowercasing and trimming any trailing slash; apply the same normalization to both referenced ids and backend-pool inventory ids before matching |
| rule and membership collections | Normalize `None` to empty collection before evaluation |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `lb.id` absent, `None`, or empty | Skip |
| 8.2 | `lb.name` absent, `None`, or empty | Skip |
| 8.3 | Region filter set and normalized location does not match | Skip |
| 8.4 | Provisioning state does not resolve to `"Succeeded"` under the provisioning-state contract | Skip |
| 8.5 | SKU does not resolve to exact lowercase `standard` | Skip |
| 8.6 | No billable rules exist | Skip |
| 8.7 | Relevant backend-pool set cannot be resolved reliably | Skip |
| 8.8 | Billable rules exist but the resolved relevant backend-pool set is empty | Skip |
| 8.9 | Any relevant backend pool has one or more members | Skip |
| 8.10 | All relevant backend pools resolve and all are empty | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Provisioning-state contract

Resolve provisioning state in this order:

1. SDK projection such as `lb.provisioning_state`
2. nested/raw properties projection if present
3. otherwise unknown

Only `"Succeeded"` is eligible for evaluation. Unknown or any other value must skip.

### 9.2 Billable-rule contract

For this rule:

- **billable load-balancing rule** = entry in `loadBalancingRules`
- **billable outbound rule** = entry in `outboundRules`
- **non-billable for this rule** = `inboundNatRules`

Required behavior:

1. Prefer SDK projections for `loadBalancingRules` and `outboundRules`; use raw/nested ARM-style fields only if needed.
2. Normalize missing rule collections (`None`) to empty before evaluation.
3. Count `loadBalancingRules` and `outboundRules` only.
4. If both sets are empty, skip.
5. Do not treat inbound NAT rules as evidence of billable load-balancing cost for this rule.

### 9.3 Relevant-backend-pool contract

The set of **relevant backend pools** is the union of pool ids referenced by:

1. `loadBalancingRules[].properties.backendAddressPool.id`
2. `loadBalancingRules[].properties.backendAddressPools[].id`
3. `outboundRules[].properties.backendAddressPool.id`

Required behavior:

1. Prefer SDK projections for rule-to-backend references; use raw/nested ARM-style fields only if needed.
2. Normalize missing reference collections (`None`) to empty before evaluation.
3. Normalize backend pool ids before comparison by lowercasing and trimming any trailing slash.
4. Normalize backend-pool inventory ids using the same lowercase + trailing-slash-trim contract before matching.
5. Match referenced ids against the normalized load balancer backend-pool inventory.
6. If billable rules exist but the resolved relevant backend-pool set is empty after normalization and resolution, skip the load balancer rather than emitting.
7. If a billable rule exists but its backend-pool reference is missing, unclear, or cannot be resolved, skip the load
   balancer rather than emitting.
8. Treat partially configured or transitional billable rules with incomplete backend linkage as incomplete configuration and skip.
9. Unreferenced backend pools are **context only** and must not suppress or trigger findings.

### 9.4 Backend-membership contract

A relevant backend pool is considered to have members when **either** of the following contains
at least one entry:

1. NIC-based members (SDK projection such as `backend_ip_configurations`, with raw/nested fallback only if needed)
2. IP-based members (SDK projection such as `load_balancer_backend_addresses`, with raw/nested fallback only if needed)

A relevant backend pool is empty only when **both** backend representations are absent or empty
after normalizing `None` to empty collections.

Rationale:

- Standard Load Balancer supports both membership models
- checking only NIC-based or only IP-based membership creates false positives

---

## 10. Contextual Signals

These may appear in evidence/details but must not create or suppress findings directly:

- `frontend_ip_configurations`
- `probes`
- `tags`
- unreferenced backend pools
- `inboundNatRules`

---

## 11. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** use a fixed monthly estimate such as `$18`
2. Do **not** infer cost from SKU alone
3. Do **not** infer cost when no billable rules are configured
4. Document that Standard Load Balancer pricing depends on configured billable rules and processed data

---

## 12. Finding Shape

### 12.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.load_balancer.no_backends"` |
| `resource_type` | `"azure.load_balancer"` |
| `resource_id` | Original ARM id from `lb.id` |
| `region` | Normalized location |
| `risk` | `LOW` |
| `confidence` | `HIGH` |
| `estimated_monthly_cost_usd` | `None` |

### 12.2 Required evidence

`signals_used` must include:

1. `"Load Balancer SKU is Standard"`
2. `"Billable rule count is {billable_rule_count}"`
3. `"All relevant backend pools evaluated to empty using NIC-based and IP-based membership checks"`

`signals_not_checked` should include:

1. `"Planned backend attachment or cutover intent"`
2. `"IaC-managed placeholder or staged deployment intent"`
3. `"Traffic history or future activation plans"`
4. `"Frontend public IP cost or attachment evaluated by other rules"`

### 12.3 Required details

| Key | Nullable |
|---|---|
| `resource_name` | No |
| `subscription_id` | No |
| `sku_name` | No |
| `sku_tier` | Yes |
| `backend_pool_count` | No |
| `relevant_backend_pool_count` | No |
| `frontend_ip_count` | No |
| `load_balancing_rule_count` | No |
| `outbound_rule_count` | No |
| `tags` | No (`{}` when absent) |

---

## 13. Failure Behavior

- If the load balancer list call raises, let the exception propagate
- If an individual load balancer record is malformed or missing required fields, skip that load balancer
- If billable-rule references cannot be resolved to backend pools reliably, skip that load balancer
- Do not silently emit on incomplete provisioning or backend-reference data

---

## 14. Acceptance Examples

### 14.1 Must emit

1. Standard SKU, provisioning state `"Succeeded"`, one load-balancing rule referencing one backend pool, and that pool has no NIC-based or IP-based members -> **EMIT**
2. Standard SKU, provisioning state `"Succeeded"`, two billable rules referencing two backend pools, and both referenced pools are empty -> **EMIT**
3. Standard SKU, provisioning state `"Succeeded"`, one outbound rule referencing one backend pool, and that pool is empty -> **EMIT**

### 14.2 Must skip

1. Basic or Gateway SKU -> **SKIP**
2. Provisioning state not `"Succeeded"` -> **SKIP**
3. No load-balancing rules and no outbound rules configured -> **SKIP**
4. A referenced backend pool has NIC-based members -> **SKIP**
5. A referenced backend pool has IP-based members -> **SKIP**
6. A billable rule references a backend pool that cannot be resolved -> **SKIP**
7. Region filter is set and location does not match -> **SKIP**
8. `lb.id == None` or `lb.name == None` -> **SKIP**

---

## 15. Anti-Goals

Implementations must **not**:

1. emit on Basic or Gateway SKU load balancers
2. emit solely because `backendAddressPools` is empty when no billable rules exist
3. use inbound NAT rules as billable-rule evidence for this rule
4. use a fixed monthly load balancer cost estimate
5. use unreferenced backend pools to suppress or trigger findings
6. require Azure Monitor metrics for evaluation

---

## 16. Rule Summary

Rule: `azure.load_balancer.no_backends`

- **Signal:** Standard Load Balancer with billable rule-backed backend pools that are empty
- **Type:** conservative review candidate
- **Scope:** Standard SKU only
- **Confidence:** `HIGH`
- **Risk:** `LOW`
- **Cost:** `None` (pricing depends on rule count and data processed; no hourly charge when no rules are configured)
