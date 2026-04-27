# GCP Rule Spec - `gcp.compute.ip.unused`

## 1. Rule Identity

- **Rule ID:** `gcp.compute.ip.unused`
- **Provider:** GCP
- **Resource type:** Compute Engine address reservation
- **Finding resource_type:** `gcp.compute.address` for regional addresses, `gcp.compute.global_address` for global addresses

---

## 2. Intent

Detect **static external IPv4 address reservations that are currently in `RESERVED` state and therefore represent higher-cost, not-in-use external IP allocations** so they can be reviewed as conservative cleanup candidates.

This rule is deliberately **precision-first**. It is a **review-candidate** rule only, not proof that releasing the address is safe, not proof that no allowlists or DNS dependencies exist, and not proof that the public list price exactly matches the customer bill.

---

## 3. GCP Documentation Grounding

### 3.1 Regional and global address resources expose canonical status and usage fields

Google documents regional and global Compute Engine address resources with:

1. `status` values `RESERVING`, `RESERVED`, and `IN_USE`
2. `users[]` as the output-only URLs of resources using the address
3. `addressType` as `INTERNAL` or `EXTERNAL`
4. `ipVersion` as `IPV4` or `IPV6`
5. `purpose`
6. `networkTier`

Sources:

- *Resource: addresses*
- *Resource: globalAddresses*

URLs:

- https://cloud.google.com/compute/docs/reference/rest/v1/addresses
- https://cloud.google.com/compute/docs/reference/rest/v1/globalAddresses

Rule consequence:

1. Current address state must be evaluated from documented control-plane fields.
2. `status == "RESERVED"` is the canonical not-in-use state for this rule.
3. `IN_USE` and `RESERVING` are out of scope.

### 3.2 GCP bills external IPv4 addresses differently when unused vs in use

Google documents current external IP pricing as follows:

1. You are charged for static and ephemeral external IP addresses.
2. A static external IP address that is assigned but unused is charged at **$0.01 per hour**.
3. Static and ephemeral IP addresses in use on standard VMs are charged at **$0.005 per hour**.
4. Static and ephemeral IP addresses used by Cloud NAT are charged at **$0.005 per hour**.
5. Static external IP addresses assigned to forwarding rules are **not charged**.
6. Google considers a static external IP address **in use** when it is associated with a VM instance whether the VM is running or stopped.
7. If a static external IP address is dissociated from the instance or the instance is deleted, Google considers it **not in use**.

Source:

- *VPC pricing - External IP address pricing*

URL:

- https://cloud.google.com/vpc/pricing#ipaddress

Rule consequence:

1. This rule must target the **higher-cost unused static external IPv4** state, not all external IP billing.
2. This rule must not treat in-use static IPs as eligible findings even though they are still billed.
3. Addresses attached to forwarding rules must not be emitted as unused.
4. The rule may rely only on documented address control-plane state.
5. It must not invent separate indirect attachment heuristics beyond what the address APIs expose.

### 3.3 Internal IPs and external IPv6 are out of scope for this billing rule

Google documents:

1. There is **no charge** for static or ephemeral internal IP addresses.
2. You are not charged for external IPv6 address ranges assigned to subnets, for external IPv6 addresses assigned to VM instances, or for static regional IPv6 addresses.

Source:

- *VPC pricing - Internal IP address pricing / External IP address pricing*

URL:

- https://cloud.google.com/vpc/pricing#ipaddress

Rule consequence:

1. Internal addresses are out of scope.
2. This rule should be scoped to **external IPv4** only.
3. IPv6 addresses must not be emitted by this rule.

### 3.4 Aggregated regional inventory supports partial success and warning surfaces

Google documents `addresses.aggregatedList` as the aggregated regional inventory surface and recommends `returnPartialSuccess=true` to prevent failure. The response can include scoped `warning` data and top-level `unreachables`.

Source:

- *Method: addresses.aggregatedList*

URL:

- https://cloud.google.com/compute/docs/reference/rest/v1/addresses/aggregatedList

Rule consequence:

1. Regional address inventory may be enumerated from aggregated inventory.
2. Partial coverage must be surfaced conservatively and must not be treated as proof that the project is clean.

### 3.5 Cloud NAT automatic NAT IPs are reserved external IPs managed by Cloud NAT

Google documents that Public NAT automatic allocation:

1. creates **static (reserved) regional external IP addresses**
2. adds and removes them automatically based on gateway needs
3. exposes them in the list of static external IP addresses

Google also documents address `purpose = NAT_AUTO` for regional external IP addresses used by Cloud NAT automatic NAT IP address allocation.

Sources:

- *Cloud NAT - IP addresses and ports*
- *Resource: addresses*

URLs:

- https://cloud.google.com/nat/docs/ports-and-addresses
- https://cloud.google.com/compute/docs/reference/rest/v1/addresses

Rule consequence:

1. A reserved external IP with `purpose == "NAT_AUTO"` is not an unused customer-held reservation.
2. `NAT_AUTO` addresses must be excluded even if they appear in the static external IP list.

### 3.6 Network tier is contextual, not a detection primitive

Google documents:

1. internal IP addresses are always `PREMIUM`
2. global external IP addresses are always `PREMIUM`
3. regional external IP addresses can be `PREMIUM` or `STANDARD`

Sources:

- *Resource: addresses*
- *Resource: globalAddresses*

URLs:

- https://cloud.google.com/compute/docs/reference/rest/v1/addresses
- https://cloud.google.com/compute/docs/reference/rest/v1/globalAddresses

Rule consequence:

1. `networkTier` may be useful reviewer context.
2. `networkTier` must not override the canonical unused-state contract.

---

## 4. Detection Goal

Emit only when the address passes every rule in section **8**. Section **8** is the single source of truth for decisioning; sections **7** and **9** define normalization and evaluation contracts.

Decision precedence is:

1. normalize scope and required fields
2. apply hard scope and billable-surface exclusions
3. apply canonical unused-state and Cloud NAT exclusions
4. treat `users[]` only as contradictory current-use evidence
5. emit only when no exclusion applies

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that releasing the IP is operationally safe
- that DNS, firewall allowlists, or customer integrations no longer depend on the address
- that no imminent re-attachment is intended
- that the address is not intentionally held for manual failover, allowlisting, or cutover use
- that the exact billed amount matches public USD list pricing

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| `addresses.aggregatedList` | enumerate regional address reservations, including status, users, address type, IP version, purpose, network tier, labels, and warnings |
| `globalAddresses.list` | enumerate global address reservations with the same control-plane fields except regional scope |
| VPC pricing page | authoritative billing semantics for unused static external IPv4 addresses |

### 6.2 Authentication / permissions

Required permissions:

- `compute.addresses.list`
- `compute.globalAddresses.list`

Typical predefined role:

- `roles/compute.viewer`

### 6.3 Thresholds

This rule has **no user-configurable parameter**.

Detection is based on current control-plane state, not age.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `scope_key` | For aggregated regional inventory, supported form is exactly `regions/REGION`. Any other value is unsupported and must skip. |
| `scope` | `"regional"` for `regions/REGION`; `"global"` for global address inventory. |
| `region` | For regional addresses, use the region name from the aggregated scope key. For global addresses, use exact string `"global"`. |
| `status` | Resolve from documented address `status` and compare case-sensitively to canonical values such as `"RESERVED"` and `"IN_USE"`. |
| `address_type` | Resolve from documented `addressType` and compare case-sensitively to exact `"EXTERNAL"`. Unknown / unresolved must skip. |
| `ip_version` | Resolve from documented `ipVersion` and compare case-sensitively to exact `"IPV4"`. Unknown / unresolved must skip. |
| `purpose` | Preserve exact documented purpose string when present. |
| `users` | Treat `users[]` as contextual current-use evidence. A non-empty list means in-use evidence and must skip. Missing or empty does not override status. |
| `network_tier` | Preserve exact documented value when present; if absent, preserve as unknown context rather than guessing. |
| `labels` | `address.labels or {}` - never `None` in output. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | address record is malformed or `name` absent / empty | Skip |
| 8.2 | regional aggregated scope key is unsupported or malformed | Skip |
| 8.3 | region filter is set and the normalized regional scope does not match | Skip |
| 8.4 | address is global and a region filter is set | Skip |
| 8.5 | `status` is absent, unknown, or not exactly `"RESERVED"` | Skip |
| 8.6 | `addressType` is absent, unknown, or not exactly `"EXTERNAL"` | Skip |
| 8.7 | `ipVersion` is absent, unknown, or not exactly `"IPV4"` | Skip |
| 8.8 | `purpose == "NAT_AUTO"` | Skip |
| 8.9 | `users[]` resolves to one or more entries | Skip |
| 8.10 | all required signals resolve and the address is an external IPv4 reservation in `RESERVED` state with no contradictory current-use evidence | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Inventory contract

Required behavior:

1. Enumerate regional addresses from `addresses.aggregatedList`.
2. Use `returnPartialSuccess=true` for aggregated regional inventory.
3. Enumerate global addresses from `globalAddresses.list` unless a region filter is active.
4. Treat aggregated scope keys of the form `regions/REGION` as regional.
5. Skip any unexpected regional scope kind.
6. If aggregated inventory returns scoped warnings, top-level warnings, or `unreachables`, implementations must not silently treat the result as complete project coverage.
7. Under partial aggregated coverage, item-level findings from successfully enumerated scopes may still be emitted, but zero findings must not be interpreted as a clean project.

### 9.2 Unused-state contract

Required behavior:

1. `status == "RESERVED"` is the canonical eligible state.
2. `status == "IN_USE"` must skip.
3. `status == "RESERVING"` must skip.
4. Unknown or unresolved status must skip.

Rationale:

Google explicitly documents `RESERVED` as currently reserved and available to use, while `IN_USE` is currently being used by another resource.

### 9.3 Billable-scope contract

Required behavior:

1. Only `addressType == "EXTERNAL"` is in scope.
2. Only `ipVersion == "IPV4"` is in scope.
3. Internal addresses must skip.
4. IPv6 addresses must skip.

Rationale:

Google explicitly documents no charge for internal IP addresses and no-charge external IPv6 cases relevant to this rule surface. This rule is therefore scoped to the billed unused static external IPv4 contract.

### 9.4 Cloud NAT exclusion contract

Required behavior:

1. If `purpose == "NAT_AUTO"`, skip.
2. `NAT_AUTO` must be treated as Cloud NAT automatic allocation, not as a customer-held unused reservation.

### 9.5 `users[]` contract

Required behavior:

1. A non-empty `users[]` list is contradictory current-use evidence and must skip.
2. Empty or absent `users[]` does not create eligibility by itself; canonical eligibility still depends on section `9.2`.
3. `users[]` is supportive evidence only, not a substitute for the documented `status` contract.
4. Implementations must not separately traverse indirect dependency chains such as forwarding rules, target proxies, or backend services.
5. A future rule revision may add those surfaces only if it is backed by an official documented contract.

### 9.6 Global / region-filter contract

Required behavior:

1. Regional addresses participate in exact region filtering by normalized regional name.
2. Global addresses have no regional scope and must be skipped when a region filter is active.

### 9.7 Cost model contract

Required behavior:

1. `estimated_monthly_cost_usd = 7.30`
2. The estimate must be derived from Google’s documented **$0.01/hour** price for a static IP address that is assigned but unused, using a normalized **730-hour month**.
3. The summary/evidence must make clear that this is an **estimated** public USD list-price monthly equivalent derived from hourly pricing, not contract-specific billing.
4. The monthly figure is a rounded estimate for comparability across rules; authoritative billing remains hourly.
5. Do not use the lower in-use rates for standard VMs, Spot/preemptible VMs, Cloud NAT, or forwarding-rule attachments.

Rationale:

Google’s current pricing page explicitly documents the higher unused static external IPv4 hourly rate. The rule’s monthly estimate may therefore be derived from that rate using a normalized 730-hour month as a rounded cross-rule comparison figure, while still disclosing that actual billing remains hourly and can vary by currency, contract, or exact calendar month length.

### 9.8 Failure behavior contract

Required behavior:

1. Permission failures for regional inventory should surface as a permission error, not silent empty findings.
2. Permission failures for global inventory should also surface as a permission error during full-scope scans; they must not silently degrade to regional-only coverage.
3. If the Compute Engine API for addresses is unavailable / disabled for the project, returning no findings is acceptable.
4. Malformed address records should be skipped item-by-item rather than failing the whole rule.
5. Partial aggregated regional coverage must be surfaced as incomplete coverage or degraded scan state; it must not silently collapse into a clean no-findings outcome.

---

## 10. Confidence and Risk

### 10.1 Confidence

| Condition | Confidence |
|---|---|
| Finding emitted | `HIGH` |

Rationale:

Google documents `RESERVED` vs `IN_USE` control-plane state explicitly, so current unused reservation state is a high-confidence signal.

### 10.2 Risk

| Condition | Risk |
|---|---|
| Finding emitted | `LOW` |

Rationale:

Unused reserved external IPs are usually low direct operational risk to review, but they are still not automatically safe to release.

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"gcp"` |
| `rule_id` | `"gcp.compute.ip.unused"` |
| `resource_type` | `gcp.compute.address` for regional, `gcp.compute.global_address` for global |
| `resource_id` | canonical project/scope address path |
| `region` | regional name for regional addresses; `"global"` for global addresses |
| `confidence` | `HIGH` |
| `risk` | `LOW` |
| `estimated_monthly_cost_usd` | `7.30` |

### 11.2 Required evidence

`signals_used` must clearly disclose:

1. address `status` is `RESERVED`
2. address type is external
3. IP version is IPv4
4. whether the address is regional or global
5. if known, the network tier
6. that the monthly cost is an estimate derived from public USD list pricing

`signals_not_checked` should include remaining blind spots such as:

1. imminent re-attachment intent
2. DNS / firewall allowlist / customer integration dependencies
3. operational reserve, cutover, or manual failover intent
4. contract-specific or non-USD billing differences

### 11.3 Required details

Details should include at least:

- `address_name`
- `ip_address`
- `scope`
- `is_regional`
- `address_type`
- `ip_version`
- `network_tier`
- `purpose`
- `creation_timestamp`
- `labels`

---

## 12. Failure Behavior

- Regional inventory permission denied -> raise permission error
- Global inventory permission denied during full-scope scan -> raise permission error
- Compute Engine API disabled / not found for the project -> return no findings
- Malformed or unsupported scoped address records -> skip those items
- Partial aggregated regional inventory coverage -> do not treat zero findings as proof of full clean coverage
