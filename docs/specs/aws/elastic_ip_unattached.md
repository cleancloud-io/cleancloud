# aws.ec2.elastic_ip.unattached — Canonical Rule Specification

## 1. Intent

Detect Elastic IP address records that are currently allocated to the account in the
scanned Region and are not currently associated with an instance or network interface,
so they can be reviewed for possible release if no longer needed.

This is a **read-only review-candidate rule**. It is not a delete-safe rule and not
proof that release is operationally safe.

---

## 2. AWS API Grounding

Based on official EC2/VPC API and user-guide behavior.

### Key DescribeAddresses fields

| Field | Behaviour |
|---|---|
| `AllocationId` | Unique allocation identifier; present for VPC-domain addresses |
| `PublicIp` | Public IPv4 address string; always present |
| `CarrierIp` | Carrier IP for Wavelength zones; present when applicable |
| `AssociationId` | Present when currently associated with an instance or ENI |
| `InstanceId` | Present when associated with a specific instance |
| `NetworkInterfaceId` | Present when associated with a specific ENI |
| `PrivateIpAddress` | Present when currently associated |
| `Domain` | `"vpc"` or `"standard"` |
| `NetworkBorderGroup` | Network border group the address is in |
| `PublicIpv4Pool` | BYOIP pool identifier |
| `CustomerOwnedIp` | Customer-owned IP for Outposts |
| `CustomerOwnedIpv4Pool` | Customer-owned IP pool |
| `SubnetId` | Subnet for Wavelength addresses |
| `NetworkInterfaceOwnerId` | Owner of the associated ENI |
| `ServiceManaged` | Whether AWS manages the association on behalf of a service |
| `Tags` | Key-value tags |

### Critical AWS facts

1. **No `AllocationTime`** — the documented `Address` shape does not include
   `AllocationTime`, `AssociationTime`, `DisassociationTime`, or any canonical
   `unattached_since`/`allocated_since` timestamp.

2. **Billing** — AWS charges for all public IPv4 addresses, including Elastic IPs,
   whether associated or unassociated. Unattached state alone is not a unique billing
   trigger.

3. **DescribeAddresses** is non-paginated; one successful call returns all addresses
   for the scanned Region and caller scope.

4. **Region-specific** — Elastic IPs are Region-scoped. Results from one Region
   cannot prove absence from another.

5. **Association signals** — an address can be associated via `AssociationId`,
   `InstanceId`, `NetworkInterfaceId`, or `PrivateIpAddress`. All four must be absent
   for the address to be considered currently unattached.

### Rule-design consequence

- Current association state is the only baseline eligibility signal this rule can
  prove from `DescribeAddresses`.
- No temporal predicate (allocation age, unattached duration) may be required for
  baseline eligibility.
- Undocumented fields such as `AllocationTime` must not be used.

---

## 3. Scope

**Included:**
- All addresses returned by `DescribeAddresses` with a stable `resource_id`
- `currently_associated == False` (all canonical association fields absent)

**Excluded:**
- Addresses missing `AllocationId`, `PublicIp`, and `CarrierIp` (no stable identity)
- Addresses with any canonical association field present

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `resource_id` | `AllocationId` → `PublicIp` → `CarrierIp` → absent (skip item if absent) |
| `currently_associated` | `True` when any of `association_id`, `instance_id`, `network_interface_id`, `private_ip_address` is present |
| `currently_unattached` | All four canonical association fields absent |

---

## 5. Signal Model (Strict Separation)

### Normalization Contract

All rule logic must operate on normalized fields only.

**Identity fields:**

| Field | Derivation |
|---|---|
| `resource_id` | `address.AllocationId` → `address.PublicIp` → `address.CarrierIp` → absent (skip item if absent) |
| `allocation_id` | `address.AllocationId` → `null` |
| `public_ip` | `address.PublicIp` → `null` |
| `carrier_ip` | `address.CarrierIp` → `null` |

**Association fields (all must be absent for currently_unattached):**

| Field | Derivation |
|---|---|
| `association_id` | `address.AssociationId` → `null` |
| `instance_id` | `address.InstanceId` → `null` |
| `network_interface_id` | `address.NetworkInterfaceId` → `null` |
| `private_ip_address` | `address.PrivateIpAddress` → `null` |

**Context fields:**

| Field | Derivation |
|---|---|
| `domain` | `address.Domain` → `null` |
| `network_interface_owner_id` | `address.NetworkInterfaceOwnerId` → `null` |
| `network_border_group` | `address.NetworkBorderGroup` → `null` |
| `public_ipv4_pool` | `address.PublicIpv4Pool` → `null` |
| `customer_owned_ip` | `address.CustomerOwnedIp` → `null` |
| `customer_owned_ipv4_pool` | `address.CustomerOwnedIpv4Pool` → `null` |
| `subnet_id` | `address.SubnetId` → `null` |
| `service_managed` | `address.ServiceManaged` → `null` |
| `tags` | `address.Tags` → `[]` |

String-valued fields must be normalized only from non-empty strings.
Malformed or unexpected field types must not be converted into positive eligibility evidence.

### A. EXCLUSION_RULES

| Condition | Result |
|---|---|
| `resource_id` absent | **SKIP** (malformed identity) |
| any canonical association field present | **SKIP** (currently associated) |

There must be **no** exclusion for `service_managed`, tags, `domain`, BYOIP fields,
`network_border_group`, or `public_ipv4_pool`.

### B. DETECTION_SIGNAL

| Condition | Result |
|---|---|
| `resource_id` present, all association fields absent | **EMIT** |

### C. CONTEXTUAL_SIGNALS (non-detecting)

All context fields are evidence/details only. `network_interface_owner_id` and
`service_managed` are contextual and must not affect eligibility.

---

## 6. Evaluation Order (Mandatory)

1. Call `DescribeAddresses` once for the scanned Region; fail rule on error.
2. Validate that the top-level `Addresses` field is present and iterable; fail rule if not.
3. Normalize each address item; skip items that return `None`.
4. For each normalized address, apply EXCLUSION_RULES sequentially.
5. Emit findings for remaining eligible addresses.

No raw AWS field access after Step 3.

---

## 7. Confidence Model

| Condition | Confidence |
|---|---|
| All exclusion checks passed | `HIGH` |

High confidence refers to current unattached state, not to release safety or
business irrelevance. `DescribeAddresses` deterministically reports association state.

---

## 8. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `LOW` |

---

## 9. Cost Model

AWS charges for all public IPv4 addresses regardless of association state. Unattached
state alone is not a unique billing trigger.

- Do not present unattached state as a unique billing trigger.
- Do not hardcode a fixed estimate such as `$3.75/month`.
- `estimated_monthly_cost_usd` must be `None`.

---

## 10. Failure Behavior

### Required API

- `ec2:DescribeAddresses` — failure → **FAIL RULE**

### Response integrity

- `Addresses` key absent from response → **FAIL RULE**
- `Addresses` value not iterable as a list → **FAIL RULE**

### Item-level

- Address missing stable identity (`resource_id` absent) → **SKIP** (not FAIL RULE)
- Malformed contextual fields → **SKIP** that field; never fail the rule

---

## 11. Blind Spots

Every finding must disclose in `signals_not_checked`:

1. Future planned attachment or operational reserve intent not known
2. DNS / allowlist / manual failover dependencies
3. Application-level use of the reserved public IP
4. Exact monthly pricing from the current pricing page
5. Service-managed lifecycle expectations outside current association state

---

## 12. Evidence Contract

Every finding **must** include all of the following (null allowed, never omitted):

| Field | Requirement |
|---|---|
| `evaluation_path` | Exactly `"unattached-eip-review-candidate"` |
| `resource_id` | Always present |
| `allocation_id` | Present or `null` |
| `public_ip` | Present or `null` |
| `carrier_ip` | Present or `null` |
| `domain` | Present or `null` |
| `currently_associated` | Always `false` |
| `association_id` | Always `null` |
| `instance_id` | Always `null` |
| `network_interface_id` | Always `null` |
| `private_ip_address` | Always `null` |

Optional contextual fields:
- `network_interface_owner_id`, `network_border_group`, `public_ipv4_pool`,
  `customer_owned_ip`, `customer_owned_ipv4_pool`, `subnet_id`, `service_managed`, `tags`

---

## 13. Title and Reason Contract

| Field | Value |
|---|---|
| `title` | `"Unattached Elastic IP review candidate"` |
| `reason` | `"Address has no current association per DescribeAddresses"` |

**Hard rules:**
- Do NOT call the address "safe to release"
- Do NOT claim an allocation age or unattached duration
- Do NOT use `AllocationTime` as evidence

---

## 14. API and IAM Contract

**Required:** `ec2:DescribeAddresses`

### API usage constraints

- `DescribeAddresses` has no documented pagination; one call defines the full address set
- No undocumented fields (`AllocationTime`, etc.) may be used

---

## 15. Acceptance Scenarios

### Must emit

1. VPC EIP with `AllocationId`, `PublicIp`, no association fields → EMIT HIGH
2. Standard-domain address with no `InstanceId` or other association field → EMIT HIGH
3. BYOIP / customer-owned / `service_managed` contextual fields present, no association fields → EMIT
4. `CarrierIp` only (no `AllocationId`, no `PublicIp`) → EMIT; `CarrierIp` is `resource_id`

### Must skip

1. Address with `AssociationId` → SKIP
2. Address with `NetworkInterfaceId` but no `AssociationId` → SKIP
3. Address with `InstanceId` but no `AssociationId` → SKIP
4. Address with `PrivateIpAddress` but no `AssociationId` → SKIP
5. Address missing `AllocationId`, `PublicIp`, and `CarrierIp` → SKIP

### Must fail

1. `DescribeAddresses` unauthorized or request failure → FAIL RULE
2. Response missing `Addresses` key → FAIL RULE
3. Response `Addresses` not a list → FAIL RULE

### Must NOT happen

1. Temporal threshold applied to baseline eligibility
2. `AllocationTime` used for any eligibility or evidence logic
3. `$3.75` or any hardcoded cost in `estimated_monthly_cost_usd`
4. `domain == "standard"` used as an exclusion
5. `service_managed` used as an exclusion
6. `AssociationId` as the sole association check (other association fields ignored)

---

## 16. In-File Contract

```
Rule: aws.ec2.elastic_ip.unattached

Intent:
    Detect Elastic IP address records that are currently allocated to the account
    in the scanned Region and are not currently associated with an instance or
    network interface.

Exclusions:
    - resource_id absent (malformed identity)
    - any canonical association field present (currently associated)

Detection:
    - resource_id present
    - association_id, instance_id, network_interface_id, private_ip_address all absent

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - No temporal threshold — current unattached state is the sole eligibility signal.
    - Do not use AllocationTime (undocumented field).
    - All four canonical association fields must be checked, not only AssociationId.
    - Missing/non-iterable Addresses response fails the rule.
    - Do not hardcode a fixed monthly cost estimate.

Blind spots:
    - future planned attachment or operational reserve intent not known
    - DNS / allowlist / manual failover dependencies
    - application-level use of the reserved public IP
    - service-managed lifecycle expectations outside current association state

APIs:
    - ec2:DescribeAddresses
```

---

## 17. Implementation Constants

No rule-level numeric constants required for baseline eligibility.
