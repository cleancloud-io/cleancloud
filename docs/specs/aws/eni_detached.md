# aws.ec2.eni.detached — Canonical Rule Specification

## 1. Intent

Detect network interfaces that are currently not attached according to the EC2
`DescribeNetworkInterfaces` contract, so they can be reviewed as possible cleanup
candidates if no longer needed.

This is a **read-only review-candidate rule**. It is not a delete-safe rule.

---

## 2. AWS API Grounding

Based on official EC2 API and User Guide.

### Key facts

1. `DescribeNetworkInterfaces` is the canonical API for enumerating ENIs in the scanned
   Region/account scope; AWS strongly recommends paginated requests.
2. Top-level `Status` valid values: `available | associated | attaching | in-use | detaching`.
3. AWS explicitly states: if an ENI is not attached, `Status == "available"`.
4. `Attachment` is optional; `Attachment.Status` valid values: `attaching | attached | detaching | detached`.
5. The documented shape does **not** include `CreateTime`, `DetachTime`, or any
   `detached_since` / `allocated_since` timestamp.
6. Requester-managed ENIs are created by AWS services on your behalf; if a service
   detached an ENI but did not delete it, you can delete the detached ENI.

### Rule-design consequences

- Current not-attached state must be determined from documented current-state fields only.
- No temporal inference (age, detach duration) may be used.
- Top-level `Status` is the canonical state authority.
- `requesterManaged`, `operator.managed`, `interfaceType`, and `description` are contextual
  only — not eligibility gates.

---

## 3. Scope

- "Not currently attached" means `Status == "available"` per the documented EC2 contract.
- The rule is evaluated independently per Region.

---

## 4. API and IAM Contract

**Required:** `ec2:DescribeNetworkInterfaces` — failure → FAIL RULE

**Pagination:** Must be fully exhausted; no early exit.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only. No raw AWS field access after
normalization.

### Identity fields

| Field | Derivation |
|---|---|
| `resource_id` | `NetworkInterfaceId` → absent (skip) |
| `network_interface_id` | `NetworkInterfaceId` → absent (skip) |

### State fields

| Field | Derivation |
|---|---|
| `normalized_status` | `Status` → absent |

### Attachment fields

| Field | Derivation |
|---|---|
| `attachment_status` | `Attachment.Status` → null |
| `attachment_id` | `Attachment.AttachmentId` → null |
| `attachment_instance_id` | `Attachment.InstanceId` → null |
| `attachment_instance_owner_id` | `Attachment.InstanceOwnerId` → null |

### Ownership / service-context fields

| Field | Derivation |
|---|---|
| `interface_type` | `InterfaceType` → null |
| `requester_managed` | `RequesterManaged` (bool only) → null |
| `operator_managed` | `Operator.Managed` (bool only) → null |
| `operator_principal` | `Operator.Principal` → null |

### Network / resource-metadata fields

| Field | Derivation |
|---|---|
| `description` | `Description` → null |
| `availability_zone` | `AvailabilityZone` → null |
| `subnet_id` | `SubnetId` → null |
| `vpc_id` | `VpcId` → null |
| `private_ip_address` | `PrivateIpAddress` → null |
| `public_ip` | `Association.PublicIp` → null |
| `tag_set` | `TagSet` → `[]` |

Normalization requirements:
- String fields: normalized only from non-empty strings.
- Boolean fields: normalized only from actual `bool` values.
- Malformed contextual fields must not produce positive eligibility evidence.

---

## 6. Current Attachment-State Determination

Top-level `normalized_status` is the **sole** state authority.

| `normalized_status` | Eligibility |
|---|---|
| `"available"` | **ELIGIBLE** (not currently attached) |
| `"in-use"` | SKIP |
| `"attaching"` | SKIP |
| `"detaching"` | SKIP |
| `"associated"` | SKIP |

**Attachment consistency check:**
- If `normalized_status == "available"` and `attachment_status` is `"attached"`,
  `"attaching"`, or `"detaching"` → structural inconsistency → **SKIP ITEM**.
- `attachment_status` is validation only; it does not override `normalized_status`.

---

## 7. Service-Managed / Requester-Managed Handling

`requester_managed`, `operator_managed`, and `interface_type` are contextual only.
None of them exclude an ENI from evaluation. AWS documents that if a service detached
an ENI and did not delete it, the ENI is a valid deletion candidate.

---

## 8. Evaluation Order (Mandatory)

1. Retrieve and fully paginate `DescribeNetworkInterfaces`; fail rule on error.
2. Normalize each ENI item; skip non-dict or identity-absent items.
3. Skip items with absent `normalized_status`.
4. Skip items where `normalized_status != "available"`.
5. Skip items where `attachment_status` conflicts with the available state.
6. Emit findings for remaining items.

No raw AWS field access after Step 2.

---

## 9. Exclusion Rules

| Condition | Result |
|---|---|
| `network_interface_id` absent | **SKIP ITEM** |
| `normalized_status` absent | **SKIP ITEM** |
| `normalized_status != "available"` | **SKIP ITEM** |
| `normalized_status == "available"` and `attachment_status` in `{"attached","attaching","detaching"}` | **SKIP ITEM** |

No exclusion for: `requester_managed`, `operator_managed`, `interface_type`, tags, description.

---

## 10. Failure Model

- `DescribeNetworkInterfaces` request/pagination error → **FAIL RULE**
- Non-dict ENI item → SKIP ITEM (not FAIL RULE)
- Missing identity → SKIP ITEM (not FAIL RULE)

---

## 11. Evidence and Cost Contract

### 11.1 Required Evidence/Details Fields

| Field | Requirement |
|---|---|
| `evaluation_path` | Exactly `"detached-eni-review-candidate"` |
| `network_interface_id` | Always present |
| `normalized_status` | Always `"available"` |
| `attachment_status` | Present or null |
| `interface_type` | Present or null |
| `requester_managed` | Present or null |
| `operator_managed` | Present or null |
| `operator_principal` | Present or null |
| `availability_zone` | Present or null |
| `subnet_id` | Present or null |
| `vpc_id` | Present or null |
| `private_ip_address` | Present or null |
| `public_ip` | Present or null |

Optional: `attachment_id`, `attachment_instance_id`, `attachment_instance_owner_id`,
`description`, `tag_set`.

### 11.2 Cost Estimation Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode a generic detached-ENI monthly cost estimate.

---

## 12. Confidence Model

| Condition | Confidence |
|---|---|
| `normalized_status == "available"` and no structural conflict | `HIGH` |

High confidence refers to current not-attached state, not delete safety.

---

## 13. Title and Reason Contract

| Field | Value |
|---|---|
| `title` | `"Detached ENI review candidate"` |
| `reason` | `"ENI Status is 'available' — not currently attached per DescribeNetworkInterfaces"` |

Do NOT claim the ENI is safe to delete.

---

## 14. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `LOW` |

---

## 15. Acceptance Scenarios

### Must emit

1. ENI with `Status == "available"`, no attachment object → EMIT HIGH
2. ENI with `Status == "available"`, `Attachment.Status == "detached"` → EMIT HIGH
3. Requester-managed ENI with `Status == "available"` → EMIT (include context)
4. Operator-managed ENI with `Status == "available"` → EMIT (include context)
5. Any `interface_type` value, `Status == "available"` → EMIT (no type exclusion)

### Must skip

6. ENI with `Status == "in-use"` → SKIP
7. ENI with `Status == "attaching"`, `"detaching"`, or `"associated"` → SKIP
8. ENI with `Status == "available"` and `Attachment.Status == "attached"` → SKIP
9. ENI missing `NetworkInterfaceId` → SKIP
10. ENI missing `Status` → SKIP

### Must fail

11. `DescribeNetworkInterfaces` request/pagination failure → FAIL RULE

### Must NOT happen

1. Temporal threshold applied to eligibility
2. `CreateTime` or age used for any eligibility or evidence logic
3. `interface_type` used as an exclusion
4. `requester_managed == true` used as an exclusion
5. MEDIUM or LOW confidence for a valid not-attached ENI
6. Hardcoded cost estimate in `estimated_monthly_cost_usd`

---

## 16. In-File Contract

```
Rule: aws.ec2.eni.detached

    (spec — docs/specs/aws/eni_detached.md)

Intent:
    Detect network interfaces that are currently not attached according to the
    EC2 DescribeNetworkInterfaces contract, so they can be reviewed as possible
    cleanup candidates if no longer needed.

Exclusions:
    - network_interface_id absent (malformed identity)
    - normalized_status absent (missing current-state signal)
    - normalized_status != "available" (attached or other non-eligible state)
    - structural inconsistency: normalized_status == "available" but
      attachment_status in {"attached","attaching","detaching"}

Detection:
    - network_interface_id present
    - normalized_status == "available"
    - attachment_status absent, null, or "detached"

Key rules:
    - Top-level Status is the sole state authority; attachment_status is validation only.
    - No temporal threshold — current not-attached state is the sole eligibility signal.
    - No exclusion for interface_type, requester_managed, or operator_managed.
    - Do not use CreateTime or any age/duration field for eligibility.
    - estimated_monthly_cost_usd = None.
    - Confidence: HIGH.
    - Risk: LOW.

Blind spots:
    - how long the ENI has been in a not-currently-attached state
    - previous attachment history
    - whether an AWS service expects to recycle or clean up this ENI
    - application, failover, or operational intent
    - exact pricing impact

APIs:
    - ec2:DescribeNetworkInterfaces
```

---

## 17. Implementation Constants

No rule-level numeric constants required for baseline eligibility.
