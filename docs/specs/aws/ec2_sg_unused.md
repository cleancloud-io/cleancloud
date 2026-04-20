# aws.ec2.security_group.unused — Canonical Rule Specification

## 1. Intent

Detect EC2 security groups that are not currently associated with any network
interface in the scanned region and should be surfaced as cleanup review candidates.

This is a **read-only hygiene rule**. It is not a delete-safe rule and not proof that
deletion is operationally safe.

ENI coverage is region-scoped and includes any AWS service usage materialized as
ENIs returned by `DescribeNetworkInterfaces`. Absence from that result means only
"no visible runtime ENI association in this regional scan"; it does not prove there is
no dependency elsewhere in the AWS control plane.

---

## 2. AWS API Grounding

Based on official EC2/VPC API and user-guide behavior.

### Key DescribeSecurityGroups fields

| Field | Behaviour |
|---|---|
| `GroupId` | Unique SG identifier; always present |
| `GroupName` | Human name; `"default"` for the VPC default group |
| `VpcId` | VPC the SG belongs to |
| `Description` | User-supplied description |
| `IpPermissions` | List of ingress rules |
| `IpPermissionsEgress` | List of egress rules |
| `Tags` | Key-value tags |

### Key DescribeNetworkInterfaces fields

| Field | Behaviour |
|---|---|
| `NetworkInterfaceId` | Unique ENI identifier; always present |
| `Groups` | List of `{GroupId, GroupName}` entries — SGs currently associated with the ENI |

### Critical AWS facts

1. **`DeleteSecurityGroup` fails with `DependencyViolation`** if the group is associated
   with an instance or ENI, referenced by another SG rule, or has a VPC association.

2. **The default SG** in each VPC is named `"default"` and cannot be deleted.

3. **ENI association** is the canonical current runtime signal. Cross-SG rule references
   and higher-level service configurations (launch templates, Auto Scaling, ECS, Lambda)
   are not visible from ENI data alone.

4. **EC2 follows eventual consistency** — recently created, modified, attached, or
   detached resources may not be immediately reflected in subsequent Describe responses.

5. **`DescribeNetworkInterfaces` must be fully paginated** — partial pagination can miss
   associated ENIs and create false positives.

6. **Service-managed SGs** — AWS does not expose a canonical SG-level managed/service
   owner field; name-prefix inference is heuristic only.

### Rule-design consequence

- Current ENI association is the only canonical eligibility signal.
- ENIs expose runtime attachment visibility only, not the full dependency graph.
- Cross-SG rule references are dependency metadata, not runtime attachment evidence.
- This rule must never claim delete-safe certainty.

---

## 3. Scope

**Included:**
- All security groups returned by `DescribeSecurityGroups`
- `is_default_group == False`
- `attached_eni_count == 0`

**Excluded:**
- Default SGs (`GroupName == "default"`)
- SGs with at least one visible ENI association
- Malformed SG records missing `GroupId`

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `sg_id` | Normalized from `sg.GroupId` → `sg.groupId` → absent |
| `is_default_group` | `True` when `sg_name == "default"` |
| `attached_eni_count` | `len(sg_to_eni_ids[sg_id])` — distinct ENI IDs referencing this SG |
| `referenced_by_other_sg` | `True` when this SG's `sg_id` appears in any other SG's rule `UserIdGroupPairs` |
| `sg_to_eni_ids` | Region-level mapping: `sg_id → set[eni_id]` built from all paginated ENI group memberships |

### `referenced_by_other_sg` semantics

- Contextual evidence only — never an exclusion signal
- Always emitted in details as `true` or `false`
- `True` must not be treated as proof of active attachment or deletion safety

---

## 5. Signal Model (Strict Separation)

### Normalization Contract

All rule logic must operate on normalized fields only.

**SG normalization:**

| Field | Derivation |
|---|---|
| `sg_id` | `sg.GroupId` → `sg.groupId` → absent (skip item if absent) |
| `sg_name` | `sg.GroupName` → `sg.groupName` → `""` |
| `vpc_id` | `sg.VpcId` → `sg.vpcId` → `null` |
| `description` | `sg.Description` → `sg.groupDescription` → `sg.description` → `null` |
| `normalized_tags` | `sg.Tags` → `sg.TagSet` → `sg.tagSet` → `[]` |
| `normalized_ingress_rules` | `sg.IpPermissions` → `sg.ipPermissions` → `[]` |
| `normalized_egress_rules` | `sg.IpPermissionsEgress` → `sg.ipPermissionsEgress` → `[]` |
| `rule_count` | `len(normalized_ingress_rules) + len(normalized_egress_rules)` |
| `is_default_group` | `sg_name == "default"` |

**ENI normalization:**

| Field | Derivation |
|---|---|
| `eni_id` | `eni.NetworkInterfaceId` → `eni.networkInterfaceId` → absent (FAIL RULE if absent) |
| `groups` | `eni.Groups` → `eni.GroupSet` → `eni.groupSet` → absent (FAIL RULE if absent) |
| `gid` | `group.GroupId` → `group.groupId` |

**`sg_to_eni_ids`:** distinct `eni_id` values per `gid`, built by exhausting all ENI pages.

**`referenced_sg_set`:** built from all `sg.normalized_ingress_rules` and
`sg.normalized_egress_rules` by scanning `UserIdGroupPairs` → `groups` in each rule.

### A. EXCLUSION_RULES

| Condition | Result |
|---|---|
| `sg_id` absent | **SKIP** (malformed) |
| `is_default_group == True` | **SKIP** |
| `attached_eni_count > 0` | **SKIP** |

There must be **no** exclusion for `referenced_by_other_sg`, rule count, tags, description,
or heuristic service-managed naming.

### B. DETECTION_SIGNAL

| Condition | Result |
|---|---|
| `is_default_group == False`, `attached_eni_count == 0` | **EMIT** |

### C. CONTEXTUAL_SIGNALS (non-detecting)

| Signal | Effect |
|---|---|
| `referenced_by_other_sg` | Evidence/details only |
| `rule_count` | Evidence/details only |
| `normalized_tags` | Evidence/details only |
| `description` | Evidence/details only |
| service-managed name hint | Evidence/details only — never affects eligibility or confidence |

---

## 6. Evaluation Order (Mandatory)

1. Retrieve all SGs via paginated `DescribeSecurityGroups`; fail rule on error
2. Normalize SG records; skip items with absent `sg_id`
3. Build `referenced_sg_set` from normalized SG rules
4. Retrieve all ENIs via paginated `DescribeNetworkInterfaces`; fail rule on error
5. Build `sg_to_eni_ids` from ENI group memberships; fail rule on malformed ENI identity or membership
6. For each normalized SG, apply EXCLUSION_RULES sequentially
7. Emit findings for remaining eligible SGs

No raw SDK field access after Step 2.

---

## 7. Confidence Model

| Condition | Confidence |
|---|---|
| All exclusion checks passed | `MEDIUM` |

**Mandatory rule:** Use `MEDIUM` confidence. `HIGH` must not be used — AWS documents
additional deletion blockers (cross-SG references, VPC associations) beyond ENI
association, and this rule does not verify those.

---

## 8. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `LOW` |

---

## 9. Cost Model

Security groups have no direct billing cost. `estimated_monthly_cost_usd` must be `None`.

---

## 10. Failure Behavior

### Required APIs

- `ec2:DescribeSecurityGroups` — failure → **FAIL RULE**
- `ec2:DescribeNetworkInterfaces` — failure → **FAIL RULE**

### ENI parsing

- ENI record missing `NetworkInterfaceId` or group-membership field → **FAIL RULE**
  (undercounting associations creates false positives)
- ENI record malformed only in non-membership fields → skip that ENI record
- Incomplete pagination → **FAIL RULE**

### Optional enrichment

- `ec2:DescribeVpcs` failure → continue without VPC name; never fails the rule

---

## 11. Blind Spots

Every finding must disclose in `signals_not_checked`:

1. Launch templates, Auto Scaling, ECS, Lambda, and similar configurations not
   currently materialized as ENIs
2. Security group VPC associations (not queried by this rule)
3. Business/application or DR intent not known
4. EC2 eventual-consistency windows after recent SG or ENI changes
5. AWS control-plane dependencies not visible in `DescribeNetworkInterfaces`

---

## 12. Evidence Contract

Every finding **must** include all of the following (null allowed, never omitted):

| Field | Requirement |
|---|---|
| `evaluation_path` | Exactly `"unused-security-group-review-candidate"` |
| `sg_id` | Always present |
| `sg_name` | Always present |
| `vpc_id` | Present or `null` |
| `attached_eni_count` | Always `0` |
| `referenced_by_other_sg` | Always present: `true` or `false` |
| `rule_count` | Always present |
| `description` | Present or `null` |
| `is_default_group` | Always `false` |
| `region_scope_only` | Always `true` |

Optional contextual fields:
- `vpc_name`, `tags`, `heuristic_service_managed_hint`

---

## 13. Title and Reason Contract

| Field | Value |
|---|---|
| `title` | `"Unused security group review candidate"` |
| `reason` | `"Security group has normalized attachment_eni_count == 0 and the default-group exclusion did not match"` |

**Hard rules:**
- Do NOT call the group "safe to delete"
- Do NOT imply cross-SG references make deletion safe
- Do NOT claim regional ENI non-association proves the full dependency graph

---

## 14. API and IAM Contract

**Required:** `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`

**Best-effort:** `ec2:DescribeVpcs`

### API usage constraints

- Both required APIs must paginate fully
- ENI association counting must use all returned ENIs regardless of ENI status or
  attachment state — filtering by status is not allowed

---

## 15. Acceptance Scenarios

### Must emit

1. Non-default SG, `attached_eni_count == 0`, no references
2. Non-default SG, `attached_eni_count == 0`, `referenced_by_other_sg == True`
   (include as context, do not suppress)
3. Non-default SG, `attached_eni_count == 0`, has rules/tags/description
   (include as context only)

### Must skip

1. Default SG (`GroupName == "default"`)
2. SG whose ID appears in any ENI group membership list
3. SG missing `GroupId`

### Must fail rule

1. `DescribeNetworkInterfaces` pagination or request failure
2. ENI payload missing `NetworkInterfaceId` or group-membership field

### Must NOT happen

1. `referenced_by_other_sg == True` suppresses a finding
2. `referenced_by_other_sg` conditionally absent from details
3. `HIGH` confidence emitted
4. Service-managed name hint affects eligibility or confidence
5. ENI membership evaluated by ENI status/attachment state filter

---

## 16. In-File Contract

```
Rule: aws.ec2.security_group.unused

Intent:
    Detect security groups not currently associated with any network interface in
    the scanned region that are cleanup review candidates.

Exclusions:
    - sg_id is absent (malformed)
    - is_default_group == True (GroupName == "default")
    - attached_eni_count > 0 (SG ID found in any ENI group membership)

Detection:
    - is_default_group == False
    - normalized attachment_eni_count == 0

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - ENI coverage is region-scoped; absence from ENI scan does not prove no AWS
      control-plane dependency.
    - referenced_by_other_sg is dependency metadata and context only, never an
      exclusion.
    - Service-managed name hints are heuristic context only, never affect
      eligibility or confidence.
    - ENI pagination must be exhausted; partial pagination can create false
      positives.

Blind spots:
    - launch templates, Auto Scaling, ECS, Lambda, and similar configs not
      currently materialized as ENIs
    - security group VPC associations (not queried by this rule)
    - EC2 eventual-consistency windows after recent SG or ENI changes
    - business/application or DR intent not known

APIs:
    - ec2:DescribeSecurityGroups
    - ec2:DescribeNetworkInterfaces
```

---

## 17. Implementation Constants

| Constant | Value | Description |
|---|---|---|
| `_SERVICE_MANAGED_PREFIXES` | see impl | Heuristic name prefixes — contextual only |
