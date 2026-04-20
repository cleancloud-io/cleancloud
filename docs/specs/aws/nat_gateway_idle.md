# aws.ec2.nat_gateway.idle — Canonical Rule Specification

## 1. Intent

Detect NAT Gateways that are currently `available`, old enough to evaluate, and show no
trusted CloudWatch traffic/activity evidence during the configured observation window, so
they can be reviewed as possible cleanup candidates.

This is a **read-only review-candidate rule**. It is not a delete-safe rule.

---

## 2. AWS API Grounding

Based on official EC2/VPC API and CloudWatch documentation.

### Key facts

1. `DescribeNatGateways` is the canonical API for enumerating NAT Gateways in the scanned
   Region/account scope and supports pagination.
2. `NatGateway.State` valid values: `pending | failed | available | deleting | deleted`.
3. AWS documents that `available` means the NAT Gateway is able to process traffic and that
   this status remains until you delete it; it does not indicate usage.
4. `NatGateway.CreateTime` is a documented timestamp field.
5. NAT Gateways have `ConnectivityType` values `public | private`.
6. AWS documents NAT Gateway CloudWatch metrics in namespace `AWS/NATGateway` with dimension
   `NatGatewayId`.
7. Required CloudWatch metrics and statistics:
   - `BytesOutToDestination` → `Sum`
   - `BytesInFromSource` → `Sum`
   - `BytesInFromDestination` → `Sum`
   - `BytesOutToSource` → `Sum`
   - `ActiveConnectionCount` → `Maximum`
8. AWS states `ActiveConnectionCount == 0` indicates no active TCP connections.
9. AWS pricing: charged per hour available and per GB processed. No canonical fixed monthly
   USD value exists in the product docs used by this rule.
10. `GetMetricStatistics` does not guarantee ordered datapoints. Missing datapoints must not
    be assumed to mean zero activity.

### Rule-design consequences

- Only `available` NAT Gateways are eligible.
- Age thresholding is valid because `CreateTime` is documented.
- CloudWatch is the sole trusted activity source; missing datapoints → SKIP ITEM.
- Route-table references are contextual only, not eligibility gates.

---

## 3. Scope

- "idle" is a CleanCloud-derived heuristic: no trusted CloudWatch activity over the full
  observation window.
- `age_days = floor((now_utc - create_time_utc) / 86400)`
- Observation window: `now_utc - idle_days_threshold * 86400` → `now_utc`
- Rule is evaluated independently per Region.

---

## 4. API and IAM Contract

**Required:** `ec2:DescribeNatGateways` — failure → FAIL RULE
**Required:** `cloudwatch:GetMetricStatistics` — failure → FAIL RULE
**Optional:** `ec2:DescribeRouteTables` — failure → degrade context, do not fail rule

**Pagination:** `DescribeNatGateways` must be fully exhausted; no early exit.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only. No raw AWS field access after
normalization.

### Identity fields

| Field | Derivation |
|---|---|
| `resource_id` | `NatGatewayId` → absent (skip) |
| `nat_gateway_id` | `NatGatewayId` → absent (skip) |

### State / age fields

| Field | Derivation |
|---|---|
| `normalized_state` | `State` → absent (skip) |
| `create_time_utc` | `CreateTime` (timezone-aware UTC only) → absent (skip) |
| `age_days` | `floor((now_utc - create_time_utc) / 86400)` if valid and not future → absent (skip) |

### Core context fields

| Field | Derivation |
|---|---|
| `connectivity_type` | `ConnectivityType` → null |
| `availability_mode` | `AvailabilityMode` → null |
| `vpc_id` | `VpcId` → null |
| `subnet_id` | `SubnetId` → null |
| `nat_gateway_addresses` | `NatGatewayAddresses` → `[]` |
| `attached_appliances` | `AttachedAppliances` → `[]` |
| `auto_scaling_ips` | `AutoScalingIps` → null |
| `auto_provision_zones` | `AutoProvisionZones` → null |
| `tag_set` | `Tags` → `[]` |

Normalization requirements:
- String fields: normalized only from non-empty strings.
- Timestamp: timezone-aware UTC only; naive datetime → absent (skip).
- Future `CreateTime` → absent (skip).
- Malformed contextual fields must not produce positive idle evidence.

---

## 6. CloudWatch Traffic Contract

### 6.1 Required Metrics

| Metric | Statistic | Activity if |
|---|---|---|
| `BytesOutToDestination` | `Sum` | `Sum > 0` |
| `BytesInFromSource` | `Sum` | `Sum > 0` |
| `BytesInFromDestination` | `Sum` | `Sum > 0` |
| `BytesOutToSource` | `Sum` | `Sum > 0` |
| `ActiveConnectionCount` | `Maximum` | `Maximum > 0` |

Namespace: `AWS/NATGateway`, dimension `NatGatewayId = <nat_gateway_id>`

### 6.2 Datapoint Completeness

- Missing datapoints for any required metric must not be treated as zero.
- If any required metric returns no datapoints → **SKIP ITEM** (insufficient evidence).
- If any required metric request fails → **FAIL RULE**.

### 6.3 Period Selection

Period must be chosen deterministically from the configured lookback age:

| Window age | Period requirement |
|---|---|
| < 15 days | Multiple of 60 seconds |
| 15–63 days | Multiple of 300 seconds |
| > 63 days | Multiple of 3600 seconds |

Using `idle_days_threshold * 86400` as the Period satisfies all three constraints (86400 is a
multiple of 60, 300, and 3600) and produces a single full-window aggregate bucket.

---

## 7. Route-Table Handling

Route-table references are contextual only.

- A route targeting `nat-gateway-id` may be surfaced as evidence.
- Route-table presence must not suppress an otherwise valid idle finding.
- Route-table absence must not compensate for missing or incomplete CloudWatch evidence.
- `DescribeRouteTables` failure → degrade context, do not fail rule.

---

## 8. Evaluation Order (Mandatory)

1. Retrieve and fully paginate `DescribeNatGateways`; fail rule on error.
2. Normalize each item.
3. Skip items with absent identity, state, `create_time_utc`, or `age_days`.
4. Skip items where `normalized_state != "available"`.
5. Skip items where `age_days < idle_days_threshold`.
6. Retrieve required CloudWatch metrics; fail rule on API error.
7. Skip items where any required metric returns no datapoints.
8. Skip items where any metric shows activity (`> 0`).
9. Retrieve route-table context (best-effort).
10. Emit findings.

No raw AWS field access after Step 2.

---

## 9. Exclusion Rules

| Condition | Result |
|---|---|
| `nat_gateway_id` absent | **SKIP ITEM** |
| `normalized_state` absent | **SKIP ITEM** |
| `normalized_state != "available"` | **SKIP ITEM** |
| `create_time_utc` absent / naive / future | **SKIP ITEM** |
| `age_days < idle_days_threshold` | **SKIP ITEM** |
| Any required metric has no datapoints | **SKIP ITEM** |
| Any required metric shows activity | **SKIP ITEM** |

No exclusion for: `connectivity_type`, `availability_mode`, tags, route-table presence.

---

## 10. Failure Model

- `DescribeNatGateways` error → **FAIL RULE**
- CloudWatch metric API error → **FAIL RULE**
- `DescribeRouteTables` error → degrade context only

---

## 11. Evidence and Cost Contract

### 11.1 Required Evidence/Details Fields

| Field | Requirement |
|---|---|
| `evaluation_path` | `"idle-nat-gateway-review-candidate"` |
| `nat_gateway_id` | Always present |
| `normalized_state` | Always `"available"` |
| `create_time` | ISO 8601 UTC string |
| `age_days` | Integer |
| `idle_days_threshold` | Integer |
| `connectivity_type` | Present or null |
| `availability_mode` | Present or null |
| `vpc_id` | Present or null |
| `subnet_id` | Present or null |
| `bytes_out_to_destination` | Numeric (0.0 if metric zero) |
| `bytes_in_from_source` | Numeric |
| `bytes_in_from_destination` | Numeric |
| `bytes_out_to_source` | Numeric |
| `active_connection_count_max` | Numeric |

Optional: `nat_gateway_addresses`, `attached_appliances`, `route_table_referenced`,
`auto_scaling_ips`, `auto_provision_zones`, `tag_set`.

### 11.2 Cost Estimation Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode a fixed NAT Gateway monthly cost estimate.

---

## 12. Confidence Model

| Condition | Confidence |
|---|---|
| Zero traffic AND route-table confirms no reference | `HIGH` |
| Zero traffic AND route-table referenced OR unavailable | `MEDIUM` |

No LOW-confidence finding may be emitted. Metric failure = FAIL RULE.

---

## 13. Title and Reason Contract

| Field | Value |
|---|---|
| `title` | `"Idle NAT Gateway review candidate"` |
| `reason` | `"NAT Gateway has no trusted CloudWatch traffic signal in the last {N} days"` |

Do NOT claim the NAT Gateway is safe to delete.

---

## 14. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `MEDIUM` |

---

## 15. Acceptance Scenarios

### Must emit

1. Available, old enough, all metrics zero, no route-table reference → EMIT HIGH
2. Available, old enough, all metrics zero, route-table still references → EMIT MEDIUM
3. Available, old enough, all metrics zero, route-table lookup failed → EMIT MEDIUM

### Must skip

4. State `pending`, `failed`, `deleting`, or `deleted` → SKIP
5. Available but younger than threshold → SKIP
6. Any byte metric `Sum > 0` → SKIP
7. `ActiveConnectionCount Maximum > 0` → SKIP
8. Absent/naive/future `CreateTime` → SKIP
9. Any required metric returns no datapoints → SKIP

### Must fail

10. `DescribeNatGateways` failure → FAIL RULE
11. CloudWatch metric fetch failure → FAIL RULE

### Must NOT happen

1. LOW-confidence finding emitted
2. CloudWatch metric failure → LOW-confidence finding
3. Missing datapoints treated as zero activity
4. `estimated_monthly_cost_usd` set to non-null
5. Route-table absence used as traffic evidence substitute

---

## 16. In-File Contract

```
Rule: aws.ec2.nat_gateway.idle

    (spec — docs/specs/aws/nat_gateway_idle.md)

Intent:
    Detect NAT Gateways that are currently available, old enough to evaluate,
    and show no trusted CloudWatch traffic/activity evidence during the
    configured observation window, so they can be reviewed as possible cleanup
    candidates.

Exclusions:
    - nat_gateway_id absent (malformed identity)
    - normalized_state absent (missing current-state signal)
    - normalized_state != "available"
    - create_time_utc absent, naive, or in the future
    - age_days < idle_days_threshold (too new to evaluate)
    - any required CloudWatch metric has no datapoints (insufficient evidence)
    - any required metric shows activity > 0

Detection:
    - nat_gateway_id present, normalized_state == "available"
    - age_days >= idle_days_threshold
    - all 5 required CloudWatch metrics return datapoints and are all zero

Key rules:
    - Missing CloudWatch datapoints → SKIP ITEM (not zero).
    - CloudWatch API failure → FAIL RULE (not LOW-confidence finding).
    - 5 required metrics: BytesOutToDestination, BytesInFromSource,
      BytesInFromDestination, BytesOutToSource (Sum), ActiveConnectionCount (Maximum).
    - Route-table context is contextual only; absence does not substitute
      for CloudWatch evidence.
    - Naive CreateTime → SKIP ITEM.
    - estimated_monthly_cost_usd = None.
    - Confidence: HIGH (no route ref) or MEDIUM (route ref or unavailable).
    - Risk: MEDIUM.

Blind spots:
    - planned future usage or DR/failover intent
    - seasonal or cyclical usage outside the observation window
    - organizational ownership or business intent
    - exact region-specific pricing impact

APIs:
    - ec2:DescribeNatGateways
    - cloudwatch:GetMetricStatistics
    - ec2:DescribeRouteTables (contextual)
```

---

## 17. Implementation Constants

- `_DEFAULT_IDLE_DAYS_THRESHOLD = 14`
