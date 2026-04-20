# aws.elbv2.alb.idle / aws.elbv2.nlb.idle / aws.elb.clb.idle — Canonical Rule Specification

## 1. Intent

Detect ALB, NLB, and CLB load balancers that are at least `idle_days_threshold` days old
and show no trusted CloudWatch evidence of client traffic during the full lookback window,
so they can be reviewed as potential cleanup candidates.

This is a **read-only review-candidate rule family**. It is not a delete-safe rule family.

---

## 2. AWS API Grounding

Based on official ELB / ELBv2 API and CloudWatch documentation.

### Key facts

1. ELBv2 `DescribeLoadBalancers` returns `LoadBalancerArn`, `LoadBalancerName`, `CreatedTime`,
   `Scheme`, `VpcId`, `State`, and `Type` (`application`, `network`, `gateway`).
2. Classic ELB `DescribeLoadBalancers` returns `LoadBalancerName`, `CreatedTime`, `Scheme`,
   `VPCId`, `DNSName`, and `Instances`.
3. ALB and CLB metrics are published only when requests flow; missing datapoints may be treated
   as zero for ALB and CLB metrics.
4. NLB metrics `NewFlowCount`, `ProcessedBytes`, and `ActiveFlowCount` are documented as always
   reported. Missing datapoints for NLB metrics must be treated as incomplete / untrusted —
   not as zero.
5. ALB metrics are published under `AWS/ApplicationELB` using `LoadBalancer` dimension.
6. NLB metrics are published under `AWS/NetworkELB` using `LoadBalancer` dimension.
7. CLB metrics are published under `AWS/ELB` using `LoadBalancerName` dimension.
8. The ELBv2 CloudWatch dimension value is the ARN suffix strictly after `loadbalancer/`.
9. Gateway Load Balancers (`Type == "gateway"`) are out of scope.
10. `CreatedTime` is a documented field and may be used for age calculation.

---

## 3. Scope and Terminology

- ALB: ELBv2 `Type == "application"`
- NLB: ELBv2 `Type == "network"`
- CLB: Classic Load Balancer returned by the classic ELB API
- Gateway LBs (`Type == "gateway"`) must be skipped
- "idle over N days" means no trusted CloudWatch client-traffic signal over the full configured window

---

## 4. API and IAM Contract

**Required:**
- `elbv2:DescribeLoadBalancers` — failure → FAIL RULE for ELBv2 branch
- `elb:DescribeLoadBalancers` — failure → FAIL RULE for CLB branch
- `cloudwatch:GetMetricStatistics` — failure → FAIL RULE for the affected item's branch

**Contextual (enrichment only; failure does not fail rule):**
- `elbv2:DescribeTargetGroups`
- `elbv2:DescribeTargetHealth`

**Pagination:** ELBv2 and CLB pagination must be fully exhausted.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only. No raw AWS field access after
normalization.

### ELBv2 Normalized Fields

| Field | Derivation |
|---|---|
| `resource_id` | `LoadBalancerArn` → absent (skip) |
| `lb_family` | `"alb"` when `Type == "application"`, `"nlb"` when `Type == "network"`, `"unsupported"` otherwise |
| `load_balancer_name` | `LoadBalancerName` → null |
| `load_balancer_arn` | `LoadBalancerArn` → null |
| `created_time` | `CreatedTime` (timezone-aware UTC) → absent (skip) |
| `age_days` | `floor((now_utc - created_time_utc) / 86400)` |
| `scheme` | `Scheme` → null |
| `dns_name` | `DNSName` → null |
| `vpc_id` | `VpcId` → null |
| `state_code` | `State.Code` → null |

### CLB Normalized Fields

| Field | Derivation |
|---|---|
| `resource_id` | `LoadBalancerName` → absent (skip) |
| `lb_family` | Always `"clb"` |
| `load_balancer_name` | `LoadBalancerName` → null |
| `load_balancer_arn` | Always null |
| `created_time` | `CreatedTime` (timezone-aware UTC) → absent (skip) |
| `age_days` | `floor((now_utc - created_time_utc) / 86400)` |
| `scheme` | `Scheme` → null |
| `dns_name` | `DNSName` → null |
| `vpc_id` | `VPCId` → null |
| `state_code` | Always null |

### Backend Context Fields (contextual only; never affect eligibility)

ALB/NLB: `target_group_count`, `registered_target_count`, `has_registered_targets`
CLB: `registered_instance_count`, `has_registered_instances`

String fields must be normalized from non-empty strings only.

---

## 6. Trusted Traffic-Signal Contract

### 6.1 ALB Traffic Contract

Traffic present if any of:
- `RequestCount` `Sum > 0`
- `ProcessedBytes` `Sum > 0`
- `ActiveConnectionCount` `Sum > 0`

Namespace: `AWS/ApplicationELB`, dimension `LoadBalancer = <ARN suffix after loadbalancer/>`

### 6.2 NLB Traffic Contract

Traffic present if any of:
- `NewFlowCount` `Sum > 0`
- `ProcessedBytes` `Sum > 0`
- `ActiveFlowCount` `Maximum > 0`

Namespace: `AWS/NetworkELB`, dimension `LoadBalancer = <ARN suffix after loadbalancer/>`

**NLB-specific:** Missing datapoints for any of these three metrics over the full lookback
window must be treated as incomplete / untrusted → FAIL RULE.

### 6.3 CLB Traffic Contract

Traffic present if any of:
- `RequestCount` `Sum > 0`
- `EstimatedProcessedBytes` `Sum > 0`

Namespace: `AWS/ELB`, dimension `LoadBalancerName = <load balancer name>`

### 6.4 Metric-Reading Rules

- ALB/CLB: missing datapoints (none reported) may be treated as zero (no traffic).
- NLB: missing datapoints over the full window must be treated as FAIL RULE.
- Any required metric read failure (non-permission API error) → FAIL RULE.
- Metric evaluation is deterministic: positive signal → traffic present; all-zero with
  complete coverage → zero-traffic candidate; NLB incomplete → FAIL RULE.

---

## 7. Backend Registration Context Contract

Backend registration is contextual only. Zero registered targets/instances increases
confidence but does not independently qualify a load balancer as idle.

ALBs can be useful with rules performing redirects or fixed responses;
"no registered targets" must never be treated as equivalent to "unused."

---

## 8. Evaluation Order (Mandatory)

**ELBv2 branch:**
1. Retrieve and fully paginate ELBv2 load balancers; fail ELBv2 branch on error.
2. Normalize each ELBv2 item.
3. Skip items with `lb_family == "unsupported"`.
4. Skip items without stable identity or without usable `created_time`.
5. Skip items where `age_days < idle_days_threshold`.
6. Skip items where `state_code` is not `"active"` or `"active_impaired"`.
7. Retrieve CloudWatch traffic signals; fail rule on error.
8. Skip items with trusted traffic present.
9. Enrich with target-group/target-health context (best-effort; failure degrades context, not rule).
10. Emit findings.

**CLB branch:**
11. Retrieve and fully paginate CLB inventory; fail CLB branch on error.
12. Normalize each CLB item.
13. Skip items without stable identity or without usable `created_time`.
14. Skip items where `age_days < idle_days_threshold`.
15. Retrieve CloudWatch traffic signals; fail rule on error.
16. Skip items with trusted traffic present.
17. Enrich with registered-instance context from normalized item.
18. Emit findings.

No raw AWS field access after normalization.

---

## 9. Exclusion Rules

| Condition | Result |
|---|---|
| `resource_id` absent | **SKIP ITEM** |
| `lb_family == "unsupported"` | **SKIP ITEM** |
| `created_time` absent or not safely comparable | **SKIP ITEM** |
| `age_days < idle_days_threshold` | **SKIP ITEM** |
| ELBv2 `state_code` not `"active"` or `"active_impaired"` | **SKIP ITEM** |
| Trusted traffic signal present | **SKIP ITEM** |
| ELBv2 dimension unparsable from ARN | **SKIP ITEM** |

No exclusion for: registered targets present, zero registered targets, scheme, VPC presence, tags.

---

## 10. Failure Model

- `elbv2:DescribeLoadBalancers` error → **FAIL RULE** (ELBv2 branch)
- `elb:DescribeLoadBalancers` error → **FAIL RULE** (CLB branch)
- CloudWatch metric error for any evaluated item → **FAIL RULE**
- NLB metric with no datapoints over full window → **FAIL RULE**
- Target-group / target-health enrichment failure → degrade context only (not FAIL RULE)

---

## 11. Evidence and Cost Contract

### 11.1 Required Evidence/Details Fields

Every emitted finding must include:
- `evaluation_path = "idle-load-balancer-review-candidate"`
- `lb_family`
- `resource_id`
- `load_balancer_name`
- `load_balancer_arn`
- `scheme`
- `dns_name`
- `vpc_id`
- `created_time`
- `age_days`
- `idle_days_threshold`
- `traffic_window_days`
- `traffic_signals_checked`
- `traffic_detected = false`

Family-specific:
- ALB/NLB: `state_code`, `has_registered_targets`, `registered_target_count`, `target_group_count`
- CLB: `has_registered_instances`, `registered_instance_count`

### 11.2 Cost Estimation Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode static cost guesses such as `~$16-22/month`.

---

## 12. Confidence Model

| Condition | Confidence |
|---|---|
| Zero traffic AND no registered targets/instances | `HIGH` |
| Zero traffic AND registered targets/instances still present | `MEDIUM` |

No LOW-confidence finding may be emitted. Metric failure = FAIL RULE, not LOW finding.

---

## 13. Title and Reason Contract

| Condition | Title | Reason |
|---|---|---|
| ALB finding | `"Idle ALB review candidate"` | `"ALB has no trusted CloudWatch traffic signal in the last {N} days"` |
| NLB finding | `"Idle NLB review candidate"` | `"NLB has no trusted CloudWatch traffic signal in the last {N} days"` |
| CLB finding | `"Idle CLB review candidate"` | `"CLB has no trusted CloudWatch traffic signal in the last {N} days"` |

Do NOT claim the load balancer is safe to delete.

---

## 14. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `MEDIUM` |

---

## 15. Acceptance Scenarios

### Must emit

1. ALB older than threshold, `state_code == "active"`, no ALB traffic over full window, zero targets → EMIT, HIGH
2. NLB older than threshold, `state_code == "active_impaired"`, zero NLB traffic with valid datapoints, registered targets → EMIT, MEDIUM
3. CLB older than threshold, zero CLB traffic, no instances → EMIT, HIGH

### Must skip

4. ELBv2 `Type == "gateway"` → SKIP
5. Load balancer younger than threshold → SKIP
6. ALB/NLB with any metric > 0 → SKIP
7. CLB with any metric > 0 → SKIP
8. ELBv2 in `"provisioning"` or `"failed"` state → SKIP
9. ELBv2 with ARN from which CloudWatch dimension cannot be extracted → SKIP

### Must fail

10. CloudWatch metric read failure for evaluated item → FAIL RULE
11. Inventory pagination failure → FAIL RULE
12. NLB metric missing datapoints over full window → FAIL RULE

### Must NOT happen

1. LOW-confidence finding emitted
2. Metric failure → LOW finding
3. Gateway LB evaluated
4. `estimated_monthly_cost_usd` set to a non-null value
5. `has_traffic=True, fetch_failed=True` producing any finding

---

## 16. In-File Contract

```
Rule: aws.elbv2.alb.idle
Rule: aws.elbv2.nlb.idle
Rule: aws.elb.clb.idle

    (spec — docs/specs/aws/elb_idle.md)

Intent:
    Detect ALB, NLB, and CLB load balancers that are at least
    idle_days_threshold days old and show no trusted CloudWatch evidence of
    client traffic during the full lookback window, so they can be reviewed
    as potential cleanup candidates.

Exclusions:
    - resource_id absent (malformed identity)
    - lb_family == "unsupported" (gateway LB or unknown type)
    - created_time absent or not safely comparable
    - age_days < idle_days_threshold (too new to evaluate)
    - ELBv2 state_code not "active" or "active_impaired"
    - trusted traffic present (any CloudWatch signal > 0)
    - ELBv2 ARN dimension unparsable

Detection:
    - resource_id present, lb_family in {"alb","nlb","clb"}
    - age_days >= idle_days_threshold
    - ELBv2: state_code "active" or "active_impaired"
    - all traffic signals absent during full lookback window

Key rules:
    - ALB: RequestCount Sum>0, ProcessedBytes Sum>0, or ActiveConnectionCount Sum>0
    - NLB: NewFlowCount Sum>0, ProcessedBytes Sum>0, or ActiveFlowCount Maximum>0
    - NLB: missing datapoints over full window = FAIL RULE (not zero)
    - CLB: RequestCount Sum>0 or EstimatedProcessedBytes Sum>0
    - Any metric read failure = FAIL RULE; no LOW-confidence path
    - ELBv2 dimension strictly from ARN suffix after loadbalancer/
    - Backend registration is contextual only
    - estimated_monthly_cost_usd = None

Blind spots:
    - planned future usage or blue/green staging
    - seasonal traffic patterns outside the current lookback window
    - DNS / allowlist / manual failover dependencies
    - NLB traffic rejected by security groups (not in CloudWatch)

APIs:
    - elbv2:DescribeLoadBalancers
    - elb:DescribeLoadBalancers
    - cloudwatch:GetMetricStatistics
    - elbv2:DescribeTargetGroups (contextual)
    - elbv2:DescribeTargetHealth (contextual)
```

---

## 17. Implementation Constants

- `_DEFAULT_IDLE_DAYS_THRESHOLD = 14`
