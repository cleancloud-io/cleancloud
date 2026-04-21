# aws.bedrock.provisioned_throughput.idle — Canonical Rule Specification

## 1. Intent

Detect Amazon Bedrock Provisioned Throughputs in the currently evaluated account/Region that
are currently serving capacity and show **no observed runtime request activity** for the full
configured observation window, so they can be reviewed as potential FinOps cleanup or
rightsizing candidates.

This is a **read-only review-candidate rule**. It is not proof that the throughput is safe to
delete, not proof that no one intends to use it, and not proof that immediate savings are
available if the throughput is under commitment.

---

## 2. AWS API Grounding

Based on official Amazon Bedrock control-plane, runtime, monitoring, pricing, and CloudWatch
API documentation.

### Key AWS facts

1. `ListProvisionedModelThroughputs` is the canonical Bedrock control-plane inventory API for
   Provisioned Throughputs in the account and supports pagination.
2. `ListProvisionedModelThroughputs` can filter by `statusEquals`.
3. `ProvisionedModelSummary.status` valid values are `Creating`, `InService`, `Updating`,
   and `Failed`.
4. `ProvisionedModelSummary.creationTime` is documented and required in list responses.
5. `ProvisionedModelSummary.provisionedModelArn` is documented and required in list
   responses.
6. `ProvisionedModelSummary.provisionedModelName` is documented and required in list
   responses.
7. `ProvisionedModelSummary.modelArn`, `foundationModelArn`, `modelUnits`,
   `desiredModelUnits`, `commitmentDuration`, and `commitmentExpirationTime` are documented
   control-plane fields.
8. Bedrock Provisioned Throughput is billed **hourly** until deleted.
9. Bedrock user-guide documentation states you can purchase Provisioned Throughput with
   commitment options including no commitment, one month, and six months.
10. Bedrock user-guide documentation states you **can't delete a Provisioned Throughput by
    Model Units with commitment before the commitment term is complete**.
11. Bedrock runtime APIs (`InvokeModel`, `Converse`) allow the request `modelId` to be the
    ARN of a Provisioned Throughput.
12. Bedrock runtime metrics are published in CloudWatch namespace `AWS/Bedrock`.
13. Bedrock monitoring docs state runtime metrics use dimension `ModelId`.
14. Bedrock monitoring docs define:
    - `Invocations` = number of successful runtime requests
    - `InvocationClientErrors` = number of invocation client-side errors
    - `InvocationServerErrors` = number of invocation server-side errors
    - `InvocationThrottles` = number of throttled invocation requests
15. CloudWatch `GetMetricStatistics` requires the exact metric/dimension combination that was
    published, uses inclusive `StartTime` and exclusive `EndTime`, rounds `StartTime`, does
    not guarantee datapoint order, and enforces retention/period constraints.
16. Bedrock pricing docs do **not** publish a canonical per-Model-Unit monthly USD table for
    Provisioned Throughput in the fetched documentation; pricing depends on model, units,
    Region, and commitment term, and some providers direct customers to their account team.

### Implications

- Only `InService` Provisioned Throughputs are eligible.
- Age thresholding is supportable because `creationTime` is documented.
- Runtime-activity evidence must be grounded in documented CloudWatch metrics under
  `AWS/Bedrock`.
- The documented request identifier for invoking a Provisioned Throughput is the
  `provisionedModelArn`; this is the canonical `ModelId` dimension value for this rule.
- `Invocations` alone does **not** cover failed or throttled request attempts; if the rule
  wants “no observed runtime request activity,” it must also consider error/throttle metrics.
- Missing CloudWatch datapoints are **not** documented as zero activity and must not be
  interpreted as zero by default.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **"Provisioned Throughput"** — an item returned by `ListProvisionedModelThroughputs`.
- **"idle"** — no observed Bedrock runtime request activity via the documented CloudWatch
  metrics contract for the full configured observation window.
- **"runtime request activity"** — any observed positive value in one or more of:
  `Invocations`, `InvocationClientErrors`, `InvocationServerErrors`, `InvocationThrottles`.
- **`idle_days_threshold`** — operator-configurable threshold, default `7`.
- **`observation_window_start_utc = now_utc − idle_days_threshold × 86400 seconds`**
- **`observation_window_end_utc = now_utc`**
- **`age_days = floor((now_utc − creation_time_utc) / 86400 seconds)`**

### Included

- Provisioned Throughputs in the currently evaluated Region/account
- `status == "InService"`
- `age_days >= idle_days_threshold`
- full required CloudWatch activity evidence available
- all required activity metrics show zero observed activity in the observation window

### Excluded

- `Creating`, `Updating`, `Failed`
- missing or invalid stable identity
- missing or invalid `creationTime`
- too new to evaluate (`age_days < idle_days_threshold`)
- missing CloudWatch datapoints for any required activity metric
- any observed runtime request activity

---

## 4. Canonical Rule Statement

A Provisioned Throughput is eligible only when **all** of the following are true:

- stable Provisioned Throughput identity exists
- `status == "InService"`
- `creationTime` is valid and not in the future
- `age_days >= idle_days_threshold`
- required Bedrock runtime activity metrics are available under
  `ModelId = provisionedModelArn`
- all required activity metrics sum to zero over the observation window

No additional predicate may be required for baseline eligibility, including:

- model family
- custom-vs-foundation model type
- commitment duration
- commitment expiration
- model units / desired model units
- inferred pricing band
- tags
- foundation model ARN presence

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `provisionedModelArn` | skip item |
| `provisioned_model_arn` | `provisionedModelArn` | skip item |
| `provisioned_model_name` | `provisionedModelName` | null |
| `normalized_status` | `status` | skip item |
| `creation_time_utc` | `creationTime` (tz-aware UTC) | skip item |
| `age_days` | floor((now − creation_time_utc) / 86400) | skip item |
| `model_arn` | `modelArn` | null |
| `foundation_model_arn` | `foundationModelArn` | null |
| `model_units` | `modelUnits` (int only) | null |
| `desired_model_units` | `desiredModelUnits` (int only) | null |
| `commitment_duration` | `commitmentDuration` | null |
| `commitment_expiration_time_utc` | `commitmentExpirationTime` (tz-aware UTC) | null |
| `last_modified_time_utc` | `lastModifiedTime` (tz-aware UTC) | null |

### Normalization requirements

- String-valued identifiers must normalize only from non-empty strings.
- Timestamp fields must be timezone-aware UTC before use; naive → skip item for required
  timestamps, null for contextual timestamps.
- Future `creationTime` → skip item.
- `resource_id` must be the `provisionedModelArn`, not the friendly name.

---

## 6. Idle-Activity Determination

CloudWatch is the **sole trusted runtime-activity source** for this rule.

### Required CloudWatch contract

| Field | Value |
|---|---|
| Namespace | `AWS/Bedrock` |
| Dimension | `ModelId = provisionedModelArn` |
| Statistics | `Sum` |
| Period | `idle_days_threshold × 86400` (satisfies CloudWatch retention constraints) |

### Required metrics

1. `Invocations`
2. `InvocationClientErrors`
3. `InvocationServerErrors`
4. `InvocationThrottles`

### Interpretation rules

- If any required metric returns datapoints with `Sum > 0` → **not idle** → **SKIP ITEM**
- The Provisioned Throughput is idle only when **all required metrics return datapoints** and
  all observed `Sum` values are exactly `0`

### Datapoint completeness

- Missing datapoints **must not** be interpreted as zero runtime activity
- If any required metric returns no datapoints → **SKIP ITEM** (insufficient evidence)
- If retrieval of any required metric fails → **FAIL RULE**

### Semantic boundary

- This rule detects **no observed Bedrock runtime request activity**, not “no business value”
- `Invocations` covers successful requests only; the error/throttle metrics are required so
  that failed/throttled attempts are still treated as observed activity

---

## 7. Pricing / Commitment Boundary

- `estimated_monthly_cost_usd = null`

### Mandatory rules

- MUST NOT emit a fixed per-MU monthly estimate from the fetched AWS docs
- MUST NOT infer immediate savings from idle state alone
- MAY surface `model_units`, `desired_model_units`, `commitment_duration`, and
  `commitment_expiration_time` as context only

### Required caveats

- Billing continues until the Provisioned Throughput is deleted
- Committed Model Unit Provisioned Throughputs may not be deletable before term completion
- Idle state does not necessarily mean the cost is immediately avoidable

---

## 8. Deterministic Evaluation Order

1. Retrieve and fully paginate `ListProvisionedModelThroughputs(statusEquals="InService")`
2. Normalize each item
3. For each normalized item:
   - `provisioned_model_arn` absent → **SKIP ITEM**
   - `normalized_status` absent or not `InService` → **SKIP ITEM**
   - `creation_time_utc` absent/invalid/future → **SKIP ITEM**
   - `age_days < idle_days_threshold` → **SKIP ITEM**
   - retrieve all required CloudWatch activity metrics using `ModelId = provisionedModelArn`
   - any required metric retrieval failure → **FAIL RULE**
   - any required metric has no datapoints → **SKIP ITEM**
   - any required metric has `Sum > 0` → **SKIP ITEM**
   - otherwise → **EMIT**

---

## 9. Exclusion Rules

1. `provisioned_model_arn` absent → malformed identity
2. `normalized_status` absent → missing current-state signal
3. `normalized_status != "InService"` → not currently serving provisioned capacity
4. `creation_time_utc` absent/naive/future → invalid age source
5. `age_days < idle_days_threshold` → too new
6. any required CloudWatch activity metric has no datapoints → insufficient trusted evidence
7. any required CloudWatch activity metric has positive observed activity → not idle

---

## 10. Failure Model

### Rule-level failures (FAIL RULE)

- `ListProvisionedModelThroughputs` request/pagination failure
- `GetMetricStatistics` failure for any required activity metric
- permission failure for required Bedrock or CloudWatch APIs

### Item-level skips (SKIP ITEM)

- malformed identity or creation time
- non-`InService` state
- too new
- insufficient CloudWatch datapoints
- observed runtime request activity

---

## 11. Confidence Model

| Condition | Confidence |
|---|---|
| All required activity metrics present and all sums zero over full window | `HIGH` |

**Mandatory rule:** use `HIGH` confidence. The finding is based on direct control-plane
status plus direct runtime-activity metrics with full required metric coverage.

---

## 12. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `HIGH` |

**Mandatory rule:** use `HIGH` risk. Provisioned Throughput is dedicated always-on Bedrock
capacity that continues billing while serving no observed runtime requests.

---

## 13. Evidence / Details Contract

### Required details fields

Each emitted finding should include, at minimum:

```text
evaluation_path                 = "idle-bedrock-provisioned-throughput-review-candidate"
provisioned_model_arn
provisioned_model_name
normalized_status               = "InService"
creation_time
age_days
idle_days_threshold
model_arn
foundation_model_arn
model_units
desired_model_units
commitment_duration
commitment_expiration_time
activity_metrics_checked
```

### Required `activity_metrics_checked`

```text
["Invocations", "InvocationClientErrors", "InvocationServerErrors", "InvocationThrottles"]
```

### Required evidence wording

Signals used should state:

- Provisioned Throughput is `InService`
- required Bedrock runtime activity metrics were queried under `ModelId = provisionedModelArn`
- no observed runtime request activity was present over the configured window

Signals not checked should state major blind spots, such as:

- whether the throughput is intentionally kept warm for failover or rare batch windows
- whether a commitment term prevents immediate deletion
- whether future traffic is expected soon
- application/business criticality
- exact current pricing and immediate avoidable savings

---

## 14. Non-goals / Blind Spots

This rule does **not** prove any of the following:

- that the Provisioned Throughput is safe to delete
- that the Provisioned Throughput is not intentionally reserved for future or failover use
- that immediate savings are available despite commitment constraints
- that no one attempted model usage outside the observation window
- that there are no operational dependencies on the provisioned ARN

---

## 15. API and IAM Contract

### Required APIs

- `bedrock:ListProvisionedModelThroughputs`
- `cloudwatch:GetMetricStatistics`

### Mandatory API usage rules

- `ListProvisionedModelThroughputs` must be paginated
- inventory should be filtered to `statusEquals="InService"` or equivalently excluded later
- `GetMetricStatistics` must query the exact published dimension combination
- this rule must use `ModelId = provisionedModelArn`
- undocumented fallback metric dimensions (for example foundation-model IDs) must not be
  required for canonical correctness

---

## 16. Acceptance Scenarios

### Must emit

1. `InService` Provisioned Throughput older than threshold, all 4 required metrics have
   datapoints, and all sums are `0`

### Must skip

2. `Creating` Provisioned Throughput
3. `Updating` Provisioned Throughput
4. `Failed` Provisioned Throughput
5. `InService` Provisioned Throughput younger than threshold
6. malformed item without `provisionedModelArn`
7. malformed item with missing/invalid/future `creationTime`
8. any required activity metric returns no datapoints
9. `Invocations` has `Sum > 0`
10. `InvocationClientErrors` has `Sum > 0`
11. `InvocationServerErrors` has `Sum > 0`
12. `InvocationThrottles` has `Sum > 0`

### Must fail

13. `ListProvisionedModelThroughputs` request/pagination failure
14. any required `GetMetricStatistics` request failure

---

Rule: aws.bedrock.provisioned_throughput.idle
