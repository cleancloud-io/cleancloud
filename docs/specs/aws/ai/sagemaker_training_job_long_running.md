# aws.sagemaker.training_job.long_running — Canonical Rule Specification

## 1. Intent

Detect SageMaker training jobs that are still `InProgress` and have remained active longer than
the configured review threshold, so they can be reviewed as possible runaway, stuck, or forgotten
jobs.

This is a **CleanCloud-derived review heuristic** based on SageMaker training-job metadata, not an
AWS-native long-running finding. It is a **read-only review-candidate rule** — not a stop-safe
rule.

---

## 2. AWS API Grounding

Based on official SageMaker training-job API and documentation.

### Key facts

1. `ListTrainingJobs` is the canonical inventory API for SageMaker training jobs and supports
   pagination.
2. AWS explicitly documents that when `StatusEquals` and `MaxResults` are used together,
   `MaxResults` jobs are retrieved first and only then filtered by status.
3. `ListTrainingJobs` returns `TrainingJobSummary` objects including `CreationTime`,
   `LastModifiedTime`, `SecondaryStatus`, `TrainingJobArn`, `TrainingJobName`, and
   `TrainingJobStatus`.
4. `DescribeTrainingJob` returns `TrainingJobArn`, `TrainingJobName`, `TrainingJobStatus`,
   `CreationTime`, `TrainingStartTime`, `TrainingTimeInSeconds`, `BillableTimeInSeconds`,
   `SecondaryStatus`, `StoppingCondition`, `EnableManagedSpotTraining`, `ResourceConfig`,
   `ServerlessJobConfig`, and `WarmPoolStatus`.
5. `TrainingStartTime` is when the training job starts on training instances. AWS bills for the
   interval between `TrainingStartTime` and `TrainingEndTime`.
6. `StoppingCondition.MaxRuntimeInSeconds` caps how long a training job can run.
7. `StoppingCondition.MaxWaitTimeInSeconds` applies to managed Spot training and includes both
   waiting for Spot capacity and actual running time; it must be greater than or equal to
   `MaxRuntimeInSeconds`.
8. `StoppingCondition.MaxPendingTimeInSeconds` caps pending time, but AWS documents caveats for
   training plans where not all `Pending` time counts toward that limit.
9. `SecondaryStatus` values are explicitly documented as subject to change.
10. Warm pools are billable resources, but warm-pool billing behavior is separate from evaluating a
    currently `InProgress` training job.
11. Fixed monthly USD cost estimates are not canonical from the fetched AWS docs.

### Implications

- Inventory must be built by fully paginating `ListTrainingJobs` and filtering `TrainingJobStatus`
  client-side; this rule must not depend on `StatusEquals="InProgress"` as complete inventory.
- `DescribeTrainingJob` is required for authoritative runtime-state enrichment and stopping
  condition context.
- `TrainingStartTime` is the canonical active-training runtime anchor when present.
- `CreationTime` is the canonical submission / wall-clock anchor and is used for pending or
  pre-start jobs where `TrainingStartTime` is absent.
- `SecondaryStatus` is contextual only, not a stable primary decision key.
- `MaxPendingTimeInSeconds` is contextual only for this rule because AWS documents special pending
  semantics for training plans.
- When both `MaxWaitTimeInSeconds` and `MaxRuntimeInSeconds` are absent or inapplicable, the job has
  no configured runtime cap for this rule and remains eligible for threshold-only evaluation.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **Training job** — an item returned by `ListTrainingJobs`.
- **Eligible primary status** — `TrainingJobStatus == "InProgress"`.
- `long_running_hours_threshold` — operator-configurable, default 24.
- `clock_skew_tolerance_seconds` — implementation tolerance for future timestamps, recommended 300.
- **job_age_hours** — `floor((now_utc - creation_time_utc) / 3600 seconds)`.
- **active_training_hours** — `floor((now_utc - training_start_time_utc) / 3600 seconds)` when
  `TrainingStartTime` is present.
- **runtime_anchor**:
  - `training_start_time_utc` when present
  - otherwise `creation_time_utc`
- **runtime_anchor_type**:
  - `"training_start_time"` when `TrainingStartTime` is present
  - `"creation_time"` otherwise
- **applicable_runtime_limit_seconds**:
  - `MaxWaitTimeInSeconds` for managed Spot training when present
  - otherwise `MaxRuntimeInSeconds` when `TrainingStartTime` is present
  - otherwise `null`
- **unbounded_runtime_limit** — `true` when `applicable_runtime_limit_seconds == null`
- `evaluation_window_start_utc = now_utc - long_running_hours_threshold × 3600 seconds`
- `evaluation_window_end_utc = now_utc`

### Explicit scope boundary

This rule applies only to training jobs whose primary status is currently `InProgress`.

Out of scope:

- `Completed`
- `Failed`
- `Stopping`
- `Stopped`
- `Deleting`
- warm-pool-only cost after a job has completed or stopped
- exact price estimation, accrued USD estimation, or savings estimation

---

## 4. Canonical Rule Statement

A SageMaker training job is eligible only when **all** of the following are true:

- stable training-job identity exists
- primary status is `InProgress`
- `CreationTime` is valid
- `runtime_anchor` is valid
- `elapsed_runtime_hours >= long_running_hours_threshold`, where:
  - `elapsed_runtime_hours = active_training_hours` when `TrainingStartTime` is present
  - otherwise `elapsed_runtime_hours = job_age_hours`

No additional predicate may be required for baseline eligibility, including `SecondaryStatus`,
training image, instance type, instance count, warm-pool status, training plan ARN, or static cost
heuristics.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

### 5.1 List-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `training_job_name` | `TrainingJobName` | skip item |
| `training_job_arn` | `TrainingJobArn` | skip item |
| `list_status` | `TrainingJobStatus` | skip item |
| `creation_time_utc` | `CreationTime` (tz-aware UTC) | skip item |
| `last_modified_time_utc` | `LastModifiedTime` (tz-aware UTC) | null |
| `list_secondary_status` | `SecondaryStatus` | null |

### 5.2 Describe-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `TrainingJobArn` | fall back to normalized `training_job_arn` |
| `describe_status` | `TrainingJobStatus` | skip item |
| `training_start_time_utc` | `TrainingStartTime` (tz-aware UTC) | null |
| `describe_secondary_status` | `SecondaryStatus` | null |
| `enable_managed_spot_training` | `EnableManagedSpotTraining` | false |
| `max_runtime_seconds` | `StoppingCondition.MaxRuntimeInSeconds` | null |
| `max_wait_time_seconds` | `StoppingCondition.MaxWaitTimeInSeconds` | null |
| `max_pending_time_seconds` | `StoppingCondition.MaxPendingTimeInSeconds` | null |
| `instance_type` | `ResourceConfig.InstanceType` | null |
| `instance_count` | `ResourceConfig.InstanceCount` | null |
| `instance_groups` | `ResourceConfig.InstanceGroups` | null |
| `serverless_job_config_present` | `ServerlessJobConfig` present | false |
| `warm_pool_status` | `WarmPoolStatus.Status` | null |

### 5.3 Derived Fields

| Canonical field | Derivation |
|---|---|
| `job_age_hours` | floor((now_utc - creation_time_utc) / 3600) |
| `active_training_hours` | floor((now_utc - training_start_time_utc) / 3600) when training start exists |
| `runtime_anchor_type` | `"training_start_time"` when training start exists, else `"creation_time"` |
| `elapsed_runtime_hours` | `active_training_hours` when training start exists, else `job_age_hours` |
| `applicable_runtime_limit_seconds` | `max_wait_time_seconds` for managed Spot when present; else `max_runtime_seconds` when training start exists; else `null` |
| `unbounded_runtime_limit` | `true` when `applicable_runtime_limit_seconds` is `null` |
| `exceeded_applicable_runtime_limit` | `true` when `applicable_runtime_limit_seconds` is non-null and elapsed time from the corresponding anchor exceeds it |

Normalization requirements:

- String-valued fields: normalize only from non-empty strings.
- Timestamp fields: must be timezone-aware UTC before use; naive timestamps must skip the item
  when required and normalize to `null` when optional.
- Future `CreationTime`, `TrainingStartTime`, or `LastModifiedTime` beyond
  `clock_skew_tolerance_seconds` must skip the item.
- `TrainingStartTime < CreationTime` by more than `clock_skew_tolerance_seconds` must skip the item
  as inconsistent timestamp state.
- `ResourceConfig` and `StoppingCondition` must degrade safely to `null` fields when absent or
  malformed; optional context must not crash evaluation.

---

## 6. Runtime Signal Contract

This rule evaluates **elapsed runtime**, not true model progress.

### 6.1 Primary elapsed-runtime rule

- If `TrainingStartTime` is present, use `TrainingStartTime` as the runtime anchor.
- If `TrainingStartTime` is absent, use `CreationTime` as the runtime anchor.
- If `elapsed_runtime_hours >= long_running_hours_threshold`, the job is a long-running review
  candidate.

### 6.2 Stopping-condition interpretation

- For managed Spot training, `MaxWaitTimeInSeconds` is the applicable wall-clock upper bound when
  present.
- For non-Spot training, `MaxRuntimeInSeconds` is applicable only when `TrainingStartTime` is
  present.
- If no applicable runtime limit is configured, treat the job as unbounded and rely on the
  threshold-only signal.
- `MaxPendingTimeInSeconds` must not be used as a canonical emission predicate for this rule.
- Exceeding the applicable runtime limit is a stronger signal than threshold age alone.

### 6.3 Explicit blind spots

This rule does **not** prove:

- that the training algorithm is hung or making no progress
- that the elapsed runtime is financially wasteful
- that a long pending state is definitely billable compute
- that `SecondaryStatus` values are exhaustive or stable over time

---

## 7. Pricing / Cost Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode instance-price tables, accrued USD estimates, or regional billing assumptions.
- `BillableTimeInSeconds` and warm-pool billing may be emitted as optional context only when
  available, but they are not required for rule logic.

---

## 8. Deterministic Evaluation Order

1. Retrieve and fully paginate `ListTrainingJobs` **without** relying on `StatusEquals` for
   completeness.
2. Normalize each list item.
3. For each normalized item:
   - identity absent → **SKIP ITEM**
   - list status absent → **SKIP ITEM**
   - list status != `InProgress` → **SKIP ITEM**
   - invalid / naive / future `creation_time_utc` → **SKIP ITEM**
4. Call `DescribeTrainingJob` for the candidate item.
5. Permission failure → **FAIL RULE**.
6. Non-permission describe failure (for example resource vanished between list and describe) →
   **SKIP ITEM**.
7. Normalize describe fields.
8. Re-check describe status; if not `InProgress` → **SKIP ITEM**.
9. invalid / future `training_start_time_utc` beyond skew tolerance → **SKIP ITEM**.
10. `training_start_time_utc < creation_time_utc` beyond skew tolerance → **SKIP ITEM**.
11. Compute `elapsed_runtime_hours` from the canonical runtime anchor.
12. `elapsed_runtime_hours < long_running_hours_threshold` → **SKIP ITEM**.
13. Otherwise → **EMIT**.

No raw AWS field access after normalization.

---

## 9. Exclusion Rules

1. identity absent (`training_job_name` or `training_job_arn`) → malformed inventory item
2. list or describe status absent → missing primary state
3. status not `InProgress` → out of scope
4. `CreationTime` absent / naive / future beyond skew tolerance → missing or invalid runtime anchor
5. `TrainingStartTime` future beyond skew tolerance → invalid runtime anchor
6. `TrainingStartTime < CreationTime` beyond skew tolerance → inconsistent timestamp state
7. `elapsed_runtime_hours < long_running_hours_threshold` → not long-running enough

---

## 10. Failure Model

**Rule-level failures (FAIL RULE):**

- `ListTrainingJobs` request or pagination failure
- `DescribeTrainingJob` permission failure
- permission failure for required APIs

**Item-level skips (SKIP ITEM):**

- malformed identity or missing required timestamps
- non-`InProgress` status
- invalid timestamp relationships
- non-permission `DescribeTrainingJob` failure
- candidate below threshold

---

## 11. Evidence / Details Contract

### Required details fields

```
evaluation_path                  = "long-running-sagemaker-training-job-review-candidate"
training_job_arn
training_job_name
normalized_status                = "InProgress"
creation_time
training_start_time
runtime_anchor_type
elapsed_runtime_hours
job_age_hours
active_training_hours
long_running_hours_threshold
evaluation_window_start
evaluation_window_end
enable_managed_spot_training
applicable_runtime_limit_seconds
unbounded_runtime_limit
exceeded_applicable_runtime_limit
```

### Optional context fields

```
secondary_status
max_runtime_seconds
max_wait_time_seconds
max_pending_time_seconds
instance_type
instance_count
instance_groups
serverless_job_config_present
warm_pool_status
is_accelerator_backed
```

### Required evidence wording

**Signals used** must state:

- training job primary status is `InProgress`
- `elapsed_runtime_hours` met or exceeded the configured threshold
- which runtime anchor was used (`TrainingStartTime` or `CreationTime`)
- whether the job exceeded an applicable SageMaker stopping-condition limit

**Signals not checked** must state major blind spots:

- actual model-progress or convergence state
- exact price impact or savings impact
- whether long pending time is actively billable compute
- warm-pool-only post-job billing

---

## 12. Confidence Model

| Condition | Confidence |
|---|---|
| `exceeded_applicable_runtime_limit = true` | `HIGH` |
| all other emitted findings | `MEDIUM` |

No LOW finding should be emitted.

---

## 13. Risk Model

| Condition | Risk |
|---|---|
| any instance type in `instance_type` or `instance_groups` is accelerator-backed (`g*`, `p*`, `inf*`, `trn*`) | `HIGH` |
| all other emitted findings, including serverless jobs | `MEDIUM` |

Risk is about likely waste severity, not proof of safe interruption.

---

## 14. Title and Reason Contract

| Condition | Title | Reason |
|---|---|---|
| Long-running training job finding | `"Long-running SageMaker training job review candidate"` | `"InProgress SageMaker training job has exceeded the configured long-running threshold"` |

---

## 15. Non-Goals

This rule does **not**:

- infer exact billing from static price tables
- use `SecondaryStatus` as a stable canonical decision key
- treat `MaxPendingTimeInSeconds` as a canonical emission predicate
- cover warm-pool cost after a training job completes
- determine whether a long-running job should be stopped automatically
