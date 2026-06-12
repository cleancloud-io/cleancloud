# aws.sagemaker.processing_job.long_running — Canonical Rule Specification

## 1. Intent

Detect SageMaker processing jobs that are still `InProgress` and have remained active longer than
the configured review threshold, so they can be reviewed as possible hung, stuck, or forgotten
jobs.

This is a **CleanCloud-derived review heuristic** based on SageMaker processing-job metadata, not
an AWS-native long-running finding. It is a **read-only review-candidate rule** — not a stop-safe
rule.

---

## 2. AWS API Grounding

Based on official SageMaker processing-job API and documentation.

### Key facts

1. `ListProcessingJobs` is the canonical inventory API for SageMaker processing jobs and supports
   pagination (max 100 per page).
2. AWS documents a `StatusEquals` / `MaxResults` interaction caveat for `ListTrainingJobs` where
   `MaxResults` jobs are retrieved first and only then filtered by status. The
   `ListProcessingJobs` documentation does not carry this same explicit warning. As a
   conservative design choice, this rule fully paginates without `StatusEquals` and filters
   client-side, to avoid any risk of silently missing `InProgress` jobs.
3. `ListProcessingJobs` returns `ProcessingJobSummary` objects including `ProcessingJobName`,
   `ProcessingJobArn`, `CreationTime`, `ProcessingJobStatus`, `ProcessingEndTime`,
   `LastModifiedTime`, `ExitMessage`, and `FailureReason`.
4. `ProcessingStartTime` is **only** available in `DescribeProcessingJob`, not in the list summary.
5. `DescribeProcessingJob` returns `ProcessingJobArn`, `ProcessingJobName`,
   `ProcessingJobStatus`, `CreationTime`, `LastModifiedTime`, `ProcessingStartTime`,
   `ProcessingEndTime`, `StoppingCondition`, `ProcessingResources`, `AppSpecification`,
   `RoleArn`, `ExitMessage`, `FailureReason`, `NetworkConfig`, `Environment`,
   `ExperimentConfig`, `AutoMLJobArn`, `MonitoringScheduleArn`, and `TrainingJobArn`.
6. `ProcessingStartTime` is when the processing job starts on instances.
7. `StoppingCondition.MaxRuntimeInSeconds` is the **only** stopping-condition field for processing
   jobs. Min: 1, Max: 777600 (9 days). There is no `MaxWaitTimeInSeconds` or
   `MaxPendingTimeInSeconds`.
8. `ProcessingResources.ClusterConfig` contains `InstanceType`, `InstanceCount`, `VolumeSizeInGB`,
   and optional `VolumeKmsKeyId`. There are no `InstanceGroups` (heterogeneous clusters).
9. Processing jobs do not support managed Spot training, warm pools, serverless execution, or
   secondary status.
10. `ProcessingJobStatus` values: `InProgress`, `Completed`, `Failed`, `Stopping`, `Stopped`.
11. Fixed monthly USD cost estimates are not canonical from the fetched AWS docs.

### Implications

- Inventory must be built by fully paginating `ListProcessingJobs` and filtering
  `ProcessingJobStatus` client-side; this rule must not depend on `StatusEquals="InProgress"` as
  complete inventory.
- `DescribeProcessingJob` is required for `ProcessingStartTime` (not available in list) and
  authoritative runtime-state enrichment.
- `ProcessingStartTime` is the canonical active-processing runtime anchor when present.
- `CreationTime` is the canonical submission / wall-clock anchor and is used for pending or
  pre-start jobs where `ProcessingStartTime` is absent.
- `MaxRuntimeInSeconds` is the configured runtime limit and becomes applicable when
  `ProcessingStartTime` is present.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **Processing job** — an item returned by `ListProcessingJobs`.
- **Eligible primary status** — `ProcessingJobStatus == "InProgress"`.
- `long_running_hours_threshold` — operator-configurable integer >= 1, default 24.
- `clock_skew_tolerance_seconds` — implementation tolerance for future timestamps, recommended 300.
- **job_age_hours** — `floor((now_utc - creation_time_utc) / 3600 seconds)`.
- **active_processing_hours** — `floor((now_utc - processing_start_time_utc) / 3600 seconds)` when
  `ProcessingStartTime` is present.
- **runtime_anchor**:
  - `processing_start_time_utc` when present
  - otherwise `creation_time_utc`
- **runtime_anchor_type**:
  - `"processing_start_time"` when `ProcessingStartTime` is present
  - `"creation_time"` otherwise
- **configured_runtime_limit_seconds** — `MaxRuntimeInSeconds` from `StoppingCondition` when
  present and valid; otherwise `null`. This is the raw configured value, independent of whether
  the job has started processing.
- **applicable_runtime_limit_seconds**:
  - `configured_runtime_limit_seconds` when `ProcessingStartTime` is present (the limit applies
    once processing has started)
  - `null` when `ProcessingStartTime` is absent (the job has not started, so the limit is not
    yet in effect)
- **unbounded_runtime_limit** — `true` when `applicable_runtime_limit_seconds == null`
- `evaluation_window_start_utc = now_utc - long_running_hours_threshold × 3600 seconds`
- `evaluation_window_end_utc = now_utc`

### Explicit scope boundary

This rule applies only to processing jobs whose primary status is currently `InProgress`.

Out of scope:

- `Completed`
- `Failed`
- `Stopping`
- `Stopped`
- exact price estimation, accrued USD estimation, or savings estimation

---

## 4. Canonical Rule Statement

A SageMaker processing job is eligible only when **all** of the following are true:

- stable processing-job identity exists
- primary status is `InProgress`
- `CreationTime` is valid
- `runtime_anchor` is valid
- `elapsed_runtime_hours >= long_running_hours_threshold`, where:
  - `elapsed_runtime_hours = active_processing_hours` when `ProcessingStartTime` is present
  - otherwise `elapsed_runtime_hours = job_age_hours`

No additional predicate may be required for baseline eligibility, including instance type, instance
count, or static cost heuristics.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

### 5.1 List-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `processing_job_name` | `ProcessingJobName` | skip item |
| `processing_job_arn` | `ProcessingJobArn` | skip item |
| `list_status` | `ProcessingJobStatus` | skip item |
| `creation_time_utc` | `CreationTime` (tz-aware UTC) | skip item |
| `last_modified_time_utc` | `LastModifiedTime` (tz-aware UTC) | null |

### 5.2 Describe-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `ProcessingJobArn` | fall back to normalized `processing_job_arn` |
| `describe_status` | `ProcessingJobStatus` | skip item |
| `processing_start_time_utc` | `ProcessingStartTime` (tz-aware UTC) | null |
| `configured_runtime_limit_seconds` | `StoppingCondition.MaxRuntimeInSeconds` | null |
| `instance_type` | `ProcessingResources.ClusterConfig.InstanceType` | null |
| `instance_count` | `ProcessingResources.ClusterConfig.InstanceCount` | null |

### 5.3 Derived Fields

| Canonical field | Derivation |
|---|---|
| `job_age_hours` | floor((now_utc - creation_time_utc) / 3600) |
| `active_processing_hours` | floor((now_utc - processing_start_time_utc) / 3600) when processing start exists |
| `runtime_anchor_type` | `"processing_start_time"` when processing start exists, else `"creation_time"` |
| `elapsed_runtime_hours` | `active_processing_hours` when processing start exists, else `job_age_hours` |
| `applicable_runtime_limit_seconds` | `configured_runtime_limit_seconds` when processing start exists; else `null` |
| `unbounded_runtime_limit` | `true` when `applicable_runtime_limit_seconds` is `null` |
| `elapsed_runtime_seconds` | `(now_utc - runtime_anchor).total_seconds()` — used for runtime-limit comparison (avoids floor rounding) |
| `exceeded_applicable_runtime_limit` | `true` when `applicable_runtime_limit_seconds` is non-null and `elapsed_runtime_seconds > applicable_runtime_limit_seconds` |

Normalization requirements:

- String-valued fields: normalize only from non-empty strings.
- Timestamp fields: must be timezone-aware UTC before use; naive timestamps must skip the item
  when required and normalize to `null` when optional.
- Future `CreationTime` or `ProcessingStartTime` beyond `clock_skew_tolerance_seconds` must skip
  the item.
- `LastModifiedTime` must never cause a skip; if absent, naive, or future beyond skew tolerance,
  normalize to `null`.
- `ProcessingStartTime < CreationTime` by more than `clock_skew_tolerance_seconds` must skip the
  item as inconsistent timestamp state.
- `ProcessingResources` and `StoppingCondition` must degrade safely to `null` fields when absent
  or malformed; optional context must not crash evaluation.

---

## 6. Runtime Signal Contract

This rule evaluates **elapsed runtime**, not true processing progress.

### 6.1 Primary elapsed-runtime rule

- If `ProcessingStartTime` is present, use `ProcessingStartTime` as the runtime anchor.
- If `ProcessingStartTime` is absent, use `CreationTime` as the runtime anchor.
- If `elapsed_runtime_hours >= long_running_hours_threshold`, the job is a long-running review
  candidate.

### 6.2 Stopping-condition interpretation

- `MaxRuntimeInSeconds` is the configured runtime limit. It becomes the applicable runtime upper
  bound only when `ProcessingStartTime` is present (the limit governs active processing time).
- If `ProcessingStartTime` is absent, the configured limit exists but is not yet in effect — the
  job has not started actual processing.
- Runtime-limit comparison must use `elapsed_runtime_seconds` (not floored hours) to avoid a job
  that is slightly over the limit appearing equal.
- If no applicable runtime limit exists, treat the job as unbounded and rely on the
  threshold-only signal.
- Exceeding the applicable runtime limit is a stronger signal than threshold age alone.

### 6.3 Explicit blind spots

This rule does **not** prove:

- that the processing container is hung or making no progress
- that the elapsed runtime is financially wasteful
- that a long pending state is definitely billable compute

---

## 7. Pricing / Cost Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode instance-price tables, accrued USD estimates, or regional billing assumptions.

---

## 8. Deterministic Evaluation Order

1. Retrieve and fully paginate `ListProcessingJobs` **without** relying on `StatusEquals` for
   completeness.
2. Normalize each list item.
3. For each normalized item:
   - identity absent → **SKIP ITEM**
   - list status absent → **SKIP ITEM**
   - list status != `InProgress` → **SKIP ITEM**
   - invalid / naive / future `creation_time_utc` → **SKIP ITEM**
4. Call `DescribeProcessingJob` for the candidate item.
5. Permission failure → **FAIL RULE**.
6. Non-permission describe failure (for example resource vanished between list and describe) →
   **SKIP ITEM**.
7. Normalize describe fields.
8. Re-check describe status; if not `InProgress` → **SKIP ITEM**.
9. invalid / future `processing_start_time_utc` beyond skew tolerance → **SKIP ITEM**.
10. `processing_start_time_utc < creation_time_utc` beyond skew tolerance → **SKIP ITEM**.
11. Compute `elapsed_runtime_hours` from the canonical runtime anchor.
12. `elapsed_runtime_hours < long_running_hours_threshold` → **SKIP ITEM**.
13. Otherwise → **EMIT**.

No raw AWS field access after normalization.

---

## 9. Exclusion Rules

1. identity absent (`processing_job_name` or `processing_job_arn`) → malformed inventory item
2. list or describe status absent → missing primary state
3. status not `InProgress` → out of scope
4. `CreationTime` absent / naive / future beyond skew tolerance → missing or invalid runtime anchor
5. `ProcessingStartTime` future beyond skew tolerance → invalid runtime anchor
6. `ProcessingStartTime < CreationTime` beyond skew tolerance → inconsistent timestamp state
7. `elapsed_runtime_hours < long_running_hours_threshold` → not long-running enough

---

## 10. Failure Model

**Rule-level failures (FAIL RULE):**

- `ListProcessingJobs` request or pagination failure
- `DescribeProcessingJob` permission failure
- permission failure for required APIs

**Item-level skips (SKIP ITEM):**

- malformed identity or missing required timestamps
- non-`InProgress` status
- invalid timestamp relationships
- non-permission `DescribeProcessingJob` failure
- candidate below threshold

---

## 11. Evidence / Details Contract

### Required details fields

```
evaluation_path                  = "long-running-sagemaker-processing-job-review-candidate"
processing_job_arn
processing_job_name
normalized_status                = "InProgress"
creation_time
processing_start_time
runtime_anchor_type
elapsed_runtime_hours
job_age_hours
active_processing_hours
long_running_hours_threshold
evaluation_window_start
evaluation_window_end
configured_runtime_limit_seconds
applicable_runtime_limit_seconds
unbounded_runtime_limit
exceeded_applicable_runtime_limit
```

### Optional context fields

```
instance_type
instance_count
is_accelerator_backed
```

### Required evidence wording

**Signals used** must state:

- processing job primary status is `InProgress`
- `elapsed_runtime_hours` met or exceeded the configured threshold
- which runtime anchor was used (`ProcessingStartTime` or `CreationTime`)
- whether the job exceeded the SageMaker `MaxRuntimeInSeconds` limit

**Signals not checked** must state major blind spots:

- actual processing-container progress state
- exact price impact or savings impact
- whether long pending time is actively billable compute

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
| `instance_type` is accelerator-backed (`ml.g*`, `ml.p*`, `ml.inf*`, `ml.trn*`) | `HIGH` |
| all other emitted findings | `MEDIUM` |

Risk is about likely waste severity, not proof of safe interruption.

---

## 14. Title and Reason Contract

| Condition | Title | Reason |
|---|---|---|
| Long-running processing job finding | `"Long-running SageMaker processing job review candidate"` | `"InProgress SageMaker processing job has exceeded the configured long-running threshold"` |

---

## 15. Non-Goals

This rule does **not**:

- infer exact billing from static price tables
- cover MonitoringSchedule-spawned processing jobs differently from standalone ones
- cover AutoML-spawned processing jobs differently from standalone ones
- determine whether a long-running job should be stopped automatically
