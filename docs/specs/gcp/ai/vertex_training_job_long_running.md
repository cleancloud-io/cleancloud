# GCP Rule Spec - `gcp.vertex.training_job.long_running`

## 1. Rule Identity

- **Rule ID:** `gcp.vertex.training_job.long_running`
- **Provider:** GCP
- **Resource type:** Vertex AI training job
- **Finding resource_type:** `gcp.vertex.training_job`

---

## 2. Intent

Detect **Vertex AI training resources that are provably still in an exact documented running state** and whose documented `startTime` shows they have been running for at least a conservative review threshold.

This rule is deliberately **precision-first**. It is a **review-candidate** rule only. It is **not** proof that a job is hung, **not** proof that no useful progress is occurring, **not** proof that the resource is safe to cancel, and **not** proof of a specific monthly dollar saving.

### 2.1 Canonical definitions

| Term | Definition |
|---|---|
| Vertex training job | Either a Vertex AI `CustomJob` or a Vertex AI `TrainingPipeline` |
| running custom job | A `CustomJob` whose `state` is exactly `JOB_STATE_RUNNING` |
| running training pipeline | A `TrainingPipeline` whose `state` is exactly `PIPELINE_STATE_RUNNING` |
| scan clock | Single `now_utc` instant captured once per scan run and reused for all resources |
| runtime anchor | The documented `startTime` field of the resource |
| elapsed runtime hours | `(now_utc - start_time_utc)` expressed in hours |
| elapsed runtime seconds | `(now_utc - start_time_utc)` expressed in seconds |
| long-running threshold hours | Configured review threshold for this rule (`long_running_hours_threshold`); default `24` hours |
| accelerator-backed job | A job whose documented worker-pool machine spec explicitly shows accelerator hardware |
| hardware unknown | A job for which the control-plane response does not expose enough documented machine-spec data to classify hardware |

---

## 3. GCP Documentation Grounding

### 3.1 CustomJob is the canonical Vertex AI resource for custom training workloads

Google documents `CustomJob` as a resource that runs custom workloads such as a Docker container or a Python package. Google also documents:

1. `jobSpec`
2. `state`
3. `createTime`
4. `startTime`
5. `endTime`
6. `updateTime`

Google explicitly defines `CustomJob.startTime` as the time when the `CustomJob` **for the first time entered** `JOB_STATE_RUNNING`.

Source:

- *REST Resource: projects.locations.customJobs*

URL:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.customJobs

Rule consequence:

1. `CustomJob` is an in-scope training resource for this rule.
2. `startTime` is the canonical runtime anchor for `CustomJob`.
3. `createTime` is **not** the canonical runtime anchor for a running job.

### 3.2 TrainingPipeline is also an in-scope training resource, but it is an orchestrator

Google documents `TrainingPipeline` as a resource that **orchestrates tasks associated with training a Model** and **always executes the training task**, while it may also export dataset data, upload the model, and evaluate the model.

Google also documents:

1. `trainingTaskDefinition`
2. `trainingTaskInputs`
3. `trainingTaskMetadata`
4. `state`
5. `createTime`
6. `startTime`
7. `endTime`
8. `updateTime`

Google explicitly defines `TrainingPipeline.startTime` as the time when the pipeline **for the first time entered** `PIPELINE_STATE_RUNNING`.

Google also documents that `trainingTaskMetadata` is populated only on a **best effort basis** while the pipeline is running.

Source:

- *REST Resource: projects.locations.trainingPipelines*

URL:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.trainingPipelines

Rule consequence:

1. `TrainingPipeline` is an in-scope training resource for this rule.
2. `startTime` is the canonical runtime anchor for `TrainingPipeline`.
3. `trainingTaskMetadata` must not be treated as canonical proof of runtime, progress, or hardware shape.
4. A `TrainingPipeline` finding remains review-candidate only because the resource may also be orchestrating non-training auxiliary tasks.

### 3.3 Exact running-state enums are documented

Google documents:

1. `JOB_STATE_RUNNING` means **the job is in progress**
2. `PIPELINE_STATE_RUNNING` means **the pipeline is in progress**
3. queued, pending, updating, pausing, cancelling, cancelled, failed, and succeeded are distinct states

Sources:

- *JobState*
- *PipelineState*

URLs:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/JobState
- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/PipelineState

Rule consequence:

1. Eligibility must require exact documented running states only.
2. The rule must not treat queued, pending, paused, updating, cancelling, cancelled, failed, or succeeded resources as running.

### 3.4 Worker-pool machine shape is documented for CustomJob

Google documents `CustomJobSpec.workerPoolSpecs` and `WorkerPoolSpec.machineSpec`.

Google documents on these surfaces:

1. `workerPoolSpecs`
2. `replicaCount`
3. `machineSpec.machineType`
4. `machineSpec.acceleratorType`
5. `machineSpec.acceleratorCount`
6. `machineSpec.tpuTopology`

Source:

- *CustomJobSpec*
- *MachineSpec*

URLs:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/CustomJobSpec
- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/MachineSpec

Rule consequence:

1. CustomJob hardware classification may be based on documented worker-pool machine-spec fields.
2. TPU-backed training may be identified from documented machine-spec fields such as TPU machine types and `tpuTopology`.
3. Hardware evidence must come from documented structured machine-spec fields, not from name heuristics outside those documented surfaces.

### 3.5 TrainingPipeline hardware exposure is task-definition dependent

Google documents:

1. `trainingTaskDefinition` points to the YAML definition of the training task
2. `trainingTaskInputs` contains the training task parameters **as specified by that definition**

Source:

- *REST Resource: projects.locations.trainingPipelines*

URL:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.trainingPipelines

Rule consequence:

1. Hardware classification for `TrainingPipeline` is optional and definition-dependent.
2. If the pipeline response does not expose documented worker-pool machine-spec fields through `trainingTaskInputs`, hardware must remain unknown.
3. The rule must not guess GPU, TPU, machine type, or replica count for `TrainingPipeline` resources whose task inputs do not expose those fields.

### 3.6 Vertex AI training pricing is usage-based and configuration-specific

Google documents that:

1. for custom-trained models, training prices depend on the selected machine types
2. if Compute Engine machine types have attached accelerators, accelerator cost is separate unless included in the machine type
3. pricing varies by region
4. reservations, committed use discounts, and Spot usage can change effective cost
5. there is **no minimum usage duration** for training and prediction; usage is charged in **30 second increments**

Source:

- *Vertex AI pricing*

URL:

- https://cloud.google.com/vertex-ai/pricing

Rule consequence:

1. Long-running training is a valid cost-review candidate because training compute is usage-billed while it runs.
2. Static hardcoded pricing tables are not canonical rule logic.
3. `estimated_monthly_cost_usd` must remain `None` because training jobs are transient, not recurring monthly resources.
4. The rule must not rely on region-agnostic or stale price heuristics for eligibility.

### 3.7 Vertex AI locations are regional, not global

Google documents that Vertex AI does not support a global location and uses regional resource names and regional service endpoints.

Source:

- *Vertex AI locations*

URL:

- https://cloud.google.com/vertex-ai/docs/general/locations

Rule consequence:

1. Location must be derived from the resource name.
2. Region filters must compare against exact regional location values.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. the resource is a documented in-scope Vertex AI training resource (`CustomJob` or `TrainingPipeline`)
2. the resource is in an exact documented running state
3. the resource has a valid, parseable, non-future `startTime`
4. the derived elapsed runtime is at least `long_running_hours_threshold`

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the training job is hung or deadlocked
- that the training job is abandoned or forgotten
- that the job is safe to cancel
- that no checkpointing or useful progress is occurring
- that the job is definitely expensive
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required surfaces

The implementation may use the following documented APIs:

1. `projects.locations.customJobs.list`
2. `projects.locations.trainingPipelines.list`

Relevant list-filter capability documented by Google:

1. CustomJobs support filtering by `state`
2. TrainingPipelines support filtering by `state`
3. paginated results must be exhausted using `nextPageToken`

Sources:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.customJobs/list
- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.trainingPipelines/list

### 6.2 Required per-resource fields

| Resource type | Required fields |
|---|---|
| `CustomJob` | `name`, `state`, `startTime` |
| `TrainingPipeline` | `name`, `state`, `startTime` |

### 6.3 Optional context fields

These may enrich the finding when present, but are not required for eligibility:

- `displayName`
- `jobSpec.workerPoolSpecs` on `CustomJob`
- `trainingTaskDefinition` on `TrainingPipeline`
- `trainingTaskInputs` on `TrainingPipeline`
- `labels`

---

## 7. Canonical normalization rules

Normalize the following values:

| Field | Canonical rule |
|---|---|
| `resource_name` | Must exactly match one of these forms: `projects/{project}/locations/{location}/customJobs/{id}` or `projects/{project}/locations/{location}/trainingPipelines/{id}`. Otherwise skip. |
| `location` | Parse from the exact `locations/{location}` segment of the resource name. Region-filter comparison must use exact string equality only, with no aliasing or case folding. |
| `state` | Compare exactly to the documented running enum for the resource type, case-sensitive and with no normalization. Null or empty values skip. |
| `start_time_utc` | Parse documented RFC3339 `startTime` into timezone-aware UTC. Valid RFC3339 timestamps, including fractional seconds and either `Z` or explicit offsets, must be accepted. Any other format is invalid. Missing, unparsable, or future values skip. No fallback parsing is allowed. |
| `elapsed_runtime_seconds` | Compute from a single per-run `now_utc - start_time_utc`. Do not round for eligibility decisions. |
| `elapsed_runtime_hours` | Derived display/context form of elapsed runtime. It must not be the canonical comparison unit. |

Important:

1. `createTime` is context only; it must **not** replace `startTime` as the runtime anchor.
2. `updateTime` is context only; it must **not** replace `startTime` as the runtime anchor.
3. `endTime` is not relevant for resources still in running state.
4. `now_utc` must be captured once per scan run in UTC and reused for all resources in that run.
5. `now_utc` must not be recomputed, shifted, or otherwise adjusted mid-scan.

---

## 8. Hardware evidence rules

### 8.1 CustomJob hardware classification

For `CustomJob`, hardware may be classified from documented `jobSpec.workerPoolSpecs[].machineSpec` fields:

1. `machineType`
2. `acceleratorType`
3. `acceleratorCount`
4. `tpuTopology`
5. `replicaCount`

If `workerPoolSpecs` is missing, empty, or all entries are structurally invalid, the job must remain eligible on duration/state grounds but `hardware_unknown = true`.

A pool entry is structurally valid only when `machineType` is present and non-empty. Pool entries without `machineType` are treated as malformed and must be skipped for hardware classification.

If some worker-pool entries are partially malformed, those invalid pools should be ignored for hardware classification rather than making the whole job ineligible. Hardware remains based only on structurally valid documented pools.

A `CustomJob` is accelerator-backed when **any** worker pool explicitly shows any of the following:

1. `acceleratorType` is a recognized documented enum value **and** `acceleratorCount > 0`, or
2. `machineType` is in a documented bundled-GPU machine family (e.g. `a2-*`, `a3-*`, `a4-*`, `a4x-*`, `g2-*`, `g4-*`) where the accelerator hardware is part of the machine type and no separate `acceleratorType` is required, or
3. `machineType` is in a documented Cloud TPU machine family (e.g. `ct4-*`, `ct5*`, `ct6*`, `tpu7x-*`)

`acceleratorType` alone with `acceleratorCount == 0` does **not** classify a pool as accelerator-backed.

### 8.2 TrainingPipeline hardware classification

For `TrainingPipeline`, hardware may be classified only when the response structurally exposes documented worker-pool machine-spec fields through `trainingTaskInputs` for that task definition.

At minimum, the exposed structure must contain:

1. the expected nested shape `trainingTaskInputs.workerPoolSpecs[].machineSpec`
2. `machineType` within that nested `machineSpec`
3. optionally `acceleratorType`, `acceleratorCount`, or `tpuTopology` within that same nested `machineSpec`

Flat, renamed, or otherwise shape-incompatible fields must not be treated as equivalent.

A `trainingTaskInputs.workerPoolSpecs[]` entry is structurally valid only when it contains a `machineSpec` dict with `machineType` present and non-empty. Entries without `machineType`, or entries that are not dicts, are treated as malformed and must be skipped for hardware classification.

If some entries are partially malformed, those invalid entries should be ignored for hardware classification rather than making the whole resource ineligible. Hardware remains based only on structurally valid documented entries.

If those fields are not exposed, then:

1. `hardware_unknown = true`
2. hardware class must remain unresolved
3. the rule must not guess GPU, TPU, replica count, or machine type

### 8.3 Hardware is auxiliary, not eligibility

Hardware evidence may affect risk labeling or finding context, but it must **not** be required for the rule to emit.

All worker pools that are exposed by the control-plane response must be evaluated. Accelerator classification must use **any** documented accelerator-backed pool, not only the first pool.

---

## 9. Decision rule

### 9.1 Eligibility

The resource is eligible only when:

1. resource type is `CustomJob` or `TrainingPipeline`
2. `state` is exactly:
   - `JOB_STATE_RUNNING` for `CustomJob`, or
   - `PIPELINE_STATE_RUNNING` for `TrainingPipeline`
3. `start_time_utc` is valid
4. `elapsed_runtime_seconds >= long_running_hours_threshold * 3600`

Configuration requirement:

1. `long_running_hours_threshold` must be `>= 1` (integer hours; equivalent to `> 0` for an integer parameter)
2. invalid threshold configuration must fail fast rather than silently clamp or reinterpret the value

### 9.2 Confidence

Confidence is a product policy, not a Google-defined concept:

1. `MEDIUM` when `elapsed_runtime_seconds >= long_running_hours_threshold * 3600`
2. `HIGH` when `elapsed_runtime_seconds >= 3 * long_running_hours_threshold * 3600`

### 9.3 Risk

Risk is a product policy and may use documented hardware evidence when available:

1. `CRITICAL` when confidence is `HIGH` and the job is provably accelerator-backed
2. `HIGH` when confidence is `HIGH` and accelerator hardware is not proven
3. `MEDIUM` for all `MEDIUM` confidence findings

### 9.4 Explicitly forbidden heuristics

The rule must **not**:

- emit below the configured long-running threshold
- emit a sub-threshold GPU or TPU "early warning"
- use `createTime` as a fallback runtime anchor
- use hardcoded hourly-price thresholds as an eligibility gate
- infer accelerator hardware when machine-spec evidence is absent

---

## 10. Cost handling

### 10.1 Canonical monthly cost field

`estimated_monthly_cost_usd = None`

Reason:

1. training jobs are transient, not monthly recurring resources
2. pricing varies by region, machine type, accelerator shape, reservations, discounts, and Spot usage
3. eligibility does not depend on cost

### 10.2 Accrued-cost estimates

The canonical rule does **not** require any accrued-cost calculation.

If a future implementation chooses to surface an accrued-cost hint, it must:

1. be clearly labeled non-canonical advisory context
2. use authoritative current pricing inputs for the exact region and hardware configuration
3. never affect eligibility, confidence, or risk

Static price tables and placeholder cost tiers are out of scope for the canonical rule.

---

## 11. Failure behavior

Always skip:

- empty resource names
- resource names that do not exactly match the documented 6-segment pattern for the resource type (extra segments, wrong resource-type keyword, empty segments all skip)
- `state` absent, empty, or not exactly equal to the documented running enum for the resource type
- `startTime` absent, not strict RFC3339 (space separator, no timezone offset, date-only, etc.), unparsable, or future
- elapsed runtime below threshold

Operational behavior:

1. permission errors on a required list surface should propagate
2. a non-permission fetch failure on one independent surface (`customJobs` or `trainingPipelines`) may warn and continue with the other surface
3. if pagination fails on a later page of one surface, earlier successfully fetched pages from that same surface may still be kept, but the partial read must be treated as a non-permission failure and warned
4. if both independent surfaces fail non-permissionally, the rule returns no findings and should warn that results are incomplete
5. the rule must not synthesize findings from a surface it failed to read
6. no cross-resource dedupe is required; each `CustomJob` or `TrainingPipeline` resource is evaluated independently

---

## 12. Output contract

### 12.1 Required finding fields

| Field | Value |
|---|---|
| `provider` | `gcp` |
| `rule_id` | `gcp.vertex.training_job.long_running` |
| `resource_type` | `gcp.vertex.training_job` |
| `resource_id` | Full Vertex AI resource name |
| `region` | Parsed resource location |
| `estimated_monthly_cost_usd` | `None` |

Identity rules:

1. `resource_id` is the canonical full resource name
2. `display_name` is optional context only and must not replace canonical identity

### 12.2 Required decision facts in details or evidence

The finding should surface, when available:

1. `job_type` (`customJob` or `trainingPipeline`)
2. exact running state
3. `startTime`
4. elapsed runtime hours
5. threshold hours
6. hardware evidence, if explicitly exposed
7. whether hardware is unknown

---

## 13. Examples of resources that must skip

- a `CustomJob` in `JOB_STATE_PENDING`
- a `TrainingPipeline` in `PIPELINE_STATE_QUEUED`
- a `CustomJob` whose `name` is `projects/p/locations/us-central1/customJobs/123/extra` (seven segments, not six)
- a `CustomJob` whose `name` is `projects/p/locations/us-central1/models/123` (wrong resource-type segment)
- a running resource with missing `startTime`
- a running resource whose `startTime` is `2025-06-01 12:00:00Z` (space separator — not RFC3339)
- a running resource whose `startTime` is `2025-06-01T12:00:00` (no timezone offset — not RFC3339)
- a running resource whose `startTime` is unparsable
- a running resource whose elapsed runtime is 23.9h when threshold is 24h
- a `TrainingPipeline` whose task inputs do not expose worker-pool machine specs, when the implementation would otherwise need those fields only to guess cost or accelerator class

---

## 14. Summary

This is a **duration-first Vertex AI training review rule**:

1. scope to resources whose name exactly matches the documented Vertex AI resource-name pattern
2. require exact state enum match read from the resource, not inferred from the list filter alone
3. anchor runtime strictly to documented `startTime` (RFC3339 only; no fallback parsing)
4. classify hardware from documented machine-spec fields only: explicit acceleratorType + count, bundled-GPU machine families, or TPU machine families
5. require `machineType` to be present for a pool entry to contribute to hardware classification
6. avoid sub-threshold warning heuristics
7. avoid pricing heuristics in canonical detection
