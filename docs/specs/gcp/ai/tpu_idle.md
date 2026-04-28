# GCP Rule Spec - `gcp.tpu.idle`

## 1. Rule Identity

- **Rule ID:** `gcp.tpu.idle`
- **Provider:** GCP
- **Resource type:** Cloud TPU Node
- **Finding resource_type:** `gcp.tpu.node`

---

## 2. Intent

Detect **standalone Cloud TPU Nodes that are currently in the documented billable `READY` state** and show **no observed accelerator-processing activity above a conservative threshold** over a buffered review window, using documented Cloud Monitoring duty-cycle telemetry.

This rule is deliberately **precision-first**. It is a **review-candidate** rule only. It is **not** proof that a TPU-backed job is abandoned, **not** proof that the node is safe to delete or stop, and **not** proof of a specific monthly dollar saving.

### 2.1 Canonical definitions

| Term | Definition |
|---|---|
| standalone TPU node | A TPU Node that is not clearly part of queued-resource or multislice orchestration for this rule: `queuedResource` absent/empty and `multisliceNode != true` |
| billable TPU node | A TPU Node in exact documented `READY` state |
| duty-cycle telemetry | Cloud Monitoring metric `tpu.googleapis.com/accelerator/duty_cycle` on monitored resource `tpu.googleapis.com/GceTpuWorker` |
| duty-cycle percent | Raw metric value in documented percent units with values in the range `[0,100]` |
| idle threshold percent | Product threshold for this rule: `2.0` percent maximum observed duty cycle; this threshold is a CleanCloud review threshold, not a Google-defined idle contract |
| evaluation window end | Inclusive buffered end instant `now_utc - 180 seconds` |
| evaluation window start | `evaluation_window_end_utc - idle_days × 86400 seconds` |
| full observation window | `[evaluation_window_start_utc, evaluation_window_end_utc]`, usable only when `create_time_utc <= evaluation_window_start_utc` |
| expected worker set | The full set of TPU workers that documented first-party identity surfaces prove belong to the TPU Node |
| joined worker set | The subset of the expected worker set for which worker-scoped duty-cycle telemetry is also proven to belong to the TPU Node |

---

## 3. GCP Documentation Grounding

### 3.1 TPU Node resource exposes the control-plane fields used by this rule

Google documents the TPU `Node` resource with fields including:

1. `name`
2. `description`
3. `acceleratorType`
4. `acceleratorConfig`
5. `state`
6. `runtimeVersion`
7. `createTime`
8. `schedulingConfig`
9. `health`
10. `queuedResource`
11. `multisliceNode`

Google also documents TPU Node lifecycle states including:

- `CREATING`
- `READY`
- `RESTARTING`
- `REIMAGING`
- `DELETING`
- `REPAIRING`
- `STOPPED`
- `STOPPING`
- `STARTING`
- `PREEMPTED`
- `TERMINATED`
- `HIDING`
- `HIDDEN`
- `UNHIDING`
- `UNKNOWN`

Source:

- *REST Resource: projects.locations.nodes*

URL:

- https://cloud.google.com/tpu/docs/reference/rest/v2/projects.locations.nodes

Rule consequence:

1. Eligibility must be based on documented TPU Node control-plane fields only.
2. Exact state `READY` is the only canonical in-scope billable lifecycle state for this rule.
3. Transitional or stopped-like states such as `STOPPING`, `STOPPED`, `STARTING`, `PREEMPTED`, and `TERMINATED` must skip.
4. `acceleratorConfig`, `acceleratorType`, `runtimeVersion`, `health`, and `schedulingConfig` are valid enrichment/context fields.

### 3.2 Billing accrues while a TPU Node is `READY`

Google documents Cloud TPU pricing as follows:

1. charges for Cloud TPU accrue while a TPU node is in `READY` state
2. prices are listed per chip-hour in USD
3. pricing varies by TPU version, region, and usage option
4. On Demand, Spot/Preemptible, and commitment-based usage options have different prices

Source:

- *Cloud TPU pricing*

URL:

- https://cloud.google.com/tpu/pricing

Rule consequence:

1. This rule must evaluate only nodes in exact `READY` state.
2. Nodes outside `READY` are out of scope for idle-cost findings.
3. The rule must not hardcode a universal hourly or monthly cost estimate across regions, TPU versions, and usage options.
4. `estimated_monthly_cost_usd` should remain `None` unless a future implementation computes current pricing from authoritative current region- and usage-specific pricing inputs.

### 3.3 Duty-cycle telemetry is documented on worker-scoped monitoring resources

Google documents Cloud TPU monitoring metrics including:

1. metric type `tpu.googleapis.com/accelerator/duty_cycle`
2. display name *Accelerator Duty Cycle*
3. kind `GAUGE`
4. type `DOUBLE`
5. unit `%`
6. monitored resource `tpu.googleapis.com/GceTpuWorker`
7. value semantics: percentage of time over the sample period during which the accelerator was actively processing, with values in the range `[0,100]`
8. metric label `accelerator_id`

Google also documents the `tpu.googleapis.com/GceTpuWorker` monitored resource with labels including:

1. `resource_container`
2. `location`
3. `worker_id`

Sources:

- *Monitor Cloud TPU VMs*
- *Google Cloud monitored resource list*

URLs:

- https://cloud.google.com/tpu/docs/troubleshooting/tpu-vm-monitoring
- https://docs.cloud.google.com/monitoring/api/resources

Rule consequence:

1. The canonical activity signal for this rule is `tpu.googleapis.com/accelerator/duty_cycle`.
2. This telemetry is documented at **worker/accelerator scope**, not directly at TPU Node scope.
3. Node-level idle determination therefore requires a **documented first-party join** from worker-scoped telemetry back to the TPU Node being evaluated.
4. If the implementation cannot prove the complete expected worker set and then prove that all evaluated worker/accelerator series belong to the TPU Node using documented first-party surfaces, the node must skip rather than guess.

### 3.4 Google documents a monitoring visibility delay buffer

Google documents:

1. it can take up to `180 seconds` between the time a Cloud TPU metric value is generated and when it is displayed in Metrics Explorer

Source:

- *Monitor Cloud TPU VMs*

URL:

- https://cloud.google.com/tpu/docs/troubleshooting/tpu-vm-monitoring

Rule consequence:

1. The trailing `180 seconds` before `now` must be excluded from the evaluation window.
2. The rule must not treat missing very-recent telemetry as proof of inactivity.

### 3.5 Queued resources and multislice TPU deployments are operationally different

Google documents that:

1. best practice is to create TPUs using queued resources rather than the direct Create Node API
2. multislice environments should use queued resources
3. TPU Node surfaces expose `queuedResource` and `multisliceNode`

Sources:

- *Manage TPU resources*
- *REST Resource: projects.locations.nodes*

URLs:

- https://cloud.google.com/tpu/docs/managing-tpus-tpu-vm
- https://cloud.google.com/tpu/docs/reference/rest/v2/projects.locations.nodes

Rule consequence:

1. Queued-resource-managed and multislice nodes are operationally different from standalone TPU nodes.
2. This rule should exclude `queuedResource`-backed and `multisliceNode == true` nodes rather than presenting them as ordinary standalone cleanup candidates.

### 3.6 Other TPU VM metrics are not canonical substitutes for duty-cycle telemetry

Google also documents TPU VM metrics such as:

- `cpu/utilization`
- `memory/usage`
- `network/received_bytes_count`
- `network/sent_bytes_count`
- `tpu/tensorcore/idle_duration`

These metrics support general monitoring and troubleshooting, but Google documents a distinct accelerator-processing signal via `accelerator/duty_cycle`.

Source:

- *Monitor Cloud TPU VMs*

URL:

- https://cloud.google.com/tpu/docs/troubleshooting/tpu-vm-monitoring

Rule consequence:

1. This rule must not substitute worker CPU, memory, network, or tensorcore-idle metrics for the canonical duty-cycle telemetry without a separately documented contract.
2. The rule is about **observed accelerator processing activity**, not generic TPU VM host utilization.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. the TPU Node is in exact documented `READY` state
2. the TPU Node is standalone for this rule, not queued-resource-managed or multislice
3. canonical duty-cycle telemetry is provably joined to the TPU Node and sufficiently observed across the full buffered observation window
4. no joined duty-cycle datapoint above `2.0` exists anywhere in the full buffered observation window, including the earliest valid joined datapoint in that window

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the TPU-backed job is abandoned
- that the TPU node is safe to stop or delete
- that queued-resource-managed or multislice capacity is safe to dismantle
- that a specific monthly saving exists
- that host CPU, memory, or network inactivity is enough to prove TPU accelerator idleness

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| TPU Nodes list (`projects.locations.nodes.list`) | enumerate candidate TPU Nodes and their lifecycle, creation, scheduling, and orchestration context |
| Cloud Monitoring `tpu.googleapis.com/accelerator/duty_cycle` | determine observed accelerator-processing activity |
| Additional first-party documented worker-identity surface, if needed | prove that worker-scoped duty-cycle telemetry belongs to the TPU Node being evaluated |

### 6.2 Permissions

Minimum permissions:

- `tpu.nodes.list`
- `monitoring.timeSeries.list`

If the implementation uses an additional documented first-party join surface, that read permission is also required.

### 6.3 Idle window

- Configurable parameter: `idle_days`
- Default: `7`
- Minimum effective value: `1`

Reason:

- TPU workloads are expensive enough that a one-week zero-processing window is a conservative review threshold.
- The threshold is intentionally longer than short experiment pauses but still surfaces likely idle accelerators.

### 6.4 Idle threshold

- Fixed rule threshold: `max_observed_duty_cycle_percent <= 2.0`

Reason:

- Google documents `duty_cycle` in percent units but does not define an idle threshold.
- `2.0%` is a conservative product threshold chosen to tolerate tiny background fluctuation without masking meaningful accelerator activity.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `resource_name` | Must be a non-empty string in documented TPU Node name form `projects/{project}/locations/{zone}/nodes/{node_id}`. Malformed names skip. |
| `node_id` | Final node-name segment. Empty result skips. |
| `zone` | Resolve from exact `locations/{zone}` segment in the node name. If unresolved, skip. |
| `region` | Derive from the zone by removing the final hyphen-delimited zone suffix. If the zone is unusable for region derivation, skip. |
| `state` | Compare case-sensitively to exact documented enum value `READY`. Any other value is out of scope. |
| `create_time_utc` | Parse documented RFC3339 `createTime` into a timezone-aware UTC instant. If present but unparsable, skip. Future timestamps skip. |
| `evaluation_window_end_utc` | `now_utc - 180 seconds`. If this buffered end would be before `create_time_utc`, the node is too young to evaluate. |
| `evaluation_window_start_utc` | `evaluation_window_end_utc - idle_days × 86400 seconds`. |
| `full_window_coverable` | True only when `create_time_utc <= evaluation_window_start_utc`. Otherwise skip. |
| `queued_resource_name` | Preserve raw `queuedResource`; a non-empty value means the node is out of scope. Malformed non-string/non-null values skip rather than assume standalone. |
| `multislice_node` | Treat exact boolean `true` as out of scope. Malformed non-boolean/non-null values skip rather than assume standalone. |
| `accelerator_type_context` | Prefer documented `acceleratorConfig.type` when present; otherwise preserve raw legacy `acceleratorType` as context only. |
| `topology_context` | Preserve documented `acceleratorConfig.topology` when present; context only. |
| `preemptible` | Preserve documented `schedulingConfig.preemptible` as context only. |
| `spot` | Preserve documented `schedulingConfig.spot` as context only. |
| `reserved` | Preserve documented `schedulingConfig.reserved` as context only. |
| `duty_cycle_metric_type` | Exact `tpu.googleapis.com/accelerator/duty_cycle`. |
| `duty_cycle_resource_type` | Exact `tpu.googleapis.com/GceTpuWorker`. |
| `duty_cycle_percent` | Preserve raw metric value in percent units `[0,100]`. Do not reinterpret as fraction. |
| `expected_worker_count` | Cardinality of the documented expected worker set for the TPU Node. If unknown, `telemetry_join_state` is not `complete`. |
| `joined_worker_count` | Cardinality of the joined worker set with proven telemetry ownership. Must equal `expected_worker_count`. |
| `max_observed_duty_cycle_percent` | Maximum observed `duty_cycle_percent` across all joined worker/accelerator series over the buffered observation window. |
| `telemetry_join_state` | `complete`, `incomplete`, or `unresolved`. `complete` means provably complete via documented first-party linkage. Only `complete` is eligible. |
| `telemetry_coverage_state` | `complete` or `unresolved`. `complete` means the joined telemetry is sufficiently observed across the full buffered window with no unresolved gaps. |
| `telemetry_state` | `no_observed_activity_above_threshold`, `observed_activity_above_threshold`, or `unresolved`. No age-only fallback state is allowed. |

Normalization requirements:

1. All timestamps used for comparison must be timezone-aware UTC.
2. Empty strings normalize to unusable, not meaningful values.
3. If a chosen field is present but unparsable, skip rather than silently falling back.
4. Duty-cycle thresholds and comparisons must be performed in **percent units**, not fractional units.
5. Threshold comparison is exact: `<= 2.0` qualifies, `> 2.0` does not. Do not round values before comparison.
6. Monitoring timestamps are the source of truth for telemetry coverage. Small clock skew may be tolerated only for coverage-boundary interpretation; it must never convert missing telemetry into zero activity or suppress a datapoint above `2.0`.
7. Join completeness and telemetry completeness are separate proof obligations. Ownership proof does not imply coverage proof, and coverage proof does not imply ownership proof.

---

## 8. Activity Determination Contract

Cloud Monitoring duty-cycle telemetry is the **sole trusted telemetry source** for this rule.

### 8.1 Required metric

| Field | Value |
|---|---|
| Metric type | `tpu.googleapis.com/accelerator/duty_cycle` |
| Kind | `GAUGE` |
| Value type | `DOUBLE` |
| Unit | `%` |
| Monitored resource | `tpu.googleapis.com/GceTpuWorker` |
| Resource labels | `resource_container`, `location`, `worker_id` |
| Metric label | `accelerator_id` |

### 8.2 Required query shape

The monitoring query must:

1. specify exactly one `metric.type`
2. specify exact resource type `tpu.googleapis.com/GceTpuWorker`
3. constrain resource location to the TPU Node zone or equivalent documented worker location
4. evaluate the buffered interval `[evaluation_window_start_utc, evaluation_window_end_utc]`
5. return all worker/accelerator series that can be proven to belong to the TPU Node
6. preserve worker/accelerator identity so the final decision can take the maximum across all workers, accelerators, and timestamps
7. avoid averaging across workers, accelerators, or timestamps

### 8.3 Worker-to-node join requirement

Because the documented duty-cycle metric is worker-scoped, the rule must establish a documented first-party join from the returned `GceTpuWorker` telemetry to the TPU Node under evaluation.

Allowed join principles:

1. use only documented first-party Google Cloud surfaces
2. join by explicit documented worker or VM identity, not names guessed from conventions
3. determine the complete expected worker set for the TPU Node from a documented identity surface only
4. prove that all worker/accelerator series used in evaluation belong to the TPU Node

Forbidden join strategies:

- guessing from prefixes, suffixes, or free-text descriptions
- inferring expected workers from topology, accelerator shape, or worker-count conventions unless Google explicitly documents that identity linkage
- treating all workers in a zone as belonging to one TPU Node
- silently ignoring workers or accelerators whose ownership cannot be proven

Join completeness requirements:

1. `expected_worker_count` must be known from documented first-party identity linkage
2. `joined_worker_count` must equal `expected_worker_count`
3. if the total worker count is unknown, partial, or contradictory, `telemetry_join_state` is not `complete`

If the join cannot be fully established, `telemetry_join_state` is not `complete` and the node must skip.

### 8.4 Telemetry coverage requirement

Telemetry coverage is a separate requirement from join completeness.

Coverage requirements:

1. no-series-returned is unresolved, not zero activity
2. `0.0` values are valid observed signals
3. missing datapoints must never be treated as zero
4. telemetry must be sufficiently observed across the full buffered window for every joined worker/accelerator series
5. coverage must be established from actual datapoint timestamps, not assumed sampling behavior
6. if the implementation cannot prove from monitoring timestamps that coverage across the full buffered window is sufficient, `telemetry_coverage_state = unresolved` and the node must skip
7. any gap that cannot be proven from datapoint timestamps to preserve sufficient observation is unresolved and must skip
8. the rule must not emit unless the full buffered window has no joined duty-cycle datapoint above `2.0`, including at the earliest valid joined datapoint in that window

Because Google does not publish a duty-cycle sampling cadence in the cited metric contract, the rule must not invent an age-only or heuristic fallback when telemetry completeness cannot be proven.

### 8.5 Interpretation rules

For a TPU Node with `telemetry_join_state == complete`:

1. use monitoring timestamps as the source of truth for telemetry timing
2. compute `max_observed_duty_cycle_percent` as the maximum across all joined worker/accelerator datapoints in the buffered window
3. if any joined datapoint exceeds `2.0`, `telemetry_state = observed_activity_above_threshold` and the node must skip
4. if all usable joined datapoints are less than or equal to `2.0`, the node is eligible only if `telemetry_coverage_state == complete`
5. do not average duty-cycle values across workers, accelerators, or timestamps
6. do not round duty-cycle values before comparison

Missing telemetry, missing joined workers, sparse coverage, or query failures are unresolved and must skip.

### 8.6 Forbidden fallbacks

The following must **not** be used to prove idleness:

- node age alone
- `createTime` alone
- host CPU, host memory, or host network metrics
- `tpu/tensorcore/idle_duration` or other TPU metrics as undocumented substitutes for `accelerator/duty_cycle`
- pricing level, TPU type, or topology alone
- missing monitoring telemetry treated as equivalent to zero activity
- incomplete join or sparse telemetry treated as equivalent to no joined duty-cycle datapoint above threshold

---

## 9. Unified Decision Rule

Emit only when **all** of the following are true:

1. the node identity and zone are parseable
2. if a region filter is set, the derived region matches exactly
3. exact node state is `READY`
4. `create_time_utc` is valid and the full buffered window is coverable
5. `queuedResource` is absent/empty and not malformed
6. `multisliceNode != true` and is not malformed
7. `telemetry_join_state == "complete"`
8. `joined_worker_count == expected_worker_count`
9. `telemetry_coverage_state == "complete"`
10. `max_observed_duty_cycle_percent <= 2.0`

If canonical duty-cycle telemetry is not both provably joined and sufficiently observed across the full buffered window, the rule **MUST NOT** emit.

Always skip:

- nodes not in `READY`
- nodes younger than the full buffered window
- nodes with malformed identity, timestamps, or orchestration fields
- queued-resource-managed or multislice nodes
- telemetry query failures
- incomplete or unresolved worker-to-node joins
- missing or sparse joined telemetry treated as unresolved
- no joined series returned
- any joined duty-cycle observation above `2.0`

---

## 10. Finding Shape

### 10.1 Core fields

| Field | Value |
|---|---|
| `provider` | `gcp` |
| `rule_id` | `gcp.tpu.idle` |
| `resource_type` | `gcp.tpu.node` |
| `resource_id` | full TPU Node resource name when available, otherwise normalized `node_id` |
| `region` | normalized region derived from node zone |
| `detected_at` | evaluation time |
| `estimated_monthly_cost_usd` | `None` |

### 10.2 Confidence / risk

| Field | Value |
|---|---|
| `confidence` | `HIGH` |
| `risk` | `HIGH` |

Reason:

- The rule emits only when the node is in documented billable `READY` state, is not queued/multislice-managed, and complete documented duty-cycle telemetry joined to the node shows **no joined duty-cycle datapoint above the conservative threshold** over the buffered window.

### 10.3 Required evidence content

Evidence should include factual signals only, such as:

1. exact state `READY`
2. node zone and derived region
3. `createTime`
4. buffered idle window
5. standalone/orchestration context (`queuedResource`, `multisliceNode`)
6. accelerator type/topology context when available
7. scheduling context (`preemptible`, `spot`, `reserved`) when available
8. canonical metric type used
9. expected vs joined worker counts
10. maximum observed duty-cycle percent
11. statement that complete joined telemetry showed no joined duty-cycle datapoint above threshold over the buffered window

Evidence must **not**:

- claim the TPU-backed job is abandoned
- claim the node is safe to stop or delete
- present a flat price estimate as authoritative current spend

---

## 11. Failure Behavior

### 11.1 Permission failures

Permission failures on required TPU inventory or monitoring surfaces must be surfaced explicitly. They must not be silently converted into heuristic findings.

### 11.2 Monitoring failures

If duty-cycle telemetry cannot be queried reliably, findings must not be emitted from age-only, host-metric, partial-join, or sparse-coverage fallback logic.

### 11.3 Malformed records

Malformed individual TPU Nodes should be skipped item-by-item when required identity, state, timestamp, or orchestration fields are unusable.

### 11.4 Join or telemetry incompleteness

Partial worker-to-node joins or incomplete duty-cycle telemetry are unresolved, not weak evidence.

Examples:

- some worker/accelerator series can be joined but not all
- the complete expected worker set cannot be proven
- no worker-scoped telemetry can be proven to belong to the node
- no joined series are returned for the node
- query succeeds but returns no usable joined telemetry
- telemetry exists only for a subset of proven workers or accelerators
