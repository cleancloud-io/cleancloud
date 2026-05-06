# GCP Rule Spec - `gcp.vertex.workbench.idle`

## 1. Rule Identity

- **Rule ID:** `gcp.vertex.workbench.idle`
- **Provider:** GCP
- **Resource type:** Vertex AI Workbench Instance
- **Finding resource_type:** `gcp.vertex.workbench.instance`

---

## 2. Intent

Detect **Vertex AI Workbench instances that are provably still running** and have **documented first-party evidence of notebook/kernel inactivity** over a conservative review window.

This rule is deliberately **precision-first**. It is a **review-candidate** rule only. It is **not** proof that an instance is safe to stop, **not** proof that no scheduled or background work exists, and **not** proof of a specific monthly dollar saving.

This rule is a **proof-based** rule, not a heuristic rule. In its current canonical form it is **currently dormant pending signal availability**: it is non-emitting unless a documented canonical activity signal path exists and passes the signal-availability gate.

This rule is designed to prove idleness when a qualifying canonical signal exists; it does **not** suggest optimization by itself.

### 2.1 Canonical definitions

| Term | Definition |
|---|---|
| Workbench instance | Vertex AI Workbench v2 `Instance` resource `projects/{project}/locations/{location}/instances/{instance_id}` |
| running instance | Instance whose `state` is exactly `ACTIVE` |
| kernel inactivity | The documented idle-shutdown notion of inactivity: no kernel activity for the configured time period; running a cell or new notebook output resets the timer; CPU usage does not |
| idle-shutdown configuration | Workbench metadata keys that control automatic shutdown behavior, especially `idle-timeout-seconds` and `enable-guest-attributes` |
| canonical idle signal | A documented first-party signal that can prove absence of kernel activity for the review window under the canonical signal requirements |
| activity signal source | The exact first-party source used for proof, such as a documented Workbench-attributable Cloud Logging or Cloud Monitoring surface |
| review window end | `now_utc` |
| review window start | `review_window_end_utc - idle_days x 86400 seconds` |
| full observation window | `[review_window_start_utc, review_window_end_utc]`, usable only when the chosen canonical idle signal can cover the full window |
| signal availability gate | The source is usable only when retention covers `idle_days`, the full observation window is continuously visible, and no permission gaps exist |
| invalid resource record | Record excluded from evaluation because required identity fields are missing, malformed, or unparsable |
| out-of-scope resource record | Valid resource record excluded from evaluation because it does not satisfy in-scope lifecycle conditions for this rule |
| not evaluable | Explicit outcome when no qualifying canonical signal exists or the signal-availability gate fails; this is not the same as "0 findings" |
| not evaluable reason code | Root-cause category for a not-evaluable outcome: `NO_SIGNAL`, `PERMISSIONS`, or `COVERAGE` |
| partial scan | Scan-level outcome for discovery-layer coverage gaps in the requested scope, such as when `unreachable[]` is reported; signal-quality failures alone are **not evaluable**, not partial, and MUST NOT change `scan_scope_state` |
| rule capability state | Static rule capability: `EMITTING_DISABLED` or `EMITTING_ENABLED` |
| scan scope state | Scope-level runtime state: `FULL` or `PARTIAL` |
| resource evaluation state | Aggregate runtime state across valid in-scope resources: `EVALUABLE`, `NOT_EVALUABLE`, or `MIXED`; it is determined independently from discovery completeness |
| reporting mode | Output mode for not-evaluable categories: `FULL_ENUMERATION` or `COUNT_ONLY` |
| candidate resources | Valid, in-scope Workbench instances with `state = ACTIVE` after normalization and filtering |
| `signal_coverage_start` | Placeholder for the earliest timestamp in the signal window actually used for proof |
| `signal_coverage_end` | Placeholder for the latest timestamp in the signal window actually used for proof |

---

## 3. GCP Documentation Grounding

### 3.1 Vertex AI Workbench `Instance` is the control-plane resource for this rule

Google documents the Vertex AI Workbench v2 `Instance` resource with fields including:

1. `name`
2. `state`
3. `createTime`
4. `updateTime`
5. `labels`
6. `gceSetup`
7. `gceSetup.machineType`
8. `gceSetup.acceleratorConfigs`
9. `gceSetup.metadata`
10. `gceSetup.bootDisk`
11. `gceSetup.dataDisks`

Google also documents:

1. `name` format: `projects/{projectId}/locations/{location}/instances/{instanceId}`
2. `ACTIVE` means **the instance is running**
3. `STOPPED` means the instance is stopped
4. `SUSPENDED` means the instance is suspended
5. `createTime` and `updateTime` are output-only timestamps on the instance resource

Source:

- *Resource: Instance*

URL:

- https://cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances

Rule consequence:

1. Eligibility must be based on documented `Instance` control-plane fields only.
2. Exact state `ACTIVE` is the only in-scope running lifecycle state for this rule.
3. `createTime` and `updateTime` are documented lifecycle/update timestamps, but Google does **not** document them as notebook-session or kernel-activity timestamps.
4. Resource identity and region must come from the documented full resource name, not from display text or labels.

### 3.2 The list API is paginated and can report unreachable locations

Google documents `projects.locations.instances.list` with:

1. `pageSize`
2. `pageToken`
3. `filter`
4. `instances[]`
5. `nextPageToken`
6. `unreachable[]`

Google documents `instances[]` and `unreachable[]` on `ListInstancesResponse`. The implementation must treat both fields as independently usable when present and must not assume mutual exclusivity unless Google documents that guarantee explicitly.

Source:

- *Method: projects.locations.instances.list*

URL:

- https://cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances/list

Rule consequence:

1. Pagination must be exhausted using `nextPageToken`.
2. Reported `unreachable` locations mean visibility is incomplete for that read.
3. If `unreachable[]` is present, the scan is **partial**.
4. Each unreachable location is a **not evaluable scope** for that scan; any resources in that location are outside canonical evaluable coverage and MUST NOT produce findings.
5. The rule may still emit findings for reachable locations within the requested scope, but the scan MUST remain `partial = true` and MUST surface the unreachable locations as `not_evaluable_scopes[]`.
6. The rule must not claim complete project-wide idle evaluation when the list response reports unreachable locations.
7. A future CleanCloud implementation may surface partial-scan status as a warning or exit-code signal, but canonical detection logic must already treat coverage as incomplete.

### 3.3 Google defines Workbench idleness in terms of kernel activity, not control-plane timestamps

Google documents Workbench idle shutdown as follows:

1. Workbench instances shut down after a specified period of inactivity by default
2. default idle-shutdown threshold is 180 inactive minutes
3. idle shutdown requires guest attributes to be enabled
4. the instance shuts down when there is **no kernel activity** for the specified time period
5. running a notebook cell or new output printing resets the idle-shutdown timer
6. CPU usage does **not** reset the idle-shutdown timer
7. idle shutdown looks for activity in local Jupyter session, terminal, and kernel endpoints

Source:

- *Idle shutdown*

URL:

- https://cloud.google.com/vertex-ai/docs/workbench/instances/idle-shutdown

Rule consequence:

1. The canonical inactivity concept for this rule is **kernel inactivity**, not generic VM age, not `updateTime`, and not CPU utilization.
2. `updateTime` must not be interpreted as "last notebook activity" or "last kernel activity".
3. `createTime` must not be used as an idle fallback or as proof that an instance has been unused since creation.
4. CPU or host activity metrics would not be canonical substitutes for notebook idleness without a separate documented contract, because Google explicitly distinguishes CPU usage from idle-shutdown activity.

### 3.4 Workbench metadata documents idle-shutdown configuration, not actual last activity

Google documents the following metadata keys for Workbench instances:

1. `idle-timeout-seconds` - integer idle time in seconds; default `10800`
2. `enable-guest-attributes` - required for idle shutdown; default `true`

Google also documents:

1. these metadata keys are managed through instance metadata
2. `instances.patch` supports updates to `gceSetup.metadata`
3. turning off idle shutdown is managed through metadata

Sources:

- *Manage metadata*
- *Method: projects.locations.instances.patch*

URLs:

- https://cloud.google.com/vertex-ai/docs/workbench/instances/manage-metadata
- https://cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances/patch

Rule consequence:

1. Idle-shutdown metadata is valid **configuration context** only.
2. Metadata can explain why an instance may remain running, but it does **not** prove whether the instance has been idle or active over the review window.
3. Presence, absence, or value changes of `idle-timeout-seconds` must not be treated as first-party evidence of recent or absent kernel activity.
4. `enable-guest-attributes` is operational context only; it is not a direct activity signal.

### 3.5 Workbench accelerator configuration is documented as GPU-only on this surface

Google documents `gceSetup.acceleratorConfigs` and `AcceleratorConfig` with:

1. `type`
2. `coreCount`
3. currently only one accelerator configuration is supported
4. **TPUs are not supported**

Source:

- *Resource: Instance* (`GceSetup`, `AcceleratorConfig`, `AcceleratorType`)

URL:

- https://cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances

Rule consequence:

1. Hardware enrichment may use the documented accelerator configuration when present.
2. This rule must not classify Workbench instances as TPU-backed from the documented `acceleratorConfigs` surface.
3. Hardware is auxiliary context only; it is not canonical proof of idleness.

### 3.6 Billing guidance distinguishes running compute from stopped storage-only cost

Google documents that:

1. while a Workbench instance is shut down, there are no CPU or GPU usage charges except scheduled executions that run during shutdown
2. disk storage charges still apply while the instance is shut down

Source:

- *Idle shutdown*

URL:

- https://cloud.google.com/vertex-ai/docs/workbench/instances/idle-shutdown

Rule consequence:

1. `ACTIVE` instances are the relevant compute-cost surface for this rule.
2. `STOPPED` or `SUSPENDED` instances are out of scope for this idle-compute rule, although storage cost can still remain.
3. The rule must not hardcode a fixed monthly estimate from static machine-price tables as canonical logic.
4. `estimated_monthly_cost_usd` should remain `None` unless a future implementation computes current pricing from authoritative region- and configuration-specific pricing inputs.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. the resource is a documented Workbench `Instance`
2. the resource name is valid and the location is parseable from it
3. if a region filter is set, it matches the normalized location exactly
4. the resource state is exactly `ACTIVE`
5. the resource satisfies the canonical idle signal requirements in section 8

If any required canonical signal condition cannot be established reliably, the resource is **not evaluable** for this rule version and MUST NOT produce findings.

**Current canonical status:** based on the documented surfaces referenced in this spec, no qualifying canonical signal exists that exposes per-instance last kernel activity or a kernel-idle time series suitable for this rule. Therefore the rule is currently in `EMITTING_DISABLED` mode and must not emit findings from control-plane timestamps alone until a qualifying signal path is documented and usable.

### 4.1 Current canonical decision flow

Implement the current version in this order:

1. capture `now_utc` once for the scan
2. list Workbench instances for the requested scope and exhaust pagination
3. if `unreachable[]` is reported, set `partial = true` and record each unreachable location in `not_evaluable_scopes[]`
4. normalize returned records; count invalid records in `excluded_invalid_resources_count` and exclude out-of-scope records before candidate resource formation
5. keep only valid in-scope `ACTIVE` instances as candidate resources
6. if there are no candidate resources:
   - set `resource_evaluation_state = EVALUABLE`
   - emit no findings
7. otherwise, as defined in section 4, classify those candidate resources as `not_evaluable_resources[]`
8. set `rule_capability_state = EMITTING_DISABLED`
9. in the current version, candidate resources default to `reason_code = NO_SIGNAL` because no qualifying canonical signal exists
10. in the current version, all candidate resources share the same evaluation outcome; therefore `resource_evaluation_state` cannot be `MIXED`
11. set `resource_evaluation_state = NOT_EVALUABLE` for the current version when candidate resources exist
12. emit no findings

`scan_scope_state` is determined exclusively by discovery-layer reachability, such as `unreachable[]`, and MUST NOT be changed by resource-level signal evaluation outcomes. Resource evaluation MUST remain independent of discovery completeness for reachable candidate resources.

If a future qualifying canonical signal path is documented, the implementation may continue from step 5 by applying section 8 to reachable candidate resources only.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that an old `updateTime` means the notebook is idle
- that an old `createTime` means the notebook has been unused
- that low CPU usage means the notebook is idle
- that the configured idle-shutdown timeout has already been exceeded
- that the instance is safe to stop
- that no scheduled executions or other intentional automation exist
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required surfaces

The implementation may use the following documented APIs and docs-backed fields:

1. `projects.locations.instances.list`
2. `Instance.name`
3. `Instance.state`
4. `Instance.gceSetup.metadata`
5. `Instance.gceSetup.machineType`
6. `Instance.gceSetup.acceleratorConfigs`
7. `Instance.createTime`
8. `Instance.updateTime`

### 6.2 Future activation path: conditional canonical activity signal sources

Canonical qualification is defined only in section 8.

These source classes are permitted only when explicitly documented by Google as Workbench-attributable and semantically aligned with kernel activity.

Permitted canonical source classes are:

1. **Google Cloud Logging**, but only when Google documents Workbench-attributable logs as part of Vertex AI Workbench itself, with semantics that map to notebook or kernel activity for an exact instance rather than incidental infrastructure events
2. notebook execution logs, when documented by Google as part of Vertex AI Workbench activity evidence and attributable per instance
3. kernel/session activity logs, but only when documented by Google as part of Vertex AI Workbench, attributable to the exact instance, and semantically tied to the Workbench idle definition
4. **Google Cloud Monitoring**, but only when Google documents a Workbench-specific metric/resource contract whose semantics map to kernel activity or documented absence of kernel activity rather than VM utilization

The consulted control-plane docs do **not** provide such a signal on the `Instance` resource itself, and this spec does **not** currently establish a qualifying Logging or Monitoring signal path. This section is therefore a **future activation path**, not an active emit path in the current version.

### 6.3 Future activation path: signal-availability gate

Even when a candidate signal source is documented, it is canonical only when all of the following are true:

1. retention for the chosen log or metric source is at least `idle_days`
2. the exact source is explicitly documented to provide continuous, gap-free coverage across the full observation window, including no sampling, ingestion, or visibility gaps
3. there are no permission gaps for the source over the evaluated scope
4. any required location-level reads are reachable for the evaluated scope

In a future activated version, implementations may rely only on explicit Google documentation or source contracts to establish these properties; they must not infer completeness, cadence, or gap-freeness heuristically.

If any condition fails, the resource or affected scope is **not evaluable**. The implementation must not silently treat missing, partial, or gap-ridden telemetry as equivalent to zero activity, and must not infer idle from "no events found".

### 6.4 Optional context fields

These may enrich a future finding but are not themselves eligibility signals:

- `labels`
- `creator`
- `instanceOwners`
- `healthState`
- `gceSetup.machineType`
- `gceSetup.acceleratorConfigs`
- `gceSetup.bootDisk`
- `gceSetup.dataDisks`
- `gceSetup.metadata`
- `createTime`
- `updateTime`

---

## 7. Canonical normalization rules

Normalize the following values:

| Field | Canonical rule |
|---|---|
| `resource_name` | Must exactly match `projects/{project}/locations/{location}/instances/{instance_id}`. Otherwise treat the record as invalid and exclude it from evaluation and findings. |
| `location` | Parse from the exact `locations/{location}` segment of the resource name. Region-filter comparison must use exact string equality only, with no aliasing or case folding. |
| `state` | Compare exactly to documented enum `ACTIVE`, case-sensitive and with no normalization. Null or empty values make the record invalid for this rule. |
| `now_utc` | Capture once per scan run in UTC and reuse for all resources in that run. |
| `metadata.idle-timeout-seconds` | Context only. If used, parse as an integer number of seconds or treat as unusable context. It must not be used as a substitute for observed inactivity. |
| `create_time_utc` | Optional context only. If parsed, require strict RFC3339. Parse failure removes context; it must not trigger fallback idle logic. |
| `update_time_utc` | Optional context only. If parsed, require strict RFC3339. Parse failure removes context; it must not trigger fallback idle logic. |

Important:

1. `updateTime` is **not** the canonical last-activity field.
2. `createTime` is **not** an idle fallback.
3. The rule must not derive `idle_since_days` from `updateTime` or `createTime`.
4. Normalization failures are invalid-resource exclusions, not **not evaluable** outcomes.
5. Invalid or out-of-scope resource records are excluded before evaluation and MUST NOT appear in `not_evaluable` outputs.

---

## 8. Future activation path: activity evidence rules

### 8.1 Canonical idle signal requirements

The rule may use an activity signal only when all of the following are true:

1. the signal is documented by Google
2. the signal is attributable to the exact Workbench instance being evaluated
3. the signal maps to Workbench's documented kernel-activity semantics, or the documented absence of such activity, rather than generic VM host utilization
4. the signal must have either an explicit documented inactivity contract or a documented last-activity contract with completeness guarantees, and it must support proving absence of activity; inactivity must not be inferred from missing events
5. the signal is resolved at per-instance scope, not only at project or aggregated scope
6. the signal passes the signal-availability gate

Examples of qualifying contracts include:

1. a documented per-instance Workbench metric explicitly defined as an idle-state signal for notebook or kernel activity
2. a documented per-instance Workbench field or metric explicitly defined as a last notebook or kernel activity timestamp, where Google documents completeness guarantees for the full observation window

### 8.2 Conditional source-path allowances

The following source paths may be used **only if fully compliant with section 8.1**:

1. Google Cloud Logging notebook execution logs
2. Google Cloud Logging kernel/session activity logs
3. Google Cloud Monitoring metrics that are explicitly documented against Workbench activity semantics

Allowing these source classes does **not** mean they are currently established as canonical for this rule.

### 8.3 Global exclusion list: non-canonical signals

The following are **not** canonical idle signals for this rule:

1. `updateTime`
2. `createTime`
3. instance age alone
4. idle-shutdown metadata values alone
5. machine type or accelerator configuration
6. generic CPU, GPU, memory, or network host utilization without a separate documented contract equating it to Workbench kernel inactivity
7. partial-window logs or metrics
8. aggregated or project-level signals that cannot be attributed to the exact instance
9. Cloud Monitoring host or VM utilization used as a proxy for notebook or kernel activity
10. "no events found" or "no logs returned" treated as proof of idleness
11. fallback to heuristics when a qualifying canonical signal is missing

For this spec, "proof" means an explicit Google-documented inactivity or last-activity contract with completeness guarantees across the full observation window. Proof is never inferred from sparse, partial, or missing events.

### 8.4 Idle-shutdown configuration is context only

Idle-shutdown configuration may be used to explain or enrich behavior, for example:

1. idle shutdown default exists
2. `enable-guest-attributes` is required
3. the configured timeout may be visible

But this configuration does **not** prove:

1. whether the instance actually experienced no kernel activity
2. whether idle shutdown ran successfully
3. whether the timer has or has not been reset within the review window

---

## 9. Decision rule

### 9.1 Eligibility

The resource is eligible only when:

1. resource type is Workbench `Instance`
2. `state` is exactly `ACTIVE`
3. the resource satisfies the canonical idle signal requirements in section 8

Configuration requirement:

1. `idle_days` must be `>= 1`
2. invalid threshold configuration must fail fast rather than silently clamp or reinterpret the value

### 9.2 Current canonical outcome

Under the currently consulted official docs, the canonical implementation follows the decision flow in section 4.1.

In the current version:

1. unreachable requested locations make the scan `partial` and populate `not_evaluable_scopes[]`
2. valid in-scope `ACTIVE` resources remain **not evaluable** as defined in section 4
3. findings remain empty until a documented qualifying signal path exists and satisfies section 8 for reachable resources

Absence of signal MUST NOT be interpreted as inactivity.

Important:

1. **not evaluable** is a separate first-class outcome, not a synonym for `0 findings`
2. the rule may return zero findings even when `ACTIVE` instances exist

### 9.3 Explicitly forbidden heuristics

The rule must **not**:

- emit from `updateTime` age alone
- emit from `createTime` age alone
- emit from an age fallback when `updateTime` is absent
- infer notebook inactivity from low CPU usage
- infer notebook inactivity from machine type or accelerator presence
- emit because idle shutdown is disabled or appears unconfigured
- fall back to heuristics if a qualifying canonical signal is missing

---

## 10. Cost handling

### 10.1 Canonical monthly cost field

`estimated_monthly_cost_usd = None`

Reason:

1. the canonical spec does not currently emit findings
2. authoritative Workbench cost depends on running compute shape, attached accelerators, disks, region, and usage option
3. stopped instances still incur disk charges, so simplistic compute-only estimates are incomplete

### 10.2 Future advisory cost hints

If a future implementation chooses to surface an advisory cost hint, it must:

1. be clearly labeled non-canonical advisory context
2. use authoritative current pricing inputs for the exact region and configuration
3. distinguish running compute from persistent disk charges
4. never affect eligibility

---

## 11. Failure behavior

### 11.1 Invalid or out-of-scope resource exclusion

Exclude from evaluation and findings:

- empty resource names
- resource names that do not exactly match the documented instance pattern
- `state` absent or empty
- resources in non-`ACTIVE` states

Use this exclusion taxonomy:

| Category | Meaning | Counted in `excluded_invalid_resources_count` |
|---|---|---|
| `INVALID` | malformed, missing, or unparsable required identity or state fields | yes |
| `OUT_OF_SCOPE` | valid resource record that is not in the rule's lifecycle scope, including non-`ACTIVE` resources | no |

Records with absent or empty `state` are `INVALID`. Resources in non-`ACTIVE` states are `OUT_OF_SCOPE`: they are valid but excluded from evaluation and MUST NOT be counted in `excluded_invalid_resources_count`.

`excluded_invalid_resources_count` excludes `OUT_OF_SCOPE` records by design.

Out-of-scope resources are excluded before candidate resource formation.

These are not **not evaluable** outcomes.

### 11.2 Not evaluable taxonomy

Classify as **not evaluable** and MUST NOT produce findings.

Section 12 is the authoritative runtime contract for `scan_scope_state`, `resource_evaluation_state`, `partial`, and reporting behavior. This section defines only the taxonomy and reason-code classification used by not-evaluable records.

Use the following reason codes:

| Reason code | Meaning |
|---|---|
| `NO_SIGNAL` | No qualifying canonical signal path exists for the resource or requested reachable scope |
| `PERMISSIONS` | Required permissions for the qualifying signal source are missing or incomplete |
| `COVERAGE` | Coverage is incomplete for the qualifying signal source or requested scope, including unreachable locations and partial observation windows |

If more than one reason applies, select the primary `reason_code` using this precedence:

1. `PERMISSIONS`
2. `COVERAGE`
3. `NO_SIGNAL`

Implementations may retain additional secondary reasons as non-canonical context, but each `not_evaluable` record should expose one primary `reason_code`.

When no qualifying canonical signal exists for the rule version, valid in-scope resources MUST use `reason_code = NO_SIGNAL`.

In `EMITTING_DISABLED` mode, `NO_SIGNAL` is a synthetic default applied uniformly to candidate resources and does not represent per-resource evaluation variance.

Apply them as follows:

- `NO_SIGNAL`: resources for which no qualifying canonical signal exists
- `COVERAGE`: resources for which signal retention is shorter than `idle_days`
- `COVERAGE`: resources for which the candidate signal covers only part of the observation window
- `NO_SIGNAL`, `PERMISSIONS`, or `COVERAGE`: resources for which the candidate signal fails the signal-availability gate, according to the underlying cause
- `PERMISSIONS`: resources or scopes for which permissions are insufficient to evaluate the chosen signal source
- `COVERAGE`: unreachable locations reported in the documented list response

Runtime handling of these reason codes, including scope partiality, output separation, and state precedence, is defined in section 12.

---

## 12. Output contract

### 12.1 Current runtime contract

The implementation must preserve these rule-level outcomes separately:

| Output | Meaning |
|---|---|
| `rule_capability_state` | Static capability state: `EMITTING_DISABLED` or `EMITTING_ENABLED` |
| `scan_scope_state` | Scope-level runtime state: `FULL` or `PARTIAL` |
| `resource_evaluation_state` | Aggregate runtime evaluation state across valid in-scope resources: `EVALUABLE`, `NOT_EVALUABLE`, or `MIXED` |
| `findings[]` | Emitted findings only |
| `partial` | `true` only for discovery-layer coverage gaps in the requested scope, including when `unreachable[]` is reported |
| `excluded_invalid_resources_count` | Exact count of invalid resource records excluded before canonical evaluation |
| `reporting_mode_not_evaluable_resources` | `FULL_ENUMERATION` or `COUNT_ONLY` |
| `reporting_mode_not_evaluable_scopes` | `FULL_ENUMERATION` or `COUNT_ONLY` |
| `not_evaluable_resources[]` | Valid in-scope resources that could not be evaluated under canonical signal requirements; each record should carry a `reason_code` |
| `not_evaluable_scopes[]` | Scope-level not-evaluable records, including unreachable locations; each record should carry a `reason_code` |

`partial = true` if and only if `scan_scope_state = PARTIAL`. `partial = false` if and only if `scan_scope_state = FULL`.

`scan_scope_state` is determined exclusively by discovery-layer reachability and MUST NOT be upgraded or downgraded by signal-evaluation outcomes.

All entries in `not_evaluable_scopes[]` derived from `unreachable[]` MUST use `reason_code = COVERAGE`.

For each not-evaluable category, the implementation MUST choose exactly one reporting mode:

1. `FULL_ENUMERATION` — return the complete set for that category
2. `COUNT_ONLY` — return the exact full count for that category without full enumeration

The implementation MUST NOT silently drop either category.

Implementations SHOULD default to `FULL_ENUMERATION` unless payload size or platform constraints require `COUNT_ONLY`.

If enumeration would make the payload unreasonably large, the implementation MAY use `COUNT_ONLY` for that category. If an exact full count cannot be established because of permission or coverage limits, the implementation MUST NOT claim `COUNT_ONLY`; instead, it must surface the affected scope or category as `PARTIAL` and/or `NOT_EVALUABLE` with the corresponding `reason_code`.

In the current version, counts for `not_evaluable_resources` are always exact because they derive from fully enumerated candidate resources.

The implementation MUST always retain an exact count for `excluded_invalid_resources_count`, even if individual excluded records are not returned in the payload.

This current runtime contract describes the rule as it behaves today.

### 12.2 Current canonical behavior

The current canonical behavior is to return **no findings** as defined in section 4.

This reflects `rule_capability_state = EMITTING_DISABLED`, not an accidental empty result.

Interpretation:

1. `0 findings` does **not** mean there are no idle Workbench instances
2. `0 findings` means there are no instances provably idle under canonical signals accepted by this spec
3. if signal availability or scope coverage is insufficient, the implementation should surface that the rule was **not evaluable** and/or **partial**, rather than implying complete negative coverage
4. as defined in section 4, no findings will be emitted even for reachable locations
5. even when `scan_scope_state = PARTIAL`, the current version MUST emit zero findings because no qualifying canonical signal exists
6. `rule_capability_state = EMITTING_DISABLED` is appropriate in the current dormant version
7. `scan_scope_state = PARTIAL` is appropriate only for discovery-layer coverage gaps, such as `unreachable[]`; signal evaluation gaps alone do not make the scan partial
8. `resource_evaluation_state = EVALUABLE` is appropriate when either no valid in-scope reachable candidate resources exist after filtering, or when evaluation is attempted and all candidate resources satisfy the canonical signal preconditions
9. `resource_evaluation_state = NOT_EVALUABLE` is appropriate when candidate resources exist but none of them can be evaluated under a qualifying canonical signal path
10. `resource_evaluation_state = MIXED` is appropriate when some valid in-scope reachable resources are evaluable and others are not
11. in the current dormant version, `resource_evaluation_state` will normally be `NOT_EVALUABLE`
12. `resource_evaluation_state = MIXED` MUST NOT be emitted in `EMITTING_DISABLED` mode
13. consumers SHOULD treat `NOT_EVALUABLE` as an unknown state requiring explicit surfacing rather than as a negative result or a retry guarantee
14. when a single primary status must be displayed, consumers SHOULD prioritize `scan_scope_state = PARTIAL` over any resource evaluation state

`EVALUABLE` when no candidate resources exist indicates a valid reachable scope with no eligible resources present after filtering; evaluation was not required on any candidate resource.

### 12.3 Future enhancement schema

If a future documented idle signal is added, the implementation may also populate the following finding fields:

| Field | Value |
|---|---|
| `provider` | `gcp` |
| `rule_id` | `gcp.vertex.workbench.idle` |
| `category` | `ai` |
| `severity` | Placeholder for future classification; must not affect canonical eligibility |
| `confidence` | Placeholder for future classification; must not affect canonical eligibility |
| `resource_type` | `gcp.vertex.workbench.instance` |
| `resource_id` | Full Workbench instance resource name |
| `region` | Parsed location from resource name |
| `activity_signal_source` | Canonical source used for proof, such as a documented log or metric surface |
| `signal_coverage_start` | Earliest timestamp covered by the exact signal window used for proof |
| `signal_coverage_end` | Latest timestamp covered by the exact signal window used for proof |
| `estimated_monthly_cost_usd` | `None` in canonical logic unless authoritative live pricing is added |

These fields are dormant in the current version because the rule does not yet have a qualifying canonical signal path.

---

## 13. Implementation notes for future hardening

This spec intentionally rejects the following as insufficient for canonical idle detection:

1. `ACTIVE` + old `updateTime`
2. `ACTIVE` + old `createTime`
3. `ACTIVE` + disabled idle shutdown
4. `ACTIVE` + low host utilization

To make this rule emit canonically in the future, the implementation needs a documented first-party per-instance activity surface that is semantically aligned with Workbench's documented idle-shutdown notion of **kernel inactivity**.

Likely future-enablement paths are:

1. documented Google Cloud Logging notebook execution logs that Google defines as part of Vertex AI Workbench
2. documented Google Cloud Logging kernel/session activity logs that Google defines as part of Vertex AI Workbench
3. documented Google Cloud Monitoring metrics whose semantics map directly to Workbench kernel activity

Any such path still requires full-window coverage, sufficient retention, exact per-instance attribution, and no permission or reachability gaps.
