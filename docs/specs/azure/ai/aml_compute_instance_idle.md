# Azure Rule Spec - `azure.ml.compute_instance.idle`

## 1. Rule Identity

- **Rule ID:** `azure.ml.compute_instance.idle`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.MachineLearningServices/workspaces/computes`
- **Finding resource_type:** `azure.ml.compute_instance`

---

## 2. Intent

Detect **Azure Machine Learning compute instances that remain billable in `Running` state while showing no recent documented control-plane lifecycle activity** over a conservative review window.

This rule is deliberately **precision-first**. It is **not** a generic "inactive notebook" rule, **not** proof that a compute instance is safe to stop or delete, and **not** proof that no user is actively connected. It is a conservative review-candidate rule for compute instances that appear to have been left running without recent documented lifecycle actions.

---

## 3. Azure Documentation Grounding

### 3.1 Running compute instances continue to incur compute cost until stopped

Microsoft documents that Azure Machine Learning compute instances:

1. are managed cloud workstations for development and testing
2. can be started, stopped, restarted, and deleted
3. should be stopped to prevent ongoing compute-hour charges
4. stop compute-hour billing when deallocated, while disk, public IP, and standard load balancer charges can still remain

Sources:

- *What is an Azure Machine Learning compute instance?*
- *Manage an Azure Machine Learning compute instance*

URLs:

- https://learn.microsoft.com/en-us/azure/machine-learning/concept-compute-instance?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-compute-instance?view=azureml-api-2

Rule consequence:

1. This rule must evaluate only compute instances that are currently `Running`.
2. A stopped compute instance is out of scope for this rule.
3. The rule may state that stopping the instance would stop compute-hour spend, but it must not imply total workspace cost becomes zero.

### 3.2 Azure's documented inactivity definition is stronger than this rule's observable surface

Microsoft documents that compute-instance idle shutdown is based on runtime inactivity conditions such as:

- no active Jupyter kernel sessions
- no active Jupyter terminal sessions
- no active Azure Machine Learning runs or experiments
- no VS Code connections
- no custom applications running on the compute

Microsoft further documents that idle shutdown can be configured only within bounded inactivity periods, from a minimum of `15 minutes` to a maximum of `3 days`.

Sources:

- *Create an Azure Machine Learning compute instance*
- *Compute - Update Idle Shutdown Setting (Azure ML REST API)*

URLs:

- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-create-compute-instance?view=azureml-api-2
- https://learn.microsoft.com/en-us/rest/api/azureml/compute/update-idle-shutdown-setting?view=rest-azureml-2026-01-15-preview

Rule consequence:

1. This rule must **not** claim it observes actual notebook, terminal, run, VS Code, or custom-app inactivity.
2. This rule must be framed as a **control-plane review candidate**, not as definitive runtime idleness.
3. The rule must not use Azure's idle-shutdown bounds (`15 minutes` to `3 days`) as its own detection threshold; those bounds govern platform auto-shutdown settings, not this cost-hygiene review rule.

### 3.3 Compute-instance control-plane fields expose the documented lifecycle surfaces for this rule

Microsoft documents compute-instance control-plane fields including:

- top-level ARM `location`
- `properties.computeType`
- `properties.provisioningState`
- `properties.createdOn`
- `properties.modifiedOn`
- `properties.properties.state`
- `properties.properties.vmSize`
- `properties.properties.lastOperation.operationName`
- `properties.properties.lastOperation.operationTime`
- `properties.properties.lastOperation.operationStatus`

Sources:

- *Compute - Get (Azure ML REST API)*
- *Compute - List (Azure ML REST API)*
- *azure.mgmt.machinelearningservices.models.ComputeResource*
- *azure.mgmt.machinelearningservices.models.ComputeInstance*
- *azure.mgmt.machinelearningservices.models.ComputeInstanceProperties*
- *azure.mgmt.machinelearningservices.models.ComputeInstanceLastOperation*

URLs:

- https://learn.microsoft.com/en-us/rest/api/azureml/compute/get?view=rest-azureml-2025-06-01
- https://learn.microsoft.com/en-us/rest/api/azureml/compute/list?view=rest-azureml-2025-06-01
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-machinelearningservices/azure.mgmt.machinelearningservices.models.computeresource?view=azure-python
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-machinelearningservices/azure.mgmt.machinelearningservices.models.computeinstance?view=azure-python
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-machinelearningservices/azure.mgmt.machinelearningservices.models.computeinstanceproperties?view=azure-python
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-machinelearningservices/azure.mgmt.machinelearningservices.models.computeinstancelastoperation?view=azure-python

Rule consequence:

1. This rule must be limited to exact `computeType == "ComputeInstance"`.
2. The rule should evaluate only stable resources: exact `provisioningState == "Succeeded"` and exact inner `state == "Running"`.
3. `lastOperation.operationTime` is the primary documented lifecycle-activity timestamp.
4. `modifiedOn` may be used only as a weaker documented fallback when `lastOperation.operationTime` is unavailable.
5. Undocumented fallbacks such as age-only inference must not be used to prove idleness.

### 3.4 Idle-shutdown and schedule configuration are not reliable read-side exclusions for this rule

Microsoft documents that compute instances can be configured with idle shutdown and scheduled start/stop behavior.

Sources:

- *Create an Azure Machine Learning compute instance*
- *Manage an Azure Machine Learning compute instance*

URLs:

- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-create-compute-instance?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-compute-instance?view=azureml-api-2

Rule consequence:

1. This rule must not assume that a compute instance lacks schedule or idle-shutdown protection merely because those settings are not available on the standard read path used by the rule.
2. Schedule or idle-shutdown configuration may be mentioned as a blind spot, but must not be required to emit or to skip.
3. The rule is read-only; it must not mutate idle-shutdown settings.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `compute.id` is present and non-empty
2. `compute.name` is present and non-empty
3. `workspace.name` is present and non-empty
4. the optional region filter matches the normalized compute location
5. `compute_type` resolves to exactly `"ComputeInstance"`
6. `provisioning_state` resolves to exactly `"Succeeded"`
7. `state` resolves to exactly `"Running"`
8. `created_at` is known and the instance age is at least the configured idle window
9. a documented lifecycle-activity timestamp resolves reliably from `lastOperation.operationTime` or documented `modifiedOn`
10. the resolved lifecycle inactivity duration is at least the configured idle window

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that no notebook kernel, terminal session, VS Code session, AML run, or custom application is active right now
- that stopping or deleting the instance is safe
- that the creator or assigned user no longer needs the instance
- that no automatic schedule or platform policy will stop the instance later
- that a specific monthly dollar saving exists

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| AML workspace inventory | enumerate candidate workspaces |
| AML compute list/get for each workspace | determine resource identity, location, compute type, provisioning state, creation/modification timestamps, current state, VM size, and last lifecycle operation |

### 6.2 Authentication / permissions

Minimum permissions:

- `Microsoft.MachineLearningServices/workspaces/read`
- `Microsoft.MachineLearningServices/workspaces/computes/read`

No secret, key, session, or notebook-content retrieval is required for this rule.

### 6.3 Idle window

- Configurable parameter: `idle_days`
- Default: `14`
- Minimum effective value: `1`

Reason:

- Azure's documented idle-shutdown thresholds are operational auto-stop controls, not a direct contract for this review rule.
- A two-week default window is conservative enough to avoid flagging brief pauses while still surfacing compute instances that appear to have been left running.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Resolve from documented compute resource location surfaces only. If unresolved, treat as unknown and skip. Lowercase before comparison, then compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `compute_type` | Resolve from documented SDK/raw surfaces and compare case-sensitively to exact `"ComputeInstance"`. |
| `provisioning_state` | Resolve from documented SDK/raw surfaces and compare case-sensitively to exact `"Succeeded"`. |
| `state` | Resolve from documented inner compute-instance properties, normalize only by string extraction / surrounding-whitespace trimming, then compare case-sensitively to exact `"Running"`. Any other casing or value is not eligible. |
| `created_at` | Parse as a UTC instant from documented `createdOn` or equivalent SDK projection. If the chosen field is present but unparsable, skip. |
| `modified_at` | Parse as a UTC instant from documented `modifiedOn` or equivalent SDK projection. Use only as a fallback lifecycle timestamp when `last_operation_time` is absent, and only when `modified_at > created_at`. If used and unparsable, skip. |
| `last_operation_time` | Parse as a UTC instant from documented `lastOperation.operationTime`. If the field is present but unparsable, skip rather than silently falling back. |
| `last_operation_status` | Preserve the documented raw value such as `"Succeeded"` or `"InProgress"` for evidence only; missing status does not invalidate a parseable `last_operation_time`. |
| `lifecycle_activity_at` | Use `last_operation_time` when present and parseable; otherwise use `modified_at` only under the documented fallback rules. No other fallback is allowed. |
| `idle_signal_source` | One of `last_operation` or `modified_on`. No other fallback is allowed. |
| `vm_size` | Preserve raw documented value. GPU classification is limited to exact case-sensitive prefix matching on `Standard_NC`, `Standard_ND`, and `Standard_NV`. `null` or absent `vm_size` is non-GPU for risk purposes. |
| `tags` | `compute.tags or {}` - never `None` in output. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `compute.id` absent, `None`, or empty | Skip |
| 8.2 | `compute.name` absent, `None`, or empty | Skip |
| 8.3 | `workspace.name` absent, `None`, or empty | Skip |
| 8.4 | Region filter set and normalized compute location does not match | Skip |
| 8.5 | `compute_type` does not resolve to `"ComputeInstance"` | Skip |
| 8.6 | `provisioning_state` does not resolve to `"Succeeded"` | Skip |
| 8.7 | `state` does not resolve to `"Running"` | Skip |
| 8.8 | `location` is unresolved | Skip |
| 8.9 | `created_at` is absent, invalid, in the future, or younger than the effective `idle_days` window | Skip |
| 8.10 | Lifecycle-activity evaluation fails any deterministic rule in section `9.4` | Skip |
| 8.11 | Resolved lifecycle-activity timestamp is in the future | Skip |
| 8.12 | Floored `idle_since_days` is less than the effective `idle_days` window | Skip |
| 8.13 | All required signals resolve and documented lifecycle activity is stale for at least `idle_days` while the instance remains `Running` | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Scope and stable-state contract

Resolve `compute_type` in this order:

1. SDK projection such as `compute.properties.compute_type`
2. nested/raw management payload such as `properties.computeType`
3. otherwise unknown

Resolve `provisioning_state` in this order:

1. SDK projection such as `compute.properties.provisioning_state`
2. nested/raw management payload such as `properties.provisioningState`
3. otherwise unknown

Resolve `state` in this order:

1. SDK projection such as `compute.properties.properties.state`
2. nested/raw management payload such as `properties.properties.state`
3. otherwise unknown

Required behavior:

1. Only exact `"ComputeInstance"` is eligible for `compute_type`.
2. Only exact `"Succeeded"` is eligible for `provisioning_state`.
3. Only exact `"Running"` is eligible for `state`.
4. Unknown, conflicting, transitional, failed, or any other values must skip.

### 9.2 Location contract

Resolve `location` in this order:

1. top-level ARM resource location such as `compute.location`
2. subtype location such as `compute.properties.compute_location`
3. nested/raw subtype location such as `properties.computeLocation`
4. otherwise unknown

Required behavior:

1. Use the compute resource's documented location, not the workspace location, for filtering and reporting.
2. Compare by exact lowercase equality only.
3. If `location` cannot be resolved, skip.
4. If multiple documented location surfaces are present and conflict materially, skip.

### 9.3 Age contract

Required behavior:

1. `created_at` must resolve to a known UTC timestamp.
2. `created_at` in the future must skip.
3. Instance age must be at least the effective `idle_days` window.
4. Age may gate eligibility, but age alone must never prove idleness.
5. Timestamp parse failure on `created_at` must skip.

### 9.4 Lifecycle-activity contract

Definitions:

- **lifecycle activity**: a documented control-plane operation or modification timestamp on the compute instance resource; it is not proof of actual notebook or user-session activity
- **effective idle window**: `max(idle_days, 1)`
- **now_utc**: the evaluation time captured as a UTC timestamp
- **UTC-normalized timestamp**: a parsed timestamp converted to UTC before any comparison
- **idle duration**: `floor((now_utc - lifecycle_activity_at_utc).total_seconds() / 86400)`
- **idle_since_days**: exactly the computed `idle duration`
- **absent last operation**: `lastOperation` missing entirely, or present without an `operationTime` field
- **unusable last operation**: `lastOperation.operationTime` field is present but invalid or otherwise unusable for deterministic evaluation

Required behavior:

1. Resolve `last_operation` from documented compute-instance properties only.
2. All timestamp parsing, ordering, and age / inactivity comparisons must be performed on UTC-normalized timestamps, using `now_utc` as the comparison reference time.
3. If `lastOperation.operationTime` exists and parses successfully, use it as `lifecycle_activity_at`.
4. If `lastOperation.operationTime` exists but does not parse, skip rather than silently falling back.
5. Missing `lastOperation.operationStatus` does not invalidate a parseable `lastOperation.operationTime`.
6. `operationName` and `operationStatus` are evidence fields only; they must not independently drive skip or emit decisions unless the timestamp itself is invalid.
7. If `lastOperation.operationTime == created_at`, treat that as no proven post-create inactivity signal and skip.
8. Use documented `modifiedOn` only when `lastOperation` is absent or has no `operationTime`, and only when `modifiedOn` parses successfully and `modifiedOn > created_at`.
9. If `modifiedOn == created_at`, treat that as no proven post-create inactivity signal and skip.
10. If `modifiedOn` is selected and fails parsing, skip.
11. Future timestamps are handled strictly: any selected lifecycle timestamp greater than `now_utc` must skip; no clock-skew tolerance is allowed.
12. Do **not** use undocumented fallbacks such as `systemData.lastModifiedAt`.
13. Do **not** use age-only fallback.
14. Compute inactivity strictly from `lifecycle_activity_at`, never from age.
15. `idle_signal_source` must exactly match the timestamp actually selected for `lifecycle_activity_at`.
16. `idle_since_days` must equal the floored `idle duration`.
17. Emit only when floored `idle_since_days` is at least the effective idle window.

Rationale:

1. Microsoft documents `lastOperation` and `modifiedOn` as control-plane surfaces for compute instances.
2. Microsoft separately documents runtime inactivity for idle shutdown using signals that are not available from this rule's read path.
3. Therefore this rule must fail closed whenever documented lifecycle signals are absent, weak, or unparsable.

### 9.5 Risk and confidence contract

Risk:

1. `HIGH` when non-null `vm_size` begins with one of the exact case-sensitive matching prefixes `Standard_NC`, `Standard_ND`, or `Standard_NV`
2. `MEDIUM` otherwise, including `null` / absent `vm_size`

Confidence:

1. `MEDIUM` when `last_operation` is the idle signal source and all required conditions are met
2. `LOW` when documented `modifiedOn` fallback is the idle signal source and all required conditions are met

Rationale:

1. Even the strongest version of this rule observes only documented control-plane lifecycle staleness, not runtime notebook/session inactivity.
2. `modifiedOn` is weaker than `lastOperation.operationTime` for review purposes and must not receive the same confidence level.

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** use flat hardcoded VM price tables.
2. Do **not** claim exact monthly savings from management metadata alone.
3. State only that a compute instance left in `Running` state continues to incur compute-hour cost until stopped.
4. If relevant, note that disk, public IP, and standard load balancer charges can still remain after stop/deallocation.

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.ml.compute_instance.idle"` |
| `resource_type` | `"azure.ml.compute_instance"` |
| `resource_id` | original ARM id from `compute.id` |
| `region` | normalized compute location |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required confidence and risk

| Condition | Confidence | Risk |
|---|---|---|
| `idle_signal_source == "last_operation"` and GPU VM family | `MEDIUM` | `HIGH` |
| `idle_signal_source == "last_operation"` and non-GPU VM family | `MEDIUM` | `MEDIUM` |
| `idle_signal_source == "modified_on"` and GPU VM family | `LOW` | `HIGH` |
| `idle_signal_source == "modified_on"` and non-GPU VM family | `LOW` | `MEDIUM` |

### 11.3 Required evidence

`signals_used` must clearly disclose:

1. the resource is exact `ComputeInstance`
2. provisioning state is `"Succeeded"`
3. runtime state is `"Running"`
4. instance age is at least the configured idle window
5. the last documented control-plane lifecycle activity is older than the configured idle window
6. whether the stale timestamp came from `lastOperation.operationTime` or `modifiedOn`

`signals_not_checked` should include remaining blind spots such as:

1. active Jupyter kernels
2. active Jupyter terminals
3. active AML runs or experiments
4. active VS Code connections
5. custom applications currently running on the compute
6. creator or business-owner intent
7. automatic schedules or shutdown behavior not visible from the rule's read path
8. exact pricing after discounts, reservations, or special commercial terms

### 11.4 Required details

Details should include at least:

- `instance_name`
- `workspace_name`
- `resource_group`
- `subscription_id`
- `location`
- `vm_size`
- `compute_type`
- `provisioning_state`
- `state`
- `created_at`
- `modified_at` (may be present even when it was not used as the selected lifecycle signal)
- `last_operation_name` (`null` allowed)
- `last_operation_time`
- `last_operation_status` (`null` allowed)
- `idle_since_days`
- `idle_days_threshold`
- `idle_signal_source`
- `tags`

---

## 12. Failure Behavior

- If subscription-wide workspace inventory fails, let the exception propagate
- If per-workspace compute listing fails, skip that workspace
- If an individual compute record is malformed or missing required documented fields, skip that compute
- Do not emit when lifecycle activity can be inferred only from age, undocumented system-data timestamps, or guessed user behavior
- Do not mutate schedules or idle-shutdown settings as part of detection
