# Azure Rule Spec — `azure.aml.compute.idle`

## 1. Rule Identity

- **Rule ID:** `azure.aml.compute.idle`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.MachineLearningServices/workspaces/computes`
- **Finding resource_type:** `azure.aml.compute`

---

## 2. Intent

Detect **managed Azure Machine Learning compute clusters (`AmlCompute`) that retain billable baseline capacity while showing no observed per-cluster job activity** over a fixed observation window.

This rule is deliberately **precision-first**. It is **not** a generic “quiet workspace” rule, **not** a generic “unused training resource” rule, and **not** proof that deleting the cluster is safe. It is a conservative review-candidate rule for clusters that appear to be kept warm by configuration rather than by observed workload.

---

## 3. Azure Documentation Grounding

### 3.1 AML compute clusters keep baseline nodes running when `minNodeCount > 0`

Microsoft documents that Azure Machine Learning compute clusters:

1. autoscale based on submitted jobs
2. scale down to the configured minimum node count
3. avoid charges when idle only when the minimum node count is set to `0`
4. keep the configured minimum number of nodes running when `minNodeCount > 0`, even if no jobs are running

Sources:

- *Manage and optimize costs for Azure Machine Learning*
- *Create an Azure Machine Learning compute cluster*
- *Compute target*

URLs:

- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-optimize-cost?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-create-attach-compute-cluster?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/concept-compute-target?view=azureml-api-2

Rule consequence:

1. `minNodeCount == 0` is out of scope for this rule.
2. `minNodeCount > 0` is billing-relevant even when no jobs are active.
3. This rule should target **baseline-capacity waste**, not all possible residual AML workspace costs.

### 3.2 Azure Machine Learning costs vary by VM size, region, priority, and surrounding infrastructure

Microsoft documents that Azure Machine Learning costs can include:

- VM runtime costs
- Azure Monitor costs
- load balancer costs for compute resources
- network and other dependent infrastructure costs
- pricing that varies by Azure region and resource choice

Sources:

- *Plan to manage costs for Azure Machine Learning*
- *Manage and optimize costs for Azure Machine Learning*

URLs:

- https://learn.microsoft.com/en-us/azure/machine-learning/concept-plan-manage-cost?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-manage-optimize-cost?view=azureml-api-2

Rule consequence:

1. The rule may state that ongoing cost exists when baseline nodes are intentionally retained.
2. The rule must **not** hardcode static VM price tables.
3. `estimated_monthly_cost_usd` should remain `None`.

### 3.3 Azure Monitor exposes per-cluster AML workspace metrics

Microsoft documents that `Microsoft.MachineLearningServices/workspaces` exposes quota and resource metrics including:

- `Active Nodes`
- `Idle Nodes`
- `Total Nodes`

Microsoft further documents:

- `Active Nodes` has the `ClusterName` dimension
- `Idle Nodes` has the `ClusterName` dimension
- `Total Nodes` has the `ClusterName` dimension
- these metrics support `PT1M` time grain

Source: *Supported metrics for Microsoft.MachineLearningServices/workspaces*
URL: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-machinelearningservices-workspaces-metrics

Rule consequence:

1. `Active Nodes` is the documented per-cluster workload-activity signal for this rule.
2. The rule should evaluate the metric **for the specific cluster** using the documented `ClusterName` dimension.
3. Workspace-level unfiltered fallback must **not** be used to prove a cluster is idle.
4. If the per-cluster activity metric cannot be resolved reliably, the cluster must be skipped.

### 3.4 AML compute control-plane fields expose cluster type, baseline scale settings, and allocation state

Microsoft documents AML compute control-plane fields including:

- `properties.computeType`
- `properties.provisioningState`
- `properties.createdOn`
- `properties.properties.vmSize`
- `properties.properties.vmPriority`
- `properties.properties.scaleSettings.minNodeCount`
- `properties.properties.scaleSettings.maxNodeCount`
- `properties.properties.scaleSettings.nodeIdleTimeBeforeScaleDown`
- `properties.properties.allocationState`
- `properties.properties.currentNodeCount`
- `properties.properties.targetNodeCount`
- `properties.properties.nodeStateCounts`

Sources:

- *Compute - Get (Azure ML REST API)*
- *Compute - List (Azure ML REST API)*
- *azure.mgmt.machinelearningservices.models.AmlCompute*
- *azure.mgmt.machinelearningservices.models.AmlComputeProperties*
- *azure.mgmt.machinelearningservices.models.ScaleSettings*

URLs:

- https://learn.microsoft.com/en-us/rest/api/azureml/compute/get?view=rest-azureml-2025-06-01
- https://learn.microsoft.com/en-us/rest/api/azureml/compute/list?view=rest-azureml-2025-06-01
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-machinelearningservices/azure.mgmt.machinelearningservices.models.amlcompute?view=azure-python
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-machinelearningservices/azure.mgmt.machinelearningservices.models.amlcomputeproperties?view=azure-python
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-machinelearningservices/azure.mgmt.machinelearningservices.models.scalesettings?view=azure-python

Rule consequence:

1. This rule must be limited to exact `computeType == "AmlCompute"`.
2. The rule should evaluate only **stable** compute clusters: exact `provisioningState == "Succeeded"` and exact `allocationState == "Steady"`.
3. The rule should require positive baseline scale settings and positive current node allocation before emitting.

### 3.5 AML compute clusters can live in a different region than the workspace

Microsoft documents that compute clusters can be created in a different region than the workspace.

Source: *Create an Azure Machine Learning compute cluster*
URL: https://learn.microsoft.com/en-us/azure/machine-learning/how-to-create-attach-compute-cluster?view=azureml-api-2

Rule consequence:

If a region filter is used, it must be applied to the **compute resource location**, not the workspace location.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `compute.id` is present and non-empty
2. `compute.name` is present and non-empty
3. `workspace.name` is present and non-empty
4. the optional region filter matches the normalized **compute** location
5. `compute_type` resolves to exactly `"AmlCompute"`
6. `provisioning_state` resolves to exactly `"Succeeded"`
7. `allocation_state` resolves to exactly `"Steady"`
8. `created_at` is known and the cluster age is at least `14 days`
9. `min_node_count` resolves to a known positive integer
10. `current_node_count` resolves to a known integer and is at least `min_node_count`
11. the required per-cluster activity metric resolves reliably for the same `14-day` window
12. the required per-cluster activity metric is zero for that window

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the cluster is safe
- that no future training run, pipeline, or batch inference job depends on it
- that the cluster is the cheapest possible configuration
- that no residual Azure ML infrastructure cost exists elsewhere in the workspace
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| AML workspace inventory | enumerate candidate workspaces |
| AML compute list/get for each workspace | determine compute type, region, provisioning state, age, baseline scale settings, allocation state, and node counts |
| Azure Monitor metrics on the workspace ARM id | determine observed per-cluster activity using the documented `ClusterName` dimension |

### 6.2 Authentication / permissions

Minimum permissions:

- `Microsoft.MachineLearningServices/workspaces/read`
- `Microsoft.MachineLearningServices/workspaces/computes/read`
- `Microsoft.Insights/metrics/read`

No secret or key retrieval is required for this rule.

### 6.3 Fixed idle window

- Configurable parameter: none
- Fixed evaluation window: `14 days`

Reason:

- AML compute clusters are autoscaling training infrastructure rather than long-lived serving infrastructure
- short warm baselines can be intentional for active experimentation
- a two-week fixed window is conservative enough to avoid flagging brief pauses while still surfacing clusters that appear intentionally kept warm without observed workload

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase ARM location string from the compute resource; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `compute_type` | Resolve from documented SDK/raw surfaces and compare case-sensitively to exact `"AmlCompute"`. |
| `provisioning_state` | Resolve from documented SDK/raw surfaces and compare case-sensitively to exact `"Succeeded"`. |
| `allocation_state` | Resolve from documented SDK/raw surfaces and compare case-sensitively to exact `"Steady"`. |
| `created_at` | Parse as UTC instant from `createdOn` or equivalent SDK projection. |
| `min_node_count` | Positive integer from documented scale-settings surfaces only. `<= 0`, invalid, or unresolvable values are not eligible. |
| `current_node_count` | Integer from documented AML compute properties only. Unknown, invalid, negative, or smaller-than-minimum values are not eligible. |
| `vm_priority` | Preserve raw documented value such as `Dedicated` or `LowPriority`; do not use it to infer exact savings. |
| `active_nodes_zero` | `True` only when the documented `Active Nodes` metric resolves reliably for the requested cluster and all usable source-bucket `Maximum` values are exactly zero. |
| `tags` | `compute.tags or {}` — never `None` in output. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `compute.id` absent, `None`, or empty | Skip |
| 8.2 | `compute.name` absent, `None`, or empty | Skip |
| 8.3 | `workspace.name` absent, `None`, or empty | Skip |
| 8.4 | Region filter set and normalized compute location does not match | Skip |
| 8.5 | `compute_type` does not resolve to `"AmlCompute"` | Skip |
| 8.6 | `provisioning_state` does not resolve to `"Succeeded"` | Skip |
| 8.7 | `allocation_state` does not resolve to `"Steady"` | Skip |
| 8.8 | `created_at` is absent, invalid, in the future, or less than `14 days` old | Skip |
| 8.9 | `min_node_count <= 0` or is unresolvable | Skip |
| 8.10 | `current_node_count` is negative, unresolvable, or smaller than `min_node_count` | Skip |
| 8.11 | Required per-cluster activity metric cannot be resolved reliably | Skip |
| 8.12 | Required per-cluster activity metric is non-zero over the `14-day` window | Skip |
| 8.13 | All required signals resolve, baseline capacity is clearly retained, and per-cluster activity is zero over `14 days` | **EMIT** |

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

Resolve `allocation_state` in this order:

1. SDK projection such as `compute.properties.properties.allocation_state`
2. nested/raw management payload such as `properties.properties.allocationState`
3. otherwise unknown

Required behavior:

1. Only exact `"AmlCompute"` is eligible for `compute_type`.
2. Only exact `"Succeeded"` is eligible for `provisioning_state`.
3. Only exact `"Steady"` is eligible for `allocation_state`.
4. Unknown, conflicting, transitional, or any other values must skip.

### 9.2 Baseline-capacity contract

Required behavior:

1. `min_node_count` must resolve to a known positive integer.
2. `current_node_count` must resolve to a known integer.
3. `current_node_count` must be at least `min_node_count`.
4. `min_node_count == 0` must skip.
5. Unknown, invalid, negative, or conflicting count values must skip.
6. `vm_size`, `vm_priority`, `max_node_count`, and `node_idle_time_before_scale_down` may enrich evidence, but they must not replace the baseline-node requirement.

Rationale:

This rule is specifically about clusters that are **clearly configured to keep billable baseline nodes allocated**. If the control plane does not clearly show that retained baseline, the rule must fail closed.

### 9.3 Per-cluster activity-metric contract

Required metric:

1. `Active Nodes` with `Maximum`

Definitions:

- **usable datapoint**: a datapoint with a parseable UTC timestamp inside the requested window and a numeric `Maximum` value
- **source bucket**: the metric bucket returned by Azure Monitor for the requested query interval before any spec-level normalization
- **UTC day bucket**: the UTC day boundary derived from a datapoint timestamp by normalizing it to `00:00:00Z` for that day
- **expected buckets**: count of UTC-aligned daily buckets overlapping `[window_start, window_end)`
- **observed buckets**: count of unique UTC day buckets with at least one usable datapoint after consolidating duplicate timestamps across all returned series for the target cluster
- **coverage ratio**: `observed_buckets / expected_buckets`
- **acceptable coverage**: `coverage_ratio >= 0.95`
- **resolve reliably**: the metric query returns valid per-cluster data for the requested window, meets the coverage threshold, and does not trigger any `UNKNOWN` condition
- **unusable response shape**: a metric response with missing `value`, malformed time series collections, unparsable timestamps, non-numeric aggregation values, or no reliable `ClusterName`-scoped series for the target cluster

Required behavior:

1. Query the documented `Active Nodes` metric for the same fixed `14-day` window.
2. Scope the query to the target cluster using the documented `ClusterName` dimension and the exact compute name.
3. Implementations must not use unfiltered workspace-level fallback to prove cluster idleness.
4. Implementations should request the finest practical documented granularity available for the query and evaluate activity on the returned source buckets before any UTC-day normalization.
5. Normalize datapoint timestamps to UTC day buckets only for coverage calculation and day-level consolidation.
6. If any source bucket has `Maximum > 0`, the metric is `ACTIVE`.
7. Treat any failed query, missing metric, unsupported cluster dimension, unusable response shape, empty series, no datapoints, no valid series, or coverage below threshold as `UNKNOWN`.
8. Treat the metric as `ZERO` only when it resolves reliably and all usable source-bucket values are exactly zero.
9. Emit only when the required activity metric evaluates to `ZERO`.

Rationale:

1. This rule is about **no observed workload activity** on a cluster that is still configured to keep baseline nodes alive.
2. The per-cluster dimension is required because workspace-level activity can hide or blur cluster-specific idleness.
3. The metric is evidence of observed job activity, not proof that the cluster is safe to delete.

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** use flat hardcoded VM price tables.
2. Do **not** derive a dollar amount from VM family prefixes or from `min_node_count`.
3. Do **not** claim exact monthly savings from management and metric surfaces alone.
4. State only that clusters retaining positive baseline nodes incur ongoing cost while that baseline is kept alive.

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.aml.compute.idle"` |
| `resource_type` | `"azure.aml.compute"` |
| `resource_id` | original ARM id from `compute.id` |
| `region` | normalized compute location |
| `confidence` | `HIGH` |
| `risk` | `MEDIUM` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required evidence

`signals_used` must clearly disclose:

1. the resource is exact `AmlCompute`
2. provisioning state is `"Succeeded"`
3. allocation state is `"Steady"`
4. cluster age is at least `14 days`
5. `min_node_count` is positive and `current_node_count >= min_node_count`
6. the documented `Active Nodes` metric for the target cluster resolved to **no observed active nodes** with sufficient coverage

`signals_not_checked` should include remaining blind spots such as:

1. future or scheduled training intent
2. business-owner intent not visible in Azure control plane
3. whether a warm baseline is intentionally retained for startup latency, quota reservation, or sporadic experimentation
4. exact VM and infrastructure pricing after discounts, reservations, or special commercial terms

### 11.3 Required details

Details should include at least:

- `cluster_name`
- `workspace_name`
- `resource_group`
- `subscription_id`
- `vm_size`
- `vm_priority`
- `min_node_count`
- `max_node_count`
- `current_node_count`
- `target_node_count`
- `allocation_state`
- `provisioning_state`
- `created_at`
- `node_idle_time_before_scale_down`
- `idle_window_days`
- `metrics_used`
- `tags`

---

## 12. Failure Behavior

- If subscription-wide workspace inventory fails, let the exception propagate
- If per-workspace compute listing fails, skip that workspace
- If per-compute record resolution or metric retrieval fails, skip that compute
- If a compute record is malformed or missing required fields, skip that compute
- Do not emit on partial, aggregated-only, or unresolved per-cluster metric state
