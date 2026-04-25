# Azure Rule Spec - `azure.ml.online_endpoint.idle`

## 1. Rule Identity

- **Rule ID:** `azure.ml.online_endpoint.idle`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.MachineLearningServices/workspaces/onlineEndpoints`
- **Finding resource_type:** `azure.ml.online_endpoint`

---

## 2. Intent

Detect **Azure Machine Learning managed online endpoints that retain billable deployment baseline instances while `RequestsPerMinute` stays at zero** over a documented observation window.

This rule is deliberately **precision-first**. It is **not** a generic "quiet workspace" rule, **not** proof that deleting an endpoint is safe, and **not** proof of a specific monthly saving. It is a conservative review-candidate rule for managed online endpoints that appear to be continuously provisioned but unused.

---

## 3. Azure Documentation Grounding

### 3.1 Managed online endpoints incur compute and networking cost while deployments retain instances

Microsoft documents that managed online endpoints:

1. are the recommended Azure Machine Learning online endpoint type
2. use managed VM compute for deployments
3. charge for the VMs assigned to deployments, with no added managed-endpoint surcharge
4. can also incur networking-related charges

Sources:

- *Online endpoints for real-time inference*
- *View costs for managed online endpoints*
- *Managed online endpoint YAML reference*

URLs:

- https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-view-online-endpoints-costs?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/reference-yaml-deployment-managed-online?view=azureml-api-2

Rule consequence:

1. This rule should target **managed online endpoints** only.
2. The rule should require evidence that one or more managed deployments retain billable baseline instances.
3. The rule must **not** claim exact endpoint cost from management metadata alone.

### 3.2 Managed and Kubernetes online endpoints must not be conflated

Microsoft documents two online endpoint kinds:

- managed online endpoints
- Kubernetes online endpoints

Microsoft further documents that Kubernetes online endpoints use customer-managed compute, while managed online endpoints use Azure-managed compute.

Sources:

- *Online endpoints for real-time inference*
- *Online endpoints YAML reference*
- *ManagedOnlineEndpoint class*
- *KubernetesOnlineEndpoint class*

URLs:

- https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/reference-yaml-endpoint-online?view=azureml-api-2
- https://learn.microsoft.com/en-us/python/api/azure-ai-ml/azure.ai.ml.entities.managedonlineendpoint?view=azure-python
- https://learn.microsoft.com/en-us/python/api/azure-ai-ml/azure.ai.ml.entities.kubernetesonlineendpoint?view=azure-python

Rule consequence:

1. Kubernetes online endpoints are out of scope.
2. Managed scope should be established from documented endpoint/deployment surfaces only.
3. If managed-vs-kubernetes scope cannot be established reliably, skip rather than infer.

### 3.3 Endpoint and deployment control-plane fields expose the stable and billing-relevant surfaces

Microsoft documents online endpoint and deployment fields including:

- endpoint `location`
- endpoint `kind`
- endpoint `properties.provisioningState`
- endpoint `systemData.createdAt`
- deployment `properties.provisioningState`
- deployment type/class surfaces in SDK/REST when present
- deployment `properties.instanceType`
- deployment `properties.instanceCount`
- deployment scale settings

Sources:

- *Online Endpoints - List*
- *Online Endpoints - Get*
- *Online Deployments - List*
- *Online Deployments - Get*
- *ManagedOnlineDeployment class*
- *TargetUtilizationScaleSettings class*

URLs:

- https://learn.microsoft.com/en-us/rest/api/azureml/online-endpoints/list?view=rest-azureml-2025-06-01
- https://learn.microsoft.com/en-us/rest/api/azureml/online-endpoints/get?view=rest-azureml-2025-06-01
- https://learn.microsoft.com/en-us/rest/api/azureml/online-deployments/list?view=rest-azureml-2025-06-01
- https://learn.microsoft.com/en-us/rest/api/azureml/online-deployments/get?view=rest-azureml-2025-06-01
- https://learn.microsoft.com/en-us/python/api/azure-ai-ml/azure.ai.ml.entities.managedonlinedeployment?view=azure-python
- https://learn.microsoft.com/en-us/python/api/azure-ai-ml/azure.ai.ml.entities.targetutilizationscalesettings?view=azure-python

Rule consequence:

1. The rule should evaluate only stable endpoints and stable deployments: exact `provisioningState == "Succeeded"`.
2. Managed scope should be established primarily from documented endpoint kind/class surfaces; deployment type/class hints are reinforcing only when present.
3. The rule should require a known positive deployment baseline instance count from documented deployment surfaces before emitting.

### 3.4 Azure Monitor documents endpoint-scope request traffic via `RequestsPerMinute`

Microsoft documents that `Microsoft.MachineLearningServices/workspaces/onlineEndpoints` exposes endpoint-scope traffic metrics including:

- `RequestsPerMinute`
- `RequestLatency`
- `ConnectionsActive`
- `NetworkBytes`

Microsoft further documents:

- `RequestsPerMinute` is the endpoint request-count signal
- `RequestsPerMinute` uses `Average`
- `RequestsPerMinute` supports `PT1M`
- endpoint metrics are scoped to the online endpoint resource

Sources:

- *Supported metrics for Microsoft.MachineLearningServices/workspaces/onlineEndpoints*
- *Monitor online endpoints*
- *Autoscale online endpoints*

URLs:

- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-machinelearningservices-workspaces-onlineendpoints-metrics
- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-monitor-online-endpoints?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-autoscale-endpoints?view=azureml-api-2

Rule consequence:

1. `RequestsPerMinute` is the canonical idle-traffic signal for this rule.
2. The metric query should target the **endpoint ARM resource id**, not the workspace.
3. Workspace-level request metrics and undocumented fallback metrics such as `RequestCount` or `ModelEndpointRequests` must not be used to prove endpoint idleness.
4. If the documented endpoint metric cannot be resolved reliably, the endpoint must be skipped.

### 3.5 Managed online endpoint traffic routing can include multiple deployments and mirror traffic

Microsoft documents endpoint traffic routing and mirrored traffic across deployments for online endpoints.

Sources:

- *Safely roll out online endpoints*
- *Online endpoints YAML reference*

URLs:

- https://learn.microsoft.com/en-us/azure/machine-learning/how-to-safely-rollout-online-endpoints?view=azureml-api-2
- https://learn.microsoft.com/en-us/azure/machine-learning/reference-yaml-endpoint-online?view=azureml-api-2

Rule consequence:

1. A zero-traffic finding must be based on the endpoint-level request metric across the whole endpoint.
2. The rule must not infer idleness from deployment routing percentages alone.
3. Multiple deployments under one endpoint do not weaken the endpoint-scope request metric when that metric resolves reliably.

---

## 4. Detection Goal

Emit only when the endpoint passes every rule in section **8**. Section **8** is the single source of truth for decisioning; sections **7** and **9** define how inputs are normalized and evaluated.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the endpoint is safe
- that no future rollout, failover, or standby use is planned
- that autoscale policies outside the inspected deployment surfaces will never change live instance count
- that no deployment-specific operational need exists
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| AML workspace inventory | enumerate candidate workspaces |
| online endpoint list/get for each workspace | determine endpoint identity, region, kind, provisioning state, and age |
| online deployment list/get for each endpoint | determine managed-vs-kubernetes scope, deployment stability, instance type, and baseline instance counts |
| Azure Monitor metrics on the endpoint ARM id | determine endpoint request traffic using documented endpoint-scope metrics |

### 6.2 Authentication / permissions

Minimum permissions:

- `Microsoft.MachineLearningServices/workspaces/read`
- `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read`
- `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read`
- `Microsoft.Insights/metrics/read`

No secret, key, request-payload, or model retrieval is required for this rule.

### 6.3 Idle window

- Configurable parameter: `idle_days`
- Default: `7`
- Minimum effective value: `1`

Reason:

- Managed online endpoints are low-latency serving infrastructure and can legitimately be quiet for short periods.
- A one-week default window is conservative enough to avoid flagging brief pauses while still surfacing continuously provisioned endpoints with no observed request traffic.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Resolve from documented endpoint resource location surfaces only. If unresolved, skip. Lowercase before comparison, then compare by exact lowercase equality only. |
| `managed_scope` | Treat the endpoint as managed only by the exact rules in section `9.1`. |
| `managed_scope_source` | Observability field derived from section `9.1`. Allowed values: `endpoint`, `deployment`, or `none`. It records which surface established managed scope; it does not add new decision logic beyond section `9.1`. |
| `provisioning_state` | Resolve from documented SDK/raw surfaces and compare case-sensitively to exact `"Succeeded"`. |
| `created_at` | Parse as a UTC instant from documented `systemData.createdAt` or equivalent SDK projection. If the chosen field is present but unparsable, skip. |
| `deployment_provisioning_state` | Resolve from documented deployment surfaces and compare case-sensitively to exact `"Succeeded"`. |
| `baseline_instance_count` | Resolve in this exact order from documented deployment configuration surfaces: `scale_settings.min_instances`, then `instance_count`, otherwise unknown. Only a known integer `> 0` is billing-relevant for this rule. `0`, invalid, or unresolvable values are not enough to emit. |
| `instance_type` | Preserve raw documented value. Use only for descriptive details and GPU risk classification; it must **not** determine managed scope or billing relevance. GPU classification should use uppercase normalization and exact prefix matching on `STANDARD_NC`, `STANDARD_ND`, and `STANDARD_NV`. `null` / absent `instance_type` is non-GPU for risk purposes. |
| `requests_per_minute_zero` | `True` only when section `9.5` evaluates the endpoint metric result to `ZERO`. |
| `tags` | `endpoint.tags or {}` - never `None` in output. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `endpoint.id` absent, `None`, or empty | Skip |
| 8.2 | `endpoint.name` absent, `None`, or empty | Skip |
| 8.3 | `workspace.name` absent, `None`, or empty | Skip |
| 8.4 | Region filter set and normalized endpoint location does not match | Skip |
| 8.5 | `managed_scope` is not established per section `9.1` | Skip |
| 8.6 | Endpoint `provisioning_state` does not resolve to `"Succeeded"` | Skip |
| 8.7 | Endpoint `created_at` is absent, invalid, in the future, or younger than the effective `idle_days` window | Skip |
| 8.8 | Deployment inventory cannot be resolved reliably | Skip |
| 8.9 | No stable deployment under the managed endpoint resolves to a known positive baseline instance count | Skip |
| 8.10 | Endpoint traffic metric result is not `ZERO` per section `9.5` | Skip |
| 8.11 | All required signals resolve and the managed endpoint has `RequestsPerMinute == 0` across the effective window while retaining positive baseline deployment instances | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Scope and stable-endpoint contract

Required behavior:

1. Resolve endpoint-level scope only from documented endpoint class/type or kind surfaces.
2. Resolve deployment-level scope hints only from explicit documented deployment class/type surfaces on stable deployments; never infer them from unrelated fields.
3. Section `9.1` is the single source of truth for managed-scope resolution.
4. Endpoint-level explicit signals always override deployment-level signals for managed-scope determination.
5. Scope priority is strict:
   1. endpoint-level explicit Kubernetes -> out of scope
   2. endpoint-level explicit managed -> in scope unless any stable deployment explicitly identifies Kubernetes
   3. if endpoint-level scope is absent, stable-deployment explicit managed -> in scope only when no stable deployment explicitly identifies Kubernetes
   4. otherwise out of scope
6. If explicit managed and explicit Kubernetes signals both appear across the allowed endpoint/deployment scope surfaces, skip.
7. If no explicit managed signal can be established from the allowed surfaces, skip.
8. Set `managed_scope_source = "endpoint"` when endpoint-level explicit managed evidence establishes scope.
9. Set `managed_scope_source = "deployment"` when stable-deployment explicit managed evidence establishes scope.
10. Set `managed_scope_source = "none"` when managed scope is not established.
11. Endpoint `provisioning_state` must resolve to exact `"Succeeded"`.

### 9.2 Location and age contract

Required behavior:

1. Use the endpoint resource's documented location, not the workspace location, for filtering and reporting.
2. Endpoint `created_at` must resolve to a known UTC timestamp.
3. `created_at` in the future must skip.
4. Endpoint age must be at least the effective `idle_days` window.

### 9.3 Billing relevance gate (configured capacity proxy only)

Required behavior:

1. Deployment inventory must resolve successfully for the endpoint.
2. Only deployments with exact `deployment_provisioning_state == "Succeeded"` may contribute to baseline-instance evidence.
3. A deployment may contribute to baseline-instance evidence only when it is under an endpoint already established as managed per section `9.1`.
4. For each remaining candidate deployment, resolve `baseline_instance_count` in this exact order: `scale_settings.min_instances`, then `instance_count`, otherwise unknown.
5. A deployment is billing-relevant only when its resolved `baseline_instance_count` is a known integer greater than zero.
6. An endpoint is billing-relevant only when at least one deployment is billing-relevant.
7. Endpoints whose deployments all clearly resolve to zero baseline instances must skip.
8. If deployment configuration is too incomplete to establish any billing-relevant deployment reliably, skip.

Rationale:

This rule is about endpoints that appear to retain billable baseline serving instances while unused. `baseline_instance_count` is treated as configured retained-capacity intent, not proof of live runtime capacity at every instant, and not as a proxy for deployment existence by itself. If the deployment surfaces do not clearly show positive retained baseline instances, the rule must fail closed. This intentionally skips scale-to-zero, autoscale-min-zero, or otherwise unproven retained-capacity cases, accepting false negatives to avoid over-claiming idle cost. This rule does not attempt to model transient autoscale cost when a positive retained baseline cannot be proven from the required control-plane surfaces.

### 9.4 Instance-type and GPU contract

Required behavior:

1. Preserve the first available documented `instance_type` for details, but consider all billing-relevant deployments when classifying GPU presence.
2. GPU classification uses uppercase-normalized `instance_type` and exact prefix matching on `STANDARD_NC`, `STANDARD_ND`, and `STANDARD_NV`.
3. Unknown or absent `instance_type` must not be treated as GPU by default.
4. `instance_type` must not be used to determine managed scope or billing relevance.

### 9.5 Endpoint traffic-metric contract

Required metric:

1. `RequestsPerMinute` with `Average`

Definitions:

- **effective idle window**: `max(idle_days, 1)`
- **now_utc**: the evaluation time captured as a UTC timestamp
- **metric_end_utc**: `floor_to_minute(now_utc - 5 minutes)`
- **window_start_utc**: `metric_end_utc - effective idle window`
- **UTC-normalized timestamp**: a parsed timestamp converted to UTC before any comparison
- **usable datapoint**: a datapoint with a parseable UTC timestamp inside the requested window and a numeric `Average` value
- **acceptable coverage**: at least 80% of complete minute buckets in `[window_start_utc, metric_end_utc)` have usable datapoints
- **idle_duration**: `floor((metric_end_utc - window_start_utc).total_seconds() / 86400)`
- **idle_since_days**: derived constant equal to the configured effective idle window when the metric result is `ZERO`; it is not an observational duration estimate beyond that accepted window
- **metric_result**: one of `ACTIVE`, `ZERO`, or `UNKNOWN`

Required behavior:

1. Query the documented `RequestsPerMinute` metric on the **endpoint ARM resource id**.
2. Use the documented `PT1M` granularity and `Average` aggregation.
3. Evaluate only complete minute buckets in `[window_start_utc, metric_end_utc)`.
4. This is a rolling UTC-aligned window, not a calendar-day window.
5. Do **not** use workspace-scope metric fallback.
6. Do **not** use undocumented or legacy request metrics such as `RequestCount` or `ModelEndpointRequests` to prove idleness.
7. If any usable bucket has `Average > 0`, then `metric_result = ACTIVE`.
8. If the query fails, the metric is missing, the response shape is unusable, no usable datapoints exist, or coverage is below threshold, then `metric_result = UNKNOWN`.
9. Treat the metric as `ZERO` only when coverage is acceptable and every usable bucket has `Average == 0`.
10. When `metric_result = ZERO`, set `idle_since_days` to the effective idle window represented by `[window_start_utc, metric_end_utc)`.
11. No secondary metric may substitute for `RequestsPerMinute`; related metrics such as latency or connections are observability-only and must not override the canonical traffic result.
12. Missing buckets, late-arriving datapoints, and sparse telemetry affect only coverage calculation; if resulting coverage is below threshold, `metric_result = UNKNOWN`.

Rationale:

This metric contract is intentionally conservative. Azure Monitor ingestion delay or sparse minute coverage may increase skips, but the rule still prefers a documented zero-request result over unsupported metric fallbacks. The single-metric dependency is intentional because the Azure documentation grounds request absence most directly in `RequestsPerMinute`.

### 9.6 Risk and confidence contract

Risk:

1. `HIGH` when any billing-relevant deployment is GPU-classified
2. `MEDIUM` otherwise

Confidence:

1. `HIGH` when all required endpoint and deployment signals resolve and metric coverage is at least 95% for a `ZERO` result
2. `MEDIUM` when all required endpoint and deployment signals resolve and metric coverage is at least 80% but below 95% for a `ZERO` result

Rationale:

This rule should fail closed rather than emit from unknown traffic evidence, but confidence still reflects metric quality within the acceptable coverage band. Confidence does not override the `ZERO` requirement; it refines finding strength only after emit conditions are met.

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** use flat hardcoded VM price tables.
2. Do **not** claim exact monthly savings from management metadata alone.
3. State only that managed deployments retaining positive instance baselines continue to incur compute cost while provisioned.
4. If relevant, note that networking-related charges can also apply.

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.ml.online_endpoint.idle"` |
| `resource_type` | `"azure.ml.online_endpoint"` |
| `resource_id` | original ARM id from `endpoint.id` |
| `region` | normalized endpoint location |
| `confidence` | derived from section `9.6` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required evidence

`signals_used` must clearly disclose:

1. managed scope was established from the allowed endpoint/deployment scope surfaces
2. endpoint provisioning state is `"Succeeded"`
3. endpoint age is at least the configured idle window
4. one or more deployments under the managed endpoint retain positive configured baseline instances
5. the documented `RequestsPerMinute` metric result is `ZERO` across the rolling UTC window defined in section `9.5`

`signals_not_checked` should include remaining blind spots such as:

1. future traffic intent or standby usage
2. autoscale policies or live instance state not fully visible from the inspected deployment configuration surfaces
3. exact endpoint/deployment cost after discounts, reservations, or special commercial terms
4. business-owner intent or rollout plans

### 11.3 Required details

Details should include at least:

- `endpoint_name`
- `workspace_name`
- `resource_group`
- `subscription_id`
- `location`
- `endpoint_kind` (if present)
- `managed_scope_source`
- `endpoint_provisioning_state`
- `created_at`
- `billing_relevant_deployment_count`
- `deployment_count`
- `instance_type`
- `is_gpu`
- `baseline_instance_count_total`
- `idle_days_threshold`
- `idle_since_days`
- `metric_name`
- `metric_aggregation`
- `metric_coverage_ratio`
- `tags`

`managed_scope_source`, `deployment_count`, `instance_type`, `is_gpu`, and `metric_coverage_ratio` are observability fields for reviewer context. They do not add gating logic beyond sections `8` and `9`.

---

## 12. Failure Behavior

- If subscription-wide workspace inventory fails, let the exception propagate
- If per-workspace endpoint listing fails, skip that workspace
- If per-endpoint deployment listing or metric retrieval fails, skip that endpoint
- If endpoint or deployment records are malformed or missing required fields, skip that endpoint
- Do not emit on partial, workspace-level, legacy-metric, or age-only traffic evidence
