# Azure Rule Spec - `azure.openai.provisioned_deployment.idle`

## 1. Rule Identity

- **Rule ID:** `azure.openai.provisioned_deployment.idle`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.CognitiveServices/accounts/deployments`
- **Finding resource_type:** `azure.openai.provisioned_deployment`

---

## 2. Intent

Detect **Azure OpenAI provisioned deployments that retain billable PTU capacity while showing no observed Azure OpenAI request traffic** over a conservative documented observation window.

This rule is deliberately **precision-first**. It is **not** proof that deleting a deployment is safe, **not** proof that a reservation can be canceled without consequence, and **not** proof of an exact monthly saving. It is a conservative review-candidate rule for provisioned Azure OpenAI deployments that appear to be continuously billed but unused.

---

## 3. Azure Documentation Grounding

### 3.1 Provisioned throughput bills on deployed PTUs whether used or not

Microsoft documents that provisioned throughput:

1. allocates model processing capacity once deployed
2. is sized in Provisioned Throughput Units (PTUs)
3. is billed hourly based on the number of deployed PTUs
4. can receive substantial discount through Azure reservations
5. continues to hold capacity while the deployment exists

Microsoft also documents that:

1. deleting a deployment avoids unwanted deployment charges
2. deleting the parent resource before deleting or purging deployments can allow charges to continue
3. reservations and deployments are loosely coupled, so deleting a deployment does not cancel or change a PTU reservation

Sources:

- *What is provisioned throughput for Foundry Models?*
- *Provisioned throughput unit (PTU) costs and billing*
- *Get started with provisioned deployments in Microsoft Foundry*

URLs:

- https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/provisioned-throughput
- https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/provisioned-throughput-onboarding
- https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/provisioned-get-started

Rule consequence:

1. The rule should evaluate only deployments that clearly retain provisioned PTU capacity.
2. The rule may state that deployed PTUs continue to incur hourly cost while the deployment exists.
3. The rule must **not** hardcode a fixed monthly PTU price or claim exact savings from management metadata alone.
4. The rule must not assume idle findings are immediately avoidable cost because reservation coverage and deleted-resource purge state are separate concerns.

### 3.2 Provisioned deployment scope is established from documented deployment SKU and model surfaces

Microsoft documents that provisioned deployment types map to these `sku-name` values:

- `ProvisionedManaged`
- `GlobalProvisionedManaged`
- `DataZoneProvisionedManaged`

Microsoft also documents deployment-management surfaces under `Microsoft.CognitiveServices/accounts/deployments`, including:

- deployment `id`
- deployment `name`
- deployment `sku.name`
- deployment `sku.capacity`
- deployment `properties.model.format`
- deployment `properties.model.name`
- deployment `properties.model.version`
- deployment `properties.provisioningState`
- deployment `systemData.createdAt`

Account-management surfaces include:

- account `id`
- account `name`
- account `location`
- account `properties.provisioningState`

Sources:

- *What is provisioned throughput for Foundry Models?*
- *Get started with provisioned deployments in Microsoft Foundry*
- *Deployments - List (Azure AI Services REST API)*
- *Accounts - List (Azure AI Services REST API)*

URLs:

- https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/provisioned-throughput
- https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/provisioned-get-started
- https://learn.microsoft.com/en-us/rest/api/aiservices/accountmanagement/deployments/list?view=rest-aiservices-accountmanagement-2024-10-01
- https://learn.microsoft.com/en-us/rest/api/aiservices/accountmanagement/accounts/list?view=rest-aiservices-accountmanagement-2024-10-01

Rule consequence:

1. Provisioned scope must be established from the documented deployment SKU only.
2. OpenAI scope must be established from the documented deployment model format, not inferred from names or tags.
3. The rule should evaluate only stable deployments: exact `properties.provisioningState == "Succeeded"`.
4. A deployment is billing-relevant only when `sku.capacity` resolves to a known integer greater than zero.
5. Region filtering and reporting should use the documented **parent account location**, because the deployment list surface does not document a deployment-level location in the sample contract.

### 3.3 Azure Monitor documents the canonical request metric and warns against legacy Cognitive Services metrics

Microsoft documents that `Microsoft.CognitiveServices/accounts` exposes Azure OpenAI metrics including:

- `AzureOpenAIRequests`
- `ActiveTokens`
- `ProcessedPromptTokens`
- `GeneratedTokens`
- `AzureOpenAIProvisionedManagedUtilizationV2`

Microsoft further documents that:

1. `AzureOpenAIRequests` is the metric for number of Azure OpenAI API calls over time
2. `AzureOpenAIRequests` uses `Total (Sum)`
3. `AzureOpenAIRequests` supports `PT1M`
4. `AzureOpenAIRequests` supports dimensions including `ModelDeploymentName`, `StatusCode`, `IsSpillover`, `ServiceTierRequest`, and `ServiceTierResponse`
5. legacy **Cognitive Services - HTTP Requests** metrics such as `TotalCalls`, `SuccessfulCalls`, and `ServerErrors` should **not** be used for Azure OpenAI
6. `Provisioned-managed Utilization V2` is a utilization metric, not a request-count metric

Sources:

- *Monitoring data reference for Azure OpenAI*
- *Supported metrics - Microsoft.CognitiveServices/accounts - Azure Monitor*

URLs:

- https://learn.microsoft.com/en-us/azure/foundry/openai/monitor-openai-reference
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-cognitiveservices-accounts-metrics

Rule consequence:

1. `AzureOpenAIRequests` is the canonical idle-traffic signal for this rule.
2. The metric query must target the **parent account ARM resource id**, not the deployment ARM id.
3. The rule must scope the metric to the deployment using the documented `ModelDeploymentName` dimension with exact deployment-name equality.
4. After that deployment filter is applied, the rule must evaluate activity across **all** remaining metric dimensions together; it must not require separate per-status, per-spillover, or per-service-tier zero proofs.
5. The rule must treat **any** positive request count as activity, regardless of `StatusCode`, spillover status, or service-tier response.
6. Token metrics, utilization metrics, and legacy Cognitive Services request metrics are observability-only for this rule and must not substitute for `AzureOpenAIRequests`.

### 3.4 Provisioned deployments can spill over or return 429 under saturation, but those still represent request activity

Microsoft documents that:

1. provisioned deployments return HTTP `429` when utilization is at or above capacity
2. `AzureOpenAIRequests` can be broken down by `StatusCode`
3. `AzureOpenAIRequests` can be broken down by `IsSpillover`

Sources:

- *What is provisioned throughput for Foundry Models?*
- *Monitoring data reference for Azure OpenAI*

URLs:

- https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/provisioned-throughput
- https://learn.microsoft.com/en-us/azure/foundry/openai/monitor-openai-reference

Rule consequence:

1. The rule must treat request attempts that result in 429 or other statuses as activity when `AzureOpenAIRequests` is positive.
2. The rule must not ignore spillover-tagged request traffic when evaluating idleness.
3. The rule should aggregate over all request statuses and spillover states rather than filtering them away.

---

## 4. Detection Goal

Emit only when the deployment passes every rule in section **8**. Section **8** is the single source of truth for decisioning; sections **7** and **9** define normalization and evaluation contracts.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the deployment can be deleted safely
- that no failover, spillover, or standby purpose exists
- that no reservation or commitment discount is attached to the deployment
- that no future workload will return to this deployment
- that utilization, latency, or token metrics are healthy or unhealthy
- that a specific monthly dollar saving exists

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| Cognitive Services account inventory | enumerate candidate parent accounts and obtain account identity, location, and stable account state |
| account deployment list/get | determine deployment identity, model format, model name/version, SKU, PTU capacity, provisioning state, and creation time |
| Azure Monitor metrics on the parent account ARM id | determine deployment-scoped Azure OpenAI request activity via `ModelDeploymentName` |

### 6.2 Authentication / permissions

Minimum permissions:

- `Microsoft.CognitiveServices/accounts/read`
- `Microsoft.CognitiveServices/accounts/deployments/read`
- `Microsoft.Insights/metrics/read`

No key, prompt, completion payload, token log, or data-plane inference call is required for this rule.

### 6.3 Idle window

- Configurable parameter: `idle_days`
- Default: `7`
- Minimum effective value: `1`

Reason:

- Provisioned deployments are designed for stable production throughput and are billed whether used or not once deployed.
- A one-week default is conservative enough to avoid flagging brief pauses while still surfacing deployments that appear continuously billed with no observed request traffic.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `account_location` | Resolve from documented parent account `location`. If unresolved, skip. Lowercase before comparison, then compare by exact lowercase equality only. Do not remove spaces, hyphens, or digits. |
| `account_provisioning_state` | Resolve from documented account `properties.provisioningState` and compare case-sensitively to exact `"Succeeded"`. |
| `deployment_provisioning_state` | Resolve from documented deployment `properties.provisioningState` and compare case-sensitively to exact `"Succeeded"`. |
| `model_format` | Resolve from documented deployment `properties.model.format` and compare case-sensitively to exact `"OpenAI"`. |
| `sku_name` | Resolve from documented deployment `sku.name`. The only in-scope values are exact `ProvisionedManaged`, `GlobalProvisionedManaged`, and `DataZoneProvisionedManaged`. |
| `ptu_capacity` | Resolve from documented deployment `sku.capacity` as an integer. Only a known integer `> 0` is billing-relevant for this rule. |
| `created_at` | Parse as a UTC instant from documented deployment `systemData.createdAt` or equivalent SDK projection. If the chosen field is present but unparsable, skip. |
| `age_days` | `floor((now_utc - created_at_utc) / 86400 seconds)` using the normalized `created_at`. |
| `account_kind` | Preserve the raw documented account kind if present for reviewer context only; it must not establish OpenAI scope by itself. |
| `model_name` | Preserve raw documented deployment model name. |
| `model_version` | Preserve raw documented deployment model version. |
| `requests_metric_zero` | `True` only when section `9.3` evaluates the canonical metric result to `ZERO`. |
| `tags` | Prefer deployment tags when present; otherwise `{}`. Do not emit `None`. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | parent account `id` absent, `None`, or empty | Skip |
| 8.2 | parent account `name` absent, `None`, or empty | Skip |
| 8.3 | deployment `id` absent, `None`, or empty | Skip |
| 8.4 | deployment `name` absent, `None`, or empty | Skip |
| 8.5 | parent account location is unresolved | Skip |
| 8.6 | region filter set and normalized account location does not match | Skip |
| 8.7 | parent account provisioning state does not resolve to exact `"Succeeded"` | Skip |
| 8.8 | deployment provisioning state does not resolve to exact `"Succeeded"` | Skip |
| 8.9 | deployment model format does not resolve to exact `"OpenAI"` | Skip |
| 8.10 | deployment SKU name is not one of the documented provisioned-managed SKU names | Skip |
| 8.11 | PTU capacity is absent, invalid, zero, or negative | Skip |
| 8.12 | `created_at` is absent, invalid, in the future, or younger than the effective idle window | Skip |
| 8.13 | deployment-scoped `AzureOpenAIRequests` metric result is not `ZERO` per section `9.3` | Skip |
| 8.14 | all required signals resolve and the provisioned OpenAI deployment shows zero observed request traffic across the effective window while retaining positive PTU capacity | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Scope and stable-state contract

Required behavior:

1. Account inventory must come from documented Cognitive Services account inventory surfaces.
2. Evaluate only parent accounts whose documented `account_provisioning_state` resolves to exact `"Succeeded"`.
3. Deployment inventory must come from documented account deployment list/get surfaces.
4. A deployment is in scope for this rule only when its documented `model_format` resolves to exact `"OpenAI"`.
5. A deployment is provisioned for this rule only when `sku_name` resolves to one of:
   1. `ProvisionedManaged`
   2. `GlobalProvisionedManaged`
   3. `DataZoneProvisionedManaged`
6. A deployment is stable only when `deployment_provisioning_state == "Succeeded"`.
7. A deployment is billing-relevant only when `ptu_capacity` is a known integer greater than zero.
8. `account_kind` may be preserved in details, but it must not override or replace the deployment-level `model_format` gate.

### 9.2 Location and age contract

Required behavior:

1. Use the parent account location for region filtering and finding region.
2. Deployment `created_at` must resolve to a known UTC timestamp.
3. `created_at` in the future must skip.
4. Deployment age must be at least the effective `idle_days` window.
5. No weaker age-only fallback may substitute for missing or unknown traffic evidence.

### 9.3 Deployment traffic-metric contract

Required metric:

1. `AzureOpenAIRequests` with `Total`

Definitions:

- **effective idle window**: `max(idle_days, 1)`
- **now_utc**: the evaluation time captured as a UTC timestamp
- **metric_end_utc**: `floor_to_minute(now_utc - 5 minutes)`
- **window_start_utc**: `metric_end_utc - effective idle window`
- **usable datapoint**: a datapoint with a parseable UTC timestamp inside the requested window and a numeric `Total` value after the deployment filter from this section is applied
- **bucketed datapoint**: a usable datapoint assigned to its complete UTC minute bucket by flooring its timestamp to the minute after deployment scoping
- **usable minute bucket**: a unique complete UTC minute in `[window_start_utc, metric_end_utc)` for which at least one bucketed datapoint exists after deployment scoping
- **bucket_total**: the sum of `Total` across all bucketed datapoints that land in the same usable minute bucket after deployment scoping and bucket assignment
- **acceptable coverage**: at least 80% of complete minute buckets in `[window_start_utc, metric_end_utc)` are represented by usable minute buckets
- **metric_result**: one of `ACTIVE`, `ZERO`, or `UNKNOWN`
- **idle_since_days**: derived constant equal to the configured effective idle window when `metric_result = ZERO`; it is not an observational duration claim beyond that accepted window

Required behavior:

1. Query the documented `AzureOpenAIRequests` metric on the **parent account ARM resource id**.
2. Scope the query to the deployment using the documented `ModelDeploymentName` dimension with exact deployment-name equality.
3. Use the documented `PT1M` granularity and `Total` aggregation.
4. Evaluate only complete minute buckets in `[window_start_utc, metric_end_utc)`.
5. This is a rolling UTC-aligned window, not a calendar-day window.
6. The deterministic evaluation pipeline is:
   1. apply exact `ModelDeploymentName` deployment scoping
   2. enumerate every datapoint from every remaining metric series after that deployment scoping, without any additional pre-aggregation by status, spillover state, service tier, or other remaining dimensions
   3. discard non-usable datapoints
   4. assign each remaining datapoint to its complete UTC minute bucket
   5. sum `Total` within each minute bucket across all remaining dimensions to produce the final `bucket_total` for that minute
   6. identify unique usable minute buckets from those finalized per-minute buckets
   7. compute coverage from the set of unique usable minute buckets produced after step 5
7. After deployment scoping, aggregate activity across all remaining dimensions only by summing `Total` into final per-minute `bucket_total` values; do **not** require separate per-status, per-spillover, or per-service-tier zero proofs.
8. Coverage calculation must be based on the unique usable minute buckets that remain after final per-minute `bucket_total` values are computed, not on raw datapoint count, so duplicate points or multiple remaining dimension series cannot overstate completeness.
9. Do **not** filter away request statuses, spillover states, or service-tier values when determining activity; any positive `AzureOpenAIRequests` count is activity.
10. If any usable minute bucket has `bucket_total > 0`, then `metric_result = ACTIVE`.
11. If the query fails, the metric is missing, the response shape is unusable, no usable datapoints exist, or coverage is below threshold, then `metric_result = UNKNOWN`.
12. Treat the metric as `ZERO` only when coverage is acceptable and every usable minute bucket has `bucket_total == 0`.
13. When `metric_result = ZERO`, set `idle_since_days` to the effective idle window represented by `[window_start_utc, metric_end_utc)`.
14. Do **not** fall back to `ProcessedPromptTokens`, `GeneratedTokens`, `TokenTransaction`, `ActiveTokens`, `AzureOpenAIProvisionedManagedUtilizationV2`, deprecated `AzureOpenAIProvisionedManagedUtilization`, or legacy Cognitive Services HTTP-request metrics.
15. Do **not** emit from age-only, utilization-only, or token-only evidence.
16. Missing buckets, late-arriving datapoints, and sparse telemetry affect only coverage calculation; if resulting coverage is below threshold, `metric_result = UNKNOWN`.

Rationale:

This metric contract is intentionally conservative. Microsoft documents `AzureOpenAIRequests` as the canonical Azure OpenAI request-count metric and explicitly warns against using legacy Cognitive Services request metrics for Azure OpenAI. Azure Monitor documentation does not define missing datapoints as zero traffic, so the rule must fail closed on weak or sparse telemetry rather than substitute token or utilization metrics.

### 9.4 Risk and confidence contract

Risk:

1. `HIGH` for every emitted finding

Confidence:

1. `HIGH` when all required signals resolve and metric coverage is at least 95% for a `ZERO` result
2. `MEDIUM` when all required signals resolve and metric coverage is at least 80% but below 95% for a `ZERO` result

Rationale:

Provisioned deployments with known positive PTU capacity are inherently meaningful cost candidates because they are billed on deployed PTUs while active capacity exists. Confidence reflects telemetry quality only after all emit conditions are satisfied. This rule should never emit with `LOW` confidence.

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** hardcode a fixed PTU monthly estimate such as `$1,460/PTU/month`.
2. Do **not** infer exact savings from `sku.capacity` alone.
3. State only that deployed PTUs incur hourly billing while the deployment exists.
4. If relevant, note that reservation discounts, reservation coverage, and deleted-resource purge state can change effective avoidable cost.

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.openai.provisioned_deployment.idle"` |
| `resource_type` | `"azure.openai.provisioned_deployment"` |
| `resource_id` | original ARM id from deployment `id` |
| `region` | normalized parent account location |
| `confidence` | derived from section `9.4` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required evidence

`signals_used` must clearly disclose:

1. the deployment is an OpenAI deployment with a documented provisioned-managed SKU
2. parent account and deployment provisioning states are `"Succeeded"`
3. the deployment age is at least the configured idle window
4. the deployment retains a known positive PTU capacity
5. the documented `AzureOpenAIRequests` metric result is `ZERO` across the rolling UTC window defined in section `9.3`

`signals_not_checked` should include remaining blind spots such as:

1. business-owner intent or planned future traffic
2. spillover/failover policy intent beyond observed request activity
3. reservation coverage, reservation cancellation implications, or other commercial commitments
4. client-side retries or other application semantics not visible from the inspected management and Azure Monitor surfaces

### 11.3 Required details

Details should include at least:

- `account_name`
- `resource_group`
- `subscription_id`
- `account_location`
- `account_kind` (if present)
- `deployment_name`
- `deployment_provisioning_state`
- `sku_name`
- `ptu_capacity`
- `model_format`
- `model_name`
- `model_version`
- `created_at`
- `age_days`
- `idle_days_threshold`
- `idle_since_days`
- `metric_name`
- `metric_aggregation`
- `metric_coverage_ratio`
- `tags`

`account_kind`, `model_name`, `model_version`, and `metric_coverage_ratio` are reviewer-context fields only. They do not add gating logic beyond sections `8` and `9`.

---

## 12. Failure Behavior

- If subscription-wide account inventory fails, let the exception propagate
- If per-account deployment listing fails, skip that account
- If per-deployment metric retrieval fails or produces unusable telemetry, skip that deployment
- If account or deployment records are malformed or missing required fields, skip that deployment
- Do not emit on token-only, utilization-only, legacy-metric, account-total-only, or age-only evidence
