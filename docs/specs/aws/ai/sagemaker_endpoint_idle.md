# aws.sagemaker.endpoint.idle — Canonical Rule Specification

## 1. Intent

Detect SageMaker inference endpoints that are currently `InService`, still have billable
compute allocated, and show no observed `InvokeEndpoint` request activity for the configured
lookback window, so they can be reviewed as cleanup candidates.

This is a **read-only review-candidate rule**. It is not a delete-safe rule.

---

## 2. AWS API Grounding

Based on official SageMaker, SageMaker Runtime, Serverless Inference, Asynchronous Inference,
and CloudWatch documentation.

### Key facts

1. `ListEndpoints` is the canonical inventory API for SageMaker endpoints, supports pagination,
   and supports `StatusEquals`.
2. `EndpointSummary` includes `EndpointArn`, `EndpointName`, `EndpointStatus`, `CreationTime`,
   and `LastModifiedTime`.
3. `DescribeEndpoint` returns endpoint runtime state including `EndpointStatus`,
   `EndpointConfigName`, `ProductionVariants`, `AsyncInferenceConfig`, and `MetricsConfig`.
4. `ProductionVariantSummary` exposes `VariantName`, `CurrentInstanceCount`,
   `CurrentServerlessConfig`, `ManagedInstanceScaling`, and related runtime fields.
5. `DescribeEndpointConfig` returns configuration state including `ProductionVariants`,
   `ServerlessConfig`, `InstanceType`, `MetricsConfig`, and `AsyncInferenceConfig`.
6. SageMaker endpoint invocation metrics are published in namespace `AWS/SageMaker` and are
   documented as request metrics from calls to `InvokeEndpoint`.
7. The documented invocation-metric dimension for endpoint variants is
   `EndpointName, VariantName`.
8. CloudWatch requires callers to specify the same dimensions that were used when a metric was
   published; otherwise that metric series cannot be retrieved.
9. `Invocations` is documented as the number of `InvokeEndpoint` requests sent to a model
   endpoint, and `Sum` is the statistic for total requests.
10. Serverless Inference on-demand scales the endpoint down to `0` when there are no requests.
11. Serverless Inference with `ProvisionedConcurrency` keeps capacity warm and creates baseline
    cost while provisioned, even when the endpoint is idle.
12. The presence of `AsyncInferenceConfig` means the endpoint is intended to receive
    asynchronous invocations via `InvokeEndpointAsync`.
13. CloudWatch `GetMetricStatistics` is subject to period-retention rules, a maximum of 1,440
    datapoints per call, inclusive `StartTime`, and exclusive `EndTime`.

### Implications

- Inventory should begin from `ListEndpoints(StatusEquals="InService")`.
- The endpoint age gate can be grounded on documented summary timestamps without extra API calls.
- This rule can only make a canonical traffic claim for `InvokeEndpoint` traffic, not
  `InvokeEndpointAsync`.
- `DescribeEndpointConfig.AsyncInferenceConfig` is the authoritative async-scope signal.
- Runtime `DescribeEndpoint.ProductionVariants` are the authoritative evaluated variants;
  `DescribeEndpointConfig.ProductionVariants` are enrichment only.
- Serverless on-demand endpoints with no provisioned concurrency are not continuous idle-cost
  candidates because SageMaker documents that they scale to zero.
- `MetricsConfig` is contextual only and is not required for canonical `Invocations`
  evaluation.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **Endpoint** — an item returned by `ListEndpoints`.
- **Production variant** — an evaluated runtime variant returned by
  `DescribeEndpoint.ProductionVariants`.
- **Billable compute** for this rule means at least one of:
  - `CurrentInstanceCount > 0` on an instance-backed production variant, or
  - current `ProvisionedConcurrency > 0` on a serverless production variant.
- **Idle** means no observed `InvokeEndpoint` request activity across all in-scope production
  variants during the observation window.
- `idle_days_threshold` — operator-configurable, default 14.
- `reference_time_utc = max(CreationTime, LastModifiedTime)`.
- `age_days = floor((now_utc - reference_time_utc) / 86400 seconds)`.
- `evaluation_window_start_utc = now_utc - idle_days_threshold × 86400 seconds`.
- `evaluation_window_end_utc = now_utc`.

### Explicit scope boundary

This rule applies only to **real-time SageMaker endpoints** whose activity can be evaluated
from `InvokeEndpoint` metrics.

Out of scope:

- endpoints with `AsyncInferenceConfig`
- endpoints with no currently billable compute
- non-`InService` endpoints

---

## 4. Canonical Rule Statement

An endpoint is eligible only when **all** of the following are true:

- stable endpoint identity exists
- endpoint status is `InService`
- `reference_time_utc` is valid and `age_days >= idle_days_threshold`
- the endpoint is not async (`DescribeEndpointConfig.AsyncInferenceConfig` absent)
- at least one production variant has billable compute allocated
- every evaluated production variant shows no observed `InvokeEndpoint` traffic in the full
  observation window

No additional predicate may be required for baseline eligibility, including CPU utilization,
GPU utilization, model latency, tags, VPC placement, explainer configuration, or data capture.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

### 5.1 Endpoint-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `EndpointArn` | skip item |
| `endpoint_arn` | `EndpointArn` | skip item |
| `endpoint_name` | `EndpointName` | skip item |
| `endpoint_status` | `EndpointStatus` | skip item |
| `creation_time_utc` | `CreationTime` (tz-aware UTC) | skip item |
| `last_modified_time_utc` | `LastModifiedTime` (tz-aware UTC) | skip item |
| `reference_time_utc` | later of `creation_time_utc` and `last_modified_time_utc` | skip item |
| `age_days` | floor((now − reference_time_utc) / 86400) | skip item |
| `endpoint_config_name` | `DescribeEndpoint.EndpointConfigName` | skip item |
| `is_async_endpoint` | `DescribeEndpointConfig.AsyncInferenceConfig` present | `false` |

Normalization requirements:

- Timestamps must be timezone-aware UTC before comparison.
- Future `reference_time_utc` values must skip the item.
- Empty strings must normalize to null, not meaningful values.

### 5.2 Variant-Level Fields

Runtime variants from `DescribeEndpoint.ProductionVariants` are the authoritative evaluation set.
`DescribeEndpointConfig.ProductionVariants` may be joined by `VariantName` for enrichment only.

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `variant_name` | `VariantName` | skip variant |
| `current_instance_count` | `DescribeEndpoint.ProductionVariants[].CurrentInstanceCount` | null |
| `current_serverless_provisioned_concurrency` | `DescribeEndpoint.ProductionVariants[].CurrentServerlessConfig.ProvisionedConcurrency` | null |
| `configured_serverless_provisioned_concurrency` | `DescribeEndpointConfig.ProductionVariants[].ServerlessConfig.ProvisionedConcurrency` | null |
| `instance_type` | `DescribeEndpointConfig.ProductionVariants[].InstanceType` | null |
| `managed_instance_scaling_present` | `DescribeEndpoint.ProductionVariants[].ManagedInstanceScaling` present | `false` |
| `is_serverless_variant` | `ServerlessConfig` present in endpoint config or current serverless config present in runtime state | `false` |
| `billable_compute_mode` | `"instance"`, `"serverless_provisioned"`, `"mixed"`, or `"none"` | skip variant if indeterminate |

Variant billing rules:

- Instance-backed variant: billable only when `current_instance_count > 0`.
- Serverless variant: billable when current `ProvisionedConcurrency > 0`.
- Configured `ProvisionedConcurrency` is contextual only and may be used as enrichment, not as
  the canonical billing driver.
- Variants with neither running instances nor provisioned concurrency are not billable for this
  rule and must not be evaluated as idle-cost candidates.
- Managed instance scaling is contextual only; this rule evaluates currently allocated compute,
  not future autoscaling floor or warm-capacity intent.

---

## 6. Activity Determination Contract

CloudWatch invocation metrics are the **sole trusted activity source** for this rule.

### 6.1 Required Metric

| Field | Value |
|---|---|
| Namespace | `AWS/SageMaker` |
| Metric | `Invocations` |
| Statistic | `Sum` |
| Dimensions | `EndpointName = endpoint_name`, `VariantName = variant_name` |

### 6.2 Dimension Rules

- The rule must query **per production variant**.
- Querying `EndpointName` alone is not canonical because SageMaker documents the variant
  dimension pair and CloudWatch requires exact published dimensions.
- No undocumented fallback dimension set may be used for correctness.

### 6.3 Period Rules

Metric evaluation must use a sub-window period and sum the returned datapoints; it must **not**
use a single full-window bucket such as `idle_days_threshold × 86400`.

The selected `Period` must:

1. satisfy CloudWatch retention rules for the requested lookback,
2. be a legal CloudWatch period for that lookback age, and
3. keep the request at or below 1,440 datapoints.

Canonical selection rule:

- choose the smallest legal period that satisfies the above constraints

### 6.4 Interpretation

For each evaluated billable production variant:

- any datapoint with `Sum > 0` means observed request traffic is present
- datapoints all present with aggregate `Sum == 0` mean no observed request traffic
- no returned datapoints over the full window mean no recorded `Invocations` metrics for that
  variant during the evaluation window; this is weaker evidence than explicit zero-sum datapoints

Endpoint-level interpretation:

- if any evaluated variant shows `Invocations Sum > 0` → **SKIP ITEM**
- otherwise the endpoint is an idle candidate

### 6.5 Confidence Implication of No-Datapoint Variants

- If every evaluated variant has datapoints and aggregate `Invocations == 0` →
  stronger evidence.
- If one or more evaluated variants have no datapoints over the full window but none show
  positive traffic → weaker but still usable idle evidence.

---

## 7. Pricing / Cost Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode regional instance prices, GPU monthly approximations, or serverless
  provisioned-concurrency monthly estimates in the canonical rule output.
- The rule may still state that provisioned real-time capacity, or serverless
  `ProvisionedConcurrency`, remains billable while idle.

---

## 8. Deterministic Evaluation Order

1. Retrieve and fully paginate `ListEndpoints(StatusEquals="InService")`.
2. Normalize endpoint summary fields.
3. For each normalized endpoint:
   - missing identity or endpoint name → **SKIP ITEM**
   - invalid or missing `creation_time_utc` / `last_modified_time_utc` → **SKIP ITEM**
   - future `reference_time_utc` → **SKIP ITEM**
   - `age_days < idle_days_threshold` → **SKIP ITEM**
4. Retrieve `DescribeEndpoint`.
5. Re-check `EndpointStatus`; if not `InService` → **SKIP ITEM**.
6. Retrieve `DescribeEndpointConfig`.
7. If `DescribeEndpointConfig.AsyncInferenceConfig` is present → **SKIP ITEM**.
8. Normalize runtime production variants from `DescribeEndpoint.ProductionVariants`.
9. Discard variants without stable `variant_name`.
10. Join `DescribeEndpointConfig.ProductionVariants` by `VariantName` for enrichment only.
11. Determine billable variants.
12. If no billable variants remain → **SKIP ITEM**.
13. For each billable runtime variant, retrieve CloudWatch `Invocations Sum` using
    `EndpointName + VariantName`.
14. If any variant shows positive invocations → **SKIP ITEM**.
15. Otherwise emit a finding.

No raw AWS field access after normalization.

---

## 9. Exclusion Rules

| Condition | Result |
|---|---|
| `endpoint_arn` absent | **SKIP ITEM** |
| `endpoint_name` absent | **SKIP ITEM** |
| endpoint status not `InService` | **SKIP ITEM** |
| `creation_time_utc` absent / invalid | **SKIP ITEM** |
| `last_modified_time_utc` absent / invalid | **SKIP ITEM** |
| `reference_time_utc` future | **SKIP ITEM** |
| `age_days < idle_days_threshold` | **SKIP ITEM** |
| `DescribeEndpointConfig.AsyncInferenceConfig` present | **SKIP ITEM** |
| no production variants | **SKIP ITEM** |
| no billable variants | **SKIP ITEM** |
| any evaluated variant has positive `Invocations` | **SKIP ITEM** |

No exclusion for: VPC config, explainer config, data capture, network isolation, tag state,
multi-model usage, or accelerator presence.

---

## 10. Failure Model

**FAIL RULE:**

- `ListEndpoints` failure or pagination failure
- permission failure for required APIs at rule scope

**SKIP ITEM:**

- `DescribeEndpoint` failure for a specific endpoint
- `DescribeEndpointConfig` failure for a specific endpoint
- per-endpoint CloudWatch metric retrieval failure
- malformed timestamps or missing identity
- out-of-scope async endpoints
- endpoints without billable compute
- endpoints with observed invocation traffic

This rule does **not** emit low-confidence "verification needed" findings when required
per-endpoint data cannot be trusted; it skips that endpoint.

---

## 11. Evidence / Details Contract

### 11.1 Required details fields

```
evaluation_path                  = "idle-sagemaker-endpoint-review-candidate"
endpoint_arn
endpoint_name
endpoint_status                  = "InService"
endpoint_config_name
creation_time
last_modified_time
reference_time
evaluation_window_start
evaluation_window_end
age_days
idle_days_threshold
variant_names_evaluated
billable_variant_count
billable_compute_mode            ("instance" | "serverless_provisioned" | "mixed")
total_current_instance_count
total_provisioned_concurrency
invocation_metric_namespace      = "AWS/SageMaker"
invocation_metric_name           = "Invocations"
invocation_dimensions            = "EndpointName + VariantName"
traffic_detected                 = false
no_datapoint_variant_count
total_invocations_sum
```

### 11.2 Optional context fields

```
instance_types
is_gpu_or_accelerator_backed
managed_instance_scaling_present
metrics_config_present
multi_model_endpoint_context
```

`multi_model_endpoint_context` is informational only and must not affect eligibility,
confidence, or risk.

### 11.3 Required evidence wording

**Signals used** must state:

- endpoint is currently `InService`
- endpoint age met the configured threshold using the later of create/last-modified time
- async inference was excluded using `DescribeEndpointConfig.AsyncInferenceConfig`
- billable compute remains allocated
- no observed positive `InvokeEndpoint` traffic was found across the evaluated runtime
  production variants
- variants with no datapoints were treated as lower-confidence "no recorded invocation metrics"
  evidence, not as proven zero traffic

**Signals not checked** must state major blind spots:

- `InvokeEndpointAsync` traffic and async endpoint intent
- multi-model endpoint per-model burstiness and model-loading behavior
- shadow production variant intent
- inference-component-specific traffic review
- managed instance scaling floor/warm-capacity intent
- scheduled future usage, failover intent, or reserved warm capacity intent
- exact region-specific pricing impact

---

## 12. Confidence Model

| Condition | Confidence |
|---|---|
| Every evaluated billable variant returned datapoints and aggregate `Invocations == 0` | `HIGH` |
| No evaluated variant showed traffic, but one or more billable variants returned no datapoints | `MEDIUM` |

No LOW-confidence finding may be emitted.

---

## 13. Risk Model

| Condition | Risk |
|---|---|
| Endpoint is accelerator-backed (`g*`, `p*`, `inf*`, `trn*`) | `HIGH` |
| All other emitted findings | `MEDIUM` |

Risk is about likely waste severity, not proof of immediate safe deletion.

---

## 14. Title and Reason Contract

| Condition | Title | Reason |
|---|---|---|
| Idle endpoint finding | `"Idle SageMaker endpoint review candidate"` | `"InService SageMaker endpoint shows no observed InvokeEndpoint traffic in the last {N} days while billable compute remains allocated"` |

---

## 15. Non-Goals

This rule does **not**:

- prove an endpoint is safe to delete
- estimate canonical monthly waste in USD
- evaluate async inference endpoints
- attribute partial cost waste to individual variants
- prove absence of all possible model-serving activity beyond the documented `InvokeEndpoint`
  traffic contract
