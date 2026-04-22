# Azure Rule Spec — `azure.container_registry.unused`

## 1. Rule Identity

- **Rule ID:** `azure.container_registry.unused`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.ContainerRegistry/registries`
- **Finding resource_type:** `azure.container_registry`

---

## 2. Intent

Detect **Azure Container Registries with no successful image pull or push activity** over the configured inactivity window.

This rule is deliberately **conservative**. It optimizes for **low noise and low false positives**. A registry with no successful pulls or pushes for a long period is a strong candidate for review, but this rule does **not** claim that the registry is safe to delete without checking deployment intent and retained image value.

---

## 3. Azure Documentation Grounding

### 3.1 SKU and billing context

Microsoft documents three current Azure Container Registry pricing plans:

| SKU | Billing relevance |
|---|---|
| Basic | Base registry fee plus storage |
| Standard | Base registry fee plus storage |
| Premium | Base registry fee plus storage |

Source: *Azure Container Registry service tiers*
URL: https://learn.microsoft.com/en-us/azure/container-registry/container-registry-skus

Microsoft also documents that additional storage is billed separately from the included storage in each SKU.

### 3.2 Registry metrics used by this rule

Microsoft documents the following automatically collected platform metrics for `Microsoft.ContainerRegistry/registries`:

| Metric | REST name | Aggregation | Dimensions | Time grain |
|---|---|---|---|---|
| Successful Pull Count | `SuccessfulPullCount` | Total (Sum) | `<none>` | `PT1M` |
| Successful Push Count | `SuccessfulPushCount` | Total (Sum) | `<none>` | `PT1M` |
| Storage used | `StorageUsed` | Average | `Geolocation` | `PT1H` |

Sources:
- *Supported metrics for Microsoft.ContainerRegistry/registries*
- *Azure Container Registry monitoring reference*

URLs:
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-containerregistry-registries-metrics
- https://learn.microsoft.com/en-us/azure/container-registry/monitor-service-reference

The absence of dimensions on `SuccessfulPullCount` and `SuccessfulPushCount` is important: this rule treats those metrics as registry-scoped activity signals, not per-replica signals.

### 3.3 Resource logs are out of scope

Microsoft documents Container Registry resource logs such as:

- `ContainerRegistryLoginEvents`
- `ContainerRegistryRepositoryEvents`

These are Azure Monitor resource logs, not guaranteed baseline platform signals for every registry. This rule therefore does **not** require logs to be enabled.

Source: *Azure Container Registry monitoring reference*
URL: https://learn.microsoft.com/en-us/azure/container-registry/monitor-service-reference

### 3.4 Registry shape

Microsoft's ARM/Bicep reference for `Microsoft.ContainerRegistry/registries` documents the control-plane fields relevant to this rule:

- `id`
- `name`
- `location`
- `sku.name`
- `tags`

Source: *Microsoft.ContainerRegistry/registries template reference*
URL: https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries

The Azure Container Registry REST API also documents:

- `properties.creationDate`
- `properties.provisioningState`

Source: *Registries - Get* / *Registries - List*
URLs:
- https://learn.microsoft.com/en-us/rest/api/container-registry/registries/get?view=rest-container-registry-2023-07-01
- https://learn.microsoft.com/en-us/rest/api/container-registry/registries/list?view=rest-container-registry-2023-07-01

---

## 4. Detection Goal

Emit a finding when **all** of the following are true:

1. `registry.id` is present and non-empty
2. registry provisioning state resolves to exactly `"Succeeded"`
3. `properties.creationDate` is known and satisfies `properties.creationDate <= window_start`
4. `SuccessfulPullCount` evaluates to `ZERO` under the metric evaluation contract
5. `SuccessfulPushCount` evaluates to `ZERO` under the metric evaluation contract

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the registry is safe to delete
- that the registry contains no valuable images or artifacts
- that no workloads will pull from the registry in the future
- that failed pull attempts, login attempts, or non-push/non-pull repository operations imply active use

---

## 6. Canonical Inputs

| API / signal | SDK method / source | Required permission |
|---|---|---|
| Registry list | `acr_client.registries.list()` | `Microsoft.ContainerRegistry/registries/read` |
| Pull metric | Azure Monitor metric `SuccessfulPullCount` | `Microsoft.Insights/metrics/read` |
| Push metric | Azure Monitor metric `SuccessfulPushCount` | `Microsoft.Insights/metrics/read` |
| Registry creation / provisioning fields | `properties.creationDate`, `properties.provisioningState` or equivalent SDK projection | `Microsoft.ContainerRegistry/registries/read` |

Default inactivity window:

- parameter: `days_unused`
- default: `90`

Evaluation window:

- `window_end = now`
- `window_start = now - days_unused`

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase ARM location string; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. Examples: `eastus`, `westeurope`, `eastus2`. |
| `sku_name` for cost lookup | Lowercase only. Map exact labels `basic`, `standard`, and `premium` to known base costs. Any other value, including suffixed, versioned, or future labels such as `basic_plus`, `standardv2`, or `premiumv2`, maps to unknown cost. |
| `registry.id` | Original ARM id for `resource_id`; strip trailing slash only if needed for metric query |
| `tags` | `registry.tags or {}` — never `None` in output |
| `properties.creationDate` | Parse as UTC timestamp |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `registry.id` is absent, `None`, or empty | Skip |
| 8.2 | Region filter set and lowercase-normalized location does not match | Skip |
| 8.3 | Provisioning state does not resolve to `"Succeeded"` under the provisioning-state contract | Skip |
| 8.4 | `properties.creationDate` is absent or unparsable | Skip |
| 8.5 | `properties.creationDate > window_start` | Skip |
| 8.6 | `SuccessfulPullCount` metric result is not `ZERO` under the metric evaluation contract | Skip |
| 8.7 | `SuccessfulPushCount` metric result is not `ZERO` under the metric evaluation contract | Skip |

No SKU allowlist is required for eligibility. The rule is about inactivity, not feature gating; unknown or legacy SKU values do **not** prevent evaluation. They only affect whether a cost estimate can be produced.

---

## 9. Canonical Evaluation Contracts

The inactivity decision is based on **successful data-plane usage**, not login attempts or configuration activity.

### 9.1 Provisioning-state contract

Resolve registry provisioning state in this order:

1. `properties.provisioningState`
2. SDK fallback such as `provisioning_state`
3. otherwise unknown

Only `"Succeeded"` is eligible for evaluation. Unknown or any other value must skip.

### 9.2 Metric evaluation contract

Required metrics:

1. `SuccessfulPullCount`
2. `SuccessfulPushCount`

For each metric, implementations must:

- query each metric with `aggregation = "Total"` and a coarse interval such as `PT1H`
- use up to `3` total attempts with exponential backoff delays of `1s` then `2s`
- sum totals across all returned time series and all datapoints
- if Azure later returns multiple dimension slices, sum across all slices for the same bucket timestamp before evaluating totals

Definitions:

- **usable datapoint**: a datapoint with a parseable UTC timestamp inside the requested window and a numeric `total` value
- **valid metric series**: the metric query succeeds and returns at least one time series containing at least one usable datapoint after retries
- **expected buckets**: count of UTC-aligned interval buckets overlapping `[window_start, window_end)`. For `PT1H`, buckets align to the top of each UTC hour.
- **observed buckets**: count of unique UTC-aligned bucket timestamps with a numeric aggregated total after summing duplicate timestamps across all returned series and dimension slices
- **coverage ratio**: `observed_buckets / expected_buckets`
- **acceptable coverage**: `coverage_ratio >= 0.80`

Metric result states:

- **ACTIVE**: valid metric series, acceptable coverage, and aggregate total `> 0`
- **ZERO**: valid metric series, acceptable coverage, and aggregate total `== 0`
- **UNKNOWN**: query failure after retries, unusable response shape, no valid metric series, or `coverage_ratio < 0.80`

Emission threshold:

- emit only when **both** `SuccessfulPullCount` and `SuccessfulPushCount` evaluate to `ZERO`

Rationale:

- zero pulls alone is not enough because CI/CD pipelines may still be pushing images
- zero pushes alone is not enough because active workloads may still be pulling existing images
- this conservative contract intentionally prioritizes precision over recall when Azure metric coverage is sparse

---

## 10. Out-of-Scope Signals

The following are intentionally **not** required for emission:

- `TotalPullCount`
- `TotalPushCount`
- `StorageUsed`
- `ContainerRegistryLoginEvents`
- `ContainerRegistryRepositoryEvents`

Reasons:

- this rule is defined around **successful** pull/push activity
- `StorageUsed` measures retained data, not use
- resource logs are optional and not guaranteed to be enabled in all environments

---

## 11. Cost Model

`estimated_monthly_cost_usd` should be the approximate base monthly registry fee when SKU is known:

| SKU | Approx. monthly base fee |
|---|---|
| Basic | $5.00 |
| Standard | $20.00 |
| Premium | $50.00 |

Set `estimated_monthly_cost_usd = None` when:

- SKU is absent
- SKU is unrecognized / legacy / unsupported by the rule’s cost table

Important:

- this estimate is a **base registry fee only**
- it does **not** include storage charges
- it does **not** include data transfer, network, Private Link, or other related Azure costs

---

## 12. Finding Shape

### 12.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.container_registry.unused"` |
| `resource_type` | `"azure.container_registry"` |
| `resource_id` | Original ARM id from `registry.id` |
| `region` | Normalized location |
| `risk` | `LOW` |
| `confidence` | `HIGH` |
| `estimated_monthly_cost_usd` | Base monthly SKU fee or `None` |

### 12.2 Required evidence

`signals_used` must include:

1. `"Registry creation date satisfies properties.creationDate <= window_start"`
2. `"SuccessfulPullCount and SuccessfulPushCount both evaluated to ZERO for the {days_unused}-day window"`
3. `"Registry SKU: {sku_name}"`
4. If cost estimate is known: `"ACR {sku_name} tier costs ~${cost}/month plus storage"`

`signals_not_checked` should include:

1. `"Planned reactivation or migration intent"`
2. `"Images referenced by stopped or undeployed workloads"`
3. `"Failed pull or login attempts not treated as active use"`
4. `"Storage charges not included in estimated base monthly cost"`

### 12.3 Required details

| Key | Nullable |
|---|---|
| `registry_name` | No |
| `sku` | Yes |
| `location` | No |
| `created_at` | No |
| `days_unused_threshold` | No |
| `tags` | No (normalize `None` to `{}`) |

---

## 13. Failure Behavior

- If the registry list call raises: let the exception propagate (do not silently return empty findings)
- If either metric evaluates to `UNKNOWN`: skip that registry and continue

---

## 14. Acceptance Examples

### 14.1 Must emit

1. Provisioning state resolves to `"Succeeded"`, `properties.creationDate <= window_start`, `SuccessfulPullCount = ZERO`, `SuccessfulPushCount = ZERO`, `sku.name == "Standard"` -> **EMIT**, `estimated_monthly_cost_usd == 20.0`
2. Provisioning state resolves to `"Succeeded"`, `properties.creationDate <= window_start`, no successful pulls or pushes for 30 days, `days_unused == 30` -> **EMIT**
3. `sku.name == "Premium"`, `coverage_ratio == 0.80`, zero pulls and zero pushes, region `"eastus"` with filter `"eastus"` -> **EMIT**, `region == "eastus"`
4. `sku.name` absent or unrecognized, but both metrics evaluate to `ZERO` and control-plane fields are valid -> **EMIT**, `estimated_monthly_cost_usd == None`

### 14.2 Must skip

1. Provisioning state does not resolve to `"Succeeded"` -> **SKIP**
2. `properties.creationDate > window_start` -> **SKIP**
3. Pull metric evaluates to `ACTIVE` -> **SKIP**
4. Push metric evaluates to `ACTIVE` -> **SKIP**
5. Pull metric evaluates to `UNKNOWN` -> **SKIP**
6. Push metric evaluates to `UNKNOWN` -> **SKIP**
7. Pull or push metric has `coverage_ratio < 0.80` -> **SKIP**
8. Registry outside region filter -> **SKIP**
9. `registry.id == None` -> **SKIP**

---

## 15. Anti-Goals

Implementations must **not**:

1. emit unless **both** metrics evaluate to `ZERO`
2. require Azure Monitor resource logs to be enabled
3. use `StorageUsed` as a proxy for activity
4. convert `UNKNOWN` metric results into `ZERO`
5. evaluate registries created after the inactivity window start
6. claim storage charges are included in `estimated_monthly_cost_usd`
