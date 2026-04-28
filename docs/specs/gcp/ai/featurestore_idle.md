# GCP Rule Spec - `gcp.vertex.featurestore.idle`

## 1. Rule Identity

- **Rule ID:** `gcp.vertex.featurestore.idle`
- **Provider:** GCP
- **Covered resource families:**
  - Vertex AI Feature Store (Legacy) `Featurestore`
  - Vertex AI Feature Store `FeatureOnlineStore` with Bigtable online serving
- **Finding resource_type:**
  - `gcp.vertex.featurestore` for legacy `Featurestore`
  - `gcp.vertex.feature_online_store` for `FeatureOnlineStore`

---

## 2. Intent

Detect **Vertex AI feature serving stores with documented, provisioned online-serving capacity** that show **no documented online-serving request-count telemetry** over a conservative review window.

This rule is deliberately **precision-first**. It is a **review-candidate** rule only. It is **not** proof that a store is safe to delete, **not** proof that offline feature workflows are unused, and **not** a license to infer a fixed monthly dollar saving.

### 2.1 Canonical definitions

| Term | Definition |
|---|---|
| legacy feature store | `projects.locations.featurestores` resource family |
| feature online store | `projects.locations.featureOnlineStores` resource family |
| provisioned online serving | A documented control-plane configuration that proves persistent online-serving capacity exists: legacy `fixedNodeCount > 0`, legacy `scaling.minNodeCount > 0`, or `FeatureOnlineStore.bigtable.autoScaling.minNodeCount >= 1` |
| reference time | `max(createTime, updateTime)` |
| evaluation window start | inclusive UTC instant `now_utc - idle_days × 86400 seconds` |
| evaluation window end | exclusive UTC instant `now_utc` |
| full observation window | `[evaluation_window_start_utc, evaluation_window_end_utc)`, usable only when `reference_time_utc <= evaluation_window_start_utc` |
| daily aligned bucket | bucket `n` covers `[evaluation_window_start_utc + (n-1) × 86400s, evaluation_window_start_utc + n × 86400s)` for `n = 1..idle_days` |
| expected aligned bucket count | `idle_days` daily buckets after canonical alignment |

---

## 3. GCP Documentation Grounding

### 3.1 Vertex AI has distinct current and legacy feature-store families

Google documents two feature-store offerings:

1. Vertex AI Feature Store
2. Vertex AI Feature Store (Legacy), which is deprecated

Google also documents that the newer Vertex AI Feature Store uses BigQuery-backed feature data sources with online serving options, while the legacy product is a separate older resource family.

Sources:

- *Introduction to feature management and feature stores*
- *Online serving types*

URLs:

- https://cloud.google.com/vertex-ai/docs/featurestore
- https://docs.cloud.google.com/vertex-ai/docs/featurestore/latest/online-serving-types

Rule consequence:

1. This rule may cover both legacy `Featurestore` and newer `FeatureOnlineStore`, but they must be evaluated with separate documented contracts.
2. The rule must not blur these families into a single control-plane shape.
3. Feature groups, feature views, registries, and offline BigQuery sources are out of scope for this rule.

### 3.2 Legacy `Featurestore` exposes the documented online-serving configuration

Google documents the legacy `Featurestore` resource with fields including:

1. `name`
2. `createTime`
3. `updateTime`
4. `state`
5. `onlineServingConfig.fixedNodeCount`
6. `onlineServingConfig.scaling.minNodeCount`

Google also documents:

1. `fixedNodeCount = 0` means the feature store will not have an online store and cannot be used for online serving
2. only one of `fixedNodeCount` and `scaling` can be set
3. `STABLE` means the feature store configuration reflects current state and is usable
4. `UPDATING` means configuration is in progress and fields can reflect either original or updated values

Source:

- *REST Resource: projects.locations.featurestores*

URL:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.featurestores

Rule consequence:

1. Legacy stores are in scope only when online serving is explicitly provisioned.
2. Legacy stores with no online-serving capacity must skip.
3. Legacy stores in `UPDATING` must skip because, although the store can still be usable for serving, the documented configuration can reflect either the original or updated state and is therefore not stable enough for precision-first idle evaluation.

### 3.3 `FeatureOnlineStore` exposes storage type and Bigtable minimum node floor

Google documents the `FeatureOnlineStore` resource with fields including:

1. `name`
2. `createTime`
3. `updateTime`
4. `state`
5. `bigtable.autoScaling.minNodeCount`
6. `optimized`

Google also documents:

1. `FeatureOnlineStore` storage type is a union of `bigtable` or `optimized`
2. Bigtable autoscaling requires `minNodeCount >= 1`
3. `STABLE` means the store reflects current configuration and is usable
4. `UPDATING` means the store is still usable, but configuration is being changed

Sources:

- *REST Resource: projects.locations.featureOnlineStores*
- *Online serving types*

URLs:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.featureOnlineStores
- https://docs.cloud.google.com/vertex-ai/docs/featurestore/latest/online-serving-types

Rule consequence:

1. `FeatureOnlineStore` is in scope only when the storage type is documented Bigtable online serving and `bigtable.autoScaling.minNodeCount >= 1`.
2. `FeatureOnlineStore` resources using `optimized` serving are out of scope for this rule.
3. `UPDATING` stores must skip for the same evaluation-stability reason as legacy stores: the store can still serve traffic, but the configuration is not stable enough for a precision-first idle decision.

### 3.4 Cloud Monitoring documents the canonical request-count metrics and monitored resources

Google documents the monitored resources:

1. `aiplatform.googleapis.com/Featurestore` with resource labels including `location` and `featurestore_id`
2. `aiplatform.googleapis.com/FeatureOnlineStore` with resource labels including `location` and `feature_online_store_id`

Google also documents the request-count metrics:

1. `aiplatform.googleapis.com/featurestore/online_serving/request_count`
2. `aiplatform.googleapis.com/featureonlinestore/online_serving/request_count`

For the legacy metric, Google documents additional metric labels including:

- `entity_type_id`
- `method`
- `error_code`

For the `FeatureOnlineStore` metric, Google documents additional metric labels including:

- `method`
- `feature_view_id`
- `error_code`
- `storage_type`

Sources:

- *Google Cloud monitored resource list*
- *Google Cloud metrics list*

URLs:

- https://docs.cloud.google.com/monitoring/api/resources
- https://docs.cloud.google.com/monitoring/api/metrics_gcp_a_b

Rule consequence:

1. These request-count metrics are the **sole canonical telemetry source** for this rule.
2. Telemetry must be evaluated per store ID on the documented monitored resource.
3. Aggregation must sum across all other label combinations for the store, not only a single method, entity type, feature view, or error code.
4. Because these metrics are documented as `DELTA` metrics on the monitored resource, the rule must use explicit alignment and reduction rather than relying on raw sparse series output.

### 3.5 Legacy Feature Store uses Bigtable online serving and carries product-specific management overhead

Google documents that Vertex AI Feature Store (Legacy):

1. uses Bigtable for its online serving layer
2. can often be migrated to direct Bigtable for faster speeds and reduced costs
3. has a Vertex AI Feature Store (Legacy)-specific node-management premium

Source:

- *Migrate from Vertex AI Feature Store (Legacy) to Bigtable*

URL:

- https://docs.cloud.google.com/bigtable/docs/migrate-vertex-ai-legacy-bigtable

Rule consequence:

1. This rule is correctly framed as a review rule for persistent online-serving cost surfaces.
2. The rule must not hardcode a universal hourly or monthly cost estimate for either family.
3. `estimated_monthly_cost_usd` should remain `None` unless a future implementation computes current backend-specific pricing from authoritative pricing inputs.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. a stable resource name and ID are present
2. the resource family resolves to either legacy `Featurestore` or Bigtable-backed `FeatureOnlineStore`
3. the normalized region is parseable from the documented resource name
4. if a region filter is set, it matches the normalized region exactly
5. the normalized state is exactly `STABLE`
6. `reference_time_utc` is present, parseable, and not in the future
7. the store is old enough that the full observation window is coverable
8. documented provisioned online-serving capacity is present
9. the canonical request-count metric query succeeds for that resource family
10. usable metric data exists for the store over the full window
11. aggregate request count over the full window is exactly `0`

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that offline feature generation, sync, or BigQuery-based workflows are unused
- that the store is abandoned
- that the store is safe to delete or reconfigure
- that optimized online serving is wasteful when idle
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| Vertex AI `Featurestore` list inventory | enumerate legacy stores and their online-serving configuration |
| Vertex AI `FeatureOnlineStore` list inventory | enumerate newer stores and their storage type / Bigtable autoscaling floor |
| Cloud Monitoring time-series query | determine whether documented online-serving request activity occurred during the full window |

### 6.2 Permissions

Minimum permissions:

- `aiplatform.featurestores.list`
- `aiplatform.featureOnlineStores.list`
- `monitoring.timeSeries.list`

### 6.3 Idle window

- Configurable parameter: `idle_days`
- Default: `30`
- Minimum effective value: `1`

Reason:

- Feature-serving systems can legitimately have lower-frequency access than interactive notebooks or online endpoints.
- A 30-day default is conservative enough to reduce false positives for periodic usage.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `resource_family` | Resolve from the exact resource-name collection segment: `featurestores` => legacy `Featurestore`; `featureOnlineStores` => `FeatureOnlineStore`. Any other shape is unusable. |
| `resource_name` | Must be a non-empty string in the documented form `projects/{project}/locations/{location}/featurestores/{id}` or `projects/{project}/locations/{location}/featureOnlineStores/{id}`. Malformed names skip. |
| `store_id` | Final resource-name segment. Empty result skips. |
| `region` | Resolve from the exact `locations/{location}` segment in the documented resource name. If unresolved, skip. Compare using exact lowercase string equality. |
| `state` | Compare case-sensitively to exact documented enum value `STABLE`. Any other value, including `UPDATING`, is out of scope. |
| `create_time_utc` | Parse from documented RFC3339 `createTime` into a timezone-aware UTC instant. If present but unparsable, skip. Future timestamps skip. |
| `update_time_utc` | Parse from documented RFC3339 `updateTime` into a timezone-aware UTC instant. If present but unparsable, skip. Future timestamps skip. |
| `reference_time_utc` | `max(create_time_utc, update_time_utc)` when both exist; otherwise whichever documented timestamp exists. If neither exists, skip. If the resolved reference time is in the future, skip. |
| `evaluation_window_start_utc` | Inclusive UTC instant `now_utc - idle_days × 86400 seconds`. |
| `evaluation_window_end_utc` | Exclusive UTC instant `now_utc`. |
| `full_window_coverable` | True only when `reference_time_utc <= evaluation_window_start_utc`. Otherwise skip. |
| `legacy_fixed_node_count` | From `onlineServingConfig.fixedNodeCount`. Must be integer `> 0` to prove fixed online-serving capacity. `0` means no online store. |
| `legacy_scaling_min_node_count` | From `onlineServingConfig.scaling.minNodeCount`. Must be integer `> 0` to prove autoscaled online-serving capacity. |
| `legacy_online_serving_mode` | `fixed` when `fixedNodeCount > 0` and `scaling` is absent; `autoscaled` when `fixedNodeCount` is absent or `0` and `scaling.minNodeCount > 0`; `none` when neither proves capacity; `invalid` when both `fixedNodeCount` and `scaling` are materially present or when malformed shapes make the capacity unusable. |
| `feature_online_store_storage_type` | Exactly one union branch must be present: `bigtable` or `optimized`. If both or neither are present, treat as unusable and skip. |
| `bigtable_min_node_count` | From `bigtable.autoScaling.minNodeCount`. `bigtable.autoScaling` must be present and structurally usable for Bigtable-backed stores. The value must be integer `>= 1` to prove provisioned Bigtable serving capacity. |
| `bigtable_max_node_count` | From `bigtable.autoScaling.maxNodeCount`. For Bigtable-backed stores, this must be present and integer `>= bigtable_min_node_count`; otherwise the autoscaling block is unusable and the store must skip. |
| `provisioned_capacity_units` | Legacy: fixed nodes or scaling min nodes. New: Bigtable min nodes. Optimized stores do not produce this field for this rule. |
| `activity_metric_type` | Legacy: `aiplatform.googleapis.com/featurestore/online_serving/request_count`; new Bigtable-backed store: `aiplatform.googleapis.com/featureonlinestore/online_serving/request_count`. |
| `activity_metric_kind` | Must resolve to documented `DELTA`. If the descriptor or returned query surface contradicts this expectation, skip rather than silently reinterpret. |
| `activity_resource_label` | Legacy: `featurestore_id`; new store: `feature_online_store_id`. |
| `monitoring_filter` | Must constrain exact `metric.type`, exact `resource.type`, exact normalized `resource.labels.location`, and exact store ID label for the candidate store. |
| `alignment_period_seconds` | Fixed at `86400`. |
| `aligned_bucket_count_expected` | `idle_days`. |
| `request_count_total` | Sum of all aligned daily datapoints for the store over the full observation window after reducing across all additional series labels. |
| `metric_coverage_state` | `full_window`, `partial_window`, or `none`. |
| `telemetry_state` | `confirmed_zero`, `positive_activity`, or `unresolved`. No age-only fallback state is allowed. |

Normalization requirements:

1. Empty strings normalize to unusable, not meaningful values.
2. Timestamp parsing must preserve valid RFC3339 fractional seconds.
3. All timestamps used for comparison must be normalized to timezone-aware UTC before comparison.
4. If a field chosen for evaluation is present but unparsable, skip rather than silently falling back to weaker heuristics.

---

## 8. Activity Determination Contract

Cloud Monitoring request-count telemetry is the **sole trusted telemetry source** for this rule.

### 8.1 Required metrics

| Resource family | Metric type | Monitored resource | Resource ID label |
|---|---|---|---|
| Legacy `Featurestore` | `aiplatform.googleapis.com/featurestore/online_serving/request_count` | `aiplatform.googleapis.com/Featurestore` | `featurestore_id` |
| Bigtable-backed `FeatureOnlineStore` | `aiplatform.googleapis.com/featureonlinestore/online_serving/request_count` | `aiplatform.googleapis.com/FeatureOnlineStore` | `feature_online_store_id` |

### 8.2 Required query shape

The time-series query must:

1. specify exactly one `metric.type`
2. specify the exact documented `resource.type`
3. constrain `resource.labels.location` to the candidate store's normalized region by exact equality
4. constrain the family-specific store ID label to the candidate store's exact normalized store ID
5. evaluate the interval `[evaluation_window_start_utc, evaluation_window_end_utc)`
6. request aligned data rather than raw sparse output

This exact filter scoping is required to prevent cross-store and cross-region metric bleed.

### 8.3 Alignment and reduction rules

The query must use the following canonical aggregation:

1. `alignment_period = 86400s`
2. `per_series_aligner = ALIGN_SUM`
3. `cross_series_reducer = REDUCE_SUM`
4. `group_by_fields = [resource.labels.<family_store_id_label>]`
5. if the metric kind does not resolve to `DELTA`, skip rather than reinterpreting the metric contract

Reason:

- the request-count metrics are documented as `DELTA`
- this rule's idle contract is defined in whole UTC days, so the canonical alignment period is one day by design
- multiple raw series can exist for one store because of additional labels such as `entity_type_id`, `method`, `feature_view_id`, `error_code`, and `storage_type`
- idle determination must use the full sum for the store, not any single raw or partially aggregated series

The rule must **not** restrict evaluation to a single:

- legacy `entity_type_id`
- serving `method`
- `feature_view_id`
- `error_code`
- `storage_type`

### 8.4 Coverage requirement

`usable metric data` means **all** of the following are true:

1. after the canonical filter and reduction, exactly one reduced time series must remain for the candidate store; if the result count is not exactly `1`, the store is unresolved
2. the reduced series contains exactly `aligned_bucket_count_expected = idle_days` aligned daily datapoints for the full window
3. each aligned datapoint must belong to exactly one documented daily aligned bucket, and no aligned datapoint may extend beyond `evaluation_window_end_utc`
4. no aligned datapoint timestamp is in the future
5. each aligned datapoint must carry at least one valid numeric request value; null, empty, or non-numeric datapoints are unusable
6. the spacing between adjacent aligned datapoints must not exceed one alignment period (`86400` seconds)

If any of the above fails, `metric_coverage_state` is not `full_window` and the store is unresolved.

The exact daily-bucket requirement is intentional. A missing bucket is treated as missing telemetry coverage, not as proof of zero activity.

Interpretation:

1. zero returned time series -> `metric_coverage_state = none` -> `telemetry_state = unresolved`
2. any reduced time-series count other than `1` -> `metric_coverage_state = partial_window` -> `telemetry_state = unresolved`
3. any aligned datapoint count other than `idle_days` -> `metric_coverage_state = partial_window` -> `telemetry_state = unresolved`
4. exactly `idle_days` aligned datapoints with aggregate request total `> 0` -> `telemetry_state = positive_activity`
5. exactly `idle_days` aligned datapoints with aggregate request total `== 0` -> `metric_coverage_state = full_window` and `telemetry_state = confirmed_zero`
6. any null, empty, non-numeric, or discontinuously spaced aligned bucket -> `metric_coverage_state = partial_window` -> `telemetry_state = unresolved`

### 8.5 Forbidden fallbacks

The following must **not** be used to prove idleness:

- store age alone
- `createTime` alone
- `updateTime` alone
- legacy node count alone
- Bigtable `minNodeCount` alone
- absence of request metrics treated as equivalent to zero traffic
- a single zero datapoint without full-window bucket coverage

---

## 9. Unified Decision Rule

### 9.1 Legacy `Featurestore`

Emit only when **all** of the following are true:

1. resource family is legacy `Featurestore`
2. `state == "STABLE"`
3. region is parseable and matches the optional region filter exactly
4. `reference_time_utc` is valid and the full window is coverable
5. `legacy_online_serving_mode` is `fixed` or `autoscaled`
6. `metric_coverage_state == "full_window"`
7. canonical legacy request-count telemetry is `confirmed_zero`

### 9.2 `FeatureOnlineStore`

Emit only when **all** of the following are true:

1. resource family is `FeatureOnlineStore`
2. `state == "STABLE"`
3. region is parseable and matches the optional region filter exactly
4. `reference_time_utc` is valid and the full window is coverable
5. `feature_online_store_storage_type == "bigtable"`
6. `bigtable_min_node_count >= 1`
7. `metric_coverage_state == "full_window"`
8. canonical `FeatureOnlineStore` request-count telemetry is `confirmed_zero`

### 9.3 Explicit exclusions

Always skip:

- legacy stores with no online-serving config
- legacy stores with `fixedNodeCount == 0` and no valid `scaling.minNodeCount`
- legacy stores with `scaling.minNodeCount == 0`
- legacy stores with both materially present `fixedNodeCount` and `scaling`
- legacy stores in `UPDATING`
- `FeatureOnlineStore` resources in `UPDATING`
- `FeatureOnlineStore` resources using `optimized`
- `FeatureOnlineStore` resources with malformed storage union or unusable `bigtable.autoScaling`
- stores younger than the full observation window
- stores with unresolved telemetry

---

## 10. Finding Shape

### 10.1 Core fields

| Field | Value |
|---|---|
| `provider` | `gcp` |
| `rule_id` | `gcp.vertex.featurestore.idle` |
| `resource_type` | `gcp.vertex.featurestore` for legacy; `gcp.vertex.feature_online_store` for new |
| `resource_id` | full resource name when available, otherwise normalized store ID |
| `region` | normalized location |
| `detected_at` | rule evaluation time |
| `estimated_monthly_cost_usd` | `None` |

### 10.2 Confidence / risk

| Field | Value |
|---|---|
| `confidence` | `HIGH` |
| `risk` | `HIGH` |

Reason:

- The rule emits only when documented provisioned online-serving capacity exists and documented request-count telemetry confirms zero observed requests over the full window.

### 10.3 Required evidence content

Evidence should include factual signals only, such as:

1. resource family
2. normalized state
3. normalized region
4. reference time and idle window
5. serving mode / storage type
6. provisioned baseline node floor
7. canonical metric type used
8. aggregate request count total of `0`

Evidence must **not**:

- claim the store is abandoned
- claim offline data paths are unused
- include a flat cost estimate masquerading as authoritative pricing

---

## 11. Failure Behavior

### 11.1 Permission failures

Permission failures on required listing or monitoring surfaces must be surfaced explicitly. They must not be silently converted into heuristic findings.

### 11.2 Monitoring failures

If monitoring request-count telemetry for a resource family cannot be queried reliably, findings that depend on that family must not be emitted from age-only or config-only fallback logic.

### 11.3 Malformed records

Malformed individual resources should be skipped item-by-item when required identity, location, timestamp, state, or provisioning signals are unusable.

### 11.4 Partial coverage

If an implementation can continue after a family-specific inventory or telemetry failure, it must preserve that incompleteness as operational visibility. It must not present the project as fully evaluated for the failed family.

Partial metric coverage is unresolved, not weak evidence. This includes zero reduced series, more than one reduced series, partial bucket counts, invalid bucket values, and discontinuous bucket spacing.
