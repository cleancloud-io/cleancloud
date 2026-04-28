# GCP Rule Spec - `gcp.vertex.endpoint.idle`

## 1. Rule Identity

- **Rule ID:** `gcp.vertex.endpoint.idle`
- **Provider:** GCP
- **Resource type:** Vertex AI Endpoint
- **Finding resource_type:** `gcp.vertex.endpoint`

---

## 2. Intent

Detect **Vertex AI Endpoints with a documented always-deployed serving floor** and **no observed online prediction request activity above zero** over a conservative review window, using documented Cloud Monitoring request-count telemetry.

This rule is deliberately **precision-first**. It is a **review-candidate** rule only. It is **not** proof that the endpoint is safe to delete, **not** proof that all endpoint verbs are unused, and **not** proof of a specific monthly dollar saving.

### 2.1 Canonical definitions

| Term | Definition |
|---|---|
| Vertex AI Endpoint | `projects/{project}/locations/{location}/endpoints/{endpoint_id}` resource into which one or more models are deployed |
| in-scope deployed model | A `DeployedModel` whose prediction resource mode has an always-deployed serving floor for this rule: `dedicatedResources.minReplicaCount >= 1` or `automaticResources.minReplicaCount >= 1` |
| out-of-scope deployed model | A `DeployedModel` using only `sharedResources`, or a deployed model whose serving-floor minimum is `0` |
| provisioned serving floor | Sum of `minReplicaCount` across in-scope deployed models on the endpoint |
| shared-resource-only endpoint | An endpoint with deployed models, but none of them have an in-scope provisioned serving floor |
| capacity floor start | The latest documented creation timestamp that proves the endpoint’s current provisioned serving floor existed: `max(endpoint.createTime, all in-scope deployedModel.createTime)` |
| evaluation window end | `now_utc` |
| evaluation window start | `evaluation_window_end_utc - idle_days × 86400 seconds` |
| full observation window | `[evaluation_window_start_utc, evaluation_window_end_utc]`, usable only when `capacity_floor_start_utc <= evaluation_window_start_utc` |
| request-count telemetry | Cloud Monitoring metric `aiplatform.googleapis.com/prediction/online/request_count` |
| zero-activity threshold | Exact threshold for this rule: **no usable endpoint-scoped request-count datapoint above `0`** anywhere in the full observation window |

---

## 3. GCP Documentation Grounding

### 3.1 Endpoint is the control-plane resource for online prediction traffic

Google documents the Vertex AI `Endpoint` resource with fields including:

1. `name`
2. `displayName`
3. `description`
4. `deployedModels`
5. `trafficSplit`
6. `labels`
7. `createTime`
8. `updateTime`
9. `network`
10. `privateServiceConnectConfig`
11. `modelDeploymentMonitoringJob`
12. `dedicatedEndpointEnabled`
13. `dedicatedEndpointDns`

Google also documents that:

1. models are deployed into an `Endpoint`
2. the `Endpoint` is afterwards called to obtain predictions and explanations

Source:

- *REST Resource: projects.locations.endpoints*

URL:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.endpoints

Rule consequence:

1. Eligibility must be based on documented Endpoint and DeployedModel control-plane fields only.
2. The canonical resource identity is the full Endpoint resource name.
3. `trafficSplit`, `network`, private networking fields, and logging fields are context only; they are not independent proof of activity or inactivity.

### 3.2 DeployedModel exposes a union of prediction resource modes

Google documents `DeployedModel` as containing the prediction resource union:

1. `dedicatedResources`
2. `automaticResources`
3. `sharedResources`

Google also documents:

1. `createTime` for `DeployedModel`
2. `privateEndpoints`
3. `status`

Source:

- *REST Resource: projects.locations.endpoints* (`DeployedModel`)

URL:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.endpoints

Rule consequence:

1. Endpoint idle evaluation must consider the prediction resource mode of each deployed model.
2. `sharedResources` deployments are operationally distinct because serving cost is attached to a shared pool, not directly to the endpoint.
3. `DeployedModel.createTime` is relevant for proving how long the current serving floor has existed.

### 3.3 DedicatedResources provides an always-deployed serving floor

Google documents `DedicatedResources` as follows:

1. `machineSpec` is required
2. `minReplicaCount` is required
3. `minReplicaCount` is the minimum number of machine replicas that will be **always deployed on**
4. `maxReplicaCount` may be higher for autoscaling
5. for online prediction, supported autoscaling metrics include:
   - `aiplatform.googleapis.com/prediction/online/accelerator/duty_cycle`
   - `aiplatform.googleapis.com/prediction/online/cpu/utilization`
   - `aiplatform.googleapis.com/prediction/online/request_count`

Google also documents in the autoscaling guide:

1. when configuring a standard `DeployedModel`, `dedicatedResources.minReplicaCount` must be at least `1`
2. Vertex AI normally cannot scale a standard dedicated deployment to zero inference nodes
3. a **Scale To Zero** preview path exists where `dedicatedResources.minReplicaCount` may be set to `0`

Sources:

- *DedicatedResources*
- *Scale inference nodes for Vertex AI Inference*

URLs:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/DedicatedResources
- https://cloud.google.com/vertex-ai/docs/predictions/autoscaling

Rule consequence:

1. `dedicatedResources.minReplicaCount >= 1` is a documented always-deployed serving floor and is in scope.
2. `dedicatedResources.minReplicaCount == 0` is out of scope for this rule because there is no documented always-deployed floor to review.
3. `maxReplicaCount`, autoscaling thresholds, and target metrics are context only; they do not themselves prove current activity.

### 3.4 AutomaticResources can also provide an always-deployed serving floor

Google documents `AutomaticResources` as follows:

1. `minReplicaCount` is the minimum number of replicas that will be **always deployed on**
2. `maxReplicaCount` is the maximum number of replicas that may be deployed on as traffic increases

Source:

- *AutomaticResources*

URL:

- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/AutomaticResources

Rule consequence:

1. `automaticResources.minReplicaCount >= 1` is an always-deployed serving floor and is in scope for idle review.
2. `automaticResources.minReplicaCount == 0` is out of scope because there is no always-deployed floor to review.
3. The rule must **not** assume that all `automaticResources` endpoints scale to zero.

### 3.5 Online inference nodes and deployed models incur cost even without traffic

Google documents that:

1. Vertex AI allocates **nodes** to handle online inference
2. when serving online inference, machine type is specified in a deployed model’s prediction resources
3. for AutoML models, you pay for each model deployed to an endpoint **even if no prediction is made**
4. you must undeploy the model to stop incurring further charges
5. pricing varies by machine type, accelerator, region, and usage option

Sources:

- *Configure compute resources for inference*
- *Vertex AI pricing*

URLs:

- https://cloud.google.com/vertex-ai/docs/predictions/configure-compute
- https://cloud.google.com/vertex-ai/pricing

Rule consequence:

1. An endpoint with an always-deployed serving floor and zero observed prediction activity is a valid idle-cost review candidate.
2. The rule must not hardcode a flat monthly estimate from one region’s pricing table.
3. `estimated_monthly_cost_usd` should remain `None` unless a future implementation computes current pricing from authoritative current pricing inputs.

### 3.6 Endpoint is a documented Cloud Monitoring monitored resource

Google documents the monitored resource type:

1. `aiplatform.googleapis.com/Endpoint`
2. labels:
   - `resource_container`
   - `location`
   - `endpoint_id`

Source:

- *Google Cloud monitored resource list*

URL:

- https://cloud.google.com/monitoring/api/resources

Rule consequence:

1. Endpoint activity telemetry must be attributed using the documented Endpoint monitored resource.
2. Exact endpoint identity must be established from `location` and `endpoint_id`, not inferred from display name or traffic split.

### 3.7 Online prediction request_count is a documented autoscaling metric

Google documents the online prediction autoscaling metric:

1. metric name `aiplatform.googleapis.com/prediction/online/request_count`
2. it scales based on the **number of requests**
3. its unit is **requests per minute per replica**
4. the target value is an integer

Source:

- *Scale inference nodes for Vertex AI Inference*

URL:

- https://cloud.google.com/vertex-ai/docs/predictions/autoscaling

Rule consequence:

1. The canonical activity signal for this rule is `aiplatform.googleapis.com/prediction/online/request_count`.
2. Because the metric is request-based, **any usable datapoint above `0`** is observed endpoint activity for this rule.
3. Near-idle heuristics such as “few requests” or replica-scaled thresholds are out of scope for this rule.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. the Endpoint has at least one in-scope deployed model with a documented always-deployed serving floor
2. the documented serving floor has existed for the full observation window
3. canonical endpoint-scoped request-count telemetry is sufficiently observed across the full observation window
4. no usable endpoint-scoped request-count datapoint above `0` is observed anywhere in the full observation window

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the endpoint is safe to delete or undeploy
- that explain-only, health-only, or non-prediction endpoint usage is absent
- that shared DeploymentResourcePool cost is attributable to a specific endpoint
- that a low-but-nonzero request volume is “near-idle”
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| Endpoint list (`projects.locations.endpoints.list`) | enumerate endpoints, deployed models, resource modes, timestamps, traffic split, and networking context |
| Cloud Monitoring `aiplatform.googleapis.com/prediction/online/request_count` | determine observed online prediction request activity |

### 6.2 Permissions

Minimum permissions:

- `aiplatform.endpoints.list`
- `monitoring.timeSeries.list`

### 6.3 Idle window

- Configurable parameter: `idle_days`
- Default: `14`
- Minimum effective value: `1`

Reason:

- Vertex endpoints are frequently created for demos, experiments, and staged launches.
- A two-week zero-request window is conservative enough to reduce false positives while still surfacing abandoned always-on capacity.

### 6.4 Cost field

- `estimated_monthly_cost_usd = None`

Reason:

- Dedicated, automatic, and shared serving modes have materially different pricing and cost attribution semantics.
- Official pricing is region- and configuration-specific, so a flat estimate would be misleading.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `resource_name` | Must be a non-empty string in documented Endpoint name form `projects/{project}/locations/{location}/endpoints/{endpoint_id}`. Malformed names skip. |
| `endpoint_id` | Final endpoint-name segment. Empty result skips. |
| `location` | Resolve from exact `locations/{location}` segment in the resource name. If unresolved, skip. |
| `endpoint_create_time_utc` | Parse documented RFC3339 `Endpoint.createTime` into timezone-aware UTC. If present but unparsable, skip. Future timestamps skip. |
| `in_scope_deployed_models` | Deployed models with `dedicatedResources.minReplicaCount >= 1` or `automaticResources.minReplicaCount >= 1`. |
| `shared_resource_only` | True when deployed models exist but none are in scope because they use only `sharedResources` or have serving-floor minimum `0`. |
| `provisioned_serving_floor` | Sum of `minReplicaCount` across in-scope deployed models. Must be `>= 1` to be eligible. |
| `deployed_model_create_time_utc` | Parse each in-scope deployed model’s `createTime` into timezone-aware UTC. If a chosen timestamp is missing, future, or unparsable, skip. |
| `capacity_floor_start_utc` | `max(endpoint_create_time_utc, all in-scope deployed_model_create_time_utc)` |
| `evaluation_window_end_utc` | `now_utc` |
| `evaluation_window_start_utc` | `evaluation_window_end_utc - idle_days × 86400 seconds` |
| `full_window_coverable` | True only when `capacity_floor_start_utc <= evaluation_window_start_utc`. Otherwise skip. |
| `request_metric_type` | Exact `aiplatform.googleapis.com/prediction/online/request_count`. |
| `request_metric_resource_type` | Exact `aiplatform.googleapis.com/Endpoint`. |
| `usable_request_datapoint` | A request-count datapoint whose timestamp falls inside the full observation window and whose value is numeric: use `int64Value` first, else `doubleValue`; ignore null, missing, NaN, or unsupported value shapes. |
| `max_observed_request_rate_per_replica` | Maximum usable `request_count` datapoint value across all endpoint-scoped series/points in the observation window. |
| `telemetry_coverage_state` | `complete` or `unresolved`. `complete` means endpoint-scoped request telemetry is sufficiently observed across the full window. |
| `telemetry_state` | `no_observed_prediction_requests`, `observed_prediction_requests`, or `unresolved`. No age-only fallback state is allowed. |

Normalization requirements:

1. All timestamps used for comparison must be timezone-aware UTC.
2. Empty strings normalize to unusable, not meaningful values.
3. If a chosen field is present but unparsable, skip rather than silently falling back.
4. Resource-mode interpretation must follow the documented prediction resource union only.
5. The rule must not reinterpret `automaticResources` as automatically scale-to-zero.
6. Endpoint activity is endpoint-level for this rule: any usable endpoint-scoped request-count datapoint above `0` counts as endpoint activity regardless of which deployed model received traffic.

---

## 8. Activity Determination Contract

Cloud Monitoring request-count telemetry is the **sole trusted activity signal** for this rule.

### 8.1 Required metric

| Field | Value |
|---|---|
| Metric type | `aiplatform.googleapis.com/prediction/online/request_count` |
| Meaning | Number of requests |
| Unit | Requests per minute per replica |
| Monitored resource | `aiplatform.googleapis.com/Endpoint` |
| Resource labels | `resource_container`, `location`, `endpoint_id` |

### 8.2 Required query shape

The monitoring query must:

1. specify exact `metric.type = "aiplatform.googleapis.com/prediction/online/request_count"`
2. specify exact resource type `aiplatform.googleapis.com/Endpoint`
3. attribute data to the endpoint using exact `location` and `endpoint_id`
4. evaluate the full interval `[evaluation_window_start_utc, evaluation_window_end_utc]`
5. preserve enough timestamp information to prove telemetry coverage from actual datapoint timestamps
6. consider all endpoint-scoped series returned for that endpoint; any positive datapoint on any returned series is observed activity
7. preserve raw request-count values for zero/nonzero evaluation

The query/evaluation path must **not**:

- use a cross-series reducer
- use `ALIGN_RATE`
- transform raw request-count datapoints into derived rate, threshold, or utilization signals before zero/nonzero evaluation

The implementation **may** batch by location for efficiency, provided it still enforces exact endpoint attribution from the returned resource labels and does not treat location-only matches as sufficient.

### 8.3 Telemetry coverage requirement

Coverage requirements:

1. no-series-returned is unresolved, not zero activity
2. `0` values are valid observed signals
3. missing datapoints must never be treated as zero
4. coverage must be established from actual datapoint timestamps, not assumed sampling behavior
5. if the implementation cannot prove from monitoring timestamps that endpoint-scoped telemetry sufficiently covers the full observation window, `telemetry_coverage_state = unresolved` and the endpoint must skip
6. any gap that cannot be proven from datapoint timestamps to preserve sufficient observation is unresolved and must skip
7. datapoints outside the full observation window must be ignored for both activity and coverage evaluation
8. unexplained large gaps in endpoint-scoped telemetry are unresolved and must skip

Because the cited docs define metric name and unit but do **not** publish a definitive sampling cadence or visibility-delay contract for this metric, the rule must not invent:

- an exact sample-count requirement
- a mandatory trailing ingestion buffer
- a heuristic fallback that treats missing recent data as zero

### 8.4 Interpretation rules

For an endpoint with `telemetry_coverage_state == complete`:

1. use monitoring timestamps as the source of truth for telemetry timing
2. ignore endpoint-scoped datapoints whose timestamps fall outside the full observation window
3. extract each usable datapoint value by reading `int64Value` first, else `doubleValue`; ignore null, NaN, or unsupported value shapes
4. compute `max_observed_request_rate_per_replica` as the maximum usable endpoint-scoped request-count datapoint over the full observation window
5. if any usable datapoint is greater than `0`, `telemetry_state = observed_prediction_requests` and the endpoint must skip
6. if all usable datapoints are exactly `0`, `telemetry_state = no_observed_prediction_requests`

### 8.5 Forbidden fallbacks

The following must **not** be used to prove endpoint idleness:

- endpoint age alone
- trafficSplit alone
- `updateTime` alone
- Cloud Logging access or request/response logging alone
- CPU utilization, accelerator duty cycle, latency, or other metrics as substitutes for request-count telemetry
- “near-idle”, low-traffic, or replica-scaled request thresholds
- missing monitoring telemetry treated as equivalent to zero activity

---

## 9. Unified Decision Rule

Emit only when **all** of the following are true:

1. the endpoint identity and location are parseable
2. if a location filter is set, the endpoint location matches exactly
3. at least one deployed model is in scope and `provisioned_serving_floor >= 1`
4. the endpoint is not shared-resource-only
5. `capacity_floor_start_utc` is valid and the full observation window is coverable
6. `telemetry_coverage_state == "complete"`
7. `max_observed_request_rate_per_replica == 0`

If canonical request-count telemetry is not sufficiently observed across the full observation window, the rule **MUST NOT** emit.

Always skip:

- malformed endpoint names or locations
- endpoints with unusable chosen timestamps
- endpoints whose serving floor is too new for the full window
- endpoints with no deployed models
- endpoints with only `sharedResources`
- endpoints whose only deployed models have serving-floor minimum `0`
- endpoints with malformed prediction-resource unions or malformed chosen `minReplicaCount` fields
- monitoring query failures
- missing or sparse telemetry treated as unresolved
- any observed request-count datapoint above `0`

---

## 10. Finding Shape

### 10.1 Core fields

| Field | Value |
|---|---|
| `provider` | `gcp` |
| `rule_id` | `gcp.vertex.endpoint.idle` |
| `resource_type` | `gcp.vertex.endpoint` |
| `resource_id` | full Endpoint resource name when available, otherwise normalized `endpoint_id` |
| `region` | exact endpoint `location` |
| `detected_at` | evaluation time |
| `estimated_monthly_cost_usd` | `None` |

### 10.2 Confidence / risk

| Field | Value |
|---|---|
| `confidence` | `HIGH` |
| `risk` | `HIGH` if any in-scope dedicated model exposes a nonzero accelerator count or accelerator type; otherwise `MEDIUM` |

Reason:

- Confidence is HIGH only because the rule emits solely on full-window zero request-count telemetry with no heuristic fallback.
- Risk reflects that accelerator-backed endpoints are typically costlier and more operationally sensitive than CPU-only endpoints.

### 10.3 Required evidence content

Evidence should include factual signals only, such as:

1. endpoint location
2. endpoint `createTime`
3. capacity floor start timestamp
4. observation window
5. deployed model resource modes present on the endpoint
6. provisioned serving floor
7. whether any shared-resource deployments are also present
8. canonical request-count metric type used
9. maximum observed request-count datapoint value over the window
10. statement that endpoint-scoped request-count telemetry showed no datapoint above `0`

Evidence must **not**:

- claim the endpoint is safe to delete or undeploy
- claim that explain-only or non-prediction endpoint traffic is impossible
- present a flat price estimate as authoritative current spend

---

## 11. Failure Behavior

### 11.1 Permission failures

Permission failures on required Endpoint inventory or Monitoring surfaces must be surfaced explicitly. They must not be silently converted into heuristic findings.

### 11.2 Monitoring failures

If request-count telemetry cannot be queried reliably, findings must not be emitted from age-only, traffic-split, or low-traffic fallback logic.

### 11.3 Malformed records

Malformed individual endpoints should be skipped item-by-item when required identity, location, timestamp, or prediction-resource fields are unusable.

### 11.4 Shared-resource ambiguity

Endpoints deployed only on `sharedResources` are unresolved for endpoint-attributed idle-cost findings because shared pool cost is not directly attributable to one endpoint.

### 11.5 Telemetry incompleteness

Partial or sparse endpoint telemetry is unresolved, not weak evidence.

Examples:

- query succeeds but no endpoint-scoped series are returned
- series are returned but timestamps do not prove sufficient full-window observation
- endpoint-scoped telemetry contains gaps that cannot be resolved from datapoint timestamps
- only age or trafficSplit suggests inactivity while canonical request telemetry is absent
