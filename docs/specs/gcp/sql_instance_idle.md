# GCP Rule Spec - `gcp.sql.instance.idle`

## 1. Rule Identity

- **Rule ID:** `gcp.sql.instance.idle`
- **Provider:** GCP
- **Resource type:** Cloud SQL instance
- **Finding resource_type:** `gcp.sql.instance`

---

## 2. Intent

Detect **primary Cloud SQL instances** that show **no observed active database connections** for the full configured idle window and therefore represent conservative review candidates for cleanup, stop/start reconsideration, or rightsizing.

This rule is deliberately **precision-first**. It is a **review-candidate** rule only, not proof that the instance is safe to delete, not proof that no business continuity purpose exists, and not proof of a specific monthly saving.

---

## 3. GCP Documentation Grounding

### 3.1 Cloud SQL instance resource exposes the canonical control-plane fields

Google documents the Cloud SQL `DatabaseInstance` resource with fields including:

1. `state`
2. `instanceType`
3. `name`
4. `region`
5. `databaseVersion`
6. `createTime`
7. `masterInstanceName`
8. `settings`
9. `failoverReplica`
10. `replicaNames`
11. `tags`

Within `settings`, Google documents fields including:

1. `tier`
2. `availabilityType`
3. `dataDiskSizeGb`
4. `dataDiskType`
5. `userLabels`
6. backup configuration fields

Source:

- *Resource: instances*

URL:

- https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances

Rule consequence:

1. Instance eligibility must be based on documented Cloud SQL Admin API fields, not inferred state.
2. `createTime` is the canonical age signal for full-window coverage.
3. Tier / HA / storage fields are valid context, but not enough for a trustworthy fixed cost estimate.

### 3.2 Cloud SQL documents a canonical active-connections metric

Google documents Cloud SQL metrics exposed through Google Cloud Observability, including:

- `cloudsql.googleapis.com/database/active_connections`

Google documents these metrics on the `cloudsql_database` monitored resource and documents that Cloud SQL metrics are sampled every 60 seconds and can be delayed by up to 165 seconds before visibility.

Google documents the `cloudsql_database` monitored resource with identity labels including:

1. `project_id`
2. `location`
3. `resource_id`
4. `database`

Sources:

- *Cloud SQL metrics*
- *Monitored resource list*

URLs:

- https://docs.cloud.google.com/sql/docs/mysql/admin-api/metrics
- https://cloud.google.com/monitoring/api/resources#tag_cloudsql_database

Rule consequence:

1. The idle rule must use the documented `database/active_connections` metric, not undocumented or stale alternatives.
2. The observation window must account for documented metric visibility lag.
3. Metric-to-instance matching must use documented monitored-resource identity labels only, with no best-guess fallback.
4. If the metric cannot be resolved reliably for an instance, that instance must be skipped rather than emitted.

### 3.3 Read replicas are operationally special even though they are billed

Google documents that read replicas:

1. offload read queries and analytics traffic from the primary
2. can be promoted for disaster recovery or corruption recovery
3. are read-only copies updated in near real time

Google pricing documentation also states:

1. read replicas and failover replicas are charged at the same rate as stand-alone instances

Sources:

- *Replication*
- *Cloud SQL pricing*

URLs:

- https://cloud.google.com/sql/docs/mysql/replication
- https://cloud.google.com/sql/pricing

Rule consequence:

1. Replica-shaped instances should be treated conservatively because zero client connections does not prove lack of operational value.
2. This rule should exclude documented read-replica shapes even though they remain billable.

### 3.4 HA / regional instances remain billable and operationally important

Google documents that:

1. a high-availability Cloud SQL instance is a regional instance with a primary and standby
2. the standby instance cannot be used for read queries
3. an HA-configured instance costs about twice as much as a standalone instance

Source:

- *High availability*

URL:

- https://cloud.google.com/sql/docs/mysql/high-availability

Rule consequence:

1. HA does **not** make an instance ineligible.
2. HA materially increases cost/risk context and should be surfaced in evidence/details when present.

### 3.5 Cloud SQL pricing is too variable for a fixed rule-time estimate

Google documents that Cloud SQL pricing varies by factors including:

1. edition
2. region
3. vCPU and memory
4. high availability
5. storage and networking
6. commitment model
7. engine / licensing surface

Source:

- *Cloud SQL pricing*

URL:

- https://cloud.google.com/sql/pricing

Rule consequence:

1. The rule must not hardcode a stale tier lookup table or a single-region estimate.
2. `estimated_monthly_cost_usd` should remain `None` unless a future implementation computes pricing from documented current pricing inputs.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `instance.name` is present and non-empty
2. `instance.region` is present and non-empty
3. the optional region filter matches the normalized region
4. `instance.state` resolves to exactly `"RUNNABLE"`
5. `instance.instanceType` resolves to exactly `"CLOUD_SQL_INSTANCE"`
6. replica exclusion contract is **not** triggered
7. `createTime` is present, parseable, and old enough to cover the full observation window
8. the Cloud Monitoring metric contract resolves reliably for the instance
9. the maximum observed `active_connections` value is exactly zero for the full observation window

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the instance is safe
- that the instance is not needed for DR, failover, migration, or future reactivation
- that short-lived burst traffic never occurred between metric samples
- that zero active client connections implies zero internal or background workload
- that the instance has zero storage, backup, or network cost
- that the instance produces a specific monthly saving

---

## 6. Canonical Inputs

### 6.1 Required control-plane surface

| Surface | Purpose |
|---|---|
| `instances.list` | enumerate Cloud SQL instances and their lifecycle, type, region, age, tier, HA, storage, and replica context |

### 6.2 Required monitoring surface

| Surface | Purpose |
|---|---|
| `cloudsql.googleapis.com/database/active_connections` on `cloudsql_database` | determine whether any active connections were observed during the idle window |

### 6.3 Idle window

| Parameter | Meaning |
|---|---|
| `idle_days` | Review threshold in days; default `14` |

Window definition:

1. `window_end` must account for documented metric visibility lag and therefore should be set conservatively after the latest potentially delayed point (for example, `now - 5 minutes`)
2. `window_start = window_end - idle_days`

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `name` | Non-empty string or unusable. |
| `region` | Preserve exact documented region string; compare by exact string equality only. |
| `state` | Resolve from documented instance `state` and compare case-sensitively to canonical values such as `"RUNNABLE"`, `"SUSPENDED"`, `"MAINTENANCE"`, and `"FAILED"`. |
| `instance_type` | Resolve from documented `instanceType` and compare case-sensitively to canonical values such as `"CLOUD_SQL_INSTANCE"`, `"READ_REPLICA_INSTANCE"`, and `"ON_PREMISES_INSTANCE"`. |
| `create_time` | Parse from documented RFC3339 `createTime`. Unparseable values are unusable. |
| `master_instance_name` | Preserve exact documented string when present. |
| `database_version` | Preserve exact documented value when present; otherwise unknown. |
| `tier` | Preserve exact `settings.tier` when present; otherwise unknown. |
| `availability_type` | Preserve exact `settings.availabilityType` when present; otherwise unknown. |
| `data_disk_size_gb` | Parse as non-negative integer when possible; otherwise preserve unknown/`0` for context only. |
| `data_disk_type` | Preserve exact `settings.dataDiskType` when present; otherwise unknown. |
| `backup_retained_count` | Parse as non-negative integer when possible; otherwise unknown. |
| `labels` | `settings.userLabels or {}` - never `None` in output. |
| `metric_coverage` | `FULL` only when the full idle window is covered within documented sampling/visibility tolerance; otherwise unresolved. |
| `active_connections_max` | Maximum numeric value observed from the documented active-connections metric over the full eligible window. If unresolved, the metric is unusable. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | instance record malformed or `name` absent / empty | Skip |
| 8.2 | `region` absent / empty | Skip |
| 8.3 | region filter set and `region` does not exactly match | Skip |
| 8.4 | `state` absent, unknown, or not exactly `"RUNNABLE"` | Skip |
| 8.5 | `instanceType` absent, unknown, or not exactly `"CLOUD_SQL_INSTANCE"` | Skip |
| 8.6 | replica exclusion contract is triggered | Skip |
| 8.7 | `createTime` absent or unparsable | Skip |
| 8.8 | instance creation time is newer than `window_start` | Skip |
| 8.9 | active-connections metric cannot be resolved reliably for the full window | Skip |
| 8.10 | `active_connections_max > 0` anywhere in the full window | Skip |
| 8.11 | all required signals resolve and `active_connections_max == 0` for the full window | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Inventory contract

Required behavior:

1. Enumerate instances from `instances.list`.
2. Fully iterate paged results if pagination is present.
3. Malformed instance records must be skipped item-by-item rather than failing the whole rule.

### 9.2 Serving-state contract

Google documents Cloud SQL instance states including:

- `RUNNABLE`
- `SUSPENDED`
- `PENDING_DELETE`
- `PENDING_CREATE`
- `MAINTENANCE`
- `FAILED`
- `ONLINE_MAINTENANCE`

Required behavior:

1. Only `state == "RUNNABLE"` is eligible.
2. `MAINTENANCE` and `ONLINE_MAINTENANCE` must skip because they can show temporarily low or zero connections during service-managed transitions.
3. Unknown or any other state must skip.

### 9.3 Primary-instance contract

Required behavior:

1. Only `instanceType == "CLOUD_SQL_INSTANCE"` is eligible.
2. `READ_REPLICA_INSTANCE` must skip.
3. `ON_PREMISES_INSTANCE` must skip.

### 9.4 Replica exclusion contract

Required behavior:

1. If `instanceType == "READ_REPLICA_INSTANCE"`, skip.
2. If `masterInstanceName` is present and non-empty, treat the instance as replica-shaped and skip.
3. `replicaNames` on its own does **not** make a primary instance ineligible.

Rationale:

Google documents read replicas as read-offload and disaster-recovery resources. Zero observed active connections does not prove lack of value for these replica-shaped instances.

### 9.5 Age / full-window coverage contract

Required behavior:

1. Parse `createTime` as RFC3339.
2. Compute `window_end` with a conservative buffer for documented metric visibility lag.
3. Compute `window_start = window_end - idle_days`.
4. Emit only if `create_time <= window_start`.
5. Partial-window evaluation is not allowed.
6. If `createTime` cannot be parsed, skip rather than guess.

### 9.6 Monitoring metric contract

Required behavior:

1. Query the documented metric `cloudsql.googleapis.com/database/active_connections`.
2. Query it on the documented `cloudsql_database` monitored resource.
3. Match time series to the Cloud SQL instance only by exact documented monitored-resource identity labels:
   - `project_id == project_id`
   - `location == instance.region`
   - `resource_id == instance.name` (case-sensitive exact match required)
4. Use the `database` monitored-resource label only as a series dimension; do not use it to best-guess an instance match when the identity labels do not match exactly.
5. If the identity labels do not match exactly, skip rather than guess.
6. Use the full observation window defined in section **6.3**.
7. No time series returned for the instance means unresolved coverage and must skip.
8. Missing points, large missing chunks, parse failures, or query failures for that instance mean unresolved coverage and must skip.
9. Small gaps consistent with documented sampling and visibility lag may be tolerated; partial-window or materially sparse coverage must not be treated as idle.
10. Do **not** substitute undocumented or stale metric names such as `cloudsql.googleapis.com/database/network/connections`.
11. Do **not** substitute CPU metrics, connection-attempt metrics, or other fallback signals for the documented active-connections metric.

### 9.7 Idle decision contract

Required behavior:

1. Aggregate across **all** matched `active_connections` time series for the instance, including all matched `database` label variants.
2. Resolve the maximum observed `active_connections` value across all matched series and across the full eligible window.
3. If any matched point has a value greater than zero, treat the instance as active.
4. Emit only when the maximum observed value is exactly zero for the full eligible window.

Rationale:

The documented metric is a GAUGE sampled periodically. Zero observed active connections for the full eligible window is a strong review signal, but it is still not proof that no short-lived work occurred between samples or that the engine had no internal/background activity.

### 9.8 Region-filter contract

Required behavior:

1. Compare the optional `region_filter` only to the documented Cloud SQL instance `region`.
2. Do **not** derive region from monitoring labels, zones, or IP metadata when the control-plane region is absent or unusable.

### 9.9 HA context contract

Required behavior:

1. `availabilityType == "REGIONAL"` should not exclude the instance.
2. HA / regional context should be surfaced in evidence/details when present.

### 9.10 Cost model contract

Required behavior:

1. `estimated_monthly_cost_usd = None`
2. Do **not** use a hardcoded tier-to-price lookup table.
3. Do **not** use a single-region default pricing assumption.
4. Do **not** estimate total cost from tier alone.
5. Tier, HA, storage, and backup configuration may appear as context only.

Rationale:

Google documents Cloud SQL pricing as varying by edition, region, compute shape, HA, storage, networking, and commitment model. A stale or partial lookup table is not trustworthy enough for canonical rule output.

### 9.11 Confidence contract

Required behavior:

| Condition | Confidence |
|---|---|
| Finding emitted | `HIGH` |

Rationale:

Zero observed active connections over the full eligible monitoring window is a strong Cloud Monitoring-backed idle signal, provided the metric contract resolves reliably.

### 9.12 Risk contract

Required behavior:

| Condition | Risk |
|---|---|
| Finding emitted | `HIGH` |

Rationale:

Database resources are high-blast-radius assets. Even clearly idle-looking Cloud SQL instances can still carry application, migration, DR, or compliance importance.

### 9.13 Failure behavior contract

Required behavior:

1. `cloudsql.instances.list` permission failures should surface as a permission error.
2. `monitoring.timeSeries.list` permission failures should surface as a permission error.
3. If the Cloud SQL Admin API is unavailable / disabled for the project, returning no findings is acceptable.
4. If Cloud Monitoring is unavailable for the project, returning no findings is acceptable.
5. Per-instance metric resolution failures should skip that instance rather than emitting from incomplete evidence.

---

## 10. Finding Shape

### 10.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"gcp"` |
| `rule_id` | `"gcp.sql.instance.idle"` |
| `resource_type` | `"gcp.sql.instance"` |
| `resource_id` | canonical project/instance path |
| `region` | instance region |
| `confidence` | `HIGH` |
| `risk` | `HIGH` |
| `estimated_monthly_cost_usd` | `None` |

### 10.2 Required evidence

`signals_used` must clearly disclose:

1. instance state is `RUNNABLE`
2. instance type is primary Cloud SQL (`CLOUD_SQL_INSTANCE`)
3. metric coverage is full for the configured window
4. no observed active connections over the configured window
5. `active_connections_max = 0`
6. the exact idle window in days
7. database version
8. tier when present
9. HA / regional context when present
10. storage / backup context when present

`signals_not_checked` should include remaining blind spots such as:

1. short-lived workload bursts between metric samples were not evaluated
2. business / application retention intent
3. migration, failback, or future reactivation intent
4. storage, backup, and network savings were not estimated
5. engine-specific internal work not represented by active client connections alone

### 10.3 Required details

Details should include at least:

- `instance_name`
- `database_version`
- `tier`
- `region`
- `instance_type`
- `created_at`
- `idle_days_threshold`
- `metric_coverage`
- `active_connections_max`
- `ha_enabled`
- `labels`

When present, details should also include:

- `master_instance_name`
- `availability_type`
- `data_disk_size_gb`
- `data_disk_type`
- `backup_retained_count`

---

## 11. Failure Behavior

- Cloud SQL list permission denied -> raise permission error
- Monitoring permission denied -> raise permission error
- Cloud SQL Admin API disabled / not found -> return no findings
- Cloud Monitoring unavailable -> return no findings
- Malformed instance record -> skip that item
- Unusable per-instance activity metric -> skip that item
