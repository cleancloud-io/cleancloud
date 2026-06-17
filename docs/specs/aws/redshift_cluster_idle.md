# aws.redshift.cluster.idle — Canonical Rule Specification

## 1. Intent

Detect provisioned Redshift clusters that are in `available` status but have had zero observed
database connections over the configured idle window, so they can be reviewed as candidates for
pausing or deletion.

This is a **CleanCloud-derived idle heuristic** based on Redshift cluster metadata and CloudWatch
activity metrics. It is a **read-only review-candidate rule** — not a stop-safe or delete-safe
rule.

---

## 2. AWS API Grounding

Based on official Redshift provisioned cluster API and CloudWatch documentation.

### Key facts

1. `DescribeClusters` is the canonical inventory API for provisioned Redshift clusters and supports
   pagination via `Marker` (max 100 records per page).
2. `DescribeClusters` returns `Cluster` objects including `ClusterIdentifier`,
   `ClusterNamespaceArn`, `ClusterStatus`, `ClusterAvailabilityStatus`, `ClusterCreateTime`,
   `NodeType`, `NumberOfNodes`, `Endpoint`, `Tags`, and `TotalStorageCapacityInMegaBytes`.
3. `ClusterStatus` has 20 valid values including `available`, `paused`, `creating`, `deleting`,
   `modifying`, `resizing`, `rebooting`, `renaming`, and various `incompatible-*` states. The
   value `paused` indicates compute billing is suspended (storage only).
4. `ClusterAvailabilityStatus` has 5 valid values: `Available`, `Unavailable`, `Maintenance`,
   `Modifying`, `Failed`.
5. There is **no** `LastQueryTime`, `LastActivityTime`, or equivalent field in the API response.
   Idleness must be inferred from CloudWatch metrics.
6. Paused clusters do **not** publish hardware CloudWatch metrics. `DatabaseConnections`,
   `CPUUtilization`, `ReadIOPS`, etc. return no datapoints while a cluster is paused.
7. Paused clusters pay storage only — they are already cost-optimized from a compute perspective
   and should be excluded from this rule.
8. Redshift Serverless uses a separate boto3 client (`redshift-serverless`) and separate APIs
   (`list_workgroups`, `get_workgroup`). `DescribeClusters` does **not** return serverless
   workgroups. Serverless is out of scope for this rule.
9. CloudWatch namespace `AWS/Redshift` publishes metrics automatically at 1-minute intervals.
   Key idle-detection metrics:
   - `DatabaseConnections` — number of database connections to the cluster. Dimension:
     `ClusterIdentifier` only. 1-minute interval.
   - `ReadIOPS` / `WriteIOPS` — average disk read/write operations per second. Dimension:
     `ClusterIdentifier` or `ClusterIdentifier` + `NodeID`. 1-minute interval.
10. `QueriesCompletedPerSecond` is **not supported on single-node clusters** and reports at
    5-minute intervals. It must not be used as the primary idle signal.
11. Fixed monthly USD cost estimates are not canonical from the fetched AWS docs.

### Implications

- Inventory must be built by fully paginating `DescribeClusters`.
- Idleness is determined by CloudWatch `DatabaseConnections` (Sum = 0) over the idle window.
  `ReadIOPS` and `WriteIOPS` (Sum ≈ 0) provide secondary confirmation.
- `ClusterStatus == "paused"` clusters must be excluded — they already pay storage only.
- Only `ClusterStatus == "available"` clusters are eligible for idle evaluation.
- `QueriesCompletedPerSecond` must not be a required signal due to the single-node limitation.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **Cluster** — an item returned by `DescribeClusters`.
- **Eligible status** — `ClusterStatus == "available"`.
- `idle_days_threshold` — operator-configurable integer >= 1, default 14.
- `idle_window_seconds` — `idle_days_threshold × 86400`.
- **evaluation_window_start_utc** — `now_utc - idle_window_seconds`.
- **evaluation_window_end_utc** — `now_utc`.
- **idle** — `DatabaseConnections` Sum = 0 over a single full-window aggregate period, with at
  least one datapoint returned (missing data = inconclusive, not idle).

### Explicit scope boundary

This rule applies only to provisioned Redshift clusters whose `ClusterStatus` is `available`.

Out of scope:

- `paused` clusters (already cost-optimized, storage only)
- `creating`, `deleting`, `modifying`, `resizing`, `rebooting`, `renaming`, `final-snapshot`
- All `incompatible-*` and `hardware-failure` statuses
- `storage-full`, `rotating-keys`, `updating-hsm`, `cancelling-resize`
- `available, prep-for-resize` and `available, resize-cleanup` (transient states)
- Redshift Serverless workgroups (separate service, separate APIs)
- exact price estimation, accrued USD estimation, or savings estimation

---

## 4. Canonical Rule Statement

A provisioned Redshift cluster is flagged as idle only when **all** of the following are true:

- stable cluster identity exists (`ClusterIdentifier`)
- `ClusterStatus == "available"`
- `ClusterCreateTime` is valid and the cluster is older than `idle_days_threshold`
- CloudWatch `DatabaseConnections` Sum = 0 over a single full-window aggregate period, with at
  least one datapoint returned (no datapoints = inconclusive, skip)

No additional predicate may be required for baseline eligibility, including node type, node count,
or static cost heuristics.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

### 5.1 Describe-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `cluster_identifier` | `ClusterIdentifier` | skip item |
| `cluster_status` | `ClusterStatus` | skip item |
| `cluster_availability_status` | `ClusterAvailabilityStatus` | null |
| `cluster_create_time_utc` | `ClusterCreateTime` (tz-aware UTC) | skip item |
| `node_type` | `NodeType` | null |
| `number_of_nodes` | `NumberOfNodes` | null |
| `cluster_namespace_arn` | `ClusterNamespaceArn` | null |
| `cluster_endpoint_address` | `Endpoint.Address` | null |
| `cluster_endpoint_port` | `Endpoint.Port` | null |
| `total_storage_capacity_mb` | `TotalStorageCapacityInMegaBytes` | null |

### 5.2 CloudWatch-Derived Fields

| Canonical field | Derivation |
|---|---|
| `database_connections_sum` | Sum of `DatabaseConnections` over evaluation window |
| `read_iops_sum` | Sum of `ReadIOPS` over evaluation window |
| `write_iops_sum` | Sum of `WriteIOPS` over evaluation window |
| `is_idle` | `true` when `database_connections_sum == 0` |

### 5.3 Derived Fields

| Canonical field | Derivation |
|---|---|
| `cluster_age_days` | `max(0, floor((now_utc - cluster_create_time_utc).total_seconds() / 86400))` |
| `resource_id` | `cluster_namespace_arn` when present; else `cluster_identifier` |

Normalization requirements:

- String-valued fields: normalize only from non-empty strings.
- Timestamp fields: must be timezone-aware UTC before use; naive timestamps must skip the item.
- `ClusterCreateTime` future beyond `clock_skew_tolerance_seconds` (300) must skip the item.
- Clusters younger than `idle_days_threshold` must be skipped — insufficient evaluation history.

---

## 6. Idle Signal Contract

This rule evaluates **connection and I/O activity**, not query correctness or business value.

### 6.1 Primary idle signal

- Query CloudWatch `DatabaseConnections` with dimension `ClusterIdentifier` over the evaluation
  window using `Sum` statistic with `Period = idle_window_seconds` (single full-window aggregate).
- A single-period aggregate avoids the gap problem: if CloudWatch returns no datapoints, the
  cluster may have been paused or otherwise unavailable during the window — treat missing data as
  **inconclusive** and **SKIP ITEM** (do not emit).
- If the returned Sum is 0, the cluster is idle — no client has connected.
- If CloudWatch returns no datapoints at all, **SKIP ITEM** — insufficient evidence.

### 6.2 Secondary confirmation signals (best-effort)

- `ReadIOPS` Sum ≈ 0 and `WriteIOPS` Sum ≈ 0 over the same window confirms no disk activity.
- These are **optional context only** — the primary idle decision is based on
  `DatabaseConnections` alone and must not change based on secondary signal availability.
- If secondary metric retrieval fails or returns no datapoints: **omit from details**, set the
  corresponding field to `null`, and **degrade confidence to MEDIUM**. Do not change the primary
  idle decision or skip the item.

### 6.3 Explicit blind spots

This rule does **not** prove:

- that the cluster has no business value or planned future use
- that pausing or deleting the cluster is safe
- that the cluster is not used for disaster recovery or compliance retention
- exact price impact or savings impact

---

## 7. Pricing / Cost Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode instance-price tables, accrued USD estimates, or regional billing assumptions.
- `NodeType` and `NumberOfNodes` are emitted as context for the reviewer to assess cost impact.

---

## 8. Deterministic Evaluation Order

1. Retrieve and fully paginate `DescribeClusters`.
2. Normalize each cluster.
3. For each normalized cluster:
   - identity absent → **SKIP ITEM**
   - `cluster_status` absent → **SKIP ITEM**
   - `cluster_status != "available"` → **SKIP ITEM**
   - `cluster_availability_status` is `Unavailable`, `Maintenance`, or `Failed` (when
     present) → **SKIP ITEM**
   - `cluster_create_time_utc` absent / naive / future beyond skew tolerance → **SKIP ITEM**
   - `cluster_age_days < idle_days_threshold` → **SKIP ITEM**
4. Query CloudWatch `DatabaseConnections` for the cluster over the evaluation window using a
   single full-window aggregate period.
5. CloudWatch permission or request failure → **FAIL RULE**.
6. CloudWatch returned no datapoints → **SKIP ITEM** (insufficient evidence).
7. `DatabaseConnections` Sum > 0 → **SKIP ITEM** (not idle).
8. Otherwise → **EMIT**.

No raw AWS field access after normalization.

---

## 9. Exclusion Rules

1. identity absent (`cluster_identifier`) → malformed inventory item
2. status absent → missing primary state
3. status not `available` → out of scope (includes `paused`, `creating`, `deleting`, etc.)
4. `cluster_availability_status` is `Unavailable`, `Maintenance`, or `Failed` → transient state
5. `ClusterCreateTime` absent / naive / future → missing or invalid timestamp
6. cluster younger than `idle_days_threshold` → insufficient evaluation history
7. CloudWatch returned no datapoints → insufficient evidence
8. `DatabaseConnections` Sum > 0 → not idle

---

## 10. Failure Model

**Rule-level failures (FAIL RULE):**

- `DescribeClusters` request or pagination failure
- `DescribeClusters` permission failure
- CloudWatch `GetMetricStatistics` permission failure
- CloudWatch `GetMetricStatistics` request failure for the primary `DatabaseConnections` metric
  (any non-permission error is still a rule failure — this is a required signal, not optional
  context)

**Item-level skips (SKIP ITEM):**

- malformed identity or missing required fields
- non-`available` status
- `cluster_availability_status` is `Unavailable`, `Maintenance`, or `Failed` (when present)
- cluster too young for evaluation
- non-zero database connections
- CloudWatch returned no datapoints for `DatabaseConnections` (insufficient evidence)

---

## 11. Evidence / Details Contract

### Required details fields

```
evaluation_path                  = "idle-redshift-cluster-review-candidate"
cluster_identifier
resource_id
cluster_status                   = "available"
cluster_create_time
cluster_age_days
node_type
number_of_nodes
idle_days_threshold
evaluation_window_start
evaluation_window_end
database_connections_sum
is_idle                          = true
```

### Optional context fields

```
cluster_availability_status
cluster_endpoint_address
cluster_endpoint_port
read_iops_sum
write_iops_sum
total_storage_capacity_mb
```

### Required evidence wording

**Signals used** must state:

- cluster status is `available`
- `DatabaseConnections` Sum was 0 over the evaluation window
- the idle window duration

**Signals not checked** must state major blind spots:

- business value or planned future use
- whether pausing or deleting is safe
- disaster recovery or compliance retention purpose
- exact price impact or savings impact

---

## 12. Confidence Model

| Condition | Confidence |
|---|---|
| `database_connections_sum == 0` AND `read_iops_sum == 0` AND `write_iops_sum == 0` (all present) | `HIGH` |
| `database_connections_sum == 0` AND either secondary signal is `null` (missing/failed) | `MEDIUM` |
| `database_connections_sum == 0` only (secondary signals not zero) | `MEDIUM` |

No LOW finding should be emitted.

---

## 13. Risk Model

| Condition | Risk |
|---|---|
| `number_of_nodes >= 4` | `HIGH` |
| all other emitted findings | `MEDIUM` |

Risk is about likely waste severity based on cluster size, not proof of safe action. Node count
is a stable shape signal that does not require maintaining a list of instance types.

---

## 14. Title and Reason Contract

| Condition | Title | Reason |
|---|---|---|
| Idle Redshift cluster finding | `"Idle Redshift cluster review candidate"` | `"Available Redshift cluster has had zero database connections over the configured idle window"` |

---

## 15. Non-Goals

This rule does **not**:

- infer exact billing from static node-price tables
- cover Redshift Serverless workgroups (separate service, separate APIs)
- cover paused clusters (already cost-optimized)
- determine whether a cluster should be paused or deleted automatically
- use `QueriesCompletedPerSecond` as a required signal (not supported on single-node clusters)
