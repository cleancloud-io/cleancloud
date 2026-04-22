# aws.rds.instance.idle — Canonical Rule Specification

## 1. Intent

Detect provisioned standalone DB instances that are currently `available`, old enough to
evaluate, and show no trusted CloudWatch client-connection activity for the configured
observation window, so they can be reviewed as possible cleanup candidates.

This is a **CleanCloud-derived review heuristic**, not an AWS-native DB instance state.
It is a **read-only review-candidate rule** — not a delete-safe rule.

---

## 2. AWS API Grounding

Based on official RDS, CloudWatch, and pricing documentation.

### Key facts

1. `DescribeDBInstances` is the canonical API for enumerating provisioned DB instances in
   the scanned Region/account scope and supports pagination.
2. AWS explicitly notes that `DescribeDBInstances` can also return Amazon Neptune and Amazon
   DocumentDB DB instances.
3. `DBInstance.InstanceCreateTime` is a documented timestamp field.
4. `DBInstance.DBInstanceStatus` is a documented state field with many values including
   `available`, `creating`, `starting`, `stopped`, `stopping`, `backing-up`, `modifying`.
5. The RDS status guide states that `available` DB instances are billed.
6. `DBInstance.ReadReplicaSourceDBInstanceIdentifier`,
   `DBInstance.ReadReplicaSourceDBClusterIdentifier`, and `DBInstance.DBClusterIdentifier`
   are documented scope fields.
7. RDS publishes instance-level metrics in CloudWatch namespace `AWS/RDS`.
8. `DatabaseConnections` is the number of client network connections to the DB instance.
9. AWS explicitly states that `DatabaseConnections` does **not** include:
   - sessions that no longer have a network connection but which the database hasn't cleaned up
   - sessions created by the database engine for its own purposes
   - sessions created by the database engine's parallel execution capabilities
   - sessions created by the database engine job scheduler
   - Amazon RDS connections
10. CloudWatch `GetMetricStatistics` uses inclusive `StartTime`, exclusive `EndTime`, rounds
    `StartTime` based on lookback age, does not guarantee datapoint order, and imposes
    retention / `Period` constraints.
11. AWS pricing docs state that billing for DB instance hours starts when a DB instance
    becomes available and continues while it is running in an available state.
12. Fixed monthly USD cost estimates are not canonical from AWS docs.

### Implications

- Only `available` DB instances are eligible.
- Age thresholding is supportable because `InstanceCreateTime` is documented.
- `DatabaseConnections` Maximum is the sole required activity metric for this rule.
- `DatabaseConnections == 0` does not prove total absence of all engine activity; it only
  proves absence of observed client network connections in the metric contract.
- Connection pooling and proxy layers (RDS Proxy, PgBouncer, application connection pools)
  can reduce the reliability of instance-level observed client connection counts.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **"DB instance"** — an item returned by `DescribeDBInstances`.
- **"standalone"** — not a read replica of another DB instance, not a read replica of a
  DB cluster, and not a member of a DB cluster.
- **"idle"** — no observed client connection activity via trusted CloudWatch
  `DatabaseConnections` metric evidence for the full configured observation window.
- `idle_days_threshold` — operator-configurable, default 14.
- `observation_window_start_utc = now_utc − idle_days_threshold × 86400 seconds`
- `observation_window_end_utc = now_utc`
- `age_days = floor((now_utc − instance_create_time_utc) / 86400 seconds)`
- The rule is evaluated independently per Region.

**Scope boundary:** standalone provisioned DB instances only. Read replicas and cluster
members are out of scope.

---

## 4. Canonical Rule Statement

A DB instance is eligible only when **all** of the following are true:

- Stable DB instance identity exists
- `DBInstanceStatus == "available"`
- The instance is standalone
- `age_days >= idle_days_threshold`
- All `DatabaseConnections Maximum` datapoints in the observation window are exactly zero

No additional predicate may be required for baseline eligibility, including:
CPU utilisation thresholds, storage I/O thresholds, engine family, instance class,
Multi-AZ setting, allocated storage size, or tag presence/absence.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `DBInstanceIdentifier` | skip item |
| `db_instance_id` | `DBInstanceIdentifier` | skip item |
| `normalized_status` | `DBInstanceStatus` | skip item |
| `instance_create_time_utc` | `InstanceCreateTime` (tz-aware UTC) | skip item |
| `age_days` | floor((now − create_time) / 86400) | skip item |
| `db_cluster_identifier` | `DBClusterIdentifier` | null |
| `read_replica_source_db_instance_identifier` | `ReadReplicaSourceDBInstanceIdentifier` | null |
| `read_replica_source_db_cluster_identifier` | `ReadReplicaSourceDBClusterIdentifier` | null |
| `engine` | `Engine` | null |
| `engine_version` | `EngineVersion` | null |
| `db_instance_class` | `DBInstanceClass` | null |
| `multi_az` | `MultiAZ` (bool only) | null |
| `allocated_storage_gib` | `AllocatedStorage` (int only) | null |
| `storage_type` | `StorageType` | null |
| `dbi_resource_id` | `DbiResourceId` | null |
| `db_instance_arn` | `DBInstanceArn` | null |
| `tag_set` | `TagList` (list only) | `[]` |

Normalization requirements:
- String-valued fields: normalize only from non-empty strings.
- Timestamp fields: must be timezone-aware UTC before use; naive → skip item.
- Future `InstanceCreateTime` → skip item.

---

## 6. Idle-Activity Determination

CloudWatch is the **sole trusted activity source** for this rule.

**Required metric:**

| Field | Value |
|---|---|
| Namespace | `AWS/RDS` |
| Dimension | `DBInstanceIdentifier = db_instance_id` |
| Metric | `DatabaseConnections` |
| Statistic | `Maximum` |
| Period | `idle_days_threshold × 86400` (satisfies all CloudWatch retention constraints) |

**Interpretation:**

- If `DatabaseConnections Maximum > 0` anywhere in the observation window → **not idle** (skip item).
- The DB instance is idle only when datapoints exist and all `Maximum` values are exactly `0`.

**Datapoint completeness:**

- Missing datapoints **must not** be interpreted as zero connections.
- If `DatabaseConnections` returns no datapoints → **SKIP ITEM** (insufficient evidence).
- If `DatabaseConnections` retrieval fails → **FAIL RULE**.

---

## 7. Pricing / Cost Boundary

- `estimated_monthly_cost_usd = null` — no hardcoded per-engine or per-class estimates.

---

## 8. Deterministic Evaluation Order

1. Retrieve and fully paginate `DescribeDBInstances`.
2. Normalize each item.
3. For each normalized item:
   - `db_instance_id` absent → **SKIP ITEM**
   - `normalized_status` absent → **SKIP ITEM**
   - `normalized_status != "available"` → **SKIP ITEM**
   - `db_cluster_identifier` present → **SKIP ITEM**
   - `read_replica_source_db_instance_identifier` present → **SKIP ITEM**
   - `read_replica_source_db_cluster_identifier` present → **SKIP ITEM**
   - `instance_create_time_utc` absent/invalid/future → **SKIP ITEM**
   - `age_days < idle_days_threshold` → **SKIP ITEM**
   - Retrieve `DatabaseConnections Maximum`
   - API failure → **FAIL RULE**
   - No datapoints → **SKIP ITEM**
   - Any `Maximum > 0` → **SKIP ITEM**
   - Otherwise → **EMIT**

---

## 9. Exclusion Rules

1. `db_instance_id` absent → malformed identity
2. `normalized_status` absent → missing state signal
3. `normalized_status != "available"` → not currently evaluable
4. `db_cluster_identifier` present → cluster member (out of scope)
5. `read_replica_source_db_instance_identifier` present → DB instance read replica
6. `read_replica_source_db_cluster_identifier` present → cross-cluster read replica
7. `instance_create_time_utc` absent/naive/future → missing/invalid age source
8. `age_days < idle_days_threshold` → too young
9. `DatabaseConnections` returns no datapoints → insufficient trusted evidence
10. Any `DatabaseConnections Maximum > 0` → observed client connections

---

## 10. Failure Model

**Rule-level failures (FAIL RULE):**
- `DescribeDBInstances` request/pagination failure
- `DatabaseConnections` CloudWatch retrieval failure
- Permission failure for required APIs

**Item-level skips (SKIP ITEM):**
- Missing identity, status, or create-time
- Non-available status
- Replica / cluster-member scope exclusions
- Too young
- Insufficient CloudWatch datapoints
- Observed client connections

---

## 11. Evidence / Details Contract

### Required details fields

```
evaluation_path             = "idle-rds-instance-review-candidate"
db_instance_id
normalized_status           = "available"
instance_create_time        (ISO-8601 UTC)
age_days
idle_days_threshold
engine
engine_version
db_instance_class
database_connections_max
```

### Optional context fields

```
db_cluster_identifier
read_replica_source_db_instance_identifier
read_replica_source_db_cluster_identifier
multi_az
allocated_storage_gib
storage_type
dbi_resource_id
db_instance_arn
tag_set
```

### Required evidence wording

**Signals used** must state:
- DB instance Status is `available`
- The DB instance is standalone (not a read replica or cluster member)
- The DB instance age met the configured threshold
- `DatabaseConnections` Maximum was zero across the observation window
- The finding is based on a CleanCloud-derived idle heuristic over observed client network connections

**Signals not checked** must state major blind spots:
- Sessions without network connections that the database hasn't cleaned up
- Sessions created by the database engine for its own purposes
- Sessions created by parallel execution capabilities or job schedulers
- Amazon RDS connections
- RDS Proxy, PgBouncer, and application connection pools that can hide real usage while keeping observed client connection counts low or zero
- Planned future usage or disaster recovery intent
- Exact region-specific pricing impact

---

## 12. Confidence and Risk

| Condition | Confidence | Risk |
|---|---|---|
| Datapoints present, all `Maximum == 0`, all gates satisfied | `MEDIUM` | `MEDIUM` |

- **Do not** emit LOW-confidence findings when required metric data is unavailable — SKIP ITEM or FAIL RULE instead.
- `DatabaseConnections` has documented blind spots (2 item 9), so `MEDIUM` (not `HIGH`) is the ceiling.

---

## 13. Non-Goals / Blind Spots

This rule does not prove:
- The DB instance is safe to delete
- The DB instance has no engine-internal activity
- The DB instance had no uncounted sessions
- The DB instance will not be used again
- CPU or storage I/O was zero
- Backup, snapshot, or retention needs have been evaluated

---

## 14. Acceptance Scenarios

| # | Scenario | Expected |
|---|---|---|
| 1 | Standalone `available` instance, old enough, `DatabaseConnections Maximum == 0` across all datapoints | EMIT — confidence MEDIUM |
| 2 | Instance status not `available` | SKIP ITEM |
| 3 | DB instance read replica (`ReadReplicaSourceDBInstanceIdentifier` set) | SKIP ITEM |
| 4 | Cross-cluster read replica (`ReadReplicaSourceDBClusterIdentifier` set) | SKIP ITEM |
| 5 | DB cluster member (`DBClusterIdentifier` set) | SKIP ITEM |
| 6 | Younger than `idle_days_threshold` | SKIP ITEM |
| 7 | Any `DatabaseConnections Maximum > 0` | SKIP ITEM |
| 8 | `DatabaseConnections` returns no datapoints | SKIP ITEM |
| 9 | Missing/naive/future `InstanceCreateTime` | SKIP ITEM |
| 10 | `DescribeDBInstances` fails | FAIL RULE |
| 11 | `DatabaseConnections` retrieval fails | FAIL RULE |

---

## 15. Implementation Constraints

- Use `DescribeDBInstances` as the sole required inventory source.
- Use `DatabaseConnections Maximum` as the sole required activity metric.
- Exhaust pagination; no early exit.
- Use top-level `DBInstanceStatus` as the canonical state signal.
- Use documented `InstanceCreateTime` for age gating; naive → skip.
- Do not interpret missing datapoints as zero connections.
- Do not emit LOW-confidence findings when required CloudWatch data is absent.
- Do not require CPU or I/O metrics for baseline eligibility.
- Do not hardcode engine/class/storage monthly cost estimates.
- `estimated_monthly_cost_usd = null`.
