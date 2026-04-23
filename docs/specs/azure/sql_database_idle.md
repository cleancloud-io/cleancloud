# Azure Rule Spec — `azure.sql.database.idle`

## 1. Rule Identity

- **Rule ID:** `azure.sql.database.idle`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.Sql/servers/databases`
- **Finding resource_type:** `azure.sql.database`

---

## 2. Intent

Detect **dedicated Azure SQL Database single-database resources** that show **no observable user workload activity** over the configured idle window and therefore represent conservative cleanup or rightsizing review candidates.

This rule is deliberately **low-noise**. It is a **review-candidate** rule only, not proof that a database is delete-safe, not proof that no business continuity purpose exists, and not proof of a specific monthly saving.

---

## 3. Azure Documentation Grounding

### 3.1 Azure SQL Database metrics

Microsoft documents Azure Monitor metrics for `Microsoft.Sql/servers/databases`, including:

- `connection_successful`
- `sessions_count`
- `cpu_percent`
- `physical_data_read_percent`
- `log_write_percent`

Source:

- *Monitoring data reference for Azure SQL Database*
- *Monitor resource utilization and query activity for Azure SQL Database*

Rule consequence:

1. `connection_successful` alone is not a sufficient idle signal.
2. A conservative idle rule should require **multiple zero-activity metrics** for the same window.
3. If any required metric cannot be resolved reliably, the database must be skipped rather than emitted.
4. These are **Azure Monitor platform metrics** for `Microsoft.Sql/servers/databases`, not DMV-derived or Log Analytics-only signals.

### 3.2 Elastic pool billing semantics

Microsoft documents that databases in an elastic pool share pool resources and that **there is no per-database charge for elastic pools**; billing is at the pool level.

Source: *What are SQL elastic pools?*

Rule consequence:

Pooled databases must be **excluded** from this rule because per-database idleness does not directly imply per-database savings.

### 3.3 Purchasing models and serverless compute

Microsoft documents that Azure SQL Database supports DTU and vCore purchasing models, and that the vCore model includes a **serverless compute tier** that can automatically pause during inactive periods.

Sources:

- *Purchasing models in Azure SQL Database*
- *Serverless compute tier for Azure SQL Database*

Rule consequence:

1. Exact monthly savings cannot be inferred from SKU alone.
2. The rule must not use a flat monthly estimate.
3. Serverless requires special handling because inactivity can already be partially optimized by the platform.

### 3.4 Serverless auto-pause

Microsoft documents that, for serverless databases:

- databases can automatically pause after an inactivity delay
- when a database is **paused**, **compute cost is zero** and only storage is billed
- auto-pause is currently supported only in the General Purpose tier

Source: *Serverless compute tier for Azure SQL Database*

Rule consequence:

1. A database in a paused state must be **skipped**.
2. The rule should avoid treating already-paused serverless databases as high-confidence waste findings.

### 3.5 Control-plane resource shape

Microsoft REST/ARM documentation for `Microsoft.Sql/servers/databases` exposes database fields including:

- `status`
- `creationDate`
- `currentServiceObjectiveName`
- `elasticPoolId`
- `autoPauseDelay`
- `pausedDate`
- `resumedDate`
- `secondaryType`
- `sourceDatabaseId`
- `sku`
- `tags`

Source:

- *Databases - Get (REST API)*
- *Microsoft.Sql/servers/databases ARM / Bicep reference*

Rule consequence:

These fields provide the canonical control-plane inputs for state, pool membership, serverless pause context, and replica/secondary-shaped exclusions.

### 3.6 Geo-replication and failover groups

Microsoft documents that:

- active geo-replication creates **readable secondary databases**
- failover groups manage **replication and failover** for business continuity
- secondary databases can be used to **offload read-only workloads**

Sources:

- *Active geo-replication overview*
- *Failover groups overview*

Rule consequence:

Replica / secondary-shaped databases are valid operational resources and must be **skipped** to avoid false findings.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `database.id` is present and non-empty
2. `database.name` is present and non-empty
3. the optional region filter matches the normalized location
4. `database.status` resolves to exactly `"Online"`
5. the database is **not** the `master` system database
6. the database is old enough to cover the full observation window
7. the database is **not** in an elastic pool
8. the database is **not** replica / secondary-shaped under the replica exclusion contract
9. the database is **not** currently paused
10. all required activity metrics resolve reliably for the same window
11. all required activity metrics are zero for the same window

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the database is safe
- that the parent logical server is removable
- that the database is not required for DR, read scale-out, failback, or migration workflows
- that no future application rollout depends on the database
- that the database produces a specific monthly saving

---

## 6. Canonical Inputs

### 6.1 Required control-plane surfaces

The implementation may use:

- `sql_client.servers.list()`
- `sql_client.databases.list_by_server(resource_group, server_name)`
- Azure Monitor platform metrics for the database ARM id

It must **not** require DMV queries, in-database SQL access, or Log Analytics workspace data for rule correctness.

Optional per-database `get(...)` reads are allowed if needed for reliable normalization, but any lookup failure must remain conservative.

### 6.2 Idle window

- Configurable parameter: `idle_days`
- Default: `14`
- Evaluation window:
  - `window_end = now`
  - `window_start = now - idle_days`

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase ARM location string; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `status` | Compare case-sensitively to canonical Azure value `"Online"` after SDK/raw resolution. |
| `elastic_pool_id` | Treat non-empty value as pooled. Lowercase and trim trailing `/` when used for comparisons or diagnostics. |
| `secondary_type` | Treat non-empty value as replica / secondary context. |
| `source_database_id` | Treat non-empty value as lineage context; use only as a conservative secondary-shaped exclusion signal when paired with replica indicators or equivalent control-plane context. |
| `creation_date` | Parse as UTC instant. If absent or invalid, age is unknown. |
| `tags` | `database.tags or {}` — never `None` in output. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `id` absent, `None`, or empty | Skip |
| 8.2 | `name` absent, `None`, or empty | Skip |
| 8.3 | Region filter set and normalized location does not match | Skip |
| 8.4 | `status` does not resolve to `"Online"` | Skip |
| 8.5 | `name == "master"` | Skip |
| 8.6 | Database age is unknown or less than `idle_days` | Skip |
| 8.7 | Database is in an elastic pool | Skip |
| 8.8 | Replica / secondary exclusion contract is triggered | Skip |
| 8.9 | Current paused-state contract is triggered | Skip |
| 8.10 | One or more required metrics cannot be resolved reliably | Skip |
| 8.11 | Any required metric is non-zero over the idle window | Skip |
| 8.12 | All required signals resolve and all required metrics are zero over the idle window | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Online-state contract

Resolve database state in this order:

1. SDK projection such as `database.status`
2. nested/raw properties projection if present
3. otherwise unknown

Only `"Online"` is eligible for evaluation. Unknown or any other value must skip.

### 9.2 Age contract

Resolve `creation_date` in this order:

1. SDK projection such as `database.creation_date`
2. nested/raw properties projection such as `database.properties.creationDate`
3. otherwise unknown

Required behavior:

1. If `creation_date` is absent, invalid, or unparseable -> skip
2. If database age is less than `idle_days` -> skip
3. Only databases old enough for the full observation window are eligible

### 9.3 Elastic-pool exclusion contract

Treat the database as pooled when `elastic_pool_id` resolves to a non-empty value.

Pooled databases must skip because Microsoft documents that billing is at the **pool** level, not the database level.

### 9.4 Replica / secondary exclusion contract

Skip when reliable control-plane signals indicate the database is replica / secondary-shaped, including:

1. `secondary_type` resolves to a non-empty value
2. equivalent secondary/replica-shaped control-plane context is present

Canonical replica-signal mapping:

| Signal | Meaning |
|---|---|
| `secondary_type` | explicit replica / secondary indicator |
| `source_database_id` plus secondary/replica-shaped control-plane context | lineage tied to replica / restore / failover context |
| nested/raw replica fields such as `properties.secondaryType` or `properties.sourceDatabaseId` | conservative replica / secondary indicator when clearly present |

Conservative guidance:

1. Prefer SDK projections first.
2. Fall back to nested/raw properties fields only if needed.
3. If replica / secondary context cannot be resolved reliably, skip rather than emit.

This exclusion is required because Microsoft documents readable secondary databases and failover-group replicas as valid DR and read-scale resources.

### 9.5 Current paused-state contract

Skip when reliable control-plane signals indicate the database is currently paused, including:

1. `status == "Paused"`
2. equivalent paused-state control-plane context such as a current `paused_date` without evidence of a later resume

Required behavior:

1. Prefer SDK projections first.
2. Fall back to nested/raw properties fields only if needed.
3. If current paused state cannot be resolved reliably for a serverless-shaped database, skip rather than emit.

### 9.6 Activity-metrics contract

The following Azure Monitor **platform metrics** must be queried for the same `timespan`, where:

- `timespan = window_start / window_end`
- `window_start = now - idle_days`
- `window_end = now`

| Metric | REST name | Aggregation |
|---|---|---|
| Successful connections | `connection_successful` | `Total` |
| Sessions count | `sessions_count` | `Maximum` |
| CPU percentage | `cpu_percent` | `Maximum` |
| Data IO percentage | `physical_data_read_percent` | `Maximum` |
| Log IO percentage | `log_write_percent` | `Maximum` |

Interpretation:

1. If any aggregated datapoint returned for a required metric is `> 0`, treat the database as **active**
2. If Azure Monitor returns a usable metric series for the requested `timespan`, and all datapoints in that returned series are `0` or absent/`None`, that metric is **zero for the window**
3. If a metric query succeeds but the metric itself is absent from the response, treat that metric as **unknown** and skip
4. If a metric query succeeds and the metric is present but the series is empty, partial, or otherwise unusable for the requested `timespan`, treat that metric as **unknown** and skip
5. Implementations do **not** need bucket-by-bucket timestamp alignment across metrics; the contract is shared `timespan`, not identical datapoint timestamps
6. Missing data is **not** equivalent to proven zero activity unless Azure Monitor returned a usable metric series for that metric over the requested `timespan`

### 9.7 Emission threshold

Emit only when **all five required metrics** are zero for the full observation window.

This stronger threshold is required because:

- `connection_successful == 0` alone is not enough
- an existing session can produce work without a new connection
- read / write / CPU activity can reveal user workload even when connection counts are sparse

### 9.8 Context-only fields

The following may appear in details/evidence but must not create or suppress findings directly:

- `sku`
- `current_service_objective_name`
- `min_capacity`
- `max_size_bytes`
- `license_type`
- `zone_redundant`
- `auto_pause_delay`

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** use a flat estimate derived from DTU-era SKU tables
2. Do **not** infer cost from `current_service_objective_name` alone
3. Do **not** infer per-database savings for pooled databases
4. Document that Azure SQL pricing varies by purchasing model, tier, compute shape, storage, backup, and serverless behavior

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.sql.database.idle"` |
| `resource_type` | `"azure.sql.database"` |
| `resource_id` | Original ARM id from `database.id` |
| `region` | Normalized location |
| `risk` | `HIGH` |
| `confidence` | `HIGH` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required evidence

`signals_used` must clearly disclose:

1. database state is `"Online"`
2. database age is at least `idle_days`
3. database is not pooled
4. replica / secondary exclusion contract is not triggered
5. paused-state contract is not triggered
6. zero `connection_successful` over the idle window
7. zero `sessions_count` over the idle window
8. zero `cpu_percent` over the idle window
9. zero `physical_data_read_percent` over the idle window
10. zero `log_write_percent` over the idle window

`signals_not_checked` should include remaining blind spots such as:

1. planned future cutover or deployment intent
2. undeclared business continuity requirements
3. workload activity outside documented rule signals
4. exact Azure billing amount for this database

### 11.3 Required details

Details should include at least:

- `database_name`
- `server_name`
- `status`
- `current_service_objective_name`
- `sku_tier`
- `elastic_pool_id`
- `auto_pause_delay`
- `paused_date`
- `creation_date`
- `idle_days`
- `connection_successful`
- `sessions_count`
- `cpu_percent`
- `physical_data_read_percent`
- `log_write_percent`
- `tags`

---

## 12. Failure Behavior

- If the server list call raises, let the exception propagate
- If per-server database listing fails, skip that server rather than emit partial guesses
- If any individual database record is malformed or missing required fields, skip that database
- If any required metric query fails or returns unusable data, skip that database
- Do not silently emit on partial control-plane or metric data

---

## 13. Acceptance Examples

### 13.1 Must emit

1. A dedicated single database with `status == "Online"`, age >= 14 days, no elastic pool, no secondary/replica signals, not paused, and all five required metrics zero for 14 days -> **EMIT**

### 13.2 Must skip

1. `master` database -> **SKIP**
2. database in an elastic pool (`elastic_pool_id` present) -> **SKIP**
3. database status is not `"Online"` -> **SKIP**
4. serverless database currently paused -> **SKIP**
5. readable secondary / geo-secondary / failover secondary-shaped database -> **SKIP**
6. database younger than `idle_days` -> **SKIP**
7. `connection_successful == 0` but `sessions_count > 0` -> **SKIP**
8. `connection_successful == 0` but `cpu_percent > 0` -> **SKIP**
9. any required metric query fails or is unavailable -> **SKIP**

---

## 14. Anti-Goals

Implementations must **not**:

1. treat `connection_successful == 0` as sufficient proof of idleness by itself
2. emit for pooled databases
3. emit for currently paused serverless databases
4. emit for replica / DR-shaped databases
5. use fixed monthly price tables for findings

---

## 15. Rule Summary

Rule: `azure.sql.database.idle`

- **Signal:** dedicated single database with zero successful connections, zero sessions, zero CPU, zero data IO, and zero log IO over `idle_days`
- **Primary exclusions:** pooled databases, replicas / secondaries, paused databases, young databases, non-Online databases
- **Cost model:** no flat estimate; `estimated_monthly_cost_usd = None`
