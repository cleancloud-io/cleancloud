# GCP Rules

10 rules (5 hygiene + 5 AI/ML). AI/ML rules require `--category ai`.

← [Back to index](../rules.md)

| Rule ID | Cost Surface | What It Detects |
|---|---|---|
| `gcp.compute.vm.stopped` | Compute | TERMINATED or STOPPED VMs for 30+ days (attached disk charges continue) |
| `gcp.compute.disk.unattached` | Storage | Persistent Disks in READY state with no attached VM |
| `gcp.compute.snapshot.old` | Storage | Disk snapshots older than 90 days |
| `gcp.compute.ip.unused` | Network | Reserved static IPs in RESERVED state |
| `gcp.sql.instance.idle` | Platform | Cloud SQL instances with zero connections 14+ days |
| `gcp.vertex.endpoint.idle` | AI/ML | Vertex AI endpoints with dedicated capacity and zero predictions 14+ days |
| `gcp.vertex.workbench.idle` | AI/ML | Vertex AI Workbench instances with no activity 14+ days |
| `gcp.vertex.training_job.long_running` | AI/ML | Vertex AI jobs running beyond threshold |
| `gcp.tpu.idle` | AI/ML | Cloud TPU nodes with near-zero utilization 7+ days |
| `gcp.vertex.featurestore.idle` | AI/ML | Vertex AI Feature Stores with zero serving requests 30+ days |

---

## Compute

#### `gcp.compute.vm.stopped`
**Detects:** Compute Engine VM instances in `TERMINATED` or `STOPPED` lifecycle state for `max_age_days`+ days; attached disk charges continue regardless of instance state

**Confidence / Risk:**
- `stop_age_days >= 90`: HIGH
- `max_age_days <= stop_age_days < 90`: MEDIUM

**Cost:** `estimated_monthly_cost_usd = None` — attached resources (disks, static IPs) bill by their own pricing surface; no flat estimate is appropriate

**Permissions:** `compute.instances.list` (roles/compute.viewer)

**Params:** `max_age_days` (default: 30)

**Exclusions:**
- instance record malformed or `name` absent/empty
- aggregated scope key not in exact `zones/ZONE` form
- region filter set and region is unknown or does not match
- instance has proven active MIG membership (`created-by` metadata referencing `instanceGroupManagers/...`)
- lifecycle state not `TERMINATED` or `STOPPED`
- `lastStopTimestamp` absent or unparsable
- stop age < `max_age_days`

**Spec:** [docs/specs/gcp/vm_stopped.md](../specs/gcp/vm_stopped.md)

---

## Storage

#### `gcp.compute.disk.unattached`
**Detects:** Persistent Disks in `READY` state with an explicitly empty `users[]` (no attached VM); covers both zonal and regional disks via aggregated inventory

**Confidence / Risk:**
- Zonal, last detach ≥ 7 days ago (or never detached): HIGH
- Zonal, last detach 24 h – 7 days ago: MEDIUM — may still be mid-deletion pipeline
- Either scope, last detach < 24 h ago: LOW — very likely mid-pipeline
- Regional, unattached (any age): MEDIUM — regional disks are documented HA/failover infrastructure

**Cost:** `estimated_monthly_cost_usd = None` — GCP disk pricing varies by type, region, currency, and provisioned performance; the finding surfaces disk type and size only

**Permissions:** `compute.disks.list` (roles/compute.viewer)

**Params:** none (no user-configurable threshold — detection is based on current attachment state)

**Exclusions:** disk record malformed or name absent; aggregated scope key unresolvable (e.g. `global`); disk `status` not exactly `READY`; `users` field absent or not an explicit empty list; any non-empty `users` entry (attached disk)

**Spec:** [docs/specs/gcp/disk_unattached.md](../specs/gcp/disk_unattached.md)

#### `gcp.compute.snapshot.old`
**Detects:** Standard disk snapshots older than `max_age_days` that are not part of an automated backup workflow

**Confidence / Risk:** LOW (age alone is not proof of waste; incremental chain sharing means deletion may not reclaim billed storage proportionally) / LOW

**Cost:** `estimated_monthly_cost_usd = None` — snapshot pricing varies by type (standard vs archive), storage location, and region; no flat per-GB rate is hardcoded

**Permissions:** `compute.snapshots.list` (roles/compute.viewer)

**Params:** `max_age_days` (default: 90)

**Exclusions:**
- snapshot record malformed or `name` absent/empty
- `status` not exactly `READY` (skips `CREATING`, `DELETING`, `FAILED`, `UPLOADING`)
- `creationTimestamp` absent or unparsable
- age < `max_age_days`
- `snapshotType == "ARCHIVE"` (low-cost long-retention class — out of scope)
- `sourceSnapshotSchedulePolicy` or `sourceSnapshotSchedulePolicyId` non-empty (schedule-created backup)
- `autoCreated == true` (auto-created backup)
- `region_filter` is ignored (snapshots are global resources)

**Spec:** [docs/specs/gcp/snapshot_old.md](../specs/gcp/snapshot_old.md)

---

## Network

#### `gcp.compute.ip.unused`
**Detects:** Regional and global static external IPv4 address reservations in `RESERVED` state — allocated but not attached to any resource

**Confidence / Risk:** HIGH (`RESERVED` state is canonical GCP control-plane confirmation of non-attachment) / LOW

**Cost:** `estimated_monthly_cost_usd = 7.30` — derived from Google's documented **$0.01/hour** unused static external IPv4 rate × 730-hour normalized month; actual billing remains hourly and may vary by contract or currency

**Permissions:** `compute.addresses.list`, `compute.globalAddresses.list` (both included in roles/compute.viewer); permission failures on either surface surface as a permission error

**Params:** none — detection is based on current control-plane state, not age

**Exclusions:**
- address record malformed or `name` absent/empty
- regional aggregated scope key not exactly `regions/REGION`
- `status` not exactly `RESERVED` (skips `IN_USE`, `RESERVING`, unknown)
- `addressType` not exactly `EXTERNAL` (internal addresses are not billed this way)
- `ipVersion` not exactly `IPV4` (IPv6 addresses are out of scope)
- `purpose == "NAT_AUTO"` (Cloud NAT automatic allocations)
- `users[]` non-empty (contradictory current-use evidence)
- global addresses skipped when `region_filter` is active

**Spec:** [docs/specs/gcp/ip_unused.md](../specs/gcp/ip_unused.md)

---

## Platform

#### `gcp.sql.instance.idle`
**Detects:** Primary Cloud SQL instances (`CLOUD_SQL_INSTANCE`) in `RUNNABLE` state with zero observed active connections over the full `idle_days` window; metric coverage must be confirmed full (partial or sparse coverage skips rather than emits)

**Confidence / Risk:** HIGH (Cloud Monitoring confirms zero connections for full window) / HIGH

**Cost:** `estimated_monthly_cost_usd = None` — pricing varies by edition, region, compute shape, HA, storage, and commitment model; no flat estimate is appropriate

**Permissions:** `cloudsql.instances.list` (roles/cloudsql.viewer), `monitoring.timeSeries.list` (roles/monitoring.viewer)

**Params:** `idle_days` (default: 14)

**Exclusions:**
- instance record malformed or `name` absent/empty
- `region` absent/empty
- region filter set and region does not exactly match
- `state` not exactly `RUNNABLE`
- `instanceType` not exactly `CLOUD_SQL_INSTANCE`
- `masterInstanceName` present and non-empty (replica-shaped instance)
- `createTime` absent, unparsable, or instance newer than `window_start` (full window not coverable)
- active-connections metric coverage unresolved (no series, no points, partial window, large gap >&nbsp;10 min, timestamp parse failure, or query failure)
- `active_connections_max > 0` anywhere in the full window

**Spec:** [docs/specs/gcp/sql_instance_idle.md](../specs/gcp/sql_instance_idle.md)

---

## AI/ML *(opt-in: `--category ai`)*

#### `gcp.vertex.endpoint.idle`
**Detects:** Vertex AI Online Prediction endpoints with `dedicatedResources` and zero predictions for `idle_days`

**Confidence / Risk:** HIGH (zero predictions confirmed + age ≥ `idle_days`); MEDIUM (zero predictions, age ≥ 75% of threshold or age unknown) / HIGH (GPU-backed: T4, V100, A100, L4, H100, TPU); MEDIUM (CPU-only)

**Permissions:** `aiplatform.endpoints.list` (roles/aiplatform.viewer), `monitoring.timeSeries.list` (roles/monitoring.viewer)

**Params:** `idle_days` (default: 14)

**Exclusions:** endpoints using `automaticResources` (scale-to-zero); only `dedicatedResources` with `minReplicaCount > 0`

**Spec:** —

#### `gcp.vertex.workbench.idle`
**Detects:** Vertex AI Workbench instances `ACTIVE` with no control-plane activity (`updateTime`) for `idle_days`

**Confidence / Risk:** HIGH (`updateTime` ≥ `idle_days` + age ≥ `idle_days`); MEDIUM (`updateTime` ≥ 75% of threshold or unavailable) / CRITICAL (GPU + `idle_ratio ≥ 2.0`); HIGH (GPU-backed); MEDIUM (CPU-only)

**Permissions:** `notebooks.instances.list` (roles/notebooks.viewer)

**Params:** `idle_days` (default: 14)

**Exclusions:** instances not in `ACTIVE` state

**Spec:** —

#### `gcp.vertex.training_job.long_running`
**Detects:** Vertex AI CustomJobs and TrainingPipelines in `RUNNING` state beyond `long_running_hours_threshold`; GPU/TPU jobs near threshold also trigger early-warning findings

**Confidence / Risk:** HIGH (duration ≥ 3× threshold — clearly runaway); MEDIUM (duration ≥ threshold) / CRITICAL (HIGH confidence + GPU/accelerator); HIGH (HIGH confidence + non-GPU); MEDIUM (all MEDIUM confidence)

**Permissions:** `aiplatform.customJobs.list`, `aiplatform.trainingPipelines.list` (roles/aiplatform.viewer)

**Params:** `long_running_hours_threshold` (default: 24); `expensive_hourly_threshold` (default: $20/hr, for early-warning CPU jobs)

**Exclusions:** jobs < 90% of threshold; cheap CPU-only jobs in the 90–100% early-warning zone

**Spec:** —

#### `gcp.tpu.idle`
**Detects:** Cloud TPU nodes in `READY` state with max `duty_cycle ≤ 2%` across all workers for `idle_days`

**Confidence / Risk:** HIGH (Cloud Monitoring confirms near-zero duty cycle); LOW (Monitoring unavailable — age-only heuristic) / CRITICAL (HIGH confidence + hourly cost ≥ $10/hr); HIGH (HIGH confidence + < $10/hr); MEDIUM (LOW confidence)

**Permissions:** `tpu.nodes.list` (roles/tpu.viewer), `monitoring.timeSeries.list` (roles/monitoring.viewer, optional — falls back to age-based)

**Params:** `idle_days` (default: 7)

**Exclusions:** nodes not in `READY` state; nodes younger than `idle_days`

**Spec:** —

#### `gcp.vertex.featurestore.idle`
**Detects:** Vertex AI Feature Stores (legacy and new-gen) with zero `online_serving/request_count` for `idle_days`; Bigtable-backed stores bill ~$197/node/month regardless of utilization

**Confidence / Risk:** HIGH (Cloud Monitoring confirms zero requests); LOW (Monitoring unavailable — age-only) / HIGH (HIGH confidence); MEDIUM (LOW confidence)

**Permissions:** `aiplatform.featurestores.list`, `aiplatform.featureOnlineStores.list` (roles/aiplatform.viewer), `monitoring.timeSeries.list` (roles/monitoring.viewer, optional)

**Params:** `idle_days` (default: 30)

**Exclusions:** legacy featurestores with `fixedNodeCount == 0` and `scaling.minNodeCount == 0`; stores not in `STABLE` state

**Spec:** —
