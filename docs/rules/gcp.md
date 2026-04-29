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
| `gcp.vertex.endpoint.idle` | AI/ML | Vertex AI endpoints with an always-deployed serving floor and zero observed request activity 14+ days |
| `gcp.vertex.workbench.idle` | AI/ML | Vertex AI Workbench instances with no activity 14+ days |
| `gcp.vertex.training_job.long_running` | AI/ML | Vertex AI jobs running beyond threshold |
| `gcp.tpu.idle` | AI/ML | Standalone Cloud TPU nodes in READY state with monitoring-based idle detection; currently no findings emit until worker-to-node join is documented |
| `gcp.vertex.featurestore.idle` | AI/ML | Vertex AI Feature Stores (legacy) and Bigtable-backed Feature Online Stores with zero serving requests 30+ days (Monitoring-confirmed only) |

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
**Detects:** Vertex AI Online Prediction endpoints with an always-deployed serving floor (`dedicatedResources.minReplicaCount >= 1` or `automaticResources.minReplicaCount >= 1`) and no usable endpoint-scoped request-count datapoint above `0` across the full `idle_days` observation window, confirmed by Cloud Monitoring telemetry with proven gap-free coverage

**Confidence / Risk:** HIGH (sole emit path: full-window zero request-count telemetry with no heuristic fallback; no MEDIUM tier) / HIGH (any in-scope dedicated model with nonzero accelerator count and recognized GPU/TPU type); MEDIUM (CPU-only or automatic-resources-only endpoints)

**Cost:** `estimated_monthly_cost_usd = None` -- pricing varies by machine type, accelerator, region, and usage option; no flat estimate is appropriate

**Permissions:** `aiplatform.endpoints.list` (roles/aiplatform.viewer), `monitoring.timeSeries.list` (roles/monitoring.viewer)

**Params:** `idle_days` (default: 14)

**Exclusions:**
- endpoint name or location malformed or absent
- location filter set and location does not exactly match
- endpoint `createTime` absent, unparsable, or future
- no in-scope deployed models; `provisioned_serving_floor < 1`
- shared-resource-only endpoint (`sharedResources` only; spec 11.4)
- any in-scope deployed model `createTime` absent, unparsable, or future
- `capacity_floor_start > evaluation_window_start` (full window not coverable)
- malformed `minReplicaCount` or unrecognized prediction-resource union on any deployed model
- monitoring client creation failure -- all endpoints skip; no fallback
- monitoring query failure for a location -- all endpoints in that location skip
- telemetry coverage unresolved: no series, leading gap > `idle_days * 86400s / 2`, any interior gap > `idle_days * 86400s / 2`, or trailing gap > `idle_days * 86400s / 2`
- any usable request-count datapoint > `0` in the observation window
- `dedicatedResources.minReplicaCount == 0` (scale-to-zero preview; no always-deployed floor)
- `automaticResources.minReplicaCount == 0` (scale-to-zero; no always-deployed floor)
- near-idle, low-traffic, age-only, trafficSplit, or missing-telemetry-as-zero fallbacks are explicitly forbidden

**Spec:** [docs/specs/gcp/ai/vertex_endpoint_idle.md](../specs/gcp/ai/vertex_endpoint_idle.md)

#### `gcp.vertex.workbench.idle`
**Detects:** Vertex AI Workbench instances `ACTIVE` with no control-plane activity (`updateTime`) for `idle_days`

**Confidence / Risk:** HIGH (`updateTime` ≥ `idle_days` + age ≥ `idle_days`); MEDIUM (`updateTime` ≥ 75% of threshold or unavailable) / CRITICAL (GPU + `idle_ratio ≥ 2.0`); HIGH (GPU-backed); MEDIUM (CPU-only)

**Permissions:** `notebooks.instances.list` (roles/notebooks.viewer)

**Params:** `idle_days` (default: 14)

**Exclusions:** instances not in `ACTIVE` state

**Spec:** —

#### `gcp.vertex.training_job.long_running`
**Detects:** Vertex AI CustomJobs and TrainingPipelines whose state is exactly the expected running state (`JOB_STATE_RUNNING` / `PIPELINE_STATE_RUNNING`) and whose elapsed wall-clock time since `startTime` meets or exceeds `long_running_hours_threshold`

**Confidence / Risk:** HIGH (duration ≥ 3× threshold — clearly runaway); MEDIUM (duration ≥ threshold) / CRITICAL (HIGH confidence + GPU/TPU/accelerator); HIGH (HIGH confidence + non-accelerator); MEDIUM (all MEDIUM confidence)

**Cost:** `estimated_monthly_cost_usd = None` — training jobs are transient; no static per-hour rate is appropriate across machine types and regions

**Permissions:** `aiplatform.customJobs.list`, `aiplatform.trainingPipelines.list` (roles/aiplatform.viewer)

**Params:** `long_running_hours_threshold` (default: 24)

**Exclusions:**
- resource name not matching exact pattern `projects/{p}/locations/{l}/customJobs/{id}` or `trainingPipelines/{id}` (6 segments, non-empty components)
- state field absent or not exactly the expected running state for the job type
- `startTime` absent, non-RFC3339 (rejects space separator, date-only, missing timezone), or unparsable
- elapsed < `long_running_hours_threshold`
- region filter set and derived location does not exactly match

**Spec:** [docs/specs/gcp/ai/vertex_training_job_long_running.md](../specs/gcp/ai/vertex_training_job_long_running.md)

#### `gcp.tpu.idle`
**Detects:** Standalone Cloud TPU nodes in exact `READY` state where complete worker-joined duty-cycle telemetry (`tpu.googleapis.com/accelerator/duty_cycle` on `tpu.googleapis.com/GceTpuWorker`) confirms max observed duty cycle <= 2% across all joined workers and accelerators over the full buffered `idle_days` window; monitoring is required — no age-only, partial-join, or cadence-assumed fallback

**Confidence / Risk:** HIGH / HIGH (when emitting — requires monitoring-confirmed complete join; no tiered fallback)

**Current emission status:** No findings are emitted. The `GceTpuWorker` monitored resource labels (`resource_container`, `location`, `worker_id`) do not include a TPU Node name. No documented first-party Google Cloud surface maps `worker_id` to the owning TPU Node, so `telemetry_join_state` cannot be proven `complete` (spec 8.3). Emission requires `telemetry_join_state == complete` (spec 9, condition 7). The monitoring query is issued per zone to surface permission errors. When Google publishes a documented worker-to-node identity surface, implement the join in `_run_zone_diagnostic`.

**Cost:** `estimated_monthly_cost_usd = None` — pricing varies by TPU type, region, and usage option; no flat estimate is appropriate

**Permissions:** `tpu.nodes.list` (roles/tpu.viewer), `monitoring.timeSeries.list` (roles/monitoring.viewer)

**Params:** `idle_days` (default: 7)

**Exclusions (pre-checks applied before monitoring):**
- node name malformed, node ID or zone absent/unresolvable
- region filter set and derived region does not exactly match
- state not exactly `READY`
- `createTime` absent, unparsable, future, or node younger than full buffered window (`now - 180s - idle_days * 86400s`)
- `queuedResource` non-empty string (queued-resource-managed node)
- `multisliceNode == true` (multislice node)
- malformed `queuedResource` (non-string/non-null) or `multisliceNode` (non-bool/non-null)
- monitoring client creation failure (all nodes skip — no age-only fallback)
- monitoring query failure for a node (that node skips, warning issued)
- `telemetry_join_state` not `complete` — currently always the case (see above)

**Spec:** [docs/specs/gcp/ai/tpu_idle.md](../specs/gcp/ai/tpu_idle.md)

#### `gcp.vertex.featurestore.idle`
**Detects:** Vertex AI Feature Stores (legacy) and Bigtable-backed Feature Online Stores with provisioned online-serving capacity and zero `online_serving/request_count` confirmed by Cloud Monitoring for `idle_days`; no age-only or monitoring-absent fallback

**Confidence / Risk:** HIGH (Cloud Monitoring confirms zero requests for full aligned window) / HIGH

**Cost:** `estimated_monthly_cost_usd = None` — pricing varies by backing, region, node count, and commitment model; no flat estimate is appropriate

**Permissions:** `aiplatform.featurestores.list`, `aiplatform.featureOnlineStores.list` (roles/aiplatform.viewer), `monitoring.timeSeries.list` (roles/monitoring.viewer)

**Params:** `idle_days` (default: 30)

**Exclusions:**
- resource name malformed or store ID / region absent
- region filter set and region does not exactly match
- state not exactly `STABLE`
- `reference_time` (`max(createTime, updateTime)`) absent, unparsable, or in the future
- store younger than full `idle_days` observation window
- legacy: `fixedNodeCount == 0` and `scaling.minNodeCount == 0` (no provisioned online-serving capacity)
- legacy: both `fixedNodeCount > 0` and `scaling.minNodeCount > 0` simultaneously — invalid serving mode
- FeatureOnlineStore: storage type not exactly Bigtable (`optimized` stores are out of scope)
- FeatureOnlineStore: `bigtable.autoScaling` absent, or `maxNodeCount < minNodeCount`
- monitoring client unavailable (no age-only fallback)
- metric coverage unresolved — not exactly `idle_days` aligned daily buckets, query failure, future timestamp, or gap > 86 400 s between adjacent points
- aggregate request count > 0 over the full window

**Spec:** [docs/specs/gcp/ai/featurestore_idle.md](../specs/gcp/ai/featurestore_idle.md)
