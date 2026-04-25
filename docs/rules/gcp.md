# GCP Rules

10 rules (5 hygiene + 5 AI/ML). AI/ML rules require `--category ai`.

← [Back to index](../rules.md)

| Rule ID | Cost Surface | What It Detects |
|---|---|---|
| `gcp.compute.vm.stopped` | Compute | TERMINATED VMs stopped 30+ days (disk charges continue) |
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
**Detects:** TERMINATED VM instances stopped 30+ days; persistent disk charges continue

**Confidence / Risk:** HIGH (`lastStopTimestamp` ≥ 30 days ago); MEDIUM (TERMINATED but timestamp absent) / MEDIUM

**Permissions:** `compute.instances.list` (roles/compute.viewer)

**Params:** none (30-day threshold is fixed)

**Exclusions:** instances not in TERMINATED state; stopped < 30 days

**Spec:** —

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
**Detects:** Disk snapshots older than `days_old`; confidence reflects whether source disk still exists

**Confidence / Risk:** HIGH (source disk no longer exists — orphaned); MEDIUM (source disk still exists) / LOW

**Permissions:** `compute.snapshots.list` (roles/compute.viewer)

**Params:** `days_old` (default: 90)

**Exclusions:** snapshots not in `READY` status; younger than threshold; `region_filter` is ignored (snapshots are global)

**Spec:** —

---

## Network

#### `gcp.compute.ip.unused`
**Detects:** Reserved static IPs (regional and global) in `RESERVED` state (GCP confirms not attached)

**Confidence / Risk:** HIGH (GCP confirms RESERVED state) / LOW

**Permissions:** `compute.addresses.list`, `compute.globalAddresses.list` (roles/compute.viewer); gracefully degrades if globalAddresses permission denied

**Params:** none

**Exclusions:** IPs in `IN_USE` status; global IPs skipped if `region_filter` is set

**Spec:** —

---

## Platform

#### `gcp.sql.instance.idle`
**Detects:** Cloud SQL instances with zero connections for `idle_days`; if Monitoring unavailable, instance is assumed active (conservative fallback — not flagged)

**Confidence / Risk:** HIGH (Cloud Monitoring confirms zero connections for full window) / HIGH

**Permissions:** `cloudsql.instances.list` (roles/cloudsql.viewer), `monitoring.timeSeries.list` (roles/monitoring.viewer)

**Params:** `idle_days` (default: 14)

**Exclusions:** read replicas; instances not in `RUNNABLE` state

**Spec:** —

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
