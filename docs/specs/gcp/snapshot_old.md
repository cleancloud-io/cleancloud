~~# GCP Rule Spec - `gcp.compute.snapshot.old`

## 1. Rule Identity

- **Rule ID:** `gcp.compute.snapshot.old`
- **Provider:** GCP
- **Resource type:** Compute Engine snapshot
- **Finding resource_type:** `gcp.compute.snapshot`

---

## 2. Intent

Detect **old standard snapshot resources that are conservative cleanup review candidates** after excluding stronger Google-documented signals that the snapshot is part of an intentional automated backup workflow.

This rule is deliberately **precision-first**. It is a **review-candidate** rule only, not proof that a snapshot is unused, not proof that deleting it will reduce cost proportionally, and not proof that it is safe to remove.

---

## 3. GCP Documentation Grounding

### 3.1 Snapshot resource exposes canonical lifecycle, age, and storage fields

Google documents the Compute Engine `Snapshot` resource with fields including:

1. `creationTimestamp`
2. `status`
3. `sourceDisk`
4. `sourceDiskId`
5. `diskSizeGb`
6. `storageBytes`
7. `storageBytesStatus`
8. `storageLocations`
9. `autoCreated`
10. `chainName`
11. `sourceSnapshotSchedulePolicy`
12. `sourceSnapshotSchedulePolicyId`
13. `snapshotType`

Source:

- *Resource: snapshots*

URL:

- https://cloud.google.com/compute/docs/reference/rest/v1/snapshots

Rule consequence:

1. Age must be based on documented `creationTimestamp`.
2. Only stable snapshot lifecycle states should be evaluated.
3. `diskSizeGb` and `storageBytes` are different signals and must not be conflated.

### 3.2 Only `READY` snapshots are stably evaluable

Google documents snapshot `status` values including:

- `CREATING`
- `DELETING`
- `FAILED`
- `READY`
- `UPLOADING`

Source:

- *Resource: snapshots*

URL:

- https://cloud.google.com/compute/docs/reference/rest/v1/snapshots

Rule consequence:

1. Only `status == "READY"` is eligible.
2. `CREATING`, `DELETING`, `FAILED`, and `UPLOADING` must skip.

### 3.3 Standard snapshots are incremental and deleting one does not necessarily reclaim all of its data

Google documents:

1. Standard snapshots are incremental.
2. `storageBytes` is the storage used by the snapshot and can change as snapshots are created or deleted.
3. Because subsequent snapshots can depend on previous snapshots, deleting a snapshot does not necessarily delete all data on that snapshot.

Sources:

- *Resource: snapshots*
- *About archive and standard disk snapshots*

URLs:

- https://cloud.google.com/compute/docs/reference/rest/v1/snapshots
- https://cloud.google.com/compute/docs/disks/snapshots

Rule consequence:

1. Age alone is not a direct cost-reclaim signal.
2. `diskSizeGb` must not be treated as billed snapshot size.
3. Even `storageBytes` must not be converted into a confident monthly saving estimate without a pricing model that fully matches snapshot type and storage location.

### 3.4 Snapshot schedules are a documented intentional backup workflow

Google documents that snapshot schedules:

1. create standard snapshots at scheduled intervals
2. are a best practice for regular disk backup
3. can retain auto-generated snapshots indefinitely if no retention policy is configured
4. expose lifecycle metadata through snapshot fields such as `autoCreated`, `sourceSnapshotSchedulePolicy`, and `sourceSnapshotSchedulePolicyId`

Sources:

- *About snapshot schedules for disks*
- *Resource: snapshots*

URLs:

- https://cloud.google.com/compute/docs/disks/about-snapshot-schedules
- https://cloud.google.com/compute/docs/reference/rest/v1/snapshots

Rule consequence:

1. Schedule-created snapshots are a strong intentional-backup signal.
2. To reduce false positives, snapshots with explicit schedule-created evidence should be excluded from this rule.

### 3.5 Archive snapshots are a distinct low-cost, long-term retention class

Google documents:

1. Standard and archive snapshots are different snapshot types.
2. Archive snapshots are intended for compliance, audit, and long-term cold storage.
3. Archive snapshots are lower-cost and optimized for long retention rather than fast restore.

Source:

- *About archive and standard disk snapshots*

URL:

- https://cloud.google.com/compute/docs/disks/snapshots

Rule consequence:

1. Archive snapshots are not strong candidates for an “old snapshot” hygiene rule.
2. Archive snapshots should be excluded when the snapshot type is explicitly known.

### 3.6 Snapshot scope and storage location are not the same thing

Google documents:

1. Standard snapshots are globally scoped by default, and regionally scoped snapshots also exist.
2. `storageLocations` describes where snapshot data is stored.
3. The snapshot resource does not expose a simple canonical `region` field comparable to zonal or regional Compute resources.

Source:

- *About archive and standard disk snapshots*

URL:

- https://cloud.google.com/compute/docs/disks/snapshots

Rule consequence:

1. This rule should treat snapshots as a project-level inventory surface.
2. `region_filter` should be ignored rather than guessed from `storageLocations`.
3. `storageLocations` is context only and must not be treated as a region-filter surrogate.

### 3.7 Snapshot pricing varies by snapshot type, scope, and storage location

Google documents that snapshot pricing lives on the Compute Engine disk and image pricing page, with prices listed in USD and region/currency-specific values available via SKUs and billing surfaces.

Source:

- *Disk and image pricing*

URL:

- https://cloud.google.com/compute/disks-image-pricing#disk_snapshots

Rule consequence:

1. This rule must not hardcode a flat monthly estimate such as `$2.60` or `$0.026/GB`.
2. `estimated_monthly_cost_usd` should remain `None` unless a future implementation uses a documented pricing model that correctly incorporates snapshot type and storage location.

---

## 4. Detection Goal

Emit only when the snapshot passes every rule in section **8**. Section **8** is the single source of truth for decisioning; sections **7** and **9** define normalization and evaluation contracts.

Decision precedence is:

1. normalize required fields
2. apply hard lifecycle and age exclusions
3. exclude archive and schedule-created snapshots
4. emit only when no exclusion applies

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the snapshot is safe
- that deleting the snapshot will reduce cost proportionally
- that the snapshot is unused or orphaned
- that the source disk no longer exists
- that the snapshot is not required for backup, audit, DR, or compliance

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| `snapshots.list` | enumerate snapshot resources and their lifecycle, age, billed-storage, schedule, and type metadata |
| Disk/image pricing page | authoritative pricing model source for snapshot pricing variability |

### 6.2 Authentication / permissions

Required permission:

- `compute.snapshots.list`

Typical predefined role:

- `roles/compute.viewer`

### 6.3 Thresholds

| Parameter | Meaning |
|---|---|
| `max_age_days` | Review threshold in days; default `90` |

This is a product-policy review threshold, not a Google-defined idle threshold.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `status` | Resolve from documented snapshot `status` and compare case-sensitively to canonical values such as `"READY"` and `"FAILED"`. |
| `creation_timestamp` | Parse from documented RFC3339 `creationTimestamp`. Unparseable values are unusable. |
| `age_days` | Compute `age_days` as whole UTC days between `now` and parsed `creation_timestamp`. |
| `snapshot_type` | Preserve exact documented `snapshotType` when present; if absent, preserve as unknown rather than guessing. |
| `auto_created` | Preserve exact boolean from `autoCreated`; absent means unknown. |
| `source_snapshot_schedule_policy` | Preserve exact string when present. |
| `source_snapshot_schedule_policy_id` | Preserve exact string when present. |
| `source_disk` | Preserve exact documented value for context only. |
| `source_disk_id` | Preserve exact documented value for context only. |
| `disk_size_gb` | Parse as non-negative integer when possible; otherwise preserve unknown/`0` for context only. |
| `storage_bytes` | Parse as non-negative integer when possible; otherwise preserve `0` for context only. |
| `storage_bytes_status` | Preserve exact documented value when present. |
| `storage_locations` | Preserve as list for context only; never use as region-filter proxy. |
| `chain_name` | Preserve exact documented `chainName` when present; context only. |
| `labels` | `snapshot.labels or {}` - never `None` in output. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | snapshot record is malformed or `name` absent / empty | Skip |
| 8.2 | `status` is absent, unknown, or not exactly `"READY"` | Skip |
| 8.3 | `creationTimestamp` is absent or unparsable | Skip |
| 8.4 | `age_days < max_age_days` | Skip |
| 8.5 | `snapshotType == "ARCHIVE"` | Skip |
| 8.6 | `sourceSnapshotSchedulePolicy` or `sourceSnapshotSchedulePolicyId` is present and non-empty | Skip |
| 8.7 | `autoCreated == true` | Skip |
| 8.8 | all required signals resolve and no exclusion conditions apply | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Inventory contract

Required behavior:

1. Enumerate snapshots from `snapshots.list`.
2. Fully iterate the paged result; do not stop after the first page.
3. Ignore `region_filter` because the snapshot resource does not expose a canonical comparable region field for this rule.

### 9.2 Lifecycle contract

Required behavior:

1. Only `status == "READY"` is eligible.
2. `CREATING`, `DELETING`, `FAILED`, and `UPLOADING` must skip.
3. Unknown or unresolved status must skip.

### 9.3 Age contract

Required behavior:

1. Parse `creationTimestamp` as RFC3339.
2. Use the current UTC system time as `now`.
3. Compute `age_days` as whole UTC days.
4. Emit only when `age_days >= max_age_days`.
5. If `creationTimestamp` cannot be parsed, skip rather than guess.

### 9.4 Schedule-created exclusion contract

Required behavior:

1. A non-empty `sourceSnapshotSchedulePolicy` must skip.
2. A non-empty `sourceSnapshotSchedulePolicyId` must skip.
3. `autoCreated == true` must skip.

Rationale:

Google documents snapshot schedules as intentional recurring backups and exposes schedule-origin metadata directly on the snapshot resource.

### 9.5 Archive-snapshot exclusion contract

Required behavior:

1. If `snapshotType` is present and exactly `"ARCHIVE"`, skip.
2. If `snapshotType` is absent, do not infer archive status.

Rationale:

Google documents archive snapshots as a separate low-cost long-retention class intended for compliance/audit/cold-storage use.

### 9.6 Source-disk contract

Required behavior:

1. `sourceDisk` and `sourceDiskId` may appear in evidence/details only.
2. Do **not** infer “source disk deleted” from empty or missing `sourceDisk`.
3. Do **not** raise confidence solely because `sourceDisk` is absent.

### 9.7 Cost model contract

Required behavior:

1. `estimated_monthly_cost_usd = None`
2. Do **not** estimate cost from `diskSizeGb`.
3. Do **not** estimate cost from age.
4. Do **not** hardcode a flat per-GB monthly rate.
5. `storageBytes` may appear as billed-storage context only, including when it is very small or zero.
6. If `storageBytesStatus` is present, it should also be surfaced as context because the billed-storage value can be changing.

Rationale:

Google documents `storageBytes` as billed storage used by the snapshot and documents that it can change as snapshots are created or deleted. Google also documents snapshot pricing on the pricing page rather than in the resource itself, and pricing varies by snapshot type and storage location.

### 9.8 Confidence contract

Required behavior:

| Condition | Confidence |
|---|---|
| Finding emitted | `LOW` |

Rationale:

Even after excluding archive and schedule-created snapshots, age alone does not prove that a snapshot is waste, unused, or safe to delete.

### 9.9 Risk contract

Required behavior:

| Condition | Risk |
|---|---|
| Finding emitted | `LOW` |

### 9.10 Failure behavior contract

Required behavior:

1. Permission failures for snapshot inventory should surface as a permission error, not silent empty findings.
2. If the Compute Engine API for snapshots is unavailable / disabled for the project, returning no findings is acceptable.
3. Malformed snapshot records should be skipped item-by-item rather than failing the whole rule.

---

## 10. Finding Shape

### 10.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"gcp"` |
| `rule_id` | `"gcp.compute.snapshot.old"` |
| `resource_type` | `"gcp.compute.snapshot"` |
| `resource_id` | canonical project/global snapshot path |
| `region` | `"global"` |
| `confidence` | `LOW` |
| `risk` | `LOW` |
| `estimated_monthly_cost_usd` | `None` |

### 10.2 Required evidence

`signals_used` must clearly disclose:

1. snapshot `status` is `READY`
2. snapshot age in days
3. threshold in days
4. if present, `storageBytes` and `storageBytesStatus` as context only
5. if present, snapshot type as context only
6. if present, snapshot is part of a named incremental chain when `chain_name` is present (from `chainName`)

`signals_not_checked` should include remaining blind spots such as:

1. business/application retention intent
2. DR / audit / compliance intent
3. snapshot restore frequency or operational usage was not evaluated
4. whether deleting this snapshot would materially reduce billed storage
5. exact monthly pricing from current storage location and snapshot type

### 10.3 Required details

Details should include at least:

- `snapshot_name`
- `created_at`
- `age_days`
- `max_age_days_threshold`
- `disk_size_gb`
- `storage_bytes`
- `storage_bytes_status`
- `storage_locations`
- `snapshot_type`
- `auto_created`
- `source_snapshot_schedule_policy` when present
- `source_snapshot_schedule_policy_id` when present
- `source_disk` when present
- `source_disk_id` when present
- `chain_name` when present
- `labels`

---

## 11. Failure Behavior

- Snapshot inventory permission denied -> raise permission error
- Compute Engine API disabled / not found for the project -> return no findings
- Malformed snapshot records -> skip those items
- `region_filter` ignored -> do not guess from storage locations~~
