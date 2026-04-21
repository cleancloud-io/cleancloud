# aws.rds.snapshot.old — Canonical Rule Specification

## 1. Intent

Detect self-owned manual RDS DB snapshots that are old enough to be cleanup review
candidates after excluding AWS-documented blocker conditions and externally shared/public
restore dependencies.

This is a **read-only review-candidate rule**. It is not a delete-safe rule, not proof that
a snapshot is unused, and not proof that deleting it will reduce cost.

---

## 2. AWS API Grounding

Based on official RDS API, user-guide, and pricing documentation.

### Key facts

1. `DescribeDBSnapshots` is the canonical API for enumerating DB snapshots and supports
   pagination.
2. `DescribeDBSnapshots` supports `SnapshotType` values:
   `automated | manual | shared | public | awsbackup`.
3. If `SnapshotType` isn't specified, both automated and manual snapshots are returned.
4. `DBSnapshot.SnapshotType` is a documented field.
5. `DBSnapshot.Status` is a documented field.
6. `DBSnapshot.SnapshotCreateTime` is documented and **changes when the snapshot is copied**.
7. `DBSnapshot.OriginalSnapshotCreateTime` is documented and **does not change when the
   snapshot is copied**.
8. Manual snapshots aren't subject to the backup retention period and don't expire.
9. Automated backups are governed by backup retention period, which for DB instances can be
   set from `0` to `35` days.
10. Manual snapshot limits (100 per Region) don't apply to automated backups.
11. `DescribeDBSnapshotAttributes` returns manual DB snapshot attributes, including the
    `restore` attribute values for accounts authorized to copy or restore the snapshot.
12. If `restore` includes `all`, the manual DB snapshot is public and can be copied or
    restored by all AWS accounts.
13. Manual snapshots can be shared with up to 20 AWS accounts.
14. Sharing a manual DB snapshot with other accounts grants those accounts permission to copy
    or restore the snapshot; it does not prove active downstream usage.
15. `AllocatedStorage` is the allocated storage size of the source DB instance in GiB, not the
    snapshot storage consumed, and not a documented billed monthly snapshot-storage figure.
16. AWS pricing docs state that RDS bills for backup storage, including customer-initiated DB
    snapshots, but the fetched docs do not provide a canonical per-snapshot monthly USD formula
    derivable from `DescribeDBSnapshots` metadata alone.
17. Creating a DB snapshot requires the source DB instance to be in the `available` state,
    but old-snapshot evaluation is based on current snapshot metadata, not current DB instance
    status.

### Implications

- This rule should target **manual self-owned snapshots only**.
- Automated snapshots are out of scope because they are retention-managed by RDS.
- `awsbackup`, `shared`, and `public` snapshot types are out of scope for this rule.
- Snapshot age should be based on **`OriginalSnapshotCreateTime` when present**, otherwise
  `SnapshotCreateTime`.
- `DescribeDBSnapshotAttributes` is the authority for whether a manual snapshot is public or
  externally shared; `SnapshotType` alone is not sufficient for that determination.
- Public or externally shared manual snapshots are blocker conditions for cleanup review and
  must be excluded.
- `AllocatedStorage` can be shown as source-instance context only and must not be used for
  canonical monthly cost estimation or snapshot-storage-size inference.

---

## 3. Scope and Terminology

- **"DB snapshot"** — an item returned by `DescribeDBSnapshots`.
- **"manual snapshot"** — a snapshot with `SnapshotType == "manual"` returned from the caller
  account via `DescribeDBSnapshots(SnapshotType="manual")`.
- **"old"** — age computed from the trusted snapshot-age timestamp is greater than or equal to
  `max_age_days`.
- **"trusted_snapshot_age_time_utc"** — `OriginalSnapshotCreateTime` if present, else
  `SnapshotCreateTime`.
- **`max_age_days`** — operator-configurable threshold, default 90.
- **`age_days`** — `floor((now_utc - trusted_snapshot_age_time_utc) / 86400 seconds)`.

**Included:**
- Self-owned manual DB snapshots
- `Status == "available"`
- `age_days >= max_age_days`
- No external/public restore sharing

**Excluded:**
- Non-manual snapshot types
- Snapshots not in `available` status
- Missing/invalid age timestamp
- Public manual snapshots
- Manual snapshots shared to other AWS accounts
- Snapshots for which restore-sharing visibility is unavailable

---

## 4. Canonical Rule Statement

A DB snapshot is eligible for this rule only when **all** of the following are true:

- stable DB snapshot identity exists
- `SnapshotType == "manual"`
- `Status == "available"`
- trusted snapshot age source exists and is valid
- `age_days >= max_age_days`
- restore-sharing check confirms the snapshot is neither public nor shared to external
  accounts

No additional predicate may be required for baseline eligibility, including:

- source DB instance still existing
- source DB instance current status
- engine family
- allocated storage size
- encryption status
- source region
- tag presence or absence

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `DBSnapshotIdentifier` | skip item |
| `db_snapshot_id` | `DBSnapshotIdentifier` | skip item |
| `normalized_status` | `Status` | skip item |
| `snapshot_type` | `SnapshotType` | skip item |
| `trusted_snapshot_age_time_utc` | `OriginalSnapshotCreateTime` else `SnapshotCreateTime` | skip item |
| `age_days` | floor((now − trusted_snapshot_age_time_utc) / 86400) | skip item |
| `db_instance_id` | `DBInstanceIdentifier` | null |
| `db_snapshot_arn` | `DBSnapshotArn` | null |
| `dbi_resource_id` | `DbiResourceId` | null |
| `engine` | `Engine` | null |
| `engine_version` | `EngineVersion` | null |
| `allocated_storage_gib` | `AllocatedStorage` (int only) | null |
| `storage_type` | `StorageType` | null |
| `snapshot_target` | `SnapshotTarget` | null |
| `source_region` | `SourceRegion` | null |
| `source_db_snapshot_identifier` | `SourceDBSnapshotIdentifier` | null |
| `encrypted` | `Encrypted` (bool only) | null |
| `kms_key_id` | `KmsKeyId` | null |
| `tag_set` | `TagList` (list only) | `[]` |

### Normalization requirements

- String-valued fields: normalize only from non-empty strings.
- Timestamp fields: must be timezone-aware UTC before use; naive → skip item.
- Future trusted age timestamps → skip item.
- `OriginalSnapshotCreateTime` is optional; when present it takes precedence over
  `SnapshotCreateTime` for age calculation.

---

## 6. Restore-Sharing Blocker Determination

`DescribeDBSnapshotAttributes` is the canonical source for public / externally shared restore
visibility on manual DB snapshots.

### Required attribute contract

- API: `DescribeDBSnapshotAttributes(DBSnapshotIdentifier=...)`
- Attribute of interest: `restore`

### Interpretation rules

- If `restore` contains `all` → snapshot is **public** → **SKIP ITEM**
- If `restore` contains one or more AWS account IDs → snapshot is **shared externally** →
  **SKIP ITEM**
- If `restore` is absent or has no values → no external/public restore sharing blocker

### Semantic boundary

- `restore` values establish copy/restore **permission visibility**, not evidence of actual
  restore usage or dependency

### Visibility rule

- If restore-sharing attributes cannot be retrieved for a manual snapshot, the item must be
  **SKIP ITEM**, not treated optimistically as private

---

## 7. Evaluation Order (Mandatory)

1. Retrieve and fully paginate `DescribeDBSnapshots(SnapshotType="manual")`.
2. Normalize each snapshot item.
3. For each normalized snapshot:
   - `db_snapshot_id` absent → **SKIP ITEM**
   - `snapshot_type` absent or not `manual` → **SKIP ITEM**
   - `normalized_status` absent or not `available` → **SKIP ITEM**
   - trusted age timestamp absent/invalid/future → **SKIP ITEM**
   - `age_days < max_age_days` → **SKIP ITEM**
   - retrieve restore-sharing attributes
   - restore-sharing visibility unavailable → **SKIP ITEM**
   - public/shared restore access present → **SKIP ITEM**
   - otherwise → **EMIT**

---

## 8. Confidence Model

| Condition | Confidence |
|---|---|
| Finding emitted | `LOW` |

**Mandatory rule:** use `LOW` confidence. Age plus private manual status does not prove
business irrelevance, restore irrelevance, or safe deletion.

---

## 9. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `LOW` |

**Mandatory rule:** do not infer `MEDIUM` or `HIGH` risk from age alone.

---

## 10. Cost Model

**Canonical cost rule:** `estimated_monthly_cost_usd = null`.

### Mandatory rules

- `AllocatedStorage` is not snapshot storage and MUST NOT be used for storage or cost inference
- MUST NOT emit a hardcoded per-GB monthly snapshot rate from the fetched AWS docs
- MAY surface `AllocatedStorage` only as source-instance context

### Required caveats

- AWS charges GB-month for shared backup storage (including snapshots); per-snapshot cost
  cannot be derived from API metadata
- Snapshot age and `AllocatedStorage` do **not** prove a specific billed monthly amount or
  snapshot-storage-consumed amount from the fetched AWS docs

---

## 11. Failure Behavior

### Required API failure

- `DescribeDBSnapshots` request/pagination failure → **FAIL RULE**

### Blocker-visibility failure

- `DescribeDBSnapshotAttributes` failure for a snapshot → **SKIP ITEM**

### Item-level malformed data

- Missing or invalid `DBSnapshotIdentifier`, `SnapshotType`, `Status`, or trusted age
  timestamp → **SKIP ITEM**

---

## 12. Evidence / Details Contract

### Required details fields

Each emitted finding should include, at minimum:

```text
evaluation_path             = "old-manual-rds-snapshot-review-candidate"
db_snapshot_id
snapshot_type               = "manual"
normalized_status           = "available"
trusted_snapshot_age_time
age_days
max_age_days
db_instance_id
engine
engine_version
allocated_storage_gib
```

### Optional contextual fields

- `db_snapshot_arn`
- `dbi_resource_id`
- `storage_type`
- `snapshot_target`
- `source_region`
- `source_db_snapshot_identifier`
- `encrypted`
- `kms_key_id`
- `tag_set`

### Required evidence wording

Signals used should state:

- snapshot type is `manual`
- snapshot status is `available`
- snapshot age exceeds the configured threshold
- restore-sharing attributes indicated no public or external restore access at evaluation time

Signals not checked should state major blind spots, such as:

- legal / compliance retention requirements
- disaster recovery intent
- restore runbook dependency
- operational dependency in another account or region not visible from age alone
- exact monthly storage cost

---

## 13. Non-goals / Blind Spots

This rule does **not** prove any of the following:

- that the snapshot is safe to delete
- that deleting the snapshot will reduce billed storage cost
- that the snapshot is not part of a compliance or retention workflow
- that the snapshot is not needed for rare or emergency restore scenarios
- that cross-region or copied lineage dependencies are irrelevant
- that copied snapshot lineage does not make age alone sufficient to determine staleness

---

## 14. Acceptance Scenarios

### Should emit

1. manual snapshot, `Status == "available"`, age threshold met, restore attribute empty
   - **EMIT**
   - confidence `LOW`
   - risk `LOW`

2. copied manual snapshot where `OriginalSnapshotCreateTime` is old enough but
   `SnapshotCreateTime` is recent, restore attribute empty
   - **EMIT**
   - age must be calculated from `OriginalSnapshotCreateTime`

### Should skip

3. automated snapshot
   - **SKIP ITEM**

4. `awsbackup` snapshot
   - **SKIP ITEM**

5. manual snapshot not in `available` status
   - **SKIP ITEM**

6. manual snapshot younger than threshold
   - **SKIP ITEM**

7. public manual snapshot (`restore` contains `all`)
   - **SKIP ITEM**

8. manual snapshot shared to one or more AWS account IDs
   - **SKIP ITEM**

9. manual snapshot with missing/invalid/future trusted age timestamp
   - **SKIP ITEM**

10. manual snapshot where restore-sharing attributes can't be retrieved
    - **SKIP ITEM**

### Should fail

11. `DescribeDBSnapshots` request/pagination failure
    - **FAIL RULE**

---

## 15. Implementation Constraints

- Use `DescribeDBSnapshots(SnapshotType="manual")` as the sole required inventory source.
- Exhaust pagination.
- Use `OriginalSnapshotCreateTime` in preference to `SnapshotCreateTime` for age when
  present.
- Require `Status == "available"`.
- Use `DescribeDBSnapshotAttributes` to determine whether a manual snapshot is public or
  externally shared.
- Do not treat unknown restore-sharing visibility as private.
- Do not hardcode monthly cost from `AllocatedStorage`.

---

Rule: aws.rds.snapshot.old
