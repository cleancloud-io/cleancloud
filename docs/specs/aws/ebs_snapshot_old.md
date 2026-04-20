# aws.ebs.snapshot.old — Canonical Rule Specification

## 1. Intent

Detect self-owned EBS snapshots that are old enough to be cleanup review candidates
after excluding strong AWS-documented blockers and high-confidence dependency signals.

This is a **read-only hygiene rule**. It is not a delete-safe rule, not an idle-usage
rule, and not proof that a snapshot is unused or safe to remove.

---

## 2. AWS API Grounding

Based on official EC2/EBS API and user-guide behavior.

### Key DescribeSnapshots fields

| Field | Behaviour |
|---|---|
| `SnapshotId` | Unique snapshot identifier; always present |
| `StartTime` | Timestamp when snapshot creation was initiated |
| `State` | `pending`, `completed`, `error`, `recoverable`, `recovering` |
| `StorageTier` | `standard` (default) or `archive` (EBS Snapshot Archive) |
| `VolumeId` | Source volume ID; `"vol-ffffffff"` when source volume has been deleted |
| `VolumeSize` | GiB size of the **source volume** — NOT the actual snapshot storage footprint |
| `FullSnapshotSizeInBytes` | Full size of blocks written at snapshot creation time — NOT incremental billed size |
| `Description` | User-supplied description string |
| `Tags` | Key-value tags |
| `DataEncryptionKeyId` | Encryption key ID (if encrypted) |

### State reference

| State | Meaning |
|---|---|
| `pending` | Snapshot creation in progress |
| `completed` | Fully created, available for use |
| `error` | Snapshot creation failed |
| `recoverable` | Snapshot is in the EBS Recycle Bin (soft-deleted) |
| `recovering` | Being restored from the EBS Recycle Bin |

### StorageTier reference

| StorageTier | Meaning |
|---|---|
| `standard` | Default EBS snapshot storage |
| `archive` | EBS Snapshot Archive — long-term, low-cost; minimum 90-day retention; requires explicit user action |

### Critical AWS facts

1. **Snapshot billing is incremental.** EBS snapshots after the first are incremental —
   only changed blocks are stored. `VolumeSize` and `FullSnapshotSizeInBytes` are NOT
   monthly billed cost metrics.

2. **Deleting a snapshot might not reduce storage cost** because later snapshots can
   still reference data blocks from this snapshot.

3. **AMI-linked snapshots cannot be deleted.** AWS explicitly blocks deletion of
   snapshots associated with registered AMIs. Deleting them would corrupt the AMI.

4. **Shared snapshots**: if you delete a shared snapshot that you own, accounts it is
   shared with lose access.

5. **`DescribeImages`** supports filter `block-device-mapping.snapshot-id` and requires
   pagination.

6. **`DescribeSnapshotAttribute(Attribute="createVolumePermission")`** reveals public
   or cross-account create-volume sharing. This call may itself be permission-restricted.

7. **AWS Backup-managed snapshots** are a false-positive risk. Snapshots with AWS Backup
   or DLM management tags must be excluded.

8. **Archived snapshots** have different pricing/behavior and a minimum 90-day archive
   period with early-delete fees. They are out of scope for this rule.

### Rule-design consequence

- Age alone is not a delete signal.
- This rule is a conservative review-candidate detector, not a waste-truth detector.
- Numeric monthly cost must NOT be derived from `VolumeSize` or `FullSnapshotSizeInBytes`.
- Missing blocker visibility must cause skip, not optimism.

---

## 3. Scope

**Included:**
- `OwnerIds=["self"]`
- `State == "completed"`
- `StorageTier == "standard"` (absent `StorageTier` treated as standard)
- `age_days >= max_age_days`
- All blocker checks pass

**Excluded:**
- Non-self-owned snapshots
- Snapshots not in `completed` state
- Archived snapshots (`StorageTier == "archive"`)
- Malformed records without `SnapshotId` or `StartTime`
- Snapshots linked to self-owned AMIs
- Snapshots with public or external create-volume permissions
- Snapshots explicitly identified as AWS Backup-managed
- Snapshots for which required blocker visibility is unavailable

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `age_days` | `now − StartTime` in whole days |
| `max_age_days` | Default: `90`. Product-policy threshold, not AWS-defined. |
| `ami_linked` | `True` when `DescribeImages(Owners=["self"])` finds this snapshot in any AMI's block device mappings |
| `shared_externally` | `True` when `DescribeSnapshotAttribute(createVolumePermission)` shows `group=all` or any external `UserId` |
| `backup_managed` | `True` when snapshot tags contain an `aws:backup:` prefix (explicit tag evidence only; DLM is not in scope for this spec) |

### `backup_managed` semantics

- `True` → explicit AWS Backup/DLM tag found → SKIP
- `False`/`unknown` → no explicit tag evidence → does NOT block detection
- Only `backup_managed == True` is an exclusion signal in this spec

---

## 5. Signal Model (Strict Separation)

### A. EXCLUSION_RULES

| Condition | Result |
|---|---|
| `SnapshotId` or `StartTime` absent | **SKIP** (malformed) |
| `State != "completed"` | **SKIP** |
| `StorageTier != "standard"` | **SKIP** |
| `age_days < max_age_days` | **SKIP** |
| `ami_linked == True` | **SKIP** |
| `shared_externally == True` | **SKIP** |
| `backup_managed == True` | **SKIP** |
| AMI linkage check unavailable | **SKIP** |
| External sharing check unavailable | **SKIP** |

### B. DETECTION_SIGNAL

Single finding trigger:

| Condition | Result |
|---|---|
| Completed, standard-tier snapshot, `age >= max_age_days`, all blocker checks passed | **EMIT** |

### C. CONTEXTUAL_SIGNALS (non-detecting)

May only appear in evidence/details. MUST NOT create or suppress findings directly.

| Signal | Effect |
|---|---|
| `description` | Evidence only |
| `tags` | Evidence only (also used for backup_managed check) |
| `VolumeId` | Evidence only |
| `VolumeSize` | Evidence only (with caveat: not billing data) |
| `FullSnapshotSizeInBytes` | Evidence only (with caveat: not billing data) |
| `DataEncryptionKeyId` | Evidence only |

**Hard rules:**
- `VolumeSize` MUST NOT be used as monthly billed cost.
- `FullSnapshotSizeInBytes` MUST NOT be used as monthly billed cost.
- Contextual signals MUST NOT convert age into delete-safe certainty.

---

## 6. Evaluation Order (Mandatory)

1. Parse and normalize snapshot fields
2. Apply core scope filters: `SnapshotId`/`StartTime` present, `State`, `StorageTier`
3. Compute `age_days`; apply age threshold
4. Check AMI linkage (pre-built index from `DescribeImages`)
5. Check external sharing (`DescribeSnapshotAttribute` per snapshot)
6. Check AWS Backup-managed (tag inspection)
7. Emit finding only if all exclusion checks pass
8. Assign confidence
9. Assign risk
10. Build evidence/details

---

## 7. Confidence Model

| Condition | Confidence |
|---|---|
| All blocker checks passed | `LOW` |

**Mandatory rule:** Use `LOW` confidence. AWS APIs do not prove business intent, DR
intent, Backup ownership, or application dependency from age alone.

---

## 8. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `LOW` |

**Mandatory rule:** Do NOT infer `HIGH` or `MEDIUM` risk from age alone.

---

## 9. Cost Model

**Current spec: omit numeric monthly cost.**

**Mandatory rules:**
- MUST NOT estimate monthly cost from `VolumeSize`
- MUST NOT estimate monthly cost from `FullSnapshotSizeInBytes`
- MUST disclose that snapshot billing is incremental and deletion might not reduce cost

**Allowed:** Show `VolumeSize` and `FullSnapshotSizeInBytes` as non-billing size context,
with explicit caveats.

---

## 10. Failure Behavior

### Required API

`ec2:DescribeSnapshots` — failure = **rule fails** (raises `PermissionError`)

### Best-effort blocker checks

`ec2:DescribeImages` and `ec2:DescribeSnapshotAttribute` — failure = **SKIP the affected snapshot(s)**

### Conservative behavior (mandatory)

- AMI linkage check unavailable → **SKIP all candidate snapshots** (global)
- External sharing check unavailable for a snapshot → **SKIP that snapshot**
- Prefer SKIP over emission when blocker visibility is missing
- Missing blocker checks MUST NOT be treated as "no blockers found"

---

## 11. Blind Spots

Every finding must disclose in `signals_not_checked`:

1. Business/application retention intent not known
2. Disaster recovery or operational workflow dependency not known
3. Later snapshots may reference data blocks from this snapshot — deleting might not reduce cost
4. AWS Backup management not fully verified (tag inspection only)
5. Cross-account AMI references not checked (only self-owned AMIs scanned)
6. Multi-volume snapshot set handling not checked

---

## 12. Evidence Contract

Every finding **must** include all of the following (null allowed, never omitted):

| Field | Requirement |
|---|---|
| `evaluation_path` | Exactly `"old-snapshot-review-candidate"` |
| `snapshot_id` | Always present |
| `start_time` | Always present (ISO-8601) |
| `age_days` | Always present |
| `status` | Always present |
| `storage_tier` | Always present |
| `ami_linked_check` | `false` (only reachable when check passed) |
| `create_volume_permission_check` | `false` (only reachable when check passed) |
| `backup_managed_check` | `"unknown"` when no `aws:backup:` tag found (tag-only negative ≠ proof of non-Backup ownership); `true` never reachable — means SKIP |
| `volume_id` | Present OR null |
| `volume_size_gib` | Present OR null |
| `full_snapshot_size_bytes` | Present OR null |

---

## 13. Title and Reason Contract

| Field | Value |
|---|---|
| `title` | `"Old EBS snapshot review candidate"` |
| `reason` | `"Snapshot exceeds age threshold and no AMI linkage, external sharing, or explicit AWS Backup-managed signal was found"` |

**Hard rules:**
- Do NOT call the snapshot "unused"
- Do NOT call the snapshot "safe to delete"
- Do NOT imply cost savings are guaranteed

---

## 14. API and IAM Contract

**Required:** `ec2:DescribeSnapshots`
**Best-effort:** `ec2:DescribeImages`, `ec2:DescribeSnapshotAttribute`

### API usage constraints

- `DescribeSnapshots` must use `OwnerIds=["self"]`
- `DescribeImages` must restrict to `Owners=["self"]`
- Both must paginate fully

---

## 15. Acceptance Scenarios

### Must emit

1. Self-owned, completed, standard-tier snapshot, `age >= max_age_days`, no AMI link,
   not shared, no backup tags

### Must skip

1. Snapshot younger than threshold
2. `State` in `pending`, `error`, `recoverable`, `recovering`
3. `StorageTier == "archive"`
4. AMI-linked snapshot
5. Publicly shared (`group=all`)
6. Shared to external account (`UserId` present)
7. Explicit AWS Backup/DLM tag present
8. Malformed: `SnapshotId` absent
9. Malformed: `StartTime` absent
10. AMI blocker check unavailable (index build failed)
11. External sharing check unavailable for snapshot

### Must NOT happen

1. `VolumeSize` used as monthly cost → `estimated_monthly_cost_usd` must be `None`
2. `FullSnapshotSizeInBytes` used as monthly cost
3. AMI-linked snapshots emitted
4. Publicly/externally shared snapshots emitted
5. Archived snapshots emitted
6. Missing blocker visibility treated as "no blockers" → must SKIP

---

## 16. In-File Contract

```
Rule: aws.ebs.snapshot.old

Intent:
    Detect old self-owned EBS snapshots that are conservative cleanup review candidates.

Exclusions:
    - status is not completed
    - storage tier is not standard
    - snapshot is linked to a self-owned AMI
    - snapshot is shared publicly or to other accounts
    - snapshot is explicitly identified as AWS Backup-managed
    - blocker checks are unavailable

Detection:
    - age >= threshold after blocker checks pass

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - Snapshot billing is incremental; cost must not be inferred from volumeSize.
    - Missing blocker visibility must cause skip, not optimism.

Blind spots:
    - business/DR intent is not known
    - AWS Backup management is not fully known unless explicitly integrated
    - deleting a snapshot might not reduce storage cost

APIs:
    - ec2:DescribeSnapshots
    - ec2:DescribeImages
    - ec2:DescribeSnapshotAttribute
```

---

## 17. Implementation Constants

| Constant | Default | Description |
|---|---|---|
| `_DEFAULT_MAX_AGE_DAYS` | `90` | Age threshold in days |
| `_BACKUP_TAG_PREFIX` | `"aws:backup:"` | Tag key prefix indicating explicit AWS Backup management (DLM not in scope) |
