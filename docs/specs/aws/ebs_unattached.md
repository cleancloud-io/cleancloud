# aws.ebs.unattached — Canonical Rule Specification

## 1. Intent

Detect EBS volumes in the currently evaluated account/region that are currently
unattached and old enough to be cleanup review candidates, after excluding AWS-documented
transitional states and service-managed volumes.

This is a **read-only hygiene rule**. It is not a delete-safe rule, not proof that a
volume is orphaned, and not proof that deletion is operationally safe.

---

## 2. AWS API Grounding

Based on official EC2/EBS API and user-guide behavior.

### Key DescribeVolumes fields

| Field | Behaviour |
|---|---|
| `VolumeId` | Unique volume identifier; always present |
| `State` | `creating`, `available`, `in-use`, `deleting`, `deleted`, `error` |
| `CreateTime` | Timestamp when volume creation was initiated |
| `Size` | Volume size in GiB |
| `VolumeType` | `gp2`, `gp3`, `io1`, `io2`, `sc1`, `st1`, `standard` |
| `AvailabilityZone` | AZ the volume resides in |
| `Encrypted` | Boolean — whether volume is encrypted |
| `MultiAttachEnabled` | Boolean — whether Multi-Attach is enabled |
| `Iops` | Provisioned IOPS (for io1, io2, gp3) |
| `Throughput` | Provisioned throughput in MiB/s (for gp3) |
| `SnapshotId` | Source snapshot ID if created from snapshot; absent otherwise |
| `Attachments` | List of `VolumeAttachment` objects (boto3 field name) |
| `Operator` | Operator metadata — `Managed` (bool) and `Principal` (string) |

### VolumeAttachment status values

| Status | Meaning |
|---|---|
| `attaching` | Attachment in progress |
| `attached` | Fully attached |
| `detaching` | Detachment in progress |
| `detached` | Detached (transitional; volume returns to available) |
| `busy` | Volume is busy (Multi-Attach) |

### Critical AWS facts

1. **Volume state `available`** means the volume is not currently attached and can be
   attached to an instance in the same AZ.

2. **Attachment detection** must use `State == "available"` together with
   `Attachments == []`. Missing `instanceId` in an attachment entry does NOT mean
   the volume is unattached — some AWS-managed resources omit `instanceId`.

3. **Service-managed volumes** have `Operator.Managed == True`. These are managed by
   a service provider and are out of scope for cleanup suggestions.

4. **Multi-Attach** volumes can be attached to multiple instances. If `Attachments`
   is non-empty they are still attached — `multiAttachEnabled` alone is not a detection
   signal.

5. **EBS pricing** differs by volume type. `io1`/`io2` have separate provisioned-IOPS
   charges; `gp3` has separate throughput charges. A flat size-only rate is not valid
   across all types.

6. **Deleting a volume** destroys its data unless snapshot coverage exists elsewhere.

7. **`DescribeVolumes`** strongly recommends pagination.

### Rule-design consequence

- Detection must use `State == "available"` AND `len(Attachments) == 0` — not either alone.
- Do not treat missing `instanceId` as proof of no attachment.
- Normalize SDK field names before any evaluation.
- Service-managed volumes (`Operator.Managed == True`) must be skipped.
- Numeric monthly cost must NOT be derived from a flat per-GB rate.

---

## 3. Scope

**Included:**
- All volumes returned by `DescribeVolumes` for the currently evaluated account/region
- `State == "available"` after normalization
- `attachment_count == 0` after normalization
- `age_days >= min_unattached_age_days`
- `service_managed_check != True`

**Excluded:**
- Volumes in any state other than `available`
- Volumes with any returned attachment entries
- Service-managed volumes (`Operator.Managed == True`)
- Volumes younger than the configured threshold
- Malformed records missing `VolumeId`, `State`, or `CreateTime`

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `age_days` | `floor((now_utc − create_time).total_seconds() / 86400)`, i.e. `timedelta.days` |
| `min_unattached_age_days` | Default: `7`. Product-policy threshold, not AWS-defined. |
| `normalized_status` | Normalized from `volume.State` → else `volume.state` → else `volume.status` → else absent |
| `normalized_attachments` | `volume.Attachments` → else `volume.attachmentSet` → else `[]`; if both present use `Attachments` |
| `attachment_count` | `len(normalized_attachments)` |
| `service_managed_check` | `True` when `Operator.Managed` is explicitly `True`; `False` when explicitly `False`; `unknown` when `Operator` key is absent or `Managed` is absent/ambiguous |
| `operator_principal` | `Operator.Principal` → else `Operator.principal` → else `null` |

### `service_managed_check` semantics

- `True` → explicit operator-managed flag → **SKIP**
- `False` → explicit non-managed → continue evaluation
- `unknown` → operator metadata absent or incomplete → continue evaluation (not an exclusion)

---

## 5. Signal Model (Strict Separation)

### Normalization Contract

Normalization runs **before** all other logic and is the single source of truth.

Minimum required normalized fields:

| Field | Derivation |
|---|---|
| `volume_id` | `volume.VolumeId` → else absent |
| `normalized_status` | `volume.State` → `volume.state` → `volume.status` → absent |
| `create_time` | `volume.CreateTime` → `volume.createTime` → absent |
| `normalized_attachments` | `volume.Attachments` → `volume.attachmentSet` → `[]` |
| `attachment_count` | `len(normalized_attachments)` |
| `normalized_operator` | `volume.Operator` → `{}` |
| `service_managed_check` | from `normalized_operator.Managed` / `normalized_operator.managed` |
| `operator_principal` | from `normalized_operator.Principal` / `normalized_operator.principal` → `null` |
| `availability_zone` | `volume.AvailabilityZone` → `null` |
| `size_gib` | `volume.Size` → `null` |
| `volume_type` | `volume.VolumeType` → `null` |
| `multi_attach_enabled` | `volume.MultiAttachEnabled` → `null` |
| `iops` | `volume.Iops` → `null` |
| `throughput_mibps` | `volume.Throughput` → `null` |
| `encrypted` | `volume.Encrypted` → `null` |
| `snapshot_id` | `volume.SnapshotId` → `null` |

All rule logic operates **only** on normalized fields after Step 1.

### A. EXCLUSION_RULES

| Condition | Result |
|---|---|
| `volume_id` absent | **SKIP** (malformed) |
| `normalized_status` absent | **SKIP** (malformed) |
| `create_time` absent | **SKIP** (malformed) |
| `service_managed_check == True` | **SKIP** |
| `normalized_status != "available"` | **SKIP** |
| `attachment_count > 0` | **SKIP** |
| `age_days < min_unattached_age_days` | **SKIP** |

### B. DETECTION_SIGNAL

Single finding trigger:

| Condition | Result |
|---|---|
| `normalized_status == "available"`, `attachment_count == 0`, `age_days >= min_unattached_age_days`, `service_managed_check != True` | **EMIT** |

### C. CONTEXTUAL_SIGNALS (non-detecting)

May only appear in evidence/details. MUST NOT create or suppress findings.

| Signal | Effect |
|---|---|
| `size_gib` | Evidence only (not billing data) |
| `volume_type` | Evidence only |
| `iops` | Evidence only |
| `throughput_mibps` | Evidence only |
| `encrypted` | Evidence only |
| `multi_attach_enabled` | Evidence only |
| `availability_zone` | Evidence only |
| `snapshot_id` | Evidence only |
| `tags` | Evidence only |

**Hard rules:**
- `size_gib` MUST NOT be multiplied by a flat rate to produce `estimated_monthly_cost_usd`.
- Missing `instanceId` in an attachment entry MUST NOT be treated as unattached.
- `multi_attach_enabled` MUST NOT be used as a detection signal.

---

## 6. Evaluation Order (Mandatory)

1. Normalize all volume fields (Normalization Contract)
2. Validate required normalized fields: `volume_id`, `normalized_status`, `create_time`
3. Apply EXCLUSION_RULES sequentially; skip on first match
4. Emit finding only if all exclusion checks pass
5. Assign confidence
6. Assign risk
7. Build evidence/details

---

## 7. Confidence Model

| Condition | Confidence |
|---|---|
| All exclusion checks passed | `MEDIUM` |

**Mandatory rule:** Use `MEDIUM` confidence. Normalized empty attachments is strong
provider-level evidence, but it does not prove lack of future use, recovery intent, or
deletion safety.

---

## 8. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `LOW` |

**Mandatory rule:** Do NOT infer `MEDIUM` or `HIGH` risk from unattached state alone.

---

## 9. Cost Model

**Current spec: omit numeric monthly cost.**

**Mandatory rules:**
- MUST NOT estimate monthly cost from a flat per-GiB rate (invalid across volume types)
- `io1`/`io2` have separate provisioned-IOPS charges; `gp3` has separate throughput charges
- MUST NOT set `estimated_monthly_cost_usd` from `size_gib` alone

**Allowed:** Show `size_gib`, `volume_type`, `iops`, `throughput_mibps` as non-billing
context.

---

## 10. Failure Behavior

### Required API

`ec2:DescribeVolumes` — failure = **rule fails** (raises `PermissionError`)

### Conservative behavior (mandatory)

- Pagination failure after retries exhausted → fail rule; no partial findings emitted
- Malformed volume (missing required normalized fields) → **SKIP item**
- EXCLUSION_RULES are the canonical post-normalization skip logic

---

## 11. Blind Spots

Every finding must disclose in `signals_not_checked`:

1. Business/application retention intent not known
2. Disaster recovery or rollback/migration retention intent not known
3. Future planned attachment not known
4. Backup/snapshot recoverability for safe deletion not verified
5. Filesystem or application-level dependency before detachment not known
6. Deletion approval workflow not checked

Additional disclosures:
- Volume deletion destroys data unless recoverability is handled elsewhere
- Attachment/detachment transitions can be subject to short-lived AWS eventual consistency

---

## 12. Evidence Contract

Every finding **must** include all of the following (null allowed, never omitted):

| Field | Requirement |
|---|---|
| `evaluation_path` | Exactly `"unattached-volume-review-candidate"` |
| `volume_id` | Always present |
| `create_time` | Always present (ISO-8601) |
| `age_days` | Always present |
| `normalized_status` | Always present |
| `attachment_count` | Always present |
| `service_managed_check` | `true`, `false`, or `"unknown"` |
| `operator_principal` | String or `null` |
| `availability_zone` | Present or `null` |
| `size_gib` | Present or `null` |
| `volume_type` | Present or `null` |
| `multi_attach_enabled` | Present or `null` |
| `iops` | Present or `null` |
| `throughput_mibps` | Present or `null` |
| `encrypted` | Present or `null` |
| `snapshot_id` | Present or `null` |

---

## 13. Title and Reason Contract

| Field | Value |
|---|---|
| `title` | `"Unattached EBS volume review candidate"` |
| `reason` | `"Volume has normalized attachment_count == 0 and the service-managed exclusion did not match"` |

**Hard rules:**
- Do NOT call the volume "unused"
- Do NOT call the volume "orphaned" as a certainty statement
- Do NOT call the volume "safe to delete"

---

## 14. API and IAM Contract

**Required:** `ec2:DescribeVolumes`

### API usage constraints

- `DescribeVolumes` must paginate fully

---

## 15. Acceptance Scenarios

### Must emit

1. Volume: `State=available`, `Attachments=[]`, `age >= threshold`, `service_managed_check` is `false` or `unknown`

### Must skip

1. `State == "creating"`
2. `State == "in-use"`
3. `State == "deleting"`
4. `State == "deleted"`
5. `State == "error"`
6. `Attachments` non-empty (attachment_count > 0)
7. `Operator.Managed == True` (service-managed)
8. `age_days < min_unattached_age_days`
9. Malformed: `VolumeId` absent
10. Malformed: `State` absent
11. Malformed: `CreateTime` absent

### Must NOT happen

1. Missing `instanceId` in attachment treated as unattached
2. Flat per-GiB cost estimate presented as valid `estimated_monthly_cost_usd`
3. Service-managed volumes emitted
4. Non-`available` state volumes emitted
5. `service_managed_check` emitted as `false` when `Operator` key is absent

---

## 16. In-File Contract

```
Rule: aws.ebs.unattached

Intent:
    Detect currently unattached EBS volumes that are old enough to be cleanup review
    candidates.

Exclusions:
    - volume state is not available
    - any attachment entry is returned
    - volume is explicitly service-managed (Operator.Managed == True)
    - required fields are missing
    - volume is younger than the configured threshold

Detection:
    - normalized_status == available
    - normalized attachment_count == 0
    - age >= threshold
    - service_managed_check != True

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - Do not treat missing instanceId as proof of no attachment.
    - Normalize SDK field shapes before evaluating attachments or operator state.
    - service_managed_check == true excludes; unknown is not an exclusion.
    - Do not use a flat size-only cost estimate across all EBS types.

Blind spots:
    - business/DR/future-attachment intent is not known
    - backup/snapshot recoverability is not checked
    - available does not mean safe to delete

APIs:
    - ec2:DescribeVolumes
```

---

## 17. Implementation Constants

| Constant | Default | Description |
|---|---|---|
| `_DEFAULT_MIN_UNATTACHED_AGE_DAYS` | `7` | Age threshold in days |
