# azure.compute.snapshot.old — Canonical Rule Specification

## 1. Intent

Detect **Azure managed snapshots that are old enough to be cleanup review candidates**
while staying explicit that age alone does **not** prove a snapshot is unused, orphaned,
or safe to delete.

This is a **read-only hygiene rule**. It is not a delete-safe rule, not a backup-policy
validator, and not proof that cost will drop if a snapshot is removed.

---

## 2. Azure Documentation Grounding

### 2.1 Snapshot control-plane shape

Microsoft documents the following snapshot fields in the Azure Compute Snapshot REST API:

| Field | Meaning |
|---|---|
| `id` | Snapshot ARM resource id |
| `name` | Snapshot resource name |
| `location` | Azure region |
| `tags` | Resource tags |
| `properties.timeCreated` | Snapshot creation timestamp |
| `properties.provisioningState` | Resource provisioning state |
| `properties.incremental` | Whether the snapshot is incremental |
| `properties.completionPercent` | Background copy progress for `CopyStart` scenarios when Azure surfaces that field |
| `properties.creationData.createOption` | Source creation mode |
| `properties.creationData.sourceResourceId` | Source disk or snapshot ARM id when relevant |
| `properties.diskSizeGB` | Disk-size property of the snapshot resource |
| `sku.name` | Snapshot storage SKU |

Sources:
- *Snapshots - List*
- *Snapshots - Get*
- *Microsoft.Compute/snapshots template reference*

URLs:
- https://learn.microsoft.com/en-us/rest/api/compute/snapshots/list?view=rest-compute-2025-02-01
- https://learn.microsoft.com/en-us/rest/api/compute/snapshots/get?view=rest-compute-2025-02-01
- https://learn.microsoft.com/en-us/azure/templates/microsoft.compute/snapshots

### 2.2 Snapshot lifecycle meaning

Microsoft documents that a snapshot is a **full, read-only copy** of a virtual hard disk
that exists **independently of the source disk**, and can be used to create new managed
disks.

Source: *Create a snapshot of a virtual hard disk*
URL: https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk

### 2.3 Incremental snapshot meaning

Microsoft documents incremental snapshots as point-in-time backups that store only changes
since the previous snapshot and are commonly used as a more cost-effective backup mechanism.

Source: *Incremental snapshots for managed disks*
URL: https://learn.microsoft.com/en-us/azure/virtual-machines/disks-incremental-snapshots

### 2.4 Billing meaning

Microsoft documents that both full and incremental managed-disk snapshots are billed based
on **used size**, not provisioned disk size. Snapshot billing is separate from the source
disk.

Sources:
- *Create a snapshot of a virtual hard disk*
- *Understand Azure Disk Storage billing*

URLs:
- https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk
- https://learn.microsoft.com/en-us/azure/virtual-machines/disks-understand-billing

### 2.5 Rule-design consequence

These Microsoft-documented facts imply:

1. **Age alone is not an unused signal.**
2. **Age alone is not a delete-safe signal.**
3. **`diskSizeGB` must not be used as monthly billed snapshot cost.**
4. **Incremental snapshots are normal backup artifacts, not suspicious by default.**
5. **This rule should emit review candidates only, with conservative confidence.**
6. **`completionPercent` is a best-effort completion signal when present, not a universally required lifecycle field for every snapshot.**

---

## 3. Scope

**Included:**
- `Microsoft.Compute/snapshots`
- snapshots whose provisioning state is exactly `"Succeeded"`
- snapshots with parseable `timeCreated`
- snapshots meeting the age threshold

**Excluded:**
- snapshots without `id`
- snapshots outside optional region filter
- snapshots without parseable `timeCreated`
- snapshots not in `Succeeded` provisioning state
- snapshots with `completionPercent < 100` when `completionPercent` is present
- snapshots newer than the rule’s review threshold

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `review_age_days` | Fixed lower review threshold: `30` days |
| `max_age_days` | Configurable higher age band, default `90` days |
| `age_days` | `now - timeCreated` in whole UTC days |
| `snapshot_kind` | `"incremental"` when `properties.incremental == true`, else `"full_or_unspecified"` |
| `region_filter` | Optional input; exact lowercase region match only |

### Age bands

| Condition | Meaning |
|---|---|
| `age_days < 30` | Too new; must skip |
| `30 <= age_days < max_age_days` | Old review candidate |
| `age_days >= max_age_days` | Very old review candidate |

---

## 5. Canonical Inputs

| API / signal | Source | Required permission |
|---|---|---|
| Snapshot inventory | `compute_client.snapshots.list()` | `Microsoft.Compute/snapshots/read` |

No secondary APIs are required by this rule.

Implementations must fully iterate the paged result from `snapshots.list()` and must not
stop after the first page.

---

## 6. Signal Model (Strict Separation)

### A. EXCLUSION_RULES

| Condition | Result |
|---|---|
| `id` absent or empty | **SKIP** |
| `region_filter` set and lowercase `location` does not match | **SKIP** |
| `properties.provisioningState != "Succeeded"` | **SKIP** |
| `properties.timeCreated` absent or unparsable | **SKIP** |
| `completionPercent` present and `< 100` | **SKIP** |
| `age_days < review_age_days` | **SKIP** |

### B. DETECTION_SIGNAL

| Condition | Result |
|---|---|
| Snapshot passes exclusion rules and `age_days >= review_age_days` | **EMIT** |

### C. CONTEXTUAL_SIGNALS (non-detecting)

These may appear in evidence/details but must not create or suppress findings directly:

| Signal | Effect |
|---|---|
| `properties.incremental` | Context only |
| `properties.creationData.createOption` | Context only |
| `properties.creationData.sourceResourceId` | Context only |
| `properties.diskSizeGB` | Context only; not billing |
| `sku.name` | Context only |
| `tags` | Context only |

### Hard rules

1. Do **not** infer “unused” from age.
2. Do **not** infer “orphaned” from age.
3. Do **not** infer delete safety from age.
4. Do **not** estimate monthly cost from `diskSizeGB`.
5. Do **not** treat incremental snapshots as suspicious by default.

---

## 7. Evaluation Order (Mandatory)

1. List snapshots
2. Fully iterate all pages returned by snapshot inventory
3. Normalize `location`
4. Apply region filter if provided
5. Require non-empty `id`
6. Resolve provisioning state and require `"Succeeded"`
7. Parse `timeCreated`
8. If `completionPercent` exists, treat it as a best-effort completion signal and require `completionPercent >= 100`
9. Compute `age_days`
10. Skip if `age_days < 30`
11. Build evidence/details
12. Emit finding
13. Assign confidence/risk

---

## 8. Confidence Model

| Condition | Confidence |
|---|---|
| `30 <= age_days < max_age_days` | `LOW` |
| `age_days >= max_age_days` | `MEDIUM` |

### Confidence rule

Age is only a review heuristic. Even at `>= 90` days, Microsoft documentation still
supports ordinary backup, DR, and restore use cases for snapshots. Therefore:

- use `LOW` for the lower age band
- use `MEDIUM` for the higher age band
- never use `HIGH` from age alone

---

## 9. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `LOW` |

Age alone must not elevate risk beyond `LOW`.

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

### Mandatory rules

1. Must not derive cost from `diskSizeGB`
2. Must not derive cost from snapshot age
3. Must disclose through spec/docs that Azure snapshot billing is based on **used size**
4. `diskSizeGB` may appear in details only as non-billing context

---

## 11. Failure Behavior

- If `snapshots.list()` fails, let the exception propagate
- Implementations must fully iterate all pages returned by `snapshots.list()`
- If an individual snapshot record is malformed or missing required fields, skip that snapshot
- Do not silently emit on incomplete creation/provisioning data

---

## 12. Finding Shape

### 12.1 Required top-level fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.compute.snapshot.old"` |
| `resource_type` | `"azure.compute.snapshot"` |
| `resource_id` | Snapshot ARM id |
| `region` | Lowercase location |
| `risk` | `LOW` |
| `confidence` | `LOW` or `MEDIUM` per age band |
| `estimated_monthly_cost_usd` | `None` |

### 12.2 Required evidence

`signals_used` must include:

1. `"Snapshot age is {age_days} days"`
2. `"Snapshot provisioning state is Succeeded"`

`signals_used` may additionally include:

1. `"Snapshot completionPercent is 100"` when that field is present and was used as a best-effort completion gate

`signals_not_checked` should include:

1. `"Business or application restore intent"`
2. `"Azure Backup or external backup ownership"`
3. `"Disaster recovery retention intent"`
4. `"Whether deleting the snapshot reduces billed used size"`

### 12.3 Required details

| Key | Nullable |
|---|---|
| `resource_name` | No |
| `subscription_id` | No |
| `age_days` | No |
| `time_created` | No |
| `disk_size_gb` | Yes |
| `sku` | Yes |
| `incremental` | Yes |
| `source_resource_id` | Yes |
| `tags` | No (`{}` when absent) |

---

## 13. Acceptance Examples

### 13.1 Must emit

1. `provisioningState == "Succeeded"`, `timeCreated = now - 45 days` -> **EMIT**, confidence `LOW`
2. `provisioningState == "Succeeded"`, `timeCreated = now - 120 days` -> **EMIT**, confidence `MEDIUM`
3. Incremental snapshot, `timeCreated = now - 95 days`, all required fields valid -> **EMIT**, confidence `MEDIUM`

### 13.2 Must skip

1. `timeCreated = now - 10 days` -> **SKIP**
2. `provisioningState == "Creating"` -> **SKIP**
3. `timeCreated == None` -> **SKIP**
4. `completionPercent == 80` -> **SKIP**
5. Region filter `"eastus"` and snapshot location `"westus"` -> **SKIP**
6. `id == None` -> **SKIP**

---

## 14. Anti-Goals

Implementations must **not**:

1. label the snapshot as unused based on age alone
2. label the snapshot as orphaned based on age alone
3. estimate monthly cost from `diskSizeGB`
4. upgrade confidence to `HIGH` based on age alone
5. suppress findings because a snapshot is incremental
6. emit findings for snapshots not yet fully provisioned

---

## 15. Rule Summary

Rule: `azure.compute.snapshot.old`

- **Signal:** old managed snapshot age
- **Type:** conservative review candidate
- **Age threshold:** emit at `>= 30 days`
- **Higher age band:** `>= max_age_days` (default `90`) raises confidence only to `MEDIUM`
- **Risk:** `LOW`
- **Cost:** `None` (Azure bills snapshots on used size, not `diskSizeGB`)
