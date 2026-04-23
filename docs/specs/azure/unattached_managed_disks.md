# Azure Rule Spec — `azure.compute.disk.unattached`

## 1. Rule Identity

- **Rule ID:** `azure.compute.disk.unattached`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.Compute/disks`
- **Finding resource_type:** `azure.compute.disk`

---

## 2. Intent

Detect **Azure managed disks that are truly unattached and have remained unattached long enough** to be conservative cleanup review candidates.

This rule is deliberately **low-noise**. It is a **review-candidate** rule only, not proof that a disk is safe to delete, not proof that no cluster / migration / DR workflow exists, and not proof of a specific monthly saving.

---

## 3. Azure Documentation Grounding

### 3.1 Unattached disks keep billing after VM deletion

Microsoft documents that when you delete a VM, attached disks are not deleted by default, and you **continue to pay for unattached disks**.

Source: *Find and delete unattached Azure managed and unmanaged disks*
URL: https://learn.microsoft.com/en-us/azure/virtual-machines/disks-find-unattached-portal

Rule consequence:

1. Unattached managed disks are a valid hygiene surface.
2. The rule should focus on **review candidates**, not automatic delete claims.

### 3.2 Canonical disk state semantics

Microsoft REST documentation for `Microsoft.Compute/disks` defines `diskState`, including:

- `Unattached`
- `Attached`
- `Reserved`
- `Frozen`
- `ActiveSAS`
- `ActiveSASFrozen`
- `ReadyToUpload`
- `ActiveUpload`

Source: *Disks - Get (REST API)*
URL: https://learn.microsoft.com/en-us/rest/api/compute/disks/get?view=rest-compute-2024-11-04

Rule consequence:

1. `managedBy is None` alone is not sufficient proof of ordinary orphaned state.
2. Only `diskState == "Unattached"` is eligible for emission.
3. Upload/export/SAS/hibernation/deallocated states must be skipped.

### 3.3 Ownership-change timing

Microsoft REST documentation defines `LastOwnershipUpdateTime` as the UTC time when disk ownership last changed, such as when the disk was attached or detached, or when the VM it was attached to was deallocated or started.

Source: *Disks - Get (REST API)*
URL: https://learn.microsoft.com/en-us/rest/api/compute/disks/get?view=rest-compute-2024-11-04

Rule consequence:

1. Aging by **creation time alone** is too noisy.
2. When available, `lastOwnershipUpdateTime` is the correct conservative aging signal for unattached duration.

### 3.4 Shared-disk semantics

Microsoft documents that Azure shared disks can be attached to **multiple VMs simultaneously** and are explicitly modeled using `maxShares > 1`. Shared disks are valid clustered-application infrastructure.

Source: *Share an Azure managed disk*
URL: https://learn.microsoft.com/en-us/azure/virtual-machines/disks-shared

Rule consequence:

1. Shared-disk-capable resources are operationally special.
2. To reduce false positives, disks with shared-disk signals should be skipped rather than emitted as ordinary orphaned disks.

### 3.5 Frequent-attach intent

Microsoft ARM / Bicep documentation defines `optimizedForFrequentAttach` as a property for data disks that are frequently detached from one VM and attached to another.

Source: *Microsoft.Compute/disks ARM / Bicep reference*
URL: https://learn.microsoft.com/en-us/azure/templates/microsoft.compute/disks

Rule consequence:

A disk explicitly optimized for frequent attach is an intentional operational pattern and should be skipped to avoid false positives.

### 3.6 Pricing semantics

Microsoft pricing documentation states that managed disk pricing varies by:

- disk type / SKU
- size tier
- redundancy
- for some SKUs, performance configuration
- shared-disk semantics

Source: *Azure Managed Disks pricing*
URL: https://azure.microsoft.com/en-us/pricing/details/managed-disks/

Rule consequence:

1. The rule must **not** use a flat estimate such as `$0.10/GB-month`.
2. `estimated_monthly_cost_usd` should remain `None` unless a future implementation uses a documented, SKU-aware pricing source.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `disk.id` is present and non-empty
2. `disk.name` is present and non-empty
3. the optional region filter matches the normalized location
4. `provisioning_state` resolves to exactly `"Succeeded"`
5. `disk_state` resolves to exactly `"Unattached"`
6. no attachment surfaces are present under the attachment contract
7. the shared-disk exclusion contract is resolved and **not** triggered
8. the frequent-attach exclusion contract is resolved and **not** triggered
9. unattached age resolves reliably and is at least `min_unattached_days`

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the disk is safe
- that no restore / migration / upload workflow is in progress
- that the disk has no disaster recovery purpose
- that the disk is not intentionally retained for reuse
- that the disk produces a specific monthly saving

---

## 6. Canonical Inputs

### 6.1 Required control-plane surfaces

The implementation may use:

- `compute_client.disks.list()`

No guest inspection, VM-level guest metrics, or Azure Monitor metrics are required for this rule.

### 6.2 Unattached-age threshold

- Configurable parameter: none
- Fixed threshold: `min_unattached_days = 7`

Reason:

- This rule is intentionally conservative.
- A short aging buffer reduces false positives from recent VM deletes, detach operations, maintenance, and migration workflows.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase ARM location string; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `provisioning_state` | Compare case-sensitively to canonical Azure value `"Succeeded"` after SDK/raw resolution. |
| `disk_state` | Compare case-sensitively to canonical Azure values such as `"Unattached"` after SDK/raw resolution. |
| `managed_by` | Treat non-empty value as attached. |
| `managed_by_extended` | Treat any non-empty collection / payload as attached. |
| `max_shares` | Value greater than `1` indicates shared-disk capability. |
| `optimized_for_frequent_attach` | `True` indicates intentional frequent detach / attach workflow. Unknown or unresolved must not be treated as `False`. |
| `last_ownership_update_time` | Parse as UTC instant; use as the primary unattached-age signal when present. |
| `time_created` | Parse as UTC instant; use only as fallback age signal if ownership-update time is unavailable. |
| `tags` | `disk.tags or {}` — never `None` in output. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `id` absent, `None`, or empty | Skip |
| 8.2 | `name` absent, `None`, or empty | Skip |
| 8.3 | Region filter set and normalized location does not match | Skip |
| 8.4 | `provisioning_state` does not resolve to `"Succeeded"` | Skip |
| 8.5 | `disk_state` is unknown, missing, or does not resolve to `"Unattached"` | Skip |
| 8.6 | Any attachment surface is present under the attachment contract | Skip |
| 8.7 | Shared-disk exclusion contract is triggered | Skip |
| 8.8 | Frequent-attach exclusion contract is triggered or cannot be resolved reliably | Skip |
| 8.9 | Unattached age is unknown, invalid, in the future, or less than `7` days | Skip |
| 8.10 | All required signals resolve and unattached age is at least `7` days | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Provisioning-state contract

Resolve provisioning state in this order:

1. SDK projection such as `disk.provisioning_state`
2. nested/raw properties projection if present
3. otherwise unknown

Only `"Succeeded"` is eligible for evaluation. Unknown or any other value must skip.

### 9.2 Disk-state contract

Resolve disk state in this order:

1. SDK projection such as `disk.disk_state`
2. nested/raw properties projection such as `properties.diskState`
3. otherwise unknown

Only `"Unattached"` is eligible for emission.

If `disk_state` is unknown, missing, conflicting across control-plane surfaces, or otherwise cannot be resolved reliably, the disk must skip.

Mandatory skips include any other disk state, including:

- `"Attached"`
- `"Reserved"`
- `"Frozen"`
- `"ActiveSAS"`
- `"ActiveSASFrozen"`
- `"ReadyToUpload"`
- `"ActiveUpload"`

### 9.3 Attachment contract

Treat the disk as **attached** when any of the following are true:

1. `managed_by` resolves to a non-empty value
2. `managed_by_extended` resolves to any non-empty collection / payload

Required behavior:

1. Prefer SDK projections first.
2. Fall back to nested/raw properties fields only if needed.
3. Confirmed empty attachment surfaces are eligible to continue; unknown or unresolved attachment surfaces are not equivalent to empty.
4. If attachment surfaces conflict with `disk_state == "Unattached"`, skip rather than emit.
5. If attachment surfaces cannot be resolved reliably, skip rather than emit.

### 9.4 Shared-disk exclusion contract

Skip when reliable control-plane signals indicate the disk is configured for shared-disk use, including:

1. `max_shares > 1`
2. equivalent shared-disk control-plane context is present

Required behavior:

1. Prefer SDK projections first.
2. Fall back to nested/raw properties fields only if needed.
3. If shared-disk context cannot be resolved reliably, skip rather than emit.
4. `max_shares` unknown must not be treated as equivalent to `max_shares == 1`.

### 9.5 Frequent-attach exclusion contract

Skip when `optimized_for_frequent_attach == True`.

This is required because Microsoft explicitly documents it as an intentional frequent detach / attach workflow.

If `optimized_for_frequent_attach` cannot be resolved reliably, the disk must skip rather than emit.

### 9.6 Unattached-age contract

Resolve the primary age signal in this order:

1. `last_ownership_update_time`
2. `time_created`
3. otherwise unknown

Interpretation:

1. If `last_ownership_update_time` is present and valid, use it as the primary conservative attachment-state-change anchor for aging
2. Else if `time_created` is present and valid, use it as a fallback
3. Else age is unknown and the disk must skip
4. If the selected age anchor is invalid, unparseable, or in the future relative to `now`, the disk must skip

Emit only when:

- `now - age_anchor >= 7 days`

Rationale:

`lastOwnershipUpdateTime` is the conservative signal for how recently the disk's ownership state changed, even though it is not a perfect exact measure of unattached duration. This avoids over-flagging old disks that were only recently detached.

### 9.7 Eventual-consistency note

Azure control-plane state can lag briefly around detach, deallocate, SAS, or upload transitions.

Rule consequence:

1. Conflicting control-plane signals must skip rather than emit.
2. The 7-day unattached-age buffer exists partly to reduce transient false positives from detach / state propagation lag.

### 9.8 Context-only fields

The following may appear in details/evidence but must not create or suppress findings directly:

- `sku`
- `disk_size_gb`
- `tier`
- `os_type`
- `zones`
- `network_access_policy`

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** use a flat `$ / GB` estimate
2. Do **not** infer cost from disk size alone
3. Do **not** infer cost from SKU alone
4. Document that Azure managed disk pricing varies by disk type, size tier, redundancy, and for some SKUs performance configuration and shared-disk behavior

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.compute.disk.unattached"` |
| `resource_type` | `"azure.compute.disk"` |
| `resource_id` | Original ARM id from `disk.id` |
| `region` | Normalized location |
| `risk` | `LOW` |
| `confidence` | `MEDIUM` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required evidence

`signals_used` must clearly disclose:

1. provisioning state is `"Succeeded"`
2. disk state is `"Unattached"`
3. `managed_by` is absent
4. `managed_by_extended` is absent / empty
5. shared-disk exclusion contract is resolved and not triggered (`max_shares` known and not greater than `1`, with no equivalent shared-disk signal)
6. frequent-attach exclusion contract is resolved and not triggered (`optimized_for_frequent_attach == False`)
7. unattached age anchor type (`last_ownership_update_time` or `time_created`)
8. unattached age in days

`signals_not_checked` should include remaining blind spots such as:

1. planned future VM attachment
2. undeclared migration or restore intent
3. DR / backup planning intent
4. exact Azure billing amount for this disk
5. resource locks or delete-protection context

### 11.3 Required details

Details should include at least:

- `resource_name`
- `subscription_id`
- `disk_state`
- `managed_by`
- `managed_by_extended`
- `max_shares`
- `optimized_for_frequent_attach`
- `age_anchor`
- `age_days`
- `sku`
- `size_gb`
- `tags`

---

## 12. Failure Behavior

- If the disk list call raises, let the exception propagate
- If an individual disk record is malformed or missing required fields, skip that disk
- If disk state, attachment surfaces, or age signals cannot be resolved reliably, skip that disk
- Do not silently emit on partial control-plane state

---

## 13. Acceptance Examples

### 13.1 Must emit

1. A disk with `provisioning_state == "Succeeded"`, `disk_state == "Unattached"`, no `managed_by`, empty `managed_by_extended`, `max_shares == 1`, `optimized_for_frequent_attach == False`, and `last_ownership_update_time` 10 days ago -> **EMIT**

### 13.2 Must skip

1. `managed_by` present -> **SKIP**
2. `managed_by_extended` non-empty -> **SKIP**
3. `disk_state == "Reserved"` -> **SKIP**
4. `disk_state == "ActiveSAS"` -> **SKIP**
5. `disk_state == "ReadyToUpload"` -> **SKIP**
6. `max_shares > 1` -> **SKIP**
7. `optimized_for_frequent_attach == True` -> **SKIP**
8. `last_ownership_update_time` 2 days ago even if `time_created` is 200 days old -> **SKIP**
9. `provisioning_state != "Succeeded"` -> **SKIP**

---

## 14. Anti-Goals

Implementations must **not**:

1. treat `managed_by is None` as sufficient proof of ordinary unattached state by itself
2. age disks solely from `time_created` when `last_ownership_update_time` is available
3. emit for shared-disk-capable resources
4. emit for upload/export/SAS disk states
5. use flat managed-disk cost estimates

---

## 15. Rule Summary

Rule: `azure.compute.disk.unattached`

- **Signal:** managed disk in `Unattached` state with no attachment surfaces and unattached age >= 7 days
- **Primary exclusions:** non-`Succeeded`, non-`Unattached`, shared disks, frequent-attach disks, recent detachments, upload/export/SAS states
- **Cost model:** `estimated_monthly_cost_usd = None`
