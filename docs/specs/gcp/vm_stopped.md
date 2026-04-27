# GCP Rule Spec - `gcp.compute.vm.stopped`

## 1. Rule Identity

- **Rule ID:** `gcp.compute.vm.stopped`
- **Provider:** GCP
- **Resource type:** Compute Engine VM instance
- **Finding resource_type:** `gcp.compute.instance`

---

## 2. Intent

Detect **Compute Engine VM instances in the documented stopped lifecycle state** that have remained stopped for at least the configured threshold and therefore represent conservative review candidates for cleanup of lingering attached-cost surfaces.

This rule is deliberately **precision-first**. It is a **review-candidate** rule only, not proof that the VM is abandoned, not proof that attached resources should be deleted, and not proof of a specific monthly saving.

### 2.1 Canonical definitions

| Term | Definition |
|---|---|
| `STOPPED_VM` | Normalized stopped lifecycle state: exact raw `"TERMINATED"` or exact raw `"STOPPED"` |
| active MIG membership | The instance is currently controlled by a managed instance group, not merely historically created by or once attached to one |

---

## 3. GCP Documentation Grounding

### 3.1 Instance resource exposes canonical lifecycle and stop/start timestamps

Google documents the Compute Engine `Instance` resource with fields including:

1. `status`
2. `creationTimestamp`
3. `zone`
4. `machineType`
5. `disks`
6. `labels`
7. `lastStartTimestamp`
8. `lastStopTimestamp`
9. `lastSuspendedTimestamp`
10. `scheduling`

Source:

- *Resource: instances*

URL:

- https://cloud.google.com/compute/docs/reference/rest/v1/instances

Rule consequence:

1. VM eligibility must be based on documented instance control-plane fields.
2. `lastStopTimestamp` is the canonical stop-age signal for this rule.
3. `lastStartTimestamp`, disk attachment shape, and scheduling fields are context only.

### 3.2 Compute Engine lifecycle defines the exact stopped state

Google documents instance lifecycle states including:

- `PROVISIONING`
- `STAGING`
- `RUNNING`
- `STOPPING`
- `TERMINATED`
- `REPAIRING`
- `SUSPENDING`
- `SUSPENDED`

Google also documents that `TERMINATED` means Compute Engine has completed the stop operation and the attached resources remain attached unless detached.

Google's lifecycle documentation also distinguishes between UI wording and API wording: when you stop a VM, the Google Cloud console shows the instance as **stopped**, while the Compute Engine API reports the same stopped lifecycle state as `TERMINATED`.

Sources:

- *Compute Engine instance lifecycle*
- *Resource: instances*

URLs:

- https://docs.cloud.google.com/compute/docs/instances/instance-lifecycle
- https://cloud.google.com/compute/docs/reference/rest/v1/instances

Rule consequence:

1. The rule uses the canonical definition of `STOPPED_VM`.
2. Transitional states such as `STOPPING` and `SUSPENDING` must skip.
3. Suspended-state resources are out of scope for this rule because suspend has different billing semantics.

### 3.3 Billing semantics differ for stopped versus suspended instances

Google documents that:

1. CPU usage is billed while an instance is `RUNNING` or `PENDING_STOP`
2. memory usage is billed while an instance is `RUNNING`, `PENDING_STOP`, `SUSPENDING`, or `SUSPENDED`
3. attached resources such as disks or external IP addresses are billed until the resources no longer exist, regardless of instance state

Google also documents that while an instance is in `STOPPING` or `TERMINATED`, you do not incur CPU charges, but attached resources remain billable.

Sources:

- *Compute Engine instance lifecycle*
- *Suspend, stop, or reset Compute Engine instances*

URLs:

- https://docs.cloud.google.com/compute/docs/instances/instance-lifecycle
- https://docs.cloud.google.com/compute/docs/instances/suspend-stop-reset-instances-overview

Rule consequence:

1. This rule is about **stopped instances with still-billable attached resources**, not about billed CPU/runtime.
2. `SUSPENDED` must stay out of scope because suspended instances still have memory-storage billing semantics not shared with stopped instances.
3. The rule must not estimate total cost from VM runtime pricing alone.

### 3.4 Stopped instances retain attached resources and some identifiers

Google documents that when you stop an instance:

1. attached disks are maintained
2. internal IP and MAC addresses are maintained
3. static external IP addresses are maintained
4. ephemeral external IP addresses are released

Source:

- *Suspend, stop, or reset Compute Engine instances*

URL:

- https://docs.cloud.google.com/compute/docs/instances/suspend-stop-reset-instances-overview

Rule consequence:

1. Disk and static-IP context can be relevant to cleanup review.
2. The rule must not assume every stopped instance still has an external IP cost.
3. Attached-resource counts and shapes are valid evidence/details context, but not enough for a trustworthy universal cost estimate.

### 3.5 Managed instance groups are operationally different

Google documents that managed instance groups (MIGs) manage VM lifecycle and can resize, recreate, autoheal, and repair instances. Google also documents VM detail surfaces that show whether a VM is part of an instance group, and managed-instance-group info surfaces identify the VM instances that belong to each MIG.

Sources:

- *View the details of a VM*
- *View info about MIGs and managed instances*

URLs:

- https://docs.cloud.google.com/compute/docs/instances/view-vm-details
- https://docs.cloud.google.com/compute/docs/instance-groups/getting-info-about-migs

Rule consequence:

1. If the implementation can prove that a VM has active MIG membership, the rule should skip it.
2. Managed instances should not be treated the same as standalone stopped VMs because the group can intentionally recreate, repair, or replace them.
3. Proof of active MIG membership may come only from first-party instance-group or instance-metadata signals exposed by Google Cloud surfaces.
4. Example proof signals include instance metadata such as `created-by` referencing `instanceGroupManagers/...`, or direct managed-instance-group membership surfaces.
5. The rule must not guess from names, labels, or other weak heuristics.

### 3.6 Aggregated instance inventory supports partial success

Google documents that `instances.aggregatedList` retrieves instances across all regions and zones and recommends setting `returnPartialSuccess=true` to prevent total failure on large or partially failing projects.

Google also documents that partial success can return scope-level warnings rather than a fully complete inventory.

Source:

- *Method: instances.aggregatedList*

URL:

- https://cloud.google.com/compute/docs/reference/rest/v1/instances/aggregatedList

Rule consequence:

1. Aggregated inventory should opt in to partial success.
2. Partial coverage must be surfaced and must not be treated as a clean project.

### 3.7 Pricing is too variable for a fixed stopped-VM cost estimate

Google documents that:

1. VM runtime pricing is separate from disk, image, networking, sole tenancy, and GPU pricing
2. attached resources keep billing according to their own pricing surfaces
3. static external IP pricing is documented separately from VM runtime pricing

Sources:

- *Compute Engine VM instance pricing*
- *All networking pricing*

URLs:

- https://cloud.google.com/compute/vm-instance-pricing
- https://cloud.google.com/vpc/network-pricing#ipaddress

Rule consequence:

1. The rule must not hardcode a flat per-GB stopped-VM estimate.
2. `estimated_monthly_cost_usd` should remain `None` unless a future implementation computes pricing from authoritative current resource-specific pricing inputs.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `instance.name` is present and non-empty
2. the aggregated scope key resolves to an exact zone
3. if a region filter is set, the normalized region is parseable and matches it
4. the instance is not proven to have active MIG membership
5. the normalized lifecycle state resolves to `STOPPED_VM`
6. `lastStopTimestamp` is present and parseable
7. stop age is greater than or equal to `max_age_days`

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the VM is abandoned
- that the VM should be deleted
- that attached disks or static IPs are safe to remove
- that the VM is not intentionally kept for forensics, rollback, or future restart
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required surface

| Surface | Purpose |
|---|---|
| `instances.aggregatedList` | enumerate VM instances across zones with lifecycle, timestamps, disks, labels, machine type, and scheduling context |

### 6.2 Threshold

| Parameter | Meaning |
|---|---|
| `max_age_days` | Review threshold in days; default `30` |

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `status` | Resolve the raw lifecycle state from the source surface. Normalize it using the canonical `STOPPED_VM` definition. Otherwise preserve the raw state. |
| `zone_scope` | Resolve only from exact aggregated scope keys in the form `zones/ZONE`. Any other scope key is unusable. |
| `zone` | Extract exact zone name from the resolved `zone_scope`. |
| `region` | Derive from the resolved zone when parseable. If region derivation is not parseable from the zone string, preserve `"unknown"` rather than skipping evaluation. |
| `last_stop_timestamp` | Parse from documented RFC3339 `lastStopTimestamp`. Unparseable values are unusable. |
| `last_start_timestamp` | Preserve exact documented RFC3339 value when present; context only. |
| `machine_type` | Preserve the final machine type segment when the URL/path is parseable; otherwise unknown. |
| `mig_membership` | Preserve only if the implementation can prove active MIG membership from the allowed first-party proof sources in this spec: direct managed-instance-group membership surfaces, or current instance metadata such as `created-by` referencing `instanceGroupManagers/...`. No guessing. |
| `persistent_disk_count` | Count only attached disks where `type == "PERSISTENT"`. |
| `persistent_disk_total_gb` | Sum attached persistent `diskSizeGb` values as non-negative integers when parseable; otherwise preserve unknown/`0` for context only. |
| `disk_kinds_present` | Preserve, on a best-effort basis from instance-attached disk metadata, the distinct attached-disk kinds exposed on the instance surface, such as `PERSISTENT` and `SCRATCH`, as context only. |
| `boot_disk_count` | Count attached disks where documented boot flag is true. |
| `external_nat_ip_present` | True when any network interface access config exposes `natIP`; context only. |
| `gpu_attached` | True when `guestAccelerators` contains one or more accelerator attachments; context only. |
| `labels` | `instance.labels or {}` - never `None` in output. |
| `automatic_restart` | Preserve exact `scheduling.automaticRestart` when present; context only. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | instance record malformed or `name` absent / empty | Skip |
| 8.2 | aggregated scope key does not resolve to exact `zones/ZONE` | Skip |
| 8.3 | region filter set and normalized region is unknown or does not exactly match | Skip and surface `region_unparseable` only in `signals_not_checked` or `skip_reason` when region is unknown |
| 8.4 | instance is proven to have active MIG membership | Skip |
| 8.5 | normalized lifecycle state absent, unknown, or not `STOPPED_VM` | Skip |
| 8.6 | `lastStopTimestamp` absent or unparsable | Skip and surface `missing_last_stop_timestamp` only in `signals_not_checked` or `skip_reason` when such diagnostics exist |
| 8.7 | stop age `< max_age_days` | Skip |
| 8.8 | all required signals resolve and stop age `>= max_age_days` | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Inventory contract

Required behavior:

1. Enumerate instances from `instances.aggregatedList`.
2. Use `returnPartialSuccess=true`.
3. Fully iterate all pages.
4. Surface any partial-coverage warnings.
5. Partial inventory coverage must not be treated as a clean project.

### 9.2 Scope / zone contract

Required behavior:

1. Accept only aggregated scope keys in exact `zones/ZONE` form.
2. Extract the zone name from the scope key only when the key resolves unambiguously.
3. Derive region from the zone when parseable.
4. If region derivation is not parseable from the zone string, preserve `"unknown"` rather than guessing.
5. If region derivation is not parseable and diagnostics exist, use the literal code `region_unparseable` only in `signals_not_checked` or `skip_reason`.
6. If a region filter is set and normalized region is `"unknown"`, skip because the filter cannot be evaluated reliably.
7. If the scope key itself is malformed, skip rather than guess.

Rationale:

Preserving `"unknown"` is safer than guessing a region from a future or non-standard zone format. `region_unparseable` is a diagnostic-only signal and must never appear as emitted finding evidence.

### 9.3 Lifecycle-state contract

Required behavior:

1. Normalize the stopped lifecycle state to internal `STOPPED_VM`.
2. Apply the canonical `STOPPED_VM` definition consistently across supported source surfaces.
3. Transitional or non-stopped states such as `PROVISIONING`, `STAGING`, `RUNNING`, `STOPPING`, `REPAIRING`, `SUSPENDING`, and `SUSPENDED` must skip.
4. Unknown or unresolved status must skip.

Rationale:

Google documents `TERMINATED` as the API state after the stop operation is complete, while many user-facing or tooling surfaces describe that same condition as stopped. Transitional and suspended states have different operational and billing semantics.

### 9.4 MIG exclusion contract

Required behavior:

1. Skip only when the implementation can prove that a VM has active MIG membership.
2. Accept proof only from the allowed first-party proof sources in this spec.
3. Allowed proof sources are limited to:
   a. direct managed-instance-group membership surfaces
   b. current instance metadata such as `created-by` referencing `instanceGroupManagers/...`
4. Do not infer MIG membership from weak heuristics such as naming patterns, labels, vague metadata, or historical-only hints.
5. If MIG membership cannot be established reliably from the allowed proof sources, continue with normal evaluation rather than guessing.

Rationale:

Managed instance groups intentionally manage VM lifecycle, including replacement, repair, resizing, and recreation. A stopped VM inside a MIG is not equivalent to an independently owned standalone VM.

### 9.5 Stop-age contract

Required behavior:

1. Parse `lastStopTimestamp` as RFC3339.
2. Compute `stop_age_days` as whole UTC days between `now` and parsed `last_stop_timestamp`.
3. Emit only when `stop_age_days >= max_age_days`.
4. If `lastStopTimestamp` is absent or unparsable, skip rather than guess.
5. Do **not** substitute `creationTimestamp`, `lastStartTimestamp`, or other lifecycle fields for stop age.
6. When skip diagnostics or debug signals exist, use the literal code `missing_last_stop_timestamp` for this blind spot.
7. `missing_last_stop_timestamp` belongs only in `signals_not_checked` or `skip_reason`; it must never appear as evidence for an emitted finding.

Rationale:

`lastStopTimestamp` is the canonical control-plane stop-age signal. Some older or otherwise atypical VMs might not expose a usable stop timestamp; this rule intentionally skips those instances rather than backfilling age from weaker signals, and should surface `missing_last_stop_timestamp` only in `signals_not_checked` or `skip_reason` when such diagnostics exist. A future extension could use audit-log evidence, but that is out of scope for this rule.

### 9.6 Cost model contract

Required behavior:

1. `estimated_monthly_cost_usd = None`
2. Do **not** estimate cost from attached disk size alone.
3. Do **not** hardcode a flat pd-standard rate.
4. Persistent disk counts/sizes, attached-disk kinds, external NAT IP presence, boot-disk presence, and GPU attachment may appear as context only.

Rationale:

Google documents that attached resources continue billing, but the specific pricing depends on the actual resource mix and its own pricing surface. A fixed pd-standard estimate is not a trustworthy canonical result.

### 9.7 Confidence contract

Required behavior:

| Condition | Confidence |
|---|---|
| `max_age_days <= stop_age_days < 90` | `MEDIUM` |
| `stop_age_days >= 90` | `HIGH` |

Rationale:

Stop age is the primary confidence driver. Confidence may be nudged upward within this age-led model when the stopped VM has no external NAT IP and no GPU attachment, because those traits reduce obvious restart dependencies. Large persistent-disk footprint can strengthen cleanup-review priority and may modestly strengthen confidence only in combination with the rest of the stopped-resource picture, but it must not override the age-led precision model by itself.
These nudges do not override the age-based confidence tiers.

### 9.8 Risk contract

Required behavior:

| Condition | Risk |
|---|---|
| Finding emitted | `MEDIUM` |

Rationale:

Stopped VMs often still anchor important attached resources and can be intentionally retained for rollback, forensics, or later restart.

### 9.9 Failure behavior contract

Required behavior:

1. `compute.instances.list` permission failures should surface as a permission error.
2. If the Compute Engine API is unavailable / disabled for the project, returning no findings is acceptable.
3. Malformed instance records should be skipped item-by-item rather than failing the whole rule.

---

## 10. Finding Shape

### 10.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"gcp"` |
| `rule_id` | `"gcp.compute.vm.stopped"` |
| `resource_type` | `"gcp.compute.instance"` |
| `resource_id` | canonical project/zone/instance path |
| `region` | derived region from zone, or `"unknown"` when region derivation is not parseable |
| `risk` | `MEDIUM` |
| `estimated_monthly_cost_usd` | `None` |

### 10.2 Required evidence

`signals_used` must clearly disclose:

1. instance is in `STOPPED_VM` state, including the raw lifecycle state when useful
2. stop age in days
3. threshold in days
4. persistent disk count and total size as context only
5. machine type when present
6. boot-disk presence when present
7. `automaticRestart` context when present
8. attached-disk kinds when present
9. external NAT IP presence when present
10. GPU attachment flag when present

Diagnostic-only codes such as `missing_last_stop_timestamp` and `region_unparseable` must never appear in `signals_used`; they belong only in `signals_not_checked` or `skip_reason`.

`signals_not_checked` should include remaining blind spots such as:

1. planned seasonal or scheduled shutdown intent
2. rollback, forensics, or future restart intent
3. exact resource-specific monthly pricing for disks and IPs was not estimated
4. static external IP usage and billing state were not fully resolved
5. `missing_last_stop_timestamp` for older or atypical VMs that are intentionally skipped when no usable stop timestamp exists
6. `region_unparseable` when region derivation from zone is not parseable

### 10.3 Required details

Details should include at least:

- `instance_name`
- `machine_type`
- `zone`
- `raw_status`
- `stop_age_days`
- `max_age_days_threshold`
- `last_stop_timestamp`
- `mig_membership`
- `persistent_disk_count`
- `persistent_disk_total_gb`
- `disk_kinds_present`
- `boot_disk_count`
- `external_nat_ip_present`
- `gpu_attached`
- `labels`

When present, details should also include:

- `last_start_timestamp`
- `automatic_restart`

---

## 11. Failure Behavior

- Instance list permission denied -> raise permission error
- Compute Engine API disabled / not found -> return no findings
- Partial aggregated coverage -> surface warning / incomplete coverage signal
- Malformed scope key or instance record -> skip that item
