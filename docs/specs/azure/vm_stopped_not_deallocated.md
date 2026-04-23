# Azure Rule Spec — `azure.vm.stopped_not_deallocated`

## 1. Rule Identity

- **Rule ID:** `azure.vm.stopped_not_deallocated`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.Compute/virtualMachines`
- **Finding resource_type:** `azure.virtual_machine`

---

## 2. Intent

Detect Azure virtual machines that are in the **billed stopped-allocated state** — Azure power state `PowerState/stopped` — and therefore still incur compute charges even though they appear off.

This rule is deliberately **low-noise**. It is a **review-candidate** rule only, not proof that the VM should be deleted, not proof that the stop was accidental, and not proof of a specific monthly saving.

---

## 3. Azure Documentation Grounding

### 3.1 Azure VM power states and billing

Microsoft documents that Azure virtual machines expose power states and that billing differs by power state:

- `Starting` — billed
- `Running` — billed
- `Stopping` — billed
- `Stopped` / PoweredOff / Stopped (Allocated) — billed
- `Deallocating` — not billed
- `Deallocated` / Stopped (Deallocated) — not billed

Microsoft also documents that some other resources such as disks and networking can continue to incur charges even when compute is not billed.

Source: *States and billing status of Azure Virtual Machines*
URL: https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing

Rule consequence:

1. `PowerState/stopped` is a valid billed compute hygiene surface.
2. `PowerState/deallocated` and deallocation-related states must not emit.
3. The rule concerns **compute billing semantics**, not total VM-adjacent resource billing.

### 3.2 Power state retrieval surfaces

Microsoft documents that VM runtime state is available from **Instance View**, including a `statuses` array containing entries such as:

- `ProvisioningState/<state>`
- `PowerState/<state>`

Sources:

- *States and billing status of Azure Virtual Machines*
- *Virtual Machines - Instance View (REST API)*
- *azure.mgmt.compute.models.VirtualMachineInstanceView*

URLs:

- https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing
- https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/instance-view?view=rest-compute-2025-04-01
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-compute/azure.mgmt.compute.models.virtualmachineinstanceview?view=azure-python

Rule consequence:

1. Runtime power state must come from an authoritative Instance View–style `statuses` surface.
2. If runtime power state cannot be resolved reliably for a VM, that VM must be skipped rather than guessed.

### 3.3 Subscription-wide power-state retrieval

Microsoft documents that subscription-wide VM power states can be retrieved with `Virtual Machines - List All` using `statusOnly=true`.

Microsoft also documents that in rare situations the power state may be unavailable because of intermittent retrieval issues and recommends retrying or checking Azure Resource Health.

Sources:

- *States and billing status of Azure Virtual Machines*
- *Virtual Machines - List All (REST API)*

URLs:

- https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing
- https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/list-all?view=rest-compute-2025-04-01

Rule consequence:

1. A future implementation may use subscription-wide status retrieval or per-VM instance-view reads.
2. Missing runtime power state must be treated as **unknown -> skip**, not as stopped.

### 3.4 Stopped can be transient during create/start

Microsoft documents that the `Stopped` state can also be observed briefly:

- during VM creation
- while starting a VM from `Stopped (Deallocated)`

Source: *States and billing status of Azure Virtual Machines*
URL: https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing

Rule consequence:

A conservative enterprise-quality rule should not rely on raw `PowerState/stopped` alone. It must also require stable control-plane context so transient create/start observations do not emit.

### 3.5 PowerOff vs Deallocate billing semantics

Microsoft SDK documentation states:

- `begin_power_off` stops a VM while preserving provisioned resources, and **you are still charged**
- `begin_deallocate` releases compute resources, and **you are not billed for compute resources**

Source: *azure.mgmt.compute.operations.VirtualMachinesOperations*
URL: https://learn.microsoft.com/en-us/python/api/azure-mgmt-compute/azure.mgmt.compute.operations.virtualmachinesoperations?view=azure-python

Rule consequence:

The canonical detection target is **powered off but still allocated**, not any generic “off” state.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `vm.id` is present and non-empty
2. `vm.name` is present and non-empty
3. the optional region filter matches the normalized location
4. stable control-plane provisioning state resolves to exactly `"Succeeded"`
5. runtime power state resolves reliably from an authoritative status surface
6. runtime power state resolves to exactly `PowerState/stopped`

If any required signal cannot be established reliably, skip rather than emit.

This rule intentionally prioritizes **precision over recall** and skips unresolved runtime-state cases by design.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the VM is unused
- that the VM should be deleted
- that the stop was accidental
- that a future restart is not planned
- that attached disks, networking, licenses, or reservations are removable
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required control-plane surfaces

The implementation may use either of these authoritative runtime-state approaches:

1. `compute_client.virtual_machines.list_all()` plus per-VM `instance_view(...)`
2. `Virtual Machines - List All` with `statusOnly=true` when runtime power state is available per VM

It may also use the VM model payload for:

- `id`
- `name`
- `location`
- `tags`
- `hardware_profile.vm_size`
- `storage_profile.os_disk.os_type`
- `provisioning_state`

### 6.2 Required runtime-state source

Runtime power state must come from a `statuses` surface that yields codes such as:

- `PowerState/running`
- `PowerState/stopped`
- `PowerState/deallocated`

It must not be inferred from:

- provisioning state alone
- presence or absence of NICs/disks
- guest metrics
- operator assumptions

If an implementation supports more than one runtime-state source, it must define a deterministic precedence order and apply that order consistently. A recommended precedence is:

1. per-VM `instance_view(...)`
2. subscription-wide `listAll(statusOnly=true)` status payload

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase ARM location string; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `provisioning_state` | Compare case-sensitively to canonical Azure value `"Succeeded"` from the model/control-plane resource shape. |
| `power_state_code` | Extract exactly one runtime status code that starts with `PowerState/`. If none exist or multiple conflicting values exist, power state is unknown. |
| `tags` | `vm.tags or {}` — never `None` in output. Tags are contextual only for this rule. |
| `vm_size` | Context only from `hardware_profile.vm_size` when available. |
| `os_type` | Context only from `storage_profile.os_disk.os_type` when available. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `id` absent, `None`, or empty | Skip |
| 8.2 | `name` absent, `None`, or empty | Skip |
| 8.3 | Region filter set and normalized location does not match | Skip |
| 8.4 | `provisioning_state` does not resolve to `"Succeeded"` | Skip |
| 8.5 | runtime power state cannot be retrieved or resolved reliably | Skip |
| 8.6 | runtime power state is anything other than exact `PowerState/stopped` | Skip |
| 8.7 | all required signals resolve and runtime power state is exact `PowerState/stopped` | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Provisioning-state contract

Resolve provisioning state from the VM model/control-plane payload:

1. SDK projection such as `vm.provisioning_state`
2. nested/raw properties projection such as `vm.properties.provisioningState`
3. otherwise unknown

Required behavior:

1. Only exact `"Succeeded"` is eligible.
2. Unknown or any other value must skip.
3. If SDK and nested/raw values both exist and conflict, the VM must skip.

Rationale:

This helps avoid transient false positives because Microsoft documents that `Stopped` can appear briefly during creation or while starting from deallocated.

### 9.2 Runtime power-state contract

Resolve runtime power state from an authoritative `statuses` collection.

Required behavior:

1. If more than one runtime-state source is available, use the implementation's defined deterministic precedence order consistently.
2. Select only codes that start with `PowerState/`.
3. If no power-state code is present, the VM must skip.
4. If multiple conflicting power-state codes are present, the VM must skip.
5. Emit only for exact `PowerState/stopped`.

Mandatory skips include:

- `PowerState/running`
- `PowerState/starting`
- `PowerState/stopping`
- `PowerState/deallocating`
- `PowerState/deallocated`
- any unknown, malformed, or conflicting power-state code

### 9.3 Transitional-state contract

This rule must be conservative around transient state.

Required behavior:

1. If runtime power state is unavailable because status retrieval failed or returned incomplete data, skip.
2. If provisioning state is not stable-success, skip.
3. Do not emit for “probably stopped” or last-known stale power state without reliable current status.

Coverage note:

This rule intentionally trades some recall for reliability. Missing or incomplete runtime power state may cause otherwise valid stopped-allocated VMs to be skipped under partial API-health conditions, and that is acceptable by design.

### 9.4 Cost semantics contract

This rule may state that **compute charges continue** for stopped-allocated VMs because Microsoft documents that behavior.

However:

1. `estimated_monthly_cost_usd` must remain `None`
2. the rule must not claim exact total VM cost
3. the rule must not claim that all VM-adjacent charges disappear after deallocation, because disks and networking may still incur charges

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

The rule may describe billed compute semantics qualitatively, but must not emit a numeric monthly estimate without a documented SKU-aware pricing model.

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.vm.stopped_not_deallocated"` |
| `resource_type` | `"azure.virtual_machine"` |
| `resource_id` | original ARM id from `vm.id` |
| `region` | normalized location |
| `risk` | `HIGH` |
| `confidence` | `HIGH` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required evidence

`signals_used` must clearly disclose:

1. provisioning state is `"Succeeded"`
2. runtime power state is exact `PowerState/stopped`
3. stopped-allocated VMs continue to incur compute charges

`signals_not_checked` should include remaining blind spots such as:

1. whether the stop was intentional
2. planned restart or future usage
3. IaC-managed or schedule-managed intent
4. reservation, savings plan, or licensing context

### 11.3 Required details

Details should include at least:

- `vm_name`
- `subscription_id`
- `power_state`
- `provisioning_state`
- `vm_size`
- `os_type`
- `tags`

---

## 12. Failure Behavior

- If subscription-wide VM inventory fails, let the exception propagate
- If per-VM runtime-status retrieval fails for a specific VM, skip that VM
- If a VM record is malformed or missing required fields, skip that VM
- Do not emit on missing, incomplete, or conflicting runtime power state
