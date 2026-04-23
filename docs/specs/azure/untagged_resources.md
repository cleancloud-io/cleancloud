# Azure Rule Spec — `azure.resource.untagged`

## 1. Rule Identity

- **Rule ID:** `azure.resource.untagged`
- **Provider:** Azure
- **Supported ARM resource types:** `Microsoft.Compute/disks`, `Microsoft.Compute/snapshots`
- **Finding resource_type values:** `azure.compute.disk`, `azure.compute.snapshot`

---

## 2. Intent

Detect supported Azure compute resources that currently have **zero direct resource tags** and have remained in that state long enough to be conservative governance review candidates.

This is a **read-only hygiene rule**. It is **not** a waste rule, **not** proof that a resource violates a mandatory tagging policy, and **not** proof that a resource is safe to delete.

---

## 3. Azure Documentation Grounding

### 3.1 Azure tag semantics

Microsoft documents that Azure tags are **key-value metadata** applied to resources, resource groups, and subscriptions.

Microsoft also documents that:

- tag names are case-insensitive for operations
- tag values are case-sensitive
- tags are stored as plain text
- resources do **not** inherit tags from their resource group or subscription unless separate policy/remediation mechanisms are used

Source: *Use tags to organize your Azure resources and management hierarchy*
URL: https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources

Rule consequence:

1. This rule must evaluate only whether the **resource itself** currently has direct tags.
2. Resource-group or subscription tags must **not** be treated as equivalent to resource tags.
3. The rule must not evaluate required tag keys, tag values, or tag-policy compliance.

### 3.2 Tag support and policy remediation

Microsoft documents that:

- not all Azure resource types support tags
- Azure Policy can add, replace, or inherit tags during create/update
- remediation tasks can apply tags to existing resources later

Sources:

- *Tag support for Azure resources*
- *Tutorial: Govern tag compliance using Azure Policy*

URLs:

- https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-support
- https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-policies

Rule consequence:

1. This rule must stay limited to resource families with documented tag support and inventory contracts.
2. A conservative age buffer is appropriate to reduce transient post-deployment or pending-remediation noise.

### 3.3 Managed disk inventory shape

Microsoft Compute REST and SDK documentation for `Microsoft.Compute/disks` shows list/inventory objects include fields such as:

- `id`
- `name`
- `location`
- `tags`
- `provisioningState`
- `timeCreated`
- `managedBy`
- `managedByExtended`
- `diskState`

Sources:

- *Disks - List (REST API)*
- *azure.mgmt.compute.models.Disk*

URLs:

- https://learn.microsoft.com/en-us/rest/api/compute/disks/list?view=rest-compute-2025-04-01
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-compute/azure.mgmt.compute.models.disk?view=azure-python

Rule consequence:

1. Direct disk tag state can be evaluated from the disk resource payload itself.
2. Disk attachment state may be used as **context** for confidence, but it must not change whether a reliably untagged disk is emitted.

### 3.4 Snapshot inventory shape

Microsoft Compute REST and SDK documentation for `Microsoft.Compute/snapshots` shows list/inventory objects include fields such as:

- `id`
- `name`
- `location`
- `tags`
- `provisioningState`
- `timeCreated`

Sources:

- *Snapshots - List (REST API)*
- *azure.mgmt.compute.models.Snapshot*

URLs:

- https://learn.microsoft.com/en-us/rest/api/compute/snapshots/list?view=rest-compute-2025-04-01
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-compute/azure.mgmt.compute.models.snapshot?view=azure-python

Rule consequence:

Direct snapshot tag state can be evaluated from the snapshot resource payload itself.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. the resource belongs to a supported family: managed disk or snapshot
2. `resource.id` is present and non-empty
3. `resource.name` is present and non-empty
4. the optional region filter matches the normalized location
5. `provisioning_state` resolves to exactly `"Succeeded"`
6. direct resource tag state resolves reliably
7. direct current tag count is `0`
8. resource age resolves reliably and is at least `7` days

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the resource is unused or wasteful
- that deleting the resource is safe
- that the resource violates a required-tag policy
- that inherited resource-group or subscription tags are absent
- that Azure Policy remediation is or is not pending
- that a specific monthly saving exists

---

## 6. Canonical Inputs

### 6.1 Required control-plane surfaces

The implementation may use:

- `compute_client.disks.list()`
- `compute_client.snapshots.list()`

It must not require:

- Azure Resource Graph
- Resource Groups Tagging APIs
- Azure Policy compliance APIs
- resource group or subscription tag lookups

### 6.2 Untagged-age threshold

- Configurable parameter: none
- Fixed threshold: `min_untagged_age_days = 7`

Reason:

- Azure Policy remediation and deployment workflows can apply tags after initial creation/update.
- A short fixed buffer reduces transient governance noise without changing the factual tag contract.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `resource_family` | One of `managed_disk` or `snapshot`; any other family is out of scope. |
| `location` | Lowercase ARM location string; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `provisioning_state` | Compare case-sensitively to canonical Azure value `"Succeeded"` after SDK/raw resolution. Values such as `"SucceededWithWarnings"` or `"succeeded"` are not equivalent. |
| `tags` | Direct resource tags only. `None` or empty mapping means zero direct tags. Non-empty mapping means tagged. Missing tag field or non-mapping non-`None` values are unresolved and must skip. |
| `time_created` | Parse as UTC instant. If absent, invalid, or in the future, age is unknown. |
| `managed_by` | Disk-only context. Non-empty value indicates direct VM attachment context. |
| `managed_by_extended` | Disk-only context. Any non-empty collection / payload indicates shared-attachment context. |
| `disk_state` | Disk-only context. Compare case-sensitively to Azure values such as `"Unattached"` after SDK/raw resolution when used for confidence context. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | Unsupported family | Skip |
| 8.2 | `id` absent, `None`, or empty | Skip |
| 8.3 | `name` absent, `None`, or empty | Skip |
| 8.4 | Region filter set and normalized location does not match | Skip |
| 8.5 | `provisioning_state` does not resolve to `"Succeeded"` | Skip |
| 8.6 | Direct tag state is unknown or cannot be resolved reliably | Skip |
| 8.7 | Direct current tag count is greater than `0` | Skip |
| 8.8 | Resource age is unknown, invalid, in the future, or less than `7` days | Skip |
| 8.9 | All required signals resolve and direct current tag count is `0` for a supported resource | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Supported-scope contract

This rule is intentionally limited to:

1. Azure managed disks
2. Azure snapshots

It must not claim coverage of all Azure resources or all taggable Azure resource types.

### 9.2 Provisioning-state contract

Resolve provisioning state in this order:

1. SDK projection such as `resource.provisioning_state`
2. nested/raw properties projection such as `resource.properties.provisioningState`
3. otherwise unknown

Required behavior:

1. Only `"Succeeded"` is eligible for evaluation.
2. Values such as `"SucceededWithWarnings"` or `"succeeded"` are not equivalent to `"Succeeded"` and must skip.
3. If SDK and nested/raw values both exist and conflict, the resource must skip.
4. Unknown or any other value must skip.

### 9.3 Direct-tag contract

The authoritative tag source for this rule is the **direct resource `tags` payload** on the disk or snapshot inventory object.

Required behavior:

1. Prefer the SDK/resource field such as `resource.tags`.
2. Treat `None` as zero direct tags.
3. Treat an empty mapping such as `{}` as zero direct tags.
4. Treat a non-empty mapping as tagged.
5. If the tag field is missing entirely or is a non-mapping non-`None` value, tag state is unresolved and the resource must skip.
6. Do **not** synthesize tag state from resource-group tags, subscription tags, Azure Policy assignments, or inheritance assumptions.

### 9.4 Age contract

Resolve creation time in this order:

1. SDK projection such as `resource.time_created`
2. nested/raw properties projection such as `resource.properties.timeCreated`
3. otherwise unknown

Required behavior:

1. If SDK and nested/raw creation times both exist and conflict materially, the resource should skip rather than guess.
2. If creation time is absent, invalid, unparseable, or in the future, the resource must skip.
3. Emit only when `now - creation_time >= 7 days`.

### 9.5 Disk attachment context contract

Disk attachment context is **confidence-only context**, not a baseline eligibility requirement.

Use disk attachment context only to distinguish:

1. a directly untagged disk that also appears ordinarily unattached
2. a directly untagged disk whose attachment context is attached, special-state, or unresolved

Required behavior:

1. A reliably untagged disk that satisfies the baseline rule must still emit even if attachment context is attached or unresolved.
2. Higher confidence is allowed only when unattached context resolves conservatively.
3. If disk attachment context indicates the disk is attached, special-state, or unresolved, confidence must remain `LOW`.
4. Snapshot findings do not use disk attachment context.

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Missing tags are a governance / allocability metadata issue, not a canonical Azure price signal.

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.resource.untagged"` |
| `resource_type` | `azure.compute.disk` or `azure.compute.snapshot` |
| `resource_id` | Original ARM id from the resource object |
| `region` | Normalized location |
| `risk` | `LOW` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Confidence contract

- **Managed disk:** `MEDIUM` only when the resource is reliably untagged **and** ordinary unattached-disk context resolves conservatively
- **Managed disk:** otherwise `LOW`
- **Snapshot:** `LOW`

### 11.3 Required evidence

`signals_used` must clearly disclose:

1. supported resource family
2. provisioning state is `"Succeeded"`
3. direct resource tags resolved to zero current tags
4. resource age in days and the `>= 7 days` threshold
5. for disks, whether attachment context appears ordinarily unattached, attached, special-state, or unresolved
6. for disks, whether attachment context strengthened confidence or remained context-only

`signals_not_checked` should include remaining blind spots such as:

1. required tag-key or tag-value policy compliance
2. Azure Policy remediation status
3. resource-group or subscription tag intent
4. IaC-managed ownership intent
5. future planned usage or DR / backup purpose

### 11.4 Required details

Details should include at least:

- `resource_name`
- `subscription_id`
- `resource_family`
- `tags_present`
- `current_tag_count`
- `age_days`
- `provisioning_state`
- `tags`

For disks, details may also include:

- `disk_state`
- `managed_by`
- `managed_by_extended`

---

## 12. Failure Behavior

- If `disks.list()` raises, let the exception propagate for the disk pass
- If `snapshots.list()` raises, let the exception propagate for the snapshot pass
- If an individual resource record is malformed or missing required fields, skip that resource
- Do not emit on partial or unresolved direct-tag state
- Do not infer tag presence from parent scopes
