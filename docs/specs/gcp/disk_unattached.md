# GCP Rule Spec - `gcp.compute.disk.unattached`

## 1. Rule Identity

- **Rule ID:** `gcp.compute.disk.unattached`
- **Provider:** GCP
- **Resource type:** Compute Engine persistent disk
- **Finding resource_type:** `gcp.compute.disk`

---

## 2. Intent

Detect **Compute Engine persistent disks that are currently unattached to any VM and still bill for storage** so they can be reviewed as conservative cleanup candidates.

This rule is deliberately **precision-first**. It is **not** proof that deleting a disk is safe, **not** proof that no failover / restore workflow exists, and **not** proof of a specific monthly saving. It is a conservative review-candidate rule for disks that are present, billable, and currently unattached.

---

## 3. GCP Documentation Grounding

### 3.1 Persistent disks are independent resources that continue to exist outside VM lifecycle

Google documents persistent disks as Compute Engine storage resources used by VM instances, with separate zonal and regional disk resources.

Sources:

- *Resource: Disk*
- *Resource: regionDisks*

URLs:

- https://cloud.google.com/compute/docs/reference/rest/v1/disks
- https://cloud.google.com/compute/docs/reference/rest/v1/regionDisks

Rule consequence:

1. Unattached persistent disks are a valid hygiene review surface.
2. The rule should operate from disk control-plane state, not VM guest inspection.

### 3.2 Canonical attachment signal is the disk `users[]` field

Google documents for both zonal and regional disk resources:

1. `users[]` is an output-only list of attached-instance links
2. `lastAttachTimestamp` is the last attach timestamp
3. `lastDetachTimestamp` is the last detach timestamp

Sources:

- *Resource: Disk*
- *Resource: regionDisks*

URLs:

- https://cloud.google.com/compute/docs/reference/rest/v1/disks
- https://cloud.google.com/compute/docs/reference/rest/v1/regionDisks

Rule consequence:

1. `users[]` is the canonical current-attachment surface for this rule.
2. `lastDetachTimestamp` and `lastAttachTimestamp` are contextual timing signals only.
3. A disk with any current `users[]` entry is attached and out of scope.

### 3.3 Disk creation status is documented and only `READY` is stably evaluable

Google documents disk status values including:

- `CREATING`
- `RESTORING`
- `FAILED`
- `READY`
- `DELETING`

Source:

- *Resource: Disk*

URL:

- https://cloud.google.com/compute/docs/reference/rest/v1/disks

Rule consequence:

1. Only `status == "READY"` is eligible for emission.
2. `CREATING`, `RESTORING`, `FAILED`, and `DELETING` must skip.

### 3.4 Aggregated disk inventory returns zonal and regional scope separately

Google documents `disks.aggregatedList` as an aggregated list of persistent disks and describes per-scope results. The response includes disk fields for both zonal and regional disks and supports partial-success behavior.

Source:

- *Method: disks.aggregatedList*

URL:

- https://cloud.google.com/compute/docs/reference/rest/v1/disks/aggregatedList

Rule consequence:

1. The rule may enumerate disks via aggregated inventory.
2. Scope keys should be interpreted conservatively as zonal or regional inventory context.
3. Unknown or unsupported scope kinds must skip.
4. Partial-success behavior exists and must be handled conservatively by implementations.

### 3.5 Regional persistent disks are explicitly high-availability infrastructure

Google documents regional persistent disks and Hyperdisk Balanced High Availability as synchronously replicated storage for high-availability services, failover, and lower RPO/RTO designs.

Sources:

- *About regional persistent disk*
- *Create and manage regional disks*

URLs:

- https://cloud.google.com/compute/docs/disks/about-regional-persistent-disk
- https://cloud.google.com/compute/docs/disks/regional-persistent-disk

Rule consequence:

1. Regional disks are still billable and can still be unattached review candidates.
2. Regional unattached disks are more operationally ambiguous than zonal disks because they are explicitly documented HA / failover infrastructure.
3. Confidence for unattached regional disks should therefore be more conservative than for equivalent zonal disks.

### 3.6 Pricing varies by disk type, region, currency, and for some disks separate provisioned performance

Google documents that disk pricing varies and points users to the Pricing Calculator, Pricing Table, Cloud Billing reports, SKUs, and Catalog API for exact pricing. The pricing page also distinguishes disk/image pricing from VM pricing and notes that Cloud Platform SKUs apply for non-USD billing.

Source:

- *Disk and image pricing*

URL:

- https://cloud.google.com/compute/disks-image-pricing

Rule consequence:

1. The rule must **not** hardcode a single capacity-only disk price table as authoritative.
2. The rule must **not** claim exact monthly savings from disk size and type alone.
3. `estimated_monthly_cost_usd` should remain `None` unless a future implementation uses a documented, region-aware pricing source.

---

## 4. Detection Goal

Emit only when the disk passes every rule in section **8**. Section **8** is the single source of truth for decisioning; sections **7** and **9** define normalization and evaluation contracts.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the disk is safe
- that the disk is not reserved for imminent VM recreation
- that the disk is not part of a failover, restore, or migration workflow
- that the disk is not intentionally retained as HA capacity
- that a specific monthly dollar saving exists

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| Compute Engine persistent disk aggregated inventory | enumerate zonal and regional disks and collect current attachment, status, type, timestamps, labels, and scope |

No VM guest metrics, Cloud Monitoring metrics, or audit-log evidence are required for this rule.

### 6.2 Authentication / permissions

Minimum permission:

- `compute.disks.list`

Typical predefined role:

- `roles/compute.viewer`

### 6.3 Thresholds

This rule has **no user-configurable parameter**.

It uses documented current-attachment state plus conservative confidence shaping:

1. **zonal disks**
   1. `LOW` when last detach is known and `< 24 hours`
   2. `MEDIUM` when last detach is known and `>= 24 hours` but `< 7 days`
   3. `HIGH` otherwise
2. **regional disks**
   1. baseline confidence is `MEDIUM`
   2. if last detach is known and `< 24 hours`, downgrade to `LOW`
   3. otherwise remain `MEDIUM`

Reason:

- GCP documents the timestamps and HA semantics, but it does not define an “orphaned disk” platform state.
- This rule therefore emits from current unattached state, while using recent-detach timing and regional-HA context to reduce overconfidence.

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `scope_key` | Resolve from aggregated inventory scope key. Supported forms are zonal (`zones/ZONE`) and regional (`regions/REGION`). Any other scope kind is unsupported and must skip. |
| `location` | For zonal disks, use the zone from the aggregated scope key. For regional disks, use the region from the aggregated scope key. If zonal location parsing fails, skip rather than guess. |
| `region_filter` | Compare exactly against the normalized **region** (`us-central1`, not `us-central1-a`) for both zonal and regional disks. If normalized region derivation fails, skip. |
| `status` | Resolve from documented disk `status` and compare case-sensitively to exact `"READY"`. |
| `users` | Treat as the canonical current-attachment surface. Only an explicitly empty list means currently unattached. Any non-empty entry or entries mean attached. Non-list, missing, or unresolved values are not equivalent to empty. |
| `disk_type` | Preserve the short terminal type name extracted from the documented disk type URL when possible; otherwise preserve unknown. |
| `size_gb` | Parse from documented `sizeGb` / SDK equivalent as a non-negative integer when possible; otherwise `0` for context only. |
| `creation_timestamp` | Preserve the raw documented RFC3339 timestamp for reviewer context only; it must not determine emission. |
| `last_detach_timestamp` | Parse as a UTC instant from documented `lastDetachTimestamp` when present. If unparsable, treat as unknown rather than failing the disk. |
| `last_attach_timestamp` | Preserve the raw documented value for reviewer context only. |
| `is_regional` | `True` when the aggregated scope is regional, otherwise `False`. |
| `labels` | `disk.labels or {}` - never `None` in output. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | disk record is malformed or `name` absent / empty | Skip |
| 8.2 | aggregated scope key is unsupported or cannot be resolved to zonal vs regional context | Skip |
| 8.3 | region filter is set and normalized disk region does not match | Skip |
| 8.4 | disk `status` is absent, unknown, or not exactly `"READY"` | Skip |
| 8.5 | disk `users` is unresolved or not reliably interpretable as current attachment state | Skip |
| 8.6 | disk `users` is non-empty | Skip |
| 8.7 | all required signals resolve and the disk is `READY` with empty `users` | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Inventory and scope contract

Required behavior:

1. Enumerate disks from documented Compute Engine disk inventory surfaces.
2. Treat aggregated scope keys of the form `zones/ZONE` as zonal.
3. Treat aggregated scope keys of the form `regions/REGION` as regional.
4. Skip any unexpected scope kind such as malformed or unsupported keys.
5. For zonal disks, derive comparison region from the zone name by removing the final `-<zone-letter>` segment.
6. For regional disks, comparison region is the regional scope name directly.
7. If zonal scope parsing or zone-to-region derivation fails, skip rather than guessing a region.
8. If aggregated inventory returns partial-success, warnings, or otherwise incomplete scope coverage, implementations must not silently treat the result as complete project coverage.
9. Under partial aggregated coverage, item-level findings from successfully enumerated scopes may still be emitted, but zero findings must not be interpreted as a clean project.

### 9.2 Status contract

Required behavior:

1. Only `status == "READY"` is eligible.
2. `CREATING`, `RESTORING`, `FAILED`, and `DELETING` must skip.
3. Unknown or unresolved status must skip.

### 9.3 Attachment contract

Required behavior:

1. Use `users[]` as the sole trusted current-attachment surface for this rule.
2. A disk is currently unattached only when `users[]` resolves to an explicitly empty list.
3. A disk is attached when `users[]` contains one or more entries, including multiple entries.
4. If the attachment surface is malformed, missing in an unusable way, or cannot be resolved reliably, skip rather than assume unattached.
5. `lastAttachTimestamp` and `lastDetachTimestamp` are contextual evidence only; they must not override a non-empty `users[]`.

### 9.4 Confidence contract

Required behavior:

1. Baseline confidence for a currently unattached zonal disk is `HIGH`.
2. Baseline confidence for a currently unattached regional disk is `MEDIUM`.
3. If `lastDetachTimestamp` is present and parseable:
   1. `< 24 hours` since last detach -> `LOW`
   2. `>= 24 hours` and `< 7 days` since last detach -> `MEDIUM` for zonal disks
   3. `>= 7 days` since last detach -> no downgrade for zonal disks
   4. regional disks remain capped at `MEDIUM` unless downgraded to `LOW` for recent detach
4. If `lastDetachTimestamp` is absent or unusable, keep the baseline confidence for the disk scope.

Rationale:

Google documents current attachment (`users[]`) and detach timestamps, but it does not provide a dedicated “abandoned disk” state. This rule therefore treats current unattached state as sufficient to emit while using recency and regional-HA semantics only to modulate confidence.

### 9.5 Cost model contract

Required behavior:

1. `estimated_monthly_cost_usd = None`
2. Do **not** use flat region-reference price tables such as fixed `$ / GB / month` maps.
3. Do **not** treat hyperdisk or provisioned-performance disks as capacity-only costs.
4. State only that unattached persistent disks continue to incur storage charges.

Rationale:

Google’s pricing documentation explicitly varies by disk type, region, currency, and pricing source, and points users to SKU-aware sources for exact prices. A static in-code table would overstate precision.

### 9.6 Failure behavior contract

Required behavior:

1. Permission failures for disk inventory should surface as a permission error, not silent empty findings.
2. If the Compute Engine API for disks is unavailable / disabled for the project, returning no findings is acceptable.
3. Malformed disk records should be skipped item-by-item rather than failing the whole rule.
4. Partial aggregated inventory coverage must be surfaced as incomplete coverage or degraded scan state; it must not silently collapse into a clean no-findings outcome.

---

## 10. Finding Shape

### 10.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"gcp"` |
| `rule_id` | `"gcp.compute.disk.unattached"` |
| `resource_type` | `"gcp.compute.disk"` |
| `resource_id` | canonical project/location disk path |
| `region` | zonal location for zonal disks, regional location for regional disks |
| `confidence` | derived from section `9.4` |
| `estimated_monthly_cost_usd` | `None` |

### 10.2 Required evidence

`signals_used` must clearly disclose:

1. disk `status` is `READY`
2. `users[]` is empty
3. whether the disk is zonal or regional
4. if present, how recently the disk was detached

`signals_not_checked` should include remaining blind spots such as:

1. imminent VM recreation intent
2. restore / migration / failover workflow intent
3. exact disk pricing from region-aware billing data

### 10.3 Required details

Details should include at least:

- `disk_name`
- `disk_type`
- `size_gb`
- `location`
- `is_regional`
- `labels`
- `creation_timestamp`
- `last_detach_timestamp` when present
- `last_attach_timestamp` when present

---

## 11. Failure Behavior

- Permission denied on disk inventory -> raise permission error
- Compute Engine API disabled / not found for the project -> return no findings
- Malformed or unsupported scoped disk records -> skip those items
