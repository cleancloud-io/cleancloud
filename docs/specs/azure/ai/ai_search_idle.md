# Azure Rule Spec — `azure.ai_search.idle`

## 1. Rule Identity

- **Rule ID:** `azure.ai_search.idle`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.Search/searchServices`
- **Finding resource_type:** `azure.ai.search_service`

---

## 2. Intent

Detect **dedicated Azure AI Search services that appear structurally empty and operationally inactive** over a long observation window, making them conservative review candidates for deletion or rightsizing.

This rule is deliberately **precision-first**. It is **not** a generic "zero queries" rule. It is a review-candidate rule only, not proof that a service is safe to delete, not proof that no future rollout depends on it, and not proof of a specific monthly saving.

---

## 3. Azure Documentation Grounding

### 3.1 Azure AI Search has ongoing service cost while the service exists

Microsoft documents that Azure AI Search has:

1. a fixed base service cost driven by partitions and replicas
2. optional premium-feature usage charges
3. no way to temporarily stop billing short of deleting the service

Sources:

- *Choose a pricing tier for Azure AI Search*
- *Plan and manage costs for Azure AI Search*

URLs:

- https://learn.microsoft.com/en-us/azure/search/search-sku-tier
- https://learn.microsoft.com/en-us/azure/search/search-sku-manage-costs

Rule consequence:

1. An unused dedicated service is billing-relevant even if premium features are unused.
2. Flat monthly cost tables must not be hardcoded because pricing varies by region, tier, capacity, and optional premium features.
3. `estimated_monthly_cost_usd` should remain `None`.

### 3.2 Azure AI Search has both querying and indexing workloads

Microsoft documents that Azure AI Search supports:

- querying workloads
- indexing workloads
- push ingestion directly into an index
- pull ingestion through indexers
- AI enrichment during indexing
- agentic retrieval / knowledge-source workflows

Sources:

- *What is Azure AI Search?*
- *Import data into a search index*
- *Indexers in Azure AI Search*

URLs:

- https://learn.microsoft.com/en-us/azure/search/search-what-is-azure-search
- https://learn.microsoft.com/en-us/azure/search/search-how-to-load-search-index
- https://learn.microsoft.com/en-us/azure/search/search-indexer-overview

Rule consequence:

1. Zero query traffic alone is **not** sufficient evidence of overall service idleness.
2. Zero indexer activity alone is **not** sufficient evidence of overall service idleness.
3. A conservative rule should require both **zero documented activity metrics** and **zero configured search-service objects** before emitting.

### 3.3 Azure Monitor metrics for Azure AI Search

Microsoft documents the following platform metrics for `Microsoft.Search/searchServices`:

- `SearchQueriesPerSecond`
- `DocumentsProcessedCount`
- `SkillExecutionCount`
- `SearchLatency`
- `ThrottledSearchQueriesPercentage`

Source: *Supported metrics for Microsoft.Search/searchServices*
URL: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-search-searchservices-metrics

Rule consequence:

1. `SearchQueriesPerSecond` is the documented query-activity signal.
2. `DocumentsProcessedCount` and `SkillExecutionCount` are documented indexing / enrichment signals.
3. If any required activity metric cannot be resolved reliably, the service must be skipped.

### 3.4 Search service control-plane state

Microsoft documents search service fields including:

- `properties.provisioningState`
- `properties.status`
- `properties.replicaCount`
- `properties.partitionCount`
- `properties.hostingMode`
- `systemData.createdAt`
- `sku.name`

Sources:

- *Services - Get (Search Management REST API)*
- *azure.mgmt.search.models.SearchService*

URLs:

- https://learn.microsoft.com/en-us/rest/api/searchmanagement/services/get?view=rest-searchmanagement-2025-05-01
- https://learn.microsoft.com/en-us/python/api/azure-mgmt-search/azure.mgmt.search.models.searchservice?view=azure-python

Microsoft further documents that degraded, disabled, and error states can still be chargeable for dedicated services.

Rule consequence:

1. The rule should evaluate only **stable** services: exact `provisioningState == "succeeded"` and exact `status == "running"`.
2. The rule should skip transitional or impaired service states rather than infer idleness from them.

### 3.5 Azure AI Search object-management surfaces

Microsoft documents RBAC-backed data-plane object-management access for Azure AI Search and explicitly states that Search Service Contributor can list and manage search objects, including:

- indexes
- indexers
- data sources
- skillsets
- aliases
- synonym maps
- knowledge bases / knowledge sources

Source: *Use role-based access control in Azure AI Search*
URL: https://learn.microsoft.com/en-us/azure/search/search-security-rbac

Microsoft also documents list APIs for several object types, including:

- `GET {endpoint}/indexes`
- `GET {endpoint}/indexers`
- `GET {endpoint}/datasources`
- `GET {endpoint}/skillsets`
- `GET {endpoint}/synonymmaps`
- preview list APIs for `aliases`, `knowledgesources`, and `agents`

Sources:

- *Indexes - List*
- *Indexers - List*
- *Data Sources - List*
- *Skillsets - List*
- *Synonym Maps - List*
- *Aliases - List*
- *Knowledge Sources - List*
- *Knowledge Agents - List*

URLs:

- https://learn.microsoft.com/en-us/rest/api/searchservice/indexes/list?view=rest-searchservice-2025-09-01
- https://learn.microsoft.com/en-us/rest/api/searchservice/indexers/list?view=rest-searchservice-2025-09-01
- https://learn.microsoft.com/en-us/rest/api/searchservice/data-sources/list?view=rest-searchservice-2025-09-01
- https://learn.microsoft.com/en-us/rest/api/searchservice/skillsets/list?view=rest-searchservice-2025-09-01
- https://learn.microsoft.com/en-us/rest/api/searchservice/synonym-maps/list?view=rest-searchservice-2025-09-01
- https://learn.microsoft.com/en-us/rest/api/searchservice/aliases/list?view=rest-searchservice-2025-09-01
- https://learn.microsoft.com/en-us/rest/api/searchservice/knowledge-sources/list?view=rest-searchservice-2025-09-01
- https://learn.microsoft.com/en-us/rest/api/searchservice/knowledge-agents/list?view=rest-searchservice-2025-09-01

Rule consequence:

1. A service with configured search objects is not safely classifiable as idle.
2. A conservative rule should emit only when **all required object surfaces are empty**.
3. If object enumeration fails or is unavailable for a required surface, the service must be skipped.

### 3.6 Sensitive object definitions must not leak into findings

Microsoft's documented object-management responses can include sensitive configuration material such as:

- datasource credentials / connection strings
- encryption key references
- model connection details

Rule consequence:

Object enumeration may be used only to establish **presence / count / safe names**, never to persist, emit, or log sensitive configuration fields.

---

## 4. Detection Goal

Emit a finding only when **all** of the following are true:

1. `service.id` is present and non-empty
2. `service.name` is present and non-empty
3. the optional region filter matches the normalized location
4. `provisioning_state` resolves to exactly `"succeeded"`
5. `status` resolves to exactly `"running"`
6. `sku.name` resolves to a supported dedicated billable tier
7. `systemData.createdAt` is known and the service age is at least `90 days`
8. `replica_count` and `partition_count` are known positive integers
9. all required object-list surfaces resolve reliably
10. all required object-list surfaces are empty
11. all required activity metrics resolve reliably (see section 9.5) for the same `90-day` window
12. all required activity metrics are zero for that window

If any required signal cannot be established reliably, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the service is safe
- that no deployment, migration, or DR plan depends on the service
- that unused premium features are absent in every conceivable configuration surface
- that a specific monthly saving exists
- that future data-plane or preview feature surfaces will never expand

---

## 6. Canonical Inputs

### 6.1 Required surfaces

| Surface | Purpose |
|---|---|
| Search Management `services.list_by_subscription()` / `services.get()` | stable service identity, region, SKU, capacity, status, provisioning, creation time |
| Azure Monitor metrics on the service ARM id | documented query / indexing / skill activity |
| Azure AI Search data-plane object list APIs | determine whether the service is structurally empty |

### 6.2 Authentication / permissions

Minimum permissions:

- `Microsoft.Search/searchServices/read`
- `Microsoft.Insights/metrics/read`

And **data-plane object-management read capability** using Azure AI Search RBAC / keyless auth for object enumeration, typically via **Search Service Contributor** or an equivalent custom role.

The implementation must **not** retrieve admin keys merely to evaluate this rule.

### 6.3 Fixed idle window

- Configurable parameter: none
- Fixed evaluation window: `90 days`

Reason:

- Azure AI Search services can exist ahead of go-live
- indexing and retrieval workloads can be periodic
- a longer window materially reduces false findings for expensive dedicated services

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase ARM location string; compare by exact lowercase string equality only. Do not remove spaces, hyphens, or digits. |
| `provisioning_state` | Resolve from documented SDK/raw surfaces and compare case-sensitively to exact `"succeeded"`. |
| `status` | Resolve from documented SDK/raw surfaces and compare case-sensitively to exact `"running"`. |
| `sku_name` | Lowercase only. Supported dedicated tiers for this rule are exact: `basic`, `standard`, `standard2`, `standard3`, `storage_optimized_l1`, `storage_optimized_l2`. |
| `created_at` | Parse as UTC instant from `systemData.createdAt` or equivalent SDK projection. |
| `replica_count`, `partition_count` | Positive integers only. `<= 0`, invalid, or unresolvable values are not eligible. |
| `object_list_empty` | `True` only when the list call succeeds, all pages are exhausted, and the returned `value` collection is confirmed empty across the full paginated result set. |
| `tags` | `service.tags or {}` — never `None` in output. |

---

## 8. Unified Decision Rule

| # | Condition | Action |
|---|---|---|
| 8.1 | `id` absent, `None`, or empty | Skip |
| 8.2 | `name` absent, `None`, or empty | Skip |
| 8.3 | Region filter set and normalized location does not match | Skip |
| 8.4 | `provisioning_state` does not resolve to `"succeeded"` | Skip |
| 8.5 | `status` does not resolve to `"running"` | Skip |
| 8.6 | `sku_name` is not one of the supported dedicated billable tiers | Skip |
| 8.7 | `created_at` is absent, invalid, in the future, or less than `90 days` old | Skip |
| 8.8 | `replica_count <= 0` or `partition_count <= 0`, or either value is unresolvable | Skip |
| 8.9 | Any required object-list surface fails, is unavailable, or is unresolvable | Skip |
| 8.10 | Any required object-list surface is non-empty | Skip |
| 8.11 | Any required metric cannot be resolved reliably | Skip |
| 8.12 | Any required metric is non-zero over the `90-day` window | Skip |
| 8.13 | All required signals resolve, required object surfaces are empty, and required metrics are zero over `90 days` | **EMIT** |

---

## 9. Canonical Evaluation Contracts

### 9.1 Stable-state contract

Resolve `provisioning_state` in this order:

1. SDK projection such as `service.provisioning_state`
2. nested/raw management payload such as `properties.provisioningState`
3. otherwise unknown

Resolve `status` in this order:

1. SDK projection such as `service.status`
2. nested/raw management payload such as `properties.status`
3. otherwise unknown

Required behavior:

1. Only exact `"succeeded"` is eligible for `provisioning_state`.
2. Only exact `"running"` is eligible for `status`.
3. Unknown, conflicting, or any other values must skip.

### 9.2 Supported billing-tier contract

This rule is limited to documented dedicated billable tiers:

- `basic`
- `standard`
- `standard2`
- `standard3`
- `storage_optimized_l1`
- `storage_optimized_l2`

Required behavior:

1. `free` must skip.
2. `serverless`, unknown, preview, or future SKU labels must skip.
3. The rule must not hardcode monthly price tables.

### 9.3 Structural-emptiness contract

Required zero-count object surfaces:

1. indexes
2. indexers
3. data sources
4. skillsets
5. synonym maps

Optional reinforcing zero-count object surfaces:

1. aliases
2. knowledge sources
3. agents

Required behavior:

1. Each required surface must be enumerated explicitly.
2. A required surface is empty only when enumeration succeeds and pagination is fully exhausted across the complete result set.
3. Any non-empty required surface must skip.
4. Any failed, unauthorized, unsupported, or unresolvable required-surface enumeration must skip.
5. Optional reinforcing surfaces may be enumerated when supported, but must not be required for eligibility.
6. Optional reinforcing surfaces are ignored unless enumeration succeeds and pagination is fully exhausted across the complete result set.
7. If a fully enumerated optional reinforcing surface is non-empty, the service must skip.

Rationale:

This rule intentionally treats **configured search objects** as sufficient evidence that the service is not safely classifiable as idle.

### 9.4 Sensitive-response handling contract

When enumerating data-plane objects:

1. implementations may use only safe presence/count information
2. they must not persist, emit, or log connection strings, keys, credentials, model secrets, or equivalent sensitive payload fields
3. finding evidence may include object counts and safe object names only when they are non-sensitive

### 9.5 Activity-metric contract

Required metrics:

1. `SearchQueriesPerSecond` with `Average`
2. `DocumentsProcessedCount` with `Total`
3. `SkillExecutionCount` with `Total`

Definitions:

- **usable datapoint**: a datapoint with a parseable UTC timestamp inside the requested window and a numeric aggregation value
- **source bucket**: the metric bucket returned by Azure Monitor for the requested query interval before any spec-level normalization
- **UTC day bucket**: the UTC day boundary derived from a datapoint timestamp by normalizing it to `00:00:00Z` for that day
- **expected buckets**: count of UTC-aligned daily buckets overlapping `[window_start, window_end)`
- **observed buckets**: count of unique UTC day buckets with at least one usable datapoint after consolidating duplicate timestamps across all returned series and dimension slices
- **coverage ratio**: `observed_buckets / expected_buckets`
- **acceptable coverage**: `coverage_ratio >= 0.95`
- **resolve reliably**: the metric query returns valid data for the requested window, meets the coverage threshold, and does not trigger any `UNKNOWN` condition
- **unusable response shape**: a metric response with missing `value`, malformed time series collections, unparsable timestamps, or non-numeric aggregation values

Required behavior:

1. Query all three required metrics for the same `90-day` window.
2. Evaluate activity on the returned source buckets before any UTC-day normalization. Implementations must not rely on coarse day-level pre-aggregated buckets as the sole activity test because short-lived activity can be diluted away.
3. Normalize datapoint timestamps to UTC day buckets only for coverage calculation and day-level consolidation.
4. For `SearchQueriesPerSecond`, use the returned `Average` value for each source bucket. Any positive source-bucket value makes its containing UTC day bucket positive.
5. Consolidate duplicate series for the same UTC day bucket before final evaluation. For `SearchQueriesPerSecond`, any positive contributing value keeps that UTC day bucket positive. For `DocumentsProcessedCount` and `SkillExecutionCount`, aggregate values across all returned dimension slices for the same UTC day bucket.
6. Treat any missing metric, failed query, unusable response shape, empty series, no datapoints, no valid series, or coverage below threshold as `UNKNOWN`.
7. Treat any metric with any positive consolidated bucket value as `ACTIVE`.
8. Treat a metric as `ZERO` only when it resolves reliably and all usable bucket values are exactly zero.
9. Emit only when **all three** required metrics evaluate to `ZERO`.

Rationale:

1. Query silence alone is not enough because indexing workloads can be valid.
2. Indexer / skill silence alone is not enough because search workloads can be valid.
3. This rule still does not claim to observe every possible undocumented activity surface, which is why it also requires structural emptiness.

---

## 10. Cost Model

`estimated_monthly_cost_usd = None`

Mandatory rules:

1. Do **not** use flat hardcoded price tables
2. Do **not** infer cost from SU count alone
3. Do **not** infer cost from metric silence alone
4. State only that dedicated Azure AI Search services incur ongoing service cost while they exist

---

## 11. Finding Shape

### 11.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.ai_search.idle"` |
| `resource_type` | `"azure.ai.search_service"` |
| `resource_id` | original ARM id from `service.id` |
| `region` | normalized location |
| `confidence` | `HIGH` |
| `risk` | `MEDIUM` |
| `estimated_monthly_cost_usd` | `None` |

### 11.2 Required evidence

`signals_used` must clearly disclose:

1. provisioning state is `"succeeded"`
2. service status is `"running"`
3. supported dedicated SKU was confirmed
4. service age is at least `90 days`
5. all required object surfaces were confirmed empty with full pagination exhaustion
6. all required activity metrics resolved to **no observed query/indexing/skill activity** with sufficient coverage

`signals_not_checked` should include remaining blind spots such as:

1. future go-live or migration intent
2. business-owner intent not visible in Azure control plane
3. premium-feature billing details not inferable from baseline management and metric surfaces

### 11.3 Required details

Details should include at least:

- `service_name`
- `resource_group`
- `subscription_id`
- `sku_name`
- `replica_count`
- `partition_count`
- `hosting_mode`
- `status`
- `provisioning_state`
- `created_at`
- `idle_window_days`
- `object_counts`
- `metrics_used`
- `tags`

`object_counts` contract:

1. include counts for all required surfaces only after full pagination exhaustion
2. include counts for optional reinforcing surfaces only when they were successfully enumerated with full pagination exhaustion
3. omit unevaluated or partially evaluated surfaces rather than defaulting them to `0`

---

## 12. Failure Behavior

- If subscription-wide service inventory fails, let the exception propagate
- If per-service `get(...)`, data-plane object enumeration, or metric retrieval fails, skip that service
- If a service record is malformed or missing required fields, skip that service
- Do not emit on partial or unresolved object-surface state or metric state
