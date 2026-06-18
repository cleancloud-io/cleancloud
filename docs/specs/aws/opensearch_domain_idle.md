# aws.opensearch.domain.idle — Canonical Rule Specification

## 1. Intent

Detect provisioned OpenSearch Service domains that are active but have had zero search and
indexing activity over the configured idle window, so they can be reviewed as candidates for
deletion or downsizing.

This is a **CleanCloud-derived idle heuristic** based on OpenSearch domain metadata and CloudWatch
activity metrics. It is a **read-only review-candidate rule** — not a delete-safe rule.

---

## 2. AWS API Grounding

Based on official OpenSearch Service API and CloudWatch documentation.

### Key facts

1. `ListDomainNames` is the canonical inventory API. It returns all domains in the region in a
   single response (no pagination). Each entry includes `DomainName` and `EngineType`
   (`"OpenSearch"` or `"Elasticsearch"`). An optional `EngineType` filter parameter is available.
2. `DescribeDomain` returns a single `DomainStatus` object for a given `DomainName`.
   `DescribeDomains` (batch) accepts up to 5 domain names per request.
3. `DomainStatus` includes `DomainId`, `DomainName`, `ARN`, `EngineVersion`, `ClusterConfig`,
   `EBSOptions`, `Created` (boolean), `Deleted` (boolean), `Processing` (boolean),
   `UpgradeProcessing` (boolean), and `DomainProcessingStatus`.
4. There is **no creation timestamp** in `DomainStatus`. `Created` is a boolean lifecycle flag
   only (`true` = creation complete). There is no `CreatedAt` or equivalent field.
5. `DomainProcessingStatus` values: `Creating`, `Active`, `Modifying`,
   `UpgradingEngineVersion`, `UpdatingServiceSoftware`, `Isolated`, `Deleting`.
6. `ClusterConfig` includes `InstanceType`, `InstanceCount`, `DedicatedMasterEnabled`,
   `DedicatedMasterType`, `DedicatedMasterCount`, `WarmEnabled`, `WarmType`, `WarmCount`,
   `ZoneAwarenessEnabled`, `MultiAZWithStandbyEnabled`.
7. `EBSOptions` includes `EBSEnabled`, `VolumeType`, `VolumeSize`, `Iops`, `Throughput`.
8. OpenSearch Serverless is a **separate service** using the `opensearchserverless` boto3 client.
   `ListDomainNames` / `DescribeDomain` do **not** return serverless collections. Serverless is
   out of scope for this rule.
9. CloudWatch namespace `AWS/ES` publishes metrics **automatically** at 1-minute intervals.
   Key idle-detection metrics:
   - `OpenSearchRequests` — total HTTP requests to the domain. Dimensions: `ClientId` +
     `DomainName`. This is the cleanest "any traffic?" signal.
   - `SearchRate` — search requests per minute per shard (fan-out counted). Dimensions:
     `ClientId` + `DomainName` (cluster aggregate) or with `NodeId` (per-node).
   - `IndexingRate` — indexing operations per minute. Same dimensions as `SearchRate`.
   - `2xx`, `3xx`, `4xx`, `5xx` — HTTP response code counts. Dimensions: `ClientId` +
     `DomainName`.
   - `SearchableDocuments` — total searchable documents across data nodes.
10. The `ClientId` dimension is the AWS account ID. It is required alongside `DomainName` for
    CloudWatch queries. The account ID is extracted from the domain ARN
    (`arn:aws:es:<region>:<account-id>:domain/<name>`), avoiding an extra
    `sts:GetCallerIdentity` dependency.
11. The OpenSearch metrics page states metrics are "archived after two weeks," but CloudWatch's
    own retention rules are more nuanced: 1-minute data is retained for 15 days, 5-minute data
    for 63 days, and 1-hour data for 455 days. Metrics with no new datapoints for 2 weeks may
    disappear from `ListMetrics` / console but remain retrievable via `GetMetricStatistics`.
    Since this rule queries at 1-hour resolution, CloudWatch retention supports up to 455 days
    in theory. However, the coverage requirement (Section 6.1) naturally constrains the
    practical window: domains must have continuous hourly datapoints for 95%+ of the window.
12. Fixed monthly USD cost estimates are not canonical from the fetched AWS docs.

### Implications

- Inventory is built via `ListDomainNames` (single call, no pagination) followed by
  `DescribeDomain` for each domain (or `DescribeDomains` in batches of 5).
- Idleness is determined by CloudWatch `OpenSearchRequests` (Sum = 0) over the idle window.
  `SearchRate` and `IndexingRate` (Sum = 0) provide secondary confirmation.
- Only domains with `DomainProcessingStatus == "Active"` and `Created == true` and
  `Deleted != true` are eligible.
- Since no creation timestamp exists, cluster age cannot be validated from the API. The rule
  relies on the evaluation window having sufficient CloudWatch data.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **Domain** — an item returned by `ListDomainNames` with full details from `DescribeDomain`.
- **Eligible status** — `DomainProcessingStatus == "Active"` AND `Created == true` AND
  `Deleted != true`.
- `idle_days_threshold` — operator-configurable integer >= 1, default 14. Since this rule
  queries CloudWatch at 1-hour resolution (retained for 455 days), higher thresholds are
  technically supportable. However, the coverage requirement (Section 6.1) naturally enforces
  data availability: if insufficient hourly datapoints exist for the requested window, the
  domain is skipped as inconclusive.
- `idle_window_seconds` — `idle_days_threshold × 86400`.
- **evaluation_window_start_utc** — `now_utc - idle_window_seconds`.
- **evaluation_window_end_utc** — `now_utc`.
- **expected_datapoints** — `idle_days_threshold × 24` (one per hour over the window).
- **coverage_ratio** — `actual_datapoints / expected_datapoints`.
- **idle** — `OpenSearchRequests` Sum = 0 across all hourly periods, with coverage_ratio >= 0.95
  (missing data beyond 5% = inconclusive, not idle).

### Explicit scope boundary

This rule applies only to provisioned OpenSearch Service domains that are active.

Out of scope:

- Domains in `Creating`, `Modifying`, `UpgradingEngineVersion`, `UpdatingServiceSoftware`,
  `Isolated`, or `Deleting` status
- Domains where `Created == false` (still being created)
- Domains where `Deleted == true` (being deleted)
- OpenSearch Serverless collections (separate service, `opensearchserverless` client)
- exact price estimation, accrued USD estimation, or savings estimation

---

## 4. Canonical Rule Statement

An OpenSearch domain is flagged as idle only when **all** of the following are true:

- stable domain identity exists (`DomainName`, `ARN`)
- `DomainProcessingStatus == "Active"` AND `Created == true` AND `Deleted != true`
- CloudWatch `OpenSearchRequests` Sum = 0 across all hourly periods in the evaluation window,
  with coverage_ratio >= 0.95 (insufficient coverage = inconclusive, skip)

No additional predicate may be required for baseline eligibility, including instance type,
instance count, or static cost heuristics.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

### 5.1 Describe-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `domain_name` | `DomainName` | skip item |
| `domain_id` | `DomainId` | null |
| `arn` | `ARN` | skip item |
| `engine_version` | `EngineVersion` | null |
| `domain_processing_status` | `DomainProcessingStatus` | skip item |
| `created` | `Created` | skip item |
| `deleted` | `Deleted` | false |
| `processing` | `Processing` | false |
| `instance_type` | `ClusterConfig.InstanceType` | null |
| `instance_count` | `ClusterConfig.InstanceCount` | null |
| `dedicated_master_enabled` | `ClusterConfig.DedicatedMasterEnabled` | false |
| `dedicated_master_type` | `ClusterConfig.DedicatedMasterType` | null |
| `dedicated_master_count` | `ClusterConfig.DedicatedMasterCount` | null |
| `warm_enabled` | `ClusterConfig.WarmEnabled` | false |
| `warm_type` | `ClusterConfig.WarmType` | null |
| `warm_count` | `ClusterConfig.WarmCount` | null |
| `ebs_enabled` | `EBSOptions.EBSEnabled` | false |
| `ebs_volume_type` | `EBSOptions.VolumeType` | null |
| `ebs_volume_size_gb` | `EBSOptions.VolumeSize` | null |
| `endpoint` | `Endpoint` (public endpoint URL) | null |
| `endpoints` | `Endpoints` (map, VPC domains use key `"vpc"`) | null |

### 5.2 CloudWatch-Derived Fields

| Canonical field | Derivation |
|---|---|
| `opensearch_requests_sum` | Total of all hourly `OpenSearchRequests` Sum datapoint values (each datapoint is one hour's Sum; if all are 0, the total is 0) |
| `expected_datapoints` | `idle_days_threshold × 24` |
| `actual_datapoints` | number of hourly datapoints returned by CloudWatch |
| `coverage_ratio` | `actual_datapoints / expected_datapoints` |
| `search_rate_sum` | Sum of `SearchRate` over evaluation window (best-effort, null on failure) |
| `indexing_rate_sum` | Sum of `IndexingRate` over evaluation window (best-effort, null on failure) |
| `is_idle` | `true` when `opensearch_requests_sum == 0` AND `coverage_ratio >= 0.95` |

### 5.3 Derived Fields

| Canonical field | Derivation |
|---|---|
| `resource_id` | `arn` |

Normalization requirements:

- String-valued fields: normalize only from non-empty strings.
- Boolean fields (`Created`, `Deleted`, `Processing`): normalize from boolean values only.
- `ClusterConfig` and `EBSOptions` must degrade safely to default/null fields when absent or
  malformed; optional context must not crash evaluation.

---

## 6. Idle Signal Contract

This rule evaluates **HTTP request activity**, not data freshness or business value.

### 6.1 Primary idle signal

- Query CloudWatch `OpenSearchRequests` with dimensions `ClientId` (account ID) + `DomainName`
  over the evaluation window using `Sum` statistic with `Period = 3600` (1 hour).
- Because OpenSearch domains have **no creation timestamp**, a single full-window aggregate
  cannot prove the domain existed for the entire window. A recently created domain could return
  a zero-sum datapoint and be falsely flagged as idle. Hourly periods with a coverage
  requirement solve this.
- **Coverage requirement:** calculate `expected_datapoints = idle_days_threshold × 24`. Require
  that the number of returned datapoints is `>= expected_datapoints × 0.95` (95% coverage).
  If coverage is below this threshold, **SKIP ITEM** — insufficient evidence to claim the
  domain was idle for the full window.
- **Idle check:** if coverage is sufficient, check that every returned hourly datapoint has a
  Sum value of 0. If any single hourly datapoint has Sum > 0, the domain is not idle. (The
  implementation checks each datapoint individually — it does not re-sum the per-hour values.)
- **Missing datapoints within the window** are treated as gaps in evidence, not as zero-traffic
  hours. They reduce the coverage ratio. If too many are missing (coverage < 95%), the domain
  is skipped as inconclusive. A small number of missing datapoints (up to 5%) is tolerated as
  normal CloudWatch jitter.
- If CloudWatch returns no datapoints at all, **SKIP ITEM** — insufficient evidence.

### 6.2 Secondary confirmation signals (best-effort only)

- `SearchRate` and `IndexingRate` are **best-effort only**. These metrics may not exist
  consistently across all domains (e.g. domains with no shards, or domains that have never
  received traffic may not publish these metrics).
- When available and retrievable: a single full-window aggregate Sum = 0 for each confirms no
  search/indexing activity and upgrades confidence to HIGH.
- These must **never** change the primary idle decision or cause a skip.
- If retrieval fails, returns no datapoints, or the metric does not exist for the domain: set
  the corresponding field to `null` and **degrade confidence to MEDIUM**.

### 6.3 Explicit blind spots

This rule does **not** prove:

- that the domain has no business value or planned future use
- that deleting the domain is safe
- that the domain is not used for compliance log retention
- exact price impact or savings impact
- that the domain's data has been backed up

---

## 7. Pricing / Cost Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode instance-price tables, accrued USD estimates, or regional billing assumptions.
- `instance_type`, `instance_count`, and EBS configuration are emitted as context for the
  reviewer to assess cost impact.

---

## 8. Deterministic Evaluation Order

1. Call `ListDomainNames` to get all domain names in the region.
2. For each domain name (or in batches of 5 via `DescribeDomains`), call `DescribeDomain`.
3. Permission failure on list or describe --> **FAIL RULE**.
4. Normalize each domain.
5. For each normalized domain:
   - identity absent (`domain_name` or `arn`) --> **SKIP ITEM**
   - `domain_processing_status` absent --> **SKIP ITEM**
   - `domain_processing_status != "Active"` --> **SKIP ITEM**
   - `created != true` --> **SKIP ITEM**
   - `deleted == true` --> **SKIP ITEM**
6. Query CloudWatch `OpenSearchRequests` for the domain over the evaluation window using
   `Period = 3600` (hourly).
7. CloudWatch permission or request failure --> **FAIL RULE**.
8. CloudWatch returned no datapoints --> **SKIP ITEM** (insufficient evidence).
9. Coverage check: if `actual_datapoints / expected_datapoints < 0.95` --> **SKIP ITEM**
   (insufficient evidence — domain may not have existed for the full window).
10. `OpenSearchRequests` Sum > 0 in any period --> **SKIP ITEM** (not idle).
11. Query secondary signals (`SearchRate`, `IndexingRate`) best-effort. On failure or missing
    data, set to `null` and degrade confidence to MEDIUM.
12. **EMIT**.

No raw AWS field access after normalization.

---

## 9. Exclusion Rules

1. identity absent (`domain_name` or `arn`) --> malformed inventory item
2. `domain_processing_status` absent --> missing primary state
3. status not `Active` --> out of scope
4. `created != true` --> domain creation not complete
5. `deleted == true` --> domain is being deleted
6. CloudWatch returned no datapoints --> insufficient evidence
7. coverage_ratio < 0.95 --> insufficient evidence (domain may not have existed for full window)
8. `OpenSearchRequests` Sum > 0 --> not idle

---

## 10. Failure Model

**Rule-level failures (FAIL RULE):**

- `ListDomainNames` request failure or permission failure
- `DescribeDomain` / `DescribeDomains` permission failure
- CloudWatch `GetMetricStatistics` permission failure
- CloudWatch `GetMetricStatistics` request failure for the primary `OpenSearchRequests` metric
  (any non-permission error is still a rule failure — this is a required signal, not optional
  context)

**Item-level skips (SKIP ITEM):**

- malformed identity or missing required fields
- non-`Active` status or creation/deletion in progress
- non-zero OpenSearch requests
- CloudWatch returned no datapoints for `OpenSearchRequests` (insufficient evidence)
- non-permission `DescribeDomain` failure for a specific domain (narrow race: domain deleted
  between list and describe)

---

## 11. Evidence / Details Contract

### Required details fields

```
evaluation_path                  = "idle-opensearch-domain-review-candidate"
domain_name
arn
domain_processing_status         = "Active"
engine_version
instance_type
instance_count
idle_days_threshold
evaluation_window_start
evaluation_window_end
opensearch_requests_sum
expected_datapoints
actual_datapoints
coverage_ratio
is_idle                          = true
```

### Optional context fields

```
domain_id
search_rate_sum
indexing_rate_sum
dedicated_master_enabled
dedicated_master_type
dedicated_master_count
warm_enabled
warm_type
warm_count
ebs_enabled
ebs_volume_type
ebs_volume_size_gb
endpoint
endpoints
searchable_documents
```

### Required evidence wording

**Signals used** must state:

- domain processing status is `Active`
- `OpenSearchRequests` Sum was 0 over the evaluation window
- the idle window duration

**Signals not checked** must state major blind spots:

- business value or planned future use
- whether deleting the domain is safe
- compliance log retention purpose
- exact price impact or savings impact
- whether domain data has been backed up

---

## 12. Confidence Model

| Condition | Confidence |
|---|---|
| `opensearch_requests_sum == 0` AND `search_rate_sum == 0` AND `indexing_rate_sum == 0` (all present) | `HIGH` |
| `opensearch_requests_sum == 0` AND either secondary signal is `null` (missing/failed) | `MEDIUM` |
| `opensearch_requests_sum == 0` only (secondary signals not zero) | `MEDIUM` |

No LOW finding should be emitted.

---

## 13. Risk Model

| Condition | Risk |
|---|---|
| `instance_count >= 3` OR `warm_enabled == true` OR `dedicated_master_enabled == true` | `HIGH` |
| all other emitted findings | `MEDIUM` |

Risk is about likely waste severity based on domain topology, not proof of safe action.
Multi-node domains, domains with warm/cold tiers, and domains with dedicated masters represent
larger deployments with higher idle cost. These are stable shape signals that do not require
maintaining a list of instance types.

---

## 14. Title and Reason Contract

| Condition | Title | Reason |
|---|---|---|
| Idle OpenSearch domain finding | `"Idle OpenSearch domain review candidate"` | `"Active OpenSearch domain has had zero requests over the configured idle window"` |

---

## 15. Non-Goals

This rule does **not**:

- infer exact billing from static instance-price tables
- cover OpenSearch Serverless collections (separate service, `opensearchserverless` client)
- determine whether a domain should be deleted automatically
- assess data backup status before recommending deletion
- use `SearchableDocuments` as a primary decision signal (a domain with documents but no queries
  is still idle)
