# aws.cloudwatch.logs.infinite_retention — Canonical Rule Specification

## 1. Intent

Detect CloudWatch Logs log groups in the current account and region that have no
retention policy configured and therefore retain log events indefinitely.

This is a **read-only hygiene rule**. It is not an idle-usage rule, not a deletion rule,
and not proof that changing retention is always appropriate.

---

## 2. AWS API Grounding

Based on official CloudWatch Logs API and user-guide behavior.

### Key AWS facts

| Field | Behaviour |
|---|---|
| `logGroupName` | Always present on log group objects from `DescribeLogGroups` |
| `creationTime` | Epoch milliseconds; present on most log groups |
| `logGroupClass` | `STANDARD`, `INFREQUENT_ACCESS`, or `DELIVERY` |
| `retentionInDays` | Set by `PutRetentionPolicy`; absent if no policy is configured |
| `storedBytes` | Non-billing, eventually-consistent storage metric; deleted-data excluded |

### DELIVERY class

DELIVERY class retention is service-managed, not user-configurable for this rule's purpose.
DELIVERY class is **out of scope** for this hygiene rule.

### `logGroupNamePattern` constraint

If `DescribeLogGroups` is called with `logGroupNamePattern`, AWS returns only `arn`,
`creationTime`, and `logGroupName`. `retentionInDays` and `storedBytes` are **not** returned.

**Rule-design consequence:** This rule MUST NOT use `logGroupNamePattern` because
`retentionInDays` would not be present in that response shape.

### Rule-design consequence

- No-retention is a **configuration fact**, directly observed from the API.
- `storedBytes` is a non-billing storage metric only — never an activity signal.
- This rule is NOT an idle detector.

---

## 3. Scope

**Included:**
- Log groups returned by `DescribeLogGroups` in the current account and region
- `logGroupClass` in: `STANDARD`, `INFREQUENT_ACCESS`
- Log groups with `retentionInDays` absent or null

**Excluded:**
- Log groups with `retentionInDays` set
- `DELIVERY` class log groups
- Cross-account linked log groups unless `includeLinkedAccounts` is explicitly enabled
- Malformed records without `logGroupName`

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `age_days` | `now − creationTime` when `creationTime` is available; null otherwise |
| `stored_bytes` | The `storedBytes` value from `DescribeLogGroups`; null if absent |
| `stored_gb` | `stored_bytes / 1024³`; null if `stored_bytes` is null |
| No-retention state | `retentionInDays` is not present in the returned log group object |

### Important rules

- No-retention state is a configuration fact, not a heuristic.
- `storedBytes` MUST NOT be used to infer "active" or "inactive".
- Missing `creationTime` MUST NOT suppress detection.
- No default age-based suppression is part of this spec.

---

## 5. Signal Model (Strict Separation)

### A. EXCLUSION_RULES

Hard skip conditions:

| Condition | Result |
|---|---|
| `logGroupName` absent | **SKIP** (malformed record) |
| `logGroupClass == "DELIVERY"` | **SKIP** |
| `retentionInDays` is set | **SKIP** |

No age-based suppression is defined in this spec.

### B. DETECTION_SIGNAL

Single finding trigger:

| Condition | Result |
|---|---|
| Eligible log group (`STANDARD` or `INFREQUENT_ACCESS`) with `retentionInDays` absent | **EMIT** |

### C. CONTEXTUAL_SIGNALS (non-detecting)

May only affect risk or appear in evidence. MUST NOT create or suppress findings.

Includes:
- `storedBytes` / `stored_gb`
- `creationTime` / `age_days`
- `logGroupClass`

**Hard rules:**
- `storedBytes` must not redefine no-retention state.
- `storedBytes` is a non-billing storage metric only.

---

## 6. Evaluation Order (Mandatory)

1. Parse and normalize log-group fields
2. Apply `EXCLUSION_RULES`
3. Detect no-retention state
4. Assign confidence
5. Assign risk
6. Build evidence/details

---

## 7. Confidence Model

Confidence measures certainty of the configuration problem.

| Condition | Confidence |
|---|---|
| Eligible log group with `retentionInDays` absent | `HIGH` |

**Mandatory rule:** This rule MUST use `HIGH` confidence because the configuration state
is directly observed from the AWS API.

---

## 8. Risk Model

Risk measures business/operational urgency, independent of confidence.

| Condition | Risk |
|---|---|
| `stored_gb >= 1.0` | `HIGH` |
| `stored_bytes > 0` and `stored_gb < 1.0` | `MEDIUM` |
| `stored_bytes == 0` (or null) | `LOW` |

**Important notes:**
- These thresholds are product-policy choices, not AWS-defined thresholds.
- Infinite retention may be intentional for compliance, audit, or security logs.
- `storedBytes` may be used only as a proxy for present storage exposure, not as a
  signal of activity, inactivity, or billing truth.

---

## 9. Cost Model

**Informational only.** MUST NOT affect detection, confidence, or risk.

**Allowed:** approximate storage-cost estimate from `storedBytes` using maintained
AWS pricing references.

**Required caveats:**
- Pricing is region-dependent
- Pricing source is outside the API itself
- `storedBytes` is not billing data
- `storedBytes` is a point-in-time storage metric, not a forecast
- This is storage-cost context only, not ingestion-cost context

---

## 10. Failure Behavior

### Required API

`logs:DescribeLogGroups` — failure = **rule fails** (raises `PermissionError`)

### Mandatory API usage rules

- Implementations MUST paginate `DescribeLogGroups` until `nextToken` is exhausted.
- MUST NOT use `logGroupNamePattern` (omits `retentionInDays` and `storedBytes`).
- A finding may only be emitted when `retentionInDays` is observed on the actual
  `DescribeLogGroups` response objects used by the rule.
- Optional enrichment fields missing from an individual log group must not fail the scan.

---

## 11. Blind Spots

Every finding must disclose in `signals_not_checked`:

1. Intentional compliance/audit/security retention is not known
2. Recent ingestion activity is not checked (this is a hygiene rule)
3. Application-level usage context
4. Future ingestion volume
5. Cross-account linked log groups are out of scope unless `includeLinkedAccounts` is explicitly enabled
6. DELIVERY class log groups are excluded (retention is service-managed)

---

## 12. Evidence Contract

Every finding **must** include all of the following (null allowed, never omitted):

| Field | Requirement |
|---|---|
| `evaluation_path` | Exactly `"no-retention"` |
| `log_group_name` | Always present |
| `log_group_class` | Always present (null if absent from API) |
| `retention_state` | Always present |
| `creation_time` | Present OR null |
| `age_days` | Present OR null |
| `stored_bytes` | Present OR null |
| `stored_gb` | Present OR null |

`signals_not_checked` must include all blind spots listed in §11.

---

## 13. Title and Reason Contract

| Field | Value |
|---|---|
| `title` | `"CloudWatch log group with no retention policy"` |
| `reason` | `"Retention is not configured; log events do not expire"` |

**Hard rules:**
- Do NOT describe this as an idle or inactive log group.
- Do NOT describe zero `storedBytes` as "unused".

---

## 14. API and IAM Contract

**Required:** `logs:DescribeLogGroups`

**Constraints:**
- Do NOT use `logGroupNamePattern` if the rule depends on `retentionInDays` or `storedBytes`.
- No implicit cross-account coverage assumption is allowed.

---

## 15. Acceptance Scenarios

### Must emit

1. `STANDARD` log group, `retentionInDays` absent
2. `INFREQUENT_ACCESS` log group, `retentionInDays` absent
3. No-retention log group with `storedBytes == 0`
4. No-retention log group with `storedBytes > 0`

### Must skip

1. `retentionInDays` set to any valid AWS retention value
2. `DELIVERY` class log group, even if `retentionInDays` is absent
3. Malformed record without `logGroupName`

### Must NOT happen

1. DELIVERY log groups labeled "infinite retention"
2. `storedBytes` treated as proof of activity or inactivity
3. `logGroupNamePattern`-only responses used to infer no-retention
4. Missing `creationTime` suppresses a finding
5. Incomplete pagination causes silent coverage loss

---

## 16. In-File Contract

Every implementation file must include this docstring verbatim:

```
Rule: aws.cloudwatch.logs.infinite_retention

Intent:
    Detect eligible CloudWatch log groups with no retention policy configured.

Exclusions:
    - retentionInDays is set
    - DELIVERY class log groups

Detection:
    - retentionInDays key not present on STANDARD or INFREQUENT_ACCESS log groups

Key rules:
    - This is a hygiene/configuration rule, not an idle rule.
    - Missing retention is a direct AWS-observed configuration fact.
    - storedBytes must not be used as an activity signal.
    - storedBytes is a non-billing storage metric.
    - DELIVERY class must be excluded because its retention is service-managed.

Blind spots:
    - intent for compliance/audit/security retention is not known
    - ingestion/activity is not checked
    - future log growth is not known

API:
    - logs:DescribeLogGroups
```

---

## 17. Implementation Constants

| Constant | Default | Description |
|---|---|---|
| `_STORAGE_COST_PER_GB_APPROX` | `0.03` | Approximate cost per GB-month (us-east-1, informational only) |
| `_HIGH_RISK_GB` | `1.0` | Stored GB threshold for HIGH risk |
