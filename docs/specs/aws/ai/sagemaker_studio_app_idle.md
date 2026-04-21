# aws.sagemaker.studio_app.idle — Canonical Rule Specification

## 1. Intent

Detect SageMaker Studio applications that are currently `InService`, belong to the supported
interactive compute-backed app types, and show no recent best-effort activity timestamp for the
configured review window, so they can be reviewed as possible cleanup candidates.

This is a **CleanCloud-derived review heuristic** based on SageMaker Studio app metadata, not an
AWS-native idle state. It is a **read-only review-candidate rule** — not a delete-safe rule.

---

## 2. AWS API Grounding

Based on official SageMaker Studio app API and documentation.

### Key facts

1. `ListApps` is the canonical inventory API for SageMaker Studio apps and supports pagination.
2. `ListApps` returns `AppDetails` summaries including `AppName`, `AppType`, `CreationTime`,
   `DomainId`, `ResourceSpec`, `SpaceName`, `Status`, and `UserProfileName`.
3. `AppDetails.AppType` can include `JupyterServer`, `KernelGateway`, `DetailedProfiler`,
   `TensorBoard`, `CodeEditor`, `JupyterLab`, `RStudioServerPro`, `RSessionGateway`, and
   `Canvas`.
4. `DescribeApp` returns `AppArn`, `AppName`, `AppType`, `CreationTime`, `DomainId`,
   `LastHealthCheckTimestamp`, `LastUserActivityTimestamp`, `ResourceSpec`, `SpaceName`,
   `Status`, and `UserProfileName`.
5. AWS explicitly states that `LastUserActivityTimestamp` is also updated when SageMaker AI
   performs health checks without user activity. As a result, this value is set to the same value
   as `LastHealthCheckTimestamp`.
6. `DeleteApp` is the documented action used to stop a Studio application, and stopping the app
   also stops the instance that the app is running on.
7. The updated Studio running-instances documentation says stopped instances do not appear on the
   running-instances page.
8. Fixed monthly USD cost estimates are not canonical from the fetched AWS docs.

### Implications

- `ListApps` plus `DescribeApp` are the canonical APIs for this rule.
- `usable_activity_signal` is derived from `DescribeApp.LastUserActivityTimestamp`, but AWS does
  not define that source field as an authoritative user-activity signal.
- `LastUserActivityTimestamp == LastHealthCheckTimestamp` should be treated conservatively as a
  system-driven or otherwise non-user activity update, not as clear user activity.
- `CreationTime` is metadata only and is used for validation/reporting, not idle decisioning.
- `InService` is the only eligible runtime state for this rule.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **Studio app** — an item returned by `ListApps`.
- **Supported app types** — `KernelGateway`, `JupyterLab`, `CodeEditor`.
- **usable_activity_signal** — conservative activity proxy derived from
  `LastUserActivityTimestamp`; true only when `LastUserActivityTimestamp` is present and not equal
  to `LastHealthCheckTimestamp`.
- `idle_days_threshold` — operator-configurable, default 7.
- `age_days = floor((now_utc − creation_time_utc) / 86400 seconds)`.
- `idle_since_days = floor((now_utc − last_user_activity_time_utc) / 86400 seconds)`.
- `evaluation_window_start_utc = now_utc − idle_days_threshold × 86400 seconds`.
- `evaluation_window_end_utc = now_utc`.

### Explicit scope boundary

This rule applies only to supported Studio app types in `InService` state:

- `KernelGateway`
- `JupyterLab`
- `CodeEditor`

Out of scope:

- `JupyterServer` — excluded from evaluation
- `DetailedProfiler` — excluded from evaluation
- `TensorBoard` — excluded from evaluation
- `RStudioServerPro` — excluded from evaluation
- `RSessionGateway` — excluded from evaluation
- `Canvas` — excluded from evaluation
- stopped / deleted apps and any persistent storage associated with their spaces

---

## 4. Canonical Rule Statement

A Studio app is eligible only when **all** of the following are true:

- stable Studio app identity exists
- `Status == "InService"`
- `AppType` is in the supported app-type set
- `CreationTime` is valid
- `LastUserActivityTimestamp` is valid
- `usable_activity_signal = true`
- `idle_since_days >= idle_days_threshold`

No additional predicate may be required for baseline eligibility, including lifecycle config
attachment, tags, image ARNs, or health-check timestamp age.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

### 5.1 List-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `domain_id` | `DomainId` | skip item |
| `app_name` | `AppName` | skip item |
| `app_type` | `AppType` | skip item |
| `list_status` | `Status` | skip item |
| `creation_time_utc` | `CreationTime` (tz-aware UTC) | skip item |
| `space_name` | `SpaceName` | null |
| `user_profile_name` | `UserProfileName` | null |
| `instance_type` | `ResourceSpec.InstanceType` | null |

### 5.2 Describe-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `AppArn` | skip item |
| `app_arn` | `AppArn` | skip item |
| `describe_status` | `Status` | skip item |
| `last_user_activity_time_utc` | `LastUserActivityTimestamp` (tz-aware UTC) | skip item |
| `last_health_check_time_utc` | `LastHealthCheckTimestamp` (tz-aware UTC) | null |
| `describe_instance_type` | `ResourceSpec.InstanceType` | null |

### 5.3 Derived Fields

| Canonical field | Derivation |
|---|---|
| `owner_type` | `"space"` when `space_name` present, `"user_profile"` when `user_profile_name` present, otherwise skip item |
| `owner_name` | `space_name` or `user_profile_name` |
| `age_days` | floor((now − creation_time_utc) / 86400) |
| `idle_since_days` | floor((now − last_user_activity_time_utc) / 86400) |
| `usable_activity_signal` | defined by the usable activity signal rule in Section 6 |

Normalization requirements:

- String-valued fields: normalize only from non-empty strings.
- Timestamp fields: must be timezone-aware UTC before use; naive timestamps must skip the item.
- Future `CreationTime`, `LastUserActivityTimestamp`, or `LastHealthCheckTimestamp` must skip
  the item.
- `LastUserActivityTimestamp < CreationTime` must skip the item as inconsistent timestamp state.

---

## 6. Usable Activity Signal Contract

`usable_activity_signal` is derived from `DescribeApp.LastUserActivityTimestamp`, subject to the
health-check contamination rule below.

### 6.1 Usable signal rule

- If `LastUserActivityTimestamp` is absent → **SKIP ITEM** (insufficient evidence).
- If `LastHealthCheckTimestamp` is present and
  `LastUserActivityTimestamp == LastHealthCheckTimestamp` → **SKIP ITEM** (may indicate a
  health-check-driven or otherwise system-driven update rather than user activity).
- Otherwise `usable_activity_signal = true`.

### 6.2 Interpretation

- If `usable_activity_signal = true` and `idle_since_days >= idle_days_threshold`, the app is an
  idle review candidate.
- `CreationTime` must not be used as a fallback activity signal when
  `LastUserActivityTimestamp` is absent or unusable.

### 6.3 Explicit blind spots

This rule does **not** prove:

- no activity outside what `usable_activity_signal` can represent
- no planned future reuse

---

## 7. Pricing / Cost Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode per-instance monthly cost tables or fallback cost guesses.

---

## 8. Deterministic Evaluation Order

1. Retrieve and fully paginate `ListApps`.
2. Normalize each list item.
3. For each normalized item:
   - identity absent → **SKIP ITEM**
   - list status absent → **SKIP ITEM**
   - list status != `InService` → **SKIP ITEM**
   - unsupported `app_type` → **SKIP ITEM**
   - invalid / naive / future `creation_time_utc` → **SKIP ITEM** (timestamp validity only; not a freshness filter)
   - owner context absent (`space_name` and `user_profile_name` both absent) → **SKIP ITEM**
4. Call `DescribeApp` for the candidate item.
5. Permission failure → **FAIL RULE**.
6. Non-permission describe failure (for example resource vanished between list and describe) →
   **SKIP ITEM**.
7. Normalize describe fields.
8. Re-check describe status; if not `InService` → **SKIP ITEM**.
9. `resource_id` absent → **SKIP ITEM**.
10. invalid / naive / future `LastUserActivityTimestamp` → **SKIP ITEM**.
11. `LastUserActivityTimestamp < CreationTime` → **SKIP ITEM**.
12. `LastHealthCheckTimestamp` present and equal to `LastUserActivityTimestamp` →
    **SKIP ITEM** (treat as non-user activity signal).
13. `idle_since_days < idle_days_threshold` → **SKIP ITEM**.
14. Otherwise → **EMIT**.

No raw AWS field access after normalization.

---

## 9. Exclusion Rules

1. identity absent (`domain_id`, `app_name`, `app_type`) → malformed inventory item
2. list or describe status absent → missing state signal
3. status not `InService` → not currently evaluable
4. unsupported `app_type` → out of rule scope
5. owner context absent → malformed app identity context
6. `CreationTime` absent / naive / future → missing or invalid age source
7. `LastUserActivityTimestamp` absent / naive / future → insufficient best-effort activity evidence
8. `LastUserActivityTimestamp < CreationTime` → inconsistent timestamp state
9. `LastUserActivityTimestamp == LastHealthCheckTimestamp` → treated as non-user activity signal
10. usable `idle_since_days < idle_days_threshold` → not idle enough

---

## 10. Failure Model

**Rule-level failures (FAIL RULE):**

- `ListApps` request or pagination failure
- `DescribeApp` permission failure
- permission failure for required APIs

**Item-level skips (SKIP ITEM):**

- malformed identity or missing required timestamps
- unsupported app type
- non-`InService` status
- missing or unusable activity signal
- non-permission `DescribeApp` failure

---

## 11. Evidence / Details Contract

### Required details fields

```
evaluation_path             = "idle-sagemaker-studio-app-review-candidate"
app_arn
app_name
app_type
domain_id
owner_type
owner_name
normalized_status           = "InService"
creation_time
last_user_activity_time
last_health_check_time
age_days
idle_since_days
idle_days_threshold
evaluation_window_start
evaluation_window_end
usable_activity_signal       = true
```

### Optional context fields

```
instance_type
space_name
user_profile_name
is_gpu_or_accelerator_backed
```

### Required evidence wording

**Signals used** must state:

- Studio app status is `InService`
- Studio app type is within the supported scope
- `usable_activity_signal = true`
- `LastUserActivityTimestamp` is at least the configured threshold old
- the finding excludes timestamps that exactly match the health-check timestamp

**Signals not checked** must state major blind spots:

- background kernel execution or non-UI interactions not represented by `usable_activity_signal`
- planned future usage or intentional warm apps
- stopped-app / space storage cost
- exact region-specific pricing impact

---

## 12. Confidence Model

| Condition | Confidence |
|---|---|
| All emitted findings | `HIGH` |

No MEDIUM/LOW finding should be emitted. Missing or unusable activity signal must skip.

---

## 13. Risk Model

| Condition | Risk |
|---|---|
| Studio app instance type is accelerator-backed (`g*`, `p*`, `inf*`, `trn*`) | `HIGH` |
| All other emitted findings | `MEDIUM` |

Risk is about likely waste severity, not proof of safe deletion.

---

## 14. Title and Reason Contract

| Condition | Title | Reason |
|---|---|---|
| Idle Studio app finding | `"Idle SageMaker Studio app review candidate"` | `"InService SageMaker Studio app shows no recent usable activity timestamp for at least {N} days"` |

---

## 15. Non-Goals

This rule does **not**:

- infer idleness from `CreationTime` alone
- treat health-check-only timestamp updates as real user activity
- estimate canonical monthly waste in USD
- cover stopped apps or space/EBS persistence cost
- cover all SageMaker Studio app types
