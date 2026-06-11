# aws.sagemaker.domain.idle — Canonical Rule Specification

## 1. Intent

Detect Amazon SageMaker Domains in the currently evaluated account/Region that are
`InService` and have **no currently running apps** across all user profiles and spaces,
so they can be reviewed as potential FinOps cleanup candidates.

A SageMaker Domain creates a managed EFS file system on first user onboarding. That file
system persists and incurs continuous storage charges regardless of whether any Studio apps
are running. A domain with no active apps represents wasted EFS cost with no current
compute value.

This is a **read-only review-candidate rule**. It is not proof that the domain is safe to
delete, not proof that no user intends to start an app shortly, and not proof of the exact
storage cost.

---

## 2. AWS API Grounding

Based on official Amazon SageMaker Studio, SageMaker API Reference, SageMaker Studio
pricing, and IAM permissions documentation.

### Key AWS facts

1. `ListDomains` is the canonical SageMaker Domain inventory API and supports pagination.
2. `DomainDetails` (from `ListDomains`) documents `DomainId`, `DomainArn`, `DomainName`,
   `Status`, `CreationTime`, `LastModifiedTime`, and `Url`.
3. `Domain.Status` valid values are `Deleting`, `Failed`, `InService`, `Pending`,
   `Updating`, `Update_Failed`, and `Delete_Failed`.
4. `DescribeDomain` returns additional fields including `HomeEfsFileSystemId`,
   `HomeEfsFileSystemCreation`, `AppNetworkAccessType`, `DefaultUserSettings`,
   `DefaultSpaceSettings`, `AuthMode`, `VpcId`, and `SubnetIds`.
5. `HomeEfsFileSystemId` documents the ID of the EFS file system managed by the domain.
6. AWS documentation states that when the first user is onboarded to a domain, SageMaker
   creates an EFS volume and that "a storage charge is incurred for this directory."
7. `ListApps` supports `DomainIdEquals` filtering and returns `AppDetails` items.
8. `AppDetails` (from `ListApps`) documents `AppName`, `AppType`, `CreationTime`,
   `DomainId`, `UserProfileName`, `SpaceName`, `Status`, and `ResourceSpec`.
9. `App.Status` valid values are `Deleted`, `Deleting`, `Failed`, `InService`, and `Pending`.
10. `App.AppType` valid values include `JupyterServer`, `KernelGateway`, `JupyterLab`,
    `CodeEditor`, `RStudioServerPro`, `RSessionGateway`, `DetailedProfiler`, `TensorBoard`,
    and `Canvas`.
11. `DescribeApp` returns `LastUserActivityTimestamp` and `LastHealthCheckTimestamp`.
12. AWS documentation explicitly states: "`LastUserActivityTimestamp` is also updated when
    SageMaker AI performs health checks without user activity. As a result, this value is
    set to the same value as `LastHealthCheckTimestamp`." This makes it unreliable as a
    canonical user-activity signal.
13. There is no documented CloudWatch namespace or metric for SageMaker Studio Domain or
    App-level activity. No `KernelGateway` or domain-level CloudWatch metrics are documented.
14. Apps in `InService` status incur hourly compute charges. AWS documentation states that
    "launching a JupyterLab application, even if no resources or jobs are launched in the
    application, incurs costs."
15. There is no charge for the SageMaker Studio UI or the domain itself beyond EFS storage
    and app compute.
16. `DefaultUserSettings` may contain `AppLifecycleManagement.IdleSettings` for JupyterLab
    and CodeEditor apps, reflecting whether native idle shutdown is configured.

### Implications

- Only `InService` Domains are eligible.
- Age thresholding is supportable because `CreationTime` is documented in `ListDomains`.
- The canonical idle signal is control-plane state: presence or absence of `InService` apps
  under the domain, not a CloudWatch metric (none is documented).
- `LastUserActivityTimestamp` from `DescribeApp` is explicitly documented as contaminated
  by health checks and must not be used as a primary idle signal.
- `HomeEfsFileSystemId` surfaces cost context but cannot be mapped to a canonical per-domain
  monthly cost estimate.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **"Domain"** — an item returned by `ListDomains`.
- **"App"** — an item returned by `ListApps(DomainIdEquals=domain_id)`.
- **"idle"** — the domain has no apps in `InService` or `Pending` status across all user
  profiles and spaces at the time of evaluation.
- **"billable app state"** — `InService` or `Pending`. `Pending` means app launch is in
  progress; the domain is not considered idle while any app is starting.
- **`idle_days_threshold`** — operator-configurable threshold applied to domain age,
  default `30`. This threshold applies to domain age, not measured inactivity duration.
- **`reference_time_utc = CreationTime`** (domain level; `LastModifiedTime` reflects
  config changes, not user activity, and must not be used as the age reference).
- **`age_days = floor((now_utc − reference_time_utc) / 86400 seconds)`**

### Included

- Domains in the currently evaluated Region/account
- `Status == "InService"`
- `age_days >= idle_days_threshold`
- no apps in `InService` or `Pending` status across the domain at evaluation time

### Excluded

- `Deleting`, `Pending`, `Updating`, `Update_Failed`, `Delete_Failed`, `Failed`
- missing or invalid stable identity
- missing or invalid `CreationTime`
- too new to evaluate (`age_days < idle_days_threshold`)
- any app currently `InService` or `Pending` in the domain

---

## 4. Canonical Rule Statement

A Domain is eligible only when **all** of the following are true:

- stable domain identity (`DomainId`, `DomainArn`) exists
- `Status == "InService"`
- `CreationTime` is valid and not in the future
- `age_days >= idle_days_threshold`
- `ListApps(DomainIdEquals=domain_id)` returns no apps with `Status` in
  `{"InService", "Pending"}`

No additional predicate may be required for baseline eligibility, including:

- auth mode (`SSO` vs `IAM`)
- network access type (`PublicInternetOnly` vs `VpcOnly`)
- whether native idle shutdown is configured (`AppLifecycleManagement.IdleSettings`)
- VPC configuration
- KMS key presence
- number of user profiles or spaces
- `HomeEfsFileSystemCreation` setting
- tags

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

### 5.1 Domain-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `DomainArn` | skip item |
| `domain_arn` | `DomainArn` | skip item |
| `domain_id` | `DomainId` | skip item |
| `domain_name` | `DomainName` | null |
| `normalized_status` | `Status` | skip item |
| `creation_time_utc` | `CreationTime` (tz-aware UTC) | skip item |
| `last_modified_time_utc` | `LastModifiedTime` (tz-aware UTC) | null |
| `age_days` | floor((now − creation_time_utc) / 86400) | skip item |
| `home_efs_file_system_id` | `DescribeDomain.HomeEfsFileSystemId` | null |
| `home_efs_file_system_creation` | `DescribeDomain.HomeEfsFileSystemCreation` | null |
| `app_network_access_type` | `DescribeDomain.AppNetworkAccessType` | null |
| `auth_mode` | `DescribeDomain.AuthMode` | null |
| `idle_shutdown_configured` | `true` if `AppLifecycleManagement.IdleSettings.LifecycleManagement == "Enabled"` in any of: `DefaultUserSettings.JupyterLabAppSettings`, `DefaultUserSettings.CodeEditorAppSettings`, `DefaultSpaceSettings.JupyterLabAppSettings`, `DefaultSpaceSettings.CodeEditorAppSettings` | `false` |

### 5.2 Normalization Requirements

- String-valued identifiers must normalize only from non-empty strings.
- Timestamp fields must be timezone-aware UTC before use; naive → skip item for required
  timestamps, null for contextual timestamps.
- Future `CreationTime` → skip item.
- `resource_id` must be `DomainArn`, not `DomainId` or `DomainName`.
- `DescribeDomain` is called per domain to obtain EFS and settings context.
  - Permission-denied (`AccessDeniedException`) → **FAIL RULE** (the IAM policy is
    missing a required permission; continuing would produce systematically incomplete
    results).
  - All other `DescribeDomain` failures (throttling after retries, resource-not-found
    race, transient network error) → **SKIP ITEM** for that domain's enrichment; the
    rule continues evaluating remaining domains.

### 5.3 App-Level Fields

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `app_name` | `AppName` | null (tolerated) |
| `app_type` | `AppType` | null |
| `app_status` | `Status` | skip domain (unclassifiable) |
| `app_creation_time_utc` | `CreationTime` (tz-aware UTC) | null |
| `user_profile_name` | `UserProfileName` | null |
| `space_name` | `SpaceName` | null |

App normalization requirements:

- An app entry is **unclassifiable** if `app_status` is absent or not one of the
  documented `App.Status` values.
- If any app entry in the domain is unclassifiable → **SKIP ITEM** (the domain must not
  be emitted, because the unclassifiable app could be in a billable state).
- `AppName` absent is tolerated for status-checking purposes: an app with a valid
  `app_status` but missing `AppName` still counts toward the billable-app check.

---

## 6. Idle-Activity Determination

The control-plane `ListApps` response is the **sole trusted activity source** for this
rule. There is no documented CloudWatch metric for SageMaker Studio Domain or App activity.

### Required API contract

| Field | Value |
|---|---|
| API | `ListApps` |
| Filter | `DomainIdEquals = domain_id` |
| Pagination | full pagination required via `NextToken` |

### Billable app states

Apps in the following states must be treated as active compute presence:

- `InService` — app is running and billing
- `Pending` — app launch is in progress; domain is not considered idle

### Interpretation rules

- If any app entry has an unclassifiable `Status` (absent or not a documented value) →
  **SKIP ITEM** (cannot confirm the domain is idle)
- If any app in the domain has `Status` in `{"InService", "Pending"}` → **not idle** →
  **SKIP ITEM**
- Domain is idle only when all returned apps have `Status` in `{"Deleted", "Deleting",
  "Failed"}`, or there are no apps at all

### Pagination requirement

`ListApps` must be fully paginated. Partial results must not be interpreted as confirming
zero active apps.

### Failure semantics

- `ListApps` request or pagination failure → **FAIL RULE**
- Any app entry with unclassifiable `app_status` → **SKIP ITEM** for the entire domain
  (the unclassifiable entry could be billable)

### `LastUserActivityTimestamp` — explicitly excluded as primary signal

AWS documentation states `LastUserActivityTimestamp` is also set on health checks and
equals `LastHealthCheckTimestamp`. This field must not be used as canonical user-activity
evidence. It may be surfaced as optional context only, with caveats.

---

## 7. Pricing / Cost Boundary

- `estimated_monthly_cost_usd = null`

### What is documentable

- The domain has an EFS file system (`HomeEfsFileSystemId`) that incurs continuous EFS
  storage charges
- Apps in `InService` incur hourly compute charges; the idle domain has none currently
- The finding may state that EFS storage costs continue until the domain is deleted

### Mandatory rules

- MUST NOT emit a fixed monthly EFS storage estimate per domain
- MUST NOT infer immediate savings from idle state alone
- MAY surface `home_efs_file_system_id` and `home_efs_file_system_creation` as cost context

---

## 8. Deterministic Evaluation Order

1. Retrieve and fully paginate `ListDomains`
2. Normalize each domain summary item
3. For each normalized item:
   - `domain_arn` or `domain_id` absent → **SKIP ITEM**
   - `normalized_status` absent → **SKIP ITEM**
   - `normalized_status != "InService"` → **SKIP ITEM**
   - `creation_time_utc` absent/invalid/future → **SKIP ITEM**
   - `age_days < idle_days_threshold` → **SKIP ITEM**
4. Call `DescribeDomain(DomainId=domain_id)` to obtain `HomeEfsFileSystemId`,
   `HomeEfsFileSystemCreation`, and settings context
   - `DescribeDomain` permission-denied (`AccessDeniedException`) → **FAIL RULE**
   - `DescribeDomain` other failure → **SKIP ITEM** (item-scoped, rule continues)
5. Normalize domain enrichment fields
6. Call and fully paginate `ListApps(DomainIdEquals=domain_id)`
   - `ListApps` failure or pagination failure → **FAIL RULE**
7. Normalize app entries
8. If any app entry has unclassifiable `app_status` (absent or not a documented value)
   → **SKIP ITEM**
9. If any app has `app_status` in `{"InService", "Pending"}` → **SKIP ITEM**
10. Otherwise → **EMIT**

---

## 9. Exclusion Rules

1. `domain_arn` absent → malformed identity
2. `domain_id` absent → cannot filter `ListApps`
3. `normalized_status` absent → missing current-state signal
4. `normalized_status != "InService"` → domain not currently active
5. `creation_time_utc` absent/naive/future → invalid age source
6. `age_days < idle_days_threshold` → too new
7. any app with `Status == "InService"` → compute currently running
8. any app with `Status == "Pending"` → app launch in progress, domain not idle

No exclusion for: auth mode, network access type, VPC config, KMS key, Studio version,
native idle shutdown config, tag state, or EFS creation mode.

---

## 10. Failure Model

### Rule-level failures (FAIL RULE)

- `ListDomains` request or pagination failure
- `ListApps` request or pagination failure for any domain that reached the app-check step
- Permission-denied (`AccessDeniedException`) on any required API (`ListDomains`,
  `DescribeDomain`, `ListApps`)

### Item-level skips (SKIP ITEM)

- malformed identity or missing `CreationTime`
- non-`InService` domain status
- domain too new
- `DescribeDomain` non-permission failure (throttling after retries, resource-not-found
  race, transient network error)
- any app in `InService` or `Pending` state
- any app entry with unclassifiable `Status` (see §6 malformed-app handling)

---

## 11. Confidence Model

| Condition | Confidence |
|---|---|
| `ListApps` fully paginated, zero `InService` or `Pending` apps | `HIGH` |

**Mandatory rule:** use `HIGH` confidence. The finding is based on direct control-plane
state from fully paginated `ListApps`. The absence of running apps at evaluation time is
a documentable fact, not an inference from a metric proxy.

---

## 12. Risk Model

| Condition | Risk |
|---|---|
| `HomeEfsFileSystemId` is present (non-null, non-empty) | `HIGH` |
| `HomeEfsFileSystemId` is absent or null | `MEDIUM` |

**Note:** risk is based on `HomeEfsFileSystemId` presence from `DescribeDomain`, not on
verified EFS file system existence. No EFS API call is made. A present ID is a strong
signal of continuous storage cost because SageMaker-managed EFS volumes are not deleted
until the domain itself is deleted.

---

## 13. Evidence / Details Contract

### Required details fields

```text
evaluation_path                  = "idle-sagemaker-domain-review-candidate"
domain_arn
domain_id
domain_name
normalized_status                = "InService"
creation_time
age_days
idle_days_threshold
home_efs_file_system_id
home_efs_file_system_creation
app_network_access_type
auth_mode
idle_shutdown_configured
total_apps_evaluated
apps_by_status                   (dict: status → count across all evaluated app entries)
inservice_app_count              = 0
pending_app_count                = 0
```

### Optional context fields

```text
last_modified_time
user_profile_count               (if available from ListUserProfiles — enrichment only)
space_count                      (if available from ListSpaces — enrichment only)
```

### Required evidence wording

**Signals used** must state:

- domain is currently `InService`
- domain age met the configured threshold using `CreationTime`
- `ListApps` was fully paginated and found zero apps in `InService` or `Pending` state
- EFS file system ID is surfaced as continuous cost context

**Signals not checked** must state major blind spots:

- `LastUserActivityTimestamp` from `DescribeApp` was not used as evidence because AWS
  documents it as updated on health checks, making it unreliable as a user-activity signal
- a user may start a new app shortly after evaluation; this is a point-in-time check
- the domain may be intentionally kept active for periodic or scheduled use
- `Deleting` apps may transition back to `InService` if the deletion fails
- EFS storage cost depends on per-user home directory content; this rule does not inspect
  directory sizes or file counts
- native idle shutdown configuration (`AppLifecycleManagement.IdleSettings`) is surfaced
  as context but does not affect eligibility

---

## 14. Non-goals / Blind Spots

This rule does **not** prove any of the following:

- that the domain is safe to delete
- that users are not actively using the domain outside the observation window
- that no app will be started imminently
- that all data in the EFS home directories is safe to remove
- the exact current EFS storage cost
- that the domain has no operational dependencies (CI/CD pipelines, scheduled notebooks)

---

## 15. API and IAM Contract

### Required APIs

- `sagemaker:ListDomains`
- `sagemaker:DescribeDomain`
- `sagemaker:ListApps`

### Optional enrichment APIs (not required for eligibility)

- `sagemaker:ListUserProfiles`
- `sagemaker:ListSpaces`

### Mandatory API usage rules

- `ListDomains` must be fully paginated
- `ListApps` must be called with `DomainIdEquals` and fully paginated
- `DescribeApp` must not be called as part of the canonical eligibility path (it is not
  required for idle determination; `LastUserActivityTimestamp` is excluded as a signal)
- undocumented fallback activity signals must not be substituted

---

## 16. Acceptance Scenarios

### Must emit

1. `InService` Domain older than threshold, `ListApps` returns zero apps → emit with
   `risk = HIGH` if `HomeEfsFileSystemId` present
2. `InService` Domain older than threshold, all apps have `Status == "Deleted"` →
   emit with `risk = HIGH` if `HomeEfsFileSystemId` present
3. `InService` Domain older than threshold, all apps have `Status == "Failed"` →
   emit with `risk = MEDIUM` or `HIGH` depending on EFS presence

### Must skip

4. `Pending` domain
5. `Updating` domain
6. `Deleting` domain
7. `Failed` domain
8. `InService` domain younger than threshold
9. malformed item without `DomainArn`
10. malformed item without `DomainId`
11. malformed item with missing/invalid/future `CreationTime`
12. domain with any app in `Status == "InService"`
13. domain with any app in `Status == "Pending"`
14. domain with any app entry where `Status` is absent or not a documented value
15. `DescribeDomain` non-permission failure for a specific domain (item skipped, rule
    continues)

### Must fail

16. `ListDomains` request or pagination failure
17. `ListApps` request or pagination failure for any domain that reached the app-check step
18. `DescribeDomain` permission-denied (`AccessDeniedException`)

---

Rule: aws.sagemaker.domain.idle
