# aws.sagemaker.notebook.idle — Canonical Rule Specification

## 1. Intent

Detect SageMaker notebook instances that are currently `InService`, old enough to evaluate,
and show a stale control-plane timestamp state for the configured review window, so they can
be reviewed as possible cleanup candidates.

This is a **CleanCloud-derived low-fidelity stale-control-plane heuristic**, not an AWS-native
notebook idle state. It is intentionally conservative, and false positives are acceptable at
this review-candidate stage. It is a **read-only review-candidate rule** — not a delete-safe
rule.

---

## 2. AWS API Grounding

Based on official SageMaker notebook instance API and documentation.

### Key facts

1. `ListNotebookInstances` is the canonical inventory API for SageMaker notebook instances,
   supports pagination, and supports `StatusEquals`.
2. `NotebookInstanceSummary` includes `NotebookInstanceArn`, `NotebookInstanceName`,
   `NotebookInstanceStatus`, `InstanceType`, `CreationTime`, `LastModifiedTime`, and
   `NotebookInstanceLifecycleConfigName`.
3. `DescribeNotebookInstance` returns the same core identity/state fields plus additional
   configuration, but is not required to obtain the canonical fields needed by this rule.
4. Notebook instance status values include `Pending`, `InService`, `Stopping`, `Stopped`,
   `Failed`, `Deleting`, and `Updating`.
5. `LastModifiedTime` is a documented timestamp field for notebook instances.
6. `UpdateNotebookInstance` is the documented API used to modify notebook configuration.
7. Accessing a notebook through the console uses `CreatePresignedNotebookInstanceUrl`, which
   returns a short-lived URL to connect to the notebook instance.
8. SageMaker provides notebook-related CloudWatch Logs, including
   `/aws/sagemaker/NotebookInstances/[notebook-instance-name]/jupyter.log` and lifecycle-config
   streams.
9. Lifecycle configuration scripts run only when you create the notebook instance or whenever
   you start one.
10. The official notebook-instance API docs do **not** document a native notebook-session
    activity metric equivalent to endpoint `Invocations`.
11. Fixed monthly USD cost estimates are not canonical from the fetched AWS docs.

### Implications

- `ListNotebookInstances(StatusEquals="InService")` is sufficient for canonical inventory and
  baseline enrichment.
- `LastModifiedTime` is a weak control-plane timestamp signal, not a documented notebook-usage
  metric.
- `LastModifiedTime` can support a stale-control-plane heuristic, but it does **not** prove
  absence of Jupyter activity, kernel execution, or notebook access.
- `LastModifiedTime` may change without direct user intent, including start/stop flows or other
  SageMaker-managed control-plane actions.
- `CreatePresignedNotebookInstanceUrl` existence does not provide a canonical idle/non-idle
  signal for this rule.
- CloudWatch Logs exist for notebook instances, but log inspection is not part of the
  canonical rule contract.
- Lifecycle configuration attachment is contextual only; because lifecycle scripts run on
  create/start, attachment alone does not prove current activity.
- `ListNotebookInstances` may be slightly stale relative to per-resource describe state; that
  eventual-consistency gap is acceptable for this heuristic, and the canonical rule does not
  require per-item `DescribeNotebookInstance` calls or a describe-based fallback.
- `Stopped` notebook instances are intentionally out of scope for this rule even though attached
  storage may still cost money; they should be handled by a separate storage / cost-waste rule.
- `estimated_monthly_cost_usd = null`.

---

## 3. Scope and Terminology

- **Notebook instance** — an item returned by `ListNotebookInstances`.
- **Weak stale control-plane timestamp state** — `LastModifiedTime` is at least
  `idle_days_threshold` days old.
- **Age gate** — `CreationTime` is at least `idle_days_threshold` days old.
- `idle_days_threshold` — operator-configurable, default 14.
- `age_days = floor((now_utc − creation_time_utc) / 86400 seconds)`.
- `stale_control_plane_days = floor((now_utc − last_modified_time_utc) / 86400 seconds)`.
- `evaluation_window_start_utc = now_utc − idle_days_threshold × 86400 seconds`.
- `evaluation_window_end_utc = now_utc`.

### Explicit scope boundary

This rule applies only to **SageMaker notebook instances** returned by
`ListNotebookInstances`.

Out of scope:

- SageMaker Studio / Studio Classic apps and spaces
- `Stopped` notebook instances and their attached storage cost
- notebook-session or kernel-level activity reconstruction
- CloudWatch Logs inspection

---

## 4. Canonical Rule Statement

A notebook instance is eligible only when **all** of the following are true:

- stable notebook identity exists
- `NotebookInstanceStatus == "InService"`
- `CreationTime` is valid and `age_days >= idle_days_threshold`
- `LastModifiedTime` is valid and `stale_control_plane_days >= idle_days_threshold`

No additional predicate may be required for baseline eligibility, including lifecycle config
presence, tag state, Git repositories, internet access setting, root access setting, or URL
presence.

---

## 5. Normalization Contract

All rule logic must operate on normalized fields only.

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `NotebookInstanceArn` | skip item |
| `notebook_instance_arn` | `NotebookInstanceArn` | skip item |
| `notebook_instance_name` | `NotebookInstanceName` | skip item |
| `normalized_status` | `NotebookInstanceStatus` | skip item |
| `instance_type` | `InstanceType` | null |
| `creation_time_utc` | `CreationTime` (tz-aware UTC) | skip item |
| `last_modified_time_utc` | `LastModifiedTime` (tz-aware UTC) | skip item |
| `age_days` | floor((now − creation_time_utc) / 86400) | skip item |
| `stale_control_plane_days` | floor((now − last_modified_time_utc) / 86400) | skip item |
| `lifecycle_config_name` | `NotebookInstanceLifecycleConfigName` | null |
| `default_code_repository` | `DefaultCodeRepository` | null |
| `additional_code_repositories` | `AdditionalCodeRepositories` (list of non-empty strings only) | `[]` |

Normalization requirements:

- String-valued fields: normalize only from non-empty strings.
- Timestamp fields: must be timezone-aware UTC before use; naive timestamps must skip the item.
- Future `CreationTime` or future `LastModifiedTime` must skip the item.
- `LastModifiedTime < CreationTime` must skip the item as inconsistent timestamp state.

---

## 6. Idle-Signal Contract

This rule does **not** have a native SageMaker notebook activity metric. The canonical signal
is a **low-fidelity stale control-plane heuristic** based on documented notebook timestamps.
`LastModifiedTime` is a weak signal and the only canonical signal available to this rule.

### Canonical signal

- `stale_control_plane_days >= idle_days_threshold`

### Interpretation

- If `LastModifiedTime` is at least the configured threshold old, the notebook is a stale
  control-plane review candidate.
- This does **not** prove that no user opened Jupyter.
- This does **not** prove that no kernel execution occurred.
- This does **not** prove that no notebook access occurred through the console, browser, or a
  presigned URL.
- This does **not** infer usage intensity of any kind.

### Non-canonical signals

The following must not be required for correctness:

- `CreatePresignedNotebookInstanceUrl`
- CloudWatch Logs inspection (`jupyter.log` or lifecycle-config logs)
- custom CloudWatch metrics or lifecycle scripts
- tag-based intent inference

---

## 7. Pricing / Cost Boundary

- `estimated_monthly_cost_usd = null`
- Do not hardcode per-instance monthly cost tables or fallback cost guesses.

---

## 8. Deterministic Evaluation Order

1. Retrieve and fully paginate `ListNotebookInstances(StatusEquals="InService")`.
2. Normalize each notebook summary item.
3. For each normalized item:
   - identity absent → **SKIP ITEM**
   - `normalized_status` absent → **SKIP ITEM**
   - `normalized_status != "InService"` → **SKIP ITEM**
   - invalid / naive / future `creation_time_utc` → **SKIP ITEM**
   - invalid / naive / future `last_modified_time_utc` → **SKIP ITEM**
   - `last_modified_time_utc < creation_time_utc` → **SKIP ITEM**
   - `age_days < idle_days_threshold` → **SKIP ITEM**
   - `stale_control_plane_days < idle_days_threshold` → **SKIP ITEM**
   - otherwise → **EMIT**

No raw AWS field access after normalization.

---

## 9. Exclusion Rules

1. `resource_id` absent → malformed identity
2. `notebook_instance_name` absent → malformed identity
3. `normalized_status` absent → missing state signal
4. `normalized_status != "InService"` → not currently evaluable
5. `creation_time_utc` absent / naive / future → missing or invalid age source
6. `last_modified_time_utc` absent / naive / future → missing or invalid stale-state source
7. `last_modified_time_utc < creation_time_utc` → inconsistent timestamp state
8. `age_days < idle_days_threshold` → too young
9. `stale_control_plane_days < idle_days_threshold` → not stale enough

---

## 10. Failure Model

**Rule-level failures (FAIL RULE):**

- `ListNotebookInstances` request or pagination failure
- permission failure for required APIs

**Item-level skips (SKIP ITEM):**

- malformed identity or missing required timestamps
- non-`InService` status
- future or inconsistent timestamp state
- too young or not stale enough

---

## 11. Evidence / Details Contract

### Required details fields

```
evaluation_path             = "idle-sagemaker-notebook-review-candidate"
notebook_instance_arn
notebook_instance_name
normalized_status           = "InService"
instance_type
creation_time
last_modified_time
age_days
stale_control_plane_days
idle_days_threshold
evaluation_window_start
evaluation_window_end
```

### Optional context fields

```
lifecycle_config_name
default_code_repository
additional_code_repositories
is_gpu_or_accelerator_backed
```

### Required evidence wording

**Signals used** must state:

- notebook instance status is `InService`
- notebook age met the configured threshold
- `LastModifiedTime` is at least the configured threshold old as a control-plane timestamp
- the finding is based on a low-fidelity stale control-plane heuristic, not a native
  notebook-session activity metric
- `LastModifiedTime` is not a direct signal of Jupyter usage, kernel execution, user access, or
  usage intensity

**Signals not checked** must state major blind spots:

- active Jupyter or kernel sessions
- presigned URL creation or browser access recency
- CloudWatch Logs content such as `jupyter.log`
- scheduled notebook runs or external orchestrators
- SageMaker-managed control-plane actions that can update `LastModifiedTime` without direct user
  intent
- planned future usage or user intent
- exact region-specific pricing impact

---

## 12. Confidence Model

| Condition | Confidence |
|---|---|
| All emitted findings | `MEDIUM` |

No HIGH-confidence finding may be emitted because the rule lacks a native user-activity signal.

---

## 13. Risk Model

| Condition | Risk |
|---|---|
| Notebook instance is accelerator-backed (`g*`, `p*`, `inf*`, `trn*`) | `HIGH` |
| All other emitted findings | `MEDIUM` |

Risk is about likely waste severity, not proof of safe deletion.

---

## 14. Title and Reason Contract

| Condition | Title | Reason |
|---|---|---|
| Idle notebook finding | `"Idle SageMaker notebook review candidate"` | `"InService SageMaker notebook instance shows a stale control-plane timestamp state for at least {N} days"` |

---

## 15. Non-Goals

This rule does **not**:

- prove that no notebook user activity occurred
- parse Jupyter logs or infer kernel execution
- use presigned notebook URLs as a trusted activity signal
- estimate canonical monthly waste in USD
- cover SageMaker Studio / Studio Classic apps or spaces
