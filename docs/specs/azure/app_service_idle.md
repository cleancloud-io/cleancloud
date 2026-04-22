# Azure Rule Spec — `azure.app_service.idle`

## 1. Rule Identity

- **Rule ID:** `azure.app_service.idle`
- **Provider:** Azure
- **Resource type:** `Microsoft.Web/sites`
- **Finding resource_type:** `azure.app_service`

---

## 2. Intent

Detect **top-level Azure App Service apps on paid App Service plans** that have shown **no meaningful site activity** over the configured idle window, while excluding known false-positive surfaces documented by Microsoft.

This rule is deliberately **conservative**. It optimizes for **low noise / low false positives**, not maximum recall.

---

## 3. Azure Documentation Grounding

This rule is grounded in the following current Microsoft documentation:

1. **App Service plan billing and shared-plan behavior**
   - Azure bills App Service dedicated compute at the **plan** level, and multiple apps in the same plan share the same VM instances.
   - Source: *Azure App Service plans overview*.

2. **Deployment slots**
   - Deployment slots are **live apps with their own host names** and are commonly used for nonproduction staging and warm-up workflows.
   - Source: *Set up staging environments in Azure App Service*.

3. **WebJobs**
   - WebJobs run in the **same instance as a web app**.
   - Continuous and scheduled/triggered WebJobs can be active even when inbound HTTP request volume is zero.
   - Source: *Run background tasks with WebJobs in Azure App Service*.

4. **App Service metrics**
   - `Requests`, `CpuTime`, `BytesReceived`, and `BytesSent` are documented Azure Monitor metrics for `Microsoft.Web/sites`.
   - Source: *Supported metrics for Microsoft.Web/sites*.

5. **Site/config shape**
   - `Microsoft.Web/sites` list/get payloads expose fields such as `state`, `enabled`, `serverFarmId`, and `siteConfig.alwaysOn`.
   - Source: *App Service Web Apps REST API*.

---

## 4. Detection Goal

Emit only when all of the following are true:

1. the resource is a **top-level App Service app**, not a deployment slot
2. the app is **running**
3. the app is hosted on a **paid App Service plan**
4. the app is **not** a Function App or Workflow App
5. the app has **no WebJobs**
6. Azure Monitor shows all of the following over the idle window:
   - `Requests == 0`
   - `CpuTime == 0`
   - `BytesReceived == 0`
   - `BytesSent == 0`

If any required signal is unavailable or ambiguous, the rule must **skip** rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that deleting the app would immediately save money
- that the parent App Service plan is removable
- that the app is permanently abandoned
- that background work implemented outside documented App Service / Azure Monitor surfaces does not exist

---

## 6. Canonical Inputs

### 6.1 Required control-plane surfaces

The implementation may use:

- `web_apps.list()`
- `app_service_plans.list()`
- `web_apps.list_web_jobs(...)`
- Azure Monitor metrics for the app resource id

It may also use additional per-site reads when needed, but it must remain conservative on any lookup failure.

### 6.2 Idle window

- Configurable parameter: `idle_days`
- Default: `14`
- Evaluation window:
  - `window_end = now`
  - `window_start = now - idle_days`

---

## 7. Normalization Contract

For each site:

- normalize `resource_id` to the exact ARM id string from Azure
- normalize `location` to lowercase with spaces removed for comparison and output consistency
- normalize `server_farm_id` to lowercase when used as a lookup key
- normalize `kind` to lowercase string tokens

For each App Service plan:

- normalize `plan_id` to lowercase lookup key
- capture:
  - `sku_tier`
  - `sku_name`
  - `capacity` when present

---

## 8. Mandatory Exclusions

The rule must **skip** the app when any of the following are true:

1. `resource_id` is missing
2. region filter is set and the app is outside the filter
3. site state is not exactly `Running`
4. `enabled == false`
5. the resource is a **deployment slot**
   - e.g. ARM id contains `/slots/`
   - or slot-shaped fields such as `slotName` or `parentSiteName` are present
   - or equivalent slot-shaped payload
6. `kind` indicates a **Function App**
   - e.g. contains `functionapp`
7. `kind` indicates a **Workflow App / Logic App Standard**
   - e.g. contains `workflowapp`
8. the plan tier is:
   - `Free`
   - `Shared`
   - `Dynamic`
   - or unusable / unknown
9. WebJobs inventory cannot be determined for the app
10. one or more WebJobs exist for the app
11. one or more required metrics cannot be determined reliably
12. any required activity metric is non-zero over the idle window

These exclusions are mandatory because they directly reduce known false positives.

---

## 9. Activity Test

The following metrics must be queried for the same window using Azure Monitor:

- `Requests`
- `CpuTime`
- `BytesReceived`
- `BytesSent`

Use:

- aggregation: `Total`
- a stable interval suitable for the full window (for example daily buckets)

### 9.1 Interpretation

For each required metric:

- if any datapoint total is `> 0`, treat the app as **active**
- if all datapoint totals are `0` or absent/`None`, the metric is **zero for the window**
- if the metric query fails or the response shape is unusable, treat the app as **unknown** and **skip**

### 9.2 Emission threshold

Emit only when **all four** required metrics are zero for the full window.

This stronger threshold is required because `Requests == 0` alone is not sufficient to prove inactivity for App Service workloads.

---

## 10. WebJobs Handling

Before emission, enumerate WebJobs for the site.

- If the WebJobs list call fails -> **skip**
- If the WebJobs response is partial, incomplete, truncated, or otherwise not usable as a reliable full inventory -> **skip**
- If one or more WebJobs are returned -> **skip**
- If zero WebJobs are returned -> continue

This is required because Microsoft documents that WebJobs run in the same app instance and may be active without inbound HTTP traffic.

---

## 11. Cost Model

`estimated_monthly_cost_usd` must be **`None`**.

Reason:

- Azure bills dedicated App Service compute at the **plan** level, not the app level.
- An idle app in a shared plan does not by itself prove direct monthly savings.

If useful, the implementation may include **plan-scoped cost context** in evidence/details as informational context only, not as a direct savings claim.

---

## 12. Finding Shape

### 12.1 Required finding fields

- `provider = "azure"`
- `rule_id = "azure.app_service.idle"`
- `resource_type = "azure.app_service"`
- `resource_id = <site arm id>`
- `region = <normalized region>`
- `risk = MEDIUM`
- `confidence = HIGH`
- `estimated_monthly_cost_usd = None`

### 12.2 Required evidence

`signals_used` must clearly disclose:

1. app state is `Running`
2. app kind
3. App Service plan tier
4. zero WebJobs detected
5. zero `Requests` over the idle window
6. zero `CpuTime` over the idle window
7. zero `BytesReceived` over the idle window
8. zero `BytesSent` over the idle window
9. if available, that App Service billing is plan-scoped and the plan cost context is informational only

`signals_not_checked` should disclose remaining blind spots, for example:

- planned seasonal/reactivation intent
- undeclared business intent
- workload activity outside documented rule signals

### 12.3 Required details

Details should include at least:

- `app_name`
- `kind`
- `sku_tier`
- `location`
- `idle_days_threshold`
- `server_farm_id` when available
- `app_service_plan_site_count` when available
- `plan_monthly_cost_floor_usd` when available
- `tags` when present

---

## 13. Acceptance Examples

### 13.1 Must emit

1. A top-level `Microsoft.Web/sites` app on Standard tier is `Running`, has zero WebJobs, and Azure Monitor reports zero `Requests`, `CpuTime`, `BytesReceived`, and `BytesSent` for 14 days -> **EMIT**

### 13.2 Must skip

1. A deployment slot with zero traffic -> **SKIP**
2. A Function App on a paid App Service plan with zero HTTP requests -> **SKIP**
3. A Workflow App / Logic App Standard site with zero HTTP requests -> **SKIP**
4. A web app with one continuous or triggered WebJob -> **SKIP**
5. A web app with zero requests but non-zero `CpuTime` -> **SKIP**
6. A web app with zero requests but non-zero `BytesSent` or `BytesReceived` -> **SKIP**
7. A web app where any required metric lookup fails -> **SKIP**
8. A web app where WebJobs enumeration fails -> **SKIP**
9. A Free, Shared, or Dynamic tier app -> **SKIP**

---

## 14. Anti-Goals / What Must Not Happen

Implementations must **not**:

1. emit based on `Requests == 0` alone
2. emit on deployment slots
3. emit on Function Apps or Workflow Apps
4. emit when WebJobs exist
5. claim direct monthly savings at the app level through `estimated_monthly_cost_usd`
6. silently turn metrics/API uncertainty into a finding
