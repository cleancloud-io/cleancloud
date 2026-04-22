# Azure Rule Spec — `azure.app_service_plan.empty`

## 1. Rule Identity

- **Rule ID:** `azure.app_service_plan.empty`
- **Provider:** Azure
- **ARM resource type:** `Microsoft.Web/serverfarms`
- **Finding resource_type:** `azure.app_service_plan`

---

## 2. Intent

Detect **paid Azure App Service Plans that have zero hosted apps** and are therefore candidates for plan-level spend review because App Service plans can continue to incur charges depending on tier and configured capacity.

This rule is deliberately **conservative**. It optimizes for **low noise and low false positives**. A plan with zero apps is not necessarily permanently abandoned, but it is a candidate for human review because Microsoft explicitly documents that such plans continue to incur charges.

---

## 3. Azure Documentation Grounding

### 3.1 Plan-level billing and empty-plan charges

> "App Service plans that have no apps associated with them still incur charges because they continue to reserve the configured VM instances."

Source: *Manage an App Service Plan*
URL: https://learn.microsoft.com/en-us/azure/app-service/app-service-plan-manage

> "When you delete all apps in an App Service plan, the plan continues to accrue charges based on its configured pricing tier and number of instances."

Source: *Plan and Manage Costs for App Service*
URL: https://learn.microsoft.com/en-us/azure/app-service/overview-manage-costs

### 3.2 Pricing tier categories and billing model

Microsoft's current App Service plan overview documents the following billing-relevant tier categories for App Service plans:

| Category | Tiers | Billing model relevant to this rule |
|---|---|---|
| Shared compute | Free, Shared | Shared-resource entry tiers; not the paid dedicated-compute empty-plan target of this rule |
| Dedicated compute | Basic, Standard, Premium, PremiumV2, PremiumV3, PremiumV4 | Charged per VM instance in the plan regardless of hosted app count |
| Isolated | IsolatedV2 | Charged per isolated worker |

Source: *Azure App Service Plans overview*
URL: https://learn.microsoft.com/en-us/azure/app-service/overview-hosting-plans

### 3.3 `numberOfSites` property

The App Service Plans REST API documents `properties.numberOfSites` as the **number of apps assigned to the App Service plan**. This spec uses `numberOfSites` only as a **pre-filter** and requires a secondary `list_web_apps()` confirmation call before emission.

This conservative two-phase contract is intentional: authoritative emptiness is established only by the secondary per-plan app listing, not by `numberOfSites` alone.

`numberOfSites == 0` is a useful empty-plan candidate signal. `numberOfSites == None` is weaker: it is treated only as **not proven non-empty**, not as positive evidence of emptiness. In both cases, the secondary `list_web_apps()` call is mandatory before emission.

Source: *App Service Plans REST API reference*
URL: https://learn.microsoft.com/en-us/rest/api/appservice/app-service-plans/list

### 3.4 `provisioningState` values

| Value | Meaning |
|---|---|
| `Succeeded` | Plan is fully operational |
| `Failed` | Provisioning failed |
| `Canceled` | Provisioning was canceled |
| `InProgress` | Provisioning is in progress |
| `Deleting` | Deletion is in progress |

Source: *App Service Plans REST API reference*
URL: https://learn.microsoft.com/en-us/rest/api/appservice/app-service-plans/list

### 3.5 Secondary confirmation API

```
GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/serverfarms/{name}/sites
```

Returns a paginated `WebAppCollection`. Full iteration is required before treating a plan as empty.

Source: *App Service Plans — List Web Apps REST API*
URL: https://learn.microsoft.com/en-us/rest/api/appservice/app-service-plans/list-web-apps

Required permission: `Microsoft.Web/serverfarms/sites/read`

---

## 4. Detection Goal

Emit a finding when **all** of the following are true:

1. `plan.id` is present and non-empty
2. `plan.provisioning_state` is exactly `"Succeeded"`
3. `plan.sku` is not None
4. `plan.sku.tier` (normalized to lowercase) is in the known paid tier allowlist
5. `plan.number_of_sites` is `0` or `None` (pre-filter only; `None` is weaker and is not evidence of emptiness by itself)
6. Resource group is extractable from `plan.id`
7. `list_web_apps()` completes fully without exception and returns zero apps

If any condition cannot be confirmed, skip rather than emit.

---

## 5. Non-Goals

This rule does **not** attempt to prove:

- that the plan is permanently abandoned
- that the plan is safe to delete without review
- that no app deployment is imminent
- that associated infrastructure (VNet, ASE, certificates) is also unused

---

## 6. Canonical Inputs

| API | SDK method | Required permission |
|---|---|---|
| Plan list | `web_client.app_service_plans.list()` | `Microsoft.Web/serverfarms/read` |
| Per-plan app list | `web_client.app_service_plans.list_web_apps(rg, name)` | `Microsoft.Web/serverfarms/sites/read` |

---

## 7. Normalization Contract

| Field | Normalization |
|---|---|
| `location` | Lowercase, spaces removed (`"West Europe"` -> `"westeurope"`) |
| `sku_tier` for lookup | Lowercased before allowlist and cost table lookup |
| `sku_tier` for output | Original casing from API |
| `plan.id` | Original string for `resource_id`; case-insensitive segment match for resource group extraction |
| `tags` | `plan.tags or {}` — never `None` in output |

Resource group extraction from ARM id: split on `/`, find the segment whose **lowercase** value equals `"resourcegroups"`, take the next segment. Case-insensitive match required because ARM id casing is not guaranteed.

---

## 8. Mandatory Exclusions

| # | Condition | Action |
|---|---|---|
| 8.1 | `plan.id` is absent, `None`, or empty | Skip |
| 8.2 | Region filter set and location does not match | Skip |
| 8.3 | `plan.provisioning_state` is not exactly `"Succeeded"` | Skip (includes `None`) |
| 8.4 | `plan.sku` is `None` | Skip |
| 8.5 | `plan.sku.tier` is `None`, empty, or not in the known paid tier allowlist | Skip |
| 8.6 | `plan.number_of_sites` is not `0` and not `None` | Skip (pre-filter; no secondary call) |
| 8.7 | Resource group not extractable from `plan.id` | Skip |
| 8.8 | `list_web_apps()` raises any exception | Skip (conservative) |
| 8.9 | `list_web_apps()` returns one or more apps | Skip |

---

## 9. Tier Allowlist

Matched case-insensitively against `plan.sku.tier`:

| Lowercase key | Tier |
|---|---|
| `basic` | Basic |
| `standard` | Standard |
| `premium` | Premium |
| `premiumv2` | PremiumV2 |
| `premiumv3` | PremiumV3 |
| `premiumv4` | PremiumV4 |
| `isolated` | Isolated (legacy compatibility input if surfaced by API/read payloads) |
| `isolatedv2` | IsolatedV2 |

Any other string — including `free`, `shared`, `dynamic`, `elasticpremium`, `workflowstandard`, `flexconsumption`, or any unrecognized value — must be excluded.

---

## 10. Emptiness Test (Two-Phase)

**Phase 1 (pre-filter, fast):**

- If `number_of_sites > 0` and not `None` -> skip immediately
- If `number_of_sites == 0` -> candidate empty plan, continue to phase 2
- If `number_of_sites == None` -> unknown cached count, continue to phase 2 only because authoritative emptiness is decided by `list_web_apps()`

**Phase 2 (confirmation, authoritative):** Call `list_web_apps()` and fully iterate all pages. Any exception during iteration must skip the plan. Only an exception-free, zero-result iteration allows emission.

---

## 11. Cost Model

```
estimated_monthly_cost_usd = TIER_BASE_COST_USD[tier.lower()] * capacity
```

Set to `None` when `capacity` is `None`, `capacity == 0`, or tier not in cost table.

`capacity == 0` does **not** exclude emission by itself. The rule still emits when the plan is confirmed empty, but `estimated_monthly_cost_usd` remains `None` because the rule does not assert a positive current worker-cost floor from a zero-capacity value alone.

Approximate single-instance monthly costs (illustrative plan-level floor values used by this rule):

| Tier | Approx. monthly (single instance) |
|---|---|
| Basic | $55.00 |
| Standard | $73.00 |
| Premium | $146.00 |
| PremiumV2 | $146.00 |
| PremiumV3 | $146.00 |
| PremiumV4 | $146.00 |
| Isolated | $298.00 |
| IsolatedV2 | $298.00 |

Note: Isolated/IsolatedV2 cost shown by this rule does not include any App Service Environment stamp fee or other separately billed environment-level charges.

---

## 12. Finding Shape

### 12.1 Required fields

| Field | Value |
|---|---|
| `provider` | `"azure"` |
| `rule_id` | `"azure.app_service_plan.empty"` |
| `resource_type` | `"azure.app_service_plan"` |
| `resource_id` | Original ARM id from `plan.id` |
| `region` | Normalized location |
| `risk` | `LOW` |
| `confidence` | `HIGH` |
| `estimated_monthly_cost_usd` | `TIER_BASE_COST * capacity` or `None` |

### 12.2 Required evidence

`signals_used` must include:

1. If `number_of_sites == 0`: `"number_of_sites reported as 0 on plan list response"`
2. If `number_of_sites == None`: `"number_of_sites was None on plan list response; emptiness confirmed only via list_web_apps()"`
3. `"Confirmed via list_web_apps(): 0 apps found on plan"`
4. `"SKU tier is {sku_tier} (paid dedicated tier — in known paid tier allowlist)"`
5. If `capacity` is known and `> 0`: `"Plan has {capacity} provisioned instance(s) reserved and typically billed at the {sku_tier} tier rate"`

`signals_not_checked` must include:

1. `"Planned app deployment — plan may be created before apps in an IaC pipeline"`
2. `"IaC-managed intent — plan may be managed by Terraform, Bicep, or ARM templates"`
3. `"Reserved capacity for upcoming scaling or blue/green deployment staging"`
4. `"App Service Environment stamp fee (for Isolated/IsolatedV2) not included in estimated cost"`

### 12.3 Required details

| Key | Nullable |
|---|---|
| `resource_name` | No |
| `subscription_id` | No |
| `sku_name` | Yes |
| `sku_tier` | No |
| `capacity` | Yes |
| `confirmed_web_apps` | No (always `0` at emission) |
| `tags` | No (normalize `None` to `{}`) |

---

## 13. Failure Behavior

- If `app_service_plans.list()` raises: let the exception propagate (do not silently return empty findings).
- If `list_web_apps()` raises for a specific plan: skip that plan, continue to next.

---

## 14. Acceptance Examples

### 14.1 Must emit

1. `provisioningState == "Succeeded"`, `sku.tier == "Standard"`, `capacity == 1`, `numberOfSites == 0`, `list_web_apps()` empty → **EMIT**, `estimated_monthly_cost_usd == 73.0`
2. `sku.tier == "Standard"`, `capacity == 2`, `list_web_apps()` empty → **EMIT**, `estimated_monthly_cost_usd == 146.0`
3. `sku.tier == "PremiumV3"`, `numberOfSites == None`, `list_web_apps()` empty → **EMIT**
4. `sku.tier == "Isolated"`, `list_web_apps()` empty → **EMIT**, `estimated_monthly_cost_usd == 298.0`
5. Location `"West Europe"` with `region_filter == "westeurope"` → **EMIT** with `region == "westeurope"`
6. `sku.tier == "PremiumV4"` (new tier), `list_web_apps()` empty → **EMIT**
7. `sku.tier == "Standard"`, `capacity == 0`, `list_web_apps()` empty → **EMIT**, `estimated_monthly_cost_usd == None`

### 14.2 Must skip

1. `sku.tier == "Free"` → **SKIP**
2. `sku.tier == "Shared"` → **SKIP**
3. `sku.tier == "Dynamic"` → **SKIP**
4. `sku.tier == "ElasticPremium"` → **SKIP**
5. `sku.tier == "WorkflowStandard"` → **SKIP**
6. `sku.tier == "FlexConsumption"` → **SKIP**
7. Any unrecognized tier string → **SKIP**
8. `sku == None` → **SKIP**
9. `sku.tier == None` → **SKIP**
10. `provisioningState == "Creating"` → **SKIP**
11. `provisioningState == "Failed"` → **SKIP**
12. `provisioningState == "Deleting"` → **SKIP**
13. `provisioningState == None` → **SKIP**
14. `numberOfSites == 3` → **SKIP** (pre-filter)
15. `numberOfSites == 0` but `list_web_apps()` returns apps → **SKIP**
16. `numberOfSites == 0` but `list_web_apps()` raises → **SKIP**
17. `plan.id == None` → **SKIP**
18. Resource group not extractable from `plan.id` → **SKIP**
19. Plan in different region than filter → **SKIP**

---

## 15. Anti-Goals

Implementations must **not**:

1. Use `numberOfSites == 0` alone as the final signal without secondary confirmation
2. Use a denylist of tiers (the allowlist contract in Section 9 is mandatory)
3. Emit for `sku == None` or `sku.tier == None`
4. Extract resource group using a case-sensitive `"resourceGroups"` match
5. Return `tags = None` in finding details
6. Silently return empty findings when the main plan list call raises
7. Emit for `ElasticPremium`, `WorkflowStandard`, `FlexConsumption`, or any unrecognized tier
8. Treat a mid-iteration `list_web_apps()` exception as confirmation of emptiness
9. Include the ASE stamp fee in `estimated_monthly_cost_usd`
