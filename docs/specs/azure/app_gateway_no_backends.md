# azure.application_gateway.no_backends — Canonical Rule Specification

## 1. Intent

Detect Azure Application Gateway **active routing paths** that ultimately select a backend pool with no explicit backend targets, so they can be surfaced as operational misconfiguration review candidates.

This is a read-only review-candidate rule. It is not a remediation action and not proof that the gateway, rule, or pool is safe to remove.

---

## 2. Azure API Grounding

This rule is grounded in the current Microsoft Learn Application Gateway resource schema and routing documentation:

- ARM/Bicep resource schema for `Microsoft.Network/applicationGateways`:
  - `properties.backendAddressPools`
  - `properties.requestRoutingRules`
  - `properties.routingRules`
  - `properties.urlPathMaps`
  - `properties.loadDistributionPolicies`
  - `properties.backendHttpSettingsCollection`
  - `properties.backendSettingsCollection`
- URL path routing documentation showing that a path-based routing rule binds a listener to a `urlPathMap`
- Backend health documentation showing that runtime backend health is a separate signal from configuration presence

Authoritative documentation:

- https://learn.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways
- https://learn.microsoft.com/en-us/azure/application-gateway/url-route-overview
- https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-backend-health-troubleshooting

### Canonical target sources

Per the latest documented schema, backend pools expose explicit configured targets via:

- `properties.backendAddressPools[].properties.backendAddresses`

Some read responses or older API shapes may also surface:

- `properties.backendAddressPools[].properties.backendIPConfigurations`

That legacy/read-only field is **not required by the latest public schema**, must **never** be required for detection, and must **never** be queried separately. It is only honored when present in the Application Gateway read payload, where it must be treated as an explicit target source to avoid false positives.

### Canonical routing surfaces

A backend pool is only in scope when it is reachable through an **active routing chain** rooted in one of:

- `properties.requestRoutingRules`
- `properties.routingRules`

Active chains may reference backend pools:

- directly through `backendAddressPool`
- indirectly through `urlPathMap`
- indirectly through `loadDistributionPolicy`

`urlPathMaps` and `loadDistributionPolicies` are **not active on their own**. They matter only when referenced by an active top-level routing rule.

---

## 3. Scope

Included:

- All Application Gateway resources returned by the management API in the scanned subscription / resource-group scope.
- Backend pools reached through an active `requestRoutingRule` or `routingRule`.
- Direct pool references and indirect references via active `urlPathMap` and active `loadDistributionPolicy`.
- Backend pools with zero explicit targets after normalization.

Excluded:

- Backend pools not reached from any active top-level routing rule.
- Unused `urlPathMaps`.
- Unused `loadDistributionPolicies`.
- Redirect-only routes that do not select a backend pool.
- Pools with at least one explicit backend target in `backendAddresses` or legacy `backendIPConfigurations`.
- Runtime-health-only issues (`Healthy`, `Unhealthy`, `Unknown`) with otherwise configured targets.

---

## 4. Canonical Definitions

| Term | Definition |
|---|---|
| `application_gateway_id` | Normalized from `resource.id` |
| `application_gateway_name` | `resource.name` or `null` |
| `region` | `resource.location` or `null` |
| `backend_pool_id` | Normalized from `properties.backendAddressPools[].id` |
| `backend_pool_name` | `properties.backendAddressPools[].name`; if absent, derive from the last non-empty segment of `backend_pool_id` after trimming leading/trailing `/`; if no non-empty segment exists, `null` |
| `backend_addresses` | Normalized list from `properties.backendAddressPools[].properties.backendAddresses`; null/missing → `[]` |
| `legacy_backend_ip_configurations` | Normalized list from optional `properties.backendAddressPools[].properties.backendIPConfigurations`; null/missing → `[]` |
| `backend_target_count` | `len(backend_addresses) + len(legacy_backend_ip_configurations)` |
| `referencing_route_ids` | Deduplicated deterministic list of active route references that reach the backend pool, sorted lexicographically on the final formatted route-id strings |
| `referenced_by_active_routes` | `len(referencing_route_ids) > 0` |

### Active route reference

An active route reference is a deterministic identifier representing one concrete active path from a top-level routing rule to a backend pool.

Canonical format:

`{top_level_rule_id}::{route_hop}::{backend_pool_id}`

Where:

- `top_level_rule_id` is the normalized deterministic id of the active `requestRoutingRule` or `routingRule`
- `route_hop` is one of:
  - `direct`
  - `loadDistributionPolicy:{policy_id}:target:{target_key}`
  - `urlPathMap:{url_path_map_id}:default`
  - `urlPathMap:{url_path_map_id}:defaultLoadDistributionPolicy:{policy_id}:target:{target_key}`
  - `urlPathMap:{url_path_map_id}:pathRule:{path_rule_key}`
  - `urlPathMap:{url_path_map_id}:pathRule:{path_rule_key}:loadDistributionPolicy:{policy_id}:target:{target_key}`
- `backend_pool_id` is the normalized backend pool id reached by that active path

All embedded ids in this format (`top_level_rule_id`, `policy_id`, `url_path_map_id`, `backend_pool_id`) must use normalized lowercase ARM ids.

Examples:

- direct rule → pool
- path-based rule → urlPathMap default pool
- path-based rule → urlPathMap path rule pool
- rule → loadDistributionPolicy target pool
- path-based rule → urlPathMap loadDistributionPolicy target pool

This format is mandatory. Implementations must not emit alternate route-id shapes.

---

## 5. Signal Model

### Normalization Contract

All rule logic must operate on normalized fields only.

Application Gateway normalization:

| Field | Derivation |
|---|---|
| `application_gateway_id` | `resource.id` → absent => skip gateway |
| `application_gateway_name` | `resource.name` → `null` |
| `region` | `resource.location` → `null` |
| `backend_pools` | `resource.properties.backendAddressPools` → `[]` if missing/null |
| `request_routing_rules` | `resource.properties.requestRoutingRules` → `[]` if missing/null |
| `routing_rules` | `resource.properties.routingRules` → `[]` if missing/null |
| `url_path_maps` | `resource.properties.urlPathMaps` → `[]` if missing/null |
| `load_distribution_policies` | `resource.properties.loadDistributionPolicies` → `[]` if missing/null |

Backend pool normalization:

| Field | Derivation |
|---|---|
| `backend_pool_id` | `pool.id` → absent => skip pool |
| `backend_pool_name` | `pool.name` → last id segment → `null` |
| `backend_addresses` | `pool.properties.backendAddresses` → `[]` if missing/null |
| `legacy_backend_ip_configurations` | `pool.properties.backendIPConfigurations` → `[]` if missing/null |
| `backend_target_count` | `len(backend_addresses) + len(legacy_backend_ip_configurations)` |

Important normalization rules:

- Normalize ARM ids and SubResource ids to lowercase for matching.
- Treat missing and null arrays equivalently as `[]`.
- Preserve original display names where present; id normalization is for matching only.
- Do not assume `backendIPConfigurations` is present in latest API shapes; treat it as optional backward-compatible input only.
- No direct raw ARM field access after normalization.
- The rule must behave identically regardless of API version used, provided the read payload normalizes to the same canonical fields.

### SubResource normalization contract

Any field documented as a SubResource reference must be normalized using the following rules:

| Raw shape | Normalized result |
|---|---|
| object with non-empty `id` string | normalized lowercase ARM id |
| plain non-empty string id | normalized lowercase ARM id |
| `null` | `null` |
| empty string | `null` |
| empty object `{}` | `null` |
| object without usable `id` | `null` and record malformed diagnostic for that object/path |

SubResource normalization applies to:

- `backendAddressPool`
- `urlPathMap`
- `loadDistributionPolicy`
- any other nested backend-pool SubResource used during traversal

### Deterministic key fallback contract

If a resource has no `id` but does have a name and enough parent context, construct a deterministic synthetic id:

- top-level `requestRoutingRule`: `{application_gateway_id}/requestRoutingRules/{rule.name}`
- top-level `routingRule`: `{application_gateway_id}/routingRules/{rule.name}`
- `urlPathMap`: `{application_gateway_id}/urlPathMaps/{url_path_map.name}`

If a name is also missing and no canonical ARM id is available, the object must not participate in active traversal; record a malformed diagnostic and skip that object.

Path rule key fallback:

- use `pathRule.name` when present
- else use `index-{zero_based_index}`

Load-distribution target key fallback:

- use `target.name` when present
- else use `index-{zero_based_index}`

### Backend pool name derivation contract

When `backend_pool_name` must be derived from `backend_pool_id`:

1. trim leading and trailing `/`
2. split on `/`
3. discard empty segments
4. use the last remaining segment
5. if no segment remains, set `backend_pool_name = null`

### A. EXCLUSION_RULES

| Condition | Result |
|---|---|
| `application_gateway_id` absent | **SKIP** gateway as malformed |
| `backend_pool_id` absent | **SKIP** pool as malformed |
| `referenced_by_active_routes == false` | **SKIP** |
| `backend_target_count > 0` | **SKIP** |

There must be no exclusion based on:

- probe presence or absence
- health state
- backend settings / HTTP settings naming
- pool naming conventions

### B. DETECTION_SIGNAL

| Condition | Result |
|---|---|
| `referenced_by_active_routes == true` AND `backend_target_count == 0` | **EMIT** |

### C. CONTEXTUAL_SIGNALS (non-detecting)

| Signal | Effect |
|---|---|
| `backend_addresses` | Evidence only |
| `legacy_backend_ip_configurations` | Evidence only |
| `referencing_route_ids` | Evidence only |

Runtime backend health is contextual only and must not be used as a detection predicate.

### Diagnostics contract

Whenever this spec says "record malformed diagnostic", "record unresolved-reference diagnostic", or otherwise requires diagnostics, the diagnostic entry must be appended to `signals_not_checked` using the following minimal structure:

| Field | Requirement |
|---|---|
| `kind` | One of `malformed_object`, `unresolved_reference`, `unsupported_inconsistent_rule_shape`, `missing_properties` |
| `scope` | One of `gateway`, `top_level_rule`, `url_path_map`, `path_rule`, `load_distribution_policy`, `load_distribution_target`, `backend_pool`, `traversal_edge` |
| `object_id` | Normalized ARM id when available, else `null` |
| `parent_id` | Normalized parent object id when available, else `null` |
| `reason` | Short stable machine-readable string, e.g. `missing_subresource_id`, `missing_name_and_id`, `referenced_pool_not_found`, `url_path_map_present_without_pathbased_ruletype` |

Additional implementation-specific fields may be added, but these minimum fields are required.

---

## 6. Evaluation Order (Mandatory)

1. List Application Gateway resources via ARM `Microsoft.Network/applicationGateways` for the target scope. If the list call fails for the scan scope, **FAIL RULE**.
2. For each returned gateway, normalize:
   - `backendAddressPools`
   - `requestRoutingRules`
   - `routingRules`
   - `urlPathMaps`
   - `loadDistributionPolicies`
3. Build lookup tables:
   - `backend_pool_id -> normalized pool`
   - `url_path_map_id -> normalized path map`
   - `load_distribution_policy_id -> normalized policy`
4. Normalize top-level active-rule identifiers:
   - `requestRoutingRule.id` → fallback to `{application_gateway_id}/requestRoutingRules/{rule.name}`
   - `routingRule.id` → fallback to `{application_gateway_id}/routingRules/{rule.name}`
   - If neither id nor usable name is available, skip that top-level rule and record malformed diagnostic.
5. Traverse **top-level active routes only**:
   - For each normalized `requestRoutingRule`
   - For each normalized `routingRule`
   - If the same normalized top-level rule id is present in both collections, deduplicate by id before traversal.
6. For each active top-level rule:
   - Determine path-based status as follows:
     - if `properties.ruleType == "PathBasedRouting"` after normalization, the rule is path-based
     - else if `properties.urlPathMap` is present with a usable normalized reference, treat the rule as path-based **and** record an `unsupported_inconsistent_rule_shape` diagnostic
     - else the rule is not path-based
   - Direct and indirect backend-selection paths are **independent additive traversal paths**, not mutually exclusive branches. If a single rule exposes multiple valid backend-selection paths, all of them must be evaluated independently.
   - If `properties.redirectConfiguration` is present and `backendAddressPool`, `urlPathMap`, and `loadDistributionPolicy` are all absent or null after normalization, treat the rule as **redirect-only** and skip it.
   - If it directly references `properties.backendAddressPool`, resolve the pool id and add an active route reference to that pool.
   - If it references `properties.loadDistributionPolicy`, resolve that policy and add active route references for each usable `loadDistributionTargets[].properties.backendAddressPool`.
   - If it is path-based and references `properties.urlPathMap`, resolve that path map and:
     - process `properties.defaultBackendAddressPool`
     - process `properties.defaultLoadDistributionPolicy`
     - process each `properties.pathRules[]` using deterministic `path_rule_key`:
       - `properties.backendAddressPool`
       - `properties.loadDistributionPolicy`
7. When resolving a path rule:
   - malformed `pathRules[]` entries must be skipped individually, not fail the containing path map
   - if a path rule has neither backend reference nor load-distribution-policy reference, it contributes no backend path
8. When resolving a load distribution policy:
   - walk `properties.loadDistributionTargets[]`
   - if `loadDistributionTargets` is missing, null, or empty, the policy contributes no backend paths
   - malformed `loadDistributionTargets[]` entries must be skipped individually, not fail the containing policy
   - for each target, resolve `properties.backendAddressPool`
   - if the target has no usable backend-pool reference, skip that target and record malformed diagnostic
   - if target name is absent, use deterministic positional fallback `index-{i}`
9. When resolving any backend-pool reference:
   - if the SubResource reference is null, contribute no backend path
   - if the referenced backend pool id cannot be found in `backend_pool_id -> normalized pool`, skip that traversal path and record unresolved-reference diagnostic
10. After active traversal is complete, evaluate each backend pool:
    - `referencing_route_ids`
    - `backend_target_count`
    - deduplicate duplicate route references on the final formatted route-id strings
    - sort `referencing_route_ids` lexicographically ascending
11. Apply `EXCLUSION_RULES`.
12. Emit findings for remaining pools.

### Critical routing constraints

- Do **not** treat a `urlPathMap` as active unless a top-level path-based routing rule references it.
- If a usable `urlPathMap` reference is present but `ruleType` is missing or not `PathBasedRouting`, traverse it as path-based and record an inconsistency diagnostic rather than silently skipping it.
- Do **not** treat a `loadDistributionPolicy` as active unless a top-level rule or active path-map branch references it.
- Do **not** emit on redirect-only rules with no backend selection path.
- Do **not** emit from unresolved backend-pool references; unresolved references are diagnostics, not findings.
- Do **not** silently drop malformed or unresolved traversal objects/edges; all such skips must produce diagnostics.

---

## 7. Confidence Model

| Condition | Confidence |
|---|---|
| `backend_target_count == 0` from normalized management-plane configuration and the pool is reached from an active route | `HIGH` |

Notes:

- This is a deterministic configuration rule.
- Do not weaken confidence because backend health is unknown.
- Do not strengthen or weaken confidence using runtime health APIs.

---

## 8. Risk Model

| Condition | Risk |
|---|---|
| Finding emitted | `MEDIUM` |

Risk rationale:

- The configuration can produce routing failures for live requests.
- Microsoft documentation around backend health troubleshooting is grounded in Application Gateway returning **502 Bad Gateway** when no usable backends are available.
- This is an operational-impact rule, not a direct security or cost rule.

---

## 9. Cost Model

No direct cost model applies.

- `estimated_monthly_cost_usd = null`
- Do not add cost heuristics

---

## 10. Failure Behavior

### Required API

- `Microsoft.Network/applicationGateways/read`

### Rule-level behavior

- If the scope-wide Application Gateway list fails → **FAIL RULE**
- If an individual gateway object is malformed → **SKIP** that gateway, continue
- If a particular nested object is malformed (`urlPathMap`, `loadDistributionPolicy`, `backendAddressPool`) → skip only that malformed object/path, continue
- If an individual `pathRules[]` entry is malformed → skip only that path rule, continue
- If an individual `loadDistributionTargets[]` entry is malformed → skip only that target, continue
- If a SubResource reference is unresolved (references a pool or policy not present in the gateway payload) → skip only that traversal edge, continue
- Every malformed-object skip and unresolved-reference skip must be recorded in diagnostics / `signals_not_checked`; silent ignore is not allowed.

This rule should be resilient to malformed nested configuration as long as the overall gateway list succeeded.

---

## 11. Blind Spots

Every finding must disclose in `signals_not_checked`:

1. Runtime backend health (`Healthy` / `Unhealthy` / `Unknown`) not checked for detection.
2. External DNS or application-level service discovery outside ARM-managed backend pool targets not checked.
3. Rewrite logic does not create new backend pool references; only configured route-to-pool links are evaluated.
4. If legacy/read-only `backendIPConfigurations` is absent from the API response, the rule relies on documented `backendAddresses` plus whatever active route structure is present.
5. Unresolved references inside malformed gateway configuration are not promoted to findings; they are only diagnostics.

---

## 12. Evidence Contract

Every finding must include all of the following (null allowed where noted, never omitted):

| Field | Requirement |
|---|---|
| `evaluation_path` | Exactly `"app-gateway-no-backends"` |
| `application_gateway_id` | Always present |
| `application_gateway_name` | Present or `null` |
| `region` | Present or `null` |
| `backend_pool_id` | Always present |
| `backend_pool_name` | Present or `null` |
| `backend_target_count` | Always present; must be `0` for emitted findings |
| `referencing_route_ids` | Always present; deduplicated on final formatted strings and sorted lexicographically |
| `backend_addresses` | Always present; list |
| `legacy_backend_ip_configurations` | Always present; list |

No probe or runtime-health evidence field is required for this rule.

`referencing_route_ids` must use the canonical format defined in Section 4 and must be stable across implementations for the same normalized gateway payload.

---

## 13. Title and Reason Contract

| Field | Value |
|---|---|
| `title` | `"Application Gateway active route points to empty backend pool"` |
| `reason` | `"An active Application Gateway routing path resolves to a backend pool with no explicit backend targets in management-plane configuration"` |

Hard rules:

- Do NOT say the gateway is safe to delete.
- Do NOT say the pool is unused unless no active route reaches it.
- Do NOT infer runtime outage from health APIs.
- Do NOT emit because a pool is merely unhealthy; emit only because an active route resolves to an explicitly empty pool.

---

## 14. API and RBAC Contract

**Required**

- `Microsoft.Network/applicationGateways/read`

**Best-effort**

- none

API usage constraints:

- Read full gateway resources including:
  - `properties.backendAddressPools`
  - `properties.requestRoutingRules`
  - `properties.routingRules`
  - `properties.urlPathMaps`
  - `properties.loadDistributionPolicies`
- Do not call backend-health APIs for detection.

---

## 15. Acceptance Scenarios

### Must emit

1. A `requestRoutingRule` directly references `poolA`, and `poolA` has `backendAddresses == []` and no legacy `backendIPConfigurations` → **EMIT**
2. A path-based `requestRoutingRule` references `urlPathMapA`; `urlPathMapA.pathRules[1]` references `poolB`; `poolB` has zero explicit targets → **EMIT**
3. A `routingRule` references `loadDistributionPolicyA`; one target in that policy points to `poolC`; `poolC` has zero explicit targets → **EMIT**
4. A path-based active route reaches `urlPathMapA.defaultLoadDistributionPolicy`, which resolves to `poolD`; `poolD` has zero explicit targets → **EMIT**

### Must skip

1. Backend pool not reached from any active `requestRoutingRule` or `routingRule` → **SKIP**
2. `urlPathMapA` exists and references an empty pool, but no active top-level rule references `urlPathMapA` → **SKIP**
3. `loadDistributionPolicyA` exists and points to an empty pool, but no active route references the policy → **SKIP**
4. Backend pool has at least one `backendAddress` entry → **SKIP**
5. Backend pool has no `backendAddresses`, but optional legacy `backendIPConfigurations` is non-empty → **SKIP**
6. Redirect-only route with no backend selection path → **SKIP**
7. `loadDistributionPolicyA` is referenced, but `loadDistributionTargets == []` → **SKIP**
8. A load-distribution target is malformed or missing `backendAddressPool` → skip that target only
9. A path rule is malformed or missing both backend references → skip that path rule only
10. A rule references `poolZ`, but `poolZ` is absent from `backendAddressPools` → skip that traversal path only

### Must fail

1. Failure enumerating Application Gateways for the target scope due to API or permission error → **FAIL RULE**

### Must NOT happen

1. Emitting on an unused `urlPathMap`
2. Emitting on an unused `loadDistributionPolicy`
3. Emitting based on runtime backend health alone
4. Emitting when the backend pool contains any explicit target
5. Emitting from an unresolved backend-pool reference

---

## 16. In-File Contract

```text
Rule: azure.application_gateway.no_backends

Intent:
    Detect active Application Gateway routing paths that resolve to backend pools
    with no explicit backend targets.

Exclusions:
    - application_gateway_id absent
    - backend_pool_id absent
    - pool not reached from active top-level routing rules
    - backend_target_count > 0

Detection:
    - referenced_by_active_routes == true
    - backend_target_count == 0

Key rules:
    - Traverse from active requestRoutingRules and routingRules only.
    - Deduplicate top-level active rules by normalized rule id.
    - urlPathMaps are not active by themselves.
    - loadDistributionPolicies are not active by themselves.
    - Redirect-only rules are skipped when they have redirectConfiguration and no backend selection path.
    - Use management-plane configuration only.
    - Runtime backend health is out of scope for emission.
    - Treat optional legacy backendIPConfigurations as explicit targets only when present in the gateway read payload.
    - Unresolved or malformed nested references produce diagnostics, not findings.

APIs:
    - Microsoft.Network/applicationGateways/read
```

---

## 17. Implementation Constants

| Constant | Value | Description |
|---|---|---|
| `_EVALUATION_PATH` | `"app-gateway-no-backends"` | `evaluation_path` used in findings |
