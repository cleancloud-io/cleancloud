# Azure Rules

17 rules (12 hygiene + 5 AI/ML). AI/ML rules require `--category ai`.

← [Back to index](../rules.md)

| Rule ID | Cost Surface | What It Detects |
|---|---|---|
| `azure.vm.stopped_not_deallocated` | Compute | Stopped but not deallocated VMs (full charges) |
| `azure.compute.disk.unattached` | Storage | Managed disks in `Unattached` state with no attachment surfaces and unattached age >= 7 days |
| `azure.compute.snapshot.old` | Storage | Old managed snapshots as conservative review candidates |
| `azure.network.public_ip.unused` | Network | Public IPs unattached across all four control-plane linkage surfaces |
| `azure.load_balancer.no_backends` | Network | Standard LBs with billable rules but no backend members |
| `azure.application_gateway.no_backends` | Network | App Gateways with zero backend targets |
| `azure.virtual_network_gateway.idle` | Network | VPN/ExpressRoute Gateways with no connections |
| `azure.app_service_plan.empty` | Platform | Paid App Service Plans with zero apps |
| `azure.app_service.idle` | Platform | App Services with zero HTTP requests 14+ days |
| `azure.sql.database.idle` | Platform | Dedicated single databases with zero activity across all five required metrics over idle window |
| `azure.container_registry.unused` | Platform | Container registries with zero pulls and pushes 90+ days |
| `azure.resource.untagged` | Governance | Disks and snapshots with zero tags |
| `azure.aml.compute.idle` | AI/ML | AML compute clusters with `min_node_count > 0`, confirmed current node allocation, and zero per-cluster `Active Nodes` activity 14+ days |
| `azure.ml.compute_instance.idle` | AI/ML | Azure ML Compute Instances in `Running` state with no documented control-plane lifecycle activity for `idle_days` (default 14); uses `lastOperation.operationTime` or `modifiedOn` fallback only — no age-only or undocumented fallbacks |
| `azure.ml.online_endpoint.idle` | AI/ML | Azure ML managed online endpoints with zero scoring requests 7+ days |
| `azure.ai_search.idle` | AI/ML | Azure AI Search services (Basic+) structurally empty with zero query, indexing, and skill activity 90+ days |
| `azure.openai.provisioned_deployment.idle` | AI/ML | Azure OpenAI provisioned deployments (PTUs) with zero requests 7+ days |

---

## Compute

#### `azure.vm.stopped_not_deallocated`
**Detects:** VMs whose runtime power state resolves to exactly `PowerState/stopped` from per-VM `instance_view` statuses, with `provisioning_state == "Succeeded"` confirmed from the control-plane model payload

**Confidence / Risk:** HIGH (deterministic power state from instance_view) / HIGH

**Permissions:** `Microsoft.Compute/virtualMachines/read`, `Microsoft.Compute/virtualMachines/instanceView/action`

**Params:** none

**Exclusions:** `id` or `name` absent/empty; `provisioning_state != "Succeeded"` (SDK+nested, conflict -> skip); per-VM `instance_view` retrieval fails (skip that VM); no `PowerState/` code in statuses; multiple conflicting `PowerState/` codes; any power state other than exact `PowerState/stopped`

**Spec:** [specs/azure/vm_stopped_not_deallocated.md](../specs/azure/vm_stopped_not_deallocated.md)

---

## Storage

#### `azure.compute.disk.unattached`
**Detects:** Managed disks in `Unattached` disk state with no attachment surfaces confirmed absent and unattached age >= 7 days (age anchored to `lastOwnershipUpdateTime` when available, `timeCreated` as fallback)

**Confidence / Risk:** MEDIUM (deterministic state; attachment intent unknown) / LOW

**Permissions:** `Microsoft.Compute/disks/read`

**Params:** none

**Exclusions:** `provisioning_state != "Succeeded"`; `disk_state != "Unattached"`; `managed_by` or `managed_by_extended` present or unresolvable; `max_shares > 1` or unresolvable (shared-disk capable); `optimized_for_frequent_attach == True` or unresolvable; unattached age < 7 days or age anchor unresolvable; conflicting control-plane signals across SDK and raw surfaces

**Spec:** [specs/azure/unattached_managed_disks.md](../specs/azure/unattached_managed_disks.md)

#### `azure.compute.snapshot.old`
**Detects:** Managed snapshots older than 30 days as conservative review candidates; confidence escalates with age relative to `max_age_days`

**Confidence / Risk:** LOW (age ≥ 30 days and < `max_age_days`); MEDIUM (age ≥ `max_age_days`) / LOW

**Permissions:** `Microsoft.Compute/snapshots/read`

**Params:** `max_age_days` (default: 90)

**Exclusions:** `provisioning_state != "Succeeded"`, incomplete snapshots (`completion_percent < 100`), snapshots younger than 30 days

**Spec:** [specs/azure/disk_snapshot_old.md](../specs/azure/disk_snapshot_old.md)

---

## Network

#### `azure.network.public_ip.unused`
**Detects:** Public IP addresses fully unattached across all four known Azure control-plane linkage surfaces: `ip_configuration`, `nat_gateway`, `service_public_ip_address`, `linked_public_ip_address`

**Confidence / Risk:** HIGH (all four linkages cleanly absent — deterministic) / LOW

**Permissions:** `Microsoft.Network/publicIPAddresses/read`

**Params:** none

**Exclusions:** `provisioning_state != "Succeeded"`; any linkage present with a non-empty `id`; linkage object present but `id` unresolvable (malformed reference — skipped conservatively); unattached Dynamic Public IP with no assigned `ip_address` (low-signal placeholder)

**Spec:** [azure/public_ip_unused.md](../specs/azure/public_ip_unused.md)

#### `azure.load_balancer.no_backends`
**Detects:** Standard SKU Load Balancers with load-balancing or outbound rules whose referenced backend pools all have zero members

**Confidence / Risk:** HIGH (all relevant pools resolved and empty — deterministic) / LOW

**Permissions:** `Microsoft.Network/loadBalancers/read`

**Params:** none

**Exclusions:** Basic and Gateway SKU; LBs with no load-balancing rules and no outbound rules (no billable signal); any LB where a referenced pool cannot be resolved

**Spec:** [specs/azure/lb_no_backends.md](../specs/azure/lb_no_backends.md)

#### `azure.application_gateway.no_backends`
**Detects:** Application Gateways where all backend pools have zero targets

**Confidence / Risk:** HIGH (deterministic control-plane state) / MEDIUM

**Permissions:** `Microsoft.Network/applicationGateways/read`

**Params:** none

**Exclusions:** gateways with `provisioning_state != "Succeeded"`

**Spec:** [specs/azure/app_gateway_no_backends.md](../specs/azure/app_gateway_no_backends.md)

#### `azure.virtual_network_gateway.idle`
**Detects:** VPN or ExpressRoute Gateways with no configured in-scope connection resources (IPsec, Vnet2Vnet, ExpressRoute) and zero applicable gateway metrics over a 30-day window

**Confidence / Risk:** HIGH (all connection, P2S, bypass, and metric signals resolved deterministically) / HIGH

**Permissions:** `Microsoft.Resources/resources/read`, `Microsoft.Network/virtualNetworkGateways/read`, `Microsoft.Insights/metrics/read`

**Params:** none (30-day fixed idle window)

**Exclusions:** `id` or `name` absent/empty; malformed ARM id (resource group unextractable); `provisioning_state != "Succeeded"` (SDK+nested, conflict -> skip); `gateway_type` not `"Vpn"` or `"ExpressRoute"` (conflict -> skip); `allowVirtualWanTraffic == True`; ExpressRoute: `adminState == "Disabled"` or any connection with `expressRouteGatewayBypass == True` or unresolvable; VPN: any P2S field group (`vpnClientConfiguration`, address pool, root certs, AAD/Entra tenant, etc.) non-empty or unresolvable; any configured in-scope connection resource present; any connection type unresolvable or conflicting; `list_connections()` fails; ExpressRoute SKU tier absent (metric family unresolvable); any applicable metric unknown, below 80% daily-bucket coverage, or non-zero; per-gateway SDK retrieval errors (HttpResponseError, ServiceRequestError, ServiceResponseError)

**Spec:** [specs/azure/vnet_gateway_idle.md](../specs/azure/vnet_gateway_idle.md)

---

## Platform

#### `azure.app_service_plan.empty`
**Detects:** Paid-tier App Service Plans with zero hosted apps (`number_of_sites == 0`)

**Confidence / Risk:** HIGH (deterministic) / LOW

**Permissions:** `Microsoft.Web/serverfarms/read`, `Microsoft.Web/serverfarms/sites/read`

**Params:** none

**Exclusions:** Free and Shared tier plans

**Spec:** [specs/azure/app_service_plan_empty.md](../specs/azure/app_service_plan_empty.md)

#### `azure.app_service.idle`
**Detects:** App Services on paid plans with zero HTTP `Requests` metric for `days_idle`

**Confidence / Risk:** HIGH (zero HTTP traffic confirmed) / MEDIUM

**Permissions:** `Microsoft.Web/sites/read`, `Microsoft.Web/serverfarms/read`, `Microsoft.Insights/metrics/read`

**Params:** `days_idle` (default: 14)

**Exclusions:** Free, Shared, Dynamic (Consumption/serverless) tiers; non-HTTP workloads (WebJobs, background services) may produce false positives

**Spec:** [specs/azure/app_service_idle.md](../specs/azure/app_service_idle.md)

#### `azure.sql.database.idle`
**Detects:** Dedicated single databases with zero activity across all five required Azure Monitor metrics (`connection_successful`, `sessions_count`, `cpu_percent`, `physical_data_read_percent`, `log_write_percent`) over the idle window; single-metric silence is not sufficient

**Confidence / Risk:** HIGH (all five metrics confirmed zero for full window) / HIGH

**Permissions:** `Microsoft.Sql/servers/read`, `Microsoft.Sql/servers/databases/read`, `Microsoft.Insights/metrics/read`

**Params:** `idle_days` (default: 14)

**Exclusions:** `master` system database; elastic pool databases (billing is at pool level); replica / secondary-shaped databases (`secondary_type` non-empty); currently paused serverless databases (`status == "Paused"` or `paused_date > resumed_date`); databases younger than `idle_days`; any required metric absent, series empty, or query failing (conservative skip)

**Spec:** [azure/sql_database_idle.md](../specs/azure/sql_database_idle.md)

#### `azure.container_registry.unused`
**Detects:** Container registries with zero successful pulls AND zero successful pushes for `days_unused`; registries with sparse or missing metrics are skipped

**Confidence / Risk:** HIGH (both `SuccessfulPullCount` and `SuccessfulPushCount` metrics confirmed zero) / LOW

**Permissions:** `Microsoft.ContainerRegistry/registries/read`, `Microsoft.Insights/metrics/read`

**Params:** `days_unused` (default: 90)

**Exclusions:** `provisioning_state != "Succeeded"`; registries younger than observation window

**Spec:** [specs/azure/container_registry_unused.md](../specs/azure/container_registry_unused.md)

---

## Governance

#### `azure.resource.untagged`
**Detects:** Managed disks and snapshots with zero direct resource tags and resource age >= 7 days

**Confidence / Risk:** MEDIUM (untagged disk whose attachment context resolves conservatively as ordinarily unattached); LOW (untagged snapshot or disk with attached/unresolved attachment context) / LOW

**Permissions:** `Microsoft.Compute/disks/read`, `Microsoft.Compute/snapshots/read`

**Params:** none

**Exclusions:** `provisioning_state != "Succeeded"`; direct tag state unresolvable (field missing or non-mapping non-None value); resource has at least one direct tag; resource age < 7 days or `time_created` unresolvable, invalid, or in the future; conflicting SDK vs nested provisioning-state or time-created signals

**Spec:** [specs/azure/untagged_resources.md](../specs/azure/untagged_resources.md)

---

## AI/ML *(opt-in: `--category ai`)*

#### `azure.aml.compute.idle`
**Detects:** AML compute clusters (`computeType == "AmlCompute"`) with `min_node_count > 0` retaining confirmed baseline node allocation and no observed per-cluster `Active Nodes` activity for 14 days; requires BOTH confirmed positive baseline capacity AND confirmed zero per-cluster activity metric before emitting

**Confidence / Risk:** HIGH (always, when all required signals resolve) / MEDIUM (always)

**Permissions:** `Microsoft.MachineLearningServices/workspaces/read`, `Microsoft.MachineLearningServices/workspaces/computes/read`, `Microsoft.Insights/metrics/read`

**Params:** none (14-day window is fixed)

**Exclusions:** `id` or `name` absent/empty; workspace `name` absent/empty; outside optional region filter (exact lowercase match on **compute** resource location; spaces and hyphens preserved); `compute_type` does not resolve to exactly `"AmlCompute"` (SDK+nested, conflict → skip); `provisioning_state` does not resolve to exactly `"Succeeded"` (SDK+nested, conflict → skip); `allocation_state` does not resolve to exactly `"Steady"` (SDK+nested, conflict → skip); `created_at` absent, invalid, in the future, or cluster age < 14 days (no age-only fallback); `min_node_count <= 0` or unresolvable; `current_node_count` negative, unresolvable, or < `min_node_count`; `Active Nodes` metric with `ClusterName` dimension filter cannot be resolved reliably (< 95% daily-bucket coverage, unusable response shape, no per-cluster series); `Active Nodes` metric is non-zero over the 14-day window; per-compute retrieval error (skip that compute); per-workspace compute listing error (skip that workspace)

**Spec:** [specs/azure/ai/aml_compute_idle.md](../specs/azure/ai/aml_compute_idle.md)

#### `azure.ml.compute_instance.idle`
**Detects:** Azure ML Compute Instances (`computeType == "ComputeInstance"`) in `Running` state with `provisioning_state == "Succeeded"` and no documented control-plane lifecycle activity for `idle_days`; precision-first review-candidate rule — does not claim to observe notebook/kernel/session inactivity

**Confidence / Risk:** MEDIUM (`lastOperation.operationTime` is the idle signal source); LOW (`modifiedOn` fallback is the idle signal source) / HIGH (GPU: exact case-sensitive prefix match on `Standard_NC`, `Standard_ND`, `Standard_NV`); MEDIUM (all other VM families including null/absent `vm_size`)

**Cost:** `estimated_monthly_cost_usd = None` always — no hardcoded price tables; rule notes only that a Running instance incurs ongoing compute-hour charges

**Permissions:** `Microsoft.MachineLearningServices/workspaces/read`, `Microsoft.MachineLearningServices/workspaces/computes/read`

**Params:** `idle_days` (default: 14, minimum effective value: 1)

**Exclusions:** `id` or `name` absent/empty; workspace `name` absent/empty; outside optional region filter (exact lowercase match on **compute** resource location; spaces and hyphens preserved); `compute_type` does not resolve to exactly `"ComputeInstance"` (SDK+nested, conflict → skip); `provisioning_state` does not resolve to exactly `"Succeeded"` (SDK+nested, conflict → skip); `state` does not resolve to exactly `"Running"` (SDK+nested, conflict → skip); location unresolvable or conflicting; `created_at` absent, invalid, or in the future; instance age < `idle_days`; `lastOperation.operationTime` present but unparsable (skip — no silent fallback); `lastOperation.operationTime == created_at` (no proven post-create signal → skip); `modifiedOn` fallback only when `lastOperation` absent or has no `operationTime` — skipped when `modifiedOn` absent, unparsable, `<= created_at`, or in the future; no lifecycle signal resolvable (fail closed — no age-only fallback, no `systemData.lastModifiedAt`); resolved lifecycle timestamp in the future; floored `idle_since_days` < `idle_days`; per-compute record malformed (skip that compute); per-workspace compute listing fails (skip that workspace)

**Spec:** [specs/azure/ai/aml_compute_instance_idle.md](../specs/azure/ai/aml_compute_instance_idle.md)

#### `azure.ml.online_endpoint.idle`
**Detects:** Azure ML managed online endpoints in `Succeeded` provisioning state with zero scoring requests for `idle_days`

**Confidence / Risk:** HIGH (per-endpoint `RequestCount` metric confirms zero + age ≥ `idle_days`); MEDIUM (zero confirmed but age < `idle_days`, or metric unavailable + age ≥ 2× `idle_days`) / CRITICAL (GPU + `idle_ratio ≥ 2.0`); HIGH (GPU/accelerator); MEDIUM (CPU)

**Permissions:** `Microsoft.MachineLearningServices/workspaces/read`, `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read`, `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read`, `Microsoft.Insights/metrics/read`

**Params:** `idle_days` (default: 7)

**Exclusions:** `provisioning_state != "Succeeded"`; batch endpoints

**Spec:** —

#### `azure.ai_search.idle`
**Detects:** Azure AI Search services (Basic tier and above) that are structurally empty and have no documented query, indexing, or skill activity over a fixed 90-day window; requires BOTH confirmed zero activity across all three required metrics AND confirmed emptiness of all required object surfaces before emitting

**Confidence / Risk:** HIGH (always, when all required signals resolve) / MEDIUM (always)

**Permissions:** `Microsoft.Search/searchServices/read`, `Microsoft.Insights/metrics/read`, Azure AI Search data-plane RBAC (`Search Service Contributor` or equivalent; no admin keys)

**Params:** none (90-day window is fixed)

**Exclusions:** `id` or `name` absent/empty; outside optional region filter (exact lowercase match; spaces and hyphens preserved); `provisioning_state` does not resolve to exactly `"succeeded"` (SDK+nested, conflict → skip); `status` does not resolve to exactly `"running"` (SDK+nested, conflict → skip); `sku.name` not in supported dedicated billable tiers (`basic`, `standard`, `standard2`, `standard3`, `storage_optimized_l1`, `storage_optimized_l2`) after lowercase normalization and camelCase alias resolution; `systemData.createdAt` absent, invalid, in the future, or service age < 90 days (no age-only fallback); `replica_count` or `partition_count` not a known positive integer (conflict → skip); data-plane client factory returns `None` (azure-search-documents package unavailable → skip); any required object surface (`indexes`, `indexers`, `data_sources`, `skillsets`, `synonym_maps`) fails, is unavailable, or is non-empty; any optional reinforcing surface (`aliases`, `knowledge_sources`, `agents`) fully enumerated and non-empty; any of three required activity metrics (`SearchQueriesPerSecond`/Average, `DocumentsProcessedCount`/Total, `SkillExecutionCount`/Total) below 95% daily-bucket coverage or non-zero over 90 days; non-numeric aggregation values or malformed metric response shapes (fail-closed to UNKNOWN → skip); per-service retrieval raises `HttpResponseError`, `ServiceRequestError`, or `ServiceResponseError`

**Spec:** [specs/azure/ai/ai_search_idle.md](../specs/azure/ai/ai_search_idle.md)

#### `azure.openai.provisioned_deployment.idle`
**Detects:** Azure OpenAI provisioned deployments (PTUs) with zero API requests for `idle_days`; bills per PTU per hour regardless of traffic

**Confidence / Risk:** HIGH (per-deployment `AzureOpenAIRequests` metric confirms zero + age ≥ `idle_days`); MEDIUM (per-deployment zero but age < `idle_days`, or account-level zero only) / HIGH (≥ 7 PTUs, ~$10K+/month); MEDIUM (< 7 PTUs)

**Permissions:** `Microsoft.CognitiveServices/accounts/read`, `Microsoft.CognitiveServices/accounts/deployments/read`, `Microsoft.Insights/metrics/read`

**Params:** `idle_days` (default: 7)

**Exclusions:** non-provisioned SKUs; only `ProvisionedManaged`, `GlobalProvisionedManaged`, `DataZoneProvisionedManaged` evaluated

**Spec:** —
