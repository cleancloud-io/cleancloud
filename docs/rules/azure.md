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
| `azure.aml.compute.idle` | AI/ML | AML compute clusters with min_node_count > 0 and no active nodes 14+ days |
| `azure.ml.compute_instance.idle` | AI/ML | Azure ML Compute Instances Running with no activity 14+ days |
| `azure.ml.online_endpoint.idle` | AI/ML | Azure ML managed online endpoints with zero scoring requests 7+ days |
| `azure.ai_search.idle` | AI/ML | Azure AI Search services (Standard+) with zero queries 30+ days |
| `azure.openai.provisioned_deployment.idle` | AI/ML | Azure OpenAI provisioned deployments (PTUs) with zero requests 7+ days |

---

## Compute

#### `azure.vm.stopped_not_deallocated`
**Detects:** VMs in `PowerState/stopped` state (full compute charges continue; only `deallocated` stops billing)

**Confidence / Risk:** HIGH (deterministic power state) / HIGH

**Permissions:** `Microsoft.Compute/virtualMachines/read`

**Params:** none

**Exclusions:** `PowerState/deallocated`, transitional states (starting, stopping, deallocating)

**Spec:** —

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
**Detects:** VPN or ExpressRoute Gateways with no active S2S/ExpressRoute connections

**Confidence / Risk:** MEDIUM (no active connections; P2S client count not checked) / HIGH

**Permissions:** `Microsoft.Network/virtualNetworkGateways/read`, `Microsoft.Network/connections/read`

**Params:** none

**Exclusions:** gateways with P2S configuration present and no active connections are still flagged if no other connections exist

**Spec:** —

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
**Detects:** Managed disks and snapshots with zero tags

**Confidence / Risk:** MEDIUM (untagged + unattached disk); LOW (untagged snapshot or attached disk) / LOW

**Permissions:** `Microsoft.Compute/disks/read`, `Microsoft.Compute/snapshots/read`

**Params:** none

**Exclusions:** disks younger than 7 days

**Spec:** —

---

## AI/ML *(opt-in: `--category ai`)*

#### `azure.aml.compute.idle`
**Detects:** AML compute clusters with `min_node_count > 0` and zero active nodes for 14+ days

**Confidence / Risk:** HIGH (zero nodes, cluster age ≥ 14 days); MEDIUM (zero nodes, age 7–13 days or creation time unavailable) / HIGH (GPU VM sizes: Standard_NC*, Standard_ND*, Standard_NV*); MEDIUM (CPU)

**Permissions:** `Microsoft.MachineLearningServices/workspaces/read`, `Microsoft.MachineLearningServices/workspaces/computes/read`, `Microsoft.Insights/metrics/read`

**Params:** none (14-day threshold is fixed)

**Exclusions:** clusters with `min_node_count == 0` (scale-to-zero; no idle cost)

**Spec:** —

#### `azure.ml.compute_instance.idle`
**Detects:** Azure ML Compute Instances in `Running` state with no control-plane activity for `idle_days`

**Confidence / Risk:** HIGH (`last_operation.operation_time` or `last_modified_at` ≥ threshold, age ≥ threshold); MEDIUM (≥ 75% of threshold on both signals, or age-only fallback) / CRITICAL (GPU + `idle_ratio ≥ 2.0`); HIGH (GPU: Standard_NC*, Standard_ND*, Standard_NV*); MEDIUM (CPU)

**Permissions:** `Microsoft.MachineLearningServices/workspaces/read`, `Microsoft.MachineLearningServices/workspaces/computes/read`

**Params:** `idle_days` (default: 14)

**Exclusions:** stopped instances (only `Running` state evaluated)

**Spec:** —

#### `azure.ml.online_endpoint.idle`
**Detects:** Azure ML managed online endpoints in `Succeeded` provisioning state with zero scoring requests for `idle_days`

**Confidence / Risk:** HIGH (per-endpoint `RequestCount` metric confirms zero + age ≥ `idle_days`); MEDIUM (zero confirmed but age < `idle_days`, or metric unavailable + age ≥ 2× `idle_days`) / CRITICAL (GPU + `idle_ratio ≥ 2.0`); HIGH (GPU/accelerator); MEDIUM (CPU)

**Permissions:** `Microsoft.MachineLearningServices/workspaces/read`, `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read`, `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read`, `Microsoft.Insights/metrics/read`

**Params:** `idle_days` (default: 7)

**Exclusions:** `provisioning_state != "Succeeded"`; batch endpoints

**Spec:** —

#### `azure.ai_search.idle`
**Detects:** Azure AI Search services (Standard tier and above) with zero `SearchQueriesPerSecond` for `idle_days`

**Confidence / Risk:** HIGH (zero queries confirmed + age ≥ `idle_days`); MEDIUM (zero confirmed but age < `idle_days`, or metric unavailable + age ≥ 2× `idle_days`) / HIGH (estimated cost ≥ $1,000/month); MEDIUM (otherwise)

**Permissions:** `Microsoft.Search/searchServices/read`, `Microsoft.Insights/metrics/read`

**Params:** `idle_days` (default: 30)

**Exclusions:** Basic tier and below; only `standard`, `standard2`, `standard3`, `storage_optimized_l1`, `storage_optimized_l2` evaluated

**Spec:** —

#### `azure.openai.provisioned_deployment.idle`
**Detects:** Azure OpenAI provisioned deployments (PTUs) with zero API requests for `idle_days`; bills per PTU per hour regardless of traffic

**Confidence / Risk:** HIGH (per-deployment `AzureOpenAIRequests` metric confirms zero + age ≥ `idle_days`); MEDIUM (per-deployment zero but age < `idle_days`, or account-level zero only) / HIGH (≥ 7 PTUs, ~$10K+/month); MEDIUM (< 7 PTUs)

**Permissions:** `Microsoft.CognitiveServices/accounts/read`, `Microsoft.CognitiveServices/accounts/deployments/read`, `Microsoft.Insights/metrics/read`

**Params:** `idle_days` (default: 7)

**Exclusions:** non-provisioned SKUs; only `ProvisionedManaged`, `GlobalProvisionedManaged`, `DataZoneProvisionedManaged` evaluated

**Spec:** —
