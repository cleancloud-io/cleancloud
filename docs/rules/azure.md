# Azure Rules

17 rules (12 hygiene + 5 AI/ML). AI/ML rules require `--category ai`.

← [Back to index](../rules.md)

| Rule ID | Cost Surface | What It Detects |
|---|---|---|
| `azure.vm.stopped_not_deallocated` | Compute | Stopped but not deallocated VMs (full charges) |
| `azure.compute.disk.unattached` | Storage | Managed disks not attached to any VM |
| `azure.compute.snapshot.old` | Storage | Old managed snapshots as conservative review candidates |
| `azure.network.public_ip.unused` | Network | Public IPs not attached to any interface |
| `azure.load_balancer.no_backends` | Network | Standard LBs with billable rules but no backend members |
| `azure.application_gateway.no_backends` | Network | App Gateways with zero backend targets |
| `azure.virtual_network_gateway.idle` | Network | VPN/ExpressRoute Gateways with no connections |
| `azure.app_service_plan.empty` | Platform | Paid App Service Plans with zero apps |
| `azure.app_service.idle` | Platform | App Services with zero HTTP requests 14+ days |
| `azure.sql.database.idle` | Platform | Azure SQL databases with zero connections 14+ days |
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
**Detects:** Managed disks with `managed_by is None` for 7+ days

**Confidence / Risk:** MEDIUM (deterministic state; attachment intent unknown) / LOW

**Permissions:** `Microsoft.Compute/disks/read`

**Params:** none

**Exclusions:** disks younger than 7 days

**Spec:** —

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
**Detects:** Public IP addresses with `ip_configuration is None` (not attached to any interface)

**Confidence / Risk:** MEDIUM (deterministic; may be reserved intentionally) / LOW

**Permissions:** `Microsoft.Network/publicIPAddresses/read`

**Params:** none

**Exclusions:** none

**Spec:** —

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
**Detects:** Azure SQL databases with zero `connection_successful` metric for `idle_threshold_days`

**Confidence / Risk:** HIGH (zero connections confirmed) / HIGH

**Permissions:** `Microsoft.Sql/servers/read`, `Microsoft.Sql/servers/databases/read`, `Microsoft.Insights/metrics/read`

**Params:** `idle_threshold_days` (default: 14)

**Exclusions:** `master` system database; Basic tier databases

**Spec:** —

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
