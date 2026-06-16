# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

🇬🇧 English | 🇫🇷 [Français](README.fr.md) &nbsp;·&nbsp; **Setup:** [AWS →](docs/aws.md) · [Azure →](docs/azure.md) · [GCP →](docs/gcp.md) · [All docs →](docs/rules.md)

---

**Find $500–$20K/month of idle cloud waste in 60 seconds — no credentials needed:**

```bash
# Try instantly (no install):
docker run --rm getcleancloud/cleancloud:latest demo

# Or install locally:
pipx install cleancloud
cleancloud demo
```

*`scan` and `doctor` with Docker require credential mounts → [Docker usage →](docs/ci.md#using-the-docker-image)*

CleanCloud scans AWS, Azure, and GCP and names specific idle resources as review candidates — with cost per resource. **Read-only. No agents. No SaaS.**

---

## Sample Output

```
cleancloud demo --category ai

3 review candidates found:

1. [AWS] Idle GPU EC2 Instance (GPU utilisation <5% over 7 days)
   Risk       : Critical
   Confidence : High
   Resource   : aws.ec2.instance → i-0a1b2c3d4e5f67890
   Region     : us-east-1
   Rule       : aws.ec2.gpu.idle
   Reason     : GPU utilisation 1.2% for 7 days (p4d.24xlarge — ml-training-cluster-node-1)
   Details:
     - estimated_monthly_cost: ~$23,374/month

2. [GCP] Idle Vertex AI Endpoint (2 replica(s) always on, zero requests)
   Risk       : High
   Confidence : High
   Resource   : gcp.vertex.endpoint → projects/ml-platform/locations/us-central1/endpoints/8842531067721654272
   Region     : us-central1
   Rule       : gcp.vertex.endpoint.idle
   Reason     : Endpoint has provisioned serving floor of 2 replica(s); request-count telemetry (coverage: complete) shows max observed rate == 0 over 14d window
   Details:
     - provisioned_serving_floor: 2
     - in_scope_model_count: 1
     - has_accelerator: true
     - telemetry_coverage_state: complete

3. [Azure] Idle Azure ML Compute Instance (31 Days Since Last Activity)
   Risk       : High
   Confidence : High
   Resource   : azure.ml.compute_instance → ws-prod/compute/ds-workstation-nc24
   Region     : eastus
   Rule       : azure.ml.compute_instance.idle
   Reason     : No control-plane activity for 31 days while Running (Standard_NC24s_v3, GPU)
   Details:
     - estimated_monthly_cost: ~$2,190/month

4. [AWS] Idle RDS Instance (Zero connections for 21 days)
   Risk       : High
   Confidence : High
   Resource   : aws.rds.instance → db-prod-analytics
   Region     : us-east-1
   Rule       : aws.rds.instance.idle
   Reason     : Zero connections for 21 days (db.r5.large, postgres 15.4)
   Details:
     - estimated_monthly_cost: ~$380/month

--- Scan Summary ---
Total review candidates: 4
By risk:        critical: 1  high: 3
Minimum estimated waste: ~$25,944/month
```

*Full 10-finding example: [`docs/example-outputs.md`](docs/example-outputs.md)*

---

## As featured in

- [Korben](https://korben.info/cleancloud-nettoyeur-cloud-aws-azure.html) 🇫🇷 — Major French tech publication
- [Last Week in AWS #457](https://www.lastweekinaws.com/newsletter/15259/) — Corey Quinn's weekly AWS newsletter

> "Solid discovery tool that bubbles up potential savings. Easy to install and use!"
> — [Reddit user](https://www.reddit.com/r/AZURE/comments/1rm7an5/comment/o8zfv6a/)

---

**CleanCloud is a cloud hygiene scanner — reads your inventory, flags specific idle resources as review candidates, and estimates the cost of keeping them running.**

- Catches expensive idle AI/ML waste: SageMaker, AML, Vertex AI — GPU-backed resources flagged as higher-risk review candidates ($500–$23K/month)
- Works across AWS, Azure, and GCP in one tool
- Runs entirely in your environment — no agents, no SaaS, no credentials stored
- 49 curated, high-signal detection rules designed to avoid false positives in IaC environments
- CI/CD-ready — enforcement exit codes + JSON/CSV/markdown output

### What CleanCloud does NOT do

- No deletes or modifications to cloud resources
- No write access to any cloud API
- No credentials stored, no telemetry sent
- No SaaS account or agents required

Fully read-only. Safe for production and regulated environments.

---

## Get Started

```bash
# Add your cloud provider and scan:
pipx install 'cleancloud[aws]'            # or [azure], [gcp], [all]
cleancloud scan --provider aws --all-regions
cleancloud scan --provider azure
cleancloud scan --provider gcp --all-projects
```

**Choose your path:**

| I want to… | Start here |
|---|---|
| Scan AWS | [AWS setup (IAM policy, regions, multi-account) →](docs/aws.md) |
| Scan Azure | [Azure setup (RBAC, subscriptions, Workload Identity) →](docs/azure.md) |
| Scan GCP | [GCP setup (IAM, projects, ADC) →](docs/gcp.md) |
| Run in CI/CD | [CI/CD guide (GitHub Actions, GitLab, exit codes) →](docs/ci.md) |
| Suppress findings / set thresholds | [Policy config reference →](docs/configuration.md) |
| Tag filtering, exception patterns, rollout advice | [Best practices →](docs/best-practices.md) |
| Scan multiple AWS accounts | [Multi-account setup →](docs/aws.md#multi-account-scanning) |
| Getting an error | [Troubleshooting →](docs/troubleshooting.md) |

Not sure if your credentials have the right permissions? Run `cleancloud doctor --provider aws` first.

---

## AI/ML Waste Detection

Idle AI/ML infrastructure is the fastest-growing source of invisible cloud spend. Unlike compute or storage, these resources bill at full rate even with zero activity — GPU-backed endpoints don't scale to zero.

| Resource | Idle cost range |
|---|---|
| Bedrock Provisioned Throughput | $600 – $7,300+ / MU / month |
| SageMaker endpoint (GPU) | $500 – $23,000 / month |
| SageMaker Notebook Instance (GPU) | $500 – $23,000+ / month |
| SageMaker Studio Apps (KernelGateway/JupyterLab/CodeEditor) | $42 – $1,600+ / month |
| SageMaker Domain (idle EFS storage) | Continuous EFS charges |
| SageMaker Training Job (runaway/hung GPU job) | $670 – $2,360+ / day |
| SageMaker Processing Job (hung/stuck) | $670 – $2,360+ / day |
| Azure AML compute cluster (GPU) | $600 – $15,000 / month |
| Azure ML Compute Instance (GPU) | $600 – $15,000+ / month |
| Azure ML Online Endpoint (GPU-backed) | $200 – $2,600+ / month |
| Azure AI Search (Basic+) | $261 – $4,028+ / month |
| Azure OpenAI Provisioned Deployment (PTU) | $1,460+ / PTU / month |
| Vertex AI Online Prediction endpoint (GPU) | $449 – $23,000+ / month |
| Vertex AI Workbench instance (GPU) | $449 – $8,000+ / month |
| Cloud TPU node (v4/v5p) | $188 – $750+/ day |
| Vertex AI Feature Store (Bigtable-backed) | $197 – $591+ / month |

CleanCloud detects zero-invocation / zero-prediction endpoints, stale managed notebook and app activity, and long-running managed training jobs across all three clouds. Native cost tools show the bill — they do not name the specific resource to review.

```bash
cleancloud scan --provider aws --category ai          # Bedrock PTUs + SageMaker endpoints + notebooks + domains + Studio apps + training jobs + processing jobs + idle GPU EC2
cleancloud scan --provider azure --category ai        # AML compute + ML instances + online endpoints + AI Search + OpenAI PTUs
cleancloud scan --provider gcp --category ai          # Vertex AI endpoints + Workbench + training jobs + Cloud TPU + Feature Stores
cleancloud scan --provider aws --category all         # hygiene + AI/ML together
```

No setup required beyond the base install — opt-in with `--category ai`. Works with multi-account and multi-project scans:

```bash
cleancloud scan --provider aws --org --all-regions --category all
```

**[AI/ML rules →](docs/rules.md)** · [Full detection details →](docs/rules.md#aiml-rules)

---

## Who it's for

- **Platform and FinOps teams** — run weekly hygiene scans across your AWS Org or Azure tenant, enforce waste thresholds, catch drift before it compounds
- **Regulated industries** — financial services, healthcare, and government teams that cannot send cloud account data to a SaaS vendor
- **Mid-market engineering teams** — too large to ignore cloud waste, too lean for enterprise FinOps platforms. Native cost tools show bills; CleanCloud shows what to review
- **Cloud consultants and MSPs** — run a read-only audit against a client account in minutes, export findings to markdown or JSON
- **One-time audits** — run in CloudShell, see findings in 60 seconds, no setup required
- **Pre-review reports** — export findings to markdown before a quarterly cost review or board meeting

---

## Governance as Code

Drop a `cleancloud.yaml` in your repo root. Every exception is a git-reviewable approval — version-controlled alongside your infrastructure.

```yaml
# cleancloud.yaml
defaults:
  confidence: MEDIUM    # skip low-signal findings globally
  min_cost: 10          # skip findings below $10/month

exceptions:
  - rule_id: aws.ec2.instance.stopped
    resource_id: i-0abc1234567890def
    reason: "Bastion host — started on demand"
    expires_at: "2026-12-31"          # auto-expires — forces periodic review

  - rule_id: aws.rds.instance.idle
    resource_id: "db-test-*"          # glob — suppress all test databases
    reason: "Test databases are intentionally ephemeral"

thresholds:
  fail_on_confidence: HIGH            # exit 2 in CI if any HIGH confidence finding remains
  fail_on_cost: 500                   # exit 2 if total estimated waste exceeds $500/month
```

Enforce in CI/CD:

```bash
cleancloud scan --provider aws --org --all-regions   # picks up cleancloud.yaml automatically
```

**[Full policy config reference →](docs/configuration.md)** · [Best practices →](docs/best-practices.md)

---

## In CI/CD

CleanCloud exits `0` by default — findings are reported, nothing blocked unless you ask.

```bash
# Weekly governance: fail if monthly waste crosses $500
cleancloud scan --provider aws --org --all-regions \
  --output json --output-file findings.json \
  --fail-on-cost 500

# Pre-deploy gate: block on any HIGH confidence waste
cleancloud scan --provider aws --region us-east-1 \
  --fail-on-confidence HIGH
```

| Exit code | Meaning |
|-----------|---------|
| `0` | No policy violation (or no enforcement flags set) |
| `1` | Configuration error or unexpected failure |
| `2` | Policy violation — threshold breached |
| `3` | Missing credentials or insufficient permissions |

**[Full CI/CD guide →](docs/ci.md)** · [AWS →](docs/aws.md) · [Azure →](docs/azure.md) · [GCP →](docs/gcp.md)

---

| | AWS/Azure/GCP native cost tools | FinOps SaaS platforms | **CleanCloud** |
|---|:---:|:---:|:---:|
| Shows cost trends | ✅ | ✅ | — |
| Names specific resources flagged for review | ❌ | partial | ✅ |
| Deterministic cost estimate per resource | ❌ | ❌ | ✅ |
| Detects idle AI/ML waste (SageMaker, AML, Vertex AI — including GPU-backed endpoints) | ❌ | ❌ | ✅ |
| **Policy-as-code (exceptions + thresholds in git)** | ❌ | ❌ | ✅ |
| **Git-reviewable exception approvals** | ❌ | ❌ | ✅ |
| Read-only, no agents | ✅ | ❌ | ✅ |
| Runs in air-gapped / regulated environments | ❌ | ❌ | ✅ |
| No SaaS account or vendor access required | ❌ | ❌ | ✅ |
| Multi-account / multi-subscription / multi-project | ❌ | ✅ | ✅ |
| CI/CD and scheduled enforcement (exit codes) | ❌ | ❌ | ✅ |

---

<details>
<summary>Multi-Account Scanning (AWS)</summary>

Built for enterprises running AWS Organizations. Scan every account in parallel — findings aggregated into one report.

```bash
# Scan from a config file (commit .cleancloud/accounts.yaml to your repo)
cleancloud scan --provider aws --multi-account .cleancloud/accounts.yaml --all-regions

# Inline account IDs — no file needed
cleancloud scan --provider aws --accounts 111111111111,222222222222 --all-regions

# Auto-discover all accounts in your AWS Organization
cleancloud scan --provider aws --org --all-regions --concurrency 5
```

**Permissions required:**

| Role | Permissions |
|---|---|
| Hub account | 16 read-only permissions + `sts:AssumeRole` on spoke roles |
| Hub account (`--org` only) | Above + `organizations:ListAccounts` |
| Spoke accounts | 16 read-only permissions (same as single-account scan — no extra changes) |

**`.cleancloud/accounts.yaml`** — commit this to your repo:

```yaml
role_name: CleanCloudReadOnlyRole
accounts:
  - id: "111111111111"
    name: production
  - id: "222222222222"
    name: staging
```

**Spoke account trust policy** — allows the hub to assume the role:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<HUB_ACCOUNT_ID>:root" },
  "Action": "sts:AssumeRole"
}
```

**How it works:**

- **Hub-and-spoke** — CleanCloud assumes `CleanCloudReadOnlyRole` in each target account using STS. No persistent access, no stored credentials.
- **Three discovery modes** — `.cleancloud/accounts.yaml` for explicit control, `--accounts` for quick ad-hoc scans, `--org` for full AWS Organizations auto-discovery.
- **Efficient region detection** — active regions are discovered once on the hub account and reused across all spokes. Without this: N accounts × 160 API calls just for region probing. With it: 160 calls once.
- **Parallel with isolation** — each account runs in its own thread with its own session. One account failing (AccessDenied, timeout) never affects the others.
- **Partial-success visibility** — if 2 regions fail and 7 succeed within an account, the account is marked `partial` with the failed regions named.
- **Live progress** — `[3/50] done production (123456789012) — 47s, 12 findings` printed as each account completes.
- **Per-account cost breakdown** — JSON output includes estimated monthly waste per account, sortable and scriptable.

Full setup guide (IAM policy, trust policy, IaC templates): [AWS multi-account setup →](docs/aws.md#multi-account-scanning)

</details>

<details>
<summary>Multi-Subscription Scanning (Azure)</summary>

Built for enterprises running large Azure tenants. Scan every subscription in parallel with one identity — findings aggregated into one report with a per-subscription cost breakdown.

```bash
# Scan all subscriptions the service principal can access (default)
cleancloud scan --provider azure

# Auto-discover via Management Group
cleancloud scan --provider azure --management-group <MANAGEMENT_GROUP_ID>

# Explicit list
cleancloud scan --provider azure --subscription <SUB_1> --subscription <SUB_2>
```

**Permissions required:**

| Scope | Role |
|---|---|
| Each subscription | Reader (built-in) |
| Management Group (if using `--management-group`) | Reader + `Microsoft.Management/managementGroups/read` |

Assign Reader at the Management Group level and it inherits to all subscriptions underneath — no per-subscription role assignment needed:

```bash
az role assignment create \
  --assignee <SERVICE_PRINCIPAL_CLIENT_ID> \
  --role Reader \
  --scope /providers/Microsoft.Management/managementGroups/<MANAGEMENT_GROUP_ID>
```

**How it works:**

- **Flat identity model** — one service principal, Reader at Management Group level. No cross-subscription role assumption, no hub-and-spoke complexity.
- **Three discovery modes** — all accessible (default), `--management-group` for auto-discovery, `--subscription` for explicit control.
- **Parallel with isolation** — each subscription runs in its own thread. One subscription failing (permission denied, timeout) never affects the others.
- **Graceful permission handling** — rules that fail with 403 are reported as skipped (with the missing permission named), not as scan failures.
- **Per-subscription cost breakdown** — output shows estimated monthly waste per subscription so you can see exactly which subscription is dirty.

Full setup guide (RBAC, Workload Identity, Management Group): [Azure multi-subscription setup →](docs/azure.md#multi-subscription-scanning)

</details>

<details>
<summary>Multi-Project Scanning (GCP)</summary>

Built for teams running multiple GCP projects. Scan all accessible projects in parallel with one identity — findings aggregated into one report with a per-project cost breakdown.

```bash
# Scan all projects the identity can access (default — uses ADC project discovery)
cleancloud scan --provider gcp --all-projects

# Scan specific projects
cleancloud scan --provider gcp --project my-project-123 --project another-project-456
```

**Permissions required (per project):**

| Permission | Required for |
|---|---|
| `compute.disks.list` | Unattached persistent disks |
| `compute.instances.list` | Stopped VM instances |
| `compute.addresses.list` | Unused regional static IPs |
| `compute.globalAddresses.list` | Unused global static IPs |
| `compute.snapshots.list` | Old disk snapshots |
| `cloudsql.instances.list` | Idle Cloud SQL instances |
| `monitoring.timeSeries.list` | SQL connection activity check |

All read-only permissions are covered by four predefined roles: `roles/compute.viewer`, `roles/cloudsql.viewer`, `roles/monitoring.viewer`, and `roles/browser` (required for `--all-projects` project enumeration). For CI/CD, use Workload Identity Federation — see [GCP setup →](docs/gcp.md).

Full setup guide: [GCP setup →](docs/gcp.md)

</details>

---

## FAQ

**Is it safe to run in production?**
Yes. CleanCloud is read-only — it calls only `List`, `Describe`, and `Get` APIs. No writes, no deletes, no changes to your cloud account.

**Does CleanCloud send my data anywhere?**
No. It runs entirely in your environment. No telemetry, no SaaS, no outbound connections except to your cloud provider's own APIs.

**Will it flag resources my team manages with Terraform / CDK?**
CleanCloud detects actual idle state (zero connections, zero traffic, zero invocations) — not resource existence. A Terraform-managed RDS instance with zero connections for 30 days is still flagged. Use tag filtering or exceptions to suppress intentional infrastructure.

**How do I suppress a specific resource?**
Two options: tag it with `cleancloud-ignore: true` (tag filtering), or add an explicit exception in `cleancloud.yaml` (policy-as-code). Exceptions support glob patterns and expiry dates. See [Policy config →](docs/configuration.md#exceptions).

**My CI is failing on findings I don't care about. How do I fix it?**
Don't disable enforcement — suppress the specific noise. Use `min_cost` to hide cheap findings, `confidence: MEDIUM` to skip low-signal ones, or add exceptions for known-good resources. See [Troubleshooting →](docs/troubleshooting.md#ci-exits-2-even-though-findings-look-suppressed).

**Can I run it without a `cleancloud.yaml`?**
Yes. Without a config file all rules are enabled with their defaults. The config is optional — you can start with just a CLI flag and add a config later.

**Does it work in air-gapped / private environments?**
Yes. CleanCloud only needs network access to your cloud provider's API endpoints. No external dependencies, no package downloads at scan time.

---

## What CleanCloud Detects

49 rules across AWS, Azure, and GCP — conservative, high-signal, designed to avoid false positives in IaC environments.

**AWS:**
- Compute: stopped instances 30+ days (EBS charges continue)
- Storage: unattached EBS volumes (HIGH), old EBS snapshots, old AMIs, old RDS snapshots 90+ days
- Network: unattached Elastic IPs (HIGH), detached ENIs, idle NAT Gateways, idle load balancers (HIGH)
- Platform: idle RDS instances (HIGH), idle Redshift clusters (zero connections 14+ days)
- Observability: infinite retention CloudWatch Logs
- Governance: untagged resources, unused security groups
- AI/ML *(opt-in: `--category ai`)*: idle Bedrock Provisioned Throughput (Model Units) with zero invocations 7+ days; idle SageMaker endpoints with no observed `InvokeEndpoint` traffic 14+ days; SageMaker Notebook Instances with stale control-plane timestamps 14+ days; SageMaker Domains with no running apps across all user profiles and spaces 30+ days (continuous EFS storage cost); SageMaker Studio apps (`KernelGateway`/`JupyterLab`/`CodeEditor`) with no usable recent activity signal 7+ days; SageMaker training jobs still `InProgress` beyond the 24h threshold; SageMaker processing jobs still `InProgress` beyond the 24h threshold

**Azure:**
- Compute: stopped (not deallocated) VMs (HIGH)
- Storage: unattached managed disks (HIGH), old snapshots
- Network: unused public IPs, empty load balancers (HIGH), empty App Gateways (HIGH), idle VNet Gateways
- Platform: empty App Service Plans (HIGH), idle SQL databases (HIGH), idle App Services, unused Container Registries
- Governance: untagged resources
- AI/ML *(opt-in: `--category ai`)*: idle AML compute clusters with non-zero baseline capacity and no workload activity 14+ days — GPU clusters flagged HIGH risk ($600–$15K/month); idle Compute Instances with no control-plane activity 14+ days — GPU instances CRITICAL risk ($600–$15K+/month); idle ML managed online endpoints with zero scoring requests 7+ days — GPU-backed endpoints flagged HIGH/CRITICAL ($200–$2,600+/month); idle AI Search services (Basic+) with zero queries 90+ days — billed per SKU × replicas × partitions ($261–$4,028+/month); idle Azure OpenAI provisioned deployments (PTUs) with zero API requests 7+ days — bills ~$1,460/PTU/month on-demand regardless of traffic

**GCP:**
- Compute: stopped instances 30+ days (disk charges continue) (HIGH)
- Storage: unattached Persistent Disks (HIGH), old snapshots 90+ days
- Network: unused reserved static IPs — regional and global (HIGH)
- Platform: idle Cloud SQL instances with zero connections 14+ days (HIGH)
- AI/ML *(opt-in: `--category ai`)*: idle Vertex AI Online Prediction endpoints with zero observed predictions 14+ days (dedicated nodes continue billing regardless of traffic) — GPU-backed endpoints flagged HIGH risk ($449–$23K+/month); idle Workbench instances (v1 + v2) with no control-plane activity 14+ days — GPU instances flagged HIGH/CRITICAL ($449–$8K+/month); long-running Vertex AI training jobs (CustomJobs + TrainingPipelines) beyond 24h threshold — CRITICAL risk for GPU/accelerator jobs at 3× threshold; idle Cloud TPU nodes (v2–v6e) in READY state with near-zero duty_cycle for 7+ days — idle v4 costs $12.88/hr, v5p-8 costs $33.60/hr; idle Vertex AI Feature Store online stores with zero ReadFeatureValues requests for 30+ days — Bigtable-backed stores bill ~$197/node/month regardless of activity

Rules without a confidence marker are MEDIUM — they use time-based heuristics or multiple signals. Start with `--fail-on-confidence HIGH` to catch obvious waste, then tighten as your team validates.

**Full rule details, signals, and evidence:** [`docs/rules.md`](docs/rules.md)

---

## Roadmap

**More AI/ML waste rules** — orphaned training artifacts in S3

**More AWS rules** — S3 lifecycle gaps, Redshift idle, NAT Gateway cost leakage (internal services routing through NAT instead of VPC endpoints — S3, DynamoDB, ECR, SSM), unused VPC endpoints

**More Azure rules** — Azure Firewall idle, AKS node pool idle, Azure Batch unused pools

**More GCP rules** — GKE node pool idle, BigQuery slot waste, GCS cold storage, Cloud Run idle revisions

**Rule filtering** — `--rules` flag to run a subset of rules

---

## Documentation

- [`docs/rules.md`](docs/rules.md) — Detection rules, signals, and evidence
- [`docs/aws.md`](docs/aws.md) — AWS IAM policy and OIDC setup
- [`docs/azure.md`](docs/azure.md) — Azure RBAC and Workload Identity setup
- [`docs/gcp.md`](docs/gcp.md) — GCP IAM permissions and Application Default Credentials setup
- [`docs/ci.md`](docs/ci.md) — Automation, scheduled scans, and CI/CD integration
- [`docs/configuration.md`](docs/configuration.md) — Policy-as-code: exceptions, thresholds, tag filtering
- [`docs/best-practices.md`](docs/best-practices.md) — Rollout strategy, tag filtering patterns, exception patterns
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — Common errors and fixes
- [`docs/example-outputs.md`](docs/example-outputs.md) — Full output examples
- [`SECURITY.md`](SECURITY.md) — Security policy and threat model
- [`docs/infosec-readiness.md`](docs/infosec-readiness.md) — IAM Proof Pack, threat model

---

**Found a bug?** [Open an issue](https://github.com/cleancloud-io/cleancloud/issues)

**Feature request?** [Start a discussion](https://github.com/cleancloud-io/cleancloud/discussions)

**Questions?** suresh@getcleancloud.com

[MIT License](LICENSE)
