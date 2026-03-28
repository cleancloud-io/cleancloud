# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![Docker Pulls](https://img.shields.io/docker/pulls/getcleancloud/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Security Scanning](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml)
![GitHub stars](https://img.shields.io/github/stars/cleancloud-io/cleancloud?style=social)

**Languages / Langues :**
🇬🇧 [English](README.md) | 🇫🇷 [Français](README.fr.md)

**Docs:** [AWS Setup](docs/aws.md) · [AWS Permissions & Commands](docs/aws.md#at-a-glance) · [AWS Multi-Account](docs/aws.md#multi-account-scanning) · [Azure Setup](docs/azure.md) · [GCP Setup](docs/gcp.md) · [CI/CD Guide](docs/ci.md) · [Detection Rules](docs/rules.md) · [Example Outputs](docs/example-outputs.md) · [Docker Hub](https://hub.docker.com/r/getcleancloud/cleancloud) · [GitHub Action](https://github.com/marketplace/actions/cleancloud-scan)

---

**CleanCloud is the Cloud Hygiene Engine — the missing layer between cost visibility and cleanup.**

**Supports:** AWS · Azure · GCP

Cloud waste hit 29% of spend in 2026 — the first rise in five years (Flexera). Most teams already have cost dashboards. Dashboards show spend trends; they don't tell engineers what to clean up. SaaS FinOps platforms require vendor access to your cloud account — a non-starter for regulated industries. And as cloud environments scale across accounts and subscriptions, unused resources are no longer exceptions — they are continuous drift. Platform teams need a deterministic, enforceable process to turn that drift into a list of exactly what to act on.

That's CleanCloud. Scan your AWS, Azure, and GCP environments, get specific actionable findings with per-resource cost estimates, and enforce waste thresholds on a schedule — no agents, no SaaS, no data leaving your environment.

| | AWS/Azure/GCP native cost tools | FinOps SaaS platforms | **CleanCloud** |
|---|:---:|:---:|:---:|
| Shows cost trends | ✅ | ✅ | — |
| Names exactly which resources to clean up | ❌ | partial | ✅ |
| Deterministic cost estimate per resource | ❌ | ❌ | ✅ |
| Read-only, no agents | ✅ | ❌ | ✅ |
| Runs in air-gapped / regulated environments | ❌ | ❌ | ✅ |
| No SaaS account or vendor access required | ❌ | ❌ | ✅ |
| Multi-account / multi-subscription / multi-project | ❌ | ✅ | ✅ |
| CI/CD and scheduled enforcement (exit codes) | ❌ | ❌ | ✅ |

- **30 curated, high-signal detection rules:** orphaned volumes, idle databases, stopped instances, unused registries, and more — designed to avoid false positives in IaC environments, each with a deterministic cost estimate
- **Governance enforcement (opt-in):** `--fail-on-confidence HIGH` or `--fail-on-cost 100` — enforce waste thresholds on a schedule, owned by platform or FinOps teams
- **Multi-account scanning (AWS):** scan entire AWS Organizations in one run — config file, inline IDs, or auto-discovery via `--org`
- **Multi-subscription scanning (Azure):** scan all Azure subscriptions in parallel — auto-discovery via Management Group, per-subscription cost breakdown included
- **Multi-project scanning (GCP):** scan all accessible GCP projects in parallel — auto-discovery via Application Default Credentials, per-project cost breakdown included
- **Safe for regulated environments:** read-only, no agents, no telemetry, no SaaS — runs entirely inside your own infrastructure. Suitable for financial services, healthcare, and government accounts where third-party SaaS access is restricted
- **Ecosystem-ready output:** JSON for Slack alerts, cost dashboards, and ticketing automation — CSV for spreadsheet workflows — markdown to paste directly into GitHub PRs, Jira, or Confluence
- **No agents. No telemetry. No SaaS.** Data never leaves your environment

### What CleanCloud does NOT do

| | |
|---|---|
| ❌ Delete resources | ❌ Modify or create tags |
| ❌ Write to any cloud API | ❌ Store or log credentials |
| ❌ Send telemetry or usage data | ❌ Require a SaaS account or agent |

All operations are read-only. Safe for production accounts, air-gapped environments, and security-reviewed pipelines.

**Who uses it:**
- **Platform and FinOps teams** — run weekly hygiene scans across your AWS Org or Azure tenant, enforce waste thresholds, catch drift before it compounds
- **Regulated industries** — financial services, healthcare, and government teams that cannot send cloud account data to a SaaS vendor
- **Mid-market engineering teams** — too large to ignore cloud waste, too lean for enterprise FinOps platforms. Native cost tools show bills; CleanCloud shows you what to fix
- **Cloud consultants and MSPs** — run a read-only audit against a client account in minutes, export findings to markdown or JSON

**Use cases:**
- One-time cloud waste audit — run in CloudShell, see findings in 60 seconds
- Scheduled hygiene governance — weekly job that catches new waste and enforces thresholds across all accounts
- Pre-review reports — export findings to markdown before a quarterly cost review or board meeting

```
Found 6 hygiene issues:

1. [AWS] Unattached EBS Volume       — $40/month
2. [AWS] Idle NAT Gateway            — $32.40/month
3. [AWS] Unattached Elastic IP       — $0/month
...

Estimated monthly waste: ~$147
Regions scanned: us-east-1, us-west-2, eu-west-1
```

## As featured in

- [Korben](https://korben.info/cleancloud-nettoyeur-cloud-aws-azure.html) 🇫🇷 — Major French tech publication
- [Last Week in AWS #457](https://www.lastweekinaws.com/newsletter/15259/) — Corey Quinn's weekly AWS newsletter

## What users say

> "Solid discovery tool that bubbles up potential savings. Easy to install and use!"
> — [Reddit user](https://www.reddit.com/r/AZURE/comments/1rm7an5/comment/o8zfv6a/)

---

## Get Started

### Commands

| Command | What it does |
|---|---|
| `cleancloud demo` | Show sample findings — no credentials needed |
| `cleancloud scan` | Scan your cloud environment and report findings |
| `cleancloud doctor` | Check that credentials and permissions are correctly configured |
| `cleancloud --version` | Show installed version |
| `cleancloud --help` | List all flags |

**Via pipx (recommended for local use):**
```bash
pipx install cleancloud
pipx ensurepath        # adds cleancloud to PATH — restart your shell after this
cleancloud demo        # see sample findings without any cloud credentials
```

**Via Docker (no Python required — runs anywhere: CI/CD, scheduled jobs, servers):**
```bash
docker pull getcleancloud/cleancloud
docker run --rm getcleancloud/cleancloud demo

# With AWS credentials (Docker doesn't inherit local ~/.aws automatically)
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_REGION=us-east-1 \
  getcleancloud/cleancloud scan --provider aws --all-regions
```

> In CI/CD, `aws-actions/configure-aws-credentials` sets `AWS_*` env vars on the runner — pass them with `-e VAR_NAME` and they forward into the container automatically. See [CI/CD guide →](docs/ci.md#using-the-docker-image)

When you're ready to scan your real environment, authenticate first — then run:

```bash
# AWS: make sure you're logged in (aws configure, aws sso login, or IAM role)
cleancloud scan --provider aws --all-regions

# Azure: make sure you're logged in (az login)
cleancloud scan --provider azure

# GCP: make sure you're logged in (gcloud auth application-default login)
cleancloud scan --provider gcp --all-projects
```

**Not sure if your credentials have the right permissions?** Run `cleancloud doctor --provider aws`, `cleancloud doctor --provider azure`, or `cleancloud doctor --provider gcp` first.

### Scan flags:

| Flag | What it does |
|---|---|
| `--provider aws\|azure\|gcp` | Cloud provider to scan *(required)* |
| `--region REGION` | Scan a single region |
| `--all-regions` | Scan all active regions — AWS/Azure only |
| **AWS multi-account** | |
| `--org` | Auto-discover all accounts via AWS Organizations |
| `--multi-account FILE` | Config file listing accounts to scan |
| `--accounts 111,222` | Inline account IDs, comma-separated |
| `--concurrency N` | Parallel accounts/projects (default: 3) |
| `--timeout SECONDS` | Total scan timeout in seconds (default: 3600) |
| **Azure multi-subscription** | |
| `--management-group ID` | Scan all subscriptions under a Management Group |
| `--subscription ID` | Scan a specific subscription (default: all accessible) |
| **GCP multi-project** | |
| `--all-projects` | Scan all accessible GCP projects |
| `--project ID` | Scan a specific project (repeatable) |
| **Output** | |
| `--output human\|json\|csv\|markdown` | Output format (default: human) |
| `--output-file FILE` | Write output to file instead of stdout |
| **Enforcement** *(exit code 2 on match)* | |
| `--fail-on-confidence HIGH\|MEDIUM` | Fail on findings at or above this confidence |
| `--fail-on-cost N` | Fail if estimated monthly waste ≥ $N |
| `--fail-on-findings` | Fail on any finding |

### No install — try in your cloud shell

Got an AWS or Azure account? Run a real scan in seconds with no local setup.

**AWS — [AWS CloudShell](https://console.aws.amazon.com/cloudshell):**
```bash
pip install --upgrade cleancloud
cleancloud doctor --provider aws   # check what permissions your session has
cleancloud scan --provider aws --all-regions
```

**Azure — [Azure Cloud Shell](https://shell.azure.com):**
```bash
pip install --upgrade --user cleancloud
export PATH="$HOME/.local/bin:$PATH"
cleancloud doctor --provider azure  # check what permissions your session has
cleancloud scan --provider azure
```

**GCP — [Cloud Shell](https://shell.cloud.google.com):**
```bash
pip install --upgrade --user cleancloud
export PATH="$HOME/.local/bin:$PATH"
cleancloud doctor --provider gcp    # check what permissions your session has
cleancloud scan --provider gcp --all-projects
```

Both AWS and Azure shells authenticate using your portal session — no separate credentials needed. 

GCP Cloud Shell authenticates via gcloud Application Default Credentials, which are pre-configured in Cloud Shell.

Permissions vary by account; `doctor` tells you exactly what's available before you scan. If permissions are missing, CleanCloud skips those rules and reports what was skipped.

<details>
<summary>Install troubleshooting</summary>

**macOS:** `brew install pipx && pipx install cleancloud`

**Linux:** `sudo apt install pipx && pipx install cleancloud`

**Windows:** `python3 -m pip install --user pipx && python3 -m pipx ensurepath && pipx install cleancloud`

**Command not found: cleancloud** — Run `pipx ensurepath` then restart your shell.

**externally-managed-environment error** — Use `pipx` instead of `pip`.

**Upgrading from a previous pip install** — remove it first to avoid shadowing:
```bash
pip uninstall cleancloud && pipx install cleancloud && pipx ensurepath
```

**Wrong version after install** — Run `which cleancloud`; an old pip install may be shadowing pipx.

**Minimum recommended version: v1.7.2** — earlier versions have setup friction. Run `cleancloud --version` to check.

</details>

---

## What It Looks Like

```
Found 6 hygiene issues:

1. [AWS] Unattached EBS Volume
   Risk       : Low
   Confidence : High
   Resource   : aws.ebs.volume → vol-0a1b2c3d4e5f67890
   Region     : us-east-1
   Rule       : aws.ebs.volume.unattached
   Reason     : Volume has been unattached for 47 days
   Details:
     - size_gb: 500
     - state: available
     - tags: {"Project": "legacy-api", "Owner": "platform"}

2. [AWS] Idle NAT Gateway
   Risk       : Medium
   Confidence : Medium
   Resource   : aws.ec2.nat_gateway → nat-0abcdef1234567890
   Region     : us-west-2
   Rule       : aws.ec2.nat_gateway.idle
   Reason     : No traffic detected for 21 days
   Details:
     - name: staging-nat
     - total_bytes_out: 0
     - estimated_monthly_cost_usd: 32.40

3. [AWS] Unattached Elastic IP
   Risk       : Low
   Confidence : High
   Resource   : aws.ec2.elastic_ip → eipalloc-0a1b2c3d4e5f6
   Region     : eu-west-1
   Rule       : aws.ec2.elastic_ip.unattached
   Reason     : Elastic IP not associated with any instance or ENI (age: 92 days)

--- Scan Summary ---
Total findings: 6
By risk:        low: 5  medium: 1
By confidence:  high: 2  medium: 4
Minimum estimated waste: ~$147/month
(4 of 6 findings costed)
Regions scanned: us-east-1, us-west-2, eu-west-1 (auto-detected)
```

No cloud account yet? `cleancloud demo` shows sample output without any credentials.

### Shareable markdown report

```bash
cleancloud scan --provider aws --all-regions --output markdown
```

Prints a grouped summary you can paste directly into a GitHub PR comment, Slack message, or issue:

```markdown
## CleanCloud Scan Results

**Provider:** AWS
**Regions:** us-east-1, us-west-2, eu-west-1
**Scanned:** 2026-03-07
**Estimated monthly waste:** ~$147

**Total findings:** 6

| Finding | Count | Est. Monthly Cost |
|---------|------:|------------------:|
| Unattached EBS Volume | 2 | ~$115 |
| Idle NAT Gateway | 1 | ~$32 |
| Unattached Elastic IP | 1 | ~$0 |
| Detached ENI | 1 | — |
| CloudWatch Log Group: Infinite Retention | 1 | — |

**Confidence:** high: 3 · medium: 3

> Generated by [CleanCloud](https://github.com/cleancloud-io/cleancloud) — read-only cloud hygiene scanner for AWS and Azure.
```

Save to a file with `--output-file results.md`. Without `--output-file`, it prints to stdout.

For full output examples including `doctor`, JSON, CSV, and markdown: [`docs/example-outputs.md`](docs/example-outputs.md)

---

## What CleanCloud Detects

30 rules across AWS, Azure, and GCP — conservative, high-signal, designed to avoid false positives in IaC environments.

**AWS:**
- Compute: stopped instances 30+ days (EBS charges continue)
- Storage: unattached EBS volumes (HIGH), old EBS snapshots, old AMIs, old RDS snapshots 90+ days
- Network: unattached Elastic IPs (HIGH), detached ENIs, idle NAT Gateways, idle load balancers (HIGH)
- Platform: idle RDS instances (HIGH)
- Observability: infinite retention CloudWatch Logs
- Governance: untagged resources, unused security groups

**Azure:**
- Compute: stopped (not deallocated) VMs (HIGH)
- Storage: unattached managed disks (HIGH), old snapshots
- Network: unused public IPs, empty load balancers (HIGH), empty App Gateways (HIGH), idle VNet Gateways
- Platform: empty App Service Plans (HIGH), idle SQL databases (HIGH), idle App Services, unused Container Registries
- Governance: untagged resources

**GCP:**
- Compute: stopped instances 30+ days (disk charges continue) (HIGH)
- Storage: unattached Persistent Disks (HIGH), old snapshots 90+ days
- Network: unused reserved static IPs — regional and global (HIGH)
- Platform: idle Cloud SQL instances with zero connections 7+ days (HIGH)

Rules without a confidence marker are MEDIUM — they use time-based heuristics or multiple signals. Start with `--fail-on-confidence HIGH` to catch obvious waste, then tighten as your team validates.

**Full rule details, signals, and evidence:** [`docs/rules.md`](docs/rules.md)

---

## How Teams Run CleanCloud

CleanCloud exits `0` by default — it reports findings and never blocks anything unless you ask it to. Three common patterns:

---

**Weekly governance scan** — the most common setup for platform and FinOps teams. Run on a schedule, not tied to code changes. Catches new waste before it compounds and enforces a cost threshold across all accounts or subscriptions.

```yaml
# .github/workflows/cleancloud-weekly.yml
on:
  schedule:
    - cron: "0 9 * * 1"   # every Monday 9am
```

```bash
# AWS — scan entire org, alert if monthly waste crosses $500
cleancloud scan --provider aws --org --all-regions \
  --output json --output-file findings.json \
  --fail-on-cost 500

# Azure — scan all subscriptions under a Management Group
cleancloud scan --provider azure --management-group <MGMT_GROUP_ID> \
  --output json --output-file findings.json \
  --fail-on-cost 500
```

The JSON output can feed Slack alerts, Jira tickets, or a cost dashboard. No agents, no SaaS — runs entirely in your own infrastructure.

---

**On-demand audit** — run from CloudShell or your terminal for an immediate point-in-time view. No install, no config, findings in under 60 seconds. Useful before a quarterly cost review, a cloud migration, or an infosec audit.

```bash
# AWS CloudShell — uses your portal session, no extra auth
pip install --upgrade cleancloud
cleancloud scan --provider aws --all-regions

# Azure Cloud Shell — uses your portal session, no extra auth
pip install --upgrade --user cleancloud && export PATH="$HOME/.local/bin:$PATH"
cleancloud scan --provider azure
```

---

**In CI/CD** — run as a step in your deployment workflow to catch obvious waste before it ships. Use enforcement flags to block or warn.

```bash
# AWS
cleancloud scan --provider aws --region us-east-1 \
  --fail-on-confidence HIGH   # exit 2 if any HIGH confidence waste found

# Azure
cleancloud scan --provider azure \
  --fail-on-confidence HIGH
```

---

**Enforcement flags** — scans always exit `0` unless you opt in:

| Flag | Behavior | Exit code |
|------|----------|-----------|
| *(none)* | Report only, never fail | `0` |
| `--fail-on-confidence HIGH` | Fail on HIGH confidence findings | `2` |
| `--fail-on-confidence MEDIUM` | Fail on MEDIUM or higher | `2` |
| `--fail-on-cost 50` | Fail if estimated monthly waste >= $50 | `2` |
| `--fail-on-findings` | Fail on any finding | `2` |

Copy-pasteable GitHub Actions workflows for AWS (OIDC) and Azure (Workload Identity) — including auth setup, RBAC, and enforcement patterns:

**[Automation & CI/CD guide →](docs/ci.md)** · [AWS setup →](docs/aws.md) · [Azure setup →](docs/azure.md)

**Need help with OIDC or enforcement flags?** [Ask in our setup discussion →](https://github.com/cleancloud-io/cleancloud/discussions/98)

---

## Multi-Account Scanning (AWS only)

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

Full IAM policy, trust policy, and IaC templates: [AWS multi-account setup →](docs/aws.md#multi-account-scanning)

**How it works:**

- **Hub-and-spoke** — CleanCloud assumes `CleanCloudReadOnlyRole` in each target account using STS. No persistent access, no stored credentials.
- **Three discovery modes** — `.cleancloud/accounts.yaml` for explicit control, `--accounts` for quick ad-hoc scans, `--org` for full AWS Organizations auto-discovery.
- **Efficient region detection** — active regions are discovered once on the hub account and reused across all spokes. Without this: N accounts × 160 API calls just for region probing. With it: 160 calls once.
- **Parallel with isolation** — each account runs in its own thread with its own session. One account failing (AccessDenied, timeout) never affects the others.
- **Partial-success visibility** — if 2 regions fail and 7 succeed within an account, the account is marked `partial` with the failed regions named. You see exactly what was missed, not just a binary pass/fail.
- **Live progress** — `[3/50] done production (123456789012) — 47s, 12 findings` printed as each account completes.
- **Per-account cost breakdown** — JSON output includes estimated monthly waste per account, sortable and scriptable.

Full setup guide (IAM policy, trust policy, IaC templates): [AWS multi-account setup →](docs/aws.md#multi-account-scanning)

---

## Multi-Subscription Scanning (Azure)

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

---

## Multi-Project Scanning (GCP)

Built for teams running multiple GCP projects. Scan all accessible projects in parallel with one identity — findings aggregated into one report with a per-project cost breakdown.

```bash
# Scan all projects the identity can access (default — uses ADC project discovery)
cleancloud scan --provider gcp --all-projects

# Scan specific projects
cleancloud scan --provider gcp --project my-project-123 --project another-project-456

# With region filter
cleancloud scan --provider gcp --all-projects --region us-central1
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

All are included in `roles/compute.viewer`, `roles/cloudsql.viewer`, and `roles/monitoring.viewer`. For CI/CD, use Workload Identity Federation — see [GCP setup →](docs/gcp.md).

**How it works:**

- **Application Default Credentials** — uses the standard GCP auth chain: `GOOGLE_APPLICATION_CREDENTIALS` → gcloud ADC → Workload Identity → metadata server attached service account. No proprietary auth mechanism.
- **Auto-discovery** — with `--all-projects`, CleanCloud enumerates all ACTIVE projects the identity has access to via the Resource Manager API. With `--project`, only the specified projects are scanned.
- **Parallel with isolation** — each project runs in its own thread. One project failing (permission denied, API not enabled) never affects the others.
- **Graceful degradation** — rules that fail with 403 are recorded as skipped (with the missing permission named), not as scan failures. The Cloud SQL rule is silently skipped if the SQL Admin API is not enabled.
- **Per-project cost breakdown** — output shows estimated monthly waste per project.

Full setup guide: [GCP setup →](docs/gcp.md)

---

## Roadmap

**Policy-as-code** — `cleancloud.yaml` with rule packs, per-team exceptions, and cost thresholds in config — the top FinOps governance ask for 2025/2026

**More AWS rules** — S3 lifecycle gaps, AI/GPU waste (idle SageMaker endpoints, orphaned GPU instances), Redshift idle, idle load balancers (ALB/NLB with zero traffic), NAT Gateway cost leakage (internal services routing through NAT instead of VPC endpoints — S3, DynamoDB, ECR, SSM), unused VPC endpoints

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
- [`docs/example-outputs.md`](docs/example-outputs.md) — Full output examples
- [`SECURITY.md`](SECURITY.md) — Security policy and threat model
- [`docs/infosec-readiness.md`](docs/infosec-readiness.md) — IAM Proof Pack, threat model

---

**Found a bug?** [Open an issue](https://github.com/cleancloud-io/cleancloud/issues)

**Feature request?** [Start a discussion](https://github.com/cleancloud-io/cleancloud/discussions)

**Questions?** suresh@getcleancloud.com

[MIT License](LICENSE)
