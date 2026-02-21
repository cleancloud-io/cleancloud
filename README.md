# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Security Scanning](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml)
![GitHub stars](https://img.shields.io/github/stars/cleancloud-io/cleancloud?style=social)

**CleanCloud is a safe, read-only cloud hygiene tool for teams that can't afford to break production.**

CleanCloud helps SRE and platform teams **safely identify orphaned, untagged, and inactive cloud resources** — and **enforce cost hygiene as a CI/CD gate** so findings don't sit in a report no one acts on. Built for AWS and Azure, safe to run in production, CI/CD pipelines, and regulated environments.

- **Read-only by design** — No deletions, no tag modifications, no resource changes
- **Conservative detection** — Multiple signals with explicit confidence levels (LOW/MEDIUM/HIGH)
- **CI/CD enforcement** — Fail builds on findings with `--fail-on-confidence HIGH` (safe by default, opt-in strict)
- **Zero telemetry** — No phone-home, no data collection, no analytics

### Why CleanCloud exists

Most cost tools require write access, send data to SaaS platforms, and generate reports no one acts on. CleanCloud is different:
- **Read-only** — your cloud provider enforces it, not us
- **Runs in your environment** — no data leaves your account
- **Enforces in CI/CD** — findings become gates, not backlog

```bash
pipx install cleancloud

# AWS
cleancloud scan --provider aws --all-regions

# Azure
cleancloud scan --provider azure
```

### How it works

```
Your Cloud Account          CleanCloud (pip install)         Your CI/CD Pipeline
(AWS / Azure)               (read-only scan)                 (GitHub Actions, etc.)

IAM Role       ──────────►   cleancloud scan    ──────────►  Findings (JSON/CSV/human)
(Reader only)               - 20 detection rules                      │
No write access             - Confidence scoring                      ▼
OIDC temporary tokens       - Evidence per finding           --fail-on-confidence HIGH
                                                             Exit 0 = pass
                                                             Exit 2 = policy violation
```

### Evaluating CleanCloud for enterprise use?

CleanCloud is designed for production environments where 
- Write access is prohibited, 
- InfoSec review is mandatory,
- CI/CD enforcement is required and
- data cannot leave the cloud account.

If your team is assessing cloud cost governance or hygiene controls, we can support:
- Security reviews and IAM validation
- CI/CD rollout design
- Multi-account architecture discussions

**[Start an evaluation discussion](https://www.getcleancloud.com/#contact)**

---

## Commands at a Glance

### `doctor` — Validate credentials and permissions

Checks authentication, security grade, and read-only permissions before you scan. Run this first.

```bash
# AWS — validates IAM credentials, auth method, and all required permissions
# Defaults to us-east-1 if --region is not specified
cleancloud doctor --provider aws

# AWS — validate against a specific region
cleancloud doctor --provider aws --region us-west-2

# Azure — validates credentials, subscription access, and Reader role permissions
# --region is not applicable for Azure doctor
cleancloud doctor --provider azure
```

Sample output (AWS — CI/CD with OIDC):
```
Authentication Method: OIDC (AssumeRoleWithWebIdentity)
[OK] Security Grade: EXCELLENT
[OK]   - Temporary credentials
[OK]   - Auto-rotated
Permissions Tested: 14/14 passed
[OK] AWS ENVIRONMENT READY FOR CLEANCLOUD
```

Sample output (Azure — CI/CD with Workload Identity):
```
Authentication Method: OIDC (Workload Identity Federation)
[OK] Security Grade: EXCELLENT
[OK]   - No client secrets stored
[OK]   - Temporary credentials
Subscriptions: 2 accessible
[OK] AZURE ENVIRONMENT READY FOR CLEANCLOUD
```

> Local development uses AWS CLI profiles (ACCEPTABLE) or service principals (POOR). Doctor will recommend upgrading to OIDC. See [`docs/example-outputs.md`](docs/example-outputs.md) for full output examples.

### `scan` — Find orphaned and idle resources

Scans your cloud account for unattached volumes, idle gateways, untagged resources, and more. Read-only, safe for production. See all [20 rules across AWS and Azure](docs/rules.md).

```bash
# AWS — single region
cleancloud scan --provider aws --region us-east-1

# AWS — all regions with active resources (auto-detected)
cleancloud scan --provider aws --all-regions

# Azure — all accessible subscriptions (default)
cleancloud scan --provider azure

# Azure — specific subscription
cleancloud scan --provider azure --subscription <subscription-id>

# Azure — filter by location
cleancloud scan --provider azure --region eastus

# Output formats — feed into dashboards (Grafana, Datadog, etc.) or automation
cleancloud scan --provider aws --all-regions --output json --output-file results.json
cleancloud scan --provider azure --output csv --output-file results.csv

# Exclude resources by tag
cleancloud scan --provider aws --all-regions --ignore-tag env:production
cleancloud scan --provider aws --all-regions --config cleancloud.yaml
```

### Enforce policies in CI/CD

By default, scans exit `0` even with findings (safe for any pipeline). Opt in to enforcement with these flags:

| Flag | Behavior | Exit code |
|------|----------|-----------|
| *(none)* | Report findings, never fail | `0` |
| `--fail-on-confidence HIGH` | Fail only on HIGH confidence findings | `2` |
| `--fail-on-confidence MEDIUM` | Fail on MEDIUM or higher | `2` |
| `--fail-on-confidence LOW` | Fail on any confidence level | `2` |
| `--fail-on-findings` | Fail on any finding (strict mode) | `2` |

```bash
# AWS — fail CI on HIGH confidence findings only (recommended starting point)
cleancloud scan --provider aws --all-regions --fail-on-confidence HIGH

# Azure — fail CI on MEDIUM or higher
cleancloud scan --provider azure --fail-on-confidence MEDIUM

# Strict mode — fail on any finding
cleancloud scan --provider aws --all-regions --fail-on-findings

# Full CI/CD example: OIDC auth, JSON output, enforce HIGH confidence
cleancloud scan --provider aws --all-regions \
  --output json --output-file scan.json \
  --fail-on-confidence HIGH
```

---

## Table of Contents

- [Commands at a Glance](#commands-at-a-glance)
- [See It In Action](#see-it-in-action)
- [What CleanCloud Detects](#what-cleancloud-detects)
- [Installation](#installation)
- [Try It Locally](#try-it-locally-2-minutes)
- [CI/CD Pipelines](#running-in-cicd-pipelines)
- [Security & Trust](#security--trust)
- [Tag-Based Filtering](#tag-based-filtering)
- [Enterprise & Production Use](#built-for-production--enterprise-use)
- [Who This Is For](#who-cleancloud-is-and-is-not-for)
- [Why Teams Choose CleanCloud](#why-teams-choose-cleancloud)
- [Design Philosophy](#design-philosophy)
- [Documentation](#documentation)

---

## See It In Action

### `cleancloud scan --provider aws --all-regions` — Find what's costing you money

```
Found 6 hygiene issues:

1. [AWS] Unattached EBS Volume
   Risk       : Low
   Confidence : High
   Resource   : aws.ebs.volume → vol-0a1b2c3d4e5f67890
   Region     : us-east-1
   Rule       : aws.ebs.volume.unattached
   Reason     : Volume has been unattached for 47 days
   Detected   : 2026-02-08T14:32:01+00:00
   Details:
     - size_gb: 500
     - availability_zone: us-east-1a
     - state: available
     - tags: {"Project": "legacy-api", "Owner": "platform"}

2. [AWS] Idle NAT Gateway
   Risk       : Medium
   Confidence : Medium
   Resource   : aws.ec2.nat_gateway → nat-0abcdef1234567890
   Region     : us-west-2
   Rule       : aws.ec2.nat_gateway.idle
   Reason     : No traffic detected for 21 days
   Detected   : 2026-02-08T14:32:04+00:00
   Details:
     - name: staging-nat
     - state: available
     - vpc_id: vpc-0abc123
     - total_bytes_out: 0
     - total_bytes_in: 0
     - estimated_monthly_cost_usd: 32.40
     - idle_threshold_days: 14

3. [AWS] Unattached Elastic IP
   Risk       : Low
   Confidence : High
   Resource   : aws.ec2.elastic_ip → eipalloc-0a1b2c3d4e5f6
   Region     : eu-west-1
   Rule       : aws.ec2.elastic_ip.unattached
   Reason     : Elastic IP not associated with any instance or ENI (age: 92 days)
   Detected   : 2026-02-08T14:32:06+00:00
   Details:
     - public_ip: 52.18.xxx.xxx
     - domain: vpc
     - age_days: 92

--- Scan Summary ---
Total findings: 6
By risk:    low: 5  medium: 1
By confidence:  high: 2  medium: 4
Minimum estimated waste: ~$147/month
(4 of 6 findings costed)
Regions scanned: us-east-1, us-west-2, eu-west-1 (auto-detected)

```

> **New in v1.5:** Cost impact summary with estimated monthly waste per finding and aggregate totals.

### `cleancloud scan --provider azure` — Azure scan output

```
Found 5 hygiene issues:

1. [AZURE] Unattached Managed Disk
   Risk       : Low
   Confidence : Medium
   Resource   : azure.compute.disk → data-disk-legacy-api
   Region     : eastus
   Rule       : azure.unattached_disk
   Reason     : Managed disk not attached to any VM (age: 34 days)
   Detected   : 2026-02-08T14:45:12+00:00
   Details:
     - size_gb: 256
     - disk_state: Unattached
     - subscription: Production

2. [AZURE] Unused Public IP
   Risk       : Low
   Confidence : High
   Resource   : azure.network.public_ip → pip-old-gateway
   Region     : westeurope
   Rule       : azure.public_ip_unused
   Reason     : Public IP not associated with any resource
   Detected   : 2026-02-08T14:45:13+00:00
   Details:
     - ip_address: 20.82.xxx.xxx
     - allocation_method: Static
     - subscription: Staging

3. [AZURE] Load Balancer with No Backends
   Risk       : Medium
   Confidence : High
   Resource   : azure.network.load_balancer → lb-deprecated-service
   Region     : eastus
   Rule       : azure.lb_no_backends
   Reason     : Load balancer has no backend pools configured
   Detected   : 2026-02-08T14:45:14+00:00
   Details:
     - sku: Standard
     - subscription: Production

--- Scan Summary ---
Total findings: 5
By risk:    low: 4  medium: 1
By confidence:  high: 3  medium: 2
Minimum estimated waste: ~$72/month
(3 of 5 findings costed)
Subscriptions scanned: Production, Staging (all accessible)
```

> Every finding includes confidence levels and evidence so your team reviews with context — not guesswork.

For full output examples including doctor validation, JSON, and CSV formats, see [`docs/example-outputs.md`](docs/example-outputs.md).

---

## What CleanCloud Detects

20 high-signal rules across AWS and Azure — each read-only, conservative, and designed to avoid false positives in IaC environments.

**Understanding confidence levels:**
- **HIGH** — Single definitive signal with very low false-positive risk (e.g., a volume is unattached, an IP has no association)
- **MEDIUM** — Time-based heuristics or multiple signals required (e.g., no traffic for 14+ days, snapshot age exceeds threshold)

> **Disagree with a confidence level?** You control the enforcement threshold with `--fail-on-confidence`. Start with `HIGH` to only catch the most obvious waste, then tighten to `MEDIUM` as your team validates. You can also exclude specific resources using [tag-based filtering](#tag-based-filtering).

| Provider | Rule | What It Finds | Confidence |
|----------|------|---------------|------------|
| AWS | Unattached EBS Volumes | Volumes not attached to any instance | HIGH |
| AWS | Old EBS Snapshots | Snapshots older than 90 days | MEDIUM |
| AWS | Infinite Retention Logs | CloudWatch log groups that never expire | MEDIUM |
| AWS | Unattached Elastic IPs | EIPs not associated with any resource (30+ days) | HIGH |
| AWS | Detached ENIs | Network interfaces detached for 60+ days | MEDIUM |
| AWS | Untagged Resources | EBS volumes, S3 buckets, log groups with no tags | MEDIUM |
| AWS | Old AMIs | AMIs older than 180 days with snapshot storage costs | MEDIUM |
| AWS | Idle NAT Gateways | NAT Gateways with zero traffic for 14+ days (~$32/mo each) | MEDIUM |
| AWS | Idle RDS Instances | RDS instances with zero connections for 14+ days | HIGH |
| AWS | Idle Elastic Load Balancers | ALB/NLB/CLB with zero traffic for 14+ days | HIGH |
| Azure | Unattached Managed Disks | Disks not attached to any VM | MEDIUM |
| Azure | Old Snapshots | Snapshots exceeding age threshold | MEDIUM |
| Azure | Unused Public IPs | Public IPs with no configuration attached | HIGH |
| Azure | Empty Load Balancers | Load balancers with no backend pools | HIGH |
| Azure | Empty App Gateways | Application gateways with no backends | HIGH |
| Azure | Empty App Service Plans | App Service Plans with no web apps | HIGH |
| Azure | Idle VNet Gateways | Virtual Network Gateways with no active connections | MEDIUM |
| Azure | Stopped (Not Deallocated) VMs | VMs stopped but still incurring full compute charges | HIGH |
| Azure | Idle SQL Databases | SQL databases with zero connections for 14+ days | HIGH |
| Azure | Untagged Resources | Resources with no tags attached | MEDIUM |

**See [`docs/rules.md`](docs/rules.md) for full details, signals used, and evidence documentation.**

### Enforce these findings in CI/CD

Every rule above produces findings with a confidence level (LOW/MEDIUM/HIGH). Use that to set your enforcement threshold:

```bash
# Fail only on HIGH confidence findings (recommended starting point)
cleancloud scan --provider aws --all-regions --fail-on-confidence HIGH

# Tighten over time — fail on MEDIUM or higher
cleancloud scan --provider azure --fail-on-confidence MEDIUM

# Strictest — fail on any finding regardless of confidence
cleancloud scan --provider aws --all-regions --fail-on-findings
```

Start with `HIGH` to catch the obvious waste (unattached EBS volumes, unused public IPs, empty load balancers), then tighten to `MEDIUM` as your team cleans up. See [all enforcement options](#enforce-policies-in-cicd) for the full flag reference.

---

## Installation

### Quick Install
```bash
pipx install cleancloud
```

### Don't have pipx?

**macOS:**
```bash
brew install pipx
pipx install cleancloud
```

**Linux:**
```bash
sudo apt install pipx  # Ubuntu/Debian
pipx install cleancloud
```

**Windows:**
```powershell
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install cleancloud
```

### CI/CD Environments
```bash
pip install cleancloud
```

### Troubleshooting

<details>
<summary>Command not found: pip</summary>

```bash
pip3 install cleancloud
# or
python3 -m pip install cleancloud
```
</details>

<details>
<summary>externally-managed-environment error</summary>

Use `pipx` (see above) — this is the modern way to install Python CLI tools.
</details>

<details>
<summary>Command not found: cleancloud (after pipx install)</summary>

pipx installs to `~/.local/bin` which may not be on your PATH:
```bash
pipx ensurepath
source ~/.zshrc   # macOS (zsh)
source ~/.bashrc  # Linux (bash)
```

Then verify:
```bash
cleancloud --version
```
</details>

<details>
<summary>'cleancloud' already seems to be installed</summary>

If you previously installed an older version, reinstall with `--force`:
```bash
pipx install cleancloud --force
```
</details>

### Verify Installation
```bash
cleancloud --version
```

---

## Try It Locally (2 minutes)

Start here. No OIDC or CI/CD setup needed — just your existing cloud credentials.

### AWS

**Option A: AWS CLI** (if you already have `aws configure` set up)
```bash
# Your existing AWS CLI credentials work — no extra setup
cleancloud doctor --provider aws
cleancloud scan --provider aws --region us-east-1
```

**Option B: Environment variables**
```bash
export AWS_ACCESS_KEY_ID=<your-access-key>
export AWS_SECRET_ACCESS_KEY=<your-secret-key>
export AWS_DEFAULT_REGION=us-east-1

cleancloud doctor --provider aws
cleancloud scan --provider aws --region us-east-1
```

**Permissions required:** Your IAM user/role needs 14 read-only permissions (`ec2:Describe*`, `rds:Describe*`, `s3:List*`, etc.). The `doctor` command will tell you exactly which permissions are missing. Full IAM policy: [`docs/aws.md`](docs/aws.md)

### Azure

**Option A: Azure CLI** (if you already have `az login` set up)
```bash
# Your existing Azure CLI session works — no extra setup
cleancloud doctor --provider azure
cleancloud scan --provider azure
```

**Option B: Service principal**
```bash
export AZURE_CLIENT_ID=<your-client-id>
export AZURE_TENANT_ID=<your-tenant-id>
export AZURE_CLIENT_SECRET=<your-client-secret>
export AZURE_SUBSCRIPTION_ID=<your-subscription-id>

cleancloud doctor --provider azure
cleancloud scan --provider azure
```

**Permissions required:** `Reader` role at subscription scope (built-in, no custom definition needed). Full RBAC setup: [`docs/azure.md`](docs/azure.md)

### View Results

```bash
# Human-readable (default)
cleancloud scan --provider aws --all-regions

# JSON — feed into dashboards or automation
cleancloud scan --provider aws --all-regions --output json --output-file results.json

# CSV — for spreadsheet review
cleancloud scan --provider azure --output csv --output-file results.csv
```

**JSON Output Schema:** Versioned (`1.0.0`) with backward compatibility. See [`docs/example-outputs.md`](docs/example-outputs.md) for complete examples.

> **Ready to enforce in CI/CD?** Once local scans look right, set up OIDC and add enforcement flags. See the next section.

---

## Running in CI/CD Pipelines

Graduate from local scans to automated enforcement. This requires a one-time OIDC setup (~5 minutes) so your pipeline can authenticate without long-lived secrets.

### Prerequisites

Follow the step-by-step setup guide for your provider:

- **AWS**: [`docs/aws.md`](docs/aws.md) — Create IAM role with OIDC trust, attach read-only policy, add GitHub variable
- **Azure**: [`docs/azure.md`](docs/azure.md) — Create app registration with Workload Identity Federation, assign Reader role, add GitHub secrets

> No long-lived secrets needed — OIDC provides temporary credentials that auto-rotate every run.

### AWS — GitHub Actions with OIDC

```yaml
# .github/workflows/cleancloud.yml
- name: Configure AWS credentials (OIDC)
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
    aws-region: us-east-1

- name: Install CleanCloud
  run: pip install cleancloud

- name: Validate AWS permissions
  run: cleancloud doctor --provider aws --region us-east-1

- name: Scan and enforce
  run: |
    cleancloud scan --provider aws --region us-east-1 \
      --output json --output-file scan.json \
      --fail-on-confidence HIGH
```

> Use `--all-regions` instead of `--region us-east-1` to scan all regions with active resources.

### Azure — GitHub Actions with Workload Identity

```yaml
# .github/workflows/cleancloud.yml
- name: Azure Login (OIDC)
  uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

- name: Install CleanCloud
  run: pip install cleancloud

- name: Validate Azure permissions
  run: cleancloud doctor --provider azure

- name: Scan and enforce
  run: |
    cleancloud scan --provider azure \
      --output json --output-file scan.json \
      --fail-on-confidence MEDIUM
```

### What enforcement looks like

- **No findings or below threshold** — exit `0`, pipeline continues
- **Findings at or above threshold** — exit `2`, pipeline fails with a summary of violations
- **No flags** — exit `0` always (safe for scheduled scans and exploratory runs)

**Complete CI/CD guide:** [`docs/ci.md`](docs/ci.md) — GitHub Actions workflow examples (AWS, Azure, multi-cloud), OIDC setup, enforcement patterns, output formats, tag filtering, and troubleshooting.

---

## Security & Trust

CleanCloud is designed for enterprise environments where security review and approval are required.

### Why InfoSec Teams Trust CleanCloud

**Verifiable Read-Only Design:**
- **IAM Proof Pack**: Audit a concise JSON policy, not our code
- **OIDC-First**: Temporary credentials, no secrets stored
- **Cloud-Enforced**: AWS/Azure guarantees read-only, not us
- **Conservative Detection**: MEDIUM confidence by default, age thresholds, explicit evidence

**How It Works:**
1. You create a read-only IAM role (we provide the JSON policy)
2. Run our verification script to prove it's safe
3. CleanCloud scans using temporary OIDC tokens
4. Results are yours - we never see your data

**The Trust Model:**
> "By requiring a separate, verifiable Read-Only IAM role, CleanCloud shifts trust from our code to your Cloud Provider's enforcement. InfoSec teams don't need to audit our Python code line-by-line—they audit a concise JSON policy and verify it's read-only."

### Read-Only by Design

**No destructive permissions required:**
- Only `List*`, `Describe*`, `Get*` operations
- No `Delete*`, `Modify*`, or `Tag*` permissions
- No resource mutations or state changes
- Safe for production accounts and regulated environments

**IAM Proof Pack:** [Ready-to-use policies and verification scripts](security/) with automated safety tests

### OIDC-First Authentication

**No long-lived credentials:**
- AWS IAM Roles with GitHub Actions OIDC (recommended)
- Azure Workload Identity Federation (recommended)
- Short-lived tokens only
- No stored credentials in CI/CD

### Privacy Guarantees

**Zero telemetry, zero outbound calls:**
- No analytics or usage tracking
- No phone-home or update checks
- No data collection of any kind
- Only AWS/Azure API calls (read-only)

### Safety Regression Tests

**Multi-layer verification:**
- Static AST analysis blocks forbidden SDK calls
- Runtime SDK guards prevent mutations in tests
- IAM policy validation ensures read-only access
- Runs automatically in CI for all PRs

**For InfoSec Teams:**
- [Security Policy & Threat Model](SECURITY.md) - **Enterprise security documentation**
- [Information Security Readiness Guide](docs/infosec-readiness.md)
- [IAM Proof Pack Documentation](docs/infosec-readiness.md#iam-proof-pack)
- [Threat Model & Mitigations](docs/infosec-readiness.md#threat-model)
- [Safety Test Documentation](docs/safety.md)

---

## Tag-Based Filtering

CleanCloud supports tag-based filtering to reduce noise by ignoring findings for resources you explicitly mark. Useful when certain environments, teams, or services should be out of scope for hygiene review.

> **Note:** Tag filtering is **ignore-only** — it does not disable rules, modify resources, or protect them from deletion. CleanCloud remains read-only.

### Config file (`cleancloud.yaml`)

Create a `cleancloud.yaml` file in your project root (or specify a custom path with `--config`):

```yaml
version: 1

tag_filtering:
  enabled: true
  ignore:
    - key: env
      value: production
    - key: team
      value: platform
    - key: keep   # key-only match (any value)
```

```bash
cleancloud scan --provider aws --region us-east-1 --config cleancloud.yaml
```

### CLI overrides (highest priority)

```bash
cleancloud scan --provider aws --region us-east-1 \
  --ignore-tag env:production \
  --ignore-tag team:platform
```

**Important:** CLI `--ignore-tag` replaces YAML configuration — they are not merged. This ensures CI/CD runs are explicit and predictable.

### Behavior

- If a resource has any matching tag, its finding is ignored
- Matching is exact (no regex, no partial matches)
- Multiple ignore rules are OR'ed (any match ignores)
- Ignored findings are counted and reported in the summary for auditability

```
Ignored by tag policy: 7 findings
```

Tag filtering works best with broad ownership or scope tags (`env`, `team`, `service`) — not per-resource exceptions.

---

## Built for Production & Enterprise Use

CleanCloud is designed to be approved by security teams, not bypassed.

> **Most FinOps tools generate reports that no one acts on.** CleanCloud closes the loop with `--fail-on-confidence HIGH` — turning findings into CI/CD gates that block deployment until the waste is resolved. Detection *and* enforcement, without touching your infrastructure.

### Enterprise Features
- **Read-only by design** - No Delete*, Modify*, or Tag* permissions required
- **OIDC-first authentication** - AWS IAM Roles & Azure Workload Identity
- **Parallel, multi-region scanning** - Fast execution across all regions
- **CI/CD native** - Stable exit codes, JSON/CSV output, policy enforcement
- **Audit-friendly** - Deterministic output, no side effects, versioned schemas

### Stability Guarantees
- **CLI backward compatibility** within major versions
- **Exit codes are stable and intentional** - Never fails builds by accident
- **JSON schemas are versioned** - Safe to parse programmatically
- **Read-only always** - Safety regression tests in CI

### Exit Codes

**Safe by Default:** CleanCloud reports findings but exits with code `0` (success) unless you explicitly configure failure conditions.

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (default: findings reported but don't fail) |
| `1` | Configuration error, invalid region/location, or unexpected error |
| `2` | Policy violation (only when using `--fail-on-findings` or `--fail-on-confidence`) |
| `3` | Missing permissions or invalid credentials |

See [Enforce policies in CI/CD](#enforce-policies-in-cicd) for usage examples.

---

## Who CleanCloud Is (and Is Not) For

**Built for teams who operate at scale:**
- **Cloud Architects** designing cost-governance frameworks across accounts and subscriptions
- **SRE / Platform teams** who need safe, scheduled hygiene evaluation in production
- **FinOps teams** building resource accountability without tooling risk
- **Security-reviewed environments** where mutations are prohibited and tooling must pass InfoSec review
- **CI/CD pipelines** enforcing cost hygiene as a gate — without infrastructure changes

**CleanCloud is NOT:**
- An automated cleanup or deletion service
- A replacement for Trusted Advisor, Azure Advisor, or Config
- A cost dashboard with rightsizing recommendations
- A tool that modifies, tags, or deletes resources

---

## Why Teams Choose CleanCloud

### Cost Optimization Without Compromising Safety

Most cost tools require write access, agent installation, or SaaS data sharing. CleanCloud takes a different approach: **read-only evaluation that your InfoSec team can approve in an afternoon.**

| Need | Cost Dashboards | Cleanup Automation | CleanCloud |
|------|-----------------|-------------------|------------|
| **Spending trends** | Excellent | Not a goal | Not a goal |
| **Orphaned resource detection** | Limited or noisy | Aggressive | Conservative, high-signal |
| **Safe for production** | Varies | Risk of deletion | Read-only always |
| **CI/CD cost enforcement** | Not designed for it | Risky | Purpose-built |
| **Confidence scoring** | Binary yes/no | Binary yes/no | LOW/MEDIUM/HIGH |
| **InfoSec approval** | Varies | Difficult | Designed for it |
| **Telemetry / data sharing** | Usually required | Usually required | Zero — fully private |

### CleanCloud Complements Your Existing Stack

- Use **AWS Cost Explorer / Azure Cost Management** to track spending trends
- Use **Trusted Advisor / Azure Advisor** for rightsizing recommendations
- Use **CleanCloud** to find orphaned resources your other tools miss — safely — and enforce it as a CI/CD gate

> **Cost dashboards show you what you're spending.**
> **CleanCloud shows you what you can safely stop spending — and blocks deploys until you do.**

**Learn more:** [Where CleanCloud Fits (design diagram)](docs/design.md#where-cleancloud-fits)

---

## Design Philosophy

CleanCloud is built on four core principles:

**1. Conservative by Default** - Multiple signals with explicit confidence levels (LOW/MEDIUM/HIGH) reduce false positives

**2. Read-Only Always** - No Delete*, Tag*, or Modify* permissions; safe for production

**3. Enforce, Don't Just Report** - CI/CD gates with `--fail-on-confidence` turn findings into action, not backlog

**4. Review-Ready Findings** - Every finding includes evidence and confidence so teams can act with context, not guesswork

**Learn more:** [Confidence logic documentation](docs/confidence.md)

---

## Roadmap

> Roadmap items are added only after conservative signal design and safety review.

### Coming Soon
- GCP support (read-only, parity with existing trust guarantees)
- Additional AWS rules (empty security groups)
- Additional Azure rules (unused NICs, old images)
- Rule filtering (`--rules` flag)
- Multi-account scanning (AWS Organizations support)

### Not Planned
These are intentional non-goals to preserve safety and trust.

- Automated cleanup or deletion
- Rightsizing or instance optimization suggestions
- Billing data access or spending analysis
- Resource tagging or mutations

CleanCloud will remain focused on **safe cost optimization through hygiene detection and CI/CD enforcement**, not automation or infrastructure changes.

---

## Documentation

- [`SECURITY.md`](SECURITY.md) - **Security policy and threat model for enterprise evaluation**
- [`docs/infosec-readiness.md`](docs/infosec-readiness.md) - Information security readiness guide for enterprise teams
- [`security/`](security/) - IAM Proof Pack (ready-to-use policies and verification scripts)
- [`docs/rules.md`](docs/rules.md) - Detailed rule behavior and signals
- [`docs/aws.md`](docs/aws.md) - AWS setup and IAM policy
- [`docs/azure.md`](docs/azure.md) - Azure setup and RBAC configuration
- [`docs/ci.md`](docs/ci.md) - CI/CD integration examples
- [`docs/example-outputs.md`](docs/example-outputs.md) - Full output examples (doctor, scan, JSON) for AWS and Azure

---

## Early Adopters

CleanCloud is currently being evaluated by:

- Platform teams in regulated environments
- Financial services companies
- Government cloud workloads

**Want to evaluate CleanCloud in your environment?**  
Start a conversation: https://www.getcleancloud.com/#contact
---

## Questions or Feedback?

We'd love to hear from you:

- **Found a bug?** [Open an issue](https://github.com/cleancloud-io/cleancloud/issues)
- **Have a feature request?** [Start a discussion](https://github.com/cleancloud-io/cleancloud/discussions)
- **Want to chat?** Email us at suresh@getcleancloud.com
- **Like CleanCloud?** [Star us on GitHub](https://github.com/cleancloud-io/cleancloud)

**Using CleanCloud in production?** We'd love to feature your story!

## Contributing

Contributions are welcome! Please ensure all PRs:
- Include tests for new rules
- Follow the conservative design philosophy
- Maintain read-only operation
- Include documentation updates

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## License

[MIT License](LICENSE)

---