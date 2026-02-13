# CleanCloud

**Safe, read-only cloud hygiene for teams that can't afford to break production.**

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Security Scanning](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml)
![GitHub stars](https://img.shields.io/github/stars/cleancloud-io/cleancloud?style=social)

CleanCloud helps SRE and platform teams **safely identify orphaned, untagged, and inactive cloud resources** with the ownership context and risk confidence to **act today, not next month** using conservative, read-only checks designed for trust, not auto-cleanup. 

Built for AWS and Azure, safe to run in production, CI/CD pipelines, and regulated environments.

- **Read-only by design** — No deletions, no tag modifications, no resource changes
- **Conservative detection** — Multiple signals with explicit confidence levels (LOW/MEDIUM/HIGH)
- **Zero telemetry** — No phone-home, no data collection, no analytics

```bash
pip install cleancloud

# AWS
cleancloud doctor --provider aws
cleancloud scan --provider aws --region us-east-1

# Azure
cleancloud doctor --provider azure
cleancloud scan --provider azure
```

---

## Table of Contents

- [See It In Action](#see-it-in-action)
- [Quick Start](#quick-start)
- [What CleanCloud Detects](#what-cleancloud-detects)
- [Who This Is For](#who-cleancloud-is-and-is-not-for)
- [Security & Trust](#security--trust)
- [Enterprise & Production Use](#built-for-production--enterprise-use)
- [CI/CD Pipelines](#running-in-cicd-pipelines)
- [Configuration](#configuration)
- [Why Teams Choose CleanCloud](#why-teams-choose-cleancloud)
- [Design Philosophy](#design-philosophy)
- [Documentation](#documentation)

---

## See It In Action

### `cleancloud doctor --provider aws` — Validate your environment in seconds

```
======================================================================
AWS ENVIRONMENT VALIDATION
======================================================================

Step 1: AWS Credential Resolution
----------------------------------------------------------------------
[OK] AWS session created successfully

Step 2: Authentication Method Detection
----------------------------------------------------------------------
Authentication Method: OIDC (AssumeRoleWithWebIdentity)
  Boto3 Provider: assume-role-with-web-identity
  Credential Type: Temporary
  Lifetime: 1 hour (temporary)
  Rotation Required: No (auto-rotated)

[OK] Security Grade: EXCELLENT
[OK]   - Temporary credentials
[OK]   - Auto-rotated
[OK]   - No secret storage required

[OK] CI/CD Ready: YES

Step 3: Identity Verification
----------------------------------------------------------------------
[OK] Account ID: 123456789012
[OK] ARN: arn:aws:sts::123456789012:assumed-role/CleanCloudCIReadOnly/github-actions

Step 4: Read-Only Permission Validation
----------------------------------------------------------------------
[OK] ec2:DescribeVolumes
[OK] ec2:DescribeSnapshots
[OK] ec2:DescribeRegions
[OK] ec2:DescribeAddresses
[OK] ec2:DescribeNetworkInterfaces
[OK] ec2:DescribeImages
[OK] ec2:DescribeNatGateways
[OK] logs:DescribeLogGroups
[OK] cloudwatch:GetMetricStatistics
[OK] s3:ListAllMyBuckets
[OK] s3:GetBucketTagging

======================================================================
VALIDATION SUMMARY
======================================================================
Authentication: OIDC (AssumeRoleWithWebIdentity)
Security Grade: EXCELLENT
Permissions Tested: 11/11 passed

[OK] AWS ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

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

3. [AWS] Old AMI
   Risk       : Low
   Confidence : Medium
   Resource   : aws.ec2.ami → ami-0fedcba9876543210
   Region     : us-east-1
   Rule       : aws.ec2.ami.old
   Reason     : AMI is 243 days old with 3 associated snapshots (85.0 GB)
   Detected   : 2026-02-08T14:32:05+00:00
   Details:
     - ami_name: backend-v2.3.1-2025-06-10
     - age_days: 243
     - snapshot_count: 3
     - total_size_gb: 85.0
     - estimated_monthly_cost_usd: 4.25

4. [AWS] Unattached Elastic IP
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

5. [AWS] CloudWatch Log Group with Infinite Retention
   Risk       : Low
   Confidence : Medium
   Resource   : aws.cloudwatch.log_group → /aws/lambda/legacy-processor
   Region     : us-east-1
   Rule       : aws.cloudwatch.logs.infinite_retention
   Reason     : Log group has no retention policy (never expires)
   Detected   : 2026-02-08T14:32:07+00:00
   Details:
     - stored_bytes: 8745213952
     - retention_days: Never expires

6. [AWS] Untagged Resource
   Risk       : Low
   Confidence : Medium
   Resource   : aws.s3.bucket → company-temp-uploads-2024
   Region     : global
   Rule       : aws.resource.untagged
   Reason     : S3 bucket has no tags
   Detected   : 2026-02-08T14:32:08+00:00

--- Scan Summary ---
Total findings: 6

By risk:
  low: 5
  medium: 1

By confidence:
  high: 2
  medium: 4

Regions scanned: us-east-1, us-west-2, eu-west-1 (auto-detected)
Scanned at: 2026-02-08T14:32:08+00:00
```

### `cleancloud doctor --provider azure` — Azure validation

```
======================================================================
AZURE ENVIRONMENT VALIDATION
======================================================================

Step 1: Azure Credential Resolution
----------------------------------------------------------------------
Authentication Method: OIDC (Workload Identity Federation)
  Lifetime: 1 hour (temporary)
  Rotation Required: No
[OK] Uses Secret: No (secretless)

[OK] Security Grade: EXCELLENT
[OK]   - No client secrets stored
[OK]   - Temporary credentials
[OK]   - Auto-rotated

[OK] CI/CD Ready: YES
[OK]   Suitable for production CI/CD pipelines

[OK] Compliance: SOC2/ISO27001 Compatible

Step 2: Credential Acquisition
----------------------------------------------------------------------
[OK] Azure credentials acquired successfully
  Token expires in: ~58 minutes

Step 3: Subscription Access Validation
----------------------------------------------------------------------
[OK] Accessible subscriptions: 2
  • Production (a1b2c3d4-e5f6-7890-abcd-ef1234567890)
  • Staging (f9e8d7c6-b5a4-3210-fedc-ba0987654321)

Step 4: Permission Validation
----------------------------------------------------------------------
[OK] Subscription read access confirmed
  Reader role provides all required permissions:
    - Microsoft.Compute/disks/read
    - Microsoft.Compute/snapshots/read
    - Microsoft.Network/publicIPAddresses/read
    - Microsoft.Web/serverfarms/read
    - Microsoft.Network/loadBalancers/read
    - Microsoft.Network/applicationGateways/read
    - Microsoft.Network/virtualNetworkGateways/read
    - Microsoft.Network/connections/read

======================================================================
VALIDATION SUMMARY
======================================================================
Authentication: OIDC (Workload Identity Federation)
Security Grade: EXCELLENT
Subscriptions: 2 accessible

[OK] AZURE ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

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

4. [AZURE] Empty App Service Plan
   Risk       : Low
   Confidence : High
   Resource   : azure.web.app_service_plan → plan-old-staging
   Region     : eastus2
   Rule       : azure.app_service_plan_empty
   Reason     : App Service Plan has no associated web apps
   Detected   : 2026-02-08T14:45:15+00:00
   Details:
     - sku: P1v3
     - subscription: Staging

5. [AZURE] Untagged Resource
   Risk       : Low
   Confidence : Medium
   Resource   : azure.compute.disk → temp-migration-disk
   Region     : eastus
   Rule       : azure.resource.untagged
   Reason     : Resource has no tags
   Detected   : 2026-02-08T14:45:16+00:00

--- Scan Summary ---
Total findings: 5

By risk:
  low: 4
  medium: 1

By confidence:
  high: 3
  medium: 2

Subscriptions scanned: Production, Staging (all accessible)
Scanned at: 2026-02-08T14:45:16+00:00
```

> Every finding includes confidence levels and evidence so your team reviews with context — not guesswork.

---

## Security & Trust

CleanCloud is designed for enterprise environments where security review and approval are required.

### Why InfoSec Teams Trust CleanCloud

**Verifiable Read-Only Design:**
- **IAM Proof Pack**: Audit a 30-line JSON policy, not our code
- **OIDC-First**: Temporary credentials, no secrets stored
- **Cloud-Enforced**: AWS/Azure guarantees read-only, not us
- **Conservative Detection**: MEDIUM confidence by default, age thresholds, explicit evidence

**How It Works:**
1. You create a read-only IAM role (we provide the JSON policy)
2. Run our verification script to prove it's safe
3. CleanCloud scans using temporary OIDC tokens
4. Results are yours - we never see your data

**The Trust Model:**
> "By requiring a separate, verifiable Read-Only IAM role, CleanCloud shifts trust from our code to your Cloud Provider's enforcement. InfoSec teams don't need to audit our Python code line-by-line—they audit a 30-line JSON policy and verify it's read-only."

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

CleanCloud exists to answer one question safely:

> **What orphaned resources are costing us money — without risking production?**


## Built for Production & Enterprise Use

CleanCloud is designed to be approved by security teams, not bypassed.

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

**Examples:**

```bash
# Default: Reports findings, exits 0 (safe for any pipeline)
cleancloud scan --provider aws --region us-east-1

# Fail on HIGH confidence findings only
cleancloud scan --provider aws --region us-east-1 --fail-on-confidence HIGH

# Fail on MEDIUM or higher confidence
cleancloud scan --provider aws --region us-east-1 --fail-on-confidence MEDIUM

# Fail on ANY findings (strict mode)
cleancloud scan --provider aws --region us-east-1 --fail-on-findings
```

## Quick Start

### Requirements

**Python:** 3.9 or later

**Cloud Access:**
- **AWS**: AWS CLI configured, or IAM role (for CI/CD), or environment variables
- **Azure**: Azure CLI authenticated, or Workload Identity (for CI/CD)

---

## Running Locally

Use CleanCloud locally for development, testing, and ad-hoc hygiene reviews.

### 1. Installation

```bash
pip install cleancloud
```

### 2. Set Up Credentials

**AWS:**
```bash
export AWS_ACCESS_KEY_ID=<your-access-key>
export AWS_SECRET_ACCESS_KEY=<your-secret-key>
export AWS_DEFAULT_REGION=us-east-1
```

**Azure:**
```bash
export AZURE_CLIENT_ID=<your-client-id>
export AZURE_TENANT_ID=<your-tenant-id>
export AZURE_CLIENT_SECRET=<your-client-secret>
export AZURE_SUBSCRIPTION_ID=<your-subscription-id>
```

> **Alternative methods:** AWS CLI profiles and Azure CLI are also supported. See [Configuration](#configuration) for details.

### 3. Validate Credentials

```bash
# AWS - validate credentials and permissions
# Defaults to us-east-1 if --region not specified
cleancloud doctor --provider aws
cleancloud doctor --provider aws --region us-west-2

# Azure - validate credentials and subscription access
# Note: --region parameter is not applicable for Azure doctor
cleancloud doctor --provider azure
```

### 4. Run a Scan

```bash
# AWS - single region
cleancloud scan --provider aws --region us-east-1

# AWS - all active regions (auto-detects regions with resources)
cleancloud scan --provider aws --all-regions

# Azure - all subscriptions (default)
cleancloud scan --provider azure

# Azure - specific subscription
cleancloud scan --provider azure --subscription <subscription-id>

# Azure - multiple subscriptions
cleancloud scan --provider azure --subscription <sub-id-1> --subscription <sub-id-2>

# Azure - filter by location
cleancloud scan --provider azure --region eastus

# Azure - specific subscription and location
cleancloud scan --provider azure --subscription <subscription-id> --region eastus
```

### 5. View Results

```bash
# Human-readable output (default)
cleancloud scan --provider aws --region us-east-1

# JSON output (AWS)
cleancloud scan --provider aws --region us-east-1 --output json --output-file results.json

# JSON output (Azure)
cleancloud scan --provider azure --output json --output-file results.json

# CSV output
cleancloud scan --provider aws --region us-east-1 --output csv --output-file results.csv
```

**JSON Output Schema:**

CleanCloud uses a versioned JSON schema (current: `1.0.0`). All JSON output includes a `schema_version` field for backward compatibility.

- **Schema Definition**: [`schemas/output-v1.0.0.json`](schemas/output-v1.0.0.json)
- **Complete Examples**: [`docs/ci.md#json-output-machine-readable`](docs/ci.md#json-output-machine-readable)

AWS and Azure have slightly different summary structures:
- **AWS**: Uses `region_selection_mode` with values `"explicit"` or `"all-regions"`
- **Azure**: Uses `subscription_selection_mode` with values `"explicit"` or `"all"`, plus `subscriptions_scanned` array

**CSV Output:**
CSV is a simplified format containing core fields (11 columns) for spreadsheet review. Use JSON for complete data including evidence and diagnostic details.

---

## Running in CI/CD Pipelines

CleanCloud is built for CI/CD with OIDC authentication, stable exit codes, and JSON/CSV output. Safe by default — exits `0` even with findings unless you opt into enforcement.

```bash
# In your pipeline — no secrets required with OIDC
pip install cleancloud
cleancloud scan --provider aws --all-regions --output json --output-file scan.json --fail-on-confidence HIGH
```

**Complete CI/CD guide:** [`docs/ci.md`](docs/ci.md) — GitHub Actions examples (AWS, Azure, multi-cloud), enforcement patterns, output formats, tag filtering, and troubleshooting.

---

## What CleanCloud Detects

16 high-signal rules across AWS and Azure — each read-only, conservative, and designed to avoid false positives in IaC environments.

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
| Azure | Unattached Managed Disks | Disks not attached to any VM | MEDIUM |
| Azure | Old Snapshots | Snapshots exceeding age threshold | MEDIUM |
| Azure | Unused Public IPs | Public IPs with no configuration attached | HIGH |
| Azure | Empty Load Balancers | Load balancers with no backend pools | HIGH |
| Azure | Empty App Gateways | Application gateways with no backends | HIGH |
| Azure | Empty App Service Plans | App Service Plans with no web apps | HIGH |
| Azure | Idle VNet Gateways | Virtual Network Gateways with no active connections | MEDIUM |
| Azure | Untagged Resources | Resources with no tags attached | MEDIUM |

**See [`docs/rules.md`](docs/rules.md) for full details, signals used, and evidence documentation.**

---

### Policy Enforcement

**Default Behavior:** CleanCloud reports findings but **does not fail builds** (exits 0). This makes it safe for scheduled scans, CI/CD pipelines, and exploratory runs.

**Opt-in strict mode with explicit flags:**

```bash
# Default: Report findings, don't fail builds (exit 0)
cleancloud scan --provider aws --region us-east-1

# Fail on HIGH confidence findings
cleancloud scan --provider aws --region us-east-1 --fail-on-confidence HIGH

# Fail on MEDIUM or higher confidence
cleancloud scan --provider aws --region us-east-1 --fail-on-confidence MEDIUM

# Fail on LOW or higher (all findings by confidence)
cleancloud scan --provider aws --region us-east-1 --fail-on-confidence LOW

# Fail on ANY findings (strict mode, ignores confidence levels)
cleancloud scan --provider aws --region us-east-1 --fail-on-findings
```

**Azure Examples:**

```bash
# Default: Report findings, don't fail builds (exit 0)
cleancloud scan --provider azure

# Fail on HIGH confidence findings
cleancloud scan --provider azure --fail-on-confidence HIGH

# Fail on MEDIUM or higher confidence
cleancloud scan --provider azure --fail-on-confidence MEDIUM

# Fail on LOW or higher (all findings by confidence)
cleancloud scan --provider azure --fail-on-confidence LOW

# Fail on ANY findings (strict mode, ignores confidence)
cleancloud scan --provider azure --fail-on-findings

# With specific subscription
cleancloud scan --provider azure --subscription <subscription-id>
```

**Note:** Policy enforcement works identically for both AWS and Azure providers.

---

## Configuration

### AWS Authentication

**Local Development:**
```bash
export AWS_ACCESS_KEY_ID=<your-access-key>
export AWS_SECRET_ACCESS_KEY=<your-secret-key>
export AWS_DEFAULT_REGION=us-east-1

cleancloud scan --provider aws --region us-east-1
```

**CI/CD:**
- Use GitHub Actions OIDC (see [Running in CI/CD Pipelines](#running-in-cicd-pipelines))
- Requires IAM role with read-only permissions

**IAM Permissions:**
- Only `List*`, `Describe*`, `Get*` operations required
- No `Delete*`, `Modify*`, or `Tag*` permissions
- Full policy and alternative auth methods: [`docs/aws.md`](docs/aws.md)

---

### Azure Authentication

**Local Development:**
```bash
export AZURE_CLIENT_ID=<your-client-id>
export AZURE_TENANT_ID=<your-tenant-id>
export AZURE_CLIENT_SECRET=<your-client-secret>
export AZURE_SUBSCRIPTION_ID=<your-subscription-id>

cleancloud scan --provider azure
```

**CI/CD:**
- Use Azure Workload Identity Federation (see [Running in CI/CD Pipelines](#running-in-cicd-pipelines))
- Requires `Reader` role at subscription scope

**Permissions:**
- Only read-only access required
- No write, delete, or tag permissions
- Full setup guide and alternative auth methods: [`docs/azure.md`](docs/azure.md)

**Subscription Filtering:**
```bash
# Default: scan all accessible subscriptions
cleancloud scan --provider azure

# Scan specific subscriptions
cleancloud scan --provider azure --subscription <sub-id-1> --subscription <sub-id-2>
```

---

### Tag-Based Filtering (Ignore Only)

CleanCloud supports tag-based filtering to reduce noise by ignoring findings for resources you explicitly mark.

This is useful when certain environments, teams, or services should be out of scope for hygiene review (for example: production or shared platform resources).

> **Note:** Tag filtering is **ignore-only**
>
> It does **not** disable rules, modify resources, or protect them from deletion.  
> CleanCloud remains **read-only and review-only**.

### Configuration File (cleancloud.yaml)

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

**Usage:**

```bash
# With config file in repository root
cleancloud scan --provider aws --region us-east-1 --config cleancloud.yaml

# Or specify full path
cleancloud scan --provider aws --region us-east-1 --config /path/to/cleancloud.yaml
```

**Behavior:**
* If a resource has any matching tag, its finding is ignored
* Matching is exact (no regex, no partial matches)
* Multiple ignore rules are OR'ed (any match ignores)


### Command Line Overrides (Highest Priority)
You can pass ignore tags directly via CLI:
```
cleancloud scan \
  --provider aws \
  --region us-east-1 \
  --ignore-tag env:production \
  --ignore-tag team:platform

```

**Important:**
* CLI --ignore-tag replaces YAML configuration
* YAML and CLI tags are not merged
* This ensures CI/CD runs are explicit and predictable


#### Scan Output & Transparency

Ignored findings are:

- Not included in scan results
- Counted and reported in the summary
- Preserved internally for auditability

Example summary output:
```
Ignored by tag policy: 7 findings
```

#### Recommended Usage

Tag filtering works best with **broad ownership or scope tags**, such as:

* env: production
* team: platform
* service: core-infra

It is **not intended** for per-resource exceptions or lifecycle management.

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
- Use **CleanCloud** to find orphaned resources your other tools miss — safely

> **Cost dashboards show you what you're spending.**
> **CleanCloud shows you what you can safely stop spending.**

**Learn more:** [Where CleanCloud Fits (design diagram)](docs/design.md#where-cleancloud-fits)

---

## Design Philosophy

CleanCloud is built on three core principles:

**1. Conservative by Default** - Multiple signals with explicit confidence levels (LOW/MEDIUM/HIGH) reduce false positives

**2. Read-Only Always** - No Delete*, Tag*, or Modify* permissions; safe for production

**3. Review-Only Recommendations** - Findings are candidates for review, not automated action

**Learn more:** [Confidence logic documentation](docs/confidence.md)

---

## Roadmap

> Roadmap items are added only after conservative signal design and safety review.

### Coming Soon
- GCP support (read-only, parity with existing trust guarantees)
- Additional AWS rules (empty security groups, idle RDS instances)
- Additional Azure rules (unused NICs, old images)
- Rule filtering (`--rules` flag)
- Multi-account scanning (AWS Organizations support)

### Not Planned
These are intentional non-goals to preserve safety and trust.

- Automated cleanup or deletion
- Rightsizing or instance optimization suggestions
- Billing data access or spending analysis
- Resource tagging or mutations

CleanCloud will remain focused on **safe cost optimization through hygiene detection**, not automation or infrastructure changes.

---

## Documentation

- [`SECURITY.md`](SECURITY.md) - **Security policy and threat model for enterprise evaluation**
- [`docs/infosec-readiness.md`](docs/infosec-readiness.md) - Information security readiness guide for enterprise teams
- [`security/`](security/) - IAM Proof Pack (ready-to-use policies and verification scripts)
- [`docs/rules.md`](docs/rules.md) - Detailed rule behavior and signals
- [`docs/aws.md`](docs/aws.md) - AWS setup and IAM policy
- [`docs/azure.md`](docs/azure.md) - Azure setup and RBAC configuration
- [`docs/ci.md`](docs/ci.md) - CI/CD integration examples

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