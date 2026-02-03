# CleanCloud

**Reduce cloud costs through safe, read-only hygiene evaluation**

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Security Scanning](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml)
![GitHub stars](https://img.shields.io/github/stars/cleancloud-io/cleancloud?style=social)

CleanCloud helps teams **reduce cloud costs** by safely identifying orphaned, untagged, and inactive resources for review. Built as a **read-only, trust-first hygiene evaluation engine** for AWS and Azure — safe to run in production and CI/CD pipelines. Designed for SRE and platform teams who need cost optimization without mutations, deletions, or automated cleanup.

- **Read-only by design** - No deletions, no tag modifications, no resource changes
- **Policy-safe** - Conservative signals with explicit confidence levels
- **Privacy-first** - Zero telemetry, no phone-home, no data collection
---

## Table of Contents

- [Security & Trust](#security--trust)
- [Who This Is For](#who-cleancloud-is-and-is-not-for)
- [Enterprise & Production Use](#built-for-production--enterprise-use)
- [Quick Start](#quick-start)
- [What CleanCloud Detects](#what-cleancloud-detects)
- [Policy Enforcement](#policy-enforcement)
- [Configuration](#configuration)
- [Why Teams Choose CleanCloud](#why-teams-choose-cleancloud)
- [Design Philosophy](#design-philosophy)
- [Documentation](#documentation)

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

**CleanCloud is for:**
- Teams optimizing cloud costs in production and staging environments
- SRE / Platform teams who need safe, read-only hygiene evaluation
- Security-reviewed and regulated environments where mutations are prohibited
- CI/CD pipelines that enforce cost hygiene without infrastructure changes
- Organizations using IaC and ephemeral resources

**CleanCloud is NOT:**
- An automated cleanup or deletion service (one-click account nuking)
- A replacement for Trusted Advisor or Config
- A cost dashboard with rightsizing recommendations
- A tool that modifies, tags, or deletes resources

CleanCloud exists to answer one question safely:

> What orphaned resources are costing us money — without risking production?


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

CleanCloud is designed for CI/CD environments with OIDC authentication (no secrets required).

### Requirements for CI/CD

**Python:** 3.9 or later (usually pre-installed in GitHub Actions runners)

**Authentication:**
- **AWS**: IAM Role with OIDC trust relationship (GitHub Actions recommended)
- **Azure**: Workload Identity Federation (Microsoft Entra ID recommended)

**Key Differences from Local Usage:**
- Uses OIDC (OpenID Connect) instead of CLI credentials
- No long-lived secrets stored in CI
- Safe by default: exits 0 even with findings (won't block deployments)
- Opt-in strict mode with `--fail-on-confidence` or `--fail-on-findings` flags

### Quick Example: GitHub Actions with AWS

```yaml
permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  cleancloud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/CleanCloudCIReadOnly
          aws-region: us-east-1

      - name: Run CleanCloud scan
        run: |
          pip install cleancloud
          cleancloud scan \
            --provider aws \
            --region us-east-1 \
            --output json \
            --output-file scan.json
            # Default: Reports findings, exits 0 (safe, won't fail deployment)
            # Add --fail-on-confidence HIGH to enforce strict policy
```

### Quick Example: GitHub Actions with Azure

```yaml
permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  cleancloud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Run CleanCloud scan
        run: |
          pip install cleancloud
          cleancloud scan \
            --provider azure \
            --output json \
            --output-file scan.json
            # Default: Reports findings, exits 0 (safe, won't fail deployment)
            # Add --fail-on-confidence HIGH to enforce strict policy
```

**Complete CI/CD documentation:** See [`docs/ci.md`](docs/ci.md) for detailed setup instructions.

---

## What CleanCloud Detects

CleanCloud intentionally starts with **a small number of high-signal rules**.

Each rule:
- Is read-only
- Uses multiple conservative signals
- Avoids false positives in IaC environments
- Includes explicit confidence levels

**See [`docs/rules.md`](docs/rules.md) for full details.**

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

**Cost dashboards** show you spending trends and rightsizing recommendations.

**CleanCloud** helps you **reduce costs** by safely identifying waste — orphaned resources, unattached volumes, and inactive assets — without mutations or automation risk.

| Need | Cost Dashboards | CleanCloud |
|------|-----------------|------------|
| **Spending trends & analysis** | Excellent | Not a goal |
| **Orphaned resource detection** | Limited or noisy | Conservative, high-signal |
| **Safe for production** | Varies | Read-only always |
| **CI/CD cost enforcement** | Not designed for it | Purpose-built |
| **Confidence scoring** | Binary yes/no | LOW/MEDIUM/HIGH |
| **No mutations required** | Often needs write access | Read-only by design |

### CleanCloud Complements Your Cost Tools

- Use **cost dashboards** to track spending and identify trends
- Use **CleanCloud** to find and review orphaned resources that are costing money

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
- Additional AWS rules (unused Elastic IPs, old AMIs, empty security groups)
- Additional Azure rules (unused NICs, old images)
- Rule filtering (`--rules` flag)

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