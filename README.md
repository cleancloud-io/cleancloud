# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Security Scanning](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml)
![GitHub stars](https://img.shields.io/github/stars/cleancloud-io/cleancloud?style=social)

**Shift-left cloud hygiene. Catch orphaned resources in CI before they become monthly line items.**

Policy engine for AWS and Azure. Safe by default — report-only until you opt in to enforcement.

- **CI-native enforcement (opt-in)** : `--fail-on-confidence HIGH` or `--fail-on-cost 100` gates your pipeline
- **Read-only by design** : no deletions, no tag changes, no resource mutations
- **20 high-signal detection rules** : orphaned volumes, idle databases, empty load balancers, and more
- **Estimated monthly waste** : per finding and aggregate, so you know what's burning
- **No agents. No telemetry. No SaaS.** : runs in your environment, data never leaves

## Try It in 60 Seconds (No Local Setup)

### AWS — [AWS CloudShell](https://console.aws.amazon.com/cloudshell)

```bash
pip install cleancloud
cleancloud scan --provider aws --all-regions
```

### Azure — [Azure Cloud Shell](https://shell.azure.com)

```bash
pip install --user cleancloud
export PATH="$HOME/.local/bin:$PATH"
cleancloud scan --provider azure
```

No credentials to configure. Both shells use your portal session.
Azure Cloud Shell requires `--user` because its system Python is read-only.

> If permissions are missing, CleanCloud skips those rules and tells you exactly what's needed — it won't just fail.

---

## Install Locally

```bash
pipx install cleancloud
pipx ensurepath   # adds pipx bin to PATH — restart your shell after this

# AWS
cleancloud scan --provider aws --all-regions

# Azure
cleancloud scan --provider azure
```

---

## See It In Action

### `cleancloud scan --provider aws --all-regions`

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

## How It Works

```
Your CI/CD Pipeline          CleanCloud (pip install)         Your Cloud Account
(GitHub Actions, etc.)       (read-only scan)                 (AWS / Azure)

pip install cleancloud       cleancloud scan    ◄──────────  IAM Role (Reader only)
        │                   - 20 detection rules              No write access
        │                   - Confidence scoring              OIDC temporary tokens
        ▼                   - Estimated waste per finding
--fail-on-confidence HIGH  (or)
--fail-on-cost 100
Exit 0 = pass
Exit 2 = policy violation
```

---

## What CleanCloud Detects

20 high-signal rules across AWS and Azure — each read-only, conservative, and designed to avoid false positives in IaC environments.

**AWS:**
* Unattached EBS volumes (HIGH) 
* Old EBS snapshots 
* Infinite retention logs 
* Unattached Elastic IPs (HIGH) 
* Detached ENIs 
* Untagged resources 
* Old AMIs 
* Idle NAT Gateways 
* Idle RDS instances (HIGH) 
* Idle load balancers (HIGH)

**Azure:** 
* Unattached managed disks
* Old snapshots
* Unused public IPs (HIGH)
* Empty load balancers (HIGH)
* Empty App Gateways (HIGH)
* Empty App Service Plans (HIGH)
* Idle VNet Gateways
* Stopped (not deallocated) VMs (HIGH)
* Idle SQL databases (HIGH)
* Untagged resources

Rules not marked are MEDIUM confidence — they use time-based heuristics or multiple signals.

> **You control the threshold.** Start with `--fail-on-confidence HIGH` to catch obvious waste, then tighten to `MEDIUM` as your team validates. Exclude specific resources with [tag-based filtering](#tag-based-filtering).

**Full rule details, signals, and evidence:** [`docs/rules.md`](docs/rules.md)

---

## CI/CD Enforcement

By default, scans exit `0` even with findings — safe for any pipeline. Opt in to enforcement:

| Flag | Behavior | Exit code |
|------|----------|-----------|
| *(none)* | Report findings, never fail | `0` |
| `--fail-on-confidence HIGH` | Fail only on HIGH confidence findings | `2` |
| `--fail-on-confidence MEDIUM` | Fail on MEDIUM or higher | `2` |
| `--fail-on-confidence LOW` | Fail on any confidence level | `2` |
| `--fail-on-cost 50` | Fail if estimated monthly waste >= $50 | `2` |
| `--fail-on-findings` | Fail on any finding (strict mode) | `2` |

```bash
# Recommended starting point
cleancloud scan --provider aws --all-regions --fail-on-confidence HIGH

# Fail if estimated monthly waste exceeds $100
cleancloud scan --provider aws --all-regions --fail-on-cost 100

# Full CI/CD example: OIDC auth, JSON output, enforce HIGH confidence
cleancloud scan --provider aws --all-regions \
  --output json --output-file scan.json \
  --fail-on-confidence HIGH
```

---

## Commands

### `doctor` — Validate credentials and permissions

Run this first. Checks authentication, security grade, and read-only permissions.

```bash
cleancloud doctor --provider aws
cleancloud doctor --provider azure
```

```
Authentication Method: OIDC (AssumeRoleWithWebIdentity)
[OK] Security Grade: EXCELLENT
[OK]   - Temporary credentials
[OK]   - Auto-rotated
Permissions Tested: 14/14 passed
[OK] AWS ENVIRONMENT READY FOR CLEANCLOUD
```

### `scan` — Detect waste and enforce policy

```bash
# AWS — single region or all regions
cleancloud scan --provider aws --region us-east-1
cleancloud scan --provider aws --all-regions

# Azure — all subscriptions or specific
cleancloud scan --provider azure
cleancloud scan --provider azure --subscription <subscription-id>

# Output formats
cleancloud scan --provider aws --all-regions --output json --output-file results.json
cleancloud scan --provider azure --output csv --output-file results.csv

# Exclude resources by tag
cleancloud scan --provider aws --all-regions --ignore-tag env:production
```

---

## Installation

### Quick Install
```bash
pipx install cleancloud
pipx ensurepath   # adds pipx bin to PATH — restart your shell after this
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

<details>
<summary>Troubleshooting</summary>

**Upgrading from a previous install** — If you previously installed via `pip install cleancloud`, the old version will shadow the pipx install. Remove it first:
```bash
pip uninstall cleancloud
pipx install cleancloud
pipx ensurepath   # if not already done — open a new terminal after this
cleancloud --version  # should show 1.5.0 or later
```

**Command not found: pip** — Use `pip3 install cleancloud` or `python3 -m pip install cleancloud`

**externally-managed-environment error** — Use `pipx` (see above)

**Command not found: cleancloud** — Run `pipx ensurepath` then restart your shell

**'cleancloud' already seems to be installed** — Run `pipx install cleancloud --force`

**Wrong version after install** — An old `pip install` may be shadowing the pipx install. Run `which cleancloud` to check which binary is active. If it points to a pyenv shim or system Python path, remove the old install first (`pip uninstall cleancloud`), then run `pipx ensurepath`, open a new terminal, and verify with `cleancloud --version`.
</details>

### Verify Installation
```bash
cleancloud --version
# Should show 1.5.0 or later — earlier versions have known issues
```

If you see a version older than 1.5.0, run `pip uninstall cleancloud` first, then re-run `pipx install cleancloud`.

---

## Try It Locally (2 minutes)

No OIDC or CI/CD setup needed — just your existing cloud credentials.

### AWS

```bash
# Your existing AWS CLI credentials work — no extra setup
cleancloud doctor --provider aws
cleancloud scan --provider aws --region us-east-1
```

**Permissions required:** 14 read-only permissions (`ec2:Describe*`, `rds:Describe*`, `s3:List*`, etc.). The `doctor` command tells you exactly which are missing. Full IAM policy: [`docs/aws.md`](docs/aws.md)

### Azure

```bash
# Your existing Azure CLI session works — no extra setup
cleancloud doctor --provider azure
cleancloud scan --provider azure
```

**Permissions required:** `Reader` role at subscription scope (built-in, no custom definition needed). Full RBAC setup: [`docs/azure.md`](docs/azure.md)

---

## Running in CI/CD Pipelines

One-time OIDC setup (~5 minutes) — no long-lived secrets needed.

### AWS — GitHub Actions with OIDC

```yaml
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

### Azure — GitHub Actions with Workload Identity

```yaml
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

**Complete CI/CD guide:** [`docs/ci.md`](docs/ci.md) — workflow examples, OIDC setup, enforcement patterns, output formats, and troubleshooting.

Setup guides: [AWS OIDC](docs/aws.md) · [Azure Workload Identity](docs/azure.md)

---

## Security & Trust

CleanCloud shifts trust from code to your cloud provider's enforcement.

**Read-only always:**
- Only `List*`, `Describe*`, `Get*` operations — no `Delete*`, `Modify*`, or `Tag*`
- You create the IAM role, you audit the JSON policy
- OIDC-first: temporary credentials, no secrets stored
- Zero telemetry: no phone-home, no analytics, no outbound calls

**Safety verification:**
- Static AST analysis blocks forbidden SDK calls
- Runtime SDK guards prevent mutations in tests
- IAM policy validation ensures read-only access
- Runs automatically in CI for all PRs

**Enterprise security documentation:**
- [Security Policy & Threat Model](SECURITY.md)
- [InfoSec Readiness Guide](docs/infosec-readiness.md) — IAM Proof Pack, threat model, mitigations
- [IAM Proof Pack](security/) — ready-to-use policies and verification scripts
- [Safety Test Documentation](docs/safety.md)

---

## Tag-Based Filtering

Ignore findings for resources you explicitly mark. Useful when certain environments, teams, or services are out of scope.

### Config file (`cleancloud.yaml`)

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

CLI `--ignore-tag` replaces YAML configuration (not merged) for predictable CI/CD runs. Ignored findings are counted in the summary for auditability.

---

## How CleanCloud Compares

### vs. Cost Dashboards & Cleanup Automation

| Need | Cost Dashboards | Cleanup Automation | CleanCloud |
|------|-----------------|-------------------|------------|
| **Orphaned resource detection** | Limited or noisy | Aggressive | Conservative, high-signal |
| **Safe for production** | Varies | Risk of deletion | Read-only always |
| **CI/CD enforcement** | Not designed for it | Risky | Purpose-built |
| **Confidence scoring** | Binary yes/no | Binary yes/no | LOW/MEDIUM/HIGH |
| **Telemetry / data sharing** | Usually required | Usually required | Zero — fully private |

CleanCloud complements dashboards and advisors. Use **AWS Cost Explorer / Azure Cost Management** for spending trends. Use **Trusted Advisor / Azure Advisor** for rightsizing. Use **CleanCloud** to shift cloud hygiene left — catch waste in the pipeline before it accumulates.

### vs. Azure Orphan Resources

[Azure Orphan Resources](https://github.com/dolevshor/azure-orphan-resources) is a popular Azure Workbook for visualizing orphaned resources in the portal — great for ad-hoc visibility, but a different tool for a different workflow.

| | Azure Orphan Resources | CleanCloud                                                 |
|---|---|------------------------------------------------------------|
| **Cloud support** | Azure only | AWS + Azure                                                |
| **Interface** | Azure Portal workbook | CLI (`pipx install`)                                       |
| **CI/CD enforcement** | None — manual review only | `--fail-on-confidence` or `--fail-on-cost` gates builds    |
| **Delete capability** | Yes (requires Contributor role) | Read-only — no mutations ever                              |
| **Detection model** | Binary: orphaned or not | Confidence scoring with evidence per finding               |
| **Cost estimates** | Labels resources as "billable" | Per-finding `estimated_monthly_cost_usd` + aggregate waste |
| **Automation** | Manual import, no scheduling | `pipx install` in any pipeline, cron, or script            |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed (findings reported but don't fail by default) |
| `1` | Configuration error or unexpected error |
| `2` | Policy violation (`--fail-on-findings`, `--fail-on-confidence`, or `--fail-on-cost`) |
| `3` | Missing permissions or invalid credentials |

---

## Roadmap

> Roadmap items are added only after conservative signal design and safety review.

### Coming Soon
- Additional AWS rules (S3 lifecycle, stopped EC2 instances)
- GCP support (read-only, parity with existing trust guarantees)
- Policy-as-code in `cleancloud.yaml` — define enforcement thresholds in config
- Rule filtering (`--rules` flag)
- Multi-account scanning (AWS Organizations support)

### Not Planned
- Automated cleanup or deletion
- Rightsizing or instance optimization
- Billing data access or spending analysis
- Resource tagging or mutations

---

## Documentation

- [`docs/rules.md`](docs/rules.md) - Detection rules, signals, and evidence
- [`docs/aws.md`](docs/aws.md) - AWS setup and IAM policy
- [`docs/azure.md`](docs/azure.md) - Azure setup and RBAC configuration
- [`docs/ci.md`](docs/ci.md) - CI/CD integration guide
- [`docs/example-outputs.md`](docs/example-outputs.md) - Full output examples (doctor, scan, JSON)
- [`SECURITY.md`](SECURITY.md) - Security policy and threat model
- [`docs/infosec-readiness.md`](docs/infosec-readiness.md) - InfoSec readiness guide
- [`security/`](security/) - IAM Proof Pack (policies and verification scripts)

---

## Enterprise & Production Use

CleanCloud is designed for teams that enforce cloud hygiene in CI/CD — where write access is prohibited, InfoSec review is mandatory, and data cannot leave the cloud account.

If your team is evaluating shift-left cost governance or hygiene policy enforcement, we can support security reviews, CI/CD rollout design, and multi-account architecture discussions.

**[Start an evaluation discussion](https://www.getcleancloud.com/#contact)**

---

## Questions or Feedback?

- **Found a bug?** [Open an issue](https://github.com/cleancloud-io/cleancloud/issues)
- **Have a feature request?** [Start a discussion](https://github.com/cleancloud-io/cleancloud/discussions)
- **Want to chat?** Email us at suresh@getcleancloud.com
- **Like CleanCloud?** [Star us on GitHub](https://github.com/cleancloud-io/cleancloud)

## Contributing

Contributions are welcome! Please ensure all PRs include tests, follow the conservative design philosophy, and maintain read-only operation. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## License

[MIT License](LICENSE)
