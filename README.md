# CleanCloud

**Safe, conservative cloud hygiene scanning for modern infrastructure teams.**

CleanCloud helps SRE and DevOps teams identify orphaned, untagged, and potentially inactive cloud resources—without the risk of automated cleanup or aggressive cost optimization heuristics.

## Why CleanCloud?

Modern cloud environments constantly create and destroy storage and logs. Over time, orphaned resources accumulate — no owner, no signal, and too risky to delete blindly.

Most cloud hygiene tools fall into two categories:

1. **Auto-delete everything** - Too dangerous for production
2. **Flag everything** - Too noisy to be useful

**CleanCloud is different:**

- ✅ **Read-only by design** - Never modifies, deletes, or tags resources
- ✅ **Conservative signals** - Multiple indicators, age-based confidence thresholds
- ✅ **IaC-aware** - Designed for elastic, automated infrastructure
- ✅ **Trust-first** - Review-only recommendations, never destructive actions
- ✅ **CI/CD friendly** - Exit codes, JSON/CSV output, confidence-based policies

**CleanCloud is not:**
- ❌ A cost optimization tool
- ❌ An automated cleanup service
- ❌ A FinOps dashboard

It's a **hygiene layer** built for teams who value safety over automation.

---

## Quick Start

### Installation

```bash
pip install cleancloud
```

### Validate Credentials

```bash
# AWS
cleancloud doctor --provider aws

# Azure
cleancloud doctor --provider azure
```

### Run a Scan

```bash
# AWS - single region
cleancloud scan --provider aws --region us-east-1

# AWS - all regions
cleancloud scan --provider aws --all-regions

# Azure - all subscriptions
cleancloud scan --provider azure
```

### View Results

```bash
# Human-readable output (default)
cleancloud scan --provider aws

# JSON output
cleancloud scan --provider aws --output json --output-file results.json

# CSV output
cleancloud scan --provider azure --output csv --output-file results.csv
```

---

## What CleanCloud Detects

### AWS Rules (4 currently)
- **Unattached EBS volumes** - Volumes not attached to any EC2 instance
- **Old EBS snapshots** - Snapshots older than 90 days (configurable)
- **Inactive CloudWatch log groups** - Log groups with infinite retention
- **Untagged resources** - EBS volumes, S3 buckets, log groups without tags

### Azure Rules (4 currently)
- **Unattached managed disks** - Disks not attached to any VM (7+ days old)
- **Old snapshots** - Snapshots older than 30 days
- **Untagged resources** - Managed disks and snapshots without tags
- **Unused public IPs** - Public IP addresses not attached to any resource

See [`docs/rules.md`](docs/rules.md) for detailed rule behavior and confidence thresholds.

---

## CI/CD Integration

CleanCloud is designed for CI/CD pipelines with predictable exit codes and policy enforcement.

### GitHub Actions Example

```yaml
- name: Run CleanCloud hygiene scan
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  run: |
    pip install cleancloud
    cleancloud scan --provider aws --output json --output-file scan.json --fail-on-confidence HIGH

- name: Upload results
  uses: actions/upload-artifact@v4
  with:
    name: cleancloud-results
    path: scan.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully, no blocking findings |
| `1` | Configuration or unexpected error |
| `2` | Policy violation (findings detected with `--fail-on-findings` or `--fail-on-confidence`) |
| `3` | Missing permissions or invalid credentials |

### Policy Enforcement

```bash
# Fail only on HIGH confidence findings (recommended)
cleancloud scan --fail-on-confidence HIGH

# Fail on MEDIUM or higher confidence
cleancloud scan --fail-on-confidence MEDIUM

# Fail on any findings (strict mode, not recommended)
cleancloud scan --fail-on-findings
```

See [`docs/ci.md`](docs/ci.md) for complete CI/CD integration examples.

---

## Configuration

### AWS

CleanCloud uses standard AWS credential resolution:

```bash
# Using AWS profile
aws configure --profile cleancloud
cleancloud scan --provider aws --profile cleancloud

# Using environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
cleancloud scan --provider aws
```

**Required IAM permissions:** Read-only access to EC2, CloudWatch Logs, and S3.

See [`docs/aws.md`](docs/aws.md) for detailed setup and IAM policy.

### Azure

CleanCloud requires Azure service principal credentials:

```bash
export AZURE_CLIENT_ID=...
export AZURE_TENANT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_SUBSCRIPTION_ID=...  # Optional

cleancloud scan --provider azure
```

**Required Azure permissions:** Reader role on subscription.

See [`docs/azure.md`](docs/azure.md) for detailed setup and RBAC configuration.

---

## Design Philosophy

CleanCloud is built on three core principles:

### 1. Conservative by Default
- Age-based confidence thresholds (e.g., disks > 14 days = HIGH confidence)
- Multiple signals required before flagging resources
- Explicit confidence levels: LOW, MEDIUM, HIGH

### 2. Read-Only Always
- No `Delete*` permissions required
- No `Tag*` permissions required
- No modification APIs called
- Safe for production accounts

### 3. Review-Only Recommendations
- Findings are candidates for human review, not automated action
- Clear reasoning provided for each finding
- Detailed metadata included for investigation

This makes CleanCloud safe for:
- ✅ Regulated environments
- ✅ Production accounts
- ✅ Security-reviewed pipelines
- ✅ Shared infrastructure

---

## Roadmap

### Coming Soon
- GCP support
- Additional AWS rules (unused Elastic IPs, old AMIs, empty security groups)
- Additional Azure rules (unused NICs, old images)
- Rule filtering (`--rules` flag)
- Configuration file support (`cleancloud.yaml`)

### Not Planned
- Automated cleanup or deletion
- Cost optimization recommendations
- Rightsizing suggestions
- Billing data access

CleanCloud will remain focused on **safe hygiene detection**, not automation or cost management.

---

## Documentation

- [`docs/rules.md`](docs/rules.md) - Detailed rule behavior and signals
- [`docs/aws.md`](docs/aws.md) - AWS setup and IAM policy
- [`docs/azure.md`](docs/azure.md) - Azure setup and RBAC configuration
- [`docs/ci.md`](docs/ci.md) - CI/CD integration examples

---

## Contributing

Contributions are welcome! Please ensure all PRs:
- Include tests for new rules
- Follow the conservative design philosophy
- Maintain read-only operation
- Include documentation updates

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## Security

CleanCloud never requires you to commit cloud credentials.
All scans run using standard AWS/Azure SDK credential resolution
(AWS profiles, env vars, or workload identity).

⚠️ Never commit secrets into this repository.

---

## License

[MIT License](LICENSE)

---

## Why "CleanCloud"?

Because clean code matters, clean infrastructure matters, and cleaning up cloud resources should be **safe, deliberate, and human-reviewed**—not automated and risky.

---

**Built for SRE teams who value trust over automation.**