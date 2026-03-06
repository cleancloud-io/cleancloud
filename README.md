# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Security Scanning](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml)
![GitHub stars](https://img.shields.io/github/stars/cleancloud-io/cleancloud?style=social)

**Shift-left cloud hygiene. Catch orphaned resources in CI before they become monthly line items.**

CLI policy engine for AWS and Azure. Exits `0` by default — enforce when ready.

- **CI-native enforcement (opt-in):** `--fail-on-confidence HIGH` or `--fail-on-cost 100` gates your pipeline
- **Read-only by design:** no deletions, no tag changes, no mutations — ever
- **20 high-signal detection rules:** orphaned volumes, idle databases, empty load balancers, and more
- **Estimated monthly waste:** per finding and aggregate
- **No agents. No telemetry. No SaaS.** Runs in your environment, data never leaves

> Bug reports and feedback very welcome via [issues](https://github.com/cleancloud-io/cleancloud/issues).

---

## Get Started

```bash
pipx install cleancloud
pipx ensurepath        # adds cleancloud to PATH — restart your shell after this
cleancloud demo        # see sample findings without any cloud credentials
```

When you're ready to scan your real environment:

```bash
cleancloud scan --provider aws --all-regions
cleancloud scan --provider azure
```

### No install — try in your cloud shell

Got an AWS or Azure account? Run a real scan in seconds with no local setup.

**AWS — [AWS CloudShell](https://console.aws.amazon.com/cloudshell):**
```bash
pip install cleancloud
cleancloud doctor --provider aws   # check what permissions your session has
cleancloud scan --provider aws --all-regions
```

**Azure — [Azure Cloud Shell](https://shell.azure.com):**
```bash
pip install --user cleancloud
export PATH="$HOME/.local/bin:$PATH"
cleancloud doctor --provider azure  # check what permissions your session has
cleancloud scan --provider azure
```

Both shells authenticate using your portal session — no separate credentials needed. 

Permissions vary by account; 

`doctor` tells you exactly what's available before you scan. If permissions are missing, CleanCloud skips those rules and reports what was skipped.

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

For full output examples including `doctor`, JSON, and CSV: [`docs/example-outputs.md`](docs/example-outputs.md)

---

## What CleanCloud Detects

20 rules across AWS and Azure — conservative, high-signal, designed to avoid false positives in IaC environments.

**AWS:**
- Unattached EBS volumes (HIGH)
- Old EBS snapshots
- Infinite retention CloudWatch Logs
- Unattached Elastic IPs (HIGH)
- Detached ENIs
- Untagged resources
- Old AMIs
- Idle NAT Gateways
- Idle RDS instances (HIGH)
- Idle load balancers (HIGH)

**Azure:**
- Unattached managed disks
- Old snapshots
- Unused public IPs (HIGH)
- Empty load balancers (HIGH)
- Empty App Gateways (HIGH)
- Empty App Service Plans (HIGH)
- Idle VNet Gateways
- Stopped (not deallocated) VMs (HIGH)
- Idle SQL databases (HIGH)
- Untagged resources

Rules without a confidence marker are MEDIUM — they use time-based heuristics or multiple signals. Start with `--fail-on-confidence HIGH` to catch obvious waste, then tighten as your team validates.

**Full rule details, signals, and evidence:** [`docs/rules.md`](docs/rules.md)

---

## CI/CD Enforcement

Scans exit `0` by default. Opt in to enforcement:

| Flag | Behavior | Exit code |
|------|----------|-----------|
| *(none)* | Report only, never fail | `0` |
| `--fail-on-confidence HIGH` | Fail on HIGH confidence findings | `2` |
| `--fail-on-confidence MEDIUM` | Fail on MEDIUM or higher | `2` |
| `--fail-on-cost 50` | Fail if estimated monthly waste >= $50 | `2` |
| `--fail-on-findings` | Fail on any finding | `2` |

### GitHub Actions — AWS (OIDC)

```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
    aws-region: us-east-1

- run: pip install cleancloud

- run: |
    cleancloud scan --provider aws --all-regions \
      --fail-on-confidence HIGH \
      --output json --output-file scan.json
```

### GitHub Actions — Azure (Workload Identity)

```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

- run: pip install cleancloud

- run: |
    cleancloud scan --provider azure \
      --fail-on-confidence MEDIUM \
      --output json --output-file scan.json
```

**Complete CI/CD guide:** [`docs/ci.md`](docs/ci.md) — OIDC setup, enforcement patterns, output formats.
Setup guides: [AWS](docs/aws.md) · [Azure](docs/azure.md)

> CI/CD snippets above use `pip install` — correct for ephemeral runners where pipx isolation isn't needed.

---

## Roadmap

- Additional AWS rules (S3 lifecycle, stopped EC2 instances)
- Policy-as-code in `cleancloud.yaml` (`fail_on_confidence`, `fail_on_cost` in config)
- Rule filtering (`--rules` flag)
- Multi-account scanning (AWS Organizations)

---

## Documentation

- [`docs/rules.md`](docs/rules.md) — Detection rules, signals, and evidence
- [`docs/aws.md`](docs/aws.md) — AWS IAM policy and OIDC setup
- [`docs/azure.md`](docs/azure.md) — Azure RBAC and Workload Identity setup
- [`docs/ci.md`](docs/ci.md) — CI/CD integration guide
- [`docs/example-outputs.md`](docs/example-outputs.md) — Full output examples
- [`SECURITY.md`](SECURITY.md) — Security policy and threat model
- [`docs/infosec-readiness.md`](docs/infosec-readiness.md) — IAM Proof Pack, threat model

---

**Found a bug?** [Open an issue](https://github.com/cleancloud-io/cleancloud/issues) ·
**Feature request?** [Start a discussion](https://github.com/cleancloud-io/cleancloud/discussions) ·
**Questions?** suresh@getcleancloud.com

[MIT License](LICENSE)
