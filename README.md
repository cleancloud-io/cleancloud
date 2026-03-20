# CleanCloud

![PyPI](https://img.shields.io/pypi/v/cleancloud)
![Python Versions](https://img.shields.io/pypi/pyversions/cleancloud)
![Docker Pulls](https://img.shields.io/docker/pulls/getcleancloud/cleancloud)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Security Scanning](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cleancloud-io/cleancloud/actions/workflows/security-scan.yml)
![GitHub stars](https://img.shields.io/github/stars/cleancloud-io/cleancloud?style=social)

**Languages / Langues :**
🇬🇧 [English](README.md) | 🇫🇷 [Français](README.fr.md)

**Docs:** [AWS Setup](docs/aws.md) · [AWS Permissions & Commands](docs/aws.md#at-a-glance) · [AWS Multi-Account](docs/aws.md#multi-account-scanning) · [Azure Setup](docs/azure.md) · [CI/CD Guide](docs/ci.md) · [Detection Rules](docs/rules.md) · [Example Outputs](docs/example-outputs.md) · [Docker Hub](https://hub.docker.com/r/getcleancloud/cleancloud) · [GitHub Action](https://github.com/marketplace/actions/cleancloud-scan)

---

**Enforces cloud hygiene policy in CI and gives engineering, finance, and ops a single view of waste.**

**Supports:** AWS · Azure — GCP coming soon

Read-only cloud hygiene for regulated & sovereign environments.

CleanCloud scans your cloud environment and reports what's wasting money. Run it once for a quick audit, schedule it, or wire it into CI/CD to fail builds on policy violations.

- **20 high-signal detection rules:** orphaned volumes, idle databases, empty load balancers, and more
- **Estimated monthly waste:** per finding and aggregate
- **Multi-account scanning:** scan entire AWS Organizations in minutes — config file, inline IDs, or auto-discovery via `--org`
- **CI-native enforcement (opt-in):** `--fail-on-confidence HIGH` or `--fail-on-cost 100` gates your pipeline
- **Multiple output formats:** human-readable, JSON, CSV, and markdown (paste into GitHub PRs or Slack)
- **Read-only by design:** no deletions, no tag changes, no mutations — ever
- **No agents. No telemetry. No SaaS.** Runs in your environment, data never leaves

### What CleanCloud does NOT do

| | |
|---|---|
| ❌ Delete resources | ❌ Modify or create tags |
| ❌ Write to any cloud API | ❌ Store or log credentials |
| ❌ Send telemetry or usage data | ❌ Require a SaaS account or agent |

All operations are read-only. Safe for production accounts, air-gapped environments, and security-reviewed pipelines.

**Use cases:**
- One-time cloud waste audit — run in CloudShell, see findings in 60 seconds
- Scheduled hygiene scans — cron job or weekly CI run to catch drift
- CI/CD enforcement gates — fail builds when waste exceeds your threshold

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

**Via Docker (recommended for CI/CD — no Python required):**
```bash
docker pull getcleancloud/cleancloud
docker run --rm getcleancloud/cleancloud demo
```

When you're ready to scan your real environment, authenticate first — then run:

```bash
# AWS: make sure you're logged in (aws configure, aws sso login, or IAM role)
cleancloud scan --provider aws --all-regions

# Azure: make sure you're logged in (az login)
cleancloud scan --provider azure
```

Not sure if your credentials have the right permissions? Run `cleancloud doctor --provider aws` or `cleancloud doctor --provider azure` first.

<details>
<summary>All scan flags</summary>

```
# Required
--provider aws|azure          Cloud provider to scan

# Region (optional)
--region REGION               Single region
--all-regions                 Scan all active regions (recommended)

# Multi-account — AWS only (optional, pick one)
--multi-account FILE          Config file listing accounts (e.g. .cleancloud/accounts.yaml)
--accounts 111,222            Inline account IDs, comma-separated
--org                         Auto-discover all accounts via AWS Organizations
--concurrency N               Parallel accounts (default: 3)
--timeout SECONDS             Total scan timeout in seconds (default: 3600)

# Output (optional)
--output human|json|csv|markdown  Output format (default: human)
--output-file FILE            Write output to file instead of stdout

# CI/CD enforcement (optional, all exit code 2 on match)
--fail-on-confidence HIGH     Fail on HIGH confidence findings
--fail-on-confidence MEDIUM   Fail on MEDIUM or higher findings
--fail-on-cost N              Fail if estimated monthly waste >= $N
--fail-on-findings            Fail on any finding
```

</details>

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

Complete, copy-pasteable GitHub Actions workflows for AWS (OIDC) and Azure (Workload Identity) — including OIDC setup, trust policy, RBAC, and enforcement patterns:

**[CI/CD guide →](docs/ci.md)** · [AWS setup →](docs/aws.md) · [Azure setup →](docs/azure.md)

**Need help with OIDC or enforcement flags?** [Ask in our CI/CD setup discussion →](https://github.com/cleancloud-io/cleancloud/discussions/98)

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

## Roadmap

- Additional AWS rules (S3 lifecycle, stopped EC2 instances)
- Policy-as-code in `cleancloud.yaml` (`fail_on_confidence`, `fail_on_cost` in config)
- Rule filtering (`--rules` flag)
- Azure Management Group scanning (multi-subscription org-level)

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

**Found a bug?** [Open an issue](https://github.com/cleancloud-io/cleancloud/issues)

**Feature request?** [Start a discussion](https://github.com/cleancloud-io/cleancloud/discussions)

**Questions?** suresh@getcleancloud.com

[MIT License](LICENSE)
