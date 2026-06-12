# AWS Setup

Scan your AWS accounts for idle resources and cost waste — safely, with read-only access.

> CleanCloud is strictly read-only: no resource deletion, no changes or tagging, no background agents or telemetry. It literally cannot mutate your cloud.

> **Rules Reference:** [rules.md](rules.md) · **CI/CD Guide:** [ci.md](ci.md) · **Example Outputs:** [example-outputs.md](example-outputs.md)

---

## 60-Second Quick Start

Find idle resources and wasted cloud spend in under 2 minutes:

```bash
# 1. Verify AWS credentials (or configure if needed)
aws sts get-caller-identity || aws configure

# 2. Validate permissions
cleancloud doctor --provider aws

# 3. Run your first scan
cleancloud scan --provider aws --all-regions
```

You should see output like:

```
--- Scan Summary ---
Total findings: 8
By risk:        low: 3  medium: 3  high: 2
By confidence:  high: 6  medium: 2
Minimum estimated waste: ~$312/month

Top findings:
- Unattached EBS volumes (3)
- Idle load balancer (1)
- Old RDS snapshot (2)
```

If `doctor` reports missing permissions, see [IAM Policy](#iam-policy-minimum-required-permissions). That's it for most local and single-account use cases — the sections below cover CI/CD setup (OIDC) and multi-account scanning.

---

## At a Glance

### Permissions

> ✔ Read-only IAM policies, split by scan category
> ✔ No write, delete, or tagging access
> ✔ Safe for production accounts — CleanCloud cannot mutate your cloud

| Scenario | What you need |
|---|---|
| Single-account scan (default hygiene) | `base-readonly.json` + `hygiene-readonly.json` |
| Single-account scan (`--category ai`) | `base-readonly.json` + `ai-readonly.json` |
| Multi-account — spoke accounts | Same category policy set as the scan you run |
| Multi-account — hub account | Same category policy set + `sts:AssumeRole` on spoke roles |
| `--org` auto-discovery (hub only) | Above + `organizations:ListAccounts` |

---

### Commands

| Task | Command |
|---|---|
| Scan current account, all regions | `cleancloud scan --provider aws --all-regions` |
| Scan specific region | `cleancloud scan --provider aws --region us-east-1` |
| Scan multiple accounts (config file) | `cleancloud scan --provider aws --multi-account .cleancloud/accounts.yaml --all-regions` |
| Scan multiple accounts (inline IDs) | `cleancloud scan --provider aws --accounts 111111111111,222222222222 --all-regions` |
| Scan entire AWS Organization | `cleancloud scan --provider aws --org --all-regions` |
| Fail build on HIGH findings | Add `--fail-on-confidence HIGH` to any scan command |
| Fail build if waste ≥ $X/month | Add `--fail-on-cost 500` to any scan command |
| Check permissions (default hygiene) | `cleancloud doctor --provider aws` |
| Check AI/ML permissions | `cleancloud doctor --provider aws --category ai` |
| Check permissions + multi-account roles | `cleancloud doctor --provider aws --multi-account .cleancloud/accounts.yaml` |

---

### Multi-Account Setup (3 steps)

**Step 1 — Deploy `CleanCloudReadOnlyRole` to each spoke account** → [Deploy the Cross-Account Role](#deploy-the-cross-account-role)

**Step 2 — Add `sts:AssumeRole` to your hub role** → [IAM Setup (Hub Account)](#iam-setup-hub-account)

**Step 3 — Create `.cleancloud/accounts.yaml` in your repo** → [accounts.yaml Format](#cleanclouaccountsyaml-format)

Then run:
```bash
cleancloud doctor --provider aws --multi-account .cleancloud/accounts.yaml  # validate first
cleancloud scan --provider aws --multi-account .cleancloud/accounts.yaml --all-regions
```

---

## Authentication Methods

### 1. Local Development (AWS CLI Profile)

The simplest setup for running scans locally.

```bash
# Configure a named profile
aws configure --profile cleancloud

# Use with CleanCloud
cleancloud scan --provider aws --profile cleancloud --all-regions
```

Or use your default profile (no `--profile` flag needed):

```bash
aws configure
cleancloud scan --provider aws --all-regions
```

---

### 2. CI/CD Setup (Optional – for automation)

Only needed if you want:
- Scheduled scans running automatically
- CI enforcement (`--fail-on-cost`, `--fail-on-confidence`)
- No long-lived credentials in your pipeline (SOC2 compliant)

Otherwise, skip this section — local CLI setup is enough.

**No long-lived credentials, temporary tokens only.**

#### Quick setup (3 steps)

```bash
# 1. Create OIDC identity provider (one-time per AWS account)
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com

# 2. Create IAM role with trust policy + attach CleanCloud policy
aws iam create-role \
  --role-name CleanCloudCIReadOnly \
  --assume-role-policy-document file://cleancloud-trust-policy.json
aws iam put-role-policy \
  --role-name CleanCloudCIReadOnly \
  --policy-name CleanCloudReadOnly \
  --policy-document file://cleancloud-policy.json

# 3. Add AWS_ACCOUNT_ID as a GitHub repo variable (Settings → Secrets and variables → Variables)
```

Then add to your workflow:

```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
    aws-region: us-east-1
```

> ⚠️ **Common mistake:** The trust policy subject must exactly match your workflow trigger. Branch push, PR, and GitHub Environment each send a different subject claim — using the wrong one causes `AccessDenied`. See [OIDC subject mismatch](#oidc-subject-claim-mismatch).

Full walkthrough → [Full OIDC Setup](#full-oidc-setup)

---

### 3. Environment Variables

```bash
export AWS_ACCESS_KEY_ID=<your-key>
export AWS_SECRET_ACCESS_KEY=<your-secret>
export AWS_DEFAULT_REGION=us-east-1

cleancloud scan --provider aws --region us-east-1
```

**Not recommended for CI/CD** — use OIDC instead (no long-lived credentials to rotate or leak).

---

## Full OIDC Setup

#### Step 1: Create the OIDC Identity Provider (one-time per AWS account)
```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

> **Note:** A `--thumbprint-list` parameter is no longer required. AWS validates GitHub's OIDC tokens directly without certificate pinning. See [aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials) for details.

#### Step 2: Create the trust policy file (`cleancloud-trust-policy.json`)

Choose the subject format that matches how your GitHub Actions workflow runs:

| Workflow trigger | Subject claim to use |
|---|---|
| Branch push (e.g. `main`) | `repo:<ORG>/<REPO>:ref:refs/heads/main` |
| Pull request | `repo:<ORG>/<REPO>:pull_request` |
| GitHub Environment | `repo:<ORG>/<REPO>:environment:<ENV_NAME>` |

> ⚠️ **Common mistake:** If your workflow uses `environment: production`, GitHub sends the `environment` subject claim — not the `ref` one. Using the wrong format causes `AccessDenied` when assuming the role. See [OIDC subject mismatch](#oidc-subject-claim-mismatch) in Troubleshooting.

**For branch-based workflows:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:<YOUR_ORG>/<YOUR_REPO>:ref:refs/heads/main"
      }
    }
  }]
}
```

**For GitHub Environment workflows:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:<YOUR_ORG>/<YOUR_REPO>:environment:<YOUR_ENV_NAME>"
      }
    }
  }]
}
```

> 💡 **Tip:** To allow multiple triggers (branch push and GitHub Environment), list both subject values in the same `StringEquals` condition — see [OIDC subject mismatch](#oidc-subject-claim-mismatch) in Troubleshooting.

Replace:
- `<ACCOUNT_ID>` — Your AWS account ID
- `<YOUR_ORG>/<YOUR_REPO>` — Your GitHub organization and repository

#### Step 3: Create the IAM role
```bash
aws iam create-role \
  --role-name CleanCloudCIReadOnly \
  --assume-role-policy-document file://cleancloud-trust-policy.json
```

#### Step 4: Attach the read-only policy (see [IAM Policy](#iam-policy-minimum-required-permissions) below)
```bash
aws iam put-role-policy \
  --role-name CleanCloudCIReadOnly \
  --policy-name CleanCloudReadOnly \
  --policy-document file://cleancloud-policy.json
```

#### Step 5: Add your AWS account ID as a GitHub repository variable

Go to your repo → Settings → Secrets and variables → Actions → Variables tab → New repository variable:
- Name: `AWS_ACCOUNT_ID`
- Value: Your 12-digit AWS account ID

> Use `vars` (not `secrets`) for account ID — it's not sensitive and makes debugging easier.

#### Validate Your Setup

Once credentials are configured, verify everything works:

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  cleancloud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
          aws-region: us-east-1

      - name: Validate AWS permissions
        run: |
          pip install 'cleancloud[aws]'
          cleancloud doctor --provider aws --region us-east-1
```

For the complete production workflow with enforcement flags, scheduling, and artifact upload: **[CI/CD guide →](ci.md)**

---

## IAM Policy (Minimum Required Permissions)

> **Policy files are split by category.** The canonical policies live in [`security/aws/`](../security/aws/) as three separate files:
>
> | File | Contains | Required when |
> |------|----------|---------------|
> | `base-readonly.json` | `sts:GetCallerIdentity`, `cloudwatch:GetMetricStatistics` | **Always — every scan, every category** |
> | `hygiene-readonly.json` | EC2, RDS, ELB, S3, logs | `--category hygiene` (default) |
> | `ai-readonly.json` | Bedrock Provisioned Throughput, SageMaker endpoints/notebooks/domains/Studio apps/training jobs/processing jobs, EC2 GPU instances, CloudWatch metrics | `--category ai` |
>
> `base-readonly.json` must be attached alongside any category file. It provides `sts:GetCallerIdentity` (used at startup and by `doctor` to verify credentials) and shared CloudWatch metric access. Attach `hygiene-readonly.json` for the default scan path, and `ai-readonly.json` for `--category ai`.

Attach this policy to your IAM role or user for the default hygiene scan path (combined view of `base-readonly.json` + `hygiene-readonly.json`; for the split files see above):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2ReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:DescribeAddresses",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeNatGateways",
        "ec2:DescribeRegions",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ELBReadOnly",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth"
      ],
      "Resource": "*"
    },
    {
      "Sid": "RDSReadOnly",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBSnapshotAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchReadOnly",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:ListTagsForResource",
        "cloudwatch:GetMetricStatistics"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3ReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketTagging"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AutoScalingReadOnly",
      "Effect": "Allow",
      "Action": [
        "autoscaling:DescribeLaunchConfigurations"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

**Key characteristics:**
- Read-only operations only
- No `Delete*`, `Create*`, or `Tag*` permissions
- Safe for production accounts
- Compatible with security-reviewed pipelines

For AI/ML scans, also attach [`security/aws/ai-readonly.json`](../security/aws/ai-readonly.json). It adds permissions for Bedrock Provisioned Throughput, SageMaker endpoints, notebook instances, SageMaker Domains (`sagemaker:ListDomains`, `sagemaker:DescribeDomain`), SageMaker Studio apps (`sagemaker:ListApps`, `sagemaker:DescribeApp`), SageMaker training jobs (`sagemaker:ListTrainingJobs`, `sagemaker:DescribeTrainingJob`), SageMaker processing jobs (`sagemaker:ListProcessingJobs`, `sagemaker:DescribeProcessingJob`), EC2 GPU instances, and `cloudwatch:ListMetrics` for GPU metric discovery.

---

## Multi-Account Scanning (Advanced)

Scan multiple AWS accounts in a single run. CleanCloud assumes a cross-account IAM role in each target account, scans in parallel, and produces an aggregated report.

### Choose your setup

| Scale | Recommended approach |
|---|---|
| 1–5 accounts | [Option A: AWS CLI](#option-a-aws-cli-quickest----1-to-10-accounts) — no prerequisites, 30 seconds per account |
| 5–50 accounts | [Option B: CloudFormation StackSet](#option-b-cloudformation-stackset-10-accounts-aws-native) — deploys to all accounts in one operation |
| Already using Terraform | [Option C: Terraform module](#option-c-terraform-if-you-already-manage-iam-with-terraform) — drop into your existing codebase |

> **Two roles, two purposes.** Multi-account scanning uses two distinct IAM roles — don't confuse them:
>
> | Role | Lives in | Trusted by | Purpose |
> |---|---|---|---|
> | `CleanCloudCIReadOnly` | Hub account | GitHub Actions OIDC | What CleanCloud *runs as* in CI |
> | `CleanCloudReadOnlyRole` | Each spoke account | Hub account (STS) | What CleanCloud *assumes into* per target account |
>
> The [CI/CD Setup](#2-cicd-setup-oidc--recommended) section above covers `CleanCloudCIReadOnly`. This section covers `CleanCloudReadOnlyRole`.

### Choosing a discovery mode

| Mode | Flag | When to use |
|------|------|-------------|
| **AWS Organizations auto-discovery** | `--org` | You use AWS Organizations and want every active account scanned automatically. Requires `organizations:ListAccounts` on the hub role ([see step 3](#3-for---org-auto-discovery-add-organizationslistaccounts-to-the-hub-account-role)). |
| **Config file** | `--multi-account .cleancloud/accounts.yaml` | You want explicit control over which accounts are scanned, or you're not using AWS Organizations. |
| **Inline IDs** | `--accounts 111,222,333` | Quick ad-hoc scan of a few accounts — no file needed. |

> `--org` only needs one extra permission on the **hub** role. Spoke accounts need no changes regardless of which mode you use.

### Setup Overview

Three steps, done once:

**Step 1 — Deploy the role to each spoke account**

Use the CloudFormation template or Terraform module to create `CleanCloudReadOnlyRole` in every account you want to scan. For an AWS Organization, a single StackSet deploys to all accounts at once.

→ [CloudFormation StackSet](#option-b-cloudformation-stackset-10-accounts-aws-native) · [Terraform module](#option-c-terraform-if-you-already-manage-iam-with-terraform)

**Step 2 — Ensure your hub account has `sts:AssumeRole` permission**

The identity CleanCloud runs as (OIDC role, CLI profile, etc.) must be allowed to call `sts:AssumeRole`. Add this to its IAM policy if not already present:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/CleanCloudReadOnlyRole"
}
```

**Step 3 — Run the scan**

```bash
# Auto-discover all accounts in your AWS Organization
cleancloud scan --provider aws --org --all-regions

# Or use an explicit account list
cleancloud scan --provider aws --multi-account .cleancloud/accounts.yaml --all-regions
```

Not sure if everything is wired up correctly? Run `cleancloud doctor --provider aws --multi-account .cleancloud/accounts.yaml` first — it validates role assumption account by account before touching anything.

---

### IAM Setup (Target Accounts)

Each account you want to scan needs a role that your hub account (where CleanCloud runs) can assume.

**1. Create the role in each target account:**

```bash
aws iam create-role \
  --role-name CleanCloudReadOnlyRole \
  --assume-role-policy-document file://cleancloud-cross-account-trust.json
aws iam put-role-policy \
  --role-name CleanCloudReadOnlyRole \
  --policy-name CleanCloudReadOnly \
  --policy-document file://cleancloud-policy.json
```

**2. Trust policy (`cleancloud-cross-account-trust.json`) — allows your hub account to assume the role:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::<HUB_ACCOUNT_ID>:root"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

Replace `<HUB_ACCOUNT_ID>` with the account ID where CleanCloud runs (your CI/CD account or local account).

**With ExternalId (recommended for enterprise):**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::<HUB_ACCOUNT_ID>:root"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "your-external-id"
      }
    }
  }]
}
```

**3. For `--org` auto-discovery**, add `organizations:ListAccounts` to the hub account role:

```json
{
  "Sid": "OrgReadOnly",
  "Effect": "Allow",
  "Action": "organizations:ListAccounts",
  "Resource": "*"
}
```

---

### Deploy the Cross-Account Role

#### Option A: AWS CLI (quickest — 1 to ~10 accounts)

No prerequisites. Run this in each spoke account (or paste into [AWS CloudShell](https://console.aws.amazon.com/cloudshell) logged into the spoke account):

```bash
HUB_ACCOUNT_ID=<HUB_ACCOUNT_ID>   # account where CleanCloud runs

aws iam create-role \
  --role-name CleanCloudReadOnlyRole \
  --assume-role-policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Principal\": {\"AWS\": \"arn:aws:iam::${HUB_ACCOUNT_ID}:root\"},
      \"Action\": \"sts:AssumeRole\"
    }]
  }"

aws iam put-role-policy \
  --role-name CleanCloudReadOnlyRole \
  --policy-name CleanCloudBase \
  --policy-document file://security/aws/base-readonly.json

aws iam put-role-policy \
  --role-name CleanCloudReadOnlyRole \
  --policy-name CleanCloudHygiene \
  --policy-document file://security/aws/hygiene-readonly.json
```

> The policy files are in the [CleanCloud repo](https://github.com/cleancloud-io/cleancloud/tree/main/security/aws). Download or clone the repo first, then run the commands above.
>
> **`base-readonly.json` is always required** — it provides `cloudwatch:GetMetricStatistics` and `sts:GetCallerIdentity` used across all scan categories. Never attach a category policy without it.
>
> To also enable AI/ML rules (`--category ai`), attach the AI policy:
> ```bash
> aws iam put-role-policy \
>   --role-name CleanCloudReadOnlyRole \
>   --policy-name CleanCloudAI \
>   --policy-document file://security/aws/ai-readonly.json
> ```

Repeat for each spoke account — takes under 30 seconds per account.

**With ExternalId (optional, confused deputy protection):**
```bash
aws iam create-role \
  --role-name CleanCloudReadOnlyRole \
  --assume-role-policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Principal\": {\"AWS\": \"arn:aws:iam::${HUB_ACCOUNT_ID}:root\"},
      \"Action\": \"sts:AssumeRole\",
      \"Condition\": {\"StringEquals\": {\"sts:ExternalId\": \"my-secret-token\"}}
    }]
  }"
```

---

#### Option B: CloudFormation StackSet (10+ accounts, AWS-native)

Use [`deploy/cloudformation/cleancloud-role.yaml`](../deploy/cloudformation/cleancloud-role.yaml) — deploys to all member accounts in one operation. Requires trusted access enabled between CloudFormation and AWS Organizations (done once in your management account).

**Entire AWS Organization (management account):**
```bash
aws cloudformation create-stack-set \
  --stack-set-name cleancloud-role \
  --template-body file://deploy/cloudformation/cleancloud-role.yaml \
  --parameters ParameterKey=HubAccountId,ParameterValue=<HUB_ACCOUNT_ID> \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false

# Deploy to all accounts in the org
aws cloudformation create-stack-instances \
  --stack-set-name cleancloud-role \
  --deployment-targets OrganizationalUnitIds=<ROOT_OU_ID> \
  --regions us-east-1
```

With `AUTO_DEPLOYMENT` enabled, new accounts added to the org automatically get the role.

**Single account:**
```bash
aws cloudformation deploy \
  --stack-name cleancloud-role \
  --template-file deploy/cloudformation/cleancloud-role.yaml \
  --parameter-overrides HubAccountId=<HUB_ACCOUNT_ID> \
  --capabilities CAPABILITY_NAMED_IAM
```

**To include AI/ML rules:**
```bash
aws cloudformation deploy \
  --stack-name cleancloud-role \
  --template-file deploy/cloudformation/cleancloud-role.yaml \
  --parameter-overrides HubAccountId=<HUB_ACCOUNT_ID> EnableAIScan=true \
  --capabilities CAPABILITY_NAMED_IAM
```

---

#### Option C: Terraform (if you already manage IAM with Terraform)

Use [`deploy/terraform/aws/`](../deploy/terraform/aws/) — drop it into your existing Terraform codebase.

**Single account:**
```hcl
module "cleancloud_role" {
  source = "github.com/cleancloud-io/cleancloud//deploy/terraform/aws"

  hub_account_id = "<HUB_ACCOUNT_ID>"
}
```

**All accounts via `for_each`:**
```hcl
locals {
  spoke_accounts = {
    production = "111111111111"
    staging    = "222222222222"
    dev        = "333333333333"
  }
}

module "cleancloud_role" {
  for_each = local.spoke_accounts
  source   = "github.com/cleancloud-io/cleancloud//deploy/terraform/aws"

  providers = {
    aws = aws.accounts[each.key]
  }

  hub_account_id = "<HUB_ACCOUNT_ID>"
  role_name      = "CleanCloudReadOnlyRole"
}
```

**With ExternalId:**
```hcl
module "cleancloud_role" {
  source = "github.com/cleancloud-io/cleancloud//deploy/terraform"

  hub_account_id = "<HUB_ACCOUNT_ID>"
  external_id    = "my-secret-token"
}
```

**With AI/ML rules:**
```hcl
module "cleancloud_role" {
  source = "github.com/cleancloud-io/cleancloud//deploy/terraform/aws"

  hub_account_id = "<HUB_ACCOUNT_ID>"
  enable_ai      = true
}
```

---

### .cleancloud/accounts.yaml Format

Commit this file to your repository at `.cleancloud/accounts.yaml`. In CI/CD, `actions/checkout@v4` (or equivalent) makes it available to the runner automatically.

You can use a different path — just pass it to `--multi-account /your/path/accounts.yaml`. `.cleancloud/accounts.yaml` is the recommended convention.

```yaml
# .cleancloud/accounts.yaml
role_name: CleanCloudReadOnlyRole   # Role to assume in each account
external_id: your-external-id       # Optional — required if trust policy uses ExternalId
scan_timeout: 3600                  # Total scan timeout in seconds (default: 3600 — 1 hour)

accounts:
  - id: "111111111111"
    name: production
  - id: "222222222222"
    name: staging
  - id: "333333333333"
    name: dev
```

---

### Scanning

```bash
# From .cleancloud/accounts.yaml
cleancloud scan --provider aws --multi-account .cleancloud/accounts.yaml --all-regions

# Inline account IDs (quick scan, no file needed)
cleancloud scan --provider aws --accounts 111111111111,222222222222 --all-regions

# Auto-discover all accounts in the AWS Organization
cleancloud scan --provider aws --org --all-regions

# With enforcement
cleancloud scan --provider aws --multi-account .cleancloud/accounts.yaml --all-regions \
  --fail-on-confidence HIGH --fail-on-cost 500

# Custom role name
cleancloud scan --provider aws --multi-account .cleancloud/accounts.yaml --all-regions \
  --role-name MyCustomReadOnlyRole

# With ExternalId (overrides .cleancloud/accounts.yaml value)
cleancloud scan --provider aws --multi-account .cleancloud/accounts.yaml --all-regions \
  --external-id your-external-id
```

---

### Validate Multi-Account Setup

Before running a full scan, validate that CleanCloud can reach all target accounts:

```bash
cleancloud doctor --provider aws --multi-account .cleancloud/accounts.yaml
```

**What it checks:**
- Hub account credentials are valid
- `organizations:ListAccounts` permission (for `--org`)
- Each target account: role exists, trust policy allows assumption, returns valid identity

**Example output:**

```
======================================================================
MULTI-ACCOUNT VALIDATION
======================================================================
Role name    : CleanCloudReadOnlyRole
External ID  : (none)
Accounts     : 3

Step 1: Hub Account Credentials
----------------------------------------------------------------------
[OK] Hub account: 000000000000  (arn:aws:sts::000000000000:assumed-role/CleanCloudCIReadOnly/github-actions)

Step 2: Hub Role Permissions
----------------------------------------------------------------------
[OK] organizations:ListAccounts  ✅  (--org flag will work)

Step 3: Cross-Account Role Validation
----------------------------------------------------------------------
[OK] production (111111111111)  →  arn:aws:sts::111111111111:assumed-role/CleanCloudReadOnlyRole/cleancloud-111111111111
[OK] staging (222222222222)  →  arn:aws:sts::222222222222:assumed-role/CleanCloudReadOnlyRole/cleancloud-222222222222
❌  dev (333333333333)  →  AccessDenied: role not found

======================================================================
MULTI-ACCOUNT SUMMARY
======================================================================
Accounts passed : 2/3
Accounts failed : 1
  333333333333: AccessDenied: role not found
Expected role ARN format: arn:aws:iam::<ACCOUNT_ID>:role/CleanCloudReadOnlyRole
See docs/aws.md for cross-account IAM setup instructions
======================================================================
```

---

## Region Scanning

AWS requires you to specify a region or use `--all-regions`. There is no default.

| Mode | Command | Typical scan time |
|---|---|---|
| Single region | `cleancloud scan --provider aws --region us-east-1` | 15–30 sec |
| Active regions (recommended) | `cleancloud scan --provider aws --all-regions` | 2–3 min (scans 3–5 regions with resources) |
| All enabled regions | `cleancloud scan --provider aws --all-regions` (auto-detects) | 8–10 min (25+ regions) |

**Why no default?** AWS has 30+ regions — scanning all by default would be slow and wasteful. `--all-regions` auto-detects only the regions that have active resources.

### Region Validation

CleanCloud validates region names immediately and fails fast on typos:

```bash
cleancloud scan --provider aws --region invalid-xyz
# Error: 'invalid-xyz' is not a valid AWS region
#
# Common AWS regions:
#   us-east-1, us-east-2, us-west-1, us-west-2
#   eu-west-1, eu-central-1, ap-southeast-1, ap-northeast-1
```

---

## Validate Setup

Use the `doctor` command for the category you plan to scan:

```bash
# Default hygiene scan
cleancloud doctor --provider aws --region us-east-1

# AI/ML scan
cleancloud doctor --provider aws --category ai --region us-east-1
```

**What the default doctor checks:**
- AWS credentials are valid
- Authentication method (OIDC, Instance Profile, ECS Task Role, AssumeRole, CLI Profile, Environment Variables)
- Security grade (EXCELLENT/GOOD/ACCEPTABLE/POOR)
- CI/CD readiness and compliance compatibility
- Account ID, User ID, and ARN
- The default base + hygiene read-only permissions used by `cleancloud scan --provider aws`

**Example output:**
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

[OK] Compliance: SOC2/ISO27001 Compatible

Step 3: Identity Verification
----------------------------------------------------------------------
[OK] Account ID: 123456789012
[OK] User ID: AROA3XFRBF23:github-actions
[OK] ARN: arn:aws:sts::123456789012:assumed-role/CleanCloudCIReadOnly/github-actions
  Role Name: CleanCloudCIReadOnly
  Session Name: github-actions
[OK]   - OIDC-based assumed role (recommended)

Step 4: Read-Only Permission Validation
----------------------------------------------------------------------
[OK] ec2:DescribeVolumes
[OK] ec2:DescribeSnapshots
[OK] ec2:DescribeRegions
[OK] ec2:DescribeAddresses
[OK] ec2:DescribeNetworkInterfaces
[OK] ec2:DescribeImages
[OK] ec2:DescribeNatGateways
[OK] ec2:DescribeInstances
[OK] ec2:DescribeSecurityGroups
[OK] rds:DescribeDBInstances
[OK] rds:DescribeDBSnapshots
[OK] elasticloadbalancing:DescribeLoadBalancers
[OK] elasticloadbalancing:DescribeTargetGroups
[OK] logs:DescribeLogGroups
[OK] cloudwatch:GetMetricStatistics
[OK] s3:ListAllMyBuckets
[OK] s3:GetBucketTagging

======================================================================
VALIDATION SUMMARY
======================================================================
Authentication: OIDC (AssumeRoleWithWebIdentity)
Security Grade: EXCELLENT
Permissions Tested: 17/17 passed

[OK] AWS ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

**What the AI doctor adds:** Bedrock Provisioned Throughput, SageMaker endpoints, notebook instances, SageMaker Domains, SageMaker Studio apps, SageMaker training jobs, SageMaker processing jobs, EC2 GPU inventory, and the CloudWatch permissions those AI rules need. Run it before `cleancloud scan --provider aws --category ai`.

---

## Output Formats

```bash
# Human-readable (default)
cleancloud scan --provider aws --region us-east-1

# JSON (machine-readable, includes evidence and full metadata)
cleancloud scan --provider aws --region us-east-1 --output json --output-file results.json

# CSV (spreadsheet-friendly, 11 core columns)
cleancloud scan --provider aws --region us-east-1 --output csv --output-file results.csv

# Markdown (paste into GitHub PRs, Slack, or issues)
cleancloud scan --provider aws --all-regions --output markdown
cleancloud scan --provider aws --all-regions --output markdown --output-file results.md
```

**JSON schema, examples, and CSV column reference:** See [`ci.md`](ci.md#output-formats)

---

## Troubleshooting

### OIDC Subject Claim Mismatch

**Symptom:** `Error assuming role` or `AccessDenied` during the AWS credentials step, even though the IAM role and OIDC provider exist.

**Cause:** The subject claim in your IAM role trust policy does not match what GitHub actually sends in the JWT token. GitHub generates different subject claims depending on how your workflow is triggered.

**The three subject formats:**

| Workflow uses | GitHub sends | Trust policy `sub` condition |
|---|---|---|
| Branch push to `main` | `repo:org/repo:ref:refs/heads/main` | `repo:<ORG>/<REPO>:ref:refs/heads/main` |
| Pull request trigger | `repo:org/repo:pull_request` | `repo:<ORG>/<REPO>:pull_request` |
| `environment: production` | `repo:org/repo:environment:production` | `repo:<ORG>/<REPO>:environment:production` |

**Fix — check your workflow trigger and update the trust policy:**

If your workflow has `environment:` set:

```yaml
jobs:
  cleancloud:
    environment: production   # ← this changes the subject claim
```

Update the trust policy `sub` condition to match:

```json
"token.actions.githubusercontent.com:sub": "repo:<YOUR_ORG>/<YOUR_REPO>:environment:production"
```

**Multiple triggers — allow both subject formats in one trust policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": [
          "repo:<YOUR_ORG>/<YOUR_REPO>:ref:refs/heads/main",
          "repo:<YOUR_ORG>/<YOUR_REPO>:environment:production"
        ]
      }
    }
  }]
}
```

> 💡 GitHub Environments are the recommended approach for production pipelines — they add deployment protection rules, required reviewers, and environment-scoped secrets on top of OIDC.

---

### "No credentials found"

```bash
# Verify credentials work
aws sts get-caller-identity
```

**Fix:**
- Set up AWS CLI: `aws configure`
- Or export environment variables
- Or configure OIDC in GitHub Actions

### "Access Denied"

```bash
# Check permissions
cleancloud doctor --provider aws
```

**Fix:**
- Attach the CleanCloud IAM policy
- Wait 5-10 minutes for IAM propagation
- Verify trust policy for OIDC roles

### "No active regions detected"

**This means:** CleanCloud found no resources in any enabled region

**Options:**
1. Scan specific region: `--region us-east-1`
2. Check if you're scanning the right account
3. Verify permissions are working: `cleancloud doctor --provider aws`

---

## Security Best Practices

### DO

- Use OIDC for CI/CD (no long-lived credentials)
- Use least-privilege IAM policy
- Enable CloudTrail logging for audit trails
- Restrict OIDC trust to specific repos and branches
- Rotate access keys regularly (if using keys)

### DON'T

- Use long-lived access keys in CI/CD
- Use overly broad policies (e.g., `ReadOnlyAccess`)
- Share credentials across teams
- Commit credentials to repositories

---

## Supported Regions

All AWS commercial regions are supported.

CleanCloud auto-detects opt-in status:
- Default regions (us-east-1, us-west-2, etc.)
- Opt-in regions you've enabled (ap-east-1, me-south-1, etc.)
- Disabled regions (skipped automatically)

**Not tested:** AWS GovCloud, AWS China regions

---

**Next:** [Azure Setup →](azure.md) | [Rules Reference →](rules.md) | [CI/CD Guide →](ci.md)
