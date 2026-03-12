# AWS Setup

AWS authentication, IAM policies, and configuration guide.

> **Quick Start:** See [README.md](../README.md)  
> **Rules Reference:** See [rules.md](rules.md)  
> **CI/CD Integration:** See [ci.md](ci.md)

---

## Quick Setup

Get OIDC running in 3 steps:

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

Full walkthrough → [GitHub Actions OIDC setup](#1-github-actions-oidc-recommended-for-cicd)

---

## Authentication Methods

CleanCloud supports multiple AWS authentication methods:

### 1. GitHub Actions OIDC (Recommended for CI/CD)

**No long-lived credentials, temporary tokens only, SOC2 compliant.**

#### Setup Steps

**Step 1: Create the OIDC Identity Provider** (one-time per AWS account)
```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

> **Note:** A `--thumbprint-list` parameter is no longer required. AWS validates GitHub's OIDC tokens directly without certificate pinning. See [aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials) for details.

**Step 2: Create the trust policy file** (`cleancloud-trust-policy.json`)

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

**Step 3: Create the IAM role**
```bash
aws iam create-role \
  --role-name CleanCloudCIReadOnly \
  --assume-role-policy-document file://cleancloud-trust-policy.json
```

**Step 4: Attach the read-only policy** (see [IAM Policy](#iam-policy-minimum-required-permissions) below)
```bash
aws iam put-role-policy \
  --role-name CleanCloudCIReadOnly \
  --policy-name CleanCloudReadOnly \
  --policy-document file://cleancloud-policy.json
```

**Step 5: Add your AWS account ID as a GitHub repository variable**

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
          pip install cleancloud
          cleancloud doctor --provider aws --region us-east-1
```

For the complete production workflow with enforcement flags, scheduling, and artifact upload: **[CI/CD guide →](ci.md)**

---

### 2. AWS CLI Profiles (Local Development)

```bash
# Configure profile
aws configure --profile cleancloud

# Use with CleanCloud
cleancloud scan --provider aws --profile cleancloud --region us-east-1
```

---

### 3. Environment Variables

```bash
export AWS_ACCESS_KEY_ID=<your-key>
export AWS_SECRET_ACCESS_KEY=<your-secret>
export AWS_DEFAULT_REGION=us-east-1

cleancloud scan --provider aws --region us-east-1
```

**Not recommended for CI/CD** - Use OIDC instead

---

## IAM Policy (Minimum Required Permissions)

Attach this policy to your IAM role or user:

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
        "ec2:DescribeImages",
        "ec2:DescribeAddresses",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeNatGateways",
        "ec2:DescribeRegions"
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
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchReadOnly",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
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

Use the `doctor` command to verify credentials and permissions:

```bash
cleancloud doctor --provider aws --region us-east-1
```

**What it checks:**
- AWS credentials are valid
- Authentication method (OIDC, Instance Profile, ECS Task Role, AssumeRole, CLI Profile, Environment Variables)
- Security grade (EXCELLENT/GOOD/ACCEPTABLE/POOR)
- CI/CD readiness and compliance compatibility
- Account ID, User ID, and ARN
- All 14 required read-only permissions

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
[OK] rds:DescribeDBInstances
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
Permissions Tested: 14/14 passed

[OK] AWS ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

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