# AWS Setup

AWS authentication, IAM policies, and configuration guide.

> **Quick Start:** See [README.md](../README.md)  
> **Rules Reference:** See [rules.md](rules.md)  
> **CI/CD Integration:** See [ci.md](ci.md)

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

#### GitHub Actions Workflow

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

### Default Behavior

```bash
# AWS requires explicit region choice
cleancloud scan --provider aws --region us-east-1

# Or scan all regions with resources
cleancloud scan --provider aws --all-regions

# ERROR: Must specify --region or --all-regions
```

**Why?** AWS has 30+ regions, and scanning all by default would be slow and expensive.

### Region Validation

CleanCloud validates region names immediately. If you specify an invalid region, the scan fails fast:

```bash
cleancloud scan --provider aws --region invalid-xyz
# Error: 'invalid-xyz' is not a valid AWS region
#
# Common AWS regions:
#   us-east-1, us-east-2, us-west-1, us-west-2
#   eu-west-1, eu-central-1, ap-southeast-1, ap-northeast-1
#
# All known regions:
#   [Lists all 30+ valid regions]
```

**Benefits:**
- Fast fail (~1ms) instead of waiting for timeouts
- Clear error messages with suggestions
- Prevents accidental typos (e.g., `us-esat-1` instead of `us-east-1`)

### Scan Specific Region

```bash
cleancloud scan --provider aws --region us-east-1
```

### Scan All Active Regions

```bash
cleancloud scan --provider aws --all-regions

# Auto-detects regions with resources (typically 3-5 regions)
# Scans volumes, snapshots, and logs to determine active regions
```

**Performance:**
- Single region: 15-30 seconds
- All active regions (3-5): 2-3 minutes
- All enabled regions (25+): 8-10 minutes

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
```

**JSON schema, examples, and CSV column reference:** See [`ci.md`](ci.md#output-formats)

---

## Troubleshooting

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