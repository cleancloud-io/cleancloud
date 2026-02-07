# AWS Setup

AWS authentication, IAM policies, and configuration guide.

> **Quick Start:** See [README.md](../README.md)  
> **Rules Reference:** See [rules.md](rules.md)  
> **CI/CD Integration:** See [ci.md](ci.md)

---

## Authentication Methods

CleanCloud supports three AWS authentication methods:

### 1. GitHub Actions OIDC (Recommended for CI/CD)

**No long-lived credentials, temporary tokens only, SOC2 compliant.**

#### IAM Role Trust Policy

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
- `<ACCOUNT_ID>` - Your AWS account ID
- `<YOUR_ORG>/<YOUR_REPO>` - Your GitHub organization and repository

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
          role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/CleanCloudCIReadOnly
          aws-region: us-east-1

      - name: Run CleanCloud
        run: |
          pip install cleancloud
          cleancloud scan --provider aws --region us-east-1
```

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
        "ec2:DescribeInstances",
        "ec2:DescribeAddresses",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRegions",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogsReadOnly",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3ReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging",
        "s3:ListBucket"
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
- Authentication method (OIDC, profiles, keys)
- Security grade (EXCELLENT/GOOD/ACCEPTABLE/POOR)
- Required permissions are present
- Account ID and ARN

**Example output:**
```
Step 1: AWS Credential Resolution
[OK] AWS session created successfully

Step 2: Authentication Method Detection
Authentication Method: OIDC (AssumeRoleWithWebIdentity)
[OK] Security Grade: EXCELLENT
[OK] CI/CD Ready: YES

Step 3: Identity Verification
[OK] Account ID: 123456789012
[OK] ARN: arn:aws:sts::123456789012:assumed-role/CleanCloudScanner/GitHubActions

Step 4: Read-Only Permission Validation
[OK] ec2:DescribeVolumes
[OK] ec2:DescribeSnapshots
[OK] ec2:DescribeRegions
[OK] ec2:DescribeAddresses
[OK] ec2:DescribeNetworkInterfaces
[OK] logs:DescribeLogGroups
[OK] s3:ListAllMyBuckets

[OK] AWS ENVIRONMENT READY FOR CLEANCLOUD
```

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