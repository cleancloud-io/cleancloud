# AWS Setup Guide

Complete configuration guide for running CleanCloud against AWS accounts.

---

## Overview

CleanCloud scans AWS accounts to identify orphaned, untagged, and potentially inactive resources using **read-only APIs only**. No resources are ever modified, deleted, or tagged.

**What CleanCloud detects:**
- Unattached EBS volumes
- Old EBS snapshots (90+ days)
- CloudWatch log groups with infinite retention
- Untagged resources (volumes, buckets, log groups)

**What CleanCloud does NOT do:**
- ❌ Delete or modify resources
- ❌ Make cost optimization recommendations
- ❌ Enforce policies automatically
- ❌ Require billing/cost data access

---

## Quick Start

### 1. Validate Credentials

```bash
cleancloud doctor --provider aws --region us-east-1
```

This validates:
- AWS credentials are configured
- Required IAM permissions exist
- API connectivity works

### 2. Run a Scan

```bash
# Single region
cleancloud scan --provider aws --region us-east-1

# All enabled regions
cleancloud scan --provider aws --all-regions

# Export to JSON
cleancloud scan --provider aws --all-regions --output json --output-file results.json
```

---

## IAM Permissions

CleanCloud requires **read-only permissions** only.

### Recommended IAM Policy

Create an IAM policy named `CleanCloudReadOnly`:

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
        "ec2:DescribeInstances",
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

### What This Policy Does NOT Allow

- ❌ Delete operations (`Delete*`)
- ❌ Modification operations (`Modify*`, `Update*`)
- ❌ Tagging operations (`Tag*`, `Untag*`)
- ❌ Attachment operations (`Attach*`, `Detach*`)
- ❌ Billing data access (`ce:*`, `cur:*`)

### Attach Policy To

**Option A: IAM Role (Recommended for Production)**
```bash
aws iam attach-role-policy \
  --role-name CleanCloudRole \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/CleanCloudReadOnly
```

**Option B: IAM User (Acceptable for Testing)**
```bash
aws iam attach-user-policy \
  --user-name cleancloud \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/CleanCloudReadOnly
```

---

## Authentication

CleanCloud uses the standard AWS SDK credential resolution chain.

### Using AWS Profiles

```bash
# Configure profile
aws configure --profile cleancloud

# Use profile with CleanCloud
cleancloud scan --provider aws --profile cleancloud --region us-east-1
```

### Using Environment Variables

```bash
export AWS_ACCESS_KEY_ID=x
export AWS_SECRET_ACCESS_KEY=x
export AWS_DEFAULT_REGION=x

cleancloud scan --provider aws
```

### Using IAM Roles (EC2/ECS/Lambda)

If running on EC2, ECS, or Lambda, CleanCloud automatically uses the instance/task IAM role. No additional configuration needed.

---

## Rules

CleanCloud implements 4 conservative, high-signal rules for AWS.

### 1. Unattached EBS Volumes

**Rule ID:** `aws.ebs.volume.unattached`

**Detects:** EBS volumes not attached to any EC2 instance.

**Signal:** `volume.state != "in-use"`

**Why safe:** Volume attachment state is deterministic. No heuristics or age thresholds needed.

**Confidence:** HIGH  
**Risk:** LOW

**Common causes:**
- Volumes from terminated instances
- Volumes created by autoscaling groups
- Failed deployments

**Required permission:** `ec2:DescribeVolumes`

---

### 2. Old EBS Snapshots

**Rule ID:** `aws.ebs.snapshot.old`

**Detects:** EBS snapshots older than 90 days (configurable).

**Signals:**
- Snapshot age ≥ 90 days
- Owned by current account (`OwnerIds=["self"]`)

**Conservative approach:** Does NOT attempt to detect AMI linkage at MVP stage to avoid false positives.

**Confidence:** HIGH  
**Risk:** LOW

**Common causes:**
- Snapshots from CI/CD backup jobs
- Snapshots from deleted volumes
- Over-retention without lifecycle policies

**Required permission:** `ec2:DescribeSnapshots`

---

### 3. CloudWatch Log Groups (Infinite Retention)

**Rule ID:** `aws.cloudwatch.logs.infinite_retention`

**Detects:** CloudWatch log groups with no retention policy configured (logs never expire).

**Signal:** `retentionInDays == null`

**Why conservative:** Only flags infinite retention, does NOT infer ingestion activity (to avoid false positives).

**Confidence:** HIGH  
**Risk:** LOW

**Common causes:**
- Log groups created by Lambda/ECS without retention policies
- Log groups from deleted services
- Default CloudWatch behavior (no expiration)

**Required permission:** `logs:DescribeLogGroups`

---

### 4. Untagged Resources

**Rule ID:** `aws.resource.untagged`

**Detects:** Resources with no tags at all.

**Resources scanned:**
- EBS volumes
- S3 buckets
- CloudWatch log groups

**Signal:** Empty or missing tag set

**Why this matters:** Untagged resources are difficult to attribute to owners, making them high-risk for becoming orphaned.

**Confidence:** MEDIUM  
**Risk:** LOW

**Required permissions:**
- `ec2:DescribeVolumes`
- `s3:ListAllMyBuckets`
- `s3:GetBucketTagging`
- `logs:DescribeLogGroups`

---

## Multi-Region Scanning

### Single Region

```bash
cleancloud scan --provider aws --region us-west-2
```

### All Regions

```bash
cleancloud scan --provider aws --all-regions
```

When `--all-regions` is specified:
1. CleanCloud calls `ec2:DescribeRegions` to discover enabled regions
2. Scans each region sequentially (to avoid API throttling)
3. Aggregates findings across all regions

**Note:** S3 is scanned once globally (not per-region) to avoid duplicate findings.

---

## Output Formats

### Human-Readable (Default)

```bash
cleancloud scan --provider aws

# Example output:
🔍 Found 3 hygiene issues:

1. [AWS] Unattached EBS volume
   Resource : ebs_volume → vol-0abc123def456789
   Region   : us-east-1
   Confidence: HIGH
   Reason   : Volume state is not 'in-use'
```

### JSON

```bash
cleancloud scan --provider aws --output json --output-file results.json
```

**Schema:**
```json
{
  "summary": {
    "total_findings": 12,
    "by_provider": {"aws": 12},
    "by_confidence": {"HIGH": 8, "MEDIUM": 4},
    "scanned_at": "2025-01-15T10:30:00Z"
  },
  "findings": [
    {
      "provider": "aws",
      "rule_id": "aws.ebs.volume.unattached",
      "resource_type": "ebs_volume",
      "resource_id": "vol-0abc123def456789",
      "region": "us-east-1",
      "confidence": "HIGH",
      "risk": "LOW",
      "detected_at": "2025-01-15T10:30:00Z",
      "details": {...}
    }
  ]
}
```

### CSV

```bash
cleancloud scan --provider aws --output csv --output-file results.csv
```

**Columns:** provider, rule_id, resource_type, resource_id, region, title, confidence, risk, detected_at

---

## CI/CD Integration

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully, no policy violations |
| 1 | Configuration error or unexpected failure |
| 2 | Policy violation detected (findings present with enforcement flag) |
| 3 | Missing AWS credentials or insufficient permissions |

### Policy Enforcement

**Informational mode (default):**
```bash
cleancloud scan --provider aws
# Exit code 0 even if findings exist
```

**Fail on HIGH confidence findings (recommended):**
```bash
cleancloud scan --provider aws --fail-on-confidence HIGH
# Exit code 2 if any HIGH confidence findings exist
```

**Fail on any findings (strict):**
```bash
cleancloud scan --provider aws --fail-on-findings
# Exit code 2 if any findings exist (not recommended - too noisy)
```

### GitHub Actions Example

```yaml
name: CleanCloud AWS Scan

on:
  pull_request:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/CleanCloudRole
          aws-region: us-east-1

      - name: Run CleanCloud scan
        run: |
          pip install cleancloud
          cleancloud scan --provider aws --all-regions \
            --output json --output-file results.json \
            --fail-on-confidence HIGH

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cleancloud-results
          path: results.json
```

---

## Troubleshooting

### "No AWS credentials found"

**Cause:** AWS credentials not configured.

**Solution:**
```bash
# Check if credentials are configured
aws sts get-caller-identity

# If not, configure them
aws configure
```

### "Access Denied" / "UnauthorizedOperation"

**Cause:** Missing IAM permissions.

**Solution:**
1. Run `cleancloud doctor --provider aws` to identify missing permissions
2. Attach the CleanCloudReadOnly policy (see IAM Permissions section)
3. Verify with `aws iam get-user-policy` or `aws iam get-role-policy`

### "Rate limit exceeded"

**Cause:** Scanning too many regions/resources too quickly.

**Solution:**
- CleanCloud automatically paginates API calls
- Scans regions sequentially to avoid throttling
- If still rate-limited, wait 5-10 minutes and retry

---

## Design Philosophy

CleanCloud for AWS follows these principles:

1. **Conservative over aggressive** - Prefer false negatives to false positives
2. **Multiple signals required** - Never flag based on a single weak indicator
3. **Explicit confidence levels** - Always state LOW/MEDIUM/HIGH confidence
4. **Review-only recommendations** - Never justify automated deletion

These principles make CleanCloud safe for:
- Production AWS accounts
- Regulated environments (HIPAA, SOC2, PCI-DSS)
- Security-reviewed CI/CD pipelines
- Multi-tenant infrastructure

---

## Supported AWS Services

| Service | Resources | Status |
|---------|-----------|--------|
| EC2 | EBS volumes, snapshots | ✅ Supported |
| CloudWatch | Log groups | ✅ Supported |
| S3 | Buckets (tagging only) | ✅ Supported |
| EC2 | Elastic IPs | 🔜 Planned |
| EC2 | AMIs | 🔜 Planned |
| EC2 | Security groups | 🔜 Planned |
| RDS | Snapshots | 🔜 Planned |

---

## Next Steps

- Review detected findings: [Rule documentation](rules.md)
- Integrate with CI/CD: [CI/CD guide](ci.md)
- Configure Azure scanning: [Azure setup](azure.md)

---

## FAQ

**Q: Will CleanCloud delete my resources?**  
A: No. CleanCloud is read-only and never modifies, deletes, or tags resources.

**Q: Does CleanCloud access billing data?**  
A: No. CleanCloud does not require or access AWS billing/cost APIs.

**Q: Can I customize age thresholds?**  
A: Not yet. Conservative defaults (90 days for snapshots, 7-14 days for disks) are hardcoded at MVP stage. Configuration support is planned.

**Q: Why so few rules?**  
A: CleanCloud prioritizes high-signal, low-risk rules over breadth. Each rule must meet a strict safety bar before being added.

**Q: Does CleanCloud support GovCloud/China regions?**  
A: Not tested. Standard commercial regions only at MVP stage.