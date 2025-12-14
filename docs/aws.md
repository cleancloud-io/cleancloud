# CleanCloud — AWS Setup Guide

This document describes everything required to run **CleanCloud** against an AWS account.

CleanCloud is a **read-only cloud hygiene tool**.  
It does **not** create, modify, or delete any cloud resources.

---

## 🚀 Quick Start (5 minutes)

1. Create an IAM user or role with the policy below.
2. Configure AWS credentials (profile or environment variables).
3. Run:

   ```bash
   cleancloud doctor
This verifies credentials and permissions.
4. Run:

    ```bash
    cleancloud scan --output json


## 🔐 IAM Permissions (Required)

CleanCloud requires a least-privilege, read-only IAM policy.

Policy Name

**CleanCloudReadOnlyAWS**

Policy JSON

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "STSIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2ReadOnlyForHygiene",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVolumes",
        "ec2:DescribeInstances",
        "ec2:DescribeSnapshots"
      ],
      "Resource": "*"
    }
  ]
}

```

**What This Policy Allows**
* Read-only access to EBS metadata and EC2 resources
* Account identity verification via STS
* Safe inspection of volumes, snapshots, and instances

**What This Policy Does NOT Allow**
* No deletions
* No modifications
* No tagging
* No resource attachments

## 👤 IAM User vs Role

CleanCloud works with either:

* IAM Role (recommended for production)
* IAM User (acceptable for local testing)

Attach the policy above to either.

## 🔑 AWS Credentials Setup

CleanCloud uses the standard AWS SDK credential resolution.

#### Option 1: AWS Profile (Recommended)

```bash
    aws configure --profile cleancloud
```


Then run:

```bash
  cleancloud doctor --profile cleancloud
  cleancloud scan --profile cleancloud --output json
```



### Option 2: Environment Variables

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

#### 🌍 Region Selection

By default, CleanCloud scans: `us-east-1`

To override:

```bash
  cleancloud scan --region eu-west-1 --output json
```

Note: CleanCloud currently scans one region at a time.

### 🩺 Preflight Check (doctor command)

Before running scans, use:

```bash
cleancloud doctor
```

This command will:

* Verify AWS credentials are configured
* Confirm that CleanCloud can call sts:GetCallerIdentity
* Confirm that required EC2 permissions (DescribeVolumes) are present
* Report any missing permissions clearly

## 🧪 Verifying Access

Successful doctor output:

```ruby
🩺 Running CleanCloud doctor (AWS)...
✅ AWS credentials valid
Account ID: 123456789012
ARN: arn:aws:iam::123456789012:user/cleanclouduser
✅ Required EC2 permissions present (DescribeVolumes)

🎉 Environment is ready to run CleanCloud scans
```

### ❌ Common Errors

**Error: NoCredentialsError**

Cause: AWS credentials not configured.

Fix:

Run `aws configure`

Or set environment variables

#### Error: UnauthorizedOperation: ec2:DescribeVolumes

Cause: Missing IAM permissions.

Fix:

Attach the CleanCloudReadOnlyAWS policy

Ensure the correct profile or role is in use

Re-run cleancloud doctor

#### 🔮 Future AWS Permissions

As CleanCloud adds new rules, additional read-only permissions may be required, for example:

* logs:DescribeLogGroups (CloudWatch Logs)
* s3:ListAllMyBuckets
* s3:GetBucketLocation

These will always be documented here before becoming required.

# 📌 Summary

* CleanCloud is safe by default
* Requires only read-only AWS access
* Can be run via IAM role or user
* doctor command ensures smooth onboarding
* Designed for security-conscious environments
* If your security team approves read-only access, CleanCloud is safe to run.

