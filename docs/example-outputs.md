# Example Outputs

Complete output examples for CleanCloud across AWS and Azure — doctor validation, human-readable scan results, JSON output for CI/CD integration, and markdown for sharing in GitHub PRs or Slack.

---

## Table of Contents

- [Doctor — AWS](#doctor--aws)
- [Doctor — Azure](#doctor--azure)
- [Doctor — Multi-Account](#doctor--multi-account)
- [Doctor — Azure Multi-Subscription](#doctor--azure-multi-subscription)
- [Scan — AWS (Human-Readable)](#scan--aws-human-readable)
- [Scan — AWS Multi-Account](#scan--aws-multi-account)
- [Scan — Azure (Human-Readable)](#scan--azure-human-readable)
- [Scan — AWS (JSON)](#scan--aws-json)
- [Scan — Azure (JSON)](#scan--azure-json)
- [Scan — AWS (Markdown)](#scan--aws-markdown)
- [Scan — Azure (Markdown)](#scan--azure-markdown)
- [JSON Schema Reference](#json-schema-reference)

---

## Doctor — AWS

`cleancloud doctor --provider aws`

Validates IAM credentials, authentication method, security grade, and all read-only permissions required for scanning.

### Local Development (AWS CLI Profile)

```
Running CleanCloud doctor


======================================================================
CLEANCLOUD ENVIRONMENT DIAGNOSTICS
======================================================================

Providers to check: AWS


======================================================================
AWS ENVIRONMENT VALIDATION
======================================================================

Step 1: AWS Credential Resolution
----------------------------------------------------------------------
[OK] AWS session created successfully

Step 2: Authentication Method Detection
----------------------------------------------------------------------
Authentication Method: AWS CLI Profile (default)
  Boto3 Provider: shared-credentials-file
  Credential Type: Long-lived
  Lifetime: long-lived (access keys)
  Rotation Required: Yes (every 90 days)

[!] Security Grade: ACCEPTABLE
[!]   - Long-lived credentials
[!]   - Manual rotation required

  Recommendation for local development:
    Current setup is acceptable

CI/CD Ready: NO (Local development only)
AWS CLI profiles are not available in CI/CD

Compliance: Acceptable for development environments

Step 3: Identity Verification
----------------------------------------------------------------------
[OK] Account ID: 123456789012
[OK] User ID: AIDAURVBTGFZCW6JGFCG2
[OK] ARN: arn:aws:iam::123456789012:user/cleanclouduser
  IAM User: cleanclouduser

Region Scope
----------------------------------------------------------------------
Active Region: us-east-1
Doctor validates permissions for the active region only
Use 'cleancloud scan --provider aws --all-regions' to scan all active regions

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
Authentication: AWS CLI Profile (default)
Security Grade: ACCEPTABLE
Permissions Tested: 19/19 passed

[OK] AWS ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

### CI/CD (OIDC — Recommended)

When running with OIDC authentication (e.g., GitHub Actions), the security grade upgrades to EXCELLENT:

```
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
```

---

## Doctor — Azure

`cleancloud doctor --provider azure`

Validates Azure credentials, subscription access, and Reader role permissions across all accessible subscriptions.

### Local Development (Service Principal)

```
Running CleanCloud doctor


======================================================================
CLEANCLOUD ENVIRONMENT DIAGNOSTICS
======================================================================

Providers to check: AZURE


======================================================================
AZURE ENVIRONMENT VALIDATION
======================================================================

Step 1: Azure Credential Resolution
----------------------------------------------------------------------
Authentication Method: Service Principal (Client Secret)
  Lifetime: long-lived (client secret)
  Rotation Required: Yes (every 90 days or per policy)
[!]   Uses Secret: Yes (stored credential)

[!] Security Grade: POOR
[!]   - Long-lived client secret
[!]   - Requires manual rotation
[!]   - High blast radius if compromised

  Recommendation for CI/CD:
    Switch to OIDC (Workload Identity Federation)
    See: https://docs.cleancloud.io/azure#oidc

[!] CI/CD Ready: NO
[!]   Client secrets not recommended for automated pipelines

[!] Compliance: May not meet enterprise security requirements

Client ID: d7b1a453-4182-41f1-aa1f-2b9c99956981
Tenant ID: a8d6813d-de25-4473-bf18-94658b348c7d
Subscription Filter: 29d91ee0-922f-483a-a81f-1a5eff4ecfa2

Step 2: Credential Acquisition
----------------------------------------------------------------------
[OK] Azure credentials acquired successfully
  Token expires in: ~59 minutes

Step 3: Subscription Access Validation
----------------------------------------------------------------------
[OK] Accessible subscriptions: 1
  • Azure subscription 1 (29d91ee0-922f-483a-a81f-1a5eff4ecfa2)

[OK] Subscription filter matched: Azure subscription 1

Step 4: Permission Validation
----------------------------------------------------------------------
[OK] Subscription read access confirmed
  Reader role provides all required permissions:
    - Microsoft.Compute/disks/read
    - Microsoft.Compute/snapshots/read
    - Microsoft.Compute/virtualMachines/read
    - Microsoft.Network/publicIPAddresses/read
    - Microsoft.Network/loadBalancers/read
    - Microsoft.Network/applicationGateways/read
    - Microsoft.Network/virtualNetworkGateways/read
    - Microsoft.Network/connections/read
    - Microsoft.Web/serverfarms/read
    - Microsoft.Web/serverfarms/sites/read
    - Microsoft.Web/sites/read
    - Microsoft.ContainerRegistry/registries/read
    - Microsoft.Sql/servers/read
    - Microsoft.Sql/servers/databases/read
    - Microsoft.Insights/metrics/read
    - Microsoft.Resources/subscriptions/read
    - Microsoft.Resources/resources/read

======================================================================
VALIDATION SUMMARY
======================================================================
Authentication: Service Principal (Client Secret)
Security Grade: POOR
Subscriptions: 1 accessible
Filtered to: 29d91ee0-922f-483a-a81f-1a5eff4ecfa2

[OK] AZURE ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

### CI/CD (OIDC — Recommended)

When running with Workload Identity Federation, the security grade upgrades to EXCELLENT:

```
Step 1: Azure Credential Resolution
----------------------------------------------------------------------
Authentication Method: OIDC (Workload Identity Federation)
  Lifetime: 1 hour (temporary)
  Rotation Required: No
[OK] Uses Secret: No (secretless)

[OK] Security Grade: EXCELLENT
[OK]   - No client secrets stored
[OK]   - Temporary credentials
[OK]   - Auto-rotated

[OK] CI/CD Ready: YES
[OK]   Suitable for production CI/CD pipelines

[OK] Compliance: SOC2/ISO27001 Compatible
```

---

## Doctor — Multi-Account

`cleancloud doctor --provider aws --multi-account accounts.yaml`

Validates cross-account role access for every account in the config before committing to a full scan.

```
Running CleanCloud doctor

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
[OK] staging (222222222222)     →  arn:aws:sts::222222222222:assumed-role/CleanCloudReadOnlyRole/cleancloud-222222222222
[!] dev (333333333333)          →  AccessDenied: role not found

======================================================================
MULTI-ACCOUNT SUMMARY
======================================================================
Accounts passed : 2/3
Accounts failed : 1
  dev (333333333333): AccessDenied: role not found

Expected role ARN format: arn:aws:iam::<ACCOUNT_ID>:role/CleanCloudReadOnlyRole
See docs/aws.md for cross-account IAM setup instructions
======================================================================
```

---

## Doctor — Azure Multi-Subscription

`cleancloud doctor --provider azure`

When the service principal has Reader on multiple subscriptions, the doctor validates all of them automatically.

```
Running CleanCloud doctor


======================================================================
AZURE ENVIRONMENT VALIDATION
======================================================================

Step 1: Azure Credential Resolution
----------------------------------------------------------------------
Authentication Method: OIDC (Workload Identity Federation)
  Lifetime: 1 hour (temporary)
  Rotation Required: No
[OK] Uses Secret: No (secretless)

[OK] Security Grade: EXCELLENT
[OK]   - No client secrets stored
[OK]   - Temporary credentials
[OK]   - Auto-rotated

[OK] CI/CD Ready: YES
[OK]   Suitable for production CI/CD pipelines

[OK] Compliance: SOC2/ISO27001 Compatible

Client ID: d7b1a453-4182-41f1-aa1f-2b9c99956981
Tenant ID: a8d6813d-de25-4473-bf18-94658b348c7d

Step 2: Credential Acquisition
----------------------------------------------------------------------
[OK] Azure credentials acquired successfully
  Token expires in: ~59 minutes

Step 3: Subscription Access Validation
----------------------------------------------------------------------
[OK] Accessible subscriptions: 3
  • Production (a1b2c3d4-e5f6-7890-abcd-ef1234567890)
  • Staging    (f9e8d7c6-b5a4-3210-fedc-ba0987654321)
  • Dev        (c3d4e5f6-a7b8-9012-cdef-345678901234)

Step 4: Permission Validation
----------------------------------------------------------------------
[OK] Subscription read access confirmed
  Reader role provides all required permissions:
    - Microsoft.Compute/disks/read
    - Microsoft.Compute/snapshots/read
    - Microsoft.Compute/virtualMachines/read
    - Microsoft.Network/publicIPAddresses/read
    - Microsoft.Network/loadBalancers/read
    - Microsoft.Network/applicationGateways/read
    - Microsoft.Network/virtualNetworkGateways/read
    - Microsoft.Network/connections/read
    - Microsoft.Web/serverfarms/read
    - Microsoft.Web/serverfarms/sites/read
    - Microsoft.Web/sites/read
    - Microsoft.ContainerRegistry/registries/read
    - Microsoft.Sql/servers/read
    - Microsoft.Sql/servers/databases/read
    - Microsoft.Insights/metrics/read
    - Microsoft.Resources/subscriptions/read
    - Microsoft.Resources/resources/read

======================================================================
VALIDATION SUMMARY
======================================================================
Authentication: OIDC (Workload Identity Federation)
Security Grade: EXCELLENT
Subscriptions: 3 accessible

[OK] AZURE ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

Assign Reader at the **Management Group level** to cover all subscriptions with a single role assignment — see [docs/azure.md](azure.md#multi-subscription-scanning).

---

## Scan — AWS Multi-Account

`cleancloud scan --provider aws --multi-account accounts.yaml --all-regions`

Scans 3 accounts in parallel, aggregates findings, and shows a per-account breakdown.

```
Starting CleanCloud scan...

Provider: aws

Scanning 3 accounts (role: CleanCloudReadOnlyRole)...

[INFO] Scanning production (111111111111)...
[INFO] Scanning staging (222222222222)...
[INFO] Scanning dev (333333333333)...
[INFO] Completed dev in 14.2s — 8 findings  ~$420
[INFO] Completed staging in 18.7s — 31 findings  ~$4,200
[INFO] Completed production in 22.1s — 45 findings  ~$12,000

Found 84 hygiene issues:

1. [AWS] Unattached EBS Volume
   Account    : production (111111111111)
   Risk       : Low
   Confidence : High
   Resource   : aws.ebs.volume → vol-0a1b2c3d4e5f67890
   Region     : us-east-1
   Rule       : aws.ebs.volume.unattached
   Reason     : Volume has been unattached for 47 days
   ...

--- Scan Summary ---
Total findings: 84

By risk:
  low: 61
  medium: 23

By confidence:
  high: 38
  medium: 46

Minimum estimated waste: ~$18,200/month
(71 of 84 findings costed)
Regions scanned: eu-west-1, us-east-1, us-west-2 (explicit)
Scanned at: 2026-03-17T08:00:00+00:00

Accounts scanned:     3 ✅

Per-account breakdown:
  dev                  (333333333333):  8 findings  ~$420/month
  production           (111111111111):  45 findings  ~$12,000/month
  staging              (222222222222):  31 findings  ~$4,200/month
```

**JSON output** includes `accounts_scanned`, `per_account` breakdown, and `account_id`/`account_name` on every finding — ideal for downstream processing in CI/CD pipelines.

---

## Scan — AWS (Human-Readable)

`cleancloud scan --provider aws --all-regions`

```
Found 9 hygiene issues:

1. [AWS] Stopped EC2 Instance (30+ Days)
   Risk       : Medium
   Confidence : High
   Resource   : aws.ec2.instance → i-0abc1234567890def
   Region     : us-east-1
   Rule       : aws.ec2.instance.stopped
   Reason     : Instance has been stopped for 45 days (EBS charges continue)
   Detected   : 2026-02-08T14:32:01+00:00
   Details:
     - instance_type: t3.large
     - stopped_days: 45
     - ebs_volume_count: 2
     - ebs_total_gb: 120
     - estimated_monthly_cost_usd: 12.00
     - tags: {"Environment": "staging", "Owner": "backend-team"}

2. [AWS] Unattached EBS Volume
   Risk       : Low
   Confidence : High
   Resource   : aws.ebs.volume → vol-0a1b2c3d4e5f67890
   Region     : us-east-1
   Rule       : aws.ebs.volume.unattached
   Reason     : Volume has been unattached for 47 days
   Detected   : 2026-02-08T14:32:02+00:00
   Details:
     - size_gb: 500
     - availability_zone: us-east-1a
     - state: available
     - tags: {"Project": "legacy-api", "Owner": "platform"}

3. [AWS] Old RDS Snapshot
   Risk       : Low
   Confidence : High
   Resource   : aws.rds.snapshot → rds:db-prod-2025-08-01-00-00
   Region     : us-east-1
   Rule       : aws.rds.snapshot.old
   Reason     : Manual RDS snapshot is 191 days old
   Detected   : 2026-02-08T14:32:03+00:00
   Details:
     - db_instance_identifier: db-prod
     - age_days: 191
     - allocated_storage_gb: 100
     - engine: postgres
     - estimated_monthly_cost_usd: 9.50

4. [AWS] Idle NAT Gateway
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

5. [AWS] Old AMI
   Risk       : Low
   Confidence : Medium
   Resource   : aws.ec2.ami → ami-0fedcba9876543210
   Region     : us-east-1
   Rule       : aws.ec2.ami.old
   Reason     : AMI is 243 days old with 3 associated snapshots (85.0 GB)
   Detected   : 2026-02-08T14:32:05+00:00
   Details:
     - ami_name: backend-v2.3.1-2025-06-10
     - age_days: 243
     - snapshot_count: 3
     - total_size_gb: 85.0
     - estimated_monthly_cost_usd: 4.25

6. [AWS] Unattached Elastic IP
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

7. [AWS] Unused Security Group
   Risk       : Low
   Confidence : High
   Resource   : aws.ec2.security_group → sg-0abc123def456789
   Region     : us-east-1
   Rule       : aws.ec2.security_group.unused
   Reason     : Security group has no ENI associations
   Detected   : 2026-02-08T14:32:07+00:00
   Details:
     - group_name: legacy-api-sg
     - vpc_id: vpc-0abc123
     - tags: {"Project": "legacy-api"}

8. [AWS] CloudWatch Log Group with Infinite Retention
   Risk       : Low
   Confidence : Medium
   Resource   : aws.cloudwatch.log_group → /aws/lambda/legacy-processor
   Region     : us-east-1
   Rule       : aws.cloudwatch.logs.infinite_retention
   Reason     : Log group has no retention policy (never expires)
   Detected   : 2026-02-08T14:32:08+00:00
   Details:
     - stored_bytes: 8745213952
     - retention_days: Never expires

9. [AWS] Untagged Resource
   Risk       : Low
   Confidence : Medium
   Resource   : aws.s3.bucket → company-temp-uploads-2024
   Region     : global
   Rule       : aws.resource.untagged
   Reason     : S3 bucket has no tags
   Detected   : 2026-02-08T14:32:09+00:00

--- Scan Summary ---
Total findings: 9

By risk:
  low: 7
  medium: 2

By confidence:
  high: 5
  medium: 4

Minimum estimated waste: ~$206/month
(6 of 9 findings costed)
Regions scanned: us-east-1, us-west-2, eu-west-1 (auto-detected)
Scanned at: 2026-02-08T14:32:09+00:00
```

---

## Scan — Azure (Human-Readable)

`cleancloud scan --provider azure`

```
Found 7 hygiene issues:

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

4. [AZURE] Empty App Service Plan
   Risk       : Low
   Confidence : High
   Resource   : azure.web.app_service_plan → plan-old-staging
   Region     : eastus2
   Rule       : azure.app_service_plan_empty
   Reason     : App Service Plan has no associated web apps
   Detected   : 2026-02-08T14:45:15+00:00
   Details:
     - sku: P1v3
     - subscription: Staging

5. [AZURE] Idle App Service (No Requests for 14+ Days)
   Risk       : Medium
   Confidence : High
   Resource   : azure.app_service → /subscriptions/.../sites/api-legacy-v1
   Region     : uksouth
   Rule       : azure.app_service.idle
   Reason     : App Service has zero HTTP requests for 14+ days
   Detected   : 2026-02-08T14:45:17+00:00
   Details:
     - app_name: api-legacy-v1
     - kind: app
     - sku_tier: Standard
     - days_idle_threshold: 14
     - subscription: Production

6. [AZURE] Unused Container Registry (90+ Days No Pulls)
   Risk       : Low
   Confidence : High
   Resource   : azure.container_registry → /subscriptions/.../registries/acr-old-project
   Region     : eastus
   Rule       : azure.container_registry.unused
   Reason     : Container registry has zero pull activity for 90+ days
   Detected   : 2026-02-08T14:45:18+00:00
   Details:
     - registry_name: acr-old-project
     - sku: Standard
     - days_unused_threshold: 90
     - subscription: Staging

7. [AZURE] Untagged Resource
   Risk       : Low
   Confidence : Medium
   Resource   : azure.compute.disk → temp-migration-disk
   Region     : eastus
   Rule       : azure.resource.untagged
   Reason     : Resource has no tags
   Detected   : 2026-02-08T14:45:19+00:00

--- Scan Summary ---
Total findings: 7

By risk:
  low: 5
  medium: 2

By confidence:
  high: 5
  medium: 2

Minimum estimated waste: ~$165/month
(5 of 7 findings costed)
Subscriptions scanned: Production, Staging (all accessible)
Scanned at: 2026-02-08T14:45:19+00:00
```

---

## Scan — AWS (JSON)

`cleancloud scan --provider aws --all-regions --output json --output-file results.json`

```json
{
  "schema_version": "1.0.0",
  "summary": {
    "total_findings": 9,
    "by_provider": { "aws": 9 },
    "by_risk": { "low": 7, "medium": 2 },
    "by_confidence": { "high": 5, "medium": 4 },
    "minimum_estimated_monthly_waste_usd": 206.15,
    "findings_with_cost_estimate": 6,
    "highest_confidence": "high",
    "high_conf_findings": 5,
    "regions_scanned": ["us-east-1", "us-west-2", "eu-west-1"],
    "region_selection_mode": "all-regions",
    "provider": "aws",
    "scanned_at": "2026-02-08T14:32:09+00:00"
  },
  "findings": [
    {
      "provider": "aws",
      "rule_id": "aws.ec2.instance.stopped",
      "resource_type": "aws.ec2.instance",
      "resource_id": "i-0abc1234567890def",
      "region": "us-east-1",
      "title": "Stopped EC2 Instance (30+ Days)",
      "summary": "EC2 instance has been stopped for 45 days — EBS charges continue accruing",
      "reason": "Instance has been stopped for 45 days (EBS charges continue)",
      "risk": "medium",
      "confidence": "high",
      "detected_at": "2026-02-08T14:32:01+00:00",
      "details": {
        "instance_type": "t3.large",
        "stopped_days": 45,
        "ebs_volume_count": 2,
        "ebs_total_gb": 120,
        "tags": { "Environment": "staging", "Owner": "backend-team" }
      },
      "estimated_monthly_cost_usd": 12.00,
      "evidence": {
        "signals_used": [
          "Instance state is 'stopped' for 45 days",
          "EBS volumes attached — storage charges continue",
          "2 attached EBS volumes totalling 120 GB"
        ],
        "signals_not_checked": [
          "Intentional pause for cost-saving during off-hours",
          "IaC-managed lifecycle",
          "Pending reactivation"
        ],
        "time_window": "30 days"
      }
    },
    {
      "provider": "aws",
      "rule_id": "aws.ebs.volume.unattached",
      "resource_type": "aws.ebs.volume",
      "resource_id": "vol-0a1b2c3d4e5f67890",
      "region": "us-east-1",
      "title": "Unattached EBS Volume",
      "summary": "EBS volume has been unattached for 47 days",
      "reason": "Volume has been unattached for 47 days",
      "risk": "low",
      "confidence": "high",
      "detected_at": "2026-02-08T14:32:01+00:00",
      "details": {
        "size_gb": 500,
        "availability_zone": "us-east-1a",
        "state": "available",
        "tags": { "Project": "legacy-api", "Owner": "platform" }
      },
      "evidence": {
        "signals_used": [
          "Volume state is 'available' (not attached to any instance)",
          "Volume has been unattached for 47 days"
        ],
        "signals_not_checked": [
          "Application-level usage intent",
          "IaC-managed lifecycle",
          "Disaster recovery purpose"
        ],
        "time_window": "30 days"
      }
    },
    {
      "provider": "aws",
      "rule_id": "aws.ec2.nat_gateway.idle",
      "resource_type": "aws.ec2.nat_gateway",
      "resource_id": "nat-0abcdef1234567890",
      "region": "us-west-2",
      "title": "Idle NAT Gateway",
      "summary": "NAT Gateway with zero traffic for 21 days",
      "reason": "No traffic detected for 21 days",
      "risk": "medium",
      "confidence": "medium",
      "detected_at": "2026-02-08T14:32:04+00:00",
      "details": {
        "name": "staging-nat",
        "state": "available",
        "vpc_id": "vpc-0abc123",
        "total_bytes_out": 0,
        "total_bytes_in": 0,
        "estimated_monthly_cost_usd": 32.40,
        "idle_threshold_days": 14
      },
      "evidence": {
        "signals_used": [
          "Zero bytes transferred (in and out) over 14-day CloudWatch window",
          "NAT Gateway has been idle for 21 days"
        ],
        "signals_not_checked": [
          "Future provisioning intent",
          "IaC-managed lifecycle"
        ],
        "time_window": "14 days"
      }
    },
    {
      "provider": "aws",
      "rule_id": "aws.ec2.ami.old",
      "resource_type": "aws.ec2.ami",
      "resource_id": "ami-0fedcba9876543210",
      "region": "us-east-1",
      "title": "Old AMI",
      "summary": "AMI is 243 days old with 3 associated snapshots (85.0 GB)",
      "reason": "AMI is 243 days old with 3 associated snapshots (85.0 GB)",
      "risk": "low",
      "confidence": "medium",
      "detected_at": "2026-02-08T14:32:05+00:00",
      "details": {
        "ami_name": "backend-v2.3.1-2025-06-10",
        "age_days": 243,
        "snapshot_count": 3,
        "total_size_gb": 85.0,
        "estimated_monthly_cost_usd": 4.25
      },
      "evidence": {
        "signals_used": [
          "AMI age exceeds 180-day threshold",
          "AMI has associated snapshots incurring storage costs"
        ],
        "signals_not_checked": [
          "Whether AMI is referenced in launch templates",
          "IaC-managed lifecycle",
          "Disaster recovery or compliance retention"
        ],
        "time_window": "180 days"
      }
    },
    {
      "provider": "aws",
      "rule_id": "aws.ec2.elastic_ip.unattached",
      "resource_type": "aws.ec2.elastic_ip",
      "resource_id": "eipalloc-0a1b2c3d4e5f6",
      "region": "eu-west-1",
      "title": "Unattached Elastic IP",
      "summary": "Elastic IP not associated with any instance or ENI",
      "reason": "Elastic IP not associated with any instance or ENI (age: 92 days)",
      "risk": "low",
      "confidence": "high",
      "detected_at": "2026-02-08T14:32:06+00:00",
      "details": {
        "public_ip": "52.18.xxx.xxx",
        "domain": "vpc",
        "age_days": 92
      },
      "evidence": {
        "signals_used": [
          "Elastic IP has no association (no instance or ENI)",
          "EIP has been unattached for 92 days"
        ],
        "signals_not_checked": [
          "DNS records pointing to this IP",
          "IaC-managed lifecycle"
        ],
        "time_window": "30 days"
      }
    },
    {
      "provider": "aws",
      "rule_id": "aws.rds.snapshot.old",
      "resource_type": "aws.rds.snapshot",
      "resource_id": "rds:db-prod-2025-08-01-00-00",
      "region": "us-east-1",
      "title": "Old RDS Snapshot",
      "summary": "Manual RDS snapshot is 191 days old — no longer needed for point-in-time recovery",
      "reason": "Manual RDS snapshot is 191 days old",
      "risk": "low",
      "confidence": "high",
      "detected_at": "2026-02-08T14:32:07+00:00",
      "details": {
        "db_instance_identifier": "db-prod",
        "age_days": 191,
        "allocated_storage_gb": 100,
        "engine": "postgres"
      },
      "estimated_monthly_cost_usd": 9.50,
      "evidence": {
        "signals_used": [
          "Snapshot age (191 days) exceeds 90-day threshold",
          "Manual snapshot — not managed by automated backup retention",
          "Allocated storage: 100 GB (ceiling estimate; incremental snapshots may be smaller)"
        ],
        "signals_not_checked": [
          "Compliance or audit retention requirements",
          "Whether snapshot is referenced by a restore procedure"
        ],
        "time_window": "90 days"
      }
    },
    {
      "provider": "aws",
      "rule_id": "aws.ec2.security_group.unused",
      "resource_type": "aws.ec2.security_group",
      "resource_id": "sg-0abc123def456789",
      "region": "us-east-1",
      "title": "Unused Security Group",
      "summary": "Security group has no ENI associations",
      "reason": "Security group has no ENI associations",
      "risk": "low",
      "confidence": "high",
      "detected_at": "2026-02-08T14:32:08+00:00",
      "details": {
        "group_name": "legacy-api-sg",
        "vpc_id": "vpc-0abc123",
        "tags": { "Project": "legacy-api" }
      },
      "evidence": {
        "signals_used": [
          "Security group has zero network interface associations"
        ],
        "signals_not_checked": [
          "Referenced in launch templates or IaC",
          "Intentional placeholder for future use"
        ],
        "time_window": null
      }
    },
    {
      "provider": "aws",
      "rule_id": "aws.cloudwatch.logs.infinite_retention",
      "resource_type": "aws.cloudwatch.log_group",
      "resource_id": "/aws/lambda/legacy-processor",
      "region": "us-east-1",
      "title": "CloudWatch Log Group with Infinite Retention",
      "summary": "Log group has no retention policy (never expires)",
      "reason": "Log group has no retention policy (never expires)",
      "risk": "low",
      "confidence": "medium",
      "detected_at": "2026-02-08T14:32:07+00:00",
      "details": {
        "stored_bytes": 8745213952,
        "retention_days": null
      },
      "evidence": {
        "signals_used": [
          "Log group retention is set to 'Never expire'",
          "Log group has significant stored data (8.1 GB)"
        ],
        "signals_not_checked": [
          "Compliance or audit retention requirements",
          "Active log ingestion rate"
        ],
        "time_window": null
      }
    },
    {
      "provider": "aws",
      "rule_id": "aws.resource.untagged",
      "resource_type": "aws.s3.bucket",
      "resource_id": "company-temp-uploads-2024",
      "region": null,
      "title": "Untagged Resource",
      "summary": "S3 bucket has no tags",
      "reason": "S3 bucket has no tags",
      "risk": "low",
      "confidence": "medium",
      "detected_at": "2026-02-08T14:32:08+00:00",
      "details": {},
      "evidence": {
        "signals_used": [
          "Resource has zero tags attached"
        ],
        "signals_not_checked": [
          "Whether resource is managed by IaC with tags defined elsewhere",
          "Organizational tagging policy exceptions"
        ],
        "time_window": null
      }
    }
  ]
}
```

---

## Scan — Azure (JSON)

`cleancloud scan --provider azure --output json --output-file results.json`

```json
{
  "schema_version": "1.0.0",
  "summary": {
    "total_findings": 7,
    "by_provider": { "azure": 7 },
    "by_risk": { "low": 5, "medium": 2 },
    "by_confidence": { "high": 5, "medium": 2 },
    "minimum_estimated_monthly_waste_usd": 165.00,
    "findings_with_cost_estimate": 5,
    "highest_confidence": "high",
    "high_conf_findings": 5,
    "regions_scanned": ["eastus", "eastus2", "uksouth", "westeurope"],
    "subscriptions_scanned": [
      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "f9e8d7c6-b5a4-3210-fedc-ba0987654321"
    ],
    "subscription_selection_mode": "all",
    "provider": "azure",
    "scanned_at": "2026-02-08T14:45:19+00:00"
  },
  "findings": [
    {
      "provider": "azure",
      "rule_id": "azure.unattached_disk",
      "resource_type": "azure.compute.disk",
      "resource_id": "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890/resourceGroups/rg-legacy/providers/Microsoft.Compute/disks/data-disk-legacy-api",
      "region": "eastus",
      "title": "Unattached Managed Disk",
      "summary": "Managed disk not attached to any VM",
      "reason": "Managed disk not attached to any VM (age: 34 days)",
      "risk": "low",
      "confidence": "medium",
      "detected_at": "2026-02-08T14:45:12+00:00",
      "details": {
        "size_gb": 256,
        "disk_state": "Unattached",
        "subscription": "Production"
      },
      "evidence": {
        "signals_used": [
          "Disk state is 'Unattached'",
          "Disk has been unattached for 34 days"
        ],
        "signals_not_checked": [
          "Application-level usage intent",
          "IaC-managed lifecycle",
          "Disaster recovery purpose"
        ],
        "time_window": "30 days"
      }
    },
    {
      "provider": "azure",
      "rule_id": "azure.public_ip_unused",
      "resource_type": "azure.network.public_ip",
      "resource_id": "/subscriptions/f9e8d7c6-b5a4-3210-fedc-ba0987654321/resourceGroups/rg-staging/providers/Microsoft.Network/publicIPAddresses/pip-old-gateway",
      "region": "westeurope",
      "title": "Unused Public IP",
      "summary": "Public IP not associated with any resource",
      "reason": "Public IP not associated with any resource",
      "risk": "low",
      "confidence": "high",
      "detected_at": "2026-02-08T14:45:13+00:00",
      "details": {
        "ip_address": "20.82.xxx.xxx",
        "allocation_method": "Static",
        "subscription": "Staging"
      },
      "evidence": {
        "signals_used": [
          "Public IP has no ip_configuration (not attached to any resource)"
        ],
        "signals_not_checked": [
          "DNS records pointing to this IP",
          "IaC-managed lifecycle"
        ],
        "time_window": null
      }
    },
    {
      "provider": "azure",
      "rule_id": "azure.lb_no_backends",
      "resource_type": "azure.network.load_balancer",
      "resource_id": "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890/resourceGroups/rg-prod/providers/Microsoft.Network/loadBalancers/lb-deprecated-service",
      "region": "eastus",
      "title": "Load Balancer with No Backends",
      "summary": "Load balancer has no backend pools configured",
      "reason": "Load balancer has no backend pools configured",
      "risk": "medium",
      "confidence": "high",
      "detected_at": "2026-02-08T14:45:14+00:00",
      "details": {
        "sku": "Standard",
        "subscription": "Production"
      },
      "evidence": {
        "signals_used": [
          "Load balancer has zero backend pools configured"
        ],
        "signals_not_checked": [
          "Whether backend pools are being provisioned",
          "IaC-managed lifecycle"
        ],
        "time_window": null
      }
    },
    {
      "provider": "azure",
      "rule_id": "azure.app_service_plan_empty",
      "resource_type": "azure.web.app_service_plan",
      "resource_id": "/subscriptions/f9e8d7c6-b5a4-3210-fedc-ba0987654321/resourceGroups/rg-staging/providers/Microsoft.Web/serverfarms/plan-old-staging",
      "region": "eastus2",
      "title": "Empty App Service Plan",
      "summary": "App Service Plan has no associated web apps",
      "reason": "App Service Plan has no associated web apps",
      "risk": "low",
      "confidence": "high",
      "detected_at": "2026-02-08T14:45:15+00:00",
      "details": {
        "sku": "P1v3",
        "subscription": "Staging"
      },
      "evidence": {
        "signals_used": [
          "App Service Plan has zero web apps associated"
        ],
        "signals_not_checked": [
          "Whether apps are being deployed to this plan",
          "IaC-managed lifecycle"
        ],
        "time_window": null
      }
    },
    {
      "provider": "azure",
      "rule_id": "azure.app_service.idle",
      "resource_type": "azure.app_service",
      "resource_id": "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890/resourceGroups/rg-prod/providers/Microsoft.Web/sites/api-legacy-v1",
      "region": "uksouth",
      "title": "Idle App Service (No Requests for 14+ Days)",
      "summary": "App Service 'api-legacy-v1' (Standard) has received zero HTTP requests for 14+ days but continues to accrue compute charges.",
      "reason": "App Service has zero HTTP requests for 14+ days",
      "risk": "medium",
      "confidence": "high",
      "detected_at": "2026-02-08T14:45:17+00:00",
      "details": {
        "app_name": "api-legacy-v1",
        "kind": "app",
        "sku_tier": "Standard",
        "location": "uksouth",
        "days_idle_threshold": 14
      },
      "estimated_monthly_cost_usd": 73.0,
      "evidence": {
        "signals_used": [
          "Zero HTTP requests for 14 days (Azure Monitor: Requests metric)",
          "App state: Running",
          "App Service Plan tier: Standard",
          "App Service Plan tier 'Standard' costs ~$73/month per instance"
        ],
        "signals_not_checked": [
          "Non-HTTP workloads (WebJobs, background services)",
          "Planned reactivation or seasonal use",
          "IaC-managed placeholder deployment",
          "Blue/green deployment staging slot"
        ],
        "time_window": "14 days"
      }
    },
    {
      "provider": "azure",
      "rule_id": "azure.container_registry.unused",
      "resource_type": "azure.container_registry",
      "resource_id": "/subscriptions/f9e8d7c6-b5a4-3210-fedc-ba0987654321/resourceGroups/rg-staging/providers/Microsoft.ContainerRegistry/registries/acr-old-project",
      "region": "eastus",
      "title": "Unused Container Registry (90+ Days No Pulls)",
      "summary": "Container Registry 'acr-old-project' (Standard) has had no image pulls for 90+ days.",
      "reason": "Container registry has zero pull activity for 90+ days",
      "risk": "low",
      "confidence": "high",
      "detected_at": "2026-02-08T14:45:18+00:00",
      "details": {
        "registry_name": "acr-old-project",
        "sku": "Standard",
        "location": "eastus",
        "days_unused_threshold": 90
      },
      "estimated_monthly_cost_usd": 20.0,
      "evidence": {
        "signals_used": [
          "Zero successful image pulls for 90 days (Azure Monitor: SuccessfulPullCount)",
          "Zero successful image pushes for 90 days (Azure Monitor: SuccessfulPushCount)",
          "No push or pull activity detected across the entire 90-day window",
          "Registry SKU: Standard",
          "ACR Standard tier costs ~$20/month plus storage"
        ],
        "signals_not_checked": [
          "Geo-replication pull activity in other regions",
          "Planned reactivation or migration",
          "Images referenced by stopped but not deleted workloads"
        ],
        "time_window": "90 days"
      }
    },
    {
      "provider": "azure",
      "rule_id": "azure.resource.untagged",
      "resource_type": "azure.compute.disk",
      "resource_id": "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890/resourceGroups/rg-legacy/providers/Microsoft.Compute/disks/temp-migration-disk",
      "region": "eastus",
      "title": "Untagged Resource",
      "summary": "Resource has no tags",
      "reason": "Resource has no tags",
      "risk": "low",
      "confidence": "medium",
      "detected_at": "2026-02-08T14:45:19+00:00",
      "details": {},
      "evidence": {
        "signals_used": [
          "Resource has zero tags attached"
        ],
        "signals_not_checked": [
          "Whether resource is managed by IaC with tags defined elsewhere",
          "Organizational tagging policy exceptions"
        ],
        "time_window": null
      }
    }
  ]
}
```

---

## Scan — AWS (Markdown)

`cleancloud scan --provider aws --all-regions --output markdown`

Produces a grouped, cost-sorted summary you can paste directly into a GitHub PR comment, Slack message, or issue. Use `--output-file results.md` to save to a file instead.

```markdown
## CleanCloud Scan Results

**Provider:** AWS
**Regions:** us-east-1, us-west-2, eu-west-1
**Scanned:** 2026-02-08
**Estimated monthly waste:** ~$206

**Total findings:** 9

| Finding | Count | Est. Monthly Cost |
|---------|------:|------------------:|
| Idle NAT Gateway | 1 | ~$32 |
| Unattached EBS Volume | 2 | ~$115 |
| Old RDS Snapshot | 1 | ~$10 |
| Stopped EC2 Instance | 1 | ~$12 |
| Old AMI | 1 | ~$4 |
| Unattached Elastic IP | 1 | ~$0 |
| Unused Security Group | 1 | — |
| CloudWatch Log Group: Infinite Retention | 1 | — |
| Untagged Resource | 1 | — |

**Confidence:** high: 5 · medium: 4

> Generated by [CleanCloud](https://github.com/cleancloud-io/cleancloud) — read-only cloud hygiene scanner for AWS and Azure.
```

Findings are grouped by title (multiple instances of the same finding type are collapsed into one row with a count) and sorted by estimated cost descending.

---

## Scan — Azure (Markdown)

`cleancloud scan --provider azure --output markdown`

```markdown
## CleanCloud Scan Results

**Provider:** AZURE
**Subscriptions:** Production, Staging
**Scanned:** 2026-02-08
**Estimated monthly waste:** ~$165

**Total findings:** 7

| Finding | Count | Est. Monthly Cost |
|---------|------:|------------------:|
| Empty App Service Plan | 1 | ~$146 |
| Idle App Service | 1 | ~$73 |
| Load Balancer with No Backends | 1 | ~$18 |
| Unused Container Registry | 1 | ~$20 |
| Unused Public IP | 1 | ~$4 |
| Unattached Managed Disk | 1 | — |
| Untagged Resource | 1 | — |

**Confidence:** high: 5 · medium: 2

> Generated by [CleanCloud](https://github.com/cleancloud-io/cleancloud) — read-only cloud hygiene scanner for AWS and Azure.
```

For Azure, the **Subscriptions** field is shown instead of **Regions**, reflecting how Azure scans are scoped.

---

## JSON Schema Reference

CleanCloud uses a versioned JSON schema (current: `1.0.0`). All JSON output includes a `schema_version` field for backward compatibility.

- **Schema definition**: [`schemas/output-v1.0.0.json`](../schemas/output-v1.0.0.json)
- **CI/CD integration guide**: [`docs/ci.md`](ci.md)

**Key differences between AWS and Azure JSON output:**

| Field | AWS | Azure |
|-------|-----|-------|
| `region_selection_mode` | `"explicit"` or `"all-regions"` | Not present |
| `subscription_selection_mode` | Not present | `"explicit"` or `"all"` |
| `subscriptions_scanned` | Not present | Array of subscription IDs |
| `resource_id` | Short ID (e.g., `vol-0abc123`) | Full ARM resource ID |
