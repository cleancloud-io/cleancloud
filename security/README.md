# CleanCloud IAM Proof Pack

**Ready-to-use IAM policies and verification scripts for enterprise security teams**

This directory contains the **IAM Proof Pack** - a collection of artifacts that enable InfoSec teams to independently verify CleanCloud's read-only security model without requiring deep cloud expertise.

**Use this for:**
- Security approval workflows
- Compliance audits (SOC2, ISO 27001)
- Penetration testing preparation
- Risk assessment documentation

## Contents

| File | Description |
|------|-------------|
| `aws-readonly-policy.json` | AWS IAM policy with minimum required read-only permissions |
| `azure-readonly-role.json` | Azure custom role definition with minimum required read-only permissions |
| `gcp-readonly-roles.json` | GCP predefined IAM roles required for read-only scanning |
| `verify-aws-policy.sh` | Script to verify AWS IAM policy contains no write/delete permissions |
| `verify-azure-role.sh` | Script to verify Azure role is read-only |
| `verify-gcp-roles.sh` | Script to verify GCP service account has only read-only roles |

---

## Usage

### 1. AWS IAM Policy Verification

**Verify the policy file:**

```bash
./verify-aws-policy.sh aws-readonly-policy.json
```

**Expected output:**
```
Verifying AWS IAM Policy: aws-readonly-policy.json

PASS: No write/delete/tag permissions found

Allowed actions:
cloudwatch:GetMetricStatistics
ec2:DescribeAddresses
ec2:DescribeImages
ec2:DescribeInstances
ec2:DescribeNatGateways
ec2:DescribeNetworkInterfaces
ec2:DescribeRegions
ec2:DescribeSecurityGroups
ec2:DescribeSnapshots
ec2:DescribeVolumes
elasticloadbalancing:DescribeLoadBalancers
elasticloadbalancing:DescribeTargetGroups
elasticloadbalancing:DescribeTargetHealth
logs:DescribeLogGroups
rds:DescribeDBInstances
rds:DescribeDBSnapshots
s3:GetBucketTagging
s3:ListAllMyBuckets
sts:GetCallerIdentity
```

**Create IAM policy in AWS:**

```bash
# Create IAM policy
aws iam create-policy \
  --policy-name CleanCloudReadOnly \
  --policy-document file://aws-readonly-policy.json

# Attach to existing role (e.g., OIDC role)
aws iam attach-role-policy \
  --role-name CleanCloudCIReadOnly \
  --policy-arn arn:aws:iam::123456789012:policy/CleanCloudReadOnly
```

---

### 2. Azure Role Verification

**Verify the Reader role:**

```bash
# Login to Azure first
az login

# Run verification script
./verify-azure-role.sh Reader
```

**Expected output:**
```
Verifying Azure Role: Reader

Fetching role definition...
PASS: Role is read-only

Allowed actions:
*/read
```

**Assign Reader role to service principal:**

```bash
az role assignment create \
  --assignee <service-principal-id> \
  --role "Reader" \
  --scope /subscriptions/<subscription-id>
```

---

### 3. GCP Role Verification

GCP uses predefined IAM roles — no custom role needed. CleanCloud requires four read-only roles.

**Verify the service account roles:**

```bash
# Login to GCP first
gcloud auth login

# Run verification script
./verify-gcp-roles.sh cleancloud@YOUR_PROJECT.iam.gserviceaccount.com YOUR_PROJECT_ID
```

**Expected output:**
```
Verifying GCP Service Account: cleancloud@my-project.iam.gserviceaccount.com

Checking project-level bindings: my-project

Roles bound at project level:
  roles/browser
  roles/cloudsql.viewer
  roles/compute.viewer
  roles/monitoring.viewer

PASS: No write/admin roles found

Required roles for CleanCloud:
  PRESENT  roles/compute.viewer
  PRESENT  roles/cloudsql.viewer
  PRESENT  roles/monitoring.viewer
  PRESENT  roles/browser

PASS: All required roles are present at project level
```

**Required roles and their purpose:**

| Role | Purpose |
|------|---------|
| `roles/compute.viewer` | List disks, IPs, VMs, snapshots |
| `roles/cloudsql.viewer` | List Cloud SQL instances |
| `roles/monitoring.viewer` | Read Cloud SQL connection metrics |
| `roles/browser` | Enumerate projects (required for `--all-projects`) |

**Bind roles to service account:**

```bash
SA_EMAIL="cleancloud@YOUR_PROJECT.iam.gserviceaccount.com"

# Option 1: Org-level (recommended — covers all projects)
for role in roles/compute.viewer roles/cloudsql.viewer roles/monitoring.viewer roles/browser; do
  gcloud organizations add-iam-policy-binding YOUR_ORG_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="$role"
done

# Option 2: Project-level (single project only)
for role in roles/compute.viewer roles/cloudsql.viewer roles/monitoring.viewer roles/browser; do
  gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="$role"
done
```

---

## For Security Reviews

### Enterprise Approval Workflows

This IAM Proof Pack accelerates security approval by providing:

**For InfoSec Teams:**
- **Policy review** - Programmatic verification of read-only permissions
- **Compliance audits** - Evidence of least privilege principle
- **Penetration testing** - Proof that CleanCloud cannot mutate resources
- **Risk assessment** - Demonstrate limited blast radius

**For Compliance Teams:**
- Pre-verified policies ready for SOC2/ISO 27001 reviews
- Automated verification scripts (auditable, repeatable)
- Links to comprehensive threat model and security documentation

**Time to approval:** Many enterprises approve CleanCloud in 1-2 weeks using this proof pack.

---

## Quick Verification Checklist

Use this checklist during security review:

- [ ] Run `./verify-aws-policy.sh` - Confirms no write/delete/tag permissions
- [ ] Run `./verify-azure-role.sh Reader` - Confirms Azure role is read-only
- [ ] Run `./verify-gcp-roles.sh <sa-email> <project-id>` - Confirms GCP SA has only read-only roles
- [ ] Review [Information Security Readiness Guide](../docs/infosec-readiness.md)
- [ ] Review [Threat Model](../docs/infosec-readiness.md#threat-model)
- [ ] Check [Safety Tests](../docs/safety.md) - Multi-layer mutation prevention
- [ ] Test in non-production environment first
- [ ] Monitor CloudTrail/Azure Activity Log during test scan
- [ ] Verify zero outbound calls (except cloud provider APIs)

**Expected review time:** 2-4 hours for initial assessment

---

## Automated Testing

These policies are also validated in CI/CD:

```bash
# Run safety regression tests
pytest tests/cleancloud/safety/aws/test_aws_iam_policy_readonly.py -v
pytest tests/cleancloud/safety/azure/test_azure_role_definition_readonly.py -v
pytest tests/cleancloud/safety/gcp/test_gcp_static_readonly.py -v
```

See [`docs/safety.md`](../docs/safety.md) for details on automated safety testing.

---

## Additional Resources

**For InfoSec Teams:**
- [Information Security Readiness Guide](../docs/infosec-readiness.md) - Comprehensive security assessment
- [Threat Model & Mitigations](../docs/infosec-readiness.md#threat-model) - Detailed threat analysis
- [Safety Testing Documentation](../docs/safety.md) - Multi-layer safety regression tests

**For Implementation:**
- [AWS Setup Guide](../docs/aws.md) - Authentication methods and IAM policies
- [Azure Setup Guide](../docs/azure.md) - Authentication methods and RBAC roles
- [GCP Setup Guide](../docs/gcp.md) - Authentication methods and IAM roles
- [CI/CD Integration Guide](../docs/ci.md) - GitHub Actions and Azure DevOps examples

**Main Documentation:**
- [README](../README.md) - Quick start and overview

---

## Support

**For security-related questions:**
- Email: suresh@getcleancloud.com
- GitHub Issues: https://github.com/cleancloud-io/cleancloud/issues
- Discussions: https://github.com/cleancloud-io/cleancloud/discussions

**Enterprise customers:** We're happy to join security review calls or provide additional documentation.
