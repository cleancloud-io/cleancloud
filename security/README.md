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
| `verify-aws-policy.sh` | Script to verify AWS IAM policy contains no write/delete permissions |
| `verify-azure-role.sh` | Script to verify Azure role is read-only |

---

## Usage

### 1. AWS IAM Policy Verification

**Verify the policy file:**

```bash
./verify-aws-policy.sh aws-readonly-policy.json
```

**Expected output:**
```
🔍 Verifying AWS IAM Policy: aws-readonly-policy.json

✅ PASS: No write/delete/tag permissions found

Allowed actions:
ec2:DescribeInstances
ec2:DescribeRegions
ec2:DescribeSnapshots
ec2:DescribeVolumes
ec2:DescribeTags
logs:DescribeLogGroups
logs:DescribeLogStreams
logs:GetLogEvents
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
🔍 Verifying Azure Role: Reader

Fetching role definition...
✅ PASS: Role is read-only

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

## For Security Reviews

### Enterprise Approval Workflows

This IAM Proof Pack accelerates security approval by providing:

**For InfoSec Teams:**
- ✅ **Policy review** - Programmatic verification of read-only permissions
- ✅ **Compliance audits** - Evidence of least privilege principle
- ✅ **Penetration testing** - Proof that CleanCloud cannot mutate resources
- ✅ **Risk assessment** - Demonstrate limited blast radius

**For Compliance Teams:**
- 📋 Pre-verified policies ready for SOC2/ISO 27001 reviews
- 📋 Automated verification scripts (auditable, repeatable)
- 📋 Links to comprehensive threat model and security documentation

**Time to approval:** Many enterprises approve CleanCloud in 1-2 weeks using this proof pack.

---

## Quick Verification Checklist

Use this checklist during security review:

- [ ] Run `./verify-aws-policy.sh` - Confirms no write/delete/tag permissions
- [ ] Run `./verify-azure-role.sh Reader` - Confirms Azure role is read-only
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
pytest cleancloud/safety/aws/test_iam_policy_readonly.py -v
pytest cleancloud/safety/azure/test_role_definition_readonly.py -v
```

See [`docs/safety.md`](../docs/safety.md) for details on automated safety testing.

---

## Additional Resources

**For InfoSec Teams:**
- 🔐 [Information Security Readiness Guide](../docs/infosec-readiness.md) - Comprehensive security assessment
- 🛡️ [Threat Model & Mitigations](../docs/infosec-readiness.md#threat-model) - Detailed threat analysis
- 🧪 [Safety Testing Documentation](../docs/safety.md) - Multi-layer safety regression tests

**For Implementation:**
- ⚙️ [AWS Setup Guide](../docs/aws.md) - Authentication methods and IAM policies
- ⚙️ [Azure Setup Guide](../docs/azure.md) - Authentication methods and RBAC roles
- 🚀 [CI/CD Integration Guide](../docs/ci.md) - GitHub Actions and Azure DevOps examples

**Main Documentation:**
- 📖 [README](../README.md) - Quick start and overview

---

## Support

**For security-related questions:**
- 📧 Email: suresh@getcleancloud.com
- 🐛 GitHub Issues: https://github.com/cleancloud-io/cleancloud/issues
- 💬 Discussions: https://github.com/cleancloud-io/cleancloud/discussions

**Enterprise customers:** We're happy to join security review calls or provide additional documentation.
