# Information Security Readiness Guide

**CleanCloud Security Assessment for Enterprise Information Security Teams**

**Version:** 1.1
**Last Updated:** 2026-02-08
**Classification:** Public

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Zero Outbound Calls Assurance](#zero-outbound-calls-assurance-design--enforcement)
3. [IAM Proof Pack](#iam-proof-pack)
4. [Security Model & Architecture](#security-model--architecture)
5. [Threat Model](#threat-model)
6. [Data Privacy & Compliance](#data-privacy--compliance)
7. [Access Control & Authentication](#access-control--authentication)
8. [Operational Security](#operational-security)
9. [Audit & Verification](#audit--verification)
10. [Risk Assessment](#risk-assessment)
11. [Compliance Considerations](#compliance-considerations)
12. [Security Testing & Validation](#security-testing--validation)
13. [Supply Chain Security](#supply-chain-security)
14. [Incident Response](#incident-response)
15. [Frequently Asked Questions](#frequently-asked-questions)

---

## Executive Summary

### What is CleanCloud?

CleanCloud is an **open-source, read-only cloud hygiene scanning tool** designed for AWS and Azure environments. It identifies orphaned, untagged, or inactive cloud resources without making any modifications to infrastructure.

### Key Security Guarantees

- **Read-Only by Design**: No Delete*, Create*, Update*, or Tag* permissions required
- **Zero Telemetry**: No data collection, analytics, or phone-home capabilities
- **OIDC-First**: Supports short-lived, temporary credentials (no long-lived secrets)
- **Open Source**: Fully auditable codebase with automated safety regression tests
- **Provable Safety**: Multi-layer safety tests ensure no resource mutations

### Security Posture Summary

| Security Dimension | Rating | Evidence |
|-------------------|--------|----------|
| Data Privacy | Excellent | No data exfiltration, no telemetry |
| Access Control | Excellent | Read-only IAM/RBAC policies only |
| Authentication | Excellent | OIDC-first, short-lived credentials |
| Code Transparency | Excellent | Open-source, automated safety tests |
| Supply Chain | Good | Standard PyPI distribution, minimal dependencies |
| Auditability | Excellent | Deterministic output, CloudTrail/Activity Log compatible |

---

## Zero Outbound Calls Assurance (Design & Enforcement)

### Network Trust Model

**CleanCloud makes ZERO outbound calls except to your cloud provider APIs.**

This is a critical security guarantee for enterprise environments:

| Endpoint Type | Called? | Purpose | Verification |
|---------------|---------|---------|--------------|
| AWS APIs (`*.amazonaws.com`) | Yes | Read cloud resource metadata | CloudTrail audit logs |
| Azure APIs (`management.azure.com`) | Yes | Read cloud resource metadata | Azure Activity Log |
| Azure Auth (`login.microsoftonline.com`) | Yes | OIDC token exchange only | Azure AD sign-in logs |
| PyPI (`pypi.org`, `files.pythonhosted.org`) | Installation only | Package download during `pip install` | N/A (one-time) |
| **Analytics / Telemetry** | Never | — | Code review, network monitoring |
| **Third-party APIs** | Never | — | Code review, network monitoring |
| **Update checks / Version pings** | Never | — | No phone-home code |
| **Error reporting / Crash analytics** | Never | — | No Sentry, Bugsnag, etc. |

### Verification Methods

InfoSec teams can verify the zero outbound calls assurance through multiple methods:

#### 1. Network Monitoring (Runtime Verification)

Run CleanCloud with network traffic capture:

**Using tcpdump (Linux/macOS):**

```bash
# Start packet capture (run as root or with sudo)
sudo tcpdump -i any -n 'tcp port 443' -w cleancloud-traffic.pcap &
TCPDUMP_PID=$!

# Run CleanCloud scan
cleancloud scan --provider aws --region us-east-1

# Stop capture
sudo kill $TCPDUMP_PID

# Analyze captured traffic
tcpdump -r cleancloud-traffic.pcap -n | grep -v 'amazonaws.com\|pypi.org'
# Expected: Only AWS API endpoints (no telemetry or third-party calls)
```

**Using Wireshark:**

1. Start Wireshark capture on your network interface
2. Run CleanCloud scan
3. Stop capture and filter: `tcp.port == 443`
4. Verify all HTTPS destinations are AWS/Azure API endpoints

**Expected DNS queries:**
- AWS: `ec2.us-east-1.amazonaws.com`, `logs.us-east-1.amazonaws.com`, `monitoring.us-east-1.amazonaws.com`, `s3.amazonaws.com`, `sts.amazonaws.com`
- Azure: `management.azure.com`, `login.microsoftonline.com`

**Unacceptable DNS queries (should never appear):**
- Analytics: `analytics.google.com`, `segment.io`, `mixpanel.com`
- Error tracking: `sentry.io`, `bugsnag.com`
- Any other third-party domains

#### 2. Egress Firewall Testing (Controlled Environment)

Run CleanCloud in a network with strict egress filtering:

**AWS Example (Security Group):**

```bash
# Create security group allowing ONLY AWS API endpoints
aws ec2 create-security-group --group-name cleancloud-test --description "CleanCloud egress test"

# Allow outbound to AWS APIs only (use VPC endpoints or specific CIDR ranges)
aws ec2 authorize-security-group-egress --group-id sg-xxx \
 --ip-permissions IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}]

# Run CleanCloud from EC2 instance with this security group
# Expected: Scan succeeds (proves only AWS APIs are called)
```

**Azure Example (Network Security Group):**

```bash
# Create NSG allowing only Azure API endpoints
az network nsg create --resource-group test --name cleancloud-test-nsg

# Allow outbound to Azure Management API only
az network nsg rule create --nsg-name cleancloud-test-nsg \
 --resource-group test --name allow-azure-apis \
 --priority 100 --direction Outbound --access Allow \
 --protocol Tcp --destination-port-ranges 443 \
 --destination-address-prefixes AzureCloud

# Deny all other outbound (except DNS)
az network nsg rule create --nsg-name cleancloud-test-nsg \
 --resource-group test --name deny-all-outbound \
 --priority 200 --direction Outbound --access Deny \
 --protocol '*' --destination-address-prefixes '*'

# Run CleanCloud from VM with this NSG attached
# Expected: Scan succeeds (proves only Azure APIs are called)
```

#### 3. Proxy/MITM Analysis

Route CleanCloud traffic through a proxy to inspect all HTTPS destinations:

**Using mitmproxy:**

```bash
# Install mitmproxy
pip install mitmproxy

# Start proxy
mitmproxy --mode transparent --showhost

# Configure CleanCloud to use proxy
export HTTPS_PROXY=http://localhost:8080
cleancloud scan --provider aws --region us-east-1

# Review mitmproxy log
# Expected: Only AWS/Azure API calls visible
```

#### 4. Code Review (Static Verification)

Review the CleanCloud codebase for network calls:

**Search for HTTP libraries:**

```bash
# Clone repository
git clone https://github.com/cleancloud-io/cleancloud.git
cd cleancloud

# Search for HTTP client usage
grep -r "requests\." cleancloud/
grep -r "urllib" cleancloud/
grep -r "httpx" cleancloud/
grep -r "aiohttp" cleancloud/

# Expected: ZERO results (CleanCloud uses only boto3/azure-sdk)
```

**Search for telemetry/analytics:**

```bash
# Search for common analytics libraries
grep -r "segment" cleancloud/
grep -r "mixpanel" cleancloud/
grep -r "amplitude" cleancloud/
grep -r "google-analytics" cleancloud/
grep -r "sentry" cleancloud/
grep -r "bugsnag" cleancloud/

# Expected: ZERO results
```

**Verify dependencies (no telemetry libraries):**

```bash
# Check pyproject.toml or requirements.txt
cat pyproject.toml | grep dependencies

# Expected: Only click, pyyaml, boto3, azure-sdk packages
# NOT expected: requests, httpx, analytics SDKs
```

### Why This Matters

The zero outbound calls assurance is critical for:

- **Air-gapped environments**: Can run CleanCloud with only AWS/Azure API access
- **Compliance**: No data exfiltration risk (PCI-DSS, HIPAA, FedRAMP)
- **Privacy**: Cloud metadata never leaves your control
- **Trust**: No hidden telemetry or usage tracking
- **Auditability**: All network activity is to cloud provider APIs only

### Written Guarantee

**The CleanCloud project is designed and continuously validated to ensure that:**

1. CleanCloud makes zero outbound calls except to AWS/Azure APIs
2. CleanCloud contains zero telemetry, analytics, or tracking code
3. CleanCloud does not check for updates or phone home
4. Any violation of this assurance in a release will be treated as a critical security incident
5. This assurance is enforceable through code review, network monitoring, and our open-source license

**If you discover any violation of this assurance:**
- Report immediately to: suresh@getcleancloud.com with subject `[SECURITY] Outbound Call Violation`
- We aim to acknowledge reports within 48 hours and publish remediation details as soon as reasonably possible
- The violating code will be removed and root cause published

---

## IAM Proof Pack

### What is the IAM Proof Pack?

The **IAM Proof Pack** is a collection of ready-to-use artifacts that prove CleanCloud's read-only security model. Use this pack to accelerate security reviews and compliance approvals.

### Contents

The IAM Proof Pack includes:

1. **IAM Policies** (AWS) and **RBAC Role Definitions** (Azure)
2. **Verification Scripts** (test IAM policies for write permissions)
3. **Sample CloudTrail / Activity Log Events** (proof of read-only operations)
4. **Safety Test Results** (automated safety regression test output)

---

#### 1. AWS IAM Policy (Read-Only)

**File:** `security/aws-readonly-policy.json`

**Location in repo:** [`security/aws-readonly-policy.json`](https://github.com/cleancloud-io/cleancloud/blob/main/security/aws-readonly-policy.json)

**Policy:**

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

**Verification:**

```bash
# Download policy
curl -o aws-readonly-policy.json \
 https://raw.githubusercontent.com/cleancloud-io/cleancloud/main/security/aws-readonly-policy.json

# Verify no write/delete/tag permissions
cat aws-readonly-policy.json | jq '.Statement[].Action[]' | grep -iE '(delete|put|create|update|tag)'
# Expected: No results (exit code 1)

# Create IAM policy (optional - for testing)
aws iam create-policy --policy-name CleanCloudReadOnly \
 --policy-document file://aws-readonly-policy.json
```

**Attach to OIDC role:**

```bash
# Attach to existing role
aws iam attach-role-policy \
  --role-name CleanCloudCIReadOnly \
  --policy-arn arn:aws:iam::123456789012:policy/CleanCloudReadOnly
```

---

#### 2. Azure RBAC Role (Reader)

**Minimum Required Role:** `Reader` (built-in Azure role)

**Role ID:** `acdd72a7-3385-48ef-bd42-f606fba81ae7`

**Permissions:** Read-only across all resource types

**Verification:**

```bash
# List Reader role permissions
az role definition list --name "Reader" --output json \
 | jq '.[0].permissions[0].actions'

# Expected output (read-only actions):
[
 "*/read"
]

# Verify no write permissions
az role definition list --name "Reader" --output json \
 | jq '.[0].permissions[0].actions[]' | grep -iE '(delete|write|create|update)'
# Expected: No results (exit code 1)
```

**Assign to service principal:**

```bash
# Assign Reader role to CleanCloud service principal
az role assignment create \
  --assignee <service-principal-id> \
  --role "Reader" \
  --scope /subscriptions/<subscription-id>
```

---

#### 3. Verification Scripts

**AWS IAM Policy Validator:**

```bash
#!/bin/bash
# File: verify-aws-policy.sh
# Verifies AWS IAM policy is read-only

POLICY_FILE="aws-readonly-policy.json"

echo " Verifying AWS IAM Policy: $POLICY_FILE"

# Check for forbidden actions
FORBIDDEN=$(cat $POLICY_FILE | jq -r '.Statement[].Action[]?' | grep -iE '(delete|put|create|update|tag|modify|terminate|reboot|stop|start)')

if [ -z "$FORBIDDEN" ]; then
 echo " PASS: No write/delete/tag permissions found"
 exit 0
else
 echo " FAIL: Found forbidden permissions:"
 echo "$FORBIDDEN"
 exit 1
fi
```

**Usage:**

```bash
chmod +x verify-aws-policy.sh
./verify-aws-policy.sh
```

**Azure Role Validator:**

```bash
#!/bin/bash
# File: verify-azure-role.sh
# Verifies Azure role is read-only

ROLE_NAME="Reader"

echo " Verifying Azure Role: $ROLE_NAME"

# Get role definition
ACTIONS=$(az role definition list --name "$ROLE_NAME" --output json | jq -r '.[0].permissions[0].actions[]')

# Check for write actions
FORBIDDEN=$(echo "$ACTIONS" | grep -iE '(delete|write|create|update|action)')

if [ -z "$FORBIDDEN" ]; then
 echo " PASS: Role is read-only"
 exit 0
else
 echo " FAIL: Found write permissions:"
 echo "$FORBIDDEN"
 exit 1
fi
```

---

#### 4. Sample CloudTrail Events (AWS)

**Read-Only Event Examples:**

```json
{
  "eventVersion": "1.08",
  "eventTime": "2026-01-10T10:30:00Z",
  "eventName": "DescribeVolumes",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.10",
  "userAgent": "Boto3/1.34.0 Python/3.12.0",
  "requestParameters": {
    "volumeSet": {},
    "filterSet": {}
  },
  "responseElements": null,
  "readOnly": true,
  "eventType": "AwsApiCall",
  "recipientAccountId": "123456789012",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROA...:GitHubActions",
    "arn": "arn:aws:sts::123456789012:assumed-role/CleanCloudCIReadOnly/GitHubActions",
    "accountId": "123456789012"
  }
}
```

**Key Attributes:**
- `"readOnly": true` - Confirms read operation
- `"eventName": "DescribeVolumes"` - Read-only API call
- No `Delete*`, `Put*`, `Create*`, `Tag*` events

**CloudTrail Query (All CleanCloud Events):**

```bash
# Query CloudTrail for all CleanCloud events in last 24 hours
aws cloudtrail lookup-events \
 --lookup-attributes AttributeKey=Username,AttributeValue=CleanCloudCIReadOnly \
 --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%S) \
 --output json | jq '.Events[].CloudTrailEvent | fromjson | .eventName' | sort | uniq

# Expected output (read-only events only):
# "DescribeAddresses"
# "DescribeImages"
# "DescribeLogGroups"
# "DescribeNatGateways"
# "DescribeNetworkInterfaces"
# "DescribeRegions"
# "DescribeSnapshots"
# "DescribeVolumes"
# "GetBucketTagging"
# "GetCallerIdentity"
# "GetMetricStatistics"
# "ListBuckets"
```

---

#### 5. Safety Test Results

**Run Safety Regression Tests:**

```bash
# Clone CleanCloud repository
git clone https://github.com/cleancloud-io/cleancloud.git
cd cleancloud

# Install dependencies
pip install -e ".[dev]"

# Run all safety tests
pytest tests/cleancloud/safety/ -v --tb=short

# Expected output:
# tests/cleancloud/safety/aws/test_aws_static_readonly.py::test_no_write_operations PASSED
# tests/cleancloud/safety/aws/test_aws_runtime_readonly.py::test_runtime_guard PASSED
# tests/cleancloud/safety/aws/test_aws_iam_policy_readonly.py::test_iam_policy_readonly PASSED
# tests/cleancloud/safety/azure/test_azure_static_readonly.py::test_no_write_operations PASSED
# tests/cleancloud/safety/azure/test_azure_runtime_readonly.py::test_runtime_guard PASSED
# tests/cleancloud/safety/azure/test_azure_role_definition_readonly.py::test_role_definition_readonly PASSED
# ==================== 6 passed in 2.3s ====================
```

**Generate HTML Report (for auditors):**

```bash
# Run tests with HTML output
pytest tests/cleancloud/safety/ -v --html=safety-test-report.html --self-contained-html

# Open report
open safety-test-report.html # macOS
xdg-open safety-test-report.html # Linux
```

**Sample Output:**

```
======================== test session starts =========================
platform darwin -- Python 3.12.0, pytest-7.4.0
collected 6 items

tests/cleancloud/safety/aws/test_aws_static_readonly.py::test_no_write_operations PASSED [ 16%]
tests/cleancloud/safety/aws/test_aws_runtime_readonly.py::test_runtime_guard PASSED [ 33%]
tests/cleancloud/safety/aws/test_aws_iam_policy_readonly.py::test_iam_policy_readonly PASSED [ 50%]
tests/cleancloud/safety/azure/test_azure_static_readonly.py::test_no_write_operations PASSED [ 66%]
tests/cleancloud/safety/azure/test_azure_runtime_readonly.py::test_runtime_guard PASSED [ 83%]
tests/cleancloud/safety/azure/test_azure_role_definition_readonly.py::test_role_definition_readonly PASSED [100%]

========================= 6 passed in 2.13s ==========================
```

---

### Using the IAM Proof Pack

**For Security Teams:**

1. **Download IAM policies** from GitHub repository
2. **Run verification scripts** to confirm read-only nature
3. **Review sample CloudTrail events** to see expected audit log format
4. **Run safety tests locally** to prove automated enforcement
5. **Attach policies to OIDC roles** with confidence

**For Compliance/Audit:**

1. **Provide IAM policy JSON** as evidence of least privilege
2. **Show safety test results** (HTML report) as proof of automated checks
3. **Demonstrate CloudTrail integration** with sample event queries
4. **Reference verification scripts** as ongoing validation mechanism

**For Incident Response:**

1. Use CloudTrail queries to investigate any reported issues
2. Verify only read-only events in audit logs
3. Confirm IAM policy hasn't been modified (check policy version)

---

### Downloadable Artifacts

All IAM Proof Pack artifacts are available in the CleanCloud repository:

```bash
# Clone repository to access full IAM Proof Pack
git clone https://github.com/cleancloud-io/cleancloud.git
cd cleancloud

# IAM Proof Pack files:
# - security/aws-readonly-policy.json (AWS IAM policy)
# - docs/infosec-readiness.md (this document)
# - tests/cleancloud/safety/ (automated safety tests)
```

**Quick Download (AWS IAM Policy):**

```bash
curl -o aws-readonly-policy.json \
 https://raw.githubusercontent.com/cleancloud-io/cleancloud/main/security/aws-readonly-policy.json
```

---

## Security Model & Architecture

### Design Principles

CleanCloud is built on three core security principles:

#### 1. Read-Only Always

- **No modification APIs**: Only `Describe*`, `List*`, and `Get*` operations
- **No tag mutations**: Cannot add, remove, or modify resource tags
- **No deletions**: Cannot delete or terminate resources
- **IAM policy validation**: Automated tests ensure policies grant read-only access only

#### 2. Zero Trust Data Handling

- **No credential storage**: Uses native AWS/Azure credential chains
- **No data transmission**: Scan results remain local or in user-controlled outputs
- **No telemetry**: Zero analytics, usage tracking, or phone-home
- **No external network dependencies**: Does not call third-party APIs or services (beyond cloud provider SDKs)

#### 3. Provable Safety

- **Static analysis**: AST-level checks detect forbidden API calls in code
- **Runtime guards**: Test fixtures intercept and block any mutation attempts
- **Policy validation**: IAM/RBAC definitions are automatically tested for write permissions

### Execution Model

```
┌─────────────────────┐
│  User Environment   │
│  (CI/CD or Local)   │
└──────────┬──────────┘
           │
           │ 1. Authenticate via OIDC/CLI
           ▼
┌─────────────────────┐
│   CleanCloud CLI    │
│  (Read-Only Scan)   │
└──────────┬──────────┘
           │
           │ 2. Read-only API calls (Describe*, List*, Get*)
           ▼
┌─────────────────────┐
│  AWS / Azure APIs   │
│  (Cloud Provider)   │
└──────────┬──────────┘
           │
           │ 3. Return resource metadata
           ▼
┌─────────────────────┐
│  CleanCloud Engine  │
│  (Local Analysis)   │
└──────────┬──────────┘
           │
           │ 4. Generate findings (local processing)
           ▼
┌─────────────────────┐
│  Output (JSON/CSV)  │
│  (User-Controlled)  │
└─────────────────────┘
```

**Key Security Characteristics:**

- All processing happens locally in the execution environment
- No data is transmitted by CleanCloud itself; any downstream handling of outputs is controlled by the user's environment
- Cloud provider APIs are only queried for read operations
- Results are written to user-specified locations (stdout, files, artifacts)

---

## Threat Model

### Attack Surface Analysis

CleanCloud's attack surface is intentionally minimal:

```
┌─────────────────────────────────────────────────────────────┐
│ THREAT MODEL OVERVIEW │
└─────────────────────────────────────────────────────────────┘

┌──────────────────┐
│ ATTACK VECTORS │
└──────────────────┘
 │
 ├─► Credential Compromise
 │ ├─ Likelihood: Low-Medium (depends on auth method)
 │ ├─ Impact: Medium-High (read access to cloud metadata)
 │ └─ Mitigation: OIDC (1-hour tokens), read-only IAM/RBAC
 │
 ├─► Resource Mutation (Accidental Deletion)
 │ ├─ Likelihood: Extremely Low (prevented by IAM/RBAC enforcement and automated safety controls)
 │ ├─ Impact: Critical (if possible)
 │ └─ Mitigation: No write permissions, safety regression tests
 │
 ├─► Data Exfiltration
 │ ├─ Likelihood: Extremely Low (prevented by design: zero telemetry, local processing only)
 │ ├─ Impact: Medium (cloud metadata exposure)
 │ └─ Mitigation: No outbound calls (except cloud APIs), code review
 │
 ├─► Supply Chain Attack (Malicious Dependency)
 │ ├─ Likelihood: Low
 │ ├─ Impact: Medium
 │ └─ Mitigation: Minimal dependencies, pip-audit in CI, code review
 │
 ├─► API Throttling / Denial of Service
 │ ├─ Likelihood: Low
 │ ├─ Impact: Low (scan fails, no resource impact)
 │ └─ Mitigation: Respects rate limits, parallel scanning configurable
 │
 └─► False Positive (Incorrect Findings)
 ├─ Likelihood: Medium (conservative detection reduces this)
 ├─ Impact: Low (review-only, no auto-action)
 └─ Mitigation: Confidence levels (LOW/MEDIUM/HIGH), review-only design
```

---

### Detailed Threat Analysis

#### Threat 1: Credential Compromise

**Scenario:** Attacker gains access to CleanCloud credentials (OIDC token, AWS keys, Azure service principal)

**Attack Path:**
1. Attacker compromises CI/CD runner or developer workstation
2. Obtains CleanCloud credentials (OIDC token or long-lived keys)
3. Uses credentials to access cloud provider APIs

**Impact:**
- **Read access to cloud metadata** (resource IDs, tags, configurations)
- **Cannot delete or modify resources** (no write permissions)
- **Potential reconnaissance** for further attacks

**Likelihood:** Low-Medium (depends on credential management practices)

**Mitigations:**

| Mitigation | Effectiveness | Implementation |
|------------|--------------|----------------|
| **Use OIDC (short-lived tokens)** | High | 1-hour token lifetime, automatic expiration |
| **Restrict IAM/RBAC to read-only** | High | Limits blast radius to metadata read access |
| **Enable CloudTrail/Activity Log monitoring** | High | Detect unusual API calls, IP addresses |
| **Conditional Access (IP restrictions)** | Medium | Limit credential use to known CI/CD IPs |
| **MFA on credential issuance** | Medium | Protect OIDC token issuance (GitHub MFA) |
| **Rotate long-lived keys regularly** | Medium | If using access keys (not recommended) |

**Detection:**
```bash
# AWS: Detect unusual CleanCloud API calls
aws cloudtrail lookup-events \
 --lookup-attributes AttributeKey=Username,AttributeValue=CleanCloudCIReadOnly \
 | jq '.Events[] | select(.SourceIPAddress != "<expected-ci-ip>")'

# Azure: Detect unusual service principal activity
az monitor activity-log list \
 --caller <cleancloud-sp-id> \
 --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%S) \
 | jq '.[] | select(.ipAddress != "<expected-ci-ip>")'
```

**Response:**
1. Revoke compromised credentials immediately
2. Review CloudTrail/Activity Log for unauthorized API calls
3. Rotate OIDC trust policy or service principal
4. Investigate source of compromise

---

#### Threat 2: Accidental Resource Mutation/Deletion

**Scenario:** Bug in CleanCloud code or misconfiguration causes resource deletion

**Attack Path:**
1. Developer introduces bug that calls `delete_volume()` instead of `describe_volumes()`
2. Code passes code review (missed by reviewer)
3. CI/CD deploys malicious version
4. CleanCloud runs and attempts to delete resources

**Impact:**
- 🚨 **Critical** (if successful) - production resource deletion
- **Extremely Low in practice** - multiple safety layers prevent this

**Likelihood:** Extremely Low (prevented by multiple enforcement layers)

**Mitigations (Multi-Layer Defense):**

| Layer | Mechanism | Effectiveness |
|-------|-----------|--------------|
| **1. IAM/RBAC Policy** | No `Delete*`, `Put*`, `Create*` permissions granted | Critical - API call fails with `AccessDenied` |
| **2. Static AST Analysis** | Code is scanned for forbidden API calls before merge | High - Detected in CI before release |
| **3. Runtime Guards** | Test fixtures intercept mutation attempts during tests | High - Caught during test execution |
| **4. Policy Validation Tests** | IAM/RBAC policies automatically tested for write permissions | High - Policy drift detected |

**Detection (If Attempted):**
```bash
# AWS: No Delete events should ever appear for CleanCloud
aws cloudtrail lookup-events \
 --lookup-attributes AttributeKey=Username,AttributeValue=CleanCloudCIReadOnly \
 | jq '.Events[].CloudTrailEvent | fromjson | select(.eventName | test("Delete|Put|Create|Update|Tag"))'
# Expected: Zero results

# If results appear, it means:
# - Different IAM role/user was used (not CleanCloud)
# - OR IAM policy was modified (policy drift - investigate immediately)
```

**Response (If Detected):**
1. Halt all CleanCloud scans immediately
2. Review IAM/RBAC policy for unauthorized changes
3. Investigate who modified the policy (CloudTrail, Azure Activity Log)
4. Restore read-only policy
5. Run safety regression tests to verify policy enforcement

---

#### Threat 3: Data Exfiltration (Telemetry Backdoor)

**Scenario:** Malicious code added to CleanCloud that sends cloud metadata to external server

**Attack Path:**
1. Attacker compromises CleanCloud maintainer account or CI/CD
2. Injects code that sends resource metadata to attacker-controlled server
3. Malicious version published to PyPI
4. Users install compromised version
5. Cloud metadata exfiltrated during scans

**Impact:**
- **Medium** - Exposure of cloud resource metadata (IDs, tags, configurations)
- **No credential exfiltration** (credentials not stored by CleanCloud)
- **Reconnaissance data** for attackers

**Likelihood:** Low (open-source code, community review, no history of compromise)

**Mitigations:**

| Mitigation | Effectiveness | How to Use |
|------------|--------------|------------|
| **Open-source code review** | High | Review code before use: `git clone` and inspect |
| **Network monitoring** | High | Run with `tcpdump`/Wireshark, verify only AWS/Azure calls |
| **Egress firewall** | High | Block all outbound except AWS/Azure APIs |
| **Code auditing** | Medium | Search for HTTP libraries: `grep -r "requests\." cleancloud/` |
| **Dependency pinning** | Medium | Pin exact versions in `requirements.txt`, review diffs |
| **PyPI package verification** | Medium | Verify SHA256 checksum of downloaded package |

**Detection:**
```bash
# Network monitoring during CleanCloud scan
sudo tcpdump -i any -n 'tcp port 443' -w cleancloud-traffic.pcap &
cleancloud scan --provider aws --region us-east-1
sudo pkill tcpdump

# Analyze captured traffic - should ONLY see AWS/Azure endpoints
tcpdump -r cleancloud-traffic.pcap -n | awk '{print $3}' | sort | uniq
# Expected: Only amazonaws.com, management.azure.com, login.microsoftonline.com

# Unexpected: analytics.google.com, segment.io, <attacker-server>.com
```

**Response (If Detected):**
1. Immediately stop all CleanCloud usage
2. Report to CleanCloud maintainers: suresh@getcleancloud.com
3. Report to PyPI security team
4. Review previous scan outputs for compromised data
5. Rotate cloud credentials as precaution
6. Wait for patched version before resuming use

---

#### Threat 4: Supply Chain Attack (Malicious Dependency)

**Scenario:** One of CleanCloud's dependencies (boto3, azure-sdk, etc.) is compromised

**Attack Path:**
1. Attacker compromises upstream dependency (e.g., boto3, azure-identity)
2. Malicious version published to PyPI
3. CleanCloud users install compromised dependency
4. Dependency exfiltrates credentials or cloud metadata

**Impact:**
- 🚨 **High** - Could compromise credentials, exfiltrate data
- **Depends on compromised dependency capabilities**

**Likelihood:** Low (major dependencies like boto3 have strong security practices)

**Mitigations:**

| Mitigation | Effectiveness | Implementation |
|------------|--------------|----------------|
| **Minimal dependencies** | High | CleanCloud has only 6 core dependencies |
| **Trust reputable dependencies** | High | boto3 (AWS), azure-sdk (Microsoft), click (Pallets) |
| **Dependency scanning** | High | `pip-audit` in CI, Dependabot alerts |
| **Version pinning** | Medium | Pin minimum versions, allow security updates |
| **SBOM generation** | Medium | Track all dependencies with `pip freeze` |
| **Offline installation** | Medium | Download wheels, verify checksums, install offline |

**Detection:**
```bash
# Scan dependencies for known vulnerabilities
pip install pip-audit
pip-audit

# Check for unexpected dependencies
pip freeze | grep -v -iE '(boto3|botocore|azure|click|pyyaml|cleancloud|urllib3|jmespath|certifi|charset|idna|s])'
# Expected: Only known transitive dependencies
```

**Response (If Dependency Compromised):**
1. Check if CleanCloud uses affected dependency version
2. Update to patched version immediately
3. Review CleanCloud security advisories
4. Consider rotating cloud credentials if data exfiltration suspected

---

#### Threat 5: API Throttling / Denial of Service

**Scenario:** CleanCloud makes excessive API calls, triggering rate limits

**Attack Path:**
1. CleanCloud bug causes API call loop
2. AWS/Azure rate limits triggered
3. Scan fails, other tools in same account throttled

**Impact:**
- **Low** - Scan fails, no resource damage
- **Potential impact to other tools** using same credentials

**Likelihood:** Low (CleanCloud uses pagination, respects rate limits)

**Mitigations:**
- Pagination for large result sets (built-in to boto3/azure-sdk)
- Exponential backoff on rate limit errors (handled by SDKs)
- Configurable parallelism (scan regions sequentially if needed)
- Resource limits (scan specific regions/subscriptions only)

**Detection:**
```bash
# AWS: Monitor for throttling events
aws cloudtrail lookup-events \
 --lookup-attributes AttributeKey=ErrorCode,AttributeValue=ThrottlingException

# Azure: Monitor for 429 (Too Many Requests) responses
az monitor activity-log list --status "Failed" \
 | jq '.[] | select(.subStatus.localizedValue == "TooManyRequests")'
```

**Response:**
1. Reduce scan scope (`--region` instead of `--all-regions`)
2. Increase time between scans
3. Report bug if caused by CleanCloud issue

---

#### Threat 6: False Positive (Incorrect Findings)

**Scenario:** CleanCloud incorrectly flags resources as orphaned/inactive

**Attack Path:**
1. CleanCloud detection logic has bug or edge case
2. Active resources flagged as orphaned
3. User manually deletes resources based on finding
4. Production impact from accidental deletion

**Impact:**
- **Low** - Review-only design prevents auto-action
- **User error** if findings trusted without validation

**Likelihood:** Medium (conservative detection reduces this, but edge cases exist)

**Mitigations:**
- **Review-only design** (CleanCloud never auto-deletes)
- **Confidence levels** (LOW/MEDIUM/HIGH) - start with `--fail-on-confidence HIGH`
- **Conservative detection logic** (multiple signals, age thresholds)
- **Tag-based exclusions** (`--ignore-tag` for known resources)
- **User validation** (always verify findings before action)

**Response:**
1. Report false positive in GitHub Issues
2. Tag resources to exclude from future scans
3. Adjust CI policy to use `--fail-on-confidence HIGH` only
4. Review detection logic for edge cases

---

### Threat Prioritization Matrix

| Threat | Likelihood | Impact | Risk Level | Priority |
|--------|-----------|--------|------------|----------|
| Credential Compromise | Low-Medium | Medium-High | 🟡 Medium | High - Use OIDC |
| Resource Mutation | Extremely Low | Critical | 🟢 Low | Low - Prevented by IAM/RBAC + safety tests |
| Data Exfiltration | Low | Medium | 🟢 Low | Medium - Verify via network monitoring |
| Supply Chain Attack | Low | High | 🟡 Medium | Medium - Use `pip-audit` |
| API Throttling | Low | Low | 🟢 Low | Low - Monitor only |
| False Positive | Medium | Low | 🟡 Medium | Low - Use review-only approach |

**Risk Acceptance:**

CleanCloud is appropriate for organizations that accept:
- **Low-Medium credential compromise risk** (mitigated by OIDC, read-only permissions)
- **Low supply chain risk** (minimal dependencies, open-source auditability)

CleanCloud is NOT appropriate if you require:
- **Zero risk tolerance** (all software has some risk)
- **Guaranteed uptime SLA** (open-source tool, community support)

---

## Data Privacy & Compliance

### Data Collection

**CleanCloud collects ZERO telemetry.**

| Data Type | Collected? | Transmitted? | Stored? |
|-----------|-----------|--------------|---------|
| Usage analytics | No | No | No |
| Resource metadata | Local only | No | User-controlled |
| Account identifiers | Local only | No | User-controlled |
| Error reports | No | No | No |
| Version check | No | No | No |

**Legend:**
- No: Never accessed or stored
- Local only: Processed locally but never transmitted
- User-controlled: Only stored in outputs explicitly created by the user

### Data Residency

- **Processing**: 100% local (in CI/CD runner, developer machine, or bastion host)
- **Storage**: Only in user-specified output files (JSON, CSV, or stdout)
- **Transmission**: Zero data transmitted to third parties

### GDPR Considerations

CleanCloud is designed to avoid intentional processing of personal data.

However, cloud resource metadata (e.g., tags, resource names, IAM principals) **may contain identifiers depending on how the customer configures their environment**.

- CleanCloud does not transmit or retain such data outside the user's environment
- All processing occurs locally under the user's control
- CleanCloud does not act as a data controller or processor

GDPR applicability and obligations (e.g., DPIA, DPA requirements) must be assessed by the user based on their specific data usage and organizational policies.

### CCPA Considerations

CleanCloud is designed to avoid collection or sale of personal information.

However, organizations must assess CCPA applicability based on:
- How resource metadata is configured (e.g., user names in tags)
- Whether such metadata constitutes personal information under California law
- The organization's own data handling practices

CleanCloud does not transmit or sell any data collected during scanning operations.

### Data Classification

CleanCloud output may contain:

- **Cloud resource identifiers** (ARNs, resource IDs, subscription IDs)
- **Resource metadata** (tags, creation dates, sizes)
- **Account identifiers** (AWS account ID, Azure subscription ID)

**Recommended Classification:** Internal / Confidential (depends on your organization's data classification policy)

**Note:** Output files should be handled according to your organization's cloud metadata handling policies.

---

## Access Control & Authentication

### Supported Authentication Methods

#### AWS

| Method | Security Grade | Use Case | Credential Lifetime |
|--------|---------------|----------|---------------------|
| OIDC (GitHub Actions) | Excellent | CI/CD | 1 hour (temporary) |
| AWS CLI Profiles | Good | Local development | Session-based |
| Environment Variables | Acceptable | Local/CI | Varies (can be long-lived) |

**Recommendation:** Use OIDC for CI/CD, AWS SSO profiles for local development.

#### Azure

| Method | Security Grade | Use Case | Credential Lifetime |
|--------|---------------|----------|---------------------|
| OIDC (Workload Identity) | Excellent | CI/CD | 1 hour (temporary) |
| Azure CLI (`az login`) | Good | Local development | Session-based |
| Managed Identity | Excellent | Azure VMs/Containers | Automatic rotation |

**Recommendation:** Use OIDC for CI/CD, Azure CLI with MFA for local development.

### Minimum Required Permissions

#### AWS IAM Policy

The minimum required permissions are **read-only**:

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

**Characteristics:**
- Zero `Delete*`, `Put*`, `Create*`, `Update*`, or `Tag*` permissions
- Compatible with `Resource: "*"` without security risk
- Can be safely used in production accounts
- Automated tests ensure policy remains read-only

See: [`docs/aws.md`](aws.md) for full policy

#### Azure RBAC Role

**Minimum role required:** `Reader` at subscription scope

- Built-in Azure role (no custom role needed)
- Read-only across all resource types
- No write, delete, or tag modification permissions

See: [`docs/azure.md`](azure.md) for OIDC setup

### Credential Security Best Practices

**For InfoSec Teams:**

1. **Enforce OIDC in CI/CD**
 - Require short-lived credentials (1-hour max lifetime)
 - Use repository/branch conditions in trust policies
 - Audit OIDC token requests in CloudTrail/Azure AD logs

2. **Restrict to Specific Accounts/Subscriptions**
 - Grant CleanCloud access only to non-production environments initially
 - Expand to production after validation period
 - Use separate roles/service principals per environment

3. **Enable Audit Logging**
 - AWS: Enable CloudTrail for all API calls
 - Azure: Enable Activity Log and route to Log Analytics
 - Monitor for unexpected API calls or access patterns

4. **Review Session Duration**
 - AWS: Set `MaxSessionDuration` to 1 hour on OIDC roles
 - Azure: Use short-lived tokens (default 1 hour)
 - Avoid indefinite credential validity

---

## Operational Security

### Execution Environment

CleanCloud can run in:

| Environment | Security Considerations |
|-------------|------------------------|
| **CI/CD Runners** (GitHub Actions, GitLab CI) | Ephemeral, no persistent state<br> OIDC authentication recommended<br> Ensure artifact encryption if storing outputs |
| **Developer Workstations** | Requires credential security hygiene<br> Outputs stay local<br> Ensure disk encryption |
| **Bastion Hosts / Jump Boxes** | Centralized access control<br> Session recording recommended<br> Audit logs available |
| **Containers / Kubernetes** | Supports managed identity (AWS IRSA, Azure Workload Identity)<br> No credentials in container images<br> Ephemeral by nature |

### Network Security

**CleanCloud network requirements:**

- **Outbound HTTPS (443)** to:
 - AWS API endpoints (`*.amazonaws.com`)
 - Azure API endpoints (`management.azure.com`, `login.microsoftonline.com`)
 - PyPI (only during installation: `pypi.org`, `files.pythonhosted.org`)

- **No inbound connections required**

**Firewall/Proxy Considerations:**

- Compatible with corporate proxies (respects `HTTP_PROXY`, `HTTPS_PROXY` environment variables)
- No websocket or non-standard protocol requirements
- Standard AWS/Azure SDK network behavior (uses boto3/azure-sdk-for-python)

### Secrets Management

**CleanCloud does NOT require:**

- Storing credentials in code or configuration files
- Secrets management systems (Vault, AWS Secrets Manager) - though compatible if you choose to use them
- Credential files committed to repositories

**Best Practices:**

- Use OIDC (no secrets at all)
- Use cloud provider credential chains (AWS profiles, Azure CLI)
- Rotate any long-lived credentials regularly
- Audit credential access in CloudTrail/Azure AD logs

---

## Audit & Verification

### Audit Trail

CleanCloud operations are fully auditable through cloud provider logs:

#### AWS CloudTrail

All CleanCloud API calls appear in CloudTrail with:

- **Event Name**: `DescribeVolumes`, `DescribeSnapshots`, `DescribeLogGroups`, etc.
- **User Identity**: The assumed role (OIDC) or IAM user
- **Source IP**: CI/CD runner or execution environment
- **Request Parameters**: Region, filters (if any)

**Example CloudTrail Event:**

```json
{
  "eventName": "DescribeVolumes",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/CleanCloudScanner/GitHubActions"
  },
  "requestParameters": {
    "volumeIdSet": [],
    "filterSet": []
  },
  "readOnly": true
}
```

**Key Audit Points:**
- All events have `"readOnly": true`
- No `Delete*`, `Put*`, `Create*`, or `Tag*` events will appear
- Can set CloudWatch alarms for unexpected API calls

#### Azure Activity Log

All CleanCloud operations appear in Azure Activity Log with:

- **Operation**: `List Virtual Machines`, `Get Disk`, etc.
- **Caller**: Service principal (OIDC) or user identity
- **Authorization**: Read-only operations only
- **Correlation ID**: Trackable across operations

**Audit Queries (KQL):**

```kql
AzureActivity
| where Caller contains "cleancloud" or CallerIpAddress == "<ci-runner-ip>"
| where CategoryValue == "Administrative"
| summarize count() by OperationNameValue, ResultType
```

### Verifying Read-Only Behavior

InfoSec teams can verify CleanCloud's read-only behavior through:

#### 1. Manual Code Review

CleanCloud is open-source. Review the provider code:

- AWS provider: `cleancloud/providers/aws/`
- Azure provider: `cleancloud/providers/azure/`

**What to look for:**
- Only `describe_*`, `list_*`, `get_*` methods from boto3/Azure SDK
- No `delete_*`, `create_*`, `update_*`, `put_*` calls

#### 2. Automated Safety Tests

Run the built-in safety regression tests:

```bash
# Clone repository
git clone https://github.com/cleancloud-io/cleancloud.git
cd cleancloud

# Install dependencies
pip install -e ".[dev]"

# Run safety regression tests
pytest tests/cleancloud/safety/ -v

# Expected: All 6 tests pass
# test_aws_static_readonly (AST checks - AWS)
# test_aws_runtime_readonly (runtime interception - AWS)
# test_aws_iam_policy_readonly (policy validation - AWS)
# test_azure_static_readonly (AST checks - Azure)
# test_azure_runtime_readonly (runtime interception - Azure)
# test_azure_role_definition_readonly (role validation - Azure)
```

See: [`docs/safety.md`](safety.md) for full details

#### 3. Dry Run with Monitoring

Perform a test scan with active CloudTrail/Activity Log monitoring:

**AWS Example:**

```bash
# Enable CloudTrail monitoring
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=CleanCloudScanner

# Run CleanCloud scan
cleancloud scan --provider aws --region us-east-1

# Verify only read operations in CloudTrail
aws cloudtrail lookup-events \
 --lookup-attributes AttributeKey=Username,AttributeValue=CleanCloudScanner \
 --start-time $(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S) \
 | jq '.Events[].EventName' | sort | uniq
```

**Expected output (read-only events only):**
```
"DescribeAddresses"
"DescribeImages"
"DescribeLogGroups"
"DescribeNatGateways"
"DescribeNetworkInterfaces"
"DescribeRegions"
"DescribeSnapshots"
"DescribeVolumes"
"GetBucketTagging"
"GetCallerIdentity"
"GetMetricStatistics"
"ListBuckets"
```

---

## Risk Assessment

### Threat Model

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|-----------|
| **Accidental Resource Deletion** | Extremely Low | Critical | CleanCloud has zero delete permissions; automated tests prevent mutation APIs |
| **Credential Compromise** | Low-Medium | Medium-High | Use OIDC (short-lived); scope to read-only; monitor CloudTrail |
| **Data Exfiltration** | Extremely Low | Medium | No telemetry; all processing local; outputs user-controlled |
| **Supply Chain Attack** | Low | Medium | Open-source (auditable); minimal dependencies; PyPI checksums |
| **Denial of Service (API Throttling)** | Low | Low | CleanCloud respects rate limits; parallel scanning configurable |
| **False Positive (Incorrect Findings)** | Medium | Low | Conservative detection logic; confidence levels; review-only (no auto-action) |

### Risk Acceptance Criteria

CleanCloud is appropriate for organizations that accept:

 **Read-only tool execution** in production accounts
 **Local processing** of cloud metadata (no external transmission)
 **Open-source software** with community contributions
 **CLI-based tools** without web interfaces or dashboards

CleanCloud may NOT be appropriate if you require:

 **Fully managed SaaS** with 24/7 vendor support
 **Zero internet connectivity** (CleanCloud needs AWS/Azure API access)
 **Automated remediation** (CleanCloud is review-only)

---

## Compliance Considerations

### Industry Standards

CleanCloud does not claim certification or formal compliance with the following standards. The table below describes architectural characteristics that may support organizations pursuing these frameworks.

| Standard | Alignment Characteristics | Evidence |
|----------|--------------------------|----------|
| **SOC 2 Type II** | Read-only by design, no data storage, audit trails | Local processing; CloudTrail/Activity Log compatibility |
| **ISO 27001** | Access control, audit logging, least privilege | OIDC authentication; read-only IAM/RBAC |
| **PCI-DSS** | No cardholder data access; read-only permissions | Does not interact with payment systems |
| **HIPAA** | No PHI access; local processing; audit trails | Resource metadata only; no health data access |
| **FedRAMP** | Read-only, OIDC-compatible, audit-friendly | May support ATO process; agency assessment required |
| **NIST 800-53** | AC-6 (Least Privilege), AU-2 (Audit Events) | Read-only controls; CloudTrail logging |

**Important:** Compliance and certification status must be assessed by the deploying organization. CleanCloud provides architectural characteristics that may support compliance efforts, but does not hold third-party certifications.

### Control Mapping

| Control Framework | Control ID | Control Name | How CleanCloud Supports |
|------------------|------------|--------------|------------------------|
| NIST 800-53 | AC-6 | Least Privilege | Read-only IAM/RBAC policies; no write permissions |
| NIST 800-53 | AU-2 | Audit Events | All API calls logged in CloudTrail/Activity Log |
| NIST 800-53 | CM-3 | Configuration Change Control | Read-only; cannot modify infrastructure |
| NIST 800-53 | IA-2 | Identification and Authentication | OIDC with MFA-protected IdP |
| NIST 800-53 | SC-7 | Boundary Protection | No inbound connections; HTTPS-only outbound |
| CIS Controls | 5.1 | Establish Secure Configurations | Detects untagged/orphaned resources (hygiene) |
| CIS Controls | 6.1 | Maintain Asset Inventory | Identifies unknown/unmanaged resources |
| CIS Controls | 8.1 | Audit Logs | CloudTrail/Activity Log integration |

### Regulatory Considerations

**GDPR (EU General Data Protection Regulation):**
- CleanCloud avoids intentional processing of personal data
- All data processing occurs locally under user control
- GDPR obligations depend on customer's specific usage and environment configuration

**CCPA (California Consumer Privacy Act):**
- CleanCloud avoids collection or sale of personal information
- CCPA applicability must be assessed based on customer's data handling practices

**FISMA (Federal Information Security Management Act):**
- CleanCloud may be used within federal environments subject to agency risk acceptance and authorization (ATO)
- The tool itself does not hold FedRAMP authorization
- Deployment in federal systems requires agency-specific security assessment

---

## Security Testing & Validation

### Automated Safety Regression Tests

CleanCloud includes three layers of automated safety tests:

#### 1. Static AST Analysis

**Purpose:** Detect forbidden API calls in code before execution

**Files:**
- `tests/cleancloud/safety/aws/test_aws_static_readonly.py`
- `tests/cleancloud/safety/azure/test_azure_static_readonly.py`

**Checks:**
- Scans all provider code for `Delete*`, `Put*`, `Update*`, `Create*` methods
- Fails CI build if any forbidden call is found
- Updated automatically when new rules are added

**Run:**
```bash
pytest tests/cleancloud/safety/aws/test_aws_static_readonly.py -v
pytest tests/cleancloud/safety/azure/test_azure_static_readonly.py -v
```

#### 2. Runtime SDK Guards

**Purpose:** Intercept forbidden API calls during test execution

**Files:**
- `tests/cleancloud/safety/aws/test_aws_runtime_readonly.py`
- `tests/cleancloud/safety/azure/test_azure_runtime_readonly.py`

**Mechanism:**
- pytest autouse fixture wraps boto3/Azure SDK clients
- Raises exception if any mutating method is called during tests
- Acts as a safety net for missed static analysis

**Run:**
```bash
pytest tests/cleancloud/safety/ -v
```

#### 3. IAM/RBAC Policy Validation

**Purpose:** Ensure IAM policies and RBAC roles grant read-only permissions only

**Files:**
- `tests/cleancloud/safety/aws/test_aws_iam_policy_readonly.py`
- `tests/cleancloud/safety/azure/test_azure_role_definition_readonly.py`

**Checks:**
- Parses IAM policy JSON and Azure role definitions
- Fails if any `Delete*`, `Put*`, `Create*`, `Update*`, `Tag*` actions are found
- Validates against canonical policy files

**Run:**
```bash
pytest tests/cleancloud/safety/aws/test_aws_iam_policy_readonly.py -v
pytest tests/cleancloud/safety/azure/test_azure_role_definition_readonly.py -v
```

### Penetration Testing Guidance

InfoSec teams can perform penetration testing on CleanCloud:

**Suggested Test Scenarios:**

1. **Attempt Resource Mutation**
 - Grant CleanCloud only read permissions
 - Attempt to modify code to call `delete_volume()`
 - Expected: AWS/Azure API returns `AccessDenied`

2. **Credential Escalation**
 - Start with read-only credentials
 - Attempt to escalate privileges via CleanCloud
 - Expected: No escalation path (tool has no write permissions)

3. **Data Exfiltration**
 - Run CleanCloud with network monitoring (Wireshark/tcpdump)
 - Verify no data sent to non-AWS/Azure endpoints
 - Expected: Only API calls to `*.amazonaws.com` or `management.azure.com`

4. **Dependency Vulnerability Scanning**
 - Run `pip install safety` and `safety check`
 - Run `pip install pip-audit` and `pip-audit`
 - Expected: No known vulnerabilities in dependencies

**Responsible Disclosure:**

If you discover a security vulnerability, please report it to:
- Email: suresh@getcleancloud.com
- Subject: `[SECURITY] CleanCloud Vulnerability Report`

We aim to acknowledge reports within 48 hours and provide a resolution timeline as soon as reasonably possible.

---

## Supply Chain Security

### Dependency Management

CleanCloud has **minimal dependencies**:

```
# Core
click >= 8.0.0 # CLI framework (maintained by Pallets)
pyyaml >= 6.0 # Config parsing

# AWS (optional)
boto3 >= 1.26.0 # AWS SDK (maintained by AWS)
botocore >= 1.29.0 # AWS SDK core (maintained by AWS)

# Azure (optional)
azure-identity >= 1.15.0 # Azure Auth (maintained by Microsoft)
azure-mgmt-compute >= 30.0.0 # Azure Compute SDK
azure-mgmt-network >= 25.0.0 # Azure Network SDK
azure-mgmt-web >= 8.0.0 # Azure Web Apps SDK
azure-mgmt-resource >= 23.0.0 # Azure Resource SDK
azure-mgmt-subscription >= 3.0.0 # Azure Subscription SDK
azure-core >= 1.38.0 # Azure SDK core
```

**Dependency Security:**
- All dependencies are from well-known, actively maintained projects (AWS, Microsoft, Pallets)
- AWS and Azure dependencies are optional — install only what you need (`pip install cleancloud[aws]` or `cleancloud[azure]`)
- Minimum version pinning (allows security updates)
- No transitive dependencies from untrusted sources
- Dependencies scanned with `pip-audit` in CI

### Distribution & Integrity

**PyPI Distribution:**

CleanCloud is distributed via PyPI:
- Package: `cleancloud`
- Maintainer: CleanCloud team
- Verification: SHA256 checksums, GPG signatures (planned)

**Verification Steps:**

```bash
# Verify package integrity
pip download cleancloud
pip hash cleancloud-<version>.tar.gz

# Compare against PyPI published hash
curl -s https://pypi.org/pypi/cleancloud/json | jq '.urls[].digests.sha256'
```

**Source Code Integrity:**

All releases are tagged in GitHub:
- Tags: `v1.2.0`, `v1.1.0`, etc.
- Signed commits (planned for future releases)
- Release notes with changelogs

### SBOM (Software Bill of Materials)

Generate an SBOM for compliance:

```bash
pip install cleancloud
pip freeze | grep -iE "(cleancloud|boto3|azure|click|pyyaml)" > cleancloud-sbom.txt
```

**Example SBOM:**
```
cleancloud==1.2.0
boto3==1.34.0
azure-identity==1.15.0
azure-mgmt-compute==30.5.0
azure-mgmt-network==25.0.0
azure-mgmt-web==8.0.0
azure-mgmt-resource==23.0.0
azure-mgmt-subscription==3.0.0
azure-core==1.38.0
click==8.1.7
pyyaml==6.0.1
```

---

## Incident Response

### Incident Scenarios

#### Scenario 1: Unauthorized Resource Deletion

**Symptom:** Resource deleted from AWS/Azure account

**Investigation:**
1. Check CloudTrail/Activity Log for `Delete*` events
2. Verify event source (should NOT be CleanCloud if permissions are correct)
3. Check IAM/RBAC policy attached to CleanCloud role

**Expected Finding:**
- CleanCloud cannot delete resources (lacks permissions)
- Deletion came from another source (misconfigured automation, manual action)

**Remediation:**
- No action required for CleanCloud (not the source)
- Investigate actual source of deletion

#### Scenario 2: Credential Compromise

**Symptom:** Unexpected API calls from CleanCloud credentials

**Investigation:**
1. Review CloudTrail/Activity Log for unusual API calls
2. Check source IP, time, and operation patterns
3. Verify OIDC token issuance logs (GitHub Actions audit log)

**Containment:**
1. Revoke/disable compromised credentials immediately
2. AWS: Delete IAM role session; Azure: Revoke service principal tokens
3. Rotate OIDC trust policy (change allowed repositories/branches)

**Recovery:**
1. Create new OIDC role/service principal with tighter restrictions
2. Enable MFA on repository access
3. Audit all API calls during compromise window

**Lessons Learned:**
- Review credential lifetime settings (reduce to minimum)
- Implement conditional access policies (IP restrictions)
- Enable additional CloudTrail alerts

#### Scenario 3: False Positive Findings

**Symptom:** CleanCloud flags resources as orphaned/inactive incorrectly

**Investigation:**
1. Review finding details (age, tags, usage signals)
2. Check confidence level (LOW/MEDIUM/HIGH)
3. Verify resource is actually in use

**Remediation:**
1. Tag resources to exclude from future scans (use `--ignore-tag`)
2. Report false positive in GitHub Issues
3. Adjust confidence thresholds in CI (use `--fail-on-confidence HIGH`)

**Prevention:**
- Use CleanCloud as **review-only** (never auto-delete)
- Start with `--fail-on-confidence HIGH` in CI
- Gradually tighten policy after validation period

---

## Frequently Asked Questions

### General Security

**Q: Can CleanCloud delete or modify cloud resources?**
A: No. CleanCloud only has read permissions and makes zero modification API calls. This is enforced through:
- IAM/RBAC policies (no write permissions granted)
- Automated safety tests (detect forbidden API calls)
- Runtime guards (block mutations during execution)

**Q: Does CleanCloud send data to third-party servers?**
A: No. CleanCloud has zero telemetry. All processing happens locally, and results are written to user-specified outputs only.

**Q: Is CleanCloud safe to run in production accounts?**
A: Yes. CleanCloud is designed specifically for production use with:
- Read-only permissions
- No side effects
- Audit trail compatibility
- Conservative detection logic

**Q: How can I verify CleanCloud doesn't exfiltrate data?**
A: You can:
1. Review the open-source code
2. Monitor network traffic during scans (only AWS/Azure API calls)
3. Run in isolated network with egress filtering
4. Review CloudTrail/Activity Log (only read operations)

### Authentication & Access Control

**Q: What's the recommended authentication method?**
A: OIDC (OpenID Connect) for CI/CD:
- AWS: GitHub Actions OIDC with IAM role assumption
- Azure: Workload Identity Federation with service principal
- Benefits: Short-lived credentials (1 hour), no secrets, fully auditable

**Q: Can I use long-lived access keys?**
A: Yes, but not recommended. Use OIDC or session-based credentials instead.

**Q: Do I need to grant `*:*` permissions?**
A: No. CleanCloud requires only specific read permissions (see IAM policy in [Access Control](#minimum-required-permissions)).

**Q: Can I restrict CleanCloud to specific regions/subscriptions?**
A: Yes. Use:
- AWS: IAM policy conditions (`aws:RequestedRegion`)
- Azure: Scope service principal to specific subscriptions
- CLI flags: `--region us-east-1` or `--subscription <sub-id>`

### Compliance & Audit

**Q: Is CleanCloud SOC 2 compliant?**
A: CleanCloud does not have a SOC 2 report (it's an open-source CLI tool). However, it's compatible with SOC 2 controls through its security model (read-only, audit trails, no data storage).

**Q: Can I get audit logs of CleanCloud operations?**
A: Yes. All CleanCloud API calls appear in:
- AWS: CloudTrail
- Azure: Activity Log
These logs include user identity, timestamp, API call, and source IP.

**Q: How do I demonstrate compliance to auditors?**
A: Provide:
1. This document (Information Security Readiness Guide)
2. IAM/RBAC policy (read-only permissions)
3. CloudTrail/Activity Log samples (showing read-only operations)
4. Safety regression test results (from `pytest tests/cleancloud/safety/`)

### Operational

**Q: What happens if CleanCloud has a bug?**
A: In the worst case:
- CleanCloud crashes (no impact on cloud resources)
- CleanCloud produces incorrect findings (review-only, no auto-action)
CleanCloud **cannot** delete or modify resources due to permission constraints.

**Q: Can CleanCloud cause API throttling / rate limiting?**
A: Unlikely. CleanCloud:
- Uses pagination for large result sets
- Respects AWS/Azure rate limits
- Scans regions in parallel (configurable)

If throttling occurs, AWS/Azure will return rate limit errors (no resource impact).

**Q: How do I report a security vulnerability?**
A: Email: suresh@getcleancloud.com with subject `[SECURITY] CleanCloud Vulnerability Report`

We follow responsible disclosure practices:
- Aim to acknowledge reports within 48 hours
- Provide resolution timeline as soon as reasonably possible
- Credit security researchers in release notes (if desired)

---

## Conclusion

CleanCloud is designed as a **trust-first, enterprise-ready tool** for cloud hygiene scanning. Its security model prioritizes:

1. **Read-Only by Design** – No resource mutations possible
2. **Zero Telemetry** – No data collection or transmission
3. **Provable Safety** – Automated tests prevent permission creep
4. **Full Auditability** – CloudTrail/Activity Log integration
5. **OIDC-First** – Short-lived, temporary credentials

For information security teams evaluating CleanCloud, we recommend:

- Start with non-production accounts
- Use OIDC authentication
- Enable CloudTrail/Activity Log monitoring
- Run safety regression tests (`pytest tests/cleancloud/safety/ -v`)
- Review scan output before trusting findings
- Gradually expand to production after validation period

**Questions?**
Email: suresh@getcleancloud.com
GitHub Issues: https://github.com/cleancloud-io/cleancloud/issues
Documentation: https://github.com/cleancloud-io/cleancloud/tree/main/docs

---

**Document Version History**

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2026-02-08 | Updated IAM policy (12 permissions), fixed safety test paths, updated dependencies, updated SBOM |
| 1.0 | 2026-01-10 | Initial release |
