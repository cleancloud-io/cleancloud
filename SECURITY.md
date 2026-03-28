# Security Policy

**CleanCloud Security Documentation**

Version: 1.1

Last Updated: 2026-03-28

Classification: Public

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Security Architecture](#security-architecture)
- [Threat Model](#threat-model)
- [Security Controls](#security-controls)
- [Data Handling](#data-handling)
- [Vulnerability Management](#vulnerability-management)
- [Security Testing](#security-testing)
- [Compliance & Certifications](#compliance--certifications)
- [Incident Response](#incident-response)
- [Security Contact](#security-contact)

---

## Executive Summary

CleanCloud is a **read-only cloud hygiene evaluation tool** designed for enterprise and government organizations with strict security requirements. This document provides comprehensive security information for InfoSec teams, security architects, and compliance officers evaluating CleanCloud for deployment.

### Automated Security Scanning

**Every code change undergoes 6 automated security gates:**

```
┌─────────────────────────────────────────────────────┐
│ Automated Security Pipeline (Every PR + Main)       │
├─────────────────────────────────────────────────────┤
│  Dependency CVE Scan     → pip-audit                │
│  SAST (Code Security)    → Bandit                   │
│  Advanced SAST           → CodeQL                   │
│  Secrets Detection       → TruffleHog               │
│  License Compliance      → pip-licenses             │
│  Safety Regression       → Custom read-only test    │
│                                                     │
│  Policy: ANY FAILURE = MERGE BLOCKED                │
└─────────────────────────────────────────────────────┘
```

**Current Status** (2026-01-21): Zero CVEs, Zero HIGH/MEDIUM issues, Zero secrets

### Security Posture Summary

| Security Domain | Status | Details |
|----------------|--------|---------|
| **Read-Only by Design** | Enforced | No write, delete, or modify permissions required |
| **Zero Telemetry** | Enforced | No data leaves your environment |
| **OIDC Authentication** | Supported | Short-lived credentials, no secrets storage |
| **Automated Security Scanning** | Active | 6 security gates on every commit (pip-audit, Bandit, CodeQL, TruffleHog, license checks, safety tests) |
| **Supply Chain Security** | Active | Real-time CVE monitoring, SBOM generation, Dependabot auto-updates |
| **Secrets Detection** | Active | TruffleHog scans every commit for leaked credentials |
| **Audit Trail** | Supported | Deterministic output, versioned schemas, 30-day scan artifact retention |
| **Open Source** | MIT License | Full code transparency, community security review |

---

## Security Architecture

### Design Principles

CleanCloud is built on **defense-in-depth** principles with security enforced at multiple layers:

1. **Read-Only by Design** - Architecture prevents mutations through IAM policy restrictions
2. **Least Privilege** - Minimal permissions (List*, Describe*, Get* only)
3. **Zero Trust** - No implicit trust in cloud provider APIs
4. **Fail-Safe Defaults** - Operations default to safe, non-destructive behavior
5. **Complete Mediation** - All cloud API calls go through auditable SDK layers

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      User Environment                        │
│  ┌────────────┐     ┌──────────────┐     ┌──────────────┐  │
│  │   CI/CD    │────▶│  CleanCloud  │────▶│  Cloud APIs  │  │
│  │  Pipeline  │     │   (Read-Only)│     │  (Read-Only) │  │
│  └────────────┘     └──────────────┘     └──────────────┘  │
│         │                   │                     │          │
│         │                   ▼                     │          │
│         │            ┌──────────────┐            │          │
│         └───────────▶│ JSON/CSV Out │◀───────────┘          │
│                      │  (Local FS)  │                       │
│                      └──────────────┘                       │
│                                                              │
│  ❌ No outbound calls to CleanCloud servers                 │
│  ❌ No telemetry or phone-home                              │
│  ❌ No write operations to cloud providers                  │
└─────────────────────────────────────────────────────────────┘
```

### Network Security

**Outbound Connections:**
- **AWS, Azure, and GCP API endpoints only** (HTTPS, TLS 1.2+)
- **No connections to CleanCloud infrastructure** (we have none)
- **No analytics or telemetry endpoints**
- **No update servers or phone-home**

**Inbound Connections:**
- Not applicable (CleanCloud is a CLI tool, not a service)

### Authentication & Authorization

#### Supported Authentication Methods

| Provider | Method | Security Level | Use Case |
|----------|--------|---------------|----------|
| **AWS** | OIDC (IAM Roles) | Excellent | CI/CD (GitHub Actions) - **Recommended** |
| **AWS** | IAM Access Keys | Poor | Local development only |
| **Azure** | OIDC (Workload Identity) | Excellent | CI/CD (GitHub Actions) - **Recommended** |
| **Azure** | Service Principal (Secret) | Poor | Local development only |
| **Azure** | Azure CLI | Acceptable | Local development only |
| **Azure** | Managed Identity | Excellent | Azure VM/Container Apps |
| **GCP** | Workload Identity Federation | Excellent | CI/CD (GitHub Actions) - **Recommended** |
| **GCP** | Application Default Credentials | Excellent | Cloud Shell / local gcloud |
| **GCP** | Service Account Key (JSON) | Poor | Local development only — avoid in CI/CD |
| **GCP** | Attached Service Account | Excellent | GCP VM / Cloud Run / GKE |

#### OIDC Implementation (Recommended)

CleanCloud supports **OpenID Connect (OIDC)** federation with GitHub Actions, eliminating the need to store long-lived credentials:

- **Short-lived tokens** (1 hour validity)
- **No secrets in CI/CD**
- **Automatic rotation**
- **Conditional access via trust policies**

**Example AWS IAM Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:*"
        }
      }
    }
  ]
}
```

See: [IAM Proof Pack](security/) for complete examples.

---

## Threat Model

### Overview

CleanCloud is designed with **security-first architecture** to address industry-standard threats facing cloud tooling. This section demonstrates how CleanCloud's design mitigates common attack vectors through defense-in-depth principles.

### Assets Protected

1. **Cloud Resource Metadata** (read by CleanCloud) - Protected by read-only access
2. **Cloud Credentials** (provided by user) - Protected by OIDC and IAM least privilege
3. **Scan Results** (stored locally) - User-controlled, no external transmission
4. **CleanCloud Source Code** (open source, MIT licensed) - Transparent and auditable

### Industry Threat Landscape & CleanCloud's Defenses

CleanCloud's architecture addresses standard cloud security threats:

| Threat Category | Industry Risk | CleanCloud's Defense | Status |
|----------------|--------------|---------------------|--------|
| **Credential Exposure** | Long-lived secrets in code/CI | OIDC support, no secret storage | Mitigated |
| **Excessive Permissions** | Over-privileged cloud access | Read-only by design, IAM Proof Pack | Mitigated |
| **Supply Chain Attacks** | Compromised dependencies | Automated CVE scanning, SBOM | Monitored |
| **Data Exfiltration** | Telemetry to vendor servers | Zero telemetry, fully local | Eliminated |
| **Accidental Changes** | Unintended resource mutations | Architectural impossibility (read-only) | Eliminated |

### Threat Analysis & Mitigations

#### T1: Credential Protection

**Scenario:** Cloud credentials used by any tool could be exposed through code commits, logs, or CI/CD systems.

**How CleanCloud Addresses This:**
- **OIDC support** eliminates long-lived credentials in CI/CD
- **Read-only IAM policies** limit blast radius if credentials are compromised
- **TruffleHog scanning** in CI/CD prevents secret commits
- **No credential storage** in CleanCloud codebase
- **Short-lived tokens** (1 hour) when using OIDC

**Risk Level:** Low (with OIDC recommended deployment)

---

#### T2: Supply Chain Integrity

**Scenario:** Any software tool faces risk from compromised dependencies (industry-wide challenge).

**How CleanCloud Addresses This:**
- **Automated CVE scanning** (pip-audit on every commit)
- **Dependency pinning** with secure minimum versions
- **SBOM generation** for transparency and audit
- **License compliance checks** (no GPL/AGPL)
- **Continuous monitoring** via GitHub Dependabot
- **Open source** (code is auditable by your security team)

**Risk Level:** Low (actively monitored and patched)

---

#### T3: Least Privilege Access Control

**Scenario:** Tools granted excessive cloud permissions could enable unintended actions.

**How CleanCloud Addresses This:**
- **Read-only by design** - architecture prevents write operations
- **IAM Proof Pack** with verified, minimal permission policies
- **Automated IAM validation** scripts for your security team
- **Safety regression tests** that fail builds if write operations detected
- **Static analysis** blocks forbidden SDK calls at code level

**Risk Level:** None (architecturally enforced read-only)

---

#### T4: Data Privacy & Sovereignty

**Scenario:** SaaS tools often send telemetry or scan data to vendor servers.

**How CleanCloud Addresses This:**
- **Zero telemetry by design** - no analytics, no phone-home
- **Fully local execution** - all data stays in your environment
- **No vendor servers** - CleanCloud has no backend infrastructure
- **Open source** - network behavior is auditable
- **User-controlled output** - you decide where results are stored

**Risk Level:** None (no external data transmission)

---

#### T5: Code Security & Input Validation

**Scenario:** Tools that process user input could be vulnerable to injection attacks.

**How CleanCloud Addresses This:**
- **Bandit SAST** scanning on every commit (HIGH/MEDIUM severity)
- **CodeQL security analysis** for advanced vulnerability detection
- **Input validation** on configuration files (YAML schema)
- **Type safety** enforcement (Python type hints, mypy checking)
- **Minimal attack surface** (read-only operations, no user-generated queries)

**Risk Level:** Low (continuously tested)

---

#### T6: Operational Safety

**Scenario:** Tool bugs or misconfigurations could cause unintended cloud changes.

**How CleanCloud Addresses This:**
- **Read-only by design** - no Delete*, Modify*, or Tag* permissions ever required
- **Safety regression tests** fail builds if write operations detected
- **AST analysis** blocks forbidden SDK calls at code level
- **Runtime SDK guards** prevent mutations in test suites
- **Architectural guarantee** - destructive operations are impossible

**Risk Level:** None (architecturally eliminated)

---

## Security Controls

### Preventive Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| **Read-Only Enforcement** | IAM policy restrictions, safety tests | Active |
| **Input Validation** | Schema validation on config files | Active |
| **Least Privilege IAM** | Documented policies in IAM Proof Pack | Active |
| **Secrets Prevention** | TruffleHog scanning in CI/CD | Active |
| **Dependency Scanning** | pip-audit, automated CVE checks | Active |
| **Code Signing** | PyPI package signatures (planned) | Roadmap |

### Detective Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| **SAST Scanning** | Bandit (HIGH/MEDIUM severity) on every commit | Active |
| **Advanced SAST** | CodeQL security queries on every commit | Active |
| **Dependency Audit** | pip-audit on every commit (PR + main) | Active |
| **License Compliance** | Automated GPL/AGPL detection on every commit | Active |
| **Secret Detection** | TruffleHog (verified secrets only) on every commit | Active |

### Corrective Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| **Automated Patching** | Dependabot PRs for CVEs | Active |
| **Incident Response** | Security contact & disclosure policy | Active |
| **Version Pinning** | Minimum secure versions in pyproject.toml | Active |

---

## Data Handling

### Data Classification

| Data Type | Classification | Retention | Location |
|-----------|---------------|-----------|----------|
| **Cloud Resource Metadata** | Confidential | Scan duration only | Memory (not persisted) |
| **Scan Results (JSON/CSV)** | Confidential | User-controlled | Local filesystem |
| **Cloud Credentials** | Highly Confidential | Session duration only | Environment variables |
| **Configuration (YAML)** | Internal | User-controlled | Local filesystem |

### Data Flow

1. **Input**: User provides cloud credentials via environment variables or OIDC
2. **Processing**: CleanCloud calls cloud provider APIs (read-only)
3. **Output**: Results written to local filesystem (JSON/CSV)
4. **Storage**: No data stored by CleanCloud (user controls output)

### Data Encryption

- **In Transit**: All cloud API calls use TLS 1.2+ (enforced by AWS/Azure SDKs)
- **At Rest**: Results stored on user-controlled filesystems (user manages encryption)
- **No CleanCloud-side storage**: Tool does not persist data

### Data Retention

CleanCloud does **not retain any data**. All scan results are:
- Written to user-specified locations
- Controlled entirely by the user
- Not transmitted to CleanCloud infrastructure (we have none)

---

## Vulnerability Management

### Vulnerability Disclosure

We operate a **coordinated disclosure** program (best effort):

1. **Report**: Email security@getcleancloud.com (PGP key available on request)
2. **Acknowledgment**: Target within 3-5 business days
3. **Triage**: Assess severity and impact (timeline varies)
4. **Fix Development**: Depends on severity and complexity
5. **Disclosure**: Coordinate public disclosure with reporter

**Note**: As an open-source project, response times depend on maintainer availability and issue complexity. We prioritize critical issues but cannot guarantee fixed timelines.

### Severity Levels

| Severity | Response Target | Example |
|----------|----------------|---------|
| **Critical** | Within 24-48 hours | Remote code execution, credential theft |
| **High** | Within 7 days | Privilege escalation, data exfiltration |
| **Medium** | Within 14 days | Information disclosure, DoS |
| **Low** | Next minor release | Minor security improvements |

### CVE Handling Process (Dependency Vulnerabilities)

**Note**: The timelines below apply specifically to **dependency CVEs** (third-party packages), which are typically faster to fix via version updates. Code vulnerabilities may take longer depending on complexity.

**Automated Process**:
1. **Detection**: pip-audit scans on every commit (automated)
2. **Triage**: Review CVE severity and applicability
3. **Fix**: Update dependency minimum versions in `pyproject.toml`
4. **Verification**: Re-run pip-audit to confirm resolution
5. **Release**: Patch version bump with security fix notes
6. **Notification**: GitHub Security Advisories for user notification

**Response Targets** (best effort):
- **Critical CVEs**: Aim to patch within 24-48 hours
- **High CVEs**: Aim to patch within 7 days
- **Medium CVEs**: Aim to patch within 14 days
- **Low CVEs**: Include in next minor release

These are targets, not guarantees. Actual response time depends on CVE complexity, fix availability, and maintainer availability.

**Example Recent CVE Fixes** (2026-01-21):
- `CVE-2026-21226` (azure-core): Fixed by upgrading to 1.38.0
- `CVE-2026-21441` (urllib3): Fixed by upgrading to 2.6.3
- `CVE-2026-23949` (jaraco-context): Fixed by upgrading to 6.1.0
- `CVE-2026-23490` (pyasn1): Fixed by upgrading to 0.6.2

All fixes enforced via minimum version constraints in `pyproject.toml`.

### Known Vulnerabilities

Current status: **No known vulnerabilities** (as of 2026-01-21)

**Last pip-audit scan**: 2026-01-21 Clean

**Last Bandit scan**: 2026-01-21 Clean (0 HIGH/MEDIUM issues)

See: [GitHub Security Advisories](https://github.com/cleancloud-io/cleancloud/security/advisories) for historical records.

---

## Security Testing

### Overview

CleanCloud implements **defense-in-depth security testing** with 6 automated security gates:

```
┌─────────────────────────────────────────────────────────────┐
│ Security Scanning Pipeline │
│ (Runs on Every Commit to PR/Main) │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1️⃣  Dependency CVE Scan        → pip-audit                 │
│  2️⃣  SAST (Code Security)       → Bandit                    │
│  3️⃣  Advanced SAST              → CodeQL                    │
│  4️⃣  Secrets Detection          → TruffleHog                │
│  5️⃣  License Compliance         → pip-licenses              │
│  6️⃣  Safety Regression Tests    → Custom (read-only check)  │
│                                                              │
│  Policy: ANY FAILURE = MERGE BLOCKED ❌                      │
│  Audit: All results uploaded as artifacts (30-day retention)│
└─────────────────────────────────────────────────────────────┘
```

**Current Security Posture** (as of 2026-01-21):
- Zero known CVEs in dependencies
- Zero HIGH/MEDIUM severity code issues
- Zero verified secrets in codebase
- 100% permissive licenses (MIT/Apache/BSD)
- 100% read-only operation guarantee

### Continuous Security Testing (CI/CD)

CleanCloud implements **automated security scanning on every commit** to both pull requests and the main branch. All security checks must pass before code can be merged.

**Workflow**: `.github/workflows/security-scan.yml`

**Trigger**: Every PR, every push to main, manual dispatch

**Policy**: Build fails if any security issues detected

---

#### 1. Dependency Vulnerability Scanning

**Tool**: `pip-audit` (Python Package Vulnerability Scanner)

**What it does**:
- Scans all Python dependencies (AWS SDK, Azure SDK, transitive dependencies)
- Checks against OSV database and PyPI Advisory Database
- Detects known CVEs in installed packages
- Generates JSON reports for audit trail

**Configuration**:
```yaml
- name: pip-audit (Fail on vulnerabilities)
  run: pip-audit --desc --format json
```

**Fail Criteria**: Any known CVE in dependencies
**Result**: JSON artifact uploaded for 30-day retention

---

#### 2. Static Application Security Testing (SAST)

**Tool**: `Bandit` (Python Security Linter)

**What it does**:
- Analyzes Python code for common security issues
- Detects hardcoded passwords, SQL injection, command injection
- Checks for insecure functions (pickle, exec, eval)
- Scans for weak cryptography usage

**Configuration**:
```yaml
- name: Run Bandit SAST
 run: bandit -r cleancloud/ -ll -f json -o bandit-report.json
```

**Severity Filter**: `-ll` flag = HIGH and MEDIUM severity only
**Fail Criteria**: Any HIGH or MEDIUM security issues
**Result**: JSON report uploaded for audit

**Note**: LOW severity false positives (like B105 on metadata flags) are suppressed with `# nosec` comments with justification.

---

#### 3. Advanced Security Analysis

**Tool**: `CodeQL` (GitHub's Semantic Code Analysis)

**What it does**:
- Deep semantic analysis beyond pattern matching
- Detects complex vulnerabilities (data flow, control flow)
- Checks OWASP Top 10 vulnerabilities
- Uses security-extended query suite

**Configuration**:
```yaml
- name: Initialize CodeQL
 uses: github/codeql-action/init@v3
 with:
 languages: python
 queries: security-extended
```

**Query Suite**: `security-extended` (comprehensive security checks)
**Fail Criteria**: Any security findings
**Result**: Uploaded to GitHub Security tab for tracking

---

#### 4. Secrets Detection

**Tool**: `TruffleHog` (Secrets Scanner)

**What it does**:
- Scans entire git history for leaked credentials
- Detects AWS keys, Azure secrets, GCP service account keys, API tokens
- Verifies secrets are active (not just patterns)
- Prevents credential commits

**Configuration**:
```yaml
- name: TruffleHog Secrets Scan
 uses: trufflesecurity/trufflehog@main
 with:
 extra_args: --only-verified --fail
```

**Mode**: `--only-verified` (reduces false positives)
**Fail Criteria**: Any verified secrets found
**Scope**: Full git history

---

#### 5. License Compliance

**Tool**: `pip-licenses`

**What it does**:
- Scans all dependencies for license types
- Generates SBOM (Software Bill of Materials)
- Detects GPL/AGPL licenses (incompatible with enterprise use)
- Flags unknown licenses for review

**Configuration**:
```yaml
- name: Check for non-permissive licenses
 run: |
 if pip-licenses | grep -iE "GPL|AGPL|Unknown"; then
 exit 1
 fi
```

**Fail Criteria**: GPL, AGPL, or Unknown licenses detected
**Allowed Licenses**: MIT, Apache 2.0, BSD, ISC, PSF
**Result**: JSON and Markdown reports uploaded

---

#### 6. Safety Regression Tests

**Purpose**: Ensure CleanCloud can never perform destructive operations, even if code is modified.

**Implementation**:
1. **Static AST Analysis**: Parse code, fail if Delete*, Modify*, Tag* calls detected
2. **Runtime SDK Guards**: Mock cloud SDKs in tests, fail if write methods called
3. **IAM Policy Validation**: Verify policies contain only List*, Describe*, Get*

**Location**: `tests/safety/` (see [Safety Documentation](docs/safety.md))
**Fail Criteria**: Any write operation detected (code or IAM policy level)

---

### Security Testing Summary

| Test Type | Tool | Frequency | Blocks Merge | Retention |
|-----------|------|-----------|--------------|-----------|
| **Dependency CVEs** | pip-audit | Every commit | Yes | 30 days |
| **SAST (Basic)** | Bandit | Every commit | Yes | 30 days |
| **SAST (Advanced)** | CodeQL | Every commit | Yes | Permanent (GitHub) |
| **Secrets** | TruffleHog | Every commit | Yes | N/A (fail fast) |
| **License Compliance** | pip-licenses | Every commit | Yes | 30 days |
| **Safety Regression** | Custom tests | Every commit | Yes | Test results |

**Total Security Gates**: 6 automated checks on every PR
**Policy**: Zero tolerance - any failure blocks merge
**Audit Trail**: All scan results uploaded as artifacts

### Penetration Testing

- **Last Test**: Not yet conducted (project in early stage)
- **Planned**: Q2 2026 (community-driven or sponsored)
- **Scope**: OWASP Top 10, supply chain attacks, IAM privilege escalation

---

## Compliance & Certifications

### Standards Alignment

CleanCloud is designed to align with:

| Standard | Status | Notes |
|----------|--------|-------|
| **NIST Cybersecurity Framework** | Aligned | Identify, Protect, Detect functions |
| **CIS Controls** | Aligned | v8 Controls 2.1, 4.1, 16.1 |
| **ISO 27001** | Partial | Annex A.9.2 (Access Control), A.12.6 (Technical Vulnerability Management) |
| **FedRAMP** | Evaluating | Potential alignment for government use |
| **SOC 2** | N/A | CleanCloud is a tool, not a service |
| **GDPR** | Compliant | No personal data processed |

### Government Use

CleanCloud is suitable for government environments, including:

- **UK Public Sector** (e.g., MoJ, HMRC, NHS Digital)
- **US Federal** (with FedRAMP-aligned deployment)
- **Regulated Industries** (finance, healthcare)

**Key Requirements Met**:
- Open source (full code transparency)
- Read-only operations (minimal risk)
- Zero telemetry (data sovereignty)
- OIDC support (no long-lived credentials)
- Auditable (deterministic output)

---

## Incident Response

**Note**: CleanCloud is an open-source community project. While we take security seriously and respond as quickly as possible, we cannot guarantee enterprise-level SLAs. Response times are best-effort.

### Security Incident Contact

**Primary**: security@getcleancloud.com
**Response Target**: We aim to acknowledge within 3-5 business days
**PGP Key**: Available on request

### Severity Levels & Response Approach

| Severity | Definition | Example | Response Priority |
|----------|-----------|---------|------------------|
| **Critical** | Immediate security risk | RCE exploit, active credential theft | Urgent (best effort) |
| **High** | Significant vulnerability | Privilege escalation, data exposure | High priority |
| **Medium** | Moderate security issue | Information disclosure | Standard priority |
| **Low** | Minor security concern | Security hardening opportunity | Low priority |

### How We Handle Security Reports

**Community-Driven Response**:
1. **Detection**: Automated scanning (CI/CD) or community reports
2. **Acknowledgment**: Confirm receipt (target: within 3-5 business days)
3. **Assessment**: Evaluate severity and impact (varies by complexity)
4. **Fix Development**: Develop and test patch (varies by severity)
5. **Release**: Publish patch and GitHub Security Advisory
6. **Disclosure**: Coordinate public disclosure with reporter

**Important**:
- Response times depend on maintainer availability and issue complexity
- Critical issues will be prioritized, but cannot guarantee specific timeframes
- For mission-critical deployments, consider enterprise support options

### Communication Channels

- **GitHub Security Advisories**: Primary channel for CVE disclosure
- **GitHub Issues**: For non-sensitive security discussions (use private security advisory for sensitive issues)
- **Email**: security@getcleancloud.com for private vulnerability reports

---

## Security Contact

### Reporting Security Vulnerabilities

**Email**: security@getcleancloud.com
**PGP Key**: Available on request
**Scope**: Code vulnerabilities, dependency issues, design flaws

### Out of Scope

- Vulnerabilities in third-party dependencies (report to upstream)
- Social engineering or phishing attempts
- Physical security issues
- Denial of service (tool runs locally, no service to DoS)

### Responsible Disclosure

**What we ask from security researchers**:
- **Allow reasonable time for fixes** (suggest 90 days, but flexible based on severity)
- **Report in good faith** (no malicious exploitation)
- **Avoid public disclosure** until patch is available

**What we commit to**:
- **Acknowledge reports** (target: within 3-5 business days, best effort)
- **Keep you updated** on progress (no fixed schedule, depends on complexity)
- **Credit researchers** in security advisories (if desired)
- **No legal action** against good-faith security researchers
- **Transparent process** via GitHub Security Advisories

**Reality Check**: We're a small open-source project. Response times will vary based on maintainer availability, issue complexity, and severity. Critical issues get priority, but we can't guarantee fixed timelines.

---

## Additional Resources

- **InfoSec Readiness Guide**: [docs/infosec-readiness.md](docs/infosec-readiness.md)
- **IAM Proof Pack**: [security/](security/)
- **Safety Testing**: [docs/safety.md](docs/safety.md)
- **Threat Model**: [docs/infosec-readiness.md#threat-model](docs/infosec-readiness.md#threat-model)
- **GitHub Security**: [github.com/cleancloud-io/cleancloud/security](https://github.com/cleancloud-io/cleancloud/security)

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-21 | CleanCloud Security Team | Initial release |
| 1.1 | 2026-03-28 | CleanCloud Security Team | Added GCP: auth methods, network scope, secrets detection |

**Review Schedule**: Updated as needed (target: annually or when significant changes occur)

---

**Questions?** Contact security@getcleancloud.com or open a [discussion](https://github.com/cleancloud-io/cleancloud/discussions).
