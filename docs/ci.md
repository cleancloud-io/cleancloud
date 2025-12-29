# CI/CD Integration

Complete guide for integrating CleanCloud into continuous integration and deployment pipelines.

> **Quick Start:** See [README.md](../README.md)  
> **AWS Setup:** See [aws.md](aws.md)  
> **Azure Setup:** See [azure.md](azure.md)

---

## Overview

CleanCloud is designed for CI/CD integration with:
- **Predictable exit codes** - Control pipeline behavior based on findings
- **Machine-readable output** - JSON/CSV for parsing and storage
- **Read-only operations** - Safe to run in any environment
- **Fast execution** - Scans complete in seconds to minutes

---

## Exit Codes

CleanCloud uses standard Unix exit codes for CI control:

| Exit Code | Meaning | CI Behavior |
|-----------|---------|-------------|
| `0` | Success - no policy violations | Pipeline continues |
| `1` | Configuration error or unexpected failure | Pipeline fails |
| `2` | Policy violation - findings detected | Pipeline fails (when enforcement enabled) |
| `3` | Missing credentials or insufficient permissions | Pipeline fails |

---

## Policy Enforcement

### Informational Mode (Default)

```bash
cleancloud scan --provider aws --region us-east-1
# Always exits 0, even if findings exist
```

Use this for:
- Development environments
- Initial setup and testing
- Generating reports without blocking

### Enforcement Modes

**Fail on any findings:**
```bash
cleancloud scan --provider aws --region us-east-1 --fail-on-findings
# Exits 2 if any findings exist
```

**Fail on confidence threshold (Recommended):**
```bash
# Only fail on HIGH confidence findings
cleancloud scan --provider aws --region us-east-1 --fail-on-confidence HIGH

# Fail on MEDIUM or higher
cleancloud scan --provider aws --region us-east-1 --fail-on-confidence MEDIUM
```

**Recommendation:** Use `--fail-on-confidence HIGH` for most pipelines.

---

## GitHub Actions

### AWS with OIDC (Recommended)

```yaml
name: CleanCloud Hygiene Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 8 * * 1'  # Weekly on Monday at 8 AM

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
          role-to-assume: arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
          aws-region: us-east-1

      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Validate credentials
        run: cleancloud doctor --provider aws

      - name: Run hygiene scan
        run: |
          cleancloud scan \
            --provider aws \
            --all-regions \
            --output json \
            --output-file scan-results.json \
            --fail-on-confidence HIGH

      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cleancloud-scan-results
          path: scan-results.json
          retention-days: 30
```

### Azure with OIDC (Recommended)

```yaml
name: CleanCloud Hygiene Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 8 * * 1'

permissions:
  id-token: write
  contents: read

jobs:
  cleancloud:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Validate credentials
        run: cleancloud doctor --provider azure

      - name: Run hygiene scan
        run: |
          cleancloud scan \
            --provider azure \
            --output json \
            --output-file scan-results.json \
            --fail-on-confidence HIGH

      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cleancloud-scan-results
          path: scan-results.json
          retention-days: 30
```

### Multi-Cloud Scan

```yaml
name: CleanCloud Multi-Cloud Scan

on:
  schedule:
    - cron: '0 8 * * 1'  # Weekly

permissions:
  id-token: write
  contents: read

jobs:
  scan-aws:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
          aws-region: us-east-1
      
      - name: Scan AWS
        run: |
          pip install cleancloud
          cleancloud scan \
            --provider aws \
            --all-regions \
            --output json \
            --output-file aws-results.json
      
      - uses: actions/upload-artifact@v4
        with:
          name: aws-scan-results
          path: aws-results.json

  scan-azure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Azure Login
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      
      - name: Scan Azure
        run: |
          pip install cleancloud
          cleancloud scan \
            --provider azure \
            --output json \
            --output-file azure-results.json
      
      - uses: actions/upload-artifact@v4
        with:
          name: azure-scan-results
          path: azure-results.json
```

---

## Output Formats

### JSON Output (Machine-Readable)

```bash
cleancloud scan \
  --provider aws \
  --region us-east-1 \
  --output json \
  --output-file results.json
```

**Schema:**
```json
{
  "summary": {
    "total_findings": 12,
    "by_risk": {"MEDIUM": 12},
    "by_confidence": {"HIGH": 8, "MEDIUM": 4},
    "regions_scanned": ["us-east-1"],
    "scanned_at": "2025-01-15T10:30:00Z"
  },
  "findings": [
    {
      "rule_id": "aws.ebs.volume.unattached",
      "resource_id": "vol-0abc123",
      "confidence": "HIGH",
      "risk": "MEDIUM",
      "region": "us-east-1",
      "details": {...}
    }
  ]
}
```

### CSV Output (Spreadsheet-Friendly)

```bash
cleancloud scan \
  --provider aws \
  --region us-east-1 \
  --output csv \
  --output-file results.csv
```

**Columns:**
- rule_id
- resource_id
- confidence
- risk
- region
- provider
- details (JSON string)

---

## Tag-Based Filtering

Exclude resources from scans using tags:

### Configuration File

Create `cleancloud.yaml`:

```yaml
version: 1

tag_filtering:
  enabled: true
  ignore:
    - key: env
      value: production
    - key: team
      value: platform
    - key: keep
```

Use in CI/CD:
```bash
cleancloud scan \
  --provider aws \
  --region us-east-1 \
  --config cleancloud.yaml
```

### Command Line Override

```bash
cleancloud scan \
  --provider aws \
  --region us-east-1 \
  --ignore-tag env:production \
  --ignore-tag team:platform
```

**Note:** CLI tags replace config file tags (not merged).

---

## Common CI/CD Patterns

### Pattern 1: Development - Informational Only

```yaml
- name: Scan development account
  run: |
    cleancloud scan --provider aws --region us-east-1
    # Exits 0 even with findings
```

### Pattern 2: Staging - Warn on HIGH Confidence

```yaml
- name: Scan staging account
  run: |
    cleancloud scan \
      --provider aws \
      --all-regions \
      --fail-on-confidence HIGH
    # Fails pipeline if HIGH confidence findings exist
```

### Pattern 3: Production - Block Any Findings

```yaml
- name: Scan production account
  run: |
    cleancloud scan \
      --provider aws \
      --all-regions \
      --fail-on-findings
    # Fails pipeline if any findings exist
```

### Pattern 4: Scheduled Weekly Reports

```yaml
on:
  schedule:
    - cron: '0 8 * * 1'  # Monday 8 AM

jobs:
  weekly-scan:
    steps:
      - name: Run scan
        run: |
          cleancloud scan \
            --provider aws \
            --all-regions \
            --output json \
            --output-file weekly-report.json
      
      - name: Upload to S3
        run: |
          aws s3 cp weekly-report.json \
            s3://my-bucket/cleancloud/$(date +%Y-%m-%d).json
```

---

## Credentials & Secrets Management

### Best Practices

**✅ DO:**
- Use OIDC for CI/CD (no long-lived credentials)
- Use environment-specific secrets (dev, staging, prod)
- Store secrets in platform secret managers (GitHub Secrets, Azure Key Vault)
- Rotate credentials regularly
- Use least-privilege roles

**❌ DON'T:**
- Use repository-level secrets for production
- Hard-code credentials in workflows
- Share credentials across environments
- Use overly permissive roles

---

## Performance Optimization

### Single Region Scans (Fastest)

```bash
cleancloud scan --provider aws --region us-east-1
# 15-30 seconds
```

### Auto-Detected Active Regions (Balanced)

```bash
cleancloud scan --provider aws --all-regions
# 2-3 minutes (scans 3-5 active regions)
```

### All Enabled Regions (Comprehensive)

```bash
# This is not recommended - use --all-regions which auto-detects
cleancloud scan --provider aws --region us-east-1,us-west-2,eu-west-1,...
# 8-10 minutes (25+ regions)
```

**Recommendation:** Use `--all-regions` for comprehensive scans (auto-detects active regions only).

---

## Troubleshooting

### Pipeline Fails with Exit Code 3

**Issue:** Missing credentials or insufficient permissions

**Fix:**
```bash
# Validate setup
cleancloud doctor --provider aws
cleancloud doctor --provider azure
```

Check:
- Secrets are configured correctly
- IAM/RBAC roles have required permissions
- Trust policies allow your repo/branch

### Pipeline Fails with Exit Code 2

**Issue:** Policy violation - findings detected

**Expected behavior** when using `--fail-on-findings` or `--fail-on-confidence`.

**Fix:**
1. Review findings in artifacts
2. Clean up resources or adjust policy threshold
3. Use tag filtering to exclude known resources

### Scan Takes Too Long

**Issue:** Scanning all 25+ AWS regions

**Fix:**
```bash
# Use auto-detection instead
cleancloud scan --provider aws --all-regions
# Only scans regions with resources (3-5 typically)
```

---

## Azure DevOps Pipelines

Coming soon. For now, use Azure CLI task with manual commands:

```yaml
- task: AzureCLI@2
  inputs:
    azureSubscription: 'MyServiceConnection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      pip install cleancloud
      cleancloud scan --provider azure --output json --output-file results.json
```

---

**Next:** [AWS Setup →](aws.md) | [Azure Setup →](azure.md) | [Rules Reference →](rules.md)