# CI/CD Integration

Complete guide for integrating CleanCloud into continuous integration and deployment pipelines.

> **Quick Start:** See [README.md](../README.md)  
> **AWS Setup:** See [aws.md](aws.md)  
> **Azure Setup:** See [azure.md](azure.md)

---

## Quick CI Setup

The fastest path to a working pipeline:

**AWS** — add this job to your workflow:

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  cleancloud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
          aws-region: us-east-1
      - run: pip install cleancloud
      - run: cleancloud scan --provider aws --all-regions --fail-on-confidence HIGH
```

**Azure** — same structure, different auth:

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  cleancloud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - run: pip install cleancloud
      - run: cleancloud scan --provider azure --fail-on-confidence HIGH
```

> First time? Run `cleancloud doctor --provider aws` or `cleancloud doctor --provider azure` to validate credentials before running a full scan.

For OIDC setup, enforcement options, output formats, and advanced patterns — read on.

---

## Using the GitHub Action

The simplest way to add CleanCloud to GitHub Actions — one step, no pip install needed.

### AWS (OIDC)

```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
    aws-region: us-east-1

- uses: cleancloud-io/scan-action@v1
  with:
    provider: aws
    all-regions: 'true'
    fail-on-confidence: HIGH
    fail-on-cost: '100'
    output: json
    output-file: scan-results.json
```

### Azure (Workload Identity)

```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

- uses: cleancloud-io/scan-action@v1
  with:
    provider: azure
    fail-on-confidence: HIGH
    fail-on-cost: '100'
    output: json
    output-file: scan-results.json
```

Full input reference and options: [cleancloud-io/scan-action →](https://github.com/marketplace/actions/cleancloud-scan)

---

## Using the Docker Image

No Python setup required — pull and run. Useful for pipelines where you don't control the runner environment or want to pin to an exact CleanCloud version.

### AWS

```yaml
jobs:
  cleancloud:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
          aws-region: us-east-1

      - name: Run CleanCloud
        run: |
          docker run --rm \
            -e AWS_ACCESS_KEY_ID \
            -e AWS_SECRET_ACCESS_KEY \
            -e AWS_SESSION_TOKEN \
            -e AWS_REGION \
            getcleancloud/cleancloud scan \
              --provider aws \
              --all-regions \
              --fail-on-confidence HIGH \
              --fail-on-cost 100
```

> `configure-aws-credentials` sets `AWS_*` env vars on the runner. Passing them with `-e VAR_NAME` (no value) forwards them into the container automatically.

### Azure

```yaml
jobs:
  cleancloud:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Run CleanCloud
        run: |
          docker run --rm \
            -e AZURE_CLIENT_ID \
            -e AZURE_TENANT_ID \
            -e AZURE_SUBSCRIPTION_ID \
            -e AZURE_FEDERATED_TOKEN_FILE \
            -v "${AZURE_FEDERATED_TOKEN_FILE}:${AZURE_FEDERATED_TOKEN_FILE}:ro" \
            getcleancloud/cleancloud scan \
              --provider azure \
              --fail-on-confidence HIGH \
              --fail-on-cost 100
```

> Azure Workload Identity writes an OIDC token to a temp file on the runner. The `-v` mount makes that file accessible inside the container.

### Pinning to a specific version

```yaml
# Pin to exact version — safest for production pipelines
getcleancloud/cleancloud:1.7.2

# Pin to minor — gets patch fixes automatically
getcleancloud/cleancloud:1.7

# Always latest — simplest, least predictable
getcleancloud/cleancloud:latest
```

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
| `1` | Configuration error, invalid region/location, or unexpected failure | Pipeline fails |
| `2` | Policy violation - findings detected | Pipeline fails (when enforcement enabled) |
| `3` | Missing credentials or insufficient permissions | Pipeline fails |

**Note:** Invalid region names (AWS) or location names (Azure) now trigger exit code `1` early in the scan, before attempting API calls.

---

## Region and Location Naming

CleanCloud validates region/location names based on the provider:

### AWS Regions

AWS uses region names like:
- `us-east-1`, `us-west-2` (United States)
- `eu-west-1`, `eu-central-1` (Europe)
- `ap-southeast-1`, `ap-northeast-1` (Asia Pacific)

```bash
# AWS example
cleancloud scan --provider aws --region us-east-1
```

### Azure Locations

Azure uses location names like:
- `eastus`, `westus2` (United States)
- `northeurope`, `westeurope` (Europe)
- `southeastasia`, `japaneast` (Asia Pacific)

```bash
# Azure example
cleancloud scan --provider azure --region eastus
```

**Important:** Don't mix AWS and Azure naming! Using `us-east-1` with Azure will trigger an error.

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

**Fail on cost threshold:**
```bash
# Fail if estimated monthly waste exceeds $100
cleancloud scan --provider aws --region us-east-1 --fail-on-cost 100

# Combine with confidence threshold
cleancloud scan --provider aws --region us-east-1 --fail-on-confidence HIGH --fail-on-cost 50
```

**Recommendation:** Use `--fail-on-confidence HIGH` for most pipelines. Add `--fail-on-cost` to set a waste budget.

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
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
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
        run: |
          # Azure doctor validates credentials and subscription access
          # Note: --region parameter is not applicable for Azure
          cleancloud doctor --provider azure

      - name: Run hygiene scan
        run: |
          cleancloud scan \
            --provider azure \
            --output json \
            --output-file scan-results.json \
            --fail-on-confidence HIGH
          # Note: Scans all accessible subscriptions by default
          # Use --subscription <id> to scan specific subscription(s)
          # Use --region <location> to filter by Azure location (e.g., eastus, westeurope)

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
    continue-on-error: true  # Don't fail entire workflow if one provider fails
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
          aws-region: us-east-1

      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Scan AWS
        run: |
          cleancloud scan \
            --provider aws \
            --all-regions \
            --output json \
            --output-file aws-results.json \
            --fail-on-confidence HIGH

      - name: Upload AWS results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: aws-scan-results
          path: aws-results.json
          retention-days: 30

  scan-azure:
    runs-on: ubuntu-latest
    continue-on-error: true  # Don't fail entire workflow if one provider fails
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Scan Azure
        run: |
          cleancloud scan \
            --provider azure \
            --output json \
            --output-file azure-results.json \
            --fail-on-confidence HIGH

      - name: Upload Azure results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: azure-scan-results
          path: azure-results.json
          retention-days: 30
```

**Note:** Using `continue-on-error: true` allows the workflow to complete even if one cloud provider scan fails, ensuring you get results from all providers.

---

## Output Formats

### JSON Output (Machine-Readable, Complete Data)

```bash
cleancloud scan \
  --provider aws \
  --region us-east-1 \
  --output json \
  --output-file results.json
```

**JSON is the recommended format for programmatic processing** as it contains complete data including evidence and detailed metadata.

The JSON output follows a versioned schema (see `schemas/output-v1.0.0.json`) and varies slightly between providers to accommodate their different organizational models (AWS regions vs Azure subscriptions).

**AWS Schema Example:**
```json
{
  "schema_version": "1.0.0",
  "summary": {
    "total_findings": 12,
    "by_risk": {"medium": 12},
    "by_confidence": {"high": 8, "medium": 4},
    "minimum_estimated_monthly_waste_usd": 482.40,
    "findings_with_cost_estimate": 10,
    "regions_scanned": ["us-east-1", "us-west-2"],
    "region_selection_mode": "all-regions",
    "provider": "aws",
    "scanned_at": "2025-01-15T10:30:00Z"
  },
  "findings": [
    {
      "provider": "aws",
      "rule_id": "aws.ebs.unattached",
      "resource_type": "aws.ebs.volume",
      "resource_id": "vol-0abc123",
      "region": "us-east-1",
      "title": "Unattached EBS volume",
      "summary": "EBS volume has been unattached for 90+ days",
      "reason": "Volume has been in 'available' state for 90+ days",
      "confidence": "high",
      "risk": "medium",
      "detected_at": "2025-01-15T10:30:00Z",
      "details": {
        "size_gb": 100,
        "availability_zone": "us-east-1a"
      },
      "evidence": {
        "signals_used": ["Volume state is 'available'", "Volume age is 90+ days"],
        "signals_not_checked": ["Application-level usage", "IaC-managed intent"],
        "time_window": "90 days"
      }
    }
  ]
}
```

**Azure Schema Example:**
```json
{
  "schema_version": "1.0.0",
  "summary": {
    "total_findings": 5,
    "by_risk": {"low": 5},
    "by_confidence": {"medium": 5},
    "minimum_estimated_monthly_waste_usd": 64.00,
    "findings_with_cost_estimate": 4,
    "regions_scanned": ["eastus", "westus2"],
    "subscriptions_scanned": ["29d91ee0-922f-483a-a81f-1a5eff4ecfa2"],
    "subscription_selection_mode": "all",
    "provider": "azure",
    "scanned_at": "2025-01-15T10:30:00Z"
  },
  "findings": [
    {
      "provider": "azure",
      "rule_id": "azure.disk.unattached",
      "resource_type": "azure.compute.disk",
      "resource_id": "/subscriptions/.../disks/disk1",
      "region": "eastus",
      "title": "Unattached managed disk",
      "summary": "Disk has been unattached for 30+ days",
      "reason": "Disk state is 'Unattached' for 30+ days",
      "confidence": "medium",
      "risk": "low",
      "detected_at": "2025-01-15T10:30:00Z",
      "details": {
        "size_gb": 128,
        "sku": "Premium_LRS"
      },
      "evidence": {
        "signals_used": ["Disk state is 'Unattached'", "Disk age is 30+ days"],
        "signals_not_checked": ["Application-level usage", "IaC-managed intent"],
        "time_window": "30 days"
      }
    }
  ]
}
```

**Important Notes:**
- **Azure uses `subscription_selection_mode`** (not `region_selection_mode` like AWS) - values are "all" or "explicit"
- `regions_scanned` lists unique Azure locations from all findings across scanned subscriptions
- `subscriptions_scanned` lists the Azure subscription IDs that were scanned
- Individual findings contain the Azure location in the `region` field (e.g., "eastus", "westeurope")
- The `--region` parameter for Azure is a **filter** (filters findings by location), not a selection mode

### Markdown Output (Shareable Reports)

```bash
cleancloud scan \
  --provider aws \
  --all-regions \
  --output markdown

# Save to file
cleancloud scan \
  --provider aws \
  --all-regions \
  --output markdown \
  --output-file results.md
```

**Markdown is designed for human sharing** — paste directly into GitHub PR comments, Slack, or issues. Without `--output-file`, it prints to stdout.

---

### CSV Output (Simplified, Spreadsheet-Friendly)

```bash
cleancloud scan \
  --provider aws \
  --region us-east-1 \
  --output csv \
  --output-file results.csv
```

**CSV is a simplified format optimized for spreadsheet review.** It contains core fields for filtering and triaging, but omits nested data like `details` and `evidence`. For complete data including diagnostic information, use JSON output.

**CSV Columns (in order):**
1. `provider` - Cloud provider (aws, azure)
2. `rule_id` - Detection rule identifier
3. `resource_type` - Type of resource
4. `resource_id` - Resource identifier
5. `region` - Cloud region (or null for global resources)
6. `title` - Human-readable finding title
7. `summary` - One-line summary
8. `reason` - Why the resource was flagged
9. `risk` - Risk level (low, medium, high)
10. `confidence` - Confidence level (low, medium, high)
11. `detected_at` - ISO 8601 timestamp

**Fields NOT included in CSV:**
- `details` - Provider-specific metadata (e.g., size_gb, availability_zone)
- `evidence` - Signal analysis (signals_used, signals_not_checked, time_window)

**Use JSON output if you need:** Full diagnostic data, evidence signals, or programmatic processing.

---

## Tag-Based Filtering

Exclude resources from scans using tags:

### Configuration File

Create `cleancloud.yaml` in your repository root (or specify path with `--config`):

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
# With config file in repository root
cleancloud scan \
  --provider aws \
  --region us-east-1 \
  --config cleancloud.yaml

# Or specify full path
cleancloud scan \
  --provider aws \
  --region us-east-1 \
  --config /path/to/cleancloud.yaml
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
    # Exits 0 even with findings - useful for visibility without blocking
```

**Use case:** Early development, learning what issues exist without blocking deployments.

### Pattern 2: Staging - Fail on HIGH Confidence Only

```yaml
- name: Scan staging account
  run: |
    cleancloud scan \
      --provider aws \
      --all-regions \
      --fail-on-confidence HIGH \
      --output json \
      --output-file scan-results.json
    # Fails pipeline only if HIGH confidence findings exist
```

**Use case:** Pre-production validation with balanced enforcement.

### Pattern 3: Production - Block Any Findings

```yaml
- name: Scan production account
  run: |
    cleancloud scan \
      --provider aws \
      --all-regions \
      --fail-on-findings \
      --output json \
      --output-file scan-results.json
    # Fails pipeline if any findings exist (strictest mode)
```

**Use case:** Production accounts with zero-tolerance hygiene policy.

### Pattern 4: Azure Multi-Subscription Scan

```yaml
- name: Scan Azure subscriptions
  run: |
    # Scan all accessible subscriptions
    cleancloud scan \
      --provider azure \
      --fail-on-confidence HIGH \
      --output json \
      --output-file azure-scan.json

    # Or scan specific subscriptions
    cleancloud scan \
      --provider azure \
      --subscription sub-id-1 \
      --subscription sub-id-2 \
      --fail-on-confidence HIGH
```

**Use case:** Managing multiple Azure subscriptions with consistent hygiene standards.

### Pattern 5: Scheduled Weekly Reports

```yaml
on:
  schedule:
    - cron: '0 8 * * 1'  # Monday 8 AM

jobs:
  weekly-scan:
    steps:
      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Run comprehensive scan
        run: |
          cleancloud scan \
            --provider aws \
            --all-regions \
            --output json \
            --output-file weekly-report-$(date +%Y-%m-%d).json

      - name: Upload to S3
        run: |
          aws s3 cp weekly-report-*.json \
            s3://my-compliance-bucket/cleancloud/

      - name: Upload as artifact
        uses: actions/upload-artifact@v4
        with:
          name: weekly-scan-report
          path: weekly-report-*.json
          retention-days: 90
```

**Use case:** Regular compliance reporting and trend analysis.

---

## Credentials & Secrets Management

### Best Practices

**DO:**
- Use OIDC for CI/CD (no long-lived credentials)
- Use environment-specific secrets (dev, staging, prod)
- Store secrets in platform secret managers (GitHub Secrets, Azure Key Vault)
- Rotate credentials regularly
- Use least-privilege roles

**DON'T:**
- Use repository-level secrets for production
- Hard-code credentials in workflows
- Share credentials across environments
- Use overly permissive roles

---

## Performance Optimization

### Single Region Scans (Fastest)

```bash
# AWS - specify single region
cleancloud scan --provider aws --region us-east-1

# Azure - filter by single location
cleancloud scan --provider azure --region eastus
```

**Use case:** Quick targeted scans or region-specific validation.

### Auto-Detected Active Regions (Recommended)

```bash
# AWS - scans only regions with active resources
cleancloud scan --provider aws --all-regions

# Azure - scans all accessible subscriptions (default)
cleancloud scan --provider azure
```

**Use case:** Comprehensive scans without wasting time on empty regions. AWS auto-detects 3-5 active regions typically.

### Multi-Region AWS Scans

```bash
# INCORRECT - comma-separated regions not supported
cleancloud scan --provider aws --region us-east-1,us-west-2

# CORRECT - use --all-regions for multiple regions
cleancloud scan --provider aws --all-regions
```

**Note:** To scan specific multiple regions, you must run separate scans per region. Use `--all-regions` for the best balance of coverage and performance.

### Azure Subscription Filtering

```bash
# Scan all subscriptions (default — omit --subscription)
cleancloud scan --provider azure

# Scan specific subscription
cleancloud scan --provider azure --subscription <subscription-id>
```

---

## Troubleshooting

### Pipeline Fails with Exit Code 1 (Invalid Region)

**Issue:** Invalid region or location name

**Error examples:**
```
Error: 'us-east-1' is not a valid Azure location
Error: 'eastus' is not a valid AWS region
```

**Fix:**
- **AWS:** Use region names like `us-east-1`, `eu-west-1`, `ap-southeast-1`
- **Azure:** Use location names like `eastus`, `westeurope`, `southeastasia`

See the [Region and Location Naming](#region-and-location-naming) section for complete lists.

### Pipeline Fails with Exit Code 3

**Issue:** Missing credentials or insufficient permissions

**Fix:**
```bash
# Validate setup first
cleancloud doctor --provider aws
cleancloud doctor --provider azure
```

Check:
- Secrets are configured correctly in your CI platform
- IAM/RBAC roles have required permissions (ReadOnly access)
- Trust policies allow your repo/branch to assume roles
- For AWS: OIDC role trust relationship is configured
- For Azure: Federated credentials are configured

### Pipeline Fails with Exit Code 2

**Issue:** Policy violation - findings detected

**This is expected behavior** when using `--fail-on-findings`, `--fail-on-confidence`, or `--fail-on-cost`.

**Options:**
1. Review findings in uploaded artifacts
2. Clean up flagged resources
3. Adjust policy threshold (e.g., `--fail-on-confidence HIGH` instead of `MEDIUM`)
4. Use tag filtering to exclude known/acceptable resources

### Scan Takes Too Long

**Issue:** Scanning too many regions or subscriptions

**Fix for AWS:**
```bash
# Use auto-detection instead of scanning all regions
cleancloud scan --provider aws --all-regions
# Only scans regions with active resources (typically 3-5 regions)
```

**Fix for Azure:**
```bash
# Scan specific subscription instead of all
cleancloud scan --provider azure --subscription <subscription-id>
```

### Azure Doctor Shows Region Warning

**Issue:** Seeing "Warning: --region parameter is not applicable for Azure"

**Explanation:** The `--region` parameter is AWS-specific for the doctor command. Azure doctor validates subscription access, which is not region-specific.

**Fix:** Remove `--region` when running Azure doctor:
```bash
# Correct
cleancloud doctor --provider azure

# Incorrect
cleancloud doctor --provider azure --region eastus
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