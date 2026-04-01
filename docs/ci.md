# CI/CD Integration

Complete guide for integrating CleanCloud into continuous integration and deployment pipelines.

> **Quick Start:** See [README.md](../README.md)
> **AWS Setup:** See [aws.md](aws.md)
> **Azure Setup:** See [azure.md](azure.md)
> **GCP Setup:** See [gcp.md](gcp.md)

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

**GCP** — same structure with Workload Identity Federation:

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  cleancloud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ vars.GCP_SERVICE_ACCOUNT }}
      - run: pip install cleancloud
      - run: cleancloud scan --provider gcp --all-projects --fail-on-confidence HIGH
```

> First time? Run `cleancloud doctor --provider aws`, `cleancloud doctor --provider azure`, or `cleancloud doctor --provider gcp` to validate credentials before running a full scan.

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
    artifact-name: cleancloud-scan-results   # uploads output-file as a GitHub artifact automatically
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
    artifact-name: cleancloud-scan-results
```

### GCP (Workload Identity Federation)

```yaml
- uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
    service_account: ${{ secrets.GCP_SERVICE_ACCOUNT }}

- uses: cleancloud-io/scan-action@v1
  with:
    provider: gcp
    all-projects: 'true'
    fail-on-confidence: HIGH
    fail-on-cost: '100'
    output: json
    output-file: scan-results.json
    artifact-name: cleancloud-scan-results
```

### AWS Multi-Account (via action)

```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
    aws-region: us-east-1

- uses: cleancloud-io/scan-action@v1
  with:
    provider: aws
    multi-account: .cleancloud/accounts.yaml
    all-regions: 'true'
    concurrency: '5'
    fail-on-confidence: HIGH
    output: json
    output-file: scan-results.json
    artifact-name: multi-account-scan-results
```

### Full Inputs Reference

| Input | Description | AWS | Azure | GCP |
|---|---|:---:|:---:|:---:|
| `provider` | `aws`, `azure`, or `gcp` (required) | ✓ | ✓ | ✓ |
| `category` | `hygiene` (default), `ai` (SageMaker on AWS, AML Compute on Azure), or `all` | ✓ | ✓ | — |
| `region` | Single region filter (AWS) or location filter (Azure — filters results; all subscriptions always scanned) | ✓ | ✓ | — |
| `all-regions` | Scan all active AWS regions (AWS-only; Azure scans all subscriptions by default) | ✓ | — | — |
| `org` | Auto-discover all AWS Organization accounts | ✓ | — | — |
| `accounts` | Comma-separated account IDs | ✓ | — | — |
| `multi-account` | Path to accounts config YAML | ✓ | — | — |
| `role-name` | Cross-account role name (default: `CleanCloudReadOnlyRole`) | ✓ | — | — |
| `external-id` | External ID for cross-account role assumption | ✓ | — | — |
| `concurrency` | Parallel account scan limit | ✓ | — | ✓ |
| `timeout` | Total scan timeout in seconds | ✓ | — | ✓ |
| `per-account-regions` | Detect active regions per account (slower, more accurate) | ✓ | — | — |
| `subscription` | Comma-separated subscription IDs | — | ✓ | — |
| `management-group` | Management Group ID for subscription discovery | — | ✓ | — |
| `all-projects` | Scan all accessible GCP projects | — | — | ✓ |
| `project` | GCP project ID (repeatable) | — | — | ✓ |
| `fail-on-confidence` | Fail on `LOW`, `MEDIUM`, or `HIGH` confidence findings | ✓ | ✓ | ✓ |
| `fail-on-cost` | Fail if estimated waste exceeds this USD amount | ✓ | ✓ | ✓ |
| `fail-on-findings` | Fail on any finding | ✓ | ✓ | ✓ |
| `output` | `human`, `json`, `csv`, or `markdown` | ✓ | ✓ | ✓ |
| `output-file` | Path to write output (required for `json`/`csv`) | ✓ | ✓ | ✓ |
| `artifact-name` | Upload `output-file` as a GitHub artifact with this name | ✓ | ✓ | ✓ |
| `config` | Path to `cleancloud.yaml` config file | ✓ | ✓ | ✓ |
| `ignore-tag` | Comma-separated `key` or `key:value` tags to ignore | ✓ | ✓ | ✓ |
| `version` | CleanCloud version to install (default: latest) | ✓ | ✓ | ✓ |

> When `artifact-name` is set the action uploads `output-file` automatically — no separate `upload-artifact` step needed.

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

### GCP

GCP Application Default Credentials are resolved via a file-based mechanism. In GitHub Actions with Workload Identity Federation, `google-github-actions/auth@v2` exchanges the OIDC token and writes a short-lived credentials file to the runner filesystem, then sets `GOOGLE_APPLICATION_CREDENTIALS` to point to it. That file must be mounted into the container.

```yaml
jobs:
  cleancloud:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ secrets.GCP_SERVICE_ACCOUNT }}

      - name: Run CleanCloud
        run: |
          test -f "$GOOGLE_APPLICATION_CREDENTIALS" || exit 1
          echo "Using GCP credentials at: $GOOGLE_APPLICATION_CREDENTIALS"

          docker run --rm \
            -e GOOGLE_APPLICATION_CREDENTIALS=/gcp-creds.json \
            -v "$GOOGLE_APPLICATION_CREDENTIALS:/gcp-creds.json:ro" \
            getcleancloud/cleancloud scan \
              --provider gcp \
              --all-projects \
              --fail-on-confidence HIGH \
              --fail-on-cost 100
```

> The credentials file is short-lived and mounted read-only — no long-lived keys are exposed. The `test -f` guard catches a silent auth failure before Docker attempts the mount.

**Local development with gcloud ADC:**

`gcloud auth application-default login` writes credentials to your host filesystem. Docker can't see the host filesystem by default — mount the file explicitly:

```bash
docker run --rm \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/adc.json \
  -v ~/.config/gcloud/application_default_credentials.json:/tmp/adc.json:ro \
  getcleancloud/cleancloud scan --provider gcp --project YOUR_PROJECT_ID
```

### Pinning to a specific version

**Recommendation:** Pin to an exact version in production pipelines so a new CleanCloud release can't change scan behavior mid-sprint. Use `latest` in development where picking up new rules automatically is fine.

```yaml
# Pin to exact version — safest for production pipelines
getcleancloud/cleancloud:1.9.0

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

**Note:** Exit code `2` is only returned when an enforcement flag is set (`--fail-on-confidence`, `--fail-on-findings`, or `--fail-on-cost`). Without any enforcement flag, the scan always exits `0` regardless of findings.

**Note:** Invalid region names (AWS) or location names (Azure) trigger exit code `1` early in the scan, before attempting API calls.

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

### AWS AI/ML Scan (SageMaker)

Run SageMaker idle endpoint detection separately — requires the `security/aws/ai-readonly.json` policy attached to your IAM role.

```yaml
name: CleanCloud AI/ML Scan

on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Monday at 9 AM

permissions:
  id-token: write
  contents: read

jobs:
  cleancloud-ai:
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

      - name: Validate AI permissions
        run: cleancloud doctor --provider aws --category ai

      - name: Run AI/ML scan
        run: |
          cleancloud scan \
            --provider aws \
            --category ai \
            --all-regions \
            --output json \
            --output-file ai-scan-results.json \
            --fail-on-confidence HIGH

      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cleancloud-ai-scan-results
          path: ai-scan-results.json
          retention-days: 30
```

> To run hygiene and AI rules together, use `--category all`.

### Azure AI/ML Scan (AML Compute)

Run idle AML compute cluster detection separately — requires `security/azure/ai-readonly-role.json` assigned to your service principal in addition to Reader. See [azure.md](azure.md#custom-role-optional-least-privilege) for setup.

```yaml
name: CleanCloud Azure AI/ML Scan

on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Monday at 9 AM

permissions:
  id-token: write
  contents: read

jobs:
  cleancloud-ai:
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

      - name: Validate AI permissions
        run: cleancloud doctor --provider azure --category ai

      - name: Run AI/ML scan
        run: |
          cleancloud scan \
            --provider azure \
            --category ai \
            --output json \
            --output-file ai-scan-results.json \
            --fail-on-confidence HIGH

      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cleancloud-azure-ai-scan-results
          path: ai-scan-results.json
          retention-days: 30
```

> To run hygiene and AI rules together, use `--category all`.

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

### GCP with Workload Identity Federation (Recommended)

```yaml
name: CleanCloud GCP Scan

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

      - name: Authenticate to GCP (Workload Identity Federation)
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ secrets.GCP_SERVICE_ACCOUNT }}

      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Validate credentials
        run: cleancloud doctor --provider gcp --project ${{ vars.GCP_PROJECT_ID }}

      - name: Run hygiene scan
        run: |
          cleancloud scan \
            --provider gcp \
            --all-projects \
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

**GitHub secrets and variables required** (repo → Settings → Environments → your environment):

| Type | Name | Value |
|------|------|-------|
| Secret | `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions/providers/github` |
| Secret | `GCP_SERVICE_ACCOUNT` | `cleancloud-scanner@PROJECT_ID.iam.gserviceaccount.com` |
| Variable | `GCP_PROJECT_ID` | `your-gcp-project-id` |

> First time? Run `cleancloud doctor --provider gcp --project <PROJECT_ID>` locally to validate credentials before wiring up CI. See [GCP setup →](gcp.md) for the full Workload Identity Federation walkthrough.

---

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
    continue-on-error: true  # Each provider job runs to completion independently — a failure in one doesn't cancel the others
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
    continue-on-error: true
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

  scan-gcp:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4

      - name: Authenticate to GCP (Workload Identity Federation)
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ secrets.GCP_SERVICE_ACCOUNT }}

      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Scan GCP
        run: |
          cleancloud scan \
            --provider gcp \
            --all-projects \
            --output json \
            --output-file gcp-results.json \
            --fail-on-confidence HIGH

      - name: Upload GCP results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: gcp-scan-results
          path: gcp-results.json
          retention-days: 30
```

**Note:** `continue-on-error: true` on each provider job ensures all three scans run to completion even if one fails. Without it, a failing AWS scan would cancel the Azure and GCP jobs before they produce results.

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

The JSON output follows a versioned schema (see `schemas/output-v1.2.0.json`) and varies slightly between providers to accommodate their different organizational models (AWS regions vs Azure subscriptions).

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

### In GitHub Actions

Use `--config` to reference a `cleancloud.yaml` committed to your repo, or pass `--ignore-tag` flags directly in the run step:

```yaml
- name: Run hygiene scan (with tag exclusions)
  run: |
    cleancloud scan \
      --provider aws \
      --all-regions \
      --config cleancloud.yaml \
      --output json \
      --output-file scan-results.json \
      --fail-on-confidence HIGH
```

Or inline with the GitHub Action input:

```yaml
- uses: cleancloud-io/scan-action@v1
  with:
    provider: aws
    all-regions: 'true'
    config: cleancloud.yaml
    fail-on-confidence: HIGH
    output: json
    output-file: scan-results.json
```

> See [cleancloud.yaml examples](../README.md#configuration) for a full config reference.

---

## Multi-Account Scanning

Scan entire AWS Organizations in a single workflow run. CleanCloud assumes a cross-account role in each account in parallel and produces an aggregated report.

**Prerequisites:** Cross-account `CleanCloudReadOnlyRole` deployed to each target account. See [AWS multi-account setup →](aws.md#multi-account-scanning)

### From .cleancloud/accounts.yaml

Commit your account list to your repository at `.cleancloud/accounts.yaml`. `actions/checkout@v4` makes it available to the runner automatically — no extra steps needed.

```yaml
# .cleancloud/accounts.yaml — commit this file to your repo
role_name: CleanCloudReadOnlyRole
accounts:
  - id: "111111111111"
    name: production
  - id: "222222222222"
    name: staging
```

> You can use a different path — just pass it to `--multi-account /your/path/accounts.yaml`. `.cleancloud/accounts.yaml` is the recommended convention.

```yaml
name: CleanCloud Multi-Account Scan

on:
  schedule:
    - cron: '0 8 * * 1'  # Weekly on Monday
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  cleancloud:
    runs-on: ubuntu-latest
    steps:
      # Checks out your repo — makes .cleancloud/accounts.yaml available to the runner
      - uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/CleanCloudCIReadOnly
          aws-region: us-east-1

      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Scan all accounts
        run: |
          cleancloud scan \
            --provider aws \
            --multi-account .cleancloud/accounts.yaml \
            --all-regions \
            --concurrency 5 \
            --fail-on-confidence HIGH \
            --fail-on-cost 500 \
            --output json \
            --output-file scan-results.json

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: multi-account-scan-results
          path: scan-results.json
```

### Auto-discover via AWS Organizations

No file needed — CleanCloud calls `organizations:ListAccounts` on the hub account and discovers all member accounts automatically.

```yaml
      - name: Scan all org accounts
        run: |
          cleancloud scan \
            --provider aws \
            --org \
            --all-regions \
            --concurrency 5 \
            --timeout 7200 \
            --fail-on-confidence HIGH \
            --output json \
            --output-file scan-results.json
```

> Requires `organizations:ListAccounts` on the hub account role — one extra permission, hub only. See [AWS setup →](aws.md#multi-account-scanning)

**`--per-account-regions`** — by default CleanCloud detects active regions once on the hub account and applies them to all spoke accounts (fast). Add `--per-account-regions` to detect active regions independently in each account — slower but more accurate when accounts use different region footprints.

---

## Azure Multi-Subscription Scanning

Assign Reader at the Management Group level — CleanCloud discovers all subscriptions underneath automatically. No cross-subscription role setup required.

### All accessible subscriptions

```yaml
name: CleanCloud Azure Multi-Subscription Scan

on:
  schedule:
    - cron: '0 8 * * 1'  # Weekly on Monday
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  cleancloud:
    runs-on: ubuntu-latest
    steps:
      - name: Azure Login via OIDC
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Scan all subscriptions
        run: |
          cleancloud scan \
            --provider azure \
            --fail-on-confidence HIGH \
            --fail-on-cost 500 \
            --output json \
            --output-file scan-results.json

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: azure-multi-subscription-results
          path: scan-results.json
          retention-days: 30
```

> The service principal must have Reader role on all target subscriptions (or at Management Group level). See [Azure setup →](azure.md#multi-subscription-scanning)

### Auto-discover via Management Group

```yaml
      - name: Scan all subscriptions in Management Group
        run: |
          cleancloud scan \
            --provider azure \
            --management-group ${{ vars.AZURE_MANAGEMENT_GROUP_ID }} \
            --fail-on-confidence HIGH \
            --output json \
            --output-file scan-results.json
```

> Requires `Microsoft.Management/managementGroups/read` on the Management Group in addition to Reader on subscriptions.

---

### GitHub Action (one-liner)

```yaml
      - uses: cleancloud-io/scan-action@v1
        with:
          provider: aws
          all-regions: 'true'
          fail-on-confidence: HIGH
          fail-on-cost: '500'
          output: json
          output-file: scan-results.json
```

> The GitHub Action uses the runner's ambient AWS credentials — configure via `aws-actions/configure-aws-credentials` before this step. For multi-account scanning with the action, set up the hub account OIDC role and use `--multi-account` via the CLI directly.

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
cleancloud doctor --provider gcp --project <PROJECT_ID>
```

Check:
- Secrets are configured correctly in your CI platform
- IAM/RBAC roles have required permissions (ReadOnly access)
- Trust policies allow your repo/branch to assume roles
- For AWS: OIDC role trust relationship is configured
- For Azure: Federated credentials are configured
- For GCP: Workload Identity Pool, OIDC provider, and service account binding are all configured (see [GCP setup →](gcp.md))

### Pipeline Fails with Exit Code 2

**Issue:** Policy violation - findings detected, or rules skipped due to missing permissions

**This is expected behavior** when using `--fail-on-findings`, `--fail-on-confidence`, or `--fail-on-cost`.

**Options for findings violations:**
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

**Next:** [AWS Setup →](aws.md) | [Azure Setup →](azure.md) | [GCP Setup →](gcp.md) | [Rules Reference →](rules.md)