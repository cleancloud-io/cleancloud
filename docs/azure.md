# Azure Setup

Azure authentication, RBAC permissions, and configuration guide.

> **Quick Start:** See [README.md](../README.md)  
> **Rules Reference:** See [rules.md](rules.md)  
> **CI/CD Integration:** See [ci.md](ci.md)

---

## Authentication Methods

CleanCloud supports multiple Azure authentication methods:

### 1. Azure OIDC with Workload Identity (Recommended for CI/CD)

**Microsoft Entra ID Workload Identity Federation - No client secrets, temporary tokens only.**

#### Setup Steps

**Step 1: Create App Registration**
```bash
az ad app create --display-name "CleanCloudScanner"
# Note the Application (client) ID
```

**Step 2: Create Service Principal**
```bash
az ad sp create --id <APP_ID>
```

**Step 3: Configure Federated Identity Credential**
```bash
az ad app federated-credential create \
  --id <APP_ID> \
  --parameters '{
    "name": "CleanCloudGitHub",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<YOUR_ORG>/<YOUR_REPO>:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

Replace `<YOUR_ORG>/<YOUR_REPO>` with your GitHub organization and repository.

**Step 4: Assign Reader Role**
```bash
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

#### GitHub Actions Workflow

```yaml
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
      
      - name: Run CleanCloud
        run: |
          pip install cleancloud
          cleancloud scan --provider azure
```

**Required GitHub Secrets:**
- `AZURE_CLIENT_ID` - App registration application ID
- `AZURE_TENANT_ID` - Azure tenant ID
- `AZURE_SUBSCRIPTION_ID` - Subscription to scan

**No secret needed:** `AZURE_CLIENT_SECRET`

---

### 2. Service Principal with Environment Variables (Local Development)

**Quick setup for local testing and evaluation.**

**Step 1: Create Service Principal**
```bash
az ad sp create-for-rbac --name "CleanCloudLocal" --role "Reader" \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

This outputs:
```json
{
  "appId": "12345678-1234-1234-1234-123456789abc",
  "displayName": "CleanCloudLocal",
  "password": "your-client-secret",
  "tenant": "87654321-4321-4321-4321-987654321dcb"
}
```

**Step 2: Set Environment Variables**
```bash
export AZURE_CLIENT_ID="12345678-1234-1234-1234-123456789abc"
export AZURE_TENANT_ID="87654321-4321-4321-4321-987654321dcb"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_SUBSCRIPTION_ID="<SUBSCRIPTION_ID>"

cleancloud scan --provider azure
```

**Not recommended for CI/CD** - Use OIDC (Method 1) instead to avoid storing secrets.

---

### 3. Azure CLI (Local Development)

**Recommended for interactive local development.**

```bash
# Login
az login

# Scan all accessible subscriptions (default)
cleancloud scan --provider azure

# Scan specific subscription
cleancloud scan --provider azure --subscription <SUBSCRIPTION_ID>

# Scan multiple subscriptions
cleancloud scan --provider azure \
  --subscription <SUBSCRIPTION_ID_1> \
  --subscription <SUBSCRIPTION_ID_2>
```

CleanCloud automatically uses your active Azure CLI session.

---

## RBAC Permissions

### Reader Role (Recommended)

Built-in **Reader** role provides all required permissions:

```bash
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

**What Reader allows:**
- `Microsoft.Compute/disks/read`
- `Microsoft.Compute/snapshots/read`
- `Microsoft.Network/publicIPAddresses/read`
- `Microsoft.Web/serverfarms/read`
- `Microsoft.Network/loadBalancers/read`
- `Microsoft.Network/applicationGateways/read`
- `Microsoft.Network/virtualNetworkGateways/read`
- `Microsoft.Network/connections/read`
- `Microsoft.Resources/subscriptions/read`

**What Reader does NOT allow:**
- Delete operations (`*/delete`)
- Modification operations (`*/write`)
- Tagging operations (`Microsoft.Resources/tags/*`)
- Billing data access (`Microsoft.CostManagement/*`)

### Custom Role (Optional Least-Privilege)

```json
{
  "Name": "CleanCloud Scanner",
  "Description": "Minimal read-only access for CleanCloud",
  "Actions": [
    "Microsoft.Compute/disks/read",
    "Microsoft.Compute/snapshots/read",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Web/serverfarms/read",
    "Microsoft.Network/loadBalancers/read",
    "Microsoft.Network/applicationGateways/read",
    "Microsoft.Network/virtualNetworkGateways/read",
    "Microsoft.Network/connections/read",
    "Microsoft.Resources/subscriptions/read"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/<SUBSCRIPTION_ID>"
  ]
}
```

Create and assign:
```bash
az role definition create --role-definition cleancloud-role.json

az role assignment create \
  --assignee <APP_ID> \
  --role "CleanCloud Scanner" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

---

## Subscription Scanning

### Single Subscription (Default)

```bash
# Specify via environment
export AZURE_SUBSCRIPTION_ID="12345678-1234-1234-1234-123456789abc"
cleancloud scan --provider azure
```

### All Accessible Subscriptions

```bash
# Remove AZURE_SUBSCRIPTION_ID environment variable
unset AZURE_SUBSCRIPTION_ID
cleancloud scan --provider azure

# Scans all subscriptions the service principal can access
```

### Subscription Filtering

By default, CleanCloud scans **all accessible subscriptions**. You can filter to specific subscriptions:

```bash
# Default: Scan all accessible subscriptions
cleancloud scan --provider azure

# Scan specific subscription
cleancloud scan --provider azure --subscription <SUBSCRIPTION_ID>

# Scan multiple subscriptions
cleancloud scan --provider azure \
  --subscription <SUB_1> \
  --subscription <SUB_2>
```

**When to use subscription filtering:**
- **Enterprise scale**: Organizations with 50+ subscriptions
- **Team ownership**: Scan only your team's subscriptions
- **CI/CD pipelines**: Different pipelines for different subscriptions
- **Testing**: Test on dev subscriptions before production
- **Performance**: Faster scans targeting specific subscriptions

**Subscription Validation:**
CleanCloud validates that specified subscriptions are accessible:
```bash
cleancloud scan --provider azure --subscription invalid-sub-id
# Warning: 1 subscription(s) not accessible:
#   - invalid-sub-id
#
# Error: None of the specified subscriptions are accessible
```

### Region Filtering

```bash
# Scan only East US resources
cleancloud scan --provider azure --region eastus

# Scan only West Europe resources
cleancloud scan --provider azure --region westeurope
```

**Note:** Region is an optional filter on results (not required like AWS).

---

## Validate Setup

Use the `doctor` command to verify credentials and permissions:

```bash
cleancloud doctor --provider azure
```

**What it checks:**
- Azure credentials are valid
- Authentication method (OIDC, Service Principal, Azure CLI, Managed Identity)
- Security grade (EXCELLENT/GOOD/ACCEPTABLE/POOR)
- CI/CD readiness and compliance compatibility
- Token acquisition and expiry
- Accessible subscriptions and subscription filtering
- Required RBAC permissions (Reader role)

**Example output:**
```
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

Step 2: Credential Acquisition
----------------------------------------------------------------------
[OK] Azure credentials acquired successfully
  Token expires in: ~58 minutes

Step 3: Subscription Access Validation
----------------------------------------------------------------------
[OK] Accessible subscriptions: 2
  • Production (a1b2c3d4-e5f6-7890-abcd-ef1234567890)
  • Staging (f9e8d7c6-b5a4-3210-fedc-ba0987654321)

Step 4: Permission Validation
----------------------------------------------------------------------
[OK] Subscription read access confirmed
  Reader role provides all required permissions:
    - Microsoft.Compute/disks/read
    - Microsoft.Compute/snapshots/read
    - Microsoft.Network/publicIPAddresses/read
    - Microsoft.Web/serverfarms/read
    - Microsoft.Network/loadBalancers/read
    - Microsoft.Network/applicationGateways/read
    - Microsoft.Network/virtualNetworkGateways/read
    - Microsoft.Network/connections/read

======================================================================
VALIDATION SUMMARY
======================================================================
Authentication: OIDC (Workload Identity Federation)
Security Grade: EXCELLENT
Subscriptions: 2 accessible

[OK] AZURE ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

---

## Output Formats

```bash
# Human-readable (default)
cleancloud scan --provider azure

# JSON (machine-readable, includes evidence and full metadata)
cleancloud scan --provider azure --output json --output-file results.json

# CSV (spreadsheet-friendly, 11 core columns)
cleancloud scan --provider azure --output csv --output-file results.csv
```

**JSON schema, examples, and CSV column reference:** See [`ci.md`](ci.md#output-formats)

---

## Troubleshooting

### "Missing Azure environment variables"

**For OIDC (GitHub Actions):**
```yaml
# Ensure these secrets are set:
secrets:
  AZURE_CLIENT_ID
  AZURE_TENANT_ID
  AZURE_SUBSCRIPTION_ID
```

**For Service Principal (local with env vars):**
```bash
# Ensure all four variables are set:
export AZURE_CLIENT_ID="..."
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_SECRET="..."
export AZURE_SUBSCRIPTION_ID="..."
```

**For Azure CLI:**
```bash
# Verify you're logged in
az account show
```

### "Azure authentication failed"

**For OIDC:**
1. Verify federated credential subject matches your repo:
   ```bash
   az ad app federated-credential list --id <APP_ID>
   ```
2. Ensure `subject` is: `repo:<YOUR_ORG>/<YOUR_REPO>:ref:refs/heads/main`

**For Service Principal:**
```bash
# Verify environment variables are set correctly
echo $AZURE_CLIENT_ID
echo $AZURE_TENANT_ID
echo $AZURE_SUBSCRIPTION_ID
# Don't echo AZURE_CLIENT_SECRET (security)

# Test authentication manually
az login --service-principal \
  -u $AZURE_CLIENT_ID \
  -p $AZURE_CLIENT_SECRET \
  --tenant $AZURE_TENANT_ID
```

**For Azure CLI:**
```bash
# Re-login
az login

# Scan all accessible subscriptions
cleancloud scan --provider azure

# Or scan specific subscription
cleancloud scan --provider azure --subscription <SUBSCRIPTION_ID>
```

### "No accessible subscriptions"

```bash
# Check role assignments
az role assignment list --assignee <APP_ID>

# Assign Reader role
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>

# Wait 5-10 minutes for RBAC propagation
```

### "Missing permission: Microsoft.Compute/disks/read"

```bash
# Verify Reader role is assigned
az role assignment list \
  --assignee <APP_ID> \
  --scope /subscriptions/<SUBSCRIPTION_ID>

# Wait 5-10 minutes for RBAC propagation
```

---

## Azure vs AWS Differences

| Aspect | AWS | Azure |
|--------|-----|-------|
| **OIDC Setup** | IAM role trust policy | Federated identity credential |
| **Permissions** | IAM policies | RBAC roles |
| **Regions** | Must specify explicitly | All locations scanned by default |
| **Resource Scope** | Per-region | Per-subscription |
| **Auth Methods** | OIDC, AWS CLI, env vars | OIDC, Azure CLI, service principal |
| **Local Development** | Environment variables | Service principal or Azure CLI |

---

## Performance

| Subscriptions | Resources | Scan Time |
|---------------|-----------|-----------|
| 1 subscription | ~500 resources | 30-60 sec |
| 1 subscription | ~2,000 resources | 2-3 min |
| 3 subscriptions | ~6,000 resources | 5-8 min |

**API calls:** All free (read-only operations have no cost)

---

## Security Best Practices

### DO

- Use OIDC for CI/CD (no stored secrets)
- Use Reader role (least privilege)
- Restrict federated credential to specific repo/branch
- Monitor Azure Activity Log for CleanCloud actions
- Use separate service principals per environment

### DON'T

- Use client secrets in CI/CD
- Grant Contributor role
- Share credentials across teams
- Commit credentials to repositories

---

## Supported Azure Clouds

- Azure Commercial
- Azure Government (not tested)
- Azure China (not tested)

---

**Next:** [AWS Setup →](aws.md) | [Rules Reference →](rules.md) | [CI/CD Guide →](ci.md)