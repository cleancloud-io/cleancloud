# Azure Setup

Azure authentication, RBAC permissions, and configuration guide.

> **Quick Start:** See [README.md](../README.md)  
> **Rules Reference:** See [rules.md](rules.md)  
> **CI/CD Integration:** See [ci.md](ci.md)

---

## Authentication Methods

CleanCloud supports two Azure authentication methods:

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

**No secret needed:** `AZURE_CLIENT_SECRET` ✅

---

### 2. Azure CLI (Local Development)

```bash
# Login
az login

# Set subscription
az account set --subscription <SUBSCRIPTION_ID>

# Run scan
cleancloud scan --provider azure
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
- ✅ `Microsoft.Compute/disks/read`
- ✅ `Microsoft.Compute/snapshots/read`
- ✅ `Microsoft.Network/publicIPAddresses/read`
- ✅ `Microsoft.Resources/subscriptions/read`

**What Reader does NOT allow:**
- ❌ Delete operations (`*/delete`)
- ❌ Modification operations (`*/write`)
- ❌ Tagging operations (`Microsoft.Resources/tags/*`)
- ❌ Billing data access (`Microsoft.CostManagement/*`)

### Custom Role (Optional Least-Privilege)

```json
{
  "Name": "CleanCloud Scanner",
  "Description": "Minimal read-only access for CleanCloud",
  "Actions": [
    "Microsoft.Compute/disks/read",
    "Microsoft.Compute/snapshots/read",
    "Microsoft.Network/publicIPAddresses/read",
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

### Region Filtering

```bash
# Scan only East US resources
cleancloud scan --provider azure --region eastus

# Scan only West Europe resources
cleancloud scan --provider azure --region westeurope
```

**Note:** Unlike AWS, Azure scans all subscriptions by default. Region is an optional filter on results.

---

## Validate Setup

Use the `doctor` command to verify credentials and permissions:

```bash
cleancloud doctor --provider azure
```

**What it checks:**
- ✅ Azure credentials are valid
- ✅ Authentication method (OIDC, CLI)
- ✅ Security grade
- ✅ Required permissions are present
- ✅ Accessible subscriptions

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

**For local CLI:**
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

**For CLI:**
```bash
# Re-login
az login
az account set --subscription <SUBSCRIPTION_ID>
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
| **Authentication** | OIDC or access keys | OIDC or client secrets |

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

### ✅ DO

- Use OIDC for CI/CD (no stored secrets)
- Use Reader role (least privilege)
- Restrict federated credential to specific repo/branch
- Monitor Azure Activity Log for CleanCloud actions
- Use separate service principals per environment

### ❌ DON'T

- Use client secrets in CI/CD
- Grant Contributor role
- Share credentials across teams
- Commit credentials to repositories

---

## Supported Azure Clouds

- ✅ Azure Commercial
- ⚠️ Azure Government (not tested)
- ⚠️ Azure China (not tested)

---

**Next:** [AWS Setup →](aws.md) | [Rules Reference →](rules.md) | [CI/CD Guide →](ci.md)