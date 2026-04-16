# Azure Setup

Azure authentication, RBAC permissions, and configuration guide.

- **Quick Start:** See [README.md](../README.md)
- **Rules Reference:** See [rules.md](rules.md)
- **CI/CD Integration:** See [ci.md](ci.md)

---

## Quick Setup

Get OIDC running in 4 steps:

```bash
# 1. Create App Registration and Service Principal
az ad app create --display-name "CleanCloudScanner"
az ad sp create --id <APP_ID>

# 2. Add federated identity credential
az ad app federated-credential create \
  --id <APP_ID> \
  --parameters '{
    "name": "CleanCloudGitHub",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<YOUR_ORG>/<YOUR_REPO>:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# 3. Assign Reader role (covers the default hygiene scan path)
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>

# 4. Add AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID as GitHub secrets
#    (repo → Settings → Secrets and variables → Actions)
```

> ⚠️ **Common mistake:** The federated credential subject must exactly match your workflow trigger. Branch push, PR, and GitHub Environment each send a different subject claim — using the wrong one causes a silent auth failure (`AADSTS70021`). See [OIDC subject mismatch](#oidc-subject-claim-mismatch).

Full walkthrough → [Azure OIDC setup](#azure-oidc-with-workload-identity-recommended-for-cicd)

---

## Authentication Methods

CleanCloud supports multiple Azure authentication methods:

### Azure OIDC with Workload Identity (Recommended for CI/CD)

Microsoft Entra ID Workload Identity Federation — no client secrets, temporary tokens only.

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

Choose the subject format that matches how your GitHub Actions workflow runs:

| Workflow trigger | Subject claim to use |
|---|---|
| Branch push (e.g. `main`) | `repo:<ORG>/<REPO>:ref:refs/heads/main` |
| Pull request | `repo:<ORG>/<REPO>:pull_request` |
| GitHub Environment | `repo:<ORG>/<REPO>:environment:<ENV_NAME>` |

> ⚠️ **Common mistake:** If your workflow uses `environment: production`, GitHub sends the `environment` subject claim — not the `ref` one. Using the wrong format causes silent auth failures. See [OIDC subject mismatch](#oidc-subject-claim-mismatch) in Troubleshooting.

Create one federated credential per workflow trigger. Azure allows up to 20 per App Registration.

```bash
# Branch push (e.g. main)
az ad app federated-credential create \
  --id <APP_ID> \
  --parameters '{
    "name": "CleanCloudGitHub-Branch",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<YOUR_ORG>/<YOUR_REPO>:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# GitHub Environment (e.g. production)
az ad app federated-credential create \
  --id <APP_ID> \
  --parameters '{
    "name": "CleanCloudGitHub-Env",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<YOUR_ORG>/<YOUR_REPO>:environment:<YOUR_ENV_NAME>",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

> 💡 If you only use one trigger type, create only that credential. See [OIDC subject mismatch](#oidc-subject-claim-mismatch) if authentication fails.

**Step 4: Assign Reader Role**

```bash
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

**Step 5: Add GitHub Secrets**

Go to your repo → Settings → Secrets and variables → Actions → New repository secret:

| Secret | Value |
|---|---|
| `AZURE_CLIENT_ID` | App registration application ID |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Subscription to scan |

No `AZURE_CLIENT_SECRET` needed — OIDC uses federated credentials.

> To also enable AI/ML rules (`cleancloud scan --provider azure --category ai`), assign the additional AI role described in [RBAC Permissions](#rbac-permissions).

## AI/ML rules (opt-in)

CleanCloud includes additional AI/ML waste detectors that run only when you pass `--category ai` (or `--category all`). Two new Azure rules were added:

- `azure.ml.online_endpoint.idle` — Detects Azure ML managed online endpoints in `Succeeded` provisioning state that have received zero scoring requests for 7+ days. These endpoints bill per-instance (minimum replica count) regardless of traffic; signals are confirmed via per-endpoint Azure Monitor metrics (RequestCount, fallback ModelEndpointRequests). Age-only fallback applies only when metric data is unavailable and endpoint age >= 2× idle window (MEDIUM confidence).

- `azure.ai_search.idle` — Detects Azure AI Search services on Standard tier or above with effectively zero search queries (SearchQueriesPerSecond average == 0) over a 30-day window. Cost is computed per SKU × replicas × partitions. If metrics are unavailable, age-only fallback (age >= 2× idle window) yields MEDIUM confidence.

Permissions required for AI/ML scans

The following actions are required by the AI/ML rules (add these to a custom role such as `security/azure/ai-readonly-role.json`):

- Microsoft.MachineLearningServices/workspaces/read
- Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read
- Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read
- Microsoft.CognitiveServices/accounts/read
- Microsoft.CognitiveServices/accounts/deployments/read
- Microsoft.Search/searchServices/read
- Microsoft.Insights/metrics/read

Assign the ready-to-use AI role (one-time per subscription):

```bash
az role definition create --role-definition security/azure/ai-readonly-role.json
az role assignment create --assignee <APP_ID> --role "CleanCloudAIReadOnly" --scope /subscriptions/<SUBSCRIPTION_ID>
```

Validate AI permissions with the doctor:

```bash
pip install 'cleancloud[azure]'
cleancloud doctor --provider azure --category ai
```

This doctor run checks `Microsoft.MachineLearningServices` (workspaces, computes, online endpoints), `Microsoft.Search` (searchServices), and `Microsoft.Insights/metrics/read` and reports any missing permissions as skipped rules or warnings.



#### Validate Your Setup

Once credentials are configured, verify everything works:

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

      - name: Validate Azure permissions
        run: |
          pip install 'cleancloud[azure]'
          cleancloud doctor --provider azure
```

For AI/ML scans, also run:

```bash
cleancloud doctor --provider azure --category ai
```

For the complete production workflow with enforcement flags, scheduling, and artifact upload: **[CI/CD guide →](ci.md)**

---

### Service Principal with Environment Variables (Local Development)

Quick setup for local testing and evaluation.

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

> ⚠️ Not recommended for CI/CD — use OIDC (Method 1) to avoid storing secrets.

---

### Azure CLI (Local Development)

Recommended for interactive local development.

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

### Reader Role (Recommended for default hygiene scans)

Built-in Reader role provides all required hygiene permissions:

```bash
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

> ⏱ RBAC assignments take 5–10 minutes to propagate. Run `cleancloud doctor --provider azure` after waiting to confirm access.

**Hygiene rules — all 17 permissions covered by Reader:**

| Permission | Used by |
|---|---|
| `Microsoft.Compute/disks/read` | Unattached managed disks |
| `Microsoft.Compute/snapshots/read` | Old snapshots |
| `Microsoft.Compute/virtualMachines/read` | Stopped (not deallocated) VMs |
| `Microsoft.Network/publicIPAddresses/read` | Unused public IPs |
| `Microsoft.Network/loadBalancers/read` | Empty load balancers |
| `Microsoft.Network/applicationGateways/read` | Empty app gateways |
| `Microsoft.Network/virtualNetworkGateways/read` | Idle VNet gateways |
| `Microsoft.Network/connections/read` | Gateway connection status |
| `Microsoft.Web/serverfarms/read` | Empty App Service Plans |
| `Microsoft.Web/serverfarms/sites/read` | Empty App Service Plans (app count) |
| `Microsoft.Web/sites/read` | Idle App Services |
| `Microsoft.ContainerRegistry/registries/read` | Unused Container Registries |
| `Microsoft.Sql/servers/read` | SQL server discovery |
| `Microsoft.Sql/servers/databases/read` | Idle SQL databases |
| `Microsoft.Insights/metrics/read` | SQL connection metrics, idle App Services, idle VNet gateways, unused Container Registries, idle AML compute, idle Azure OpenAI provisioned deployments |
| `Microsoft.Resources/subscriptions/read` | Subscription discovery |
| `Microsoft.Resources/resources/read` | Resource discovery |

**AI/ML rules (`--category ai`) — NOT included in Reader, require additional role assignment:**

| Permission | Used by |
|---|---|
| `Microsoft.MachineLearningServices/workspaces/read` | Idle AML compute clusters, idle AML Compute Instances |
| `Microsoft.MachineLearningServices/workspaces/computes/read` | Idle AML compute clusters, idle AML Compute Instances |
| `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read` | Managed Azure ML Online Endpoints (endpoint metadata) |
| `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read` | Online endpoint deployments (instance SKUs and replica counts) |
| `Microsoft.Search/searchServices/read` | Azure AI Search services (service inventory, replicas/partitions) |
| `Microsoft.CognitiveServices/accounts/read` | Idle Azure OpenAI provisioned deployments (PTUs) |
| `Microsoft.CognitiveServices/accounts/deployments/read` | Idle Azure OpenAI provisioned deployments (PTUs) |

> Reader does not grant `Microsoft.MachineLearningServices` or `Microsoft.CognitiveServices` access. Assign `CleanCloudAIReadOnly` (see [Custom Role](#custom-role-optional-least-privilege)) or built-in roles such as **AzureML Data Scientist** and **Cognitive Services Reader** in addition to Reader.
>
> Rules that require missing permissions are skipped gracefully — hygiene rules continue to run unaffected. Run `cleancloud doctor --provider azure --category ai` to validate.

To scan AI/ML resources after granting those permissions:

```bash
cleancloud scan --provider azure --category ai
```

**What Reader does NOT allow:**

- Delete operations (`*/delete`)
- Modification operations (`*/write`)
- Tagging operations (`Microsoft.Resources/tags/*`)
- Billing data access (`Microsoft.CostManagement/*`)

### Custom Role (Optional Least-Privilege)

The policy files are in the [CleanCloud repo](https://github.com/cleancloud-io/cleancloud/tree/main/security/azure). Download or clone the repo first, then run the commands below.

**Hygiene rules** (`cleancloud scan --provider azure`):

```bash
az role definition create --role-definition security/azure/hygiene-readonly-role.json

az role assignment create \
  --assignee <APP_ID> \
  --role "CleanCloudReadOnly" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

> To also enable AI/ML rules (`--category ai`), assign the AI role in addition:

```bash
az role definition create --role-definition security/azure/ai-readonly-role.json

az role assignment create \
  --assignee <APP_ID> \
  --role "CleanCloudAIReadOnly" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

---

## Multi-Subscription Scanning

Large Azure tenants often have 20–200+ subscriptions. CleanCloud scans them all in parallel with one identity — no extra credentials, no cross-subscription role setup.

Findings from all subscriptions are aggregated into a single report with a per-subscription breakdown.

### Discovery modes

| Mode | Flag | When to use |
|---|---|---|
| **All accessible** | *(no flag)* | Service principal has Reader on multiple subscriptions — all are scanned automatically |
| **Management Group** | `--management-group <ID>` | Auto-discover all subscriptions under a Management Group |
| **Explicit list** | `--subscription <ID>` (repeatable) | Scan specific subscriptions only |

```bash
# All subscriptions the service principal can access
cleancloud scan --provider azure

# Auto-discover via Management Group
cleancloud scan --provider azure --management-group <MANAGEMENT_GROUP_ID>

# Explicit list
cleancloud scan --provider azure \
  --subscription <SUB_1> \
  --subscription <SUB_2>

# Single subscription
cleancloud scan --provider azure --subscription <SUBSCRIPTION_ID>
```

### Permissions for multi-subscription scanning

No extra role assignments needed beyond Reader. Assign Reader at the **Management Group level** — it inherits to all subscriptions underneath automatically.

```bash
az role assignment create \
  --assignee <SERVICE_PRINCIPAL_CLIENT_ID> \
  --role Reader \
  --scope /providers/Microsoft.Management/managementGroups/<MANAGEMENT_GROUP_ID>
```

> For `--management-group` auto-discovery, the service principal also needs `Microsoft.Management/managementGroups/read` on the Management Group.

### Per-subscription output

When scanning multiple subscriptions, CleanCloud shows a per-subscription breakdown:

```
Subscriptions scanned: 3

Per-subscription breakdown:
  production                     (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx):  12 findings  ~$147/month
  staging                        (yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy):   4 findings  ~$32/month
  dev                            (zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz):  0 findings
```

JSON output includes `per_subscription` with findings count and estimated cost per subscription.

### Performance

Subscriptions are scanned in parallel (default: 4 concurrent, configurable with `--concurrency N`). Rules within each subscription also run in parallel. A 10-subscription tenant typically completes in the same time as scanning 2–3 sequentially.

### Subscription Filtering

CleanCloud validates that specified subscriptions are accessible:

```bash
cleancloud scan --provider azure --subscription invalid-sub-id
# Warning: 1 subscription(s) not accessible:
#   - invalid-sub-id
#
# Error: None of the specified subscriptions are accessible
```

### Single Subscription

```bash
export AZURE_SUBSCRIPTION_ID="12345678-1234-1234-1234-123456789abc"
cleancloud scan --provider azure
```

> `AZURE_SUBSCRIPTION_ID` is optional if your identity has Reader on only one subscription — CleanCloud will discover and scan it automatically. Set it explicitly to target a specific subscription when multiple are accessible.

---

## Region Filtering

```bash
# Scan only East US resources
cleancloud scan --provider azure --region eastus

# Scan only West Europe resources
cleancloud scan --provider azure --region westeurope
```

> Note: Region is an optional filter on results — not required like AWS.

---

## Validate Setup

Use the doctor command for the category you plan to scan:

```bash
# Default hygiene scan
cleancloud doctor --provider azure

# AI/ML scan
cleancloud doctor --provider azure --category ai
```

**What the default doctor checks:**

- Azure credentials are valid
- Authentication method (OIDC, Service Principal, Azure CLI, Managed Identity)
- Security grade (EXCELLENT / GOOD / ACCEPTABLE / POOR)
- CI/CD readiness and compliance compatibility
- Token acquisition and expiry
- Accessible subscriptions
- Subscription-level access consistent with the default hygiene scan path

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
  Reader role provides all required permissions

======================================================================
VALIDATION SUMMARY
======================================================================
Authentication: OIDC (Workload Identity Federation)
Security Grade: EXCELLENT
Subscriptions: 2 accessible

[OK] AZURE ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

**What the AI doctor adds:** Azure Machine Learning workspace and compute read checks, Azure OpenAI/Cognitive Services account and deployment read checks, and `Microsoft.Insights/metrics/read` validation for AI rules. Run it before `cleancloud scan --provider azure --category ai`.

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

JSON schema, examples, and CSV column reference: See [ci.md](ci.md)

---

## Troubleshooting

### OIDC Subject Claim Mismatch

**Symptom:** Azure login step fails with `AADSTS70021: No matching federated identity record found` or authentication silently fails even though the App Registration and federated credential exist.

**Cause:** The subject claim in your federated credential does not match what GitHub actually sends in the JWT token. GitHub generates different subject claims depending on how your workflow is triggered.

**The three subject formats:**

| Workflow uses | GitHub sends | Federated credential subject |
|---|---|---|
| Branch push to `main` | `repo:org/repo:ref:refs/heads/main` | `repo:<ORG>/<REPO>:ref:refs/heads/main` |
| Pull request trigger | `repo:org/repo:pull_request` | `repo:<ORG>/<REPO>:pull_request` |
| `environment: production` | `repo:org/repo:environment:production` | `repo:<ORG>/<REPO>:environment:production` |

**Fix — check what subject your workflow is sending:**

```bash
# List existing federated credentials on your App Registration
az ad app federated-credential list --id <APP_ID>
```

Then check your workflow — if it has `environment:` set:

```yaml
jobs:
  cleancloud:
    environment: production   # ← this changes the subject claim
```

You need a matching federated credential:

```bash
az ad app federated-credential create \
  --id <APP_ID> \
  --parameters '{
    "name": "CleanCloudGitHub-Env-Production",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<YOUR_ORG>/<YOUR_REPO>:environment:production",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

**Multiple triggers — create one credential per subject:**

You can attach multiple federated credentials to the same App Registration. If your pipeline runs on both branch pushes and with a GitHub Environment, create one credential for each:

```bash
# Credential 1: branch push
az ad app federated-credential create \
  --id <APP_ID> \
  --parameters '{
    "name": "CleanCloudGitHub-Branch",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<YOUR_ORG>/<YOUR_REPO>:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# Credential 2: GitHub Environment
az ad app federated-credential create \
  --id <APP_ID> \
  --parameters '{
    "name": "CleanCloudGitHub-Env",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<YOUR_ORG>/<YOUR_REPO>:environment:production",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

> 💡 GitHub Environments are the recommended approach for production pipelines — they add deployment protection rules, required reviewers, and environment-scoped secrets on top of OIDC.

---

### "Missing Azure environment variables"

**For OIDC (GitHub Actions):**

```yaml
secrets:
  AZURE_CLIENT_ID
  AZURE_TENANT_ID
  AZURE_SUBSCRIPTION_ID
```

**For Service Principal (local):**

```bash
export AZURE_CLIENT_ID="..."
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_SECRET="..."
export AZURE_SUBSCRIPTION_ID="..."
```

**For Azure CLI:**

```bash
az account show
```

---

### "Azure authentication failed"

**For OIDC** — verify the federated credential subject matches your workflow:

```bash
az ad app federated-credential list --id <APP_ID>
```

See [OIDC subject claim mismatch](#oidc-subject-claim-mismatch) above.

**For Service Principal:**

```bash
# Test authentication manually
az login --service-principal \
  -u $AZURE_CLIENT_ID \
  -p $AZURE_CLIENT_SECRET \
  --tenant $AZURE_TENANT_ID
```

**For Azure CLI:**

```bash
az login
```

---

### "No accessible subscriptions"

```bash
# Check role assignments
az role assignment list --assignee <APP_ID>

# Assign Reader role
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>

# RBAC changes take 5–10 minutes to propagate — wait, then re-run doctor
```

---

### "Missing permission: Microsoft.Compute/disks/read"

```bash
# Verify Reader role is assigned
az role assignment list \
  --assignee <APP_ID> \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

> RBAC changes take 5–10 minutes to propagate — see the note in [Reader Role](#reader-role-recommended).

---

## Azure vs AWS Differences

| Aspect | AWS | Azure |
|---|---|---|
| OIDC Setup | IAM role trust policy | Federated identity credential |
| Permissions | IAM policies | RBAC roles |
| Regions | Must specify explicitly | All locations scanned by default |
| Resource Scope | Per-region | Per-subscription |
| Auth Methods | OIDC, AWS CLI, env vars | OIDC, Azure CLI, service principal |
| Local Development | Environment variables | Service principal or Azure CLI |

---

## Performance

| Subscriptions | Resources | Scan Time |
|---|---|---|
| 1 subscription | ~500 resources | 30–60 sec |
| 1 subscription | ~2,000 resources | 2–3 min |
| 3 subscriptions | ~6,000 resources | 5–8 min |

> API calls are all free — read-only operations have no cost.

---

## Security Best Practices

**DO:**
- Use OIDC for CI/CD (no stored secrets)
- Use Reader role (least privilege)
- Restrict federated credential to specific repo/branch or environment
- Use GitHub Environments for production pipelines
- Monitor Azure Activity Log for CleanCloud actions
- Use separate service principals per environment

**DON'T:**
- Use client secrets in CI/CD
- Grant Contributor role
- Share credentials across teams
- Commit credentials to repositories

---

## Supported Azure Clouds

- Azure Commercial ✅
- Azure Government — not tested. If you try it: set `AZURE_ENVIRONMENT=AzureUSGovernment` before running. The OIDC issuer endpoint and ARM resource URIs differ from commercial — federated credentials may need adjustment.
- Azure China — not tested. Set `AZURE_ENVIRONMENT=AzureChinaCloud`. Azure China uses a separate Entra ID endpoint (`login.chinacloudapi.cn`) which may not be compatible with the standard `DefaultAzureCredential` chain without additional configuration.

---

**Next:** [AWS Setup →](aws.md) | [Rules Reference →](rules.md) | [CI/CD Guide →](ci.md)
