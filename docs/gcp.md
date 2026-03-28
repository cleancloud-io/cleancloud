# GCP Setup

GCP authentication, IAM permissions, and configuration guide.

- **Quick Start:** See [README.md](../README.md)
- **Rules Reference:** See [rules.md](rules.md)
- **CI/CD Integration:** See [ci.md](ci.md)

---

## Quick Setup

Get Workload Identity Federation running in 4 steps:

```bash
# 1. Create a Workload Identity Pool
gcloud iam workload-identity-pools create "github-actions" \
  --project="<YOUR_PROJECT_ID>" \
  --location="global" \
  --display-name="GitHub Actions"

# 2. Create an OIDC provider pointing at GitHub
gcloud iam workload-identity-pools providers create-oidc "github" \
  --project="<YOUR_PROJECT_ID>" \
  --location="global" \
  --workload-identity-pool="github-actions" \
  --display-name="GitHub" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository"

# 3. Create a service account and grant read-only roles
gcloud iam service-accounts create cleancloud-scanner \
  --project="<YOUR_PROJECT_ID>" \
  --display-name="CleanCloud Scanner"

gcloud projects add-iam-policy-binding <YOUR_PROJECT_ID> \
  --member="serviceAccount:cleancloud-scanner@<YOUR_PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/compute.viewer"

gcloud projects add-iam-policy-binding <YOUR_PROJECT_ID> \
  --member="serviceAccount:cleancloud-scanner@<YOUR_PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/cloudsql.viewer"

gcloud projects add-iam-policy-binding <YOUR_PROJECT_ID> \
  --member="serviceAccount:cleancloud-scanner@<YOUR_PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/monitoring.viewer"

# 4. Allow the GitHub Actions OIDC token to impersonate the service account
gcloud iam service-accounts add-iam-policy-binding \
  cleancloud-scanner@<YOUR_PROJECT_ID>.iam.gserviceaccount.com \
  --project="<YOUR_PROJECT_ID>" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-actions/attribute.repository/<YOUR_ORG>/<YOUR_REPO>"
```

Then add to your GitHub Actions workflow:

```yaml
permissions:
  id-token: write
  contents: read

- uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-actions/providers/github
    service_account: cleancloud-scanner@<YOUR_PROJECT_ID>.iam.gserviceaccount.com

- run: pip install cleancloud
- run: cleancloud scan --provider gcp --all-projects
```

Full walkthrough → [GCP Workload Identity Federation](#1-workload-identity-federation-recommended-for-cicd)

---

## At a Glance

| What | Value |
|---|---|
| Auth method | Application Default Credentials (ADC) |
| Recommended for CI/CD | Workload Identity Federation |
| Recommended for local | `gcloud auth application-default login` |
| Required roles | `roles/compute.viewer` + `roles/cloudsql.viewer` + `roles/monitoring.viewer` + `resourcemanager.projects.get` |
| Minimum permissions | 7 individual permissions (see below) |
| Multi-project flag | `--all-projects` or `--project <ID>` |
| Doctor command | `cleancloud doctor --provider gcp` |
| Doctor command (specific project) | `cleancloud doctor --provider gcp --project <PROJECT_ID>` |

---

## Required Permissions

CleanCloud requires **read-only** IAM permissions only. No write access is needed or used.

### Minimum Permission Set

| Permission | Used by rule | Predefined role |
|---|---|---|
| `compute.disks.list` | `gcp.compute.disk.unattached` | `roles/compute.viewer` |
| `compute.instances.list` | `gcp.compute.vm.stopped` | `roles/compute.viewer` |
| `compute.addresses.list` | `gcp.compute.ip.unused` | `roles/compute.viewer` |
| `compute.globalAddresses.list` | `gcp.compute.ip.unused` | `roles/compute.viewer` |
| `compute.snapshots.list` | `gcp.compute.snapshot.old` | `roles/compute.viewer` |
| `cloudsql.instances.list` | `gcp.sql.instance.idle` | `roles/cloudsql.viewer` |
| `monitoring.timeSeries.list` | `gcp.sql.instance.idle` | `roles/monitoring.viewer` |

Additionally, `resourcemanager.projects.get` (or `resourcemanager.projects.list`) is required when using `--all-projects` to enumerate projects.

### Predefined Roles (Recommended)

The simplest approach — assign three predefined roles:

```bash
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:cleancloud-scanner@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/compute.viewer"

gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:cleancloud-scanner@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/cloudsql.viewer"

gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:cleancloud-scanner@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/monitoring.viewer"
```

For multi-project scanning, add `roles/browser` at the organization or folder level to allow project enumeration:

```bash
gcloud resource-manager folders add-iam-policy-binding <FOLDER_ID> \
  --member="serviceAccount:cleancloud-scanner@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/browser"
```

### Graceful Degradation

CleanCloud never fails a scan due to missing permissions. If a permission is absent:

- The affected rule is **skipped** (not failed)
- The missing permission is recorded in `skipped_rules` in the scan output
- All other rules continue normally

This means you can run CleanCloud with only the permissions you have — it reports what it found and what it skipped.

---

## Authentication Methods

CleanCloud uses GCP Application Default Credentials (ADC) — the standard GCP auth chain used by all Google Cloud client libraries.

### 1. Workload Identity Federation (Recommended for CI/CD)

No service account keys required — GitHub OIDC tokens are exchanged for short-lived GCP tokens.

#### Setup

**Step 1: Create Workload Identity Pool**

```bash
gcloud iam workload-identity-pools create "github-actions" \
  --project="<YOUR_PROJECT_ID>" \
  --location="global" \
  --display-name="GitHub Actions Pool"
```

**Step 2: Create OIDC Provider**

```bash
gcloud iam workload-identity-pools providers create-oidc "github" \
  --project="<YOUR_PROJECT_ID>" \
  --location="global" \
  --workload-identity-pool="github-actions" \
  --display-name="GitHub OIDC" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='<YOUR_ORG>/<YOUR_REPO>'"
```

**Step 3: Create Service Account**

```bash
gcloud iam service-accounts create cleancloud-scanner \
  --project="<YOUR_PROJECT_ID>" \
  --display-name="CleanCloud Read-Only Scanner"
```

**Step 4: Bind Read-Only Roles**

```bash
for ROLE in roles/compute.viewer roles/cloudsql.viewer roles/monitoring.viewer; do
  gcloud projects add-iam-policy-binding <YOUR_PROJECT_ID> \
    --member="serviceAccount:cleancloud-scanner@<YOUR_PROJECT_ID>.iam.gserviceaccount.com" \
    --role="$ROLE"
done
```

**Step 5: Allow GitHub Actions to Impersonate the Service Account**

```bash
# Get the project number
PROJECT_NUMBER=$(gcloud projects describe <YOUR_PROJECT_ID> --format='value(projectNumber)')

gcloud iam service-accounts add-iam-policy-binding \
  cleancloud-scanner@<YOUR_PROJECT_ID>.iam.gserviceaccount.com \
  --project="<YOUR_PROJECT_ID>" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions/attribute.repository/<YOUR_ORG>/<YOUR_REPO>"
```

**Step 6: Configure GitHub Actions Workflow**

```yaml
# .github/workflows/cleancloud-gcp.yml
name: CleanCloud GCP Scan

on:
  schedule:
    - cron: "0 9 * * 1"   # every Monday 9am
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/${{ vars.GCP_PROJECT_NUMBER }}/locations/global/workloadIdentityPools/github-actions/providers/github
          service_account: cleancloud-scanner@${{ vars.GCP_PROJECT_ID }}.iam.gserviceaccount.com

      - name: Install CleanCloud
        run: pip install cleancloud

      - name: Run scan
        run: |
          cleancloud scan --provider gcp --all-projects \
            --output json --output-file gcp-findings.json \
            --fail-on-confidence HIGH
```

Add `GCP_PROJECT_ID` and `GCP_PROJECT_NUMBER` as GitHub Actions variables (repo → Settings → Variables → Actions).

---

### 2. Service Account Key (Not Recommended)

Use only when Workload Identity is not available (e.g., non-GitHub CI systems without OIDC support).

```bash
# Create and download the key
gcloud iam service-accounts keys create cleancloud-key.json \
  --iam-account=cleancloud-scanner@<YOUR_PROJECT_ID>.iam.gserviceaccount.com

# Use it
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/cleancloud-key.json
cleancloud scan --provider gcp --all-projects
```

> Service account keys are long-lived credentials. Store them as CI secrets, never commit to source control, and rotate them regularly.

---

### 3. gcloud ADC (Local Development)

The recommended approach for local use — no key files needed.

```bash
gcloud auth application-default login
cleancloud scan --provider gcp --all-projects
```

This uses your personal Google account's credentials via the standard ADC chain. For production CI/CD, use Workload Identity Federation instead.

---

### 4. Attached Service Account (GKE / Cloud Run / Compute Engine)

If CleanCloud runs inside GCP infrastructure (GKE pod, Cloud Run job, Compute Engine VM), it automatically uses the attached service account — no configuration needed.

```bash
# Ensure the attached service account has the required roles, then just run:
cleancloud scan --provider gcp --all-projects
```

---

## Multi-Project Scanning

CleanCloud can scan all accessible GCP projects in a single run.

### Auto-Discovery (`--all-projects`)

```bash
cleancloud scan --provider gcp --all-projects
```

CleanCloud calls the Resource Manager API to enumerate all `ACTIVE` projects the identity has access to, then scans them in parallel (up to 4 at a time).

**For this to work, the identity needs project enumeration access:**

```bash
# Option A: roles/browser at folder/org level (inherits to all projects)
gcloud resource-manager folders add-iam-policy-binding <FOLDER_ID> \
  --member="serviceAccount:cleancloud-scanner@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/browser"

# Option B: resourcemanager.projects.get on each individual project
# (already included in roles/compute.viewer at project level)
```

### Explicit Projects (`--project`)

```bash
# Scan specific projects
cleancloud scan --provider gcp \
  --project my-production-project \
  --project my-staging-project

# With region filter
cleancloud scan --provider gcp \
  --project my-project \
  --region us-central1
```

### With a Specific Project for Doctor

```bash
cleancloud doctor --provider gcp --project <PROJECT_ID>
```

Without `--project`, the doctor command uses the default project from your ADC environment.

---

## Doctor Command

The `cleancloud doctor --provider gcp` command validates credentials and probes each required permission independently.

```
cleancloud doctor --provider gcp
```

Example output:

```
GCP Doctor
══════════════════════════════

[1/4] Auth method detection
  Auth method : Workload Identity Federation (GitHub Actions)

[2/4] Credential acquisition
  OK  Credentials acquired and refreshed successfully

[3/4] Project access
  Project     : my-project-123 (My Project)
  OK  Project accessible

[4/4] Permission probes
  OK  compute.disks.list
  OK  compute.instances.list
  OK  compute.addresses.list
  OK  compute.globalAddresses.list
  OK  compute.snapshots.list
  OK  cloudsql.instances.list
  OK  monitoring.timeSeries.list

Permissions tested : 7
Permissions failed : 0

Doctor complete — credentials and permissions look good.
Run: cleancloud scan --provider gcp --all-projects
```

If a permission is missing:

```
  WARN  cloudsql.instances.list — PermissionDenied
        Grant roles/cloudsql.viewer to the service account
```

The scan continues for all other rules — missing permissions are skipped, not fatal.

---

## Troubleshooting

### `google.auth.exceptions.DefaultCredentialsError`

**Cause:** No credentials found in the ADC chain.

**Fix:**
- Local: run `gcloud auth application-default login`
- CI: ensure `google-github-actions/auth@v2` step ran before `cleancloud scan`
- GKE/Cloud Run: verify the workload's service account has the required roles

### `PermissionDenied: 403 compute.instances.list denied`

**Cause:** The identity lacks `roles/compute.viewer` on the target project.

**Fix:**
```bash
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:<SA_EMAIL>" \
  --role="roles/compute.viewer"
```

### `NotFound: 404 Compute Engine API not enabled`

**Cause:** The Compute Engine API is not enabled for the scanned project.

**Fix:** This is not an error — CleanCloud returns an empty result for that rule in that project. No action needed unless you expect Compute Engine resources to be present.

### No projects found

**Cause:** The identity cannot enumerate projects (missing `resourcemanager.projects.list` or `resourcemanager.projects.get`).

**Fix:** Use `--project <ID>` to specify projects explicitly, or grant `roles/browser` at the folder/org level:

```bash
gcloud resource-manager folders add-iam-policy-binding <FOLDER_ID> \
  --member="serviceAccount:<SA_EMAIL>" \
  --role="roles/browser"
```

### Workload Identity: `INVALID_ARGUMENT` or token exchange fails

**Cause:** The `attribute-condition` or subject pattern doesn't match the GitHub Actions OIDC token subject.

GitHub Actions subjects follow the pattern:
- Branch push: `repo:<ORG>/<REPO>:ref:refs/heads/<BRANCH>`
- Pull request: `repo:<ORG>/<REPO>:pull_request`
- Environment: `repo:<ORG>/<REPO>:environment:<ENV_NAME>`
- Schedule: `repo:<ORG>/<REPO>:ref:refs/heads/<DEFAULT_BRANCH>`

Check the exact subject in your workflow by adding a debug step:

```yaml
- name: Debug OIDC token
  run: |
    curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
         "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r '.value' | cut -d. -f2 | base64 -d 2>/dev/null | jq .sub
```

---

**Next:** [Detection Rules →](rules.md) | [CI/CD Integration →](ci.md) | [Example Outputs →](example-outputs.md)
