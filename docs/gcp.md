# GCP Setup

> **Rules Reference:** [rules.md](rules.md) · **CI/CD Guide:** [ci.md](ci.md) · **Example Outputs:** [example-outputs.md](example-outputs.md)

---

## At a Glance

### Permissions by Scenario

| Scenario | What you need |
|---|---|
| Single-project scan | `roles/compute.viewer` + `roles/cloudsql.viewer` + `roles/monitoring.viewer` on the target project |
| Multi-project / org-wide scan | Same 3 roles + `roles/browser` — bound at the **organization or folder level** (covers all projects automatically) |
| Project enumeration (`--all-projects`) | `roles/browser` at org or folder level |

All roles are read-only. No create, delete, or modify permissions — ever.

---

### Commands

| Task | Command |
|---|---|
| Scan one project | `cleancloud scan --provider gcp --project <PROJECT_ID>` |
| Scan all accessible projects | `cleancloud scan --provider gcp --all-projects` |
| Scan all projects, higher concurrency | `cleancloud scan --provider gcp --all-projects --concurrency 8` |
| Filter by region | `cleancloud scan --provider gcp --all-projects --region us-central1` |
| Fail build on HIGH findings | Add `--fail-on-confidence HIGH` to any scan command |
| Fail build if waste ≥ $X/month | Add `--fail-on-cost 500` to any scan command |
| Validate credentials + permissions | `cleancloud doctor --provider gcp --project <PROJECT_ID>` |

---

### Org-Wide Setup (3 steps)

**Step 1 — Create a host project, service account, and WIF pool** → [Host Project Setup](#step-1-create-the-host-project-service-account-and-wif-pool)

**Step 2 — Bind read-only roles at the organization level** → [Org-Level IAM Binding](#step-2-bind-read-only-roles-at-the-organization-level)

**Step 3 — Configure GitHub Actions** → [GitHub Actions Setup](#step-3-configure-github-actions)

Then run:
```bash
cleancloud doctor --provider gcp --project <any-project-id>   # validate first
cleancloud scan --provider gcp --all-projects --concurrency 8
```

---

## Host Project vs Target Projects

> **Two concepts, don't mix them up.**
>
> | | Host project | Target projects |
> |---|---|---|
> | **What it is** | Where the service account and WIF pool live | Where your GCP resources (VMs, disks, SQL, etc.) live |
> | **How many** | One (a dedicated security/tools project) | As many as you have — 1 or 100 |
> | **IAM setup** | Create SA and WIF pool here | Grant the SA read-only access here (at org level — covers all at once) |
> | **AWS equivalent** | Hub account | Spoke accounts |
>
> The service account lives in the host project but scans target projects. Unlike AWS (where you deploy a role to each spoke account), GCP uses a single org-level IAM binding that covers every project automatically — present and future.

---

## Org-Wide Setup

### Before you start

You need:
- Your **GCP Organization ID**: `gcloud organizations list`
- A **host project** to own the service account and WIF pool — use an existing security/tools project, or create one:
  ```bash
  gcloud projects create cleancloud-hub --name="CleanCloud Hub"
  gcloud billing projects link cleancloud-hub --billing-account=<BILLING_ACCOUNT_ID>
  ```
- The **project number** of the host project (needed for WIF): `gcloud projects describe cleancloud-hub --format='value(projectNumber)'`

---

### Step 1: Create the Host Project, Service Account, and WIF Pool

Set variables once — used throughout all steps:

```bash
HOST_PROJECT_ID="cleancloud-hub"
ORG_ID="<your-org-id>"          # gcloud organizations list
YOUR_GITHUB_REPO="<ORG>/<REPO>" # e.g. acme-corp/infrastructure

HOST_PROJECT_NUMBER=$(gcloud projects describe "${HOST_PROJECT_ID}" --format='value(projectNumber)')
SA_EMAIL="cleancloud-scanner@${HOST_PROJECT_ID}.iam.gserviceaccount.com"
WIF_PROVIDER="projects/${HOST_PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions/providers/github"
```

**Create the service account:**

```bash
gcloud iam service-accounts create cleancloud-scanner \
  --project="${HOST_PROJECT_ID}" \
  --display-name="CleanCloud Read-Only Scanner"
```

**Create the Workload Identity Pool and OIDC Provider** *(one-time per host project)*:

```bash
# Create the pool
gcloud iam workload-identity-pools create "github-actions" \
  --project="${HOST_PROJECT_ID}" \
  --location="global" \
  --display-name="GitHub Actions Pool"

# Create the OIDC provider — restricted to your repo only
gcloud iam workload-identity-pools providers create-oidc "github" \
  --project="${HOST_PROJECT_ID}" \
  --location="global" \
  --workload-identity-pool="github-actions" \
  --display-name="GitHub OIDC" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='${YOUR_GITHUB_REPO}'"
```

> `--attribute-condition` restricts token exchange to your repo only. Without it, any GitHub repo could impersonate the service account. Don't skip it.
>
> **Multi-trigger workflows** (branch push + PR + schedule): `assertion.repository=='${YOUR_GITHUB_REPO}'` already covers all trigger types — it checks the repo name, not the trigger. You only need a more specific condition if you want to restrict by branch or environment (e.g. `assertion.sub.startsWith('repo:${YOUR_GITHUB_REPO}:ref:refs/heads/main')`). The default shown above is correct for most setups.

**Allow GitHub Actions to impersonate the service account:**

```bash
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
  --project="${HOST_PROJECT_ID}" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${HOST_PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions/attribute.repository/${YOUR_GITHUB_REPO}"
```

---

### Step 2: Bind Read-Only Roles at the Organization Level

This is the GCP equivalent of deploying `CleanCloudReadOnlyRole` to spoke accounts in AWS — **except you do it once** and it covers every project in your org automatically, including projects added in the future.

```bash
# Read-only scanning roles — covers all projects in the org
for ROLE in roles/compute.viewer roles/cloudsql.viewer roles/monitoring.viewer; do
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}"
done

# Project enumeration — required for --all-projects
gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/browser"
```

> **Folder-scoped alternative:** If you only want to scan projects in specific folders — not the whole org — replace `gcloud organizations add-iam-policy-binding` with `gcloud resource-manager folders add-iam-policy-binding --folder=<FOLDER_ID>`. Repeat for each folder. New projects added to those folders are included automatically.

---

### Step 3: Configure GitHub Actions

Add these to GitHub → Settings → Environments → `cleancloud-test` (or your environment name):

| Type | Name | Value |
|------|------|-------|
| Secret | `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/<HOST_PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-actions/providers/github` |
| Secret | `GCP_SERVICE_ACCOUNT` | `cleancloud-scanner@<HOST_PROJECT_ID>.iam.gserviceaccount.com` |
| Variable | `GCP_PROJECT_ID` | Any one target project ID — used by `doctor` for permission probing |

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
    environment: cleancloud-test
    steps:
      - uses: actions/checkout@v4

      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ secrets.GCP_SERVICE_ACCOUNT }}

      - name: Validate credentials
        run: |
          pip install cleancloud
          cleancloud doctor --provider gcp --project ${{ vars.GCP_PROJECT_ID }}

      - name: Run scan (all projects)
        run: |
          cleancloud scan \
            --provider gcp \
            --all-projects \
            --concurrency 8 \
            --output json \
            --output-file gcp-findings.json \
            --fail-on-confidence HIGH

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: gcp-scan-results
          path: gcp-findings.json
          retention-days: 30
```

---

### Validate Your Setup

Before the first CI run, validate locally:

```bash
gcloud auth application-default login
cleancloud doctor --provider gcp --project <any-target-project-id>
```

A clean doctor run looks like:

```
GCP ENVIRONMENT VALIDATION
======================================================================

Step 1: GCP Credential Resolution
[OK]  Authentication Method: gcloud Application Default Credentials

Step 2: Credential Acquisition
[OK]  GCP credentials acquired successfully

Step 3: Project Access Validation
[OK]  Project accessible: my-project (my-project-id)
      (validates resourcemanager.projects.get — required for --all-projects)

Step 4: Read-Only Permission Validation
[OK]  compute.disks.list
[OK]  compute.instances.list
[OK]  compute.addresses.list
[OK]  compute.globalAddresses.list
[OK]  compute.snapshots.list
[OK]  cloudsql.instances.list
[OK]  monitoring.timeSeries.list

Permissions: 7/7 passed
(Step 3 separately validates resourcemanager.projects.get)

Rule Coverage
  ✓ gcp.compute.disk.unattached    (enabled)
  ✓ gcp.compute.vm.stopped         (enabled)
  ✓ gcp.compute.ip.unused          (enabled)
  ✓ gcp.compute.snapshot.old       (enabled)
  ✓ gcp.sql.instance.idle          (enabled)

GCP ENVIRONMENT READY FOR CLEANCLOUD
======================================================================
```

If a permission is missing, doctor tells you exactly what to fix:

```
[WARN] cloudsql.instances.list — PermissionDenied
       Fix: gcloud organizations add-iam-policy-binding <ORG_ID> \
              --member="serviceAccount:cleancloud-scanner@<HOST_PROJECT_ID>.iam.gserviceaccount.com" \
              --role="roles/cloudsql.viewer"
```

---

## Single-Project Setup

Use this only if you are scanning one or two specific projects. For anything broader, [org-wide setup](#org-wide-setup) is the right path — it's the same number of steps and scales to any number of projects.

Skip Steps 2 and 4 from the org-wide guide, and replace the org-level IAM bindings with project-level ones:

```bash
HOST_PROJECT_ID="cleancloud-hub"
TARGET_PROJECT_ID="<project-to-scan>"
SA_EMAIL="cleancloud-scanner@${HOST_PROJECT_ID}.iam.gserviceaccount.com"

for ROLE in roles/compute.viewer roles/cloudsql.viewer roles/monitoring.viewer; do
  gcloud projects add-iam-policy-binding "${TARGET_PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}"
done
```

Then scan:

```bash
cleancloud scan --provider gcp --project "${TARGET_PROJECT_ID}"
```

> **⚠ Every new project requires a manual IAM update.** If you add a project and forget to run `gcloud projects add-iam-policy-binding`, CleanCloud will silently skip it with no findings. Switch to [org-level binding](#step-2-bind-read-only-roles-at-the-organization-level) to avoid this — it's the same number of steps and covers new projects automatically.

---

## Scanning at Scale

### Concurrency

By default CleanCloud scans 4 projects in parallel. For large orgs, increase this:

```bash
cleancloud scan --provider gcp --all-projects --concurrency 8
```

The maximum is 16 (hard cap). Higher concurrency can hit GCP API quota limits:

- **≤20 projects:** concurrency 8 is safe for most orgs
- **50+ projects:** start at 4–6 and increase only if you see no `ResourceExhausted` errors — large orgs often have tighter per-project quota baselines
- **Seeing `ResourceExhausted`?** Reduce concurrency and check Cloud Console → IAM & Admin → Quotas for the affected API

### Expected scan times

| Projects | Concurrency | Approximate time |
|---|---|---|
| 10 | 4 (default) | ~1 min |
| 50 | 8 | ~3–5 min |
| 100 | 8 | ~6–10 min |
| 100 | 16 | ~3–5 min |

Times vary with API latency. Cloud SQL monitoring queries are the slowest rule per project.

### What `--all-projects` scans

`--all-projects` queries the Resource Manager API and returns all `ACTIVE` projects visible to the service account. It includes projects at any level of your org folder hierarchy.

It does **not** include:
- `INACTIVE`, `DELETE_REQUESTED`, or suspended projects
- Projects outside the org (if using org-level roles)
- Projects where the SA has no access — those are listed as skipped in the scan summary

Projects where Compute Engine or Cloud SQL APIs are disabled are scanned but return no findings for the disabled rules. This is expected — not an error.

---

## Terraform (Optional)

If you manage GCP IAM with Terraform, you can replicate the org-wide setup:

```hcl
# Host project service account
resource "google_service_account" "cleancloud_scanner" {
  project      = var.host_project_id
  account_id   = "cleancloud-scanner"
  display_name = "CleanCloud Read-Only Scanner"
}

# Workload Identity Pool
resource "google_iam_workload_identity_pool" "github_actions" {
  project                   = var.host_project_id
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions Pool"
}

# OIDC Provider
resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.host_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_actions.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub OIDC"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"        = "assertion.sub"
    "attribute.repository"  = "assertion.repository"
  }

  # Restricts to your repo — works for all trigger types (push, PR, schedule, environment).
  # To further restrict to a specific branch: "assertion.repository == '${var.github_repo}' && assertion.sub.startsWith('repo:${var.github_repo}:ref:refs/heads/main')"
  attribute_condition = "assertion.repository == '${var.github_repo}'"
}

# Allow GitHub Actions to impersonate the SA
resource "google_service_account_iam_member" "wif_binding" {
  service_account_id = google_service_account.cleancloud_scanner.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_actions.name}/attribute.repository/${var.github_repo}"
}

# Org-level read-only roles — covers all target projects
locals {
  scanner_roles = [
    "roles/compute.viewer",
    "roles/cloudsql.viewer",
    "roles/monitoring.viewer",
    "roles/browser",
  ]
}

resource "google_organization_iam_member" "cleancloud_scanner" {
  for_each = toset(local.scanner_roles)

  org_id = var.org_id
  role   = each.value
  member = "serviceAccount:${google_service_account.cleancloud_scanner.email}"
}
```

---

## Authentication Methods

CleanCloud uses GCP Application Default Credentials (ADC) — the standard GCP auth chain used by all Google Cloud client libraries.

### 1. Workload Identity Federation (Recommended for CI/CD)

No service account keys. GitHub OIDC tokens are exchanged for short-lived GCP credentials. Covered fully in [Org-Wide Setup](#org-wide-setup) above.

---

### 2. Service Account Key (Not Recommended)

Use only when Workload Identity is not available (e.g., non-GitHub CI systems without OIDC support).

```bash
# Create and download the key
gcloud iam service-accounts keys create cleancloud-key.json \
  --iam-account=cleancloud-scanner@<HOST_PROJECT_ID>.iam.gserviceaccount.com

# Use it
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/cleancloud-key.json
cleancloud scan --provider gcp --all-projects
```

> Service account keys are long-lived credentials. Store them as CI secrets, never commit to source control, and rotate them regularly.

---

### 3. gcloud ADC (Local Development)

```bash
gcloud auth application-default login
cleancloud scan --provider gcp --all-projects
```

> **Local dev only.** ADC uses your personal Google account session and is not suitable for CI/CD — sessions expire in ~1 hour and cannot be non-interactively refreshed. Do not configure ADC in CI alongside Workload Identity Federation; the two auth methods can conflict depending on environment variable state. Use WIF exclusively in CI.

---

### 4. Attached Service Account (GKE / Cloud Run / Compute Engine)

If CleanCloud runs inside GCP (GKE pod, Cloud Run job, Compute Engine VM), it automatically picks up the attached service account. Ensure that service account has the same roles as `cleancloud-scanner`:

```bash
for ROLE in roles/compute.viewer roles/cloudsql.viewer roles/monitoring.viewer roles/browser; do
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --member="serviceAccount:<ATTACHED_SA_EMAIL>" \
    --role="${ROLE}"
done
```

---

## Required Permissions

CleanCloud requires **read-only** IAM permissions only. No write access is needed or used.

| Permission | Used by rule | Predefined role |
|---|---|---|
| `compute.disks.list` | `gcp.compute.disk.unattached` | `roles/compute.viewer` |
| `compute.instances.list` | `gcp.compute.vm.stopped` | `roles/compute.viewer` |
| `compute.addresses.list` | `gcp.compute.ip.unused` | `roles/compute.viewer` |
| `compute.globalAddresses.list` | `gcp.compute.ip.unused` | `roles/compute.viewer` |
| `compute.snapshots.list` | `gcp.compute.snapshot.old` | `roles/compute.viewer` |
| `cloudsql.instances.list` | `gcp.sql.instance.idle` | `roles/cloudsql.viewer` |
| `monitoring.timeSeries.list` | `gcp.sql.instance.idle` | `roles/monitoring.viewer` |
| `resourcemanager.projects.get` | project enumeration (`--all-projects`) | `roles/browser` |

### Graceful Degradation

CleanCloud never fails a scan due to missing permissions. If a permission is absent:

- The affected rule is **skipped** (not failed)
- The missing permission is recorded in `skipped_rules` in the scan output
- All other rules and all other projects continue normally

This means you can run CleanCloud with only the permissions you have — it reports what it found and what it skipped.

---

## Troubleshooting

### `google.auth.exceptions.DefaultCredentialsError`

**Cause:** No credentials found in the ADC chain.

**Fix:**
- Local: run `gcloud auth application-default login`
- CI: ensure `google-github-actions/auth@v2` step ran before `cleancloud scan`
- GKE/Cloud Run: verify the attached service account has the required roles

---

### `PermissionDenied: 403 <permission> denied`

**Cause:** The service account lacks the required role on the target project.

**Fix (project-level — one project):**
```bash
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/compute.viewer"
```

**Fix (org-level — all projects, prevents recurrence):**
```bash
gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/compute.viewer"
```

---

### No projects found with `--all-projects`

**Cause:** The service account cannot enumerate projects — missing `resourcemanager.projects.list` (included in `roles/browser`).

**Fix:**
```bash
gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/browser"
```

Until that's in place, specify projects explicitly:
```bash
cleancloud scan --provider gcp --project proj-1 --project proj-2
```

---

### A project shows 0 findings and no errors

**Cause:** The Compute Engine or Cloud SQL API is not enabled for that project. CleanCloud skips disabled-API rules and continues — this is expected behaviour, not an error.

To confirm:
```bash
gcloud services list --project=<PROJECT_ID> | grep -E "compute|sqladmin"
```

---

### Workload Identity: `INVALID_ARGUMENT` or token exchange fails

**Cause:** The `attribute-condition` doesn't match the GitHub Actions OIDC subject for your workflow trigger.

GitHub sends different subject claims depending on how the workflow runs:

| Workflow trigger | Subject sent |
|---|---|
| Branch push (e.g. `main`) | `repo:<ORG>/<REPO>:ref:refs/heads/main` |
| Pull request | `repo:<ORG>/<REPO>:pull_request` |
| GitHub Environment | `repo:<ORG>/<REPO>:environment:<ENV_NAME>` |
| Schedule | `repo:<ORG>/<REPO>:ref:refs/heads/<DEFAULT_BRANCH>` |

Debug the exact subject your workflow sends:

```yaml
- name: Debug OIDC token subject
  run: |
    curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
         "$ACTIONS_ID_TOKEN_REQUEST_URL" \
      | jq -r '.value' | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.sub'
```

Update the provider condition to match:

```bash
gcloud iam workload-identity-pools providers update-oidc "github" \
  --project="${HOST_PROJECT_ID}" \
  --location="global" \
  --workload-identity-pool="github-actions" \
  --attribute-condition="assertion.repository=='${YOUR_GITHUB_REPO}'"
```

---

### `ResourceExhausted` errors with many projects

**Cause:** GCP API quota exceeded at high concurrency.

**Fix:** Reduce concurrency:
```bash
cleancloud scan --provider gcp --all-projects --concurrency 4
```

Check your quota in Cloud Console → IAM & Admin → Quotas, filtering by the failing API.

---

**Next:** [Detection Rules →](rules.md) | [CI/CD Integration →](ci.md) | [Example Outputs →](example-outputs.md)
