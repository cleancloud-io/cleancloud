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
| AI/ML scan (`--category ai`) | All of the above + `roles/aiplatform.viewer` — see [AI/ML Scanning](#aiml-scanning-vertex-ai) |

All roles are read-only. No create, delete, or modify permissions — ever.

---

### Commands

| Task | Command |
|---|---|
| Scan one project | `cleancloud scan --provider gcp --project <PROJECT_ID>` |
| Scan all accessible projects | `cleancloud scan --provider gcp --all-projects` |
| Scan all projects, higher concurrency | `cleancloud scan --provider gcp --all-projects --concurrency 8` |
| Filter by region | `cleancloud scan --provider gcp --all-projects --region us-central1` |
| AI/ML scan (Vertex AI) | `cleancloud scan --provider gcp --category ai --all-projects` |
| Hygiene + AI together | `cleancloud scan --provider gcp --category all --all-projects` |
| Fail build on HIGH findings | Add `--fail-on-confidence HIGH` to any scan command |
| Fail build if waste ≥ $X/month | Add `--fail-on-cost 500` to any scan command |
| Validate credentials + permissions | `cleancloud doctor --provider gcp --project <PROJECT_ID>` |
| Validate AI permissions | `cleancloud doctor --provider gcp --project <PROJECT_ID> --category ai` |

---

### Org-Wide Setup (3 steps)

> **Using Terraform?** Skip the manual steps — the module at [`deploy/terraform/gcp/`](../deploy/terraform/gcp/) does all three in one `terraform apply`. See [Terraform](#terraform-recommended-for-teams).

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
> The service account lives in the host project but scans target projects. Unlike AWS (where you deploy a role to each spoke account), GCP uses a single org-level IAM binding that covers all existing and future projects in your org automatically — no per-project setup needed.

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

**Enable required APIs on the host project** *(one-time)*:

```bash
gcloud services enable iamcredentials.googleapis.com --project=<HOST_PROJECT_ID>
```

> `iamcredentials.googleapis.com` (IAM Service Account Credentials API) is required for Workload Identity Federation token exchange. Without it, CI fails at credential acquisition with a `403 SERVICE_DISABLED` error even if all IAM bindings are correct.

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
> **Multi-trigger workflows** (branch push + PR + schedule): `assertion.repository=='${YOUR_GITHUB_REPO}'` covers all of these — it checks the repo name, not the trigger type. The default shown above is correct for most setups.
>
> ⚠️ **GitHub Environment workflows:** If your workflow uses `environment: production`, GitHub sends a subject like `repo:<ORG>/<REPO>:environment:production`. The repository-based condition still matches, but if you use a *subject-based* condition (e.g. `assertion.sub.startsWith('...:ref:refs/heads/main')`), it will reject environment triggers with `INVALID_ARGUMENT`. If you're seeing token exchange failures only on environment-triggered runs, this is the cause — see [Workload Identity: INVALID_ARGUMENT](#workload-identity-invalid_argument-or-token-exchange-fails) in Troubleshooting.

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

To grant access to multiple projects at once without org-level IAM:

```bash
for PROJECT_ID in proj-1 proj-2 proj-3; do
  for ROLE in roles/compute.viewer roles/cloudsql.viewer roles/monitoring.viewer; do
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
      --member="serviceAccount:${SA_EMAIL}" \
      --role="${ROLE}"
  done
done
```

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

### Output files

When using `--output-file`, the JSON file is written to the current working directory of the process:
- **Locally:** the directory where you ran `cleancloud scan`
- **GitHub Actions:** the runner workspace (e.g. `/home/runner/work/<repo>/<repo>/gcp-findings.json`) — use `actions/upload-artifact` to persist it beyond the run (see [Step 3](#step-3-configure-github-actions) workflow above)

### What `--all-projects` scans

`--all-projects` queries the Resource Manager API and returns all `ACTIVE` projects visible to the service account. It includes projects at any level of your org folder hierarchy.

It does **not** include:
- `INACTIVE`, `DELETE_REQUESTED`, or suspended projects
- Projects outside the org (if using org-level roles)
- Projects where the SA has no access — those are listed as skipped in the scan summary

Projects where Compute Engine or Cloud SQL APIs are disabled are scanned but return no findings for the disabled rules. This is expected — not an error.

---

## Terraform (Recommended for Teams)

A ready-made Terraform module ships with CleanCloud at [`deploy/terraform/gcp/`](../deploy/terraform/gcp/).

It creates everything from [Org-Wide Setup](#org-wide-setup) in one `terraform apply`:
- Service account in the host project
- Enables `iamcredentials.googleapis.com` and `cloudresourcemanager.googleapis.com`
- Org-level IAM bindings (or project-level if no `organization_id` is set)
- Workload Identity Federation pool + GitHub OIDC provider

**Usage:**

```bash
cd deploy/terraform/gcp

terraform init

terraform apply \
  -var="project_id=cleancloud-hub" \
  -var="organization_id=<YOUR_ORG_ID>" \
  -var="github_repo=<ORG>/<REPO>"
```

**Outputs** — copy these directly into GitHub Actions secrets/variables:

```
service_account_email        → GCP_SERVICE_ACCOUNT secret
workload_identity_provider   → GCP_WORKLOAD_IDENTITY_PROVIDER secret
project_id                   → CLEANCLOUD_GCP_TEST_PROJECT variable
iam_scope                    → confirms org or project level
```

**Single-project** (no org access): omit `organization_id` — IAM roles are bound to `project_id` only. New projects will **not** be covered automatically; you must re-run Terraform for each additional project.

```bash
terraform apply \
  -var="project_id=my-target-project" \
  -var="github_repo=<ORG>/<REPO>"
```

> ⚠️ The Terraform identity running `terraform apply` must have `roles/iam.organizationRoleAdmin` (or equivalent) at the org or folder level to bind IAM. If you omit `organization_id`, project-level `roles/owner` or `roles/resourcemanager.projectIamAdmin` on the target project is sufficient.

**Without Workload Identity** (non-GitHub CI):

```bash
terraform apply \
  -var="project_id=cleancloud-hub" \
  -var="organization_id=<YOUR_ORG_ID>" \
  -var="github_repo=" \
  -var="enable_workload_identity=false"
```

Then [create a service account key](#2-service-account-key-not-recommended) manually for your CI system.

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

If CleanCloud runs inside GCP (GKE pod, Cloud Run job, Compute Engine VM), it automatically picks up the attached service account. Ensure that service account has the same roles as `cleancloud-scanner`.

**Org-wide (scans all projects):**

```bash
for ROLE in roles/compute.viewer roles/cloudsql.viewer roles/monitoring.viewer roles/browser; do
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --member="serviceAccount:<ATTACHED_SA_EMAIL>" \
    --role="${ROLE}"
done
```

> If the attached service account only has project-level IAM (not org-level), replace `gcloud organizations add-iam-policy-binding` with `gcloud projects add-iam-policy-binding <PROJECT_ID>` for each project you want to scan. `--all-projects` will only return projects the SA can enumerate via `roles/browser`.

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
| `monitoring.timeSeries.list` | `gcp.sql.instance.idle`, `gcp.vertex.endpoint.idle` | `roles/monitoring.viewer` |
| `resourcemanager.projects.get` | project enumeration (`--all-projects`) | `roles/browser` |

### Graceful Degradation

CleanCloud never fails a scan due to missing permissions. If a permission is absent:

- The affected rule is **skipped** (not failed)
- The missing permission is recorded in `skipped_rules` in the scan output
- All other rules and all other projects continue normally

This means you can run CleanCloud with only the permissions you have — it reports what it found and what it skipped.

---

## AI/ML Scanning (Vertex AI)

Detect idle Vertex AI Online Prediction endpoints — deployed models with `minReplicaCount > 0` that keep dedicated compute running 24/7 with zero prediction traffic. GPU-backed endpoints (T4, V100, A100, L4, H100) cost $300–$8K/month per GPU and are the highest-cost idle resource type in most GCP AI workloads.

AI scanning is **opt-in** — it requires an extra role and runs separately from hygiene scanning.

```bash
# Demo — see what this rule finds (no credentials needed)
cleancloud demo --provider gcp --category ai

# Validate permissions first
cleancloud doctor --provider gcp --project <PROJECT_ID> --category ai

# Run the AI scan
cleancloud scan --provider gcp --category ai --all-projects

# Hygiene + AI together
cleancloud scan --provider gcp --category all --all-projects
```

### Required Permission

One additional role beyond the hygiene roles:

| Role | What it grants |
|---|---|
| `roles/aiplatform.viewer` | `aiplatform.endpoints.list` + `aiplatform.endpoints.get` |

`roles/monitoring.viewer` is already required for hygiene rules — no additional grant needed.

**Grant at organization level** (covers all current and future projects):
```bash
gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/aiplatform.viewer"
```

**Grant at project level** (single project only):
```bash
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/aiplatform.viewer"
```

The full role definition is in [`security/gcp/ai-readonly-roles.json`](../security/gcp/ai-readonly-roles.json).

### Enable the Vertex AI API

The Vertex AI API must be enabled in each project you want to scan. Projects with the API disabled return 0 findings (the rule is skipped automatically — not an error):

```bash
gcloud services enable aiplatform.googleapis.com --project="${PROJECT_ID}"
```

### What Gets Flagged

| Condition | Flagged |
|---|---|
| `dedicatedResources.minReplicaCount > 0` + zero predictions for 14 days | Yes |
| `automaticResources` (scales to zero when idle) | No — no idle billing |
| Endpoint with predictions in the last 14 days | No |
| Endpoint younger than 7 days | No — too new to classify |

### Confidence and Risk

- **HIGH confidence:** Zero predictions for the full 14-day window (endpoint ≥ 14 days old)
- **MEDIUM confidence:** Zero predictions, endpoint 10–14 days old, or age unknown
- **HIGH risk:** GPU-backed endpoint (NVIDIA_TESLA_T4, V100, A100, L4, H100, TPU)
- **MEDIUM risk:** CPU-only endpoint

### Validate Before Running

```bash
cleancloud doctor --provider gcp --project <PROJECT_ID> --category ai
```

Output confirms:
- `aiplatform.endpoints.list` — required for scanning
- `monitoring.timeSeries.list` — required for idle detection metrics
- Which projects have the Vertex AI API enabled

---

## Troubleshooting

### `403 IAM Service Account Credentials API has not been used` / `SERVICE_DISABLED`

**Cause:** The IAM Service Account Credentials API (`iamcredentials.googleapis.com`) is not enabled on the host project. This API is required for Workload Identity Federation token exchange — it's not enabled by default on new projects.

**Fix:**
```bash
gcloud services enable iamcredentials.googleapis.com --project=<HOST_PROJECT_ID>
```

Wait ~1 minute for the change to propagate, then re-run.

---

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
