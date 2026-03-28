terraform {
  required_version = ">= 1.3"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

locals {
  sa_email    = "${var.service_account_name}@${var.project_id}.iam.gserviceaccount.com"
  org_binding = var.organization_id != ""
  sa_member   = "serviceAccount:${local.sa_email}"

  # Roles required for CleanCloud read-only scanning
  # - compute.viewer:    disk, IP, snapshot, VM rules
  # - cloudsql.viewer:   Cloud SQL idle rule
  # - monitoring.viewer: Cloud SQL connection metrics
  # - browser:           resourcemanager.projects.get (needed for --all-projects)
  required_roles = [
    "roles/compute.viewer",
    "roles/cloudsql.viewer",
    "roles/monitoring.viewer",
    "roles/browser",
  ]
}

# ── Enable required APIs on the host project ─────────────────────────────────

resource "google_project_service" "resource_manager" {
  project            = var.project_id
  service            = "cloudresourcemanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam_credentials" {
  project            = var.project_id
  service            = "iamcredentials.googleapis.com"
  disable_on_destroy = false
}

# ── Service account ───────────────────────────────────────────────────────────

resource "google_service_account" "cleancloud" {
  project      = var.project_id
  account_id   = var.service_account_name
  display_name = "CleanCloud read-only scanner"
  description  = "Used by CleanCloud to scan GCP resources. Read-only."
}

# ── IAM bindings — org-level (recommended: covers all projects) ───────────────

resource "google_organization_iam_member" "cleancloud" {
  for_each = local.org_binding ? toset(local.required_roles) : toset([])

  org_id = var.organization_id
  role   = each.value
  member = local.sa_member

  depends_on = [google_service_account.cleancloud]
}

# ── IAM bindings — project-level fallback (single project only) ───────────────
# Used when organization_id is not provided. Scanning is limited to project_id.

resource "google_project_iam_member" "cleancloud" {
  for_each = local.org_binding ? toset([]) : toset(local.required_roles)

  project = var.project_id
  role    = each.value
  member  = local.sa_member

  depends_on = [google_service_account.cleancloud]
}

# ── Workload Identity Federation (keyless GitHub Actions auth) ────────────────

resource "google_iam_workload_identity_pool" "github" {
  count = var.enable_workload_identity ? 1 : 0

  project                   = var.project_id
  workload_identity_pool_id = var.workload_identity_pool_id
  display_name              = "GitHub Actions"
  description               = "Workload Identity pool for CleanCloud GitHub Actions"

  depends_on = [google_project_service.iam_credentials]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  count = var.enable_workload_identity ? 1 : 0

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github[0].workload_identity_pool_id
  workload_identity_pool_provider_id = var.workload_identity_provider_id
  display_name                       = "GitHub OIDC"
  description                        = "GitHub Actions OIDC provider for CleanCloud"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
  }

  # Restrict token exchange to the specified GitHub repository.
  # Covers all trigger types: push, pull_request, schedule, workflow_dispatch.
  attribute_condition = var.github_repo != "" ? "assertion.repository=='${var.github_repo}'" : null

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Grant the service account permission to be impersonated via the WIF pool
resource "google_service_account_iam_member" "wif_binding" {
  count = var.enable_workload_identity ? 1 : 0

  service_account_id = google_service_account.cleancloud.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.repository/${var.github_repo}"
}
