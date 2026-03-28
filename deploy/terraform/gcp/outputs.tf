output "service_account_email" {
  description = "Email of the CleanCloud service account. Set as GCP_SERVICE_ACCOUNT in GitHub Actions secrets."
  value       = google_service_account.cleancloud.email
}

output "workload_identity_provider" {
  description = <<-EOT
    Full resource name of the Workload Identity provider.
    Set as GCP_WORKLOAD_IDENTITY_PROVIDER in GitHub Actions secrets.
    Format: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID
  EOT
  value       = var.enable_workload_identity ? google_iam_workload_identity_pool_provider.github[0].name : null
}

output "project_id" {
  description = "Host project ID. Set as CLEANCLOUD_GCP_TEST_PROJECT in GitHub Actions variables."
  value       = var.project_id
}

output "iam_scope" {
  description = "Indicates whether IAM roles were bound at org or project level."
  value       = local.org_binding ? "organization (${var.organization_id})" : "project (${var.project_id})"
}
