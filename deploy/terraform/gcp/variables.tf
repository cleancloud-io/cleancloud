variable "project_id" {
  type        = string
  description = "Host GCP project where the service account and Workload Identity pool are created."
}

variable "organization_id" {
  type        = string
  default     = ""
  description = <<-EOT
    GCP Organization ID for org-level IAM bindings (recommended for multi-project scanning).
    If omitted, IAM roles are bound at the project level only — scanning is limited to
    the single project specified by project_id.
    Find yours: gcloud organizations list
  EOT
}

variable "service_account_name" {
  type        = string
  default     = "cleancloud-scanner"
  description = "Name of the GCP service account to create."
}

variable "github_repo" {
  type        = string
  default     = ""
  description = <<-EOT
    GitHub repository in 'owner/repo' format (e.g. 'myorg/myrepo').
    Required when enable_workload_identity = true.
    Used as the attribute condition for the Workload Identity binding.
  EOT
}

variable "workload_identity_pool_id" {
  type        = string
  default     = "github-actions"
  description = "ID of the Workload Identity pool to create."
}

variable "workload_identity_provider_id" {
  type        = string
  default     = "github"
  description = "ID of the Workload Identity provider within the pool."
}

variable "enable_workload_identity" {
  type        = bool
  default     = true
  description = "Create a Workload Identity Federation pool and GitHub OIDC provider for keyless CI/CD auth."
}

variable "labels" {
  type        = map(string)
  default     = {}
  description = "Additional labels to apply to the service account."
}
