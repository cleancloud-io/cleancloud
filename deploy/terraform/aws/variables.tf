variable "hub_account_id" {
  type        = string
  description = "AWS account ID where CleanCloud runs (the hub/scanner account)."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.hub_account_id))
    error_message = "hub_account_id must be a 12-digit AWS account ID."
  }
}

variable "role_name" {
  type        = string
  default     = "CleanCloudReadOnlyRole"
  description = "Name of the IAM role to create. Must match --role-name flag in CleanCloud."
}

variable "external_id" {
  type        = string
  default     = ""
  description = "Optional. If set, adds an ExternalId condition to the trust policy (confused deputy protection). Pass the same value via --external-id in CleanCloud."
}

variable "enable_ai" {
  type        = bool
  default     = false
  description = "Attach the AI/ML policy (SageMaker idle endpoint detection). Required for: cleancloud scan --category ai. See: security/aws/ai-readonly.json"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags to apply to the IAM role."
}
