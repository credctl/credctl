variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "device_fingerprint" {
  description = "Device fingerprint (sub claim) from 'credctl status'"
  type        = string
}

variable "issuer_url" {
  description = "OIDC issuer URL (e.g. CloudFront domain from AWS setup)"
  type        = string
}

variable "service_account_id" {
  description = "Service account ID to create for credctl"
  type        = string
  default     = "credctl-device"
}

variable "service_account_roles" {
  description = "List of IAM roles to grant to the service account"
  type        = list(string)
}

variable "pool_id" {
  description = "Workload Identity Pool ID"
  type        = string
  default     = "credctl-pool"
}

variable "provider_id" {
  description = "Workload Identity Provider ID"
  type        = string
  default     = "credctl-provider"
}
