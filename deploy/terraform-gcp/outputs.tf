output "project_number" {
  description = "GCP project number"
  value       = data.google_project.current.number
}

output "pool_id" {
  description = "Workload Identity Pool ID"
  value       = google_iam_workload_identity_pool.credctl.workload_identity_pool_id
}

output "provider_id" {
  description = "Workload Identity Provider ID"
  value       = google_iam_workload_identity_pool_provider.credctl.workload_identity_pool_provider_id
}

output "provider_name" {
  description = "Workload Identity Provider full resource name"
  value       = google_iam_workload_identity_pool_provider.credctl.name
}

output "service_account_email" {
  description = "Service account email for credctl config"
  value       = google_service_account.credctl.email
}

output "audience" {
  description = "Audience value for credctl GCP config"
  value       = "//iam.googleapis.com/${google_iam_workload_identity_pool.credctl.name}/providers/${var.provider_id}"
}
