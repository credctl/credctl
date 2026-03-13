terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

data "google_project" "current" {
  project_id = var.project_id
}

# Workload Identity Pool
resource "google_iam_workload_identity_pool" "credctl" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "credctl Device Identity Pool"
  description               = "Workload Identity Pool for credctl Secure Enclave device identities"
}

# OIDC Provider in the pool
resource "google_iam_workload_identity_pool_provider" "credctl" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.credctl.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id
  display_name                       = "credctl OIDC Provider"

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }

  oidc {
    issuer_uri        = var.issuer_url
    allowed_audiences = ["//iam.googleapis.com/${google_iam_workload_identity_pool.credctl.name}/providers/${var.provider_id}"]
  }
}

# Service account for credctl to impersonate
resource "google_service_account" "credctl" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "credctl Device Service Account"
  description  = "Service account impersonated by credctl via Workload Identity Federation"
}

# Allow the device identity to impersonate the service account
resource "google_service_account_iam_member" "credctl_workload_identity" {
  service_account_id = google_service_account.credctl.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.credctl.name}/subject/${var.device_fingerprint}"
}

# Grant roles to the service account
resource "google_project_iam_member" "credctl" {
  count   = length(var.service_account_roles)
  project = var.project_id
  role    = var.service_account_roles[count.index]
  member  = "serviceAccount:${google_service_account.credctl.email}"
}
