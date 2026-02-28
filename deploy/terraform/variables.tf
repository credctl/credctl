variable "device_fingerprint" {
  description = "Device fingerprint (sub claim) from 'credctl status'"
  type        = string
}

variable "role_name" {
  description = "Name of the IAM role to create"
  type        = string
  default     = "credctl-device-role"
}

variable "role_policy_arns" {
  description = "List of managed policy ARNs to attach to the role"
  type        = list(string)
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
