output "issuer_url" {
  description = "OIDC issuer URL (CloudFront domain)"
  value       = "https://${aws_cloudfront_distribution.oidc.domain_name}"
}

output "role_arn" {
  description = "IAM role ARN for credctl auth"
  value       = aws_iam_role.credctl.arn
}

output "bucket_name" {
  description = "S3 bucket for OIDC documents"
  value       = aws_s3_bucket.oidc.id
}

output "cloudfront_domain" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.oidc.domain_name
}
