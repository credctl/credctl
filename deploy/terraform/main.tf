terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}

# S3 bucket for OIDC discovery documents
resource "aws_s3_bucket" "oidc" {
  bucket_prefix = "credctl-oidc-"
  tags          = var.tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "oidc" {
  bucket = aws_s3_bucket.oidc.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "oidc" {
  bucket = aws_s3_bucket.oidc.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudFront Origin Access Control
resource "aws_cloudfront_origin_access_control" "oidc" {
  name                              = "credctl-oidc-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront distribution
resource "aws_cloudfront_distribution" "oidc" {
  enabled         = true
  comment         = "credctl OIDC discovery"
  http_version    = "http2"
  is_ipv6_enabled = true

  origin {
    domain_name              = aws_s3_bucket.oidc.bucket_regional_domain_name
    origin_id                = "s3-oidc"
    origin_access_control_id = aws_cloudfront_origin_access_control.oidc.id
  }

  default_cache_behavior {
    target_origin_id       = "s3-oidc"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    cache_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = var.tags
}

# S3 bucket policy — allow CloudFront OAC
resource "aws_s3_bucket_policy" "oidc" {
  bucket = aws_s3_bucket.oidc.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontOAC"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.oidc.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/${aws_cloudfront_distribution.oidc.id}"
          }
        }
      }
    ]
  })
}

# IAM OIDC provider
resource "aws_iam_openid_connect_provider" "credctl" {
  url             = "https://${aws_cloudfront_distribution.oidc.domain_name}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["0000000000000000000000000000000000000000"]

  tags = var.tags
}

# IAM role with trust policy
resource "aws_iam_role" "credctl" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.credctl.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${aws_cloudfront_distribution.oidc.domain_name}:aud" = "sts.amazonaws.com"
            "${aws_cloudfront_distribution.oidc.domain_name}:sub" = var.device_fingerprint
          }
        }
      }
    ]
  })

  tags = var.tags
}

# Attach managed policies
resource "aws_iam_role_policy_attachment" "credctl" {
  count      = length(var.role_policy_arns)
  role       = aws_iam_role.credctl.name
  policy_arn = var.role_policy_arns[count.index]
}
