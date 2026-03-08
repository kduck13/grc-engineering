# ─────────────────────────────────────────────────────────────────────────────
# AWS Config: Delivery infrastructure
#
# Same pattern as vpc-segmentation-auditor. Config requires an S3 bucket
# for snapshots and a running recorder before rules can evaluate resources.
#
# IMPORTANT: AWS only allows ONE Config recorder per region per account.
# If vpc-segmentation-auditor is still deployed, terraform apply will fail
# on the recorder resource. Destroy the previous lab first.
#
# Cost: ~$0.003 per configuration item recorded. Destroy when done.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "config_delivery" {
  bucket        = "${var.project_name}-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = { Name = "${var.project_name}-config-delivery" }
}

resource "aws_s3_bucket_public_access_block" "config_delivery" {
  bucket                  = aws_s3_bucket.config_delivery.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config_delivery.arn
      },
      {
        Sid       = "AWSConfigBucketExistenceCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.config_delivery.arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config_delivery.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# AWS Config: Recorder and IAM role
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "config_role" {
  name = "${var.project_name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_role" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "recorder" {
  name     = "${var.project_name}-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "delivery" {
  name           = "${var.project_name}-delivery"
  s3_bucket_name = aws_s3_bucket.config_delivery.bucket

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_configuration_recorder_status" "recorder" {
  name       = aws_config_configuration_recorder.recorder.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.delivery]
}

# ─────────────────────────────────────────────────────────────────────────────
# AWS Config: Managed rules
#
# These provide CONTINUOUS compliance evaluation — they re-run automatically
# as resources change. The Python scanner provides POINT-IN-TIME auditing.
# Both approaches have value; the combination demonstrates full coverage.
# ─────────────────────────────────────────────────────────────────────────────

# CIS 2.3.1: EBS default encryption should be enabled at account level
# This will evaluate as NON_COMPLIANT because we intentionally leave it off.
resource "aws_config_config_rule" "ebs_encryption_by_default" {
  name        = "${var.project_name}-ebs-encryption-by-default"
  description = "CIS 2.3.1 | SOC2 CC6.1 | ISO A.10.1.1 — EBS encryption must be enabled by default at the account level."

  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

# CIS 2.3.1 (supplementary): All EBS volumes must be encrypted
# Catches volumes that existed before account-level default was enabled.
resource "aws_config_config_rule" "encrypted_volumes" {
  name        = "${var.project_name}-encrypted-volumes"
  description = "CIS 2.3.1 | PCI DSS 3.4 | HIPAA — EBS volumes must be encrypted at rest."

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder]
}
