# ─────────────────────────────────────────────────────────────────────────────
# AWS Config: Delivery infrastructure
#
# Config requires an S3 bucket to deliver configuration snapshots and
# compliance history. The recorder must be running before rules can evaluate.
# Cost note: ~$0.003 per configuration item recorded. Destroy when done.
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
# These run continuously and evaluate against the same misconfigs the Python
# scanner checks at a point in time. The overlap is intentional — it teaches
# the difference between continuous monitoring and on-demand auditing.
# ─────────────────────────────────────────────────────────────────────────────

# CIS 2.9: VPC Flow Logs must be enabled
resource "aws_config_config_rule" "vpc_flow_logs_enabled" {
  name = "${var.project_name}-vpc-flow-logs-enabled"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

# CIS 5.2: No SSH from 0.0.0.0/0
resource "aws_config_config_rule" "restricted_ssh" {
  name = "${var.project_name}-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({ blockedPort1 = "22" })

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

# CIS 5.3: No RDP from 0.0.0.0/0
resource "aws_config_config_rule" "restricted_rdp" {
  name = "${var.project_name}-restricted-rdp"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({ blockedPort1 = "3389" })

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

# CIS 1.16: No IAM policies with admin-level wildcard access
resource "aws_config_config_rule" "iam_no_admin_access" {
  name = "${var.project_name}-iam-no-admin-access"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

# Additional: EC2 instances should not have public IPs
# The lab instances DO have public IPs — this rule will flag them.
resource "aws_config_config_rule" "ec2_no_public_ip" {
  name = "${var.project_name}-ec2-no-public-ip"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder]
}
