# ─────────────────────────────────────────────────────────────────────────────
# KMS: Customer-Managed Key (CMK) for EBS encryption
#
# GRC context: Two types of KMS keys exist in AWS:
#
#   1. AWS-managed keys (e.g. alias/aws/ebs) — created and rotated by AWS.
#      You cannot control the key policy, cannot audit key usage in detail,
#      and cannot revoke access independently of IAM. For regulated workloads,
#      this is often insufficient.
#
#   2. Customer-managed keys (CMK) — you create and own them. You control:
#      - Who can use the key (key policy + grants)
#      - Key rotation schedule (enable_key_rotation = true → annual auto-rotation)
#      - Deletion timeline (deletion_window_in_days — gives you a recovery window)
#      - CloudTrail audit trail for every encrypt/decrypt call
#
# Compliance requirements that mandate CMKs:
#   CIS AWS Foundations Benchmark 3.8 — KMS rotation enabled
#   PCI DSS 3.6.4 — periodic key changes
#   ISO 27001 A.10.1.2 — key management
#   HIPAA — encryption key management with audit capability
#
# Cost: $1/month per key, prorated daily. Destroy after the lab.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_kms_key" "ebs_lab_key" {
  description             = "CMK for EBS encryption — GRC lab demonstrating CMK vs aws/ebs default key"
  deletion_window_in_days = 7    # Minimum window; gives recovery period if key deleted accidentally
  enable_key_rotation     = true # CIS 3.8: annual automatic key rotation

  tags = {
    Name = "${var.project_name}-ebs-cmk"
  }
}

# Aliases make keys human-readable in the console and in policy references.
# format: alias/<name> — the alias/ prefix is required.
resource "aws_kms_alias" "ebs_lab_key" {
  name          = "alias/${var.project_name}-ebs"
  target_key_id = aws_kms_key.ebs_lab_key.key_id
}
