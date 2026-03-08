output "instance_ids" {
  description = "IDs of all lab EC2 instances — pass to scanner with --instance-ids"
  value = [
    aws_instance.ec2_compliant.id,
    aws_instance.ec2_noncompliant.id,
  ]
}

output "volume_ids" {
  description = "IDs of all lab EBS volumes (including root volumes) — pass to scanner with --volume-ids"
  value = [
    aws_instance.ec2_compliant.root_block_device[0].volume_id,
    aws_instance.ec2_noncompliant.root_block_device[0].volume_id,
    aws_ebs_volume.data_compliant.id,
    aws_ebs_volume.unattached_unencrypted.id,
    aws_ebs_volume.default_key_encrypted.id,
  ]
}

output "kms_key_arn" {
  description = "ARN of the lab customer-managed KMS key — used by scanner to distinguish CMK vs aws/ebs key"
  value       = aws_kms_key.ebs_lab_key.arn
}

output "account_id" {
  description = "AWS account ID — used by scanner to scope snapshot ownership checks"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "Deployment region"
  value       = var.region
}
