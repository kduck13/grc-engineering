output "vpc_ids" {
  description = "IDs of the three lab VPCs — pass to scanner with --vpc-ids"
  value       = [aws_vpc.vpc_a.id, aws_vpc.vpc_b.id, aws_vpc.vpc_c.id]
}

output "sg_ids" {
  description = "IDs of the three security groups — pass to scanner with --sg-ids"
  value       = [aws_security_group.sg_a.id, aws_security_group.sg_b.id, aws_security_group.sg_c.id]
}

output "peering_ids" {
  description = "IDs of the two peering connections — pass to scanner with --peering-ids"
  value       = [aws_vpc_peering_connection.ab.id, aws_vpc_peering_connection.bc.id]
}

output "ec2_role_name" {
  description = "Name of the EC2 IAM role to audit — pass to scanner with --role-name"
  value       = aws_iam_role.ec2_role.name
}

output "region" {
  description = "Deployment region"
  value       = var.region
}
