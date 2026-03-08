# ─────────────────────────────────────────────────────────────────────────────
# AMI: Latest Amazon Linux 2023
# ─────────────────────────────────────────────────────────────────────────────

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# COMPLIANT: Instance with encrypted root + data volumes (CMK)
#
# This is the target state: every volume encrypted with a customer-managed key.
# The scanner should produce PASS findings for this instance.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_instance" "ec2_compliant" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro" # Free tier eligible (750 hrs/month)
  subnet_id     = tolist(data.aws_subnets.default.ids)[0]

  root_block_device {
    volume_size = 8
    encrypted   = true
    kms_key_id  = aws_kms_key.ebs_lab_key.arn

    tags = { Name = "${var.project_name}-compliant-root" }
  }

  tags = {
    Name               = "${var.project_name}-compliant"
    DataClassification = "Internal"
  }
}

# Additional encrypted data volume attached to the compliant instance.
resource "aws_ebs_volume" "data_compliant" {
  availability_zone = aws_instance.ec2_compliant.availability_zone
  size              = 1
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs_lab_key.arn

  tags = {
    Name               = "${var.project_name}-data-compliant"
    DataClassification = "Internal"
  }
}

resource "aws_volume_attachment" "data_compliant" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data_compliant.id
  instance_id = aws_instance.ec2_compliant.id
}

# ─────────────────────────────────────────────────────────────────────────────
# NONCOMPLIANT: Instance with unencrypted root volume
#
# INTENTIONAL MISCONFIGURATION — the scanner must find this.
# A running instance with unencrypted storage means data written to disk
# is readable if the underlying physical media is ever recovered or reused.
# Compliance frameworks (PCI DSS 3.4, HIPAA, CIS 2.3.1) require encryption.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_instance" "ec2_noncompliant" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"
  subnet_id     = tolist(data.aws_subnets.default.ids)[0]

  root_block_device {
    volume_size = 8
    encrypted   = false # INTENTIONAL: scanner should flag this as FAIL

    tags = { Name = "${var.project_name}-noncompliant-root" }
  }

  tags = {
    Name               = "${var.project_name}-noncompliant"
    DataClassification = "Confidential" # High sensitivity, unencrypted — bad.
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# UNATTACHED: Unencrypted standalone EBS volume
#
# INTENTIONAL MISCONFIGURATION — unattached volumes are still a risk.
# If the volume is later attached to an instance or shared as a snapshot,
# the data is exposed. Many orgs forget about unattached volumes — this
# check catches orphaned storage that slipped through policy enforcement.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_ebs_volume" "unattached_unencrypted" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  encrypted         = false # INTENTIONAL: unattached, unencrypted

  tags = {
    Name               = "${var.project_name}-unattached-unencrypted"
    DataClassification = "Confidential"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# WARNING CASE: Volume encrypted with the default AWS-managed key (not CMK)
#
# Encrypted, but not with a customer-managed key. Many orgs consider this
# a WARNING-level finding: you have encryption but lack key ownership,
# audit capability, and rotation control. The scanner flags this as WARNING.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_ebs_volume" "default_key_encrypted" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  encrypted         = true
  # No kms_key_id — AWS uses the default aws/ebs managed key for this region.

  tags = {
    Name               = "${var.project_name}-default-key"
    DataClassification = "Internal"
  }
}
