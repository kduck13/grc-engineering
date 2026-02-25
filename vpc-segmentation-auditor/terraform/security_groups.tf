# ─────────────────────────────────────────────────────────────────────────────
# SG-A: SSH open to the entire internet
#
# INTENTIONAL MISCONFIGURATION
# Violates: CIS 5.2, SOC2 CC6.1, ISO 27001 A.9.4.2
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group" "sg_a" {
  name        = "${var.project_name}-sg-a"
  description = "VPC-A security group (intentionally misconfigured)"
  vpc_id      = aws_vpc.vpc_a.id

  ingress {
    description      = "SSH from anywhere - intentional misconfiguration for lab"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-sg-a" }
}

# ─────────────────────────────────────────────────────────────────────────────
# SG-B: SSH and RDP open to the entire internet
#
# INTENTIONAL MISCONFIGURATION
# Violates: CIS 5.2 (SSH), CIS 5.3 (RDP), SOC2 CC6.1, ISO 27001 A.9.4.2
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group" "sg_b" {
  name        = "${var.project_name}-sg-b"
  description = "VPC-B security group (intentionally misconfigured)"
  vpc_id      = aws_vpc.vpc_b.id

  ingress {
    description = "SSH from anywhere - intentional misconfiguration for lab"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere - intentional misconfiguration for lab"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-sg-b" }
}

# ─────────────────────────────────────────────────────────────────────────────
# SG-C: SSH restricted to VPC-A's CIDR - compliant configuration
#
# This is intentionally PASSING so the scanner output demonstrates
# both PASS and FAIL findings.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group" "sg_c" {
  name        = "${var.project_name}-sg-c"
  description = "VPC-C security group (compliant configuration)"
  vpc_id      = aws_vpc.vpc_c.id

  ingress {
    description = "SSH from VPC-A only - least-privilege access control"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.16.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-sg-c" }
}
