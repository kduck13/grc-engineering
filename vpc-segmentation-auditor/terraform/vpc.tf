# ─────────────────────────────────────────────────────────────────────────────
# VPC A — "production" (10.16.0.0/16)
#
# INTENTIONAL MISCONFIGURATION: No VPC Flow Logs
# Violates: CIS 2.9, SOC2 CC6.6, ISO 27001 A.12.4.1
# The scanner's check_vpc_flow_logs() will detect this.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_vpc" "vpc_a" {
  cidr_block           = "10.16.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc-a"
    Role = "production"
  }
}

resource "aws_subnet" "subnet_a" {
  vpc_id                  = aws_vpc.vpc_a.id
  cidr_block              = "10.16.0.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-subnet-a" }
}

resource "aws_internet_gateway" "igw_a" {
  vpc_id = aws_vpc.vpc_a.id
  tags   = { Name = "${var.project_name}-igw-a" }
}

resource "aws_route_table" "rt_a" {
  vpc_id = aws_vpc.vpc_a.id
  tags   = { Name = "${var.project_name}-rt-a" }
}

resource "aws_route" "rt_a_igw" {
  route_table_id         = aws_route_table.rt_a.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw_a.id
}

resource "aws_route_table_association" "rta_a" {
  subnet_id      = aws_subnet.subnet_a.id
  route_table_id = aws_route_table.rt_a.id
}

# ─────────────────────────────────────────────────────────────────────────────
# VPC B — "development" (10.17.0.0/16)
#
# INTENTIONAL MISCONFIGURATION: No VPC Flow Logs
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_vpc" "vpc_b" {
  cidr_block           = "10.17.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc-b"
    Role = "development"
  }
}

resource "aws_subnet" "subnet_b" {
  vpc_id                  = aws_vpc.vpc_b.id
  cidr_block              = "10.17.0.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-subnet-b" }
}

resource "aws_internet_gateway" "igw_b" {
  vpc_id = aws_vpc.vpc_b.id
  tags   = { Name = "${var.project_name}-igw-b" }
}

resource "aws_route_table" "rt_b" {
  vpc_id = aws_vpc.vpc_b.id
  tags   = { Name = "${var.project_name}-rt-b" }
}

resource "aws_route" "rt_b_igw" {
  route_table_id         = aws_route_table.rt_b.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw_b.id
}

resource "aws_route_table_association" "rta_b" {
  subnet_id      = aws_subnet.subnet_b.id
  route_table_id = aws_route_table.rt_b.id
}

# ─────────────────────────────────────────────────────────────────────────────
# VPC C — "shared services" (10.18.0.0/16)
#
# INTENTIONAL MISCONFIGURATION: No VPC Flow Logs
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_vpc" "vpc_c" {
  cidr_block           = "10.18.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc-c"
    Role = "shared-services"
  }
}

resource "aws_subnet" "subnet_c" {
  vpc_id                  = aws_vpc.vpc_c.id
  cidr_block              = "10.18.0.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-subnet-c" }
}

resource "aws_internet_gateway" "igw_c" {
  vpc_id = aws_vpc.vpc_c.id
  tags   = { Name = "${var.project_name}-igw-c" }
}

resource "aws_route_table" "rt_c" {
  vpc_id = aws_vpc.vpc_c.id
  tags   = { Name = "${var.project_name}-rt-c" }
}

resource "aws_route" "rt_c_igw" {
  route_table_id         = aws_route_table.rt_c.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw_c.id
}

resource "aws_route_table_association" "rta_c" {
  subnet_id      = aws_subnet.subnet_c.id
  route_table_id = aws_route_table.rt_c.id
}
