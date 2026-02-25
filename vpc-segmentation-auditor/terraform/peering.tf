# ─────────────────────────────────────────────────────────────────────────────
# Peering: VPC-A <-> VPC-B
#
# INTENTIONAL MISCONFIGURATION: No authorization tags.
# Every peering connection is a deliberate decision to cross a network boundary.
# That decision needs an audit trail: who approved it, and why?
# Violates: ISO 27001 A.13.1.3, SOC2 CC6.1
# The scanner's check_peering_authorization_tags() will detect this.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_vpc_peering_connection" "ab" {
  vpc_id      = aws_vpc.vpc_a.id
  peer_vpc_id = aws_vpc.vpc_b.id
  auto_accept = true

  # Required authorization tags are intentionally absent:
  #   Purpose   = "what business requirement justifies this connection?"
  #   ApprovedBy = "who approved this boundary crossing?"

  tags = { Name = "${var.project_name}-peering-a-b" }
}

resource "aws_route" "a_to_b" {
  route_table_id            = aws_route_table.rt_a.id
  destination_cidr_block    = "10.17.0.0/16"
  vpc_peering_connection_id = aws_vpc_peering_connection.ab.id
}

resource "aws_route" "b_to_a" {
  route_table_id            = aws_route_table.rt_b.id
  destination_cidr_block    = "10.16.0.0/16"
  vpc_peering_connection_id = aws_vpc_peering_connection.ab.id
}

# ─────────────────────────────────────────────────────────────────────────────
# Peering: VPC-B <-> VPC-C
#
# INTENTIONAL MISCONFIGURATION: No authorization tags (same issue as above).
#
# Note: VPC-A and VPC-C are NOT directly peered.
# Even though A<->B and B<->C exist, traffic cannot flow A→B→C.
# VPC peering is non-transitive — this is a core architectural constraint
# that makes every peering connection an explicit authorization decision.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_vpc_peering_connection" "bc" {
  vpc_id      = aws_vpc.vpc_b.id
  peer_vpc_id = aws_vpc.vpc_c.id
  auto_accept = true

  tags = { Name = "${var.project_name}-peering-b-c" }
}

resource "aws_route" "b_to_c" {
  route_table_id            = aws_route_table.rt_b.id
  destination_cidr_block    = "10.18.0.0/16"
  vpc_peering_connection_id = aws_vpc_peering_connection.bc.id
}

resource "aws_route" "c_to_b" {
  route_table_id            = aws_route_table.rt_c.id
  destination_cidr_block    = "10.17.0.0/16"
  vpc_peering_connection_id = aws_vpc_peering_connection.bc.id
}
