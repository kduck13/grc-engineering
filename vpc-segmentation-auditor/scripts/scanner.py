#!/usr/bin/env python3
"""
vpc-segmentation-auditor: boto3 compliance scanner.

Audits VPC network segmentation controls against:
  - CIS AWS Foundations Benchmark v1.4
  - SOC2 Trust Services Criteria (2017)
  - ISO 27001:2013 Annex A

Usage:
    # Provide resource IDs manually:
    python scanner.py --region us-east-1 \\
        --vpc-ids vpc-xxx vpc-yyy vpc-zzz \\
        --sg-ids sg-xxx sg-yyy sg-zzz \\
        --peering-ids pcx-xxx pcx-yyy \\
        --role-name my-ec2-role

    # Read IDs from Terraform output (run from project root):
    python scanner.py --from-terraform-output
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

import boto3

from findings import Finding, FindingStatus, Severity, print_findings_report


# ─────────────────────────────────────────────────────────────────────────────
# Check: VPC Flow Logs (CIS 2.9 | SOC2 CC6.6 | ISO 27001 A.12.4.1)
# ─────────────────────────────────────────────────────────────────────────────

def check_vpc_flow_logs(ec2_client, vpc_ids: list[str]) -> list[Finding]:
    """
    CIS 2.9 | SOC2 CC6.6 | ISO 27001 A.12.4.1

    Check that each VPC has at least one ACTIVE flow log. Flow logs are the
    network-layer equivalent of CloudTrail — without them there is no audit
    trail for traffic accepted or rejected by security group rules.
    """
    findings = []
    covered_vpcs: set[str] = set()

    response = ec2_client.describe_flow_logs(
        Filters=[{'Name': 'resource-id', 'Values': vpc_ids}]
    )

    for flow_log in response['FlowLogs']:
        if flow_log['FlowLogStatus'] == 'ACTIVE':
            covered_vpcs.add(flow_log['ResourceId'])

    for vpc_id in vpc_ids:
        status = FindingStatus.PASS if vpc_id in covered_vpcs else FindingStatus.FAIL
        findings.append(Finding(
            control_id="CIS-2.9",
            title="VPC Flow Logs Not Enabled",
            description=(
                f"VPC {vpc_id} does not have an active flow log. "
                "Network traffic cannot be audited."
            ),
            resource_id=vpc_id,
            resource_type="AWS::EC2::VPC",
            status=status,
            severity=Severity.MEDIUM,
            remediation=(
                "Enable VPC Flow Logs and deliver to CloudWatch Logs or S3. "
                "Verify FlowLogStatus is ACTIVE after creation."
            ),
            compliance_refs=["CIS 2.9", "SOC2 CC6.6", "ISO 27001 A.12.4.1"],
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check: Unrestricted SSH / RDP (CIS 5.2/5.3 | SOC2 CC6.1 | ISO 27001 A.9.4.2)
# ─────────────────────────────────────────────────────────────────────────────

def check_unrestricted_ssh_rdp(ec2_client, sg_ids: list[str]) -> list[Finding]:
    """
    CIS 5.2/5.3 | SOC2 CC6.1 | ISO 27001 A.9.4.2

    Check that no security group allows SSH (port 22) or RDP (port 3389)
    from 0.0.0.0/0 or ::/0.
    """
    findings: list[Finding] = []
    restricted_ports = {22: "SSH", 3389: "RDP"}

    response = ec2_client.describe_security_groups(GroupIds=sg_ids)

    for sg in response["SecurityGroups"]:
        sg_id = sg["GroupId"]

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            protocol = rule.get("IpProtocol", "")

            for port, service_name in restricted_ports.items():
                # Does this rule cover the port we care about?
                port_covered = (
                    protocol == "-1"               # "-1" means ALL traffic
                    or (from_port <= port <= to_port)
                )
                if not port_covered:
                    continue

                # Is it open to all IPv4 addresses?
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        cis_id = "CIS-5.2" if port == 22 else "CIS-5.3"
                        findings.append(Finding(
                            control_id=cis_id,
                            title=f"{service_name} Open to the Internet",
                            description=(
                                f"Security group {sg_id} allows {service_name} "
                                "from 0.0.0.0/0 (all IPv4 addresses)."
                            ),
                            resource_id=sg_id,
                            resource_type="AWS::EC2::SecurityGroup",
                            status=FindingStatus.FAIL,
                            severity=Severity.HIGH,
                            remediation=(
                                f"Restrict {service_name} to known, specific IP ranges. "
                                "Never allow administrative ports from 0.0.0.0/0."
                            ),
                            compliance_refs=["CIS 5.2", "SOC2 CC6.1", "ISO 27001 A.9.4.2"],
                        ))

                # Is it open to all IPv6 addresses?
                for ipv6_range in rule.get("Ipv6Ranges", []):
                    if ipv6_range.get("CidrIpv6") == "::/0":
                        cis_id = "CIS-5.2" if port == 22 else "CIS-5.3"
                        findings.append(Finding(
                            control_id=cis_id,
                            title=f"{service_name} Open to the Internet (IPv6)",
                            description=(
                                f"Security group {sg_id} allows {service_name} "
                                "from ::/0 (all IPv6 addresses)."
                            ),
                            resource_id=sg_id,
                            resource_type="AWS::EC2::SecurityGroup",
                            status=FindingStatus.FAIL,
                            severity=Severity.HIGH,
                            remediation=(
                                f"Restrict {service_name} to known, specific IP ranges."
                            ),
                            compliance_refs=["CIS 5.2", "SOC2 CC6.1", "ISO 27001 A.9.4.2"],
                        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check: Peering Authorization Tags (ISO 27001 A.13.1.3 | SOC2 CC6.1/CC6.3)
# ─────────────────────────────────────────────────────────────────────────────

def check_peering_authorization_tags(ec2_client, peering_ids: list[str]) -> list[Finding]:
    """
    ISO 27001 A.13.1.3 | SOC2 CC6.1 / CC6.3

    Every VPC peering connection must document its business justification
    (Purpose tag) and the approver (ApprovedBy tag). VPC peering is
    non-transitive, meaning each connection is a deliberate decision to cross
    a network boundary — that decision needs an audit trail.
    """
    findings = []

    if not peering_ids:
        return findings

    response = ec2_client.describe_vpc_peering_connections(
        VpcPeeringConnectionIds=peering_ids
    )

    required_tags = {"Purpose", "ApprovedBy"}

    for conn in response["VpcPeeringConnections"]:
        conn_id = conn["VpcPeeringConnectionId"]
        existing_tags = {t["Key"] for t in conn.get("Tags", [])}
        missing = required_tags - existing_tags

        status = FindingStatus.PASS if not missing else FindingStatus.FAIL

        findings.append(Finding(
            control_id="VPC-PEER-AUTHZ",
            title="VPC Peering Connection Missing Authorization Tags",
            description=(
                f"Peering connection {conn_id} is missing required tags: "
                f"{missing or 'none'}. "
                "Each connection represents a network boundary crossing that "
                "must be documented."
            ),
            resource_id=conn_id,
            resource_type="AWS::EC2::VPCPeeringConnection",
            status=status,
            severity=Severity.MEDIUM,
            remediation=(
                "Add a 'Purpose' tag (business justification) and an 'ApprovedBy' tag "
                "(approver name or ticket reference) to this peering connection."
            ),
            compliance_refs=["ISO 27001 A.13.1.3", "SOC2 CC6.1", "SOC2 CC6.3"],
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check: IAM Wildcard Permissions (CIS 1.16 | SOC2 CC6.3 | ISO 27001 A.9.4.1)
# ─────────────────────────────────────────────────────────────────────────────

def check_iam_wildcard_policies(iam_client, role_name: str) -> list[Finding]:
    """
    CIS 1.16 | SOC2 CC6.3 | ISO 27001 A.9.4.1

    Check the EC2 instance role for inline policies that allow Action: service:*
    on Resource: *. This is the exact misconfiguration in the Cantrill demo
    CloudFormation template (s3:* and sns:* with Resource: *).
    """
    findings = []
    wildcard_found = False

    policy_names = iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]

    for policy_name in policy_names:
        policy_doc = iam_client.get_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
        )["PolicyDocument"]

        for statement in policy_doc.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            wildcard_actions = [a for a in actions if "*" in a]
            if wildcard_actions and "*" in resources:
                wildcard_found = True
                findings.append(Finding(
                    control_id="CIS-1.16",
                    title="EC2 Role Has Wildcard Permissions on All Resources",
                    description=(
                        f"Role '{role_name}', policy '{policy_name}' allows "
                        f"{wildcard_actions} on Resource: *. "
                        "Any EC2 instance with this profile has unrestricted "
                        "access to all S3 buckets and SNS topics in the account."
                    ),
                    resource_id=f"arn:aws:iam:::role/{role_name}",
                    resource_type="AWS::IAM::Role",
                    status=FindingStatus.FAIL,
                    severity=Severity.HIGH,
                    remediation=(
                        "Scope each action to only what is required and restrict "
                        "Resource to specific ARNs (e.g., a single S3 bucket ARN)."
                    ),
                    compliance_refs=["CIS 1.16", "SOC2 CC6.3", "ISO 27001 A.9.4.1"],
                ))

    if not wildcard_found:
        findings.append(Finding(
            control_id="CIS-1.16",
            title="EC2 Role Does Not Have Wildcard Permissions",
            description=f"Role '{role_name}' has no inline policies with wildcard actions on Resource: *.",
            resource_id=f"arn:aws:iam:::role/{role_name}",
            resource_type="AWS::IAM::Role",
            status=FindingStatus.PASS,
            severity=Severity.HIGH,
            remediation="No remediation needed.",
            compliance_refs=["CIS 1.16", "SOC2 CC6.3", "ISO 27001 A.9.4.1"],
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check: Unrestricted Egress (SOC2 CC6.7 | ISO 27001 A.13.1.1)
# ─────────────────────────────────────────────────────────────────────────────

def check_unrestricted_egress(ec2_client, sg_ids: list[str]) -> list[Finding]:
    """
    SOC2 CC6.7 | ISO 27001 A.13.1.1

    Flags security groups where egress allows all traffic (protocol -1) to
    0.0.0.0/0. Flagged as LOW — unrestricted egress is common and often
    operationally necessary, but it should be a documented decision.
    """
    findings = []

    if not sg_ids:
        return findings

    response = ec2_client.describe_security_groups(GroupIds=sg_ids)

    for sg in response["SecurityGroups"]:
        sg_id = sg["GroupId"]
        unrestricted = any(
            rule.get("IpProtocol") == "-1"
            and any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
            for rule in sg.get("IpPermissionsEgress", [])
        )

        status = FindingStatus.FAIL if unrestricted else FindingStatus.PASS
        findings.append(Finding(
            control_id="VPC-EGRESS-01",
            title="Security Group Allows Unrestricted Outbound Traffic",
            description=(
                f"Security group {sg_id} allows all outbound traffic to 0.0.0.0/0. "
                "This should be a documented decision."
            ),
            resource_id=sg_id,
            resource_type="AWS::EC2::SecurityGroup",
            status=status,
            severity=Severity.LOW,
            remediation=(
                "Consider restricting egress to required ports and destinations. "
                "If unrestricted egress is required, document the business justification."
            ),
            compliance_refs=["SOC2 CC6.7", "ISO 27001 A.13.1.1"],
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def run_all_checks(
    region: str,
    vpc_ids: list[str],
    sg_ids: list[str],
    peering_ids: list[str],
    role_name: str,
) -> list[Finding]:
    """Run all compliance checks and return a combined list of findings."""
    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam")

    all_findings: list[Finding] = []
    all_findings.extend(check_vpc_flow_logs(ec2, vpc_ids))
    all_findings.extend(check_unrestricted_ssh_rdp(ec2, sg_ids))
    all_findings.extend(check_peering_authorization_tags(ec2, peering_ids))
    all_findings.extend(check_iam_wildcard_policies(iam, role_name))
    all_findings.extend(check_unrestricted_egress(ec2, sg_ids))
    return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Terraform output integration
# ─────────────────────────────────────────────────────────────────────────────

def load_from_terraform_output() -> dict:
    """Read resource IDs from `terraform output -json` (run from project root)."""
    try:
        result = subprocess.run(
            ["terraform", "output", "-json"],
            capture_output=True,
            text=True,
            check=True,
            cwd="terraform",
        )
        outputs = json.loads(result.stdout)
        return {
            "vpc_ids": outputs["vpc_ids"]["value"],
            "sg_ids": outputs["sg_ids"]["value"],
            "peering_ids": outputs["peering_ids"]["value"],
            "role_name": outputs["ec2_role_name"]["value"],
            "region": outputs.get("region", {}).get("value", "us-east-1"),
        }
    except (subprocess.CalledProcessError, KeyError, json.JSONDecodeError) as exc:
        print(f"Error reading Terraform output: {exc}", file=sys.stderr)
        print(
            "Run 'terraform apply' first, or supply resource IDs with --vpc-ids etc.",
            file=sys.stderr,
        )
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Security Hub export
# ─────────────────────────────────────────────────────────────────────────────

def push_to_security_hub(findings: list[Finding], region: str) -> None:
    """Import findings into AWS Security Hub using the ASFF format."""
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    sh = boto3.client("securityhub", region_name=region)

    batch = [f.to_security_hub_format(account_id, region) for f in findings]
    if batch:
        response = sh.batch_import_findings(Findings=batch)
        print(
            f"Security Hub: {response['SuccessCount']} imported, "
            f"{response['FailedCount']} failed."
        )


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit VPC network segmentation controls against CIS/SOC2/ISO 27001."
    )
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--from-terraform-output",
        action="store_true",
        help="Load resource IDs from terraform output -json",
    )
    parser.add_argument("--vpc-ids", nargs="+")
    parser.add_argument("--sg-ids", nargs="+")
    parser.add_argument("--peering-ids", nargs="+")
    parser.add_argument("--role-name")
    parser.add_argument(
        "--push-to-security-hub",
        action="store_true",
        help="Import findings to Security Hub (requires Security Hub enabled)",
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Print findings as JSON instead of formatted report",
    )
    args = parser.parse_args()

    if args.from_terraform_output:
        tf = load_from_terraform_output()
        vpc_ids = tf["vpc_ids"]
        sg_ids = tf["sg_ids"]
        peering_ids = tf["peering_ids"]
        role_name = tf["role_name"]
        region = tf.get("region", args.region)
    else:
        if not all([args.vpc_ids, args.sg_ids, args.peering_ids, args.role_name]):
            parser.error(
                "Provide --vpc-ids, --sg-ids, --peering-ids, and --role-name, "
                "or use --from-terraform-output."
            )
        vpc_ids = args.vpc_ids
        sg_ids = args.sg_ids
        peering_ids = args.peering_ids
        role_name = args.role_name
        region = args.region

    findings = run_all_checks(region, vpc_ids, sg_ids, peering_ids, role_name)

    if args.output_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print_findings_report(findings)

    if args.push_to_security_hub:
        push_to_security_hub(findings, region)


if __name__ == "__main__":
    main()
