import json

import boto3
import pytest
from moto import mock_aws

from findings import FindingStatus, Severity
from scanner import (
    check_iam_wildcard_policies,
    check_peering_authorization_tags,
    check_unrestricted_egress,
    check_unrestricted_ssh_rdp,
    check_vpc_flow_logs,
)


# ─────────────────────────────────────────────────────────────────────────────
# VPC Flow Logs
# ─────────────────────────────────────────────────────────────────────────────

class TestVpcFlowLogs:
    @mock_aws
    def test_no_flow_logs_returns_fail(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        findings = check_vpc_flow_logs(ec2, [vpc_id])

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM

    @mock_aws
    def test_active_flow_log_returns_pass(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName="/test/vpc-flow-logs",
            DeliverLogsPermissionArn="arn:aws:iam::123456789012:role/test-role",
        )

        findings = check_vpc_flow_logs(ec2, [vpc_id])

        assert findings[0].status == FindingStatus.PASS


# ─────────────────────────────────────────────────────────────────────────────
# Unrestricted SSH / RDP
# ─────────────────────────────────────────────────────────────────────────────

class TestUnrestrictedSshRdp:
    @mock_aws
    def test_ssh_open_to_internet_returns_fail(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg_id = ec2.create_security_group(
            GroupName="open-ssh", Description="test", VpcId=vpc_id
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )

        findings = check_unrestricted_ssh_rdp(ec2, [sg_id])

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH

    @mock_aws
    def test_ssh_scoped_to_cidr_returns_no_findings(self):
        # SG-C pattern: SSH allowed only from a specific internal range.
        # The check should produce zero findings for a compliant security group.
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg_id = ec2.create_security_group(
            GroupName="scoped-ssh", Description="test", VpcId=vpc_id
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.16.0.0/16"}],
            }],
        )

        findings = check_unrestricted_ssh_rdp(ec2, [sg_id])

        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Peering Authorization Tags
# ─────────────────────────────────────────────────────────────────────────────

class TestPeeringAuthorizationTags:
    @mock_aws
    def test_required_tags_present_returns_pass(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_a = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        vpc_b = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
        pcx_id = ec2.create_vpc_peering_connection(
            VpcId=vpc_a, PeerVpcId=vpc_b
        )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
        ec2.create_tags(
            Resources=[pcx_id],
            Tags=[
                {"Key": "Purpose", "Value": "lab-connectivity"},
                {"Key": "ApprovedBy", "Value": "admin"},
            ],
        )

        findings = check_peering_authorization_tags(ec2, [pcx_id])

        assert findings[0].status == FindingStatus.PASS

    @mock_aws
    def test_missing_tags_returns_fail(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_a = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        vpc_b = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
        pcx_id = ec2.create_vpc_peering_connection(
            VpcId=vpc_a, PeerVpcId=vpc_b
        )["VpcPeeringConnection"]["VpcPeeringConnectionId"]

        findings = check_peering_authorization_tags(ec2, [pcx_id])

        assert findings[0].status == FindingStatus.FAIL


# ─────────────────────────────────────────────────────────────────────────────
# IAM Wildcard Policies
# ─────────────────────────────────────────────────────────────────────────────

class TestIamWildcardPolicies:
    @mock_aws
    def test_wildcard_policy_returns_fail(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
        )
        iam.put_role_policy(
            RoleName="test-role",
            PolicyName="wildcard-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:*"],
                    "Resource": "*",
                }],
            }),
        )

        findings = check_iam_wildcard_policies(iam, "test-role")

        assert any(f.status == FindingStatus.FAIL for f in findings)

    @mock_aws
    def test_scoped_policy_returns_pass(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="scoped-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
        )
        iam.put_role_policy(
            RoleName="scoped-role",
            PolicyName="scoped-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }],
            }),
        )

        findings = check_iam_wildcard_policies(iam, "scoped-role")

        assert all(f.status == FindingStatus.PASS for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# Unrestricted Egress
# ─────────────────────────────────────────────────────────────────────────────

class TestUnrestrictedEgress:
    @mock_aws
    def test_open_egress_returns_fail(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        # New security groups get open egress (0.0.0.0/0) by default - same as AWS.
        sg_id = ec2.create_security_group(
            GroupName="open-egress", Description="test", VpcId=vpc_id
        )["GroupId"]

        findings = check_unrestricted_egress(ec2, [sg_id])

        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.LOW
