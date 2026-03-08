#!/usr/bin/env python3
"""
ebs-encryption-auditor: boto3 compliance scanner.

Audits EBS encryption posture against:
  - CIS AWS Foundations Benchmark 2.3.1
  - SOC2 Trust Services Criteria CC6.1, CC6.7
  - ISO 27001:2013 Annex A.10.1.1
  - PCI DSS 3.4
  - HIPAA §164.312(a)(2)(iv)

Usage:
    # Read IDs from Terraform output (run from project root):
    python scanner.py --from-terraform-output

    # Supply resource IDs manually:
    python scanner.py --region us-east-1 \\
        --instance-ids i-xxx i-yyy \\
        --volume-ids vol-aaa vol-bbb vol-ccc \\
        --cmk-arn arn:aws:kms:us-east-1:123456789:key/abc-def \\
        --account-id 123456789012
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

import boto3
import botocore.exceptions

from findings import Finding, FindingStatus, Severity, print_findings_report


# ─────────────────────────────────────────────────────────────────────────────
# Check: Account-Level EBS Encryption Default
# (CIS 2.3.1 | SOC2 CC6.1 | ISO 27001 A.10.1.1)
# ─────────────────────────────────────────────────────────────────────────────

def check_account_ebs_encryption_default(ec2_client) -> list[Finding]:
    """
    CIS 2.3.1 | SOC2 CC6.1 | ISO 27001 A.10.1.1

    Checks whether EBS encryption by default is enabled at the account level.
    When enabled, all new EBS volumes and snapshots are encrypted automatically —
    no per-resource configuration required. This is the preventive control;
    check_volume_encryption is the detective control that catches volumes that
    slipped through before this setting was enabled.

    Risk: Without account-level default, any developer who forgets to set
    encrypted=true creates an unencrypted volume. This is silent — no error,
    no warning, just unencrypted data at rest.
    """
    try:
        response = ec2_client.get_ebs_encryption_by_default()
    except botocore.exceptions.ClientError as exc:
        print(f"[ERROR] get_ebs_encryption_by_default failed: {exc}", file=sys.stderr)
        return []

    enabled = response.get("EbsEncryptionByDefault", False)
    status = FindingStatus.PASS if enabled else FindingStatus.FAIL

    return [Finding(
        control_id="CIS-2.3.1-ACCOUNT",
        title="EBS Encryption Not Enabled by Default" if not enabled
              else "EBS Encryption Enabled by Default",
        description=(
            "Account-level EBS encryption by default is DISABLED. New volumes and "
            "snapshots created without an explicit kms_key_id will be unencrypted."
            if not enabled else
            "Account-level EBS encryption by default is enabled. All new volumes "
            "and snapshots are automatically encrypted."
        ),
        resource_id=f"account:{ec2_client.meta.region_name}",
        resource_type="AWS::EC2::EncryptionByDefault",
        status=status,
        severity=Severity.HIGH,
        remediation=(
            "Enable EBS encryption by default: "
            "EC2 Console → Account Settings → EBS Encryption → Enable. "
            "Or: aws ec2 enable-ebs-encryption-by-default --region <region>"
        ),
        compliance_refs=["CIS 2.3.1", "SOC2 CC6.1", "ISO 27001 A.10.1.1"],
    )]


# ─────────────────────────────────────────────────────────────────────────────
# Check: Per-Volume Encryption and CMK Usage
# (CIS 2.3.1 | PCI DSS 3.4 | ISO 27001 A.10.1.1)
# ─────────────────────────────────────────────────────────────────────────────

def check_volume_encryption(
    ec2_client,
    volume_ids: list[str],
    cmk_arn: str | None = None,
) -> list[Finding]:
    """
    CIS 2.3.1 | PCI DSS 3.4 | ISO 27001 A.10.1.1

    For each volume:
      FAIL    — volume is not encrypted at all
      WARNING — volume is encrypted but NOT with the expected CMK (uses aws/ebs
                default key, which means no customer key policy, no independent
                rotation control, no audit trail per-key)
      PASS    — volume is encrypted with the expected CMK

    If cmk_arn is not provided, only PASS/FAIL (encrypted/not) is reported.
    """
    if not volume_ids:
        return []

    try:
        response = ec2_client.describe_volumes(VolumeIds=volume_ids)
    except botocore.exceptions.ClientError as exc:
        print(f"[ERROR] describe_volumes failed: {exc}", file=sys.stderr)
        return []

    findings = []

    for volume in response["Volumes"]:
        vol_id = volume["VolumeId"]
        encrypted = volume.get("Encrypted", False)
        kms_key_id = volume.get("KmsKeyId", "")

        if not encrypted:
            findings.append(Finding(
                control_id="CIS-2.3.1-VOLUME",
                title="EBS Volume Not Encrypted",
                description=(
                    f"Volume {vol_id} is not encrypted. Data written to this volume "
                    "is stored in plaintext on the underlying physical media."
                ),
                resource_id=vol_id,
                resource_type="AWS::EC2::Volume",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                remediation=(
                    "Create a new encrypted volume from a snapshot, or enable "
                    "account-level EBS encryption to prevent future unencrypted volumes. "
                    "Note: you cannot encrypt an existing volume in-place."
                ),
                compliance_refs=["CIS 2.3.1", "PCI DSS 3.4", "ISO 27001 A.10.1.1"],
            ))
        elif cmk_arn and kms_key_id != cmk_arn:
            # Encrypted, but not with the expected customer-managed key.
            # This means it's using the aws/ebs default key or a different CMK.
            findings.append(Finding(
                control_id="CIS-2.3.1-VOLUME",
                title="EBS Volume Encrypted with Non-CMK Key",
                description=(
                    f"Volume {vol_id} is encrypted but not with the expected CMK. "
                    f"Key in use: {kms_key_id or '(aws/ebs default)'}. "
                    "AWS-managed keys cannot have custom key policies, independent "
                    "rotation schedules, or per-call audit trails beyond CloudTrail."
                ),
                resource_id=vol_id,
                resource_type="AWS::EC2::Volume",
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                remediation=(
                    "Re-create the volume encrypted with the organization CMK. "
                    "Set kms_key_id in Terraform to the approved CMK ARN."
                ),
                compliance_refs=["CIS 2.3.1", "PCI DSS 3.6.4", "ISO 27001 A.10.1.2"],
            ))
        else:
            findings.append(Finding(
                control_id="CIS-2.3.1-VOLUME",
                title="EBS Volume Encrypted with CMK",
                description=f"Volume {vol_id} is encrypted with the expected CMK.",
                resource_id=vol_id,
                resource_type="AWS::EC2::Volume",
                status=FindingStatus.PASS,
                severity=Severity.HIGH,
                remediation="No remediation needed.",
                compliance_refs=["CIS 2.3.1", "PCI DSS 3.4", "ISO 27001 A.10.1.1"],
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check: Snapshot Encryption
# (CIS 2.3.1 | SOC2 CC6.1)
# ─────────────────────────────────────────────────────────────────────────────

def check_snapshot_encryption(ec2_client, account_id: str) -> list[Finding]:
    """
    CIS 2.3.1 | SOC2 CC6.1

    Checks all EBS snapshots owned by this account for encryption.

    Why snapshots matter: an unencrypted snapshot can be shared with another
    AWS account or made public. Even if the original volume is later encrypted,
    old unencrypted snapshots persist. Many exfiltration incidents involve
    snapshot sharing, not volume access.

    Uses a paginator because accounts can have thousands of snapshots.
    Paginators handle the AWS API's page-size limits transparently.
    """
    findings = []

    try:
        paginator = ec2_client.get_paginator("describe_snapshots")
        pages = paginator.paginate(OwnerIds=[account_id])

        for page in pages:
            for snapshot in page["Snapshots"]:
                snap_id = snapshot["SnapshotId"]
                encrypted = snapshot.get("Encrypted", False)
                status = FindingStatus.PASS if encrypted else FindingStatus.FAIL

                findings.append(Finding(
                    control_id="CIS-2.3.1-SNAPSHOT",
                    title="EBS Snapshot Not Encrypted" if not encrypted
                          else "EBS Snapshot Encrypted",
                    description=(
                        f"Snapshot {snap_id} is not encrypted. Unencrypted snapshots "
                        "can be shared or made public, exposing data without restriction."
                        if not encrypted else
                        f"Snapshot {snap_id} is encrypted."
                    ),
                    resource_id=snap_id,
                    resource_type="AWS::EC2::Snapshot",
                    status=status,
                    severity=Severity.HIGH,
                    remediation=(
                        "Copy the snapshot with encryption enabled: "
                        "aws ec2 copy-snapshot --encrypted --kms-key-id <key>. "
                        "Delete the unencrypted original after verifying the copy."
                    ),
                    compliance_refs=["CIS 2.3.1", "SOC2 CC6.1"],
                ))

    except botocore.exceptions.ClientError as exc:
        print(f"[ERROR] describe_snapshots failed: {exc}", file=sys.stderr)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check: Running Instances with Unencrypted Attached Volumes
# (SOC2 CC6.7 | ISO 27001 A.10.1.1)
# ─────────────────────────────────────────────────────────────────────────────

def check_instance_unencrypted_volumes(
    ec2_client,
    instance_ids: list[str],
) -> list[Finding]:
    """
    SOC2 CC6.7 | ISO 27001 A.10.1.1

    For each running instance, checks whether any attached volume is unencrypted.
    This catches cases where:
    - An instance was created before account-level default encryption was enabled
    - The root volume was explicitly created without encryption
    - A data volume was attached without the encrypted flag

    Two API calls: describe_instances (to get attached volume IDs) then
    describe_volumes (to get encryption status).
    """
    if not instance_ids:
        return []

    findings = []

    try:
        response = ec2_client.describe_instances(InstanceIds=instance_ids)
    except botocore.exceptions.ClientError as exc:
        print(f"[ERROR] describe_instances failed: {exc}", file=sys.stderr)
        return []

    # Map instance_id → list of attached volume IDs
    instance_volume_map: dict[str, list[str]] = {}
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            iid = instance["InstanceId"]
            volume_ids = [
                bdm["Ebs"]["VolumeId"]
                for bdm in instance.get("BlockDeviceMappings", [])
                if "Ebs" in bdm
            ]
            instance_volume_map[iid] = volume_ids

    # Batch-fetch encryption status for all attached volumes
    all_volume_ids = [v for vols in instance_volume_map.values() for v in vols]
    if not all_volume_ids:
        return []

    try:
        vol_response = ec2_client.describe_volumes(VolumeIds=all_volume_ids)
    except botocore.exceptions.ClientError as exc:
        print(f"[ERROR] describe_volumes (instance check) failed: {exc}", file=sys.stderr)
        return []

    encryption_map = {v["VolumeId"]: v.get("Encrypted", False) for v in vol_response["Volumes"]}

    for instance_id, vol_ids in instance_volume_map.items():
        unencrypted = [v for v in vol_ids if not encryption_map.get(v, True)]
        status = FindingStatus.FAIL if unencrypted else FindingStatus.PASS

        findings.append(Finding(
            control_id="EBS-INSTANCE-ENC",
            title="Running Instance Has Unencrypted Attached Volume(s)" if unencrypted
                  else "All Volumes on Instance Are Encrypted",
            description=(
                f"Instance {instance_id} has {len(unencrypted)} unencrypted volume(s): "
                f"{unencrypted}. Data written by this instance is stored in plaintext."
                if unencrypted else
                f"Instance {instance_id}: all {len(vol_ids)} attached volume(s) are encrypted."
            ),
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            status=status,
            severity=Severity.HIGH,
            remediation=(
                "Stop the instance. Create encrypted volumes from unencrypted snapshots. "
                "Detach unencrypted volumes and attach encrypted replacements. "
                "Do not start the instance until all volumes are encrypted."
            ) if unencrypted else "No remediation needed.",
            compliance_refs=["SOC2 CC6.7", "ISO 27001 A.10.1.1", "CIS 2.3.1"],
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def run_all_checks(
    region: str,
    instance_ids: list[str],
    volume_ids: list[str],
    account_id: str,
    cmk_arn: str | None,
) -> list[Finding]:
    """Run all compliance checks and return a combined list of findings."""
    ec2 = boto3.client("ec2", region_name=region)

    all_findings: list[Finding] = []
    all_findings.extend(check_account_ebs_encryption_default(ec2))
    all_findings.extend(check_volume_encryption(ec2, volume_ids, cmk_arn))
    all_findings.extend(check_snapshot_encryption(ec2, account_id))
    all_findings.extend(check_instance_unencrypted_volumes(ec2, instance_ids))
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
            "instance_ids": outputs["instance_ids"]["value"],
            "volume_ids": outputs["volume_ids"]["value"],
            "kms_key_arn": outputs["kms_key_arn"]["value"],
            "account_id": outputs["account_id"]["value"],
            "region": outputs.get("region", {}).get("value", "us-east-1"),
        }
    except (subprocess.CalledProcessError, KeyError, json.JSONDecodeError) as exc:
        print(f"Error reading Terraform output: {exc}", file=sys.stderr)
        print(
            "Run 'terraform apply' first, or supply resource IDs manually.",
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
        description="Audit EBS encryption controls against CIS/SOC2/PCI DSS/ISO 27001."
    )
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--from-terraform-output",
        action="store_true",
        help="Load resource IDs from terraform output -json (run from project root)",
    )
    parser.add_argument("--instance-ids", nargs="+", metavar="INSTANCE_ID")
    parser.add_argument("--volume-ids", nargs="+", metavar="VOLUME_ID")
    parser.add_argument("--cmk-arn", help="Expected CMK ARN for per-volume CMK check")
    parser.add_argument("--account-id", help="AWS account ID for snapshot ownership check")
    parser.add_argument(
        "--push-to-security-hub",
        action="store_true",
        help="Import findings to AWS Security Hub (requires Security Hub enabled)",
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Print findings as JSON instead of formatted report",
    )
    args = parser.parse_args()

    if args.from_terraform_output:
        tf = load_from_terraform_output()
        instance_ids = tf["instance_ids"]
        volume_ids = tf["volume_ids"]
        cmk_arn = tf["kms_key_arn"]
        account_id = tf["account_id"]
        region = tf.get("region", args.region)
    else:
        if not args.account_id:
            # Auto-detect account ID from STS if not provided
            try:
                account_id = boto3.client("sts").get_caller_identity()["Account"]
            except botocore.exceptions.ClientError as exc:
                parser.error(f"Could not determine account ID: {exc}")
        else:
            account_id = args.account_id
        instance_ids = args.instance_ids or []
        volume_ids = args.volume_ids or []
        cmk_arn = args.cmk_arn
        region = args.region

    findings = run_all_checks(region, instance_ids, volume_ids, account_id, cmk_arn)

    if args.output_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print_findings_report(findings)

    if args.push_to_security_hub:
        push_to_security_hub(findings, region)


if __name__ == "__main__":
    main()
