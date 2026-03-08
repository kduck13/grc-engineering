import boto3
import pytest
from moto import mock_aws

from findings import FindingStatus, Severity
from scanner import (
    check_account_ebs_encryption_default,
    check_instance_unencrypted_volumes,
    check_snapshot_encryption,
    check_volume_encryption,
)

REGION = "us-east-1"


# ─────────────────────────────────────────────────────────────────────────────
# Account-Level EBS Encryption Default
# ─────────────────────────────────────────────────────────────────────────────

class TestAccountEbsEncryptionDefault:
    @mock_aws
    def test_disabled_by_default_returns_fail(self):
        # moto starts with EBS default encryption DISABLED — same as a new AWS account.
        ec2 = boto3.client("ec2", region_name=REGION)

        findings = check_account_ebs_encryption_default(ec2)

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].severity == Severity.HIGH

    @mock_aws
    def test_enabled_returns_pass(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        ec2.enable_ebs_encryption_by_default()

        findings = check_account_ebs_encryption_default(ec2)

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.PASS


# ─────────────────────────────────────────────────────────────────────────────
# Per-Volume Encryption and CMK Check
# ─────────────────────────────────────────────────────────────────────────────

class TestVolumeEncryption:
    @mock_aws
    def test_unencrypted_volume_returns_fail(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        volume_id = ec2.create_volume(
            AvailabilityZone=f"{REGION}a",
            Size=1,
            Encrypted=False,
        )["VolumeId"]

        findings = check_volume_encryption(ec2, [volume_id])

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].resource_id == volume_id

    @mock_aws
    def test_volume_encrypted_with_cmk_returns_pass(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        kms = boto3.client("kms", region_name=REGION)

        # Create a customer-managed key
        cmk_arn = kms.create_key(Description="test-cmk")["KeyMetadata"]["Arn"]

        volume_id = ec2.create_volume(
            AvailabilityZone=f"{REGION}a",
            Size=1,
            Encrypted=True,
            KmsKeyId=cmk_arn,
        )["VolumeId"]

        findings = check_volume_encryption(ec2, [volume_id], cmk_arn=cmk_arn)

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.PASS

    @mock_aws
    def test_volume_encrypted_with_wrong_key_returns_warning(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        kms = boto3.client("kms", region_name=REGION)

        # The "expected" CMK that policy requires
        expected_cmk_arn = kms.create_key(Description="expected-cmk")["KeyMetadata"]["Arn"]

        # A different CMK — encrypted, but not the right one
        actual_cmk_arn = kms.create_key(Description="other-cmk")["KeyMetadata"]["Arn"]

        volume_id = ec2.create_volume(
            AvailabilityZone=f"{REGION}a",
            Size=1,
            Encrypted=True,
            KmsKeyId=actual_cmk_arn,
        )["VolumeId"]

        findings = check_volume_encryption(ec2, [volume_id], cmk_arn=expected_cmk_arn)

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.WARNING
        assert findings[0].severity == Severity.MEDIUM

    @mock_aws
    def test_mixed_volumes_returns_correct_statuses(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        kms = boto3.client("kms", region_name=REGION)
        cmk_arn = kms.create_key(Description="lab-cmk")["KeyMetadata"]["Arn"]

        encrypted_id = ec2.create_volume(
            AvailabilityZone=f"{REGION}a", Size=1, Encrypted=True, KmsKeyId=cmk_arn
        )["VolumeId"]
        unencrypted_id = ec2.create_volume(
            AvailabilityZone=f"{REGION}a", Size=1, Encrypted=False
        )["VolumeId"]

        findings = check_volume_encryption(
            ec2, [encrypted_id, unencrypted_id], cmk_arn=cmk_arn
        )

        statuses = {f.resource_id: f.status for f in findings}
        assert statuses[encrypted_id] == FindingStatus.PASS
        assert statuses[unencrypted_id] == FindingStatus.FAIL


# ─────────────────────────────────────────────────────────────────────────────
# Snapshot Encryption
# ─────────────────────────────────────────────────────────────────────────────

class TestSnapshotEncryption:
    # NOTE: moto pre-populates ~1160 unencrypted snapshots in account 123456789012
    # (these are internal to moto's AMI catalog and belong to "amazon" owner in real
    # AWS, but moto returns them under the mocked account). Tests below track
    # specific snapshot IDs to avoid false positives from moto's pre-existing state.

    @mock_aws
    def test_unencrypted_snapshot_returns_fail(self):
        ec2 = boto3.client("ec2", region_name=REGION)

        volume_id = ec2.create_volume(
            AvailabilityZone=f"{REGION}a", Size=1, Encrypted=False
        )["VolumeId"]
        snap_id = ec2.create_snapshot(
            VolumeId=volume_id, Description="unencrypted-test"
        )["SnapshotId"]

        findings = check_snapshot_encryption(ec2, account_id="123456789012")
        finding_map = {f.resource_id: f for f in findings}

        assert snap_id in finding_map
        assert finding_map[snap_id].status == FindingStatus.FAIL

    @mock_aws
    def test_encrypted_snapshot_returns_pass(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        kms = boto3.client("kms", region_name=REGION)
        cmk_arn = kms.create_key(Description="snap-cmk")["KeyMetadata"]["Arn"]

        volume_id = ec2.create_volume(
            AvailabilityZone=f"{REGION}a", Size=1, Encrypted=True, KmsKeyId=cmk_arn
        )["VolumeId"]
        snap_id = ec2.create_snapshot(
            VolumeId=volume_id, Description="encrypted-test"
        )["SnapshotId"]

        findings = check_snapshot_encryption(ec2, account_id="123456789012")
        finding_map = {f.resource_id: f for f in findings}

        assert snap_id in finding_map
        assert finding_map[snap_id].status == FindingStatus.PASS

    @mock_aws
    def test_mixed_snapshots_return_correct_statuses(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        kms = boto3.client("kms", region_name=REGION)
        cmk_arn = kms.create_key(Description="mix-cmk")["KeyMetadata"]["Arn"]

        unenc_vol = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1, Encrypted=False)["VolumeId"]
        enc_vol = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1, Encrypted=True, KmsKeyId=cmk_arn)["VolumeId"]

        unenc_snap_id = ec2.create_snapshot(VolumeId=unenc_vol)["SnapshotId"]
        enc_snap_id = ec2.create_snapshot(VolumeId=enc_vol)["SnapshotId"]

        findings = check_snapshot_encryption(ec2, account_id="123456789012")
        finding_map = {f.resource_id: f for f in findings}

        assert finding_map[unenc_snap_id].status == FindingStatus.FAIL
        assert finding_map[enc_snap_id].status == FindingStatus.PASS


# ─────────────────────────────────────────────────────────────────────────────
# Instances with Unencrypted Attached Volumes
# ─────────────────────────────────────────────────────────────────────────────

class TestInstanceUnencryptedVolumes:
    def _get_moto_ami(self, ec2_client) -> str:
        """Get a valid AMI ID from moto's built-in image catalog."""
        images = ec2_client.describe_images(Owners=["amazon"])["Images"]
        assert images, "moto should provide at least one built-in AMI"
        return images[0]["ImageId"]

    @mock_aws
    def test_instance_with_unencrypted_attached_volume_returns_fail(self):
        # NOTE: moto ignores Encrypted=False in BlockDeviceMappings for root volumes —
        # it always creates them encrypted. To test the FAIL path, we attach a
        # separate unencrypted EBS volume after launch.
        ec2 = boto3.client("ec2", region_name=REGION)
        ami_id = self._get_moto_ami(ec2)

        instance = ec2.run_instances(
            ImageId=ami_id, MinCount=1, MaxCount=1, InstanceType="t2.micro",
        )["Instances"][0]
        instance_id = instance["InstanceId"]

        # Create and attach an unencrypted data volume
        unenc_vol_id = ec2.create_volume(
            AvailabilityZone=f"{REGION}a", Size=1, Encrypted=False
        )["VolumeId"]
        ec2.attach_volume(
            Device="/dev/sdf", VolumeId=unenc_vol_id, InstanceId=instance_id
        )

        findings = check_instance_unencrypted_volumes(ec2, [instance_id])

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.FAIL
        assert findings[0].resource_id == instance_id

    @mock_aws
    def test_instance_with_encrypted_root_returns_pass(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        kms = boto3.client("kms", region_name=REGION)
        ami_id = self._get_moto_ami(ec2)
        cmk_arn = kms.create_key(Description="instance-cmk")["KeyMetadata"]["Arn"]

        instance = ec2.run_instances(
            ImageId=ami_id,
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            BlockDeviceMappings=[{
                "DeviceName": "/dev/xvda",
                "Ebs": {"VolumeSize": 8, "Encrypted": True, "KmsKeyId": cmk_arn},
            }],
        )["Instances"][0]
        instance_id = instance["InstanceId"]

        findings = check_instance_unencrypted_volumes(ec2, [instance_id])

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.PASS

    @mock_aws
    def test_empty_instance_list_returns_empty(self):
        ec2 = boto3.client("ec2", region_name=REGION)

        findings = check_instance_unencrypted_volumes(ec2, [])

        assert findings == []
