"""findings.py — Compliance finding data model and output formatters."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class FindingStatus(Enum):
    PASS = "PASSED"
    WARNING = "WARNING"  # Encrypted but not with expected CMK; or low-risk deviation
    FAIL = "FAILED"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class Finding:
    """A single compliance finding mapped to one or more GRC controls."""

    control_id: str        # e.g. "CIS-2.3.1"
    title: str
    description: str
    resource_id: str       # e.g. "vol-0abc123"
    resource_type: str     # e.g. "AWS::EC2::Volume"
    status: FindingStatus
    severity: Severity
    remediation: str
    compliance_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of this finding."""
        return {
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "status": self.status.value,
            "severity": self.severity.value,
            "remediation": self.remediation,
            "compliance_refs": self.compliance_refs,
        }

    def to_security_hub_format(self, aws_account_id: str, region: str) -> dict[str, Any]:
        """Format this finding as ASFF (Amazon Security Finding Format) for Security Hub.

        ASFF Compliance.Status accepts: PASSED, WARNING, FAILED, NOT_AVAILABLE.
        WARNING maps to our FindingStatus.WARNING — encrypted but policy non-compliant.
        """
        return {
            "SchemaVersion": "2018-10-08",
            "Id": f"{region}/{self.resource_id}/{self.control_id}",
            "ProductArn": (
                f"arn:aws:securityhub:{region}:{aws_account_id}"
                f":product/{aws_account_id}/default"
            ),
            "GeneratorId": "ebs-encryption-auditor",
            "AwsAccountId": aws_account_id,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "CreatedAt": datetime.now(timezone.utc).isoformat(),
            "UpdatedAt": datetime.now(timezone.utc).isoformat(),
            "Severity": {"Label": self.severity.value},
            "Title": self.title,
            "Description": self.description,
            "Resources": [
                {
                    "Type": self.resource_type,
                    "Id": self.resource_id,
                    "Region": region,
                }
            ],
            "Compliance": {"Status": self.status.value},
            "Remediation": {"Recommendation": {"Text": self.remediation}},
        }


def print_findings_report(findings: list[Finding]) -> None:
    """Print a formatted summary of findings to stdout."""
    for finding in findings:
        if finding.status == FindingStatus.FAIL:
            label = "[FAIL]"
        elif finding.status == FindingStatus.WARNING:
            label = "[WARN]"
        else:
            label = "[PASS]"
        print(f"{label} {finding.control_id} | {finding.resource_id} | {finding.title}")

    fails = [f for f in findings if f.status == FindingStatus.FAIL]
    warnings = [f for f in findings if f.status == FindingStatus.WARNING]
    passed = len(findings) - len(fails) - len(warnings)
    print(
        f"\nResults: {passed}/{len(findings)} passed, "
        f"{len(warnings)} warnings, {len(fails)} failed"
    )
