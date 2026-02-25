"""findings.py — Compliance finding data model and output formatters."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class FindingStatus(Enum):
    PASS = "PASSED"
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

    control_id: str        # e.g. "CIS-2.9"
    title: str
    description: str
    resource_id: str       # e.g. "vpc-0abc123"
    resource_type: str     # e.g. "AWS::EC2::VPC"
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

        ASFF is the lingua franca for Security Hub integrations. Every third-party
        security tool (Prowler, Steampipe, custom scanners) uses this exact schema.
        SchemaVersion "2018-10-08" is the only version AWS currently accepts.
        """
        return {
            "SchemaVersion": "2018-10-08",
            "Id": f"{region}/{self.resource_id}/{self.control_id}",
            "ProductArn": (
                f"arn:aws:securityhub:{region}:{aws_account_id}"
                f":product/{aws_account_id}/default"
            ),
            "GeneratorId": "vpc-segmentation-auditor",
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
        label = "[FAIL]" if finding.status == FindingStatus.FAIL else "[PASS]"
        print(f"{label} {finding.control_id} | {finding.resource_id} | {finding.title}")

    fails = [f for f in findings if f.status == FindingStatus.FAIL]
    passed = len(findings) - len(fails)
    print(f"\nResults: {passed}/{len(findings)} controls passed")
