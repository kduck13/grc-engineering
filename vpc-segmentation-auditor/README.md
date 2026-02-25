# VPC Segmentation Auditor

I built this to turn observations from the Cantrill AWS VPC Peering demo into a working GRC engineering lab. The demo's CloudFormation had three real-world security issues - SSH open to `0.0.0.0/0`, wildcard IAM permissions on the EC2 role, and no VPC Flow Logs. This project deploys those misconfigurations intentionally via Terraform and then finds them with a Python/boto3 compliance scanner.

## What This Does

- Deploys a three-VPC environment with intentional misconfigurations as the scan target
- Runs a Python scanner that audits the environment against CIS, SOC2, and ISO 27001 controls
- Demonstrates the difference between continuous monitoring (AWS Config) and point-in-time auditing (the scanner)
- Includes a full pytest suite using moto to mock AWS - no credentials needed to run tests

## Architecture

```
VPC-A (10.16.0.0/16)          VPC-B (10.17.0.0/16)          VPC-C (10.18.0.0/16)
  EC2 (t3.micro)    <--peer-->   EC2 (t3.micro)    <--peer-->   EC2 (t3.micro)
  SG-A: SSH 0.0.0.0/0           SG-B: SSH+RDP 0.0.0.0/0        SG-C: SSH 10.16.0.0/16 only
  No Flow Logs                   No Flow Logs                    No Flow Logs

  EC2 IAM Role: s3:* + sns:* on Resource: * (intentional wildcard)

  VPC-A <-> VPC-C: NOT directly peered (non-transitivity demonstrated)
```

AWS Config recorder runs alongside the scanner. Both audit the same resources - Config for continuous monitoring, the scanner for on-demand audits.

## Intentional Misconfigurations

These are deployed on purpose so the scanner has something to find.

| Resource | Misconfiguration | Controls Violated |
|---|---|---|
| All 3 VPCs | No Flow Logs | CIS 2.9, SOC2 CC6.6, ISO A.12.4.1 |
| SG-A | SSH open to `0.0.0.0/0` and `::/0` | CIS 5.2, SOC2 CC6.1, ISO A.9.4.2 |
| SG-B | SSH and RDP open to `0.0.0.0/0` | CIS 5.2/5.3, SOC2 CC6.1, ISO A.9.4.2 |
| Both peering connections | Missing `Purpose` and `ApprovedBy` tags | ISO A.13.1.3, SOC2 CC6.3 |
| EC2 IAM role | `s3:*` and `sns:*` on `Resource: *` | CIS 1.16, SOC2 CC6.3, ISO A.9.4.1 |
| SG-C | SSH restricted to `10.16.0.0/16` | **Compliant - intentional PASS** |

## GRC Controls Covered

| Check | CIS | SOC2 | ISO 27001 | Severity |
|---|---|---|---|---|
| VPC Flow Logs disabled | 2.9 | CC6.6 | A.12.4.1 | MEDIUM |
| SSH open to internet | 5.2 | CC6.1 | A.9.4.2 | HIGH |
| RDP open to internet | 5.3 | CC6.1 | A.9.4.2 | HIGH |
| Peering missing auth tags | - | CC6.1/CC6.3 | A.13.1.3 | MEDIUM |
| IAM wildcard on instance role | 1.16 | CC6.3 | A.9.4.1 | HIGH |
| Unrestricted egress | - | CC6.7 | A.13.1.1 | LOW |

## Prerequisites

- Terraform >= 1.5
- Python >= 3.12
- AWS CLI configured with a profile that has permissions to create VPCs, EC2, IAM, and Config resources
- **Cost note:** The AWS Config recorder costs approximately $2-5/month for this lab. Run `terraform destroy` when done.

## Quick Start

```bash
# Deploy the lab environment
cd terraform
terraform init
terraform apply

# Set up Python environment
cd ..
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r scripts/requirements.txt

# Run the scanner against the deployed resources
python scripts/scanner.py --from-terraform-output

# Optional: output findings as JSON
python scripts/scanner.py --from-terraform-output --output-json

# Tear down when done (stops Config recorder charges)
cd terraform
terraform destroy
```

## Running Tests

Tests use moto to mock AWS - no credentials or deployed infrastructure needed.

```bash
pytest tests/ -v
```

## CI/CD

The GitHub Actions workflow at `.github/workflows/vpc-segmentation-auditor.yml` runs on every push to this directory:

- **terraform-lint**: tfsec and checkov scan the Terraform. Both tools will flag the intentional misconfigurations - this is expected and `continue-on-error: true` is set intentionally. The findings appear in the job logs as documentation.
- **python-tests**: runs the full pytest suite without AWS credentials
- **security-scan**: pip-audit checks Python dependencies for known CVEs

## Key Design Decisions

**Config rules and the scanner overlap on purpose.** Config provides continuous, real-time monitoring. The scanner provides a point-in-time audit you can run on demand, pipe to JSON, or integrate into a ticket workflow. A mature GRC program uses both.

**The scanner covers gaps Config managed rules cannot.** There is no managed Config rule for VPC peering authorization tags or unrestricted egress. Custom controls like these require code.

**No remote Terraform backend.** This is a single-person lab. A team deployment would use S3 + DynamoDB for state locking.

**Security Hub integration is opt-in.** The `--push-to-security-hub` flag exists but is off by default to avoid surprise charges from enabling the service.

## What I Learned Building This

- How VPC peering non-transitivity creates network boundary control points that matter for segmentation audits
- The ASFF (Amazon Security Finding Format) that Security Hub uses to normalize findings across tools
- How moto intercepts boto3 calls so tests run without real AWS infrastructure
- The difference between a managed Config rule (AWS maintains the logic) and a custom scanner (you maintain the logic, but you can check anything)
