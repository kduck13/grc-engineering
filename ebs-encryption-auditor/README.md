# ebs-encryption-auditor

Python/boto3 compliance scanner that audits EBS encryption posture across an AWS account. Deploys intentionally misconfigured Terraform infrastructure and finds it.

## What It Does

Checks four controls:

| Check | What It Finds | Frameworks |
|---|---|---|
| Account default encryption | Is EBS encryption enabled at the account level? | CIS 2.3.1, SOC2 CC6.1 |
| Per-volume encryption | Are individual volumes encrypted? Are they using a CMK vs the aws/ebs default key? | CIS 2.3.1, PCI DSS 3.4, ISO 27001 A.10.1.1 |
| Snapshot encryption | Are EBS snapshots encrypted? | CIS 2.3.1, SOC2 CC6.1 |
| Instance-volume mapping | Do any running instances have unencrypted volumes attached? | SOC2 CC6.7, ISO 27001 A.10.1.1 |

## Why This Matters

EBS volumes are persistent block storage. When unencrypted:
- Data is readable if the underlying physical media is ever recovered or reused
- Unencrypted snapshots can be shared cross-account or made public — a common exfiltration vector
- Compliance frameworks (PCI DSS 3.4, HIPAA, CIS 2.3.1) require encryption at rest for regulated data

The scanner distinguishes between **encrypted with a customer-managed key (CMK)** and **encrypted with the default aws/ebs key**. This matters because:
- AWS-managed keys cannot have custom key policies
- You cannot independently rotate or revoke them
- Audit trails are coarser — you see KMS calls but lack per-key policy enforcement

## Lab Infrastructure

The Terraform deploys intentional misconfigurations for the scanner to find:

```
ec2_compliant       — t2.micro, root + data volume encrypted with CMK  [PASS]
ec2_noncompliant    — t2.micro, root volume unencrypted                 [FAIL]
data_compliant      — 1 GB EBS volume, encrypted with CMK               [PASS]
unattached_unencrypted — 1 GB unattached EBS volume, not encrypted      [FAIL]
default_key_encrypted  — 1 GB EBS volume, encrypted with aws/ebs key    [WARN]
```

Account-level EBS encryption by default is intentionally left **disabled** — the first check will always FAIL in this lab.

## Usage

```bash
# 1. Deploy the lab infrastructure
cd terraform
terraform init
terraform apply

# 2. Run the scanner (reads resource IDs from Terraform output)
cd ../scripts
pip install -r requirements.txt
python scanner.py --from-terraform-output

# 3. Optional: export findings to Security Hub
python scanner.py --from-terraform-output --push-to-security-hub

# 4. Run the test suite (no AWS credentials needed — uses moto)
cd ../tests
pytest -v

# 5. Clean up when done (KMS key costs $1/month prorated — destroy promptly)
cd ../terraform
terraform destroy
```

## Cost Estimate

| Resource | Cost |
|---|---|
| 2x t2.micro EC2 | Free tier (750 hrs/month) or ~$0.02/hr |
| EBS volumes (< 30 GB total) | Free tier (30 GB/month) or ~$0.01 |
| KMS CMK (1 key) | ~$0.033/day ($1/month prorated) |
| AWS Config rule evaluations | ~$0.01–$0.05 |

**Total for a 1-2 hour lab: ~$0.05–$0.10.** Destroy the same day to minimize KMS cost.

## Stack

- **IaC:** Terraform (KMS, EC2, EBS, AWS Config)
- **Scanner:** Python + boto3
- **Tests:** pytest + moto (mock AWS)
- **CI/CD:** GitHub Actions (tfsec, checkov, pytest, pip-audit)
- **Frameworks:** CIS AWS Foundations Benchmark 2.3.1, SOC2 CC6.1/CC6.7, PCI DSS 3.4, ISO 27001 A.10.1.1, HIPAA
