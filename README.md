# GRC Engineering

I'm using this repo to build GRC engineering projects that turn security and compliance concepts into real tools. Each project takes a concept from a course, from work, or from curiosity and turns it into something I can actually run - a scanner, a policy enforcement tool, or an automated audit workflow.

## Projects

| Lab | Description | Controls |
|---|---|---|
| [vpc-segmentation-auditor](./vpc-segmentation-auditor/) | Python/boto3 compliance scanner for VPC network segmentation. Deploys intentionally misconfigured Terraform infrastructure and finds it. | CIS 1.16, 2.9, 5.2, 5.3 / SOC2 CC6.x / ISO 27001 A.9/A.12/A.13 |

## Stack

- **IaC:** Terraform
- **Scanner:** Python + boto3
- **Tests:** pytest + moto (mock AWS)
- **CI/CD:** GitHub Actions (tfsec, checkov, pytest, pip-audit)
- **Frameworks:** CIS AWS Foundations Benchmark, SOC2 TSC, ISO 27001

## Structure

Each project follows this layout:

```
project-name/
├── README.md           # what it does, architecture, how to run it
├── terraform/          # infrastructure as code
├── scripts/            # Python scanner or automation
├── policies/           # conformance pack or policy documents
└── tests/              # pytest suite with moto fixtures
```
