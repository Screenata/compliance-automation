# SOC 2 Policy Generator

An AI agent skill that generates draft SOC 2 Type I/II policy documents for startups, with codebase scanning, cloud infrastructure scanning, and automated GitHub Actions evidence collection.

## What It Does

- Generates **17 SOC 2 policies** covering all Trust Services Criteria
- Tailors policies to your company size, industry, and data types
- **Scans codebase** for security patterns and extracts concrete values (password lengths, bcrypt rounds, RBAC roles, session timeouts, TLS versions)
- **Scans cloud infrastructure** (AWS, GCP, Azure) for live configuration evidence
- **Detects drift** between infrastructure-as-code and live cloud environments
- **Generates GitHub Actions workflows** for automated, recurring evidence collection
- Includes evidence checklists with auditor sufficiency criteria
- Uses audit-safe language that under-claims to reduce risk

## Usage

Works with any agent that supports the [Agent Skills](https://agentskills.io) format:
- Claude Code
- Cursor
- Other compatible agents

Just say: "Generate SOC 2 policies"

## Workflow

1. **Gather context** — Industry, company size, data types, certification type
2. **Choose evidence collection** — Code + Cloud, Code only, or Q&A only
3. **Select policy** — Pick from 17 available policies
4. **Answer questions** — Policy-specific questions asked one at a time
5. **Generate policy** — Full document with evidence tables and concrete values
6. **Save and review** — Approve, regenerate, or skip
7. **Generate workflows** — Optional GitHub Actions for automated evidence collection

## Policies Included

1. Governance & Board Oversight
2. Organizational Structure
3. Code of Conduct & Ethics
4. Information Security Policy
5. Incident Response
6. External Communications
7. Vendor Management
8. Risk Management
9. Change Management
10. Access Control
11. Data Management
12. Physical Security
13. Vulnerability & Monitoring
14. Network Security
15. Business Continuity
16. Human Resources
17. Mobile & Endpoint

## Codebase Scanning

Extracts concrete values from your codebase — not just "auth exists" but "bcrypt uses 12 rounds":

| Policy | What It Extracts |
|--------|-----------------|
| Access Control | Password min length, bcrypt/argon2 config, RBAC roles, JWT expiry, session timeout, rate limits, account lockout |
| Data Management | Encryption algorithms (AES-256-GCM), KMS keys, backup retention periods, log retention |
| Network Security | TLS versions, SSL policies, CORS origins, HSTS config, CSP directives |
| Change Management | Required reviewers, status checks, CI/CD stages, security scanning tools (Snyk/Trivy/CodeQL) |
| Vulnerability Monitoring | Scan schedules, severity thresholds, audit levels, Dependabot config |

Example output:

```markdown
## Evidence from Codebase

| Control | Extracted Value | File | Line | Raw Evidence |
|---------|----------------|------|------|-------------|
| Password minimum length | **12 characters** | src/validation/password.ts | 18 | `minLength: 12` |
| Password hashing | **bcrypt, 12 rounds** | src/services/auth.ts | 45 | `bcrypt.hash(password, 12)` |
| RBAC roles | **Admin, Editor, Viewer, Billing** | src/models/user.ts | 12 | `enum Role { ADMIN, EDITOR, VIEWER, BILLING }` |
```

## Cloud Infrastructure Scanning

Scans live AWS, GCP, and Azure environments using CLI tools (read-only commands only):

| Provider | What It Scans |
|----------|--------------|
| AWS | IAM password policy, MFA status, S3 encryption, RDS backups, KMS rotation, ALB TLS, security groups, WAF, ECR scanning, SecurityHub, GuardDuty, CloudTrail, Backup plans |
| GCP | IAM policies, Cloud SQL backups, KMS keys, SSL policies, firewall rules, Cloud Armor, Security Command Center |
| Azure | Conditional access, RBAC assignments, storage encryption, SQL TDE, Key Vault, NSGs, App Gateway WAF, Defender assessments |

Example output:

```markdown
## Evidence from Cloud Infrastructure

| Control | Extracted Value | Service | Region | Command | Raw Evidence |
|---------|----------------|---------|--------|---------|-------------|
| Password min length | **14 characters** | AWS IAM | global | `aws iam get-account-password-policy` | `"MinimumPasswordLength": 14` |
| RDS encryption | **enabled, Multi-AZ** | AWS RDS | us-east-1 | `aws rds describe-db-instances` | `"StorageEncrypted": true` |
```

## Automated Evidence Collection

Generates GitHub Actions workflows that run your scans on a schedule:

- **Code scanning** — Weekly + on every PR, outputs to `soc2-evidence/code/`
- **Cloud scanning** — Weekly/monthly, outputs to `soc2-evidence/cloud/`
- **Drift detection** — Compares IaC values against live infrastructure
- **Git audit trail** — Evidence files are committed with timestamps for audit history

## Structure

```
soc2-policy-generator/
├── SKILL.md                          # Main skill workflow (7 steps)
├── references/
│   ├── policies.md                   # 17 policy definitions with questions
│   ├── workflow-templates.md         # GitHub Actions generation guidelines
│   └── scanning-patterns/
│       ├── shared.md                 # Codebase evidence formatting guidelines
│       ├── cloud-shared.md           # Cloud scanning safety and auth rules
│       ├── access-control.md         # CC6.1-6.3 code patterns
│       ├── data-management.md        # CC6.5-6.7 code patterns
│       ├── network-security.md       # CC6.6-6.7 code patterns
│       ├── change-management.md      # CC8.1 code patterns
│       ├── vulnerability-monitoring.md # CC7.1-7.2 code patterns
│       ├── aws.md                    # AWS CLI scanning patterns
│       ├── gcp.md                    # GCP gcloud scanning patterns
│       └── azure.md                  # Azure CLI scanning patterns
└── assets/
    ├── policy-template.md            # Output template with evidence formats
    └── workflow-soc2-code-scan.yml.template  # GitHub Actions YAML template
```

## License

MIT

## About

Created by [Screenata](https://screenata.com) - Automated SOC 2 evidence collection.

These policies are drafts. The real work is proving they're implemented.
