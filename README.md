# Compliance Automation

An AI agent skill that generates draft compliance policy documents (SOC 2, ISO 27001) for startups, with codebase scanning, cloud infrastructure scanning, SaaS tool integration, and automated GitHub Actions evidence collection.

![Compliance policies and evidence workflows from a single conversation](https://github.com/user-attachments/assets/c49c4f7f-de8c-4c99-8d34-f0223297955d)

## What It Does

- Generates **17 policies** covering SOC 2 Trust Services Criteria and ISO 27001:2022 Annex A controls
- Tailors policies to your company size, industry, and data types
- **Scans codebase** for security patterns and extracts concrete values (password lengths, bcrypt rounds, RBAC roles, session timeouts, TLS versions)
- **Scans cloud infrastructure** (AWS, GCP, Azure) for live configuration evidence
- **Scans SaaS tools** (Okta, Datadog, PagerDuty, Jira, etc.) via API for compliance evidence
- **Detects drift** between code, cloud, and SaaS configurations with cross-source comparison
- **Generates GitHub Actions workflows** for automated, recurring evidence collection
- **Auto-detects SaaS tools** from your codebase (env files, package managers, Terraform, CI configs)
- **Persists session state** across conversations so you can resume mid-workflow
- Includes evidence checklists with auditor sufficiency criteria
- Uses audit-safe language that under-claims to reduce risk

## Usage

Works with any agent that supports the [Agent Skills](https://agentskills.io) format (Claude Code, Codex, OpenCode, Cursor, Windsurf).

**Option 1: Install via CLI**
```bash
npx skills add https://github.com/screenata/compliance-automation --skill compliance-automation
```

**Option 2: Manual install**

Copy the skill to your project's `.claude/skills/` folder.

Then just say: "Generate compliance policies" or "Generate SOC 2 policies" or "Generate ISO 27001 policies"

## Workflow

1. **Gather context** — Resumes from `.compliance/config.json` if available; auto-detects SaaS tools from codebase; asks industry, company size, data types, cert type, org name
2. **Choose evidence collection** — Code + Cloud + SaaS, Code + Cloud, Code + SaaS, Code only, or Q&A only
3. **Select policy** — Pick from 17 available policies
4. **Answer questions** — Policy-specific questions asked one at a time
5. **Generate policy** — Full document with evidence tables and concrete values
6. **Save and review** — Approve, regenerate, or skip
7. **Generate workflows** — Optional GitHub Actions for automated evidence collection

## Policies Included

17 policies covering SOC 2 Trust Services Criteria and ISO 27001:2022 Annex A: Governance, Organizational Structure, Code of Conduct, Information Security, Incident Response, External Communications, Vendor Management, Risk Management, Change Management, Access Control, Data Management, Physical Security, Vulnerability & Monitoring, Network Security, Business Continuity, Human Resources, and Mobile & Endpoint.

## Codebase Scanning

Extracts concrete values from your codebase — not just "auth exists" but "bcrypt uses 12 rounds":

| Policy | What It Extracts |
|--------|-----------------|
| Access Control | Password min length, bcrypt/argon2 config, RBAC roles, JWT expiry, session timeout, rate limits, account lockout |
| Data Management | Encryption algorithms (AES-256-GCM), KMS keys, backup retention periods, log retention |
| Network Security | TLS versions, SSL policies, CORS origins, HSTS config, CSP directives |
| Change Management | Required reviewers, status checks, CI/CD stages, security scanning tools (Snyk/Trivy/CodeQL) |
| Vulnerability Monitoring | Scan schedules, severity thresholds, audit levels, Dependabot config |

## Cloud Infrastructure Scanning

Scans live AWS, GCP, and Azure environments using CLI tools (read-only commands only):

| Provider | What It Scans |
|----------|--------------|
| AWS | IAM password policy, MFA status, S3 encryption, RDS backups, KMS rotation, ALB TLS, security groups, WAF, ECR scanning, SecurityHub, GuardDuty, CloudTrail, Backup plans |
| GCP | IAM policies, Cloud SQL backups, KMS keys, SSL policies, firewall rules, Cloud Armor, Security Command Center |
| Azure | Conditional access, RBAC assignments, storage encryption, SQL TDE, Key Vault, NSGs, App Gateway WAF, Defender assessments |

## SaaS Tool Integration

The agent generates API integrations on demand for your SaaS stack — no pre-built connectors needed:

| Category | Tools | Evidence Collected |
|----------|-------|-------------------|
| Identity & Access | Okta, Auth0, Google Workspace, JumpCloud | MFA enrollment rates, password policies, admin roles, deprovisioned users |
| Monitoring & Alerting | Datadog, PagerDuty, New Relic, Splunk | Active monitors, escalation policies, on-call schedules, incident metrics |
| Project & Change Mgmt | Jira, Linear, GitHub | Change ticket metrics, branch protection, PR review stats, Dependabot alerts |
| HR & People | BambooHR, Gusto, Rippling | Employee counts, termination tracking, policy compliance |
| Endpoint Management | Jamf, Kandji, Intune | Managed device counts, encryption status, compliance policies |
| Security Scanning | Snyk, SonarCloud | Vulnerability counts by severity, quality gate status, monitored projects |

For tools not in the catalog, the agent uses its API knowledge to generate integrations on the fly, or asks for documentation.

## SaaS Auto-Detection

Before asking you to list your SaaS tools, the skill scans your codebase for signals:

| Signal Source | Examples |
|---------------|----------|
| Env templates | `.env.example` with `OKTA_DOMAIN`, `DD_API_KEY` |
| Package managers | `@okta/okta-sdk-nodejs` in package.json, `dd-trace` in requirements.txt |
| Terraform | `provider "datadog"`, `provider "pagerduty"` in `*.tf` files |
| CI/CD | `snyk/actions`, `sonarsource/sonarcloud` in GitHub Actions |
| Config files | `newrelic.js`, `.snyk`, `sonar-project.properties` |
| Docker Compose | `datadog/agent` images |

Detected tools are presented for confirmation, not assumed. Falls back to manual selection if nothing is detected.

## Session Persistence

The skill tracks progress in the `.compliance/` folder (committed to your repo):

- **`.compliance/config.json`** — org name, policy owner, industry, company size, data types, cert type, evidence method
- **`.compliance/status.md`** — policies generated, SaaS tools configured, workflows created
- **`.compliance/answers/{policy}.md`** — per-policy Q&A answers (editable before generation)

If a session ends mid-way (e.g., you configured 3 of 6 SaaS tools), the next session picks up where you left off.

## Automated Evidence Collection

Pre-built scripts for 21 SaaS tools ship in `assets/scripts/`. The agent copies them, configures, tests locally, then wires into GitHub Actions workflows:

- **Copy-first approach** — pre-built scripts are copied and tested; generate-on-demand is the fallback if APIs have changed
- **Per-tool scripts** — each tool gets `{tool}.sh` + `{tool}.config.json` (atomic pair) in `.compliance/scripts/`
- **Code scanning** — Weekly + on every PR, outputs to `.compliance/evidence/code/`
- **Cloud scanning** — Weekly/monthly, outputs to `.compliance/evidence/cloud/`
- **SaaS scanning** — Weekly, outputs to `.compliance/evidence/saas/`
- **Cross-source comparison** — Compares code vs cloud vs SaaS for overlapping controls
- **Git audit trail** — Evidence files are committed with timestamps for audit history

## Procedural Evidence Collection

The automated workflows above collect API-based evidence such as configurations and user lists. For procedural evidence, [Screenata](https://screenata.com) provides an AI-agent powered browser automation tool with self-healing to reliably collect and monitor evidence such as:

- **Access reviews** — periodic user access verification in identity providers
- **Change approvals** — approval workflows and audit trails in ticketing systems
- **Security training completion** — training status and completion records from LMS platforms
- **Incident response drills** — documented runbook execution and response timelines
- **Backup restoration tests** — verified recovery procedures with timestamps
- **Vendor security reviews** — third-party risk assessment documentation

## Structure

```
compliance-automation/
├── SKILL.md                          # Main skill workflow (Steps 1-7b)
├── references/
│   ├── policies.md                   # 17 policy definitions with questions
│   ├── frameworks/
│   │   ├── soc2.md                  # SOC 2 TSC control mappings per policy
│   │   └── iso27001.md              # ISO 27001 Annex A control mappings per policy
│   ├── workflow-templates.md         # GitHub Actions generation guidelines
│   ├── script-templates.md           # Script conventions, config pattern, test workflow
│   ├── saas-integrations/
│   │   ├── shared.md                # Evidence format, script pattern, secrets
│   │   ├── identity.md              # Okta, Auth0, Google Workspace, JumpCloud
│   │   ├── monitoring.md            # Datadog, PagerDuty, New Relic, Splunk
│   │   ├── project-management.md    # Jira, Linear, GitHub
│   │   ├── communications.md        # Slack, Opsgenie, Statuspage
│   │   ├── hr.md                    # BambooHR, Gusto, Rippling
│   │   ├── endpoint.md              # Jamf, Kandji, Intune
│   │   └── security.md              # Snyk, SonarCloud
│   └── scanning-patterns/
│       ├── shared.md                 # Codebase evidence formatting guidelines
│       ├── cloud-shared.md           # Cloud scanning safety and auth rules
│       ├── saas-detection.md          # Auto-detect SaaS tools from codebase
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
    ├── workflow-compliance-code-scan.yml.template   # Code scan workflow template
    ├── workflow-compliance-saas-scan.yml.template   # SaaS scan workflow template
    └── scripts/                      # Pre-built evidence collection scripts
        ├── collect-all.sh            # Runner: discovers and executes all scripts
        ├── okta.sh, auth0.sh, ...    # 21 SaaS tool scripts (copy to .compliance/scripts/)
        └── README: see script-templates.md for full list
```

**Generated at runtime** (committed to user's repo):
```
.compliance/
├── config.json               # Global config — persists across conversations
├── status.md                 # Progress tracking (policies, tools, workflows)
├── secrets.env               # API tokens for local testing (DO NOT commit — add to .gitignore)
├── answers/
│   └── {policy-id}.md        # Per-policy Q&A answers (editable)
├── policies/
│   └── {policy-id}.md        # Generated policy documents
├── scripts/
│   ├── collect-all.sh        # Runner: executes all scripts
│   ├── {tool}.sh             # Per-tool evidence collection script
│   └── {tool}.config.json    # Per-tool config (non-secret settings)
└── evidence/
    ├── code/                 # Codebase scan results
    ├── cloud/                # Cloud infrastructure scan results
    └── saas/                 # SaaS tool scan results
```

## License

MIT

