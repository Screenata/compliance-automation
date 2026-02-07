---
name: soc2-policy-generator
description: Generate draft SOC 2 Type II policy documents with optional codebase/cloud scanning for evidence and automated GitHub Actions workflows for recurring evidence collection. Use when the user needs to create compliance policies, security policies, or mentions SOC 2 certification.
license: MIT
metadata:
  author: screenata
  version: "3.0"
---

# SOC 2 Policy Generator

Generate draft SOC 2 Type II policy documents based on company context, answers to targeted questions, and optionally detected codebase evidence.

## Important Disclaimer

**GENERATED DRAFTS ONLY** - All policies require human review before use. These are starting points, not audit-ready documents.

## When to Use This Skill

Use this skill when the user:
- Needs to create SOC 2 compliance policies
- Mentions SOC 2 certification or audit preparation
- Asks for security policy templates
- Wants to generate compliance documentation

## Workflow

**CRITICAL: This is a conversational flow. Ask ONE question, wait for answer, then ask the next. NEVER list multiple questions in a single message.**

### Step 1: Gather Company Context

Ask each question separately. After receiving an answer, proceed to the next question.

**Question 1** (ask first, wait for response):
> What industry is your company in?
> 1. Healthcare
> 2. Fintech
> 3. B2B SaaS
> 4. E-commerce
> 5. Other

**Question 2** (ask after Q1 answered):
> Approximately how many employees?
> 1. 1-10
> 2. 11-50
> 3. 51-200
> 4. 200+

**Question 3** (ask after Q2 answered):
> What types of sensitive data do you handle?
> 1. PII (names, emails, addresses)
> 2. PHI (health records)
> 3. Financial data
> 4. Multiple types
> 5. None of the above

**Question 4** (ask after Q3 answered):
> Are you pursuing SOC 2 Type I or Type II?
> 1. Type I (point-in-time)
> 2. Type II (operational over time)

Save all answers - they apply to all policies generated in this session.

### Step 2: Choose Evidence Collection Method

After gathering context, ask:
> How would you like to collect evidence for the policies?
> 1. Code + Cloud - scan codebase AND live cloud infrastructure (most comprehensive)
> 2. Code only - scan codebase for security patterns (auth, encryption, CI/CD)
> 3. Q&A only - generate policies based on your answers only

**If user chooses Code + Cloud (option 1):**
First, detect available cloud CLIs and verify authentication per [cloud-shared.md](references/scanning-patterns/cloud-shared.md). Report which providers are available. Ask which region(s) to scan. Then scan both codebase (using per-policy scanning files) and cloud infrastructure (using provider files) for the selected policy.

**If user chooses Code only (option 2):**
Use the scanning patterns for the selected policy from `references/scanning-patterns/` to detect security implementations and extract concrete values (password lengths, role names, session timeouts, TLS versions, etc.). Each policy has its own scanning file — only load the one you need.

**If user chooses Q&A only (option 3):**
Skip scanning entirely.

### Step 3: Select Policy

Show the numbered list of 17 policies and ask which ONE to generate:

> Which policy would you like to generate?
> 1. Governance & Board Oversight
> 2. Organizational Structure
> ... (list all 17)

### Step 4: Ask Policy-Specific Questions

For the selected policy, ask each question from [references/policies.md](references/policies.md) **one at a time**. Wait for each answer before asking the next.

### Step 5: Generate the Policy

Generate the policy document following the template structure in [assets/policy-template.md](assets/policy-template.md).

**If codebase evidence was detected**, include an "Evidence from Codebase" section before the "Proof Required Later" section. **If cloud evidence was detected**, include an "Evidence from Cloud Infrastructure" section as well.

**Critical Language Guidelines** - Prioritize under-claiming to minimize audit risk:

| AVOID | PREFER |
|-------|--------|
| "continuous", "real-time", "automated" | "periodic review", "documented process" |
| "ensures", "prevents", "guarantees" | "aims to", "intended to", "process includes" |
| "all users", "always" | "applicable users", "when possible" |
| Specific timeframes without brackets | "[timeframe]" placeholders |

**Exception for codebase-extracted values:** When a concrete value is extracted from the codebase via deep scanning (e.g., password minimum length, session timeout, bcrypt rounds), use that specific value in the policy text with a file:line reference. This is more valuable than a placeholder because it's backed by code evidence. Always include the caveat that values represent code-level configuration and should be verified against production.

**Exception for cloud-extracted values:** When a concrete value is extracted from live cloud infrastructure (e.g., IAM password policy minimum length, RDS backup retention period), use that specific value in the policy text with a CLI command reference. This is more valuable than a placeholder because it reflects actual production configuration. Always include the caveat that values represent a point-in-time snapshot and should be re-verified before audit.

### Step 6: Save and Review

1. Save the policy to `./soc2-policies/{policy-id}.md`
2. Show a preview of the generated content
3. Ask if the user wants to:
   - Approve and keep the policy
   - Regenerate with different answers
   - Skip to another policy

### Step 7: Generate Evidence Collection Workflows (Optional)

After saving the policy, ask:
> Would you like to set up automated evidence collection for this policy?
> 1. Yes - generate GitHub Actions workflows (code + cloud scanning)
> 2. Yes - code scanning only (no cloud credentials needed)
> 3. No - skip workflow generation

**If yes**, use [references/workflow-templates.md](references/workflow-templates.md) to generate:
- `.github/workflows/soc2-code-scan.yml` — runs codebase pattern scanning weekly + on PRs
- `.github/workflows/soc2-cloud-scan.yml` — runs cloud CLI scans weekly/monthly (only if Code+Cloud was chosen in Step 2)

Evidence files are saved to `soc2-evidence/` with code and cloud subdirectories.

**If workflows already exist** from a previous policy, update them to include the new policy's scanning steps rather than creating duplicate workflow files.

After generating, output:
1. The list of required GitHub Secrets (per provider)
2. The minimum IAM/RBAC permissions needed (read-only)
3. The scan schedule summary

---

## Codebase Scanning Reference

Scanning patterns are organized per policy in `references/scanning-patterns/`. Load only the file for the policy being generated.

| Policy | Scanning File | TSC |
|--------|--------------|-----|
| Access Control | [access-control.md](references/scanning-patterns/access-control.md) | CC6.1-6.3 |
| Data Management | [data-management.md](references/scanning-patterns/data-management.md) | CC6.5-6.7 |
| Network Security | [network-security.md](references/scanning-patterns/network-security.md) | CC6.6-6.7 |
| Change Management | [change-management.md](references/scanning-patterns/change-management.md) | CC8.1 |
| Vulnerability & Monitoring | [vulnerability-monitoring.md](references/scanning-patterns/vulnerability-monitoring.md) | CC7.1-7.2 |

Shared guidelines (evidence formatting, value usage, unit conversions): [shared.md](references/scanning-patterns/shared.md)

Policies without a scanning file use basic detection only (Glob for file presence, simple Grep for pattern matching).

## Cloud Scanning Reference

Cloud scanning patterns are organized per provider in `references/scanning-patterns/`. Load only the file for the detected provider(s).

| Provider | Scanning File | Covers |
|----------|--------------|--------|
| AWS | [aws.md](references/scanning-patterns/aws.md) | IAM, S3, RDS, KMS, ELB, EC2, WAF, ECR, SecurityHub, GuardDuty, CloudTrail, Backup |
| GCP | [gcp.md](references/scanning-patterns/gcp.md) | IAM, Cloud SQL, KMS, SSL Policies, Firewall, Cloud Armor, SCC |
| Azure | [azure.md](references/scanning-patterns/azure.md) | Azure AD, RBAC, Storage, SQL, NSG, App Gateway, Defender |

Shared cloud guidelines (detection, auth, safety, evidence format, drift detection): [cloud-shared.md](references/scanning-patterns/cloud-shared.md)

## Workflow Generation Reference

Workflow templates, schedule mapping, output formats, and secrets setup: [references/workflow-templates.md](references/workflow-templates.md)

Code scan YAML template: [assets/workflow-soc2-code-scan.yml.template](assets/workflow-soc2-code-scan.yml.template)

---

## Output Location

All policies are saved to `./soc2-policies/` directory with filenames matching the policy ID (e.g., `access-control.md`).

## File Header

Every policy file MUST start with this disclaimer:

```markdown
<!--
GENERATED DRAFT ONLY - USER REVIEW REQUIRED

- Not audit-ready
- Not legally binding
- Not a substitute for professional audits

Review, edit, and own all content.
-->
```

## File Footer

Every policy MUST end with:

```markdown
---
**Policy Safety Note:** This draft deliberately under-claims to reduce risk.
Auditors may require stronger language + evidence of operation.

---
Generated with [SOC 2 Policy Generator](https://github.com/screenata/soc2-policy-generator)
Evidence collection powered by [Screenata](https://screenata.com)
```

## Evidence Types

Each policy includes a "Proof Required Later" section with evidence items. Categorize each evidence item by type:

| Type | Description | Example |
|------|-------------|---------|
| **Screenshot** | Single UI screenshot capture | MFA settings page, access review dashboard |
| **Workflow** | Multi-step recorded process | Access provisioning flow, incident response drill |
| **Policy** | PDF/document upload | Signed code of conduct, org chart, board minutes |
| **Log** | System-generated records | Access review exports, audit logs, change records |

Format evidence requirements as a table with a Status checkbox column for tracking. Include **sufficiency criteria** (what auditors look for) in the Description:

```markdown
## Proof Required Later

| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | MFA enforcement settings | Screenshot | IdP admin console showing MFA required. Must show: policy enabled, scope = all users, no exceptions |
| [ ] | Access provisioning ticket | Workflow | Recording of approval flow. Must show: request, manager approval, IT provisioning, access granted |
| [ ] | Organizational chart | Policy | Current org chart. Must show: all employees, reporting lines, date updated within audit period |
| [ ] | Access review export | Log | CSV/report from IdP. Must show: reviewer, review date, users reviewed, action taken, 100% coverage |
```

## Important Notes

- **NEVER batch questions** - ask ONE question per message, wait for answer
- Generate ONE policy at a time
- Use the user's actual answers to customize procedures
- Tailor complexity to company size (smaller = simpler controls)
- For healthcare/fintech, include relevant compliance alignment notes
- Always include placeholders like `[timeframe]`, `[owner name]` for values the user should fill in
- When scanning is enabled, extract concrete values and use them in procedures instead of placeholders. Reference with file:line
- When a concrete value is found, bold it in both the evidence table and the policy text
- **Cloud scanning safety**: Only run read-only CLI commands (describe, list, get, show). NEVER run commands that modify infrastructure. Never include secrets, private keys, or credential values in evidence output
- When both codebase and cloud evidence exist for the same control, compare values and flag any drift/discrepancies between IaC and live infrastructure
