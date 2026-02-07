# SaaS Integration — Shared Guidelines

The agent generates custom API integrations on demand based on the user's SaaS stack. These reference files map common tools to the SOC 2 evidence they provide, with API patterns and auth methods.

**Key principle:** Unlike pre-built connectors, the agent knows these APIs and generates the exact integration needed. These files provide the SOC 2 mapping and structural patterns — the agent fills in the API details.

## How SaaS Evidence Collection Works

1. User declares their SaaS tools in Step 1 (Q13)
2. During policy generation, the agent maps tools to relevant SOC 2 controls
3. During evidence script generation (Step 7a), the agent copies pre-built scripts from `assets/scripts/` when available, or generates new scripts on demand as a fallback
4. The agent asks for config values and tests each script locally before wiring it into a workflow
5. During workflow generation (Step 7b), the agent generates GitHub Actions that call the tested scripts
6. Evidence is written to `.compliance/evidence/saas/{tool}-evidence.md`

## Safety Rules

- **Read-only API calls only** — never call endpoints that create, update, or delete data
- **No PII in evidence** — redact user emails, names, phone numbers. Use counts and percentages instead (e.g., "48 of 50 users have MFA" not a list of user emails)
- **Redact tokens and secrets** — never include API keys, tokens, or credentials in evidence output
- **Rate limit awareness** — include `sleep` between API calls where noted; respect 429 responses
- **Pagination** — use pagination for list endpoints; don't assume all results fit in one response
- **Error handling** — wrap API calls in `|| true` so workflow continues if one tool is unreachable

## Evidence Table Format

SaaS evidence uses a 5-column format:

```markdown
## Evidence from SaaS Tools

| Control | Extracted Value | Tool | API Endpoint | Raw Evidence |
|---------|----------------|------|-------------|-------------|
| MFA enrollment rate | **96% (48/50 users)** | Okta | `/api/v1/users` | 48 of 50 active users have MFA factor enrolled |
| Open incidents | **3 active (0 critical)** | PagerDuty | `/incidents` | 3 triggered incidents, 0 high urgency |
```

## Cross-Source Evidence Comparison

When evidence exists from multiple sources (code, cloud, SaaS), compare overlapping controls:

```markdown
### Cross-Source Evidence Comparison

| Control | Code | Cloud | SaaS | Status |
|---------|------|-------|------|--------|
| MFA required | **configured** (`auth.ts:12`) | **enabled** (AWS IAM) | **96% enrolled** (Okta) | Consistent |
| Password min length | **12 chars** (`password.ts:18`) | **14 chars** (AWS IAM) | **12 chars** (Okta policy) | MISMATCH — AWS IAM stricter |
```

## Script Generation Pattern

Every SaaS tool gets a standalone script (`.compliance/scripts/{tool}.sh`) + config file (`.compliance/scripts/{tool}.config.json`). See [script-templates.md](../script-templates.md) for the full template.

```bash
#!/usr/bin/env bash
# .compliance/scripts/{tool}.sh
# SOC 2 evidence collection for {Tool Name}
# Requires: {TOOL}_API_TOKEN env var
# Config:   {tool}.config.json (co-located)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
DOMAIN=$(jq -r '.domain // empty' "$CONFIG")

OUT="${SOC2_EVIDENCE_DIR:-.compliance/evidence/saas}/$(basename "$0" .sh)-evidence.md"
mkdir -p "$(dirname "$OUT")"

{
  echo "# {Tool Name} - SaaS Evidence"
  echo ""
  echo "> Scan date: $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "> Tool: {Tool Name}"
  echo ""
  echo "| Control | Extracted Value | Tool | API Endpoint | Raw Evidence |"
  echo "|---------|----------------|------|-------------|-------------|"
} > "$OUT"

# API calls — each with || echo "{}" for graceful degradation
result=$(curl -sf -H "Authorization: {auth_scheme} ${API_TOKEN}" \
  "${DOMAIN}/{endpoint}" || echo "{}")
value=$(echo "$result" | jq -r '{extraction_expression}')
echo "| {control_name} | **${value}** | {Tool} | \`{endpoint}\` | $(echo "$result" | jq -c '{summary}' | head -c 80) |" >> "$OUT"

echo "OK: {tool} evidence written to $OUT"
```

## Workflow Step Pattern

Workflows call the tested scripts — no inline bash:

```yaml
- name: "Scan: {Tool Name}"
  env:
    {TOOL}_API_TOKEN: ${{ secrets.{TOOL}_API_TOKEN }}
    {TOOL}_DOMAIN: ${{ secrets.{TOOL}_DOMAIN }}
  run: |
    if [ -z "$TOOL_API_TOKEN" ]; then echo "Skipping {tool} (no token)"; exit 0; fi
    # Note: replace TOOL with actual tool name, e.g. $OKTA_API_TOKEN
    bash .compliance/scripts/{tool}.sh
```

## Test-First Workflow

The agent tests each script locally before wiring it into a GitHub Actions workflow:

1. **Copy or generate** — if a pre-built script exists in `assets/scripts/{tool}.sh`, copy it to `.compliance/scripts/`. Otherwise, generate a new script using API patterns from this directory
2. **Configure** — agent asks user for non-secret config values (domain, project key) and writes to `{tool}.config.json`
3. **Export secrets** — agent asks user to `export {TOOL}_API_TOKEN="..."`
4. **Test** — agent runs `bash .compliance/scripts/{tool}.sh`
5. **Verify** — agent reads the output evidence file, checks for errors, fixes issues
6. **Iterate** — if pre-built script fails (API changed, version mismatch), agent fixes the script or generates a new one from scratch, then retests
7. **Wire** — once verified, agent generates the workflow step that calls the script

## Secrets Naming Convention

| Tool | Secret Name | Value |
|------|------------|-------|
| Okta | `OKTA_API_TOKEN` | API token from Security > API > Tokens |
| Auth0 | `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET` | Machine-to-machine application credentials |
| Google Workspace | `GOOGLE_SA_KEY` | Service account JSON with admin SDK read-only |
| Datadog | `DATADOG_API_KEY`, `DATADOG_APP_KEY` | API + application key from Organization Settings |
| PagerDuty | `PAGERDUTY_API_TOKEN` | Read-only API token from Integrations > API Access |
| New Relic | `NEWRELIC_API_KEY` | User key from API Keys page |
| Jira | `JIRA_API_TOKEN`, `JIRA_EMAIL` | API token + email from Atlassian account |
| Linear | `LINEAR_API_KEY` | Personal API key from Settings > API |
| Slack | `SLACK_BOT_TOKEN` | Bot token with required read scopes |
| BambooHR | `BAMBOOHR_API_KEY`, `BAMBOOHR_SUBDOMAIN` | API key from Account > API Keys |
| Jamf | `JAMF_CLIENT_ID`, `JAMF_CLIENT_SECRET` | API client credentials |
| Snyk | `SNYK_TOKEN` | API token from Account Settings |

## Handling Unknown Tools

If the user names a SaaS tool not in the catalog:

1. **Check if the agent knows the API** — most AI coding agents have knowledge of popular SaaS APIs. Generate the integration using that knowledge, following the patterns above.
2. **If the API is unknown**, ask the user:
   > I'm not familiar with {tool}'s API. Could you provide:
   > - The API documentation URL
   > - What SOC 2 evidence you'd like to extract from it
   >
   > I'll generate the integration from the docs.
3. **If the user provides docs**, use WebFetch to read the API documentation and generate the integration.
4. **If no docs available**, note it as a manual evidence item in "Proof Required Later" instead.

## Tool-to-Policy Mapping Summary

Quick reference for which tools provide evidence for which policies:

| Policy | Relevant SaaS Tools |
|--------|-------------------|
| Access Control (CC6.1-6.3) | Okta, Auth0, Google Workspace, JumpCloud, Slack (2FA), GitHub (branch protection) |
| Data Management (CC6.5-6.7) | Jamf/Kandji (FileVault), Snyk (dependency scanning) |
| Network Security (CC6.6-6.7) | Datadog (network monitors), Snyk |
| Change Management (CC8.1) | Jira, Linear, GitHub (PRs/reviews), SonarCloud |
| Vulnerability Monitoring (CC7.1-7.2) | Snyk, SonarCloud, GitHub (Dependabot/CodeQL), Datadog (SIEM) |
| Incident Response (CC7.3-7.5) | PagerDuty, Opsgenie, Slack (incident channels), Statuspage |
| Business Continuity (A1.2-A1.3) | Datadog (SLOs), Statuspage (uptime), PagerDuty (on-call) |
| HR & Personnel (CC1.4) | BambooHR, Gusto, Rippling |
| Endpoint Security (CC6.8) | Jamf, Kandji, Intune, Rippling |
