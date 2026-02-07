# SaaS Integration — Project & Change Management

Covers: Jira, Linear, GitHub (Issues & PRs)
TSC: CC8.1 (Change Management), CC7.1 (Vulnerability Monitoring)

---

## Jira

**SOC 2 evidence provided:**

| Evidence | TSC | API Endpoint | Method |
|----------|-----|-------------|--------|
| Change management workflow | CC8.1 | `GET /rest/api/3/project/{key}/statuses` | Basic auth (email:token) |
| Open change requests | CC8.1 | `GET /rest/api/3/search?jql=project={key} AND type=Task AND status!=Done` | Basic auth |
| Recently closed changes | CC8.1 | `GET /rest/api/3/search?jql=project={key} AND status=Done AND resolved>=-30d` | Basic auth |
| Approval workflows | CC8.1 | Check for approval custom fields or workflow transitions | Basic auth |

**Auth:** `Authorization: Basic {base64(email:api_token)}`
**Base URL:** `https://{domain}.atlassian.net`
**Rate limit:** 450 requests/min per user.

**Script pattern (change management metrics):**
```bash
#!/usr/bin/env bash
# .compliance/scripts/jira.sh (excerpt)
# Requires: JIRA_API_TOKEN, JIRA_EMAIL env vars
# Config:   jira.config.json { "domain": "https://company.atlassian.net", "project": "ENG" }
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
DOMAIN=$(jq -r '.domain' "$CONFIG")
PROJECT=$(jq -r '.project' "$CONFIG")
AUTH=$(echo -n "$JIRA_EMAIL:$JIRA_API_TOKEN" | base64)

# ... (header/output setup per script-templates.md) ...

open=$(curl -sf -H "Authorization: Basic $AUTH" \
  "$DOMAIN/rest/api/3/search?jql=project%3D${PROJECT}%20AND%20status%21%3DDone&maxResults=0" \
  | jq '.total // 0' || echo "0")
resolved=$(curl -sf -H "Authorization: Basic $AUTH" \
  "$DOMAIN/rest/api/3/search?jql=project%3D${PROJECT}%20AND%20status%3DDone%20AND%20resolved%3E%3D-30d&maxResults=0" \
  | jq '.total // 0' || echo "0")
echo "| Change tickets | **${open} open, ${resolved} resolved (30d)** | Jira | \`/rest/api/3/search\` | ${open} open, ${resolved} resolved in 30 days |" >> "$OUT"
```

---

## Linear

**SOC 2 evidence provided:**

| Evidence | TSC | API Endpoint | Method |
|----------|-----|-------------|--------|
| Team workflows | CC8.1 | GraphQL: `{ teams { nodes { name states { nodes { name type } } } } }` | Bearer token |
| Open issues count | CC8.1 | GraphQL: `{ issues(filter: { state: { type: { in: ["started", "unstarted"] } } }) { totalCount } }` | Bearer token |
| Completed issues (30d) | CC8.1 | GraphQL with `completedAt` filter | Bearer token |
| Labels/categories | CC8.1 | GraphQL: `{ issueLabels { nodes { name } } }` | Bearer token |

**Auth:** `Authorization: {LINEAR_API_KEY}`
**Endpoint:** `https://api.linear.app/graphql`

---

## GitHub (Issues & PRs)

**SOC 2 evidence provided:**

| Evidence | TSC | API Endpoint | Method |
|----------|-----|-------------|--------|
| Branch protection rules | CC8.1 | `GET /repos/{owner}/{repo}/branches/{branch}/protection` | Bearer token |
| Required reviewers | CC8.1 | Branch protection -> `required_pull_request_reviews` | Bearer token |
| Open PRs | CC8.1 | `GET /repos/{owner}/{repo}/pulls?state=open` | Bearer token |
| Merged PRs (30d) | CC8.1 | `GET /search/issues?q=repo:{repo}+type:pr+is:merged+merged:>={date}` | Bearer token |
| Security alerts | CC7.1 | `GET /repos/{owner}/{repo}/dependabot/alerts?state=open` | Bearer token |
| Code scanning alerts | CC7.1 | `GET /repos/{owner}/{repo}/code-scanning/alerts?state=open` | Bearer token |

**Auth:** `Authorization: Bearer {GITHUB_TOKEN}` (use `${{ secrets.GITHUB_TOKEN }}` in workflows for same-repo, or a PAT for org-wide)
**Base URL:** `https://api.github.com`
**Rate limit:** 5,000 requests/hour with token.

**Note:** For `.compliance/scripts/github.sh`, prefer using `gh` CLI which is pre-installed and auto-authenticated in GitHub Actions:
```bash
#!/usr/bin/env bash
# .compliance/scripts/github.sh (excerpt)
# Requires: GH_TOKEN and REPO env vars (auto-set in GitHub Actions)
set -euo pipefail

# ... (header/output setup per script-templates.md) ...

# Branch protection
reviewers=$(gh api "repos/${REPO}/branches/main/protection" \
  --jq '.required_pull_request_reviews.required_approving_review_count' 2>/dev/null || echo "0")
echo "| Required reviewers | **${reviewers}** | GitHub | \`/branches/main/protection\` | ${reviewers} approving reviews required |" >> "$OUT"

# Dependabot alerts
dep_count=$(gh api "repos/${REPO}/dependabot/alerts?state=open&per_page=1" \
  --jq 'length' 2>/dev/null || echo "0")
echo "| Dependabot alerts | **${dep_count}+** | GitHub | \`/dependabot/alerts\` | ${dep_count}+ open alerts |" >> "$OUT"
```
