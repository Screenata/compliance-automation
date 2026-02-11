#!/usr/bin/env bash
# .compliance/scripts/vercel.sh
# Compliance evidence collection for Vercel
# Requires: VERCEL_TOKEN env var
# Config:   vercel.config.json { "team_id": "team_abc123" }
# Safety:   READ-ONLY API calls only (GET requests)
set -uo pipefail

# ── CLI check ──────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed. Install it with: apt-get install jq (Linux) or brew install jq (macOS)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
TEAM_ID=$(jq -r '.team_id // empty' "$CONFIG")

OUT="${COMPLIANCE_EVIDENCE_DIR:-.compliance/evidence/saas}/$(basename "$0" .sh)-evidence.md"
mkdir -p "$(dirname "$OUT")"

{
  echo "# Vercel - SaaS Evidence"
  echo ""
  echo "> Scan date: $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "> Tool: Vercel"
  echo "> Team ID: ${TEAM_ID:-not configured}"
  echo ""
  echo "| Control | Extracted Value | Tool | API Endpoint | Raw Evidence |"
  echo "|---------|----------------|------|-------------|-------------|"
} > "$OUT"

VERCEL_API="https://api.vercel.com"
AUTH=(-H "Authorization: Bearer $VERCEL_TOKEN")
TEAM_PARAM=""
[ -n "$TEAM_ID" ] && TEAM_PARAM="?teamId=$TEAM_ID"

# ── Verify Authentication ───────────────────────────────
user=$(curl -sf "${AUTH[@]}" "$VERCEL_API/v2/user" || echo '{"error":true}')
if echo "$user" | jq -e '.user.id' > /dev/null 2>&1; then
  username=$(echo "$user" | jq -r '.user.username')
  echo "| API Authentication | **verified (${username})** | Vercel | \`/v2/user\` | Token valid |" >> "$OUT"
else
  echo "| API Authentication | **FAILED** | Vercel | \`/v2/user\` | Token invalid or expired |" >> "$OUT"
  echo "" >> "$OUT"
  echo "*Scan aborted: Vercel API token not valid.*" >> "$OUT"
  echo "FAILED: vercel - API token not valid"
  exit 1
fi

# ── Team Info ───────────────────────────────────────────
if [ -n "$TEAM_ID" ]; then
  team=$(curl -sf "${AUTH[@]}" "$VERCEL_API/v2/teams/$TEAM_ID" || echo '{"error":true}')
  if echo "$team" | jq -e '.id' > /dev/null 2>&1; then
    team_name=$(echo "$team" | jq -r '.name')
    saml=$(echo "$team" | jq -r '.saml.connection.state // "not configured"')
    echo "| Team | **${team_name}** | Vercel | \`/v2/teams/{id}\` | Team: ${team_name} |" >> "$OUT"
    echo "| SAML SSO | **${saml}** | Vercel | \`/v2/teams/{id}\` | SAML state: ${saml} |" >> "$OUT"
  fi

  # Team members
  members=$(curl -sf "${AUTH[@]}" "$VERCEL_API/v2/teams/$TEAM_ID/members?limit=100" || echo '{"members":[]}')
  if echo "$members" | jq -e '.members' > /dev/null 2>&1; then
    member_count=$(echo "$members" | jq '.members | length')
    owner_count=$(echo "$members" | jq '[.members[] | select(.role == "OWNER")] | length')
    echo "| Team members | **${member_count} members** | Vercel | \`/v2/teams/{id}/members\` | ${owner_count} owners |" >> "$OUT"
  fi
fi

# ── Projects ───────────────────────────────────────────
projects=$(curl -sf "${AUTH[@]}" "$VERCEL_API/v9/projects${TEAM_PARAM}&limit=100" 2>/dev/null \
  || curl -sf "${AUTH[@]}" "$VERCEL_API/v9/projects?limit=100" 2>/dev/null \
  || echo '{"projects":[]}')
if echo "$projects" | jq -e '.projects' > /dev/null 2>&1; then
  project_count=$(echo "$projects" | jq '.projects | length')
  echo "| Projects | **${project_count} projects** | Vercel | \`/v9/projects\` | ${project_count} projects in scope |" >> "$OUT"

  # Check environment variables protection (first 10 projects)
  env_protected=0
  checked=0
  for project_id in $(echo "$projects" | jq -r '.projects[].id' | head -10); do
    checked=$((checked + 1))
    proj_detail=$(curl -sf "${AUTH[@]}" "$VERCEL_API/v9/projects/$project_id${TEAM_PARAM}" 2>/dev/null \
      || curl -sf "${AUTH[@]}" "$VERCEL_API/v9/projects/$project_id" 2>/dev/null \
      || echo '{}')
    # Check if project has environment variable protection
    has_protection=$(echo "$proj_detail" | jq -r '.autoExposeSystemEnvs // false')
    if [ "$has_protection" = "true" ]; then
      env_protected=$((env_protected + 1))
    fi
  done
  echo "| System env exposure | **${env_protected} of ${checked} sampled** | Vercel | \`/v9/projects/{id}\` | ${env_protected} projects with auto-expose system envs (first ${checked}) |" >> "$OUT"
fi

# ── Deployments (recent activity) ──────────────────────
deployments=$(curl -sf "${AUTH[@]}" "$VERCEL_API/v6/deployments${TEAM_PARAM}&limit=20" 2>/dev/null \
  || curl -sf "${AUTH[@]}" "$VERCEL_API/v6/deployments?limit=20" 2>/dev/null \
  || echo '{"deployments":[]}')
if echo "$deployments" | jq -e '.deployments' > /dev/null 2>&1; then
  deploy_count=$(echo "$deployments" | jq '.deployments | length')
  ready_count=$(echo "$deployments" | jq '[.deployments[] | select(.readyState == "READY")] | length')
  error_count=$(echo "$deployments" | jq '[.deployments[] | select(.readyState == "ERROR")] | length')
  echo "| Recent deployments | **${deploy_count} recent** | Vercel | \`/v6/deployments\` | ${ready_count} ready, ${error_count} errors |" >> "$OUT"
fi

# ── Firewall (if available) ────────────────────────────
if [ -n "$TEAM_ID" ]; then
  firewall=$(curl -sf "${AUTH[@]}" "$VERCEL_API/v1/security/firewall/config${TEAM_PARAM}" 2>/dev/null || echo '{"error":true}')
  if echo "$firewall" | jq -e '.rules' > /dev/null 2>&1; then
    rule_count=$(echo "$firewall" | jq '.rules | length')
    echo "| Firewall rules | **${rule_count} rules** | Vercel | \`/v1/security/firewall/config\` | ${rule_count} firewall rules configured |" >> "$OUT"
  fi
fi

echo "" >> "$OUT"
echo "*Auto-generated by compliance-evidence scripts.*" >> "$OUT"
echo "OK: vercel evidence written to $OUT"
