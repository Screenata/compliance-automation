# SaaS Integration — Identity & Access Management

Covers: Okta, Auth0, Google Workspace, JumpCloud
TSC: CC6.1-6.3 (Access Control)

---

## Okta

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| MFA enrollment rate | CC6.1 | `GET /api/v1/users?filter=status eq "ACTIVE"` then check factors | Bearer token |
| Password policy settings | CC6.1 | `GET /api/v1/policies?type=PASSWORD` | Bearer token |
| Active user count | CC6.1 | `GET /api/v1/users?filter=status eq "ACTIVE"&limit=1` (use header for count) | Bearer token |
| Admin role assignments | CC6.3 | `GET /api/v1/users?filter=status eq "ACTIVE"` + check admin group membership | Bearer token |
| Deactivated users (recent) | CC6.2 | `GET /api/v1/users?filter=status eq "DEPROVISIONED"&sortBy=statusChanged&sortOrder=desc` | Bearer token |
| Application assignments | CC6.1 | `GET /api/v1/apps?filter=status eq "ACTIVE"` | Bearer token |
| Sign-on policy | CC6.1 | `GET /api/v1/policies?type=OKTA_SIGN_ON` | Bearer token |

**Auth:** `Authorization: SSWS {OKTA_API_TOKEN}`
**Base URL:** `https://{okta_domain}.okta.com`
**Rate limit:** 600 requests/min for most endpoints. Add 1s sleep between paginated calls.

**Script pattern (MFA enrollment check):**
```bash
#!/usr/bin/env bash
# .compliance/scripts/okta.sh (excerpt)
# Requires: OKTA_API_TOKEN env var
# Config:   okta.config.json { "domain": "https://company.okta.com" }
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
DOMAIN=$(jq -r '.domain' "$CONFIG")

# ... (header/output setup per script-templates.md) ...

# MFA enrollment check — sample first 50 users for rate limit safety
users=$(curl -sf -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "$DOMAIN/api/v1/users?filter=status%20eq%20%22ACTIVE%22&limit=200" || echo "[]")
total=$(echo "$users" | jq 'length')
mfa_count=0
for uid in $(echo "$users" | jq -r '.[0:50] | .[].id'); do
  factors=$(curl -sf -H "Authorization: SSWS $OKTA_API_TOKEN" \
    "$DOMAIN/api/v1/users/$uid/factors" || echo "[]")
  has_mfa=$(echo "$factors" | jq '[.[] | select(.status == "ACTIVE")] | length')
  [ "$has_mfa" -gt 0 ] && mfa_count=$((mfa_count + 1))
  sleep 0.2  # Rate limiting
done
sampled=$(echo "$users" | jq '.[0:50] | length')
pct=$(( sampled > 0 ? mfa_count * 100 / sampled : 0 ))
echo "| MFA enrollment | **${mfa_count}/${sampled} sampled (${pct}%)** | Okta | \`/api/v1/users + /factors\` | ${mfa_count} of ${sampled} sampled users have active MFA |" >> "$OUT"
```

---

## Auth0

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| MFA policy status | CC6.1 | `GET /api/v2/guardian/factors` | Bearer token (Management API) |
| Connection settings | CC6.1 | `GET /api/v2/connections` | Bearer token |
| Active users count | CC6.1 | `GET /api/v2/users?include_totals=true&per_page=0` | Bearer token |
| Brute force protection | CC6.1 | `GET /api/v2/attack-protection/brute-force-protection` | Bearer token |
| Suspicious IP throttling | CC6.1 | `GET /api/v2/attack-protection/suspicious-ip-throttling` | Bearer token |
| Log streams | CC7.2 | `GET /api/v2/log-streams` | Bearer token |

**Auth:** OAuth2 client_credentials flow -> Bearer token
```bash
# In .compliance/scripts/auth0.sh — obtain Management API token
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
AUTH0_DOMAIN=$(jq -r '.domain' "$CONFIG")  # e.g., "company.us.auth0.com"

TOKEN=$(curl -sf --request POST \
  --url "https://$AUTH0_DOMAIN/oauth/token" \
  --header 'content-type: application/json' \
  --data "{\"client_id\":\"$AUTH0_CLIENT_ID\",\"client_secret\":\"$AUTH0_CLIENT_SECRET\",\"audience\":\"https://$AUTH0_DOMAIN/api/v2/\",\"grant_type\":\"client_credentials\"}" \
  | jq -r '.access_token')
```
**Rate limit:** 50 requests/second for Management API.

---

## Google Workspace (Admin SDK)

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| 2FA enrollment status | CC6.1 | `GET /admin/reports/v1/usage/users` | OAuth2 service account |
| User count & status | CC6.1 | `GET /admin/directory/v1/users?domain={domain}&maxResults=1` | OAuth2 |
| Suspended users | CC6.2 | `GET /admin/directory/v1/users?domain={domain}&query=isSuspended=true` | OAuth2 |
| Admin roles | CC6.3 | `GET /admin/directory/v1/users?domain={domain}&query=isAdmin=true` | OAuth2 |
| Mobile device management | CC6.8 | `GET /admin/directory/v1/customer/{id}/devices/mobile` | OAuth2 |
| Audit log | CC7.2 | `GET /admin/reports/v1/activity/users/all/applications/login` | OAuth2 |

**Auth:** Service account with domain-wide delegation, scopes: `admin.directory.user.readonly`, `admin.reports.usage.readonly`

---

## JumpCloud

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| MFA status | CC6.1 | `GET /api/v2/users` (check `mfa.configured`) | x-api-key header |
| System users count | CC6.1 | `GET /api/systemusers` | x-api-key header |
| Policies | CC6.1 | `GET /api/v2/policies` | x-api-key header |
| User groups | CC6.3 | `GET /api/v2/usergroups` | x-api-key header |

**Auth:** `x-api-key: {JUMPCLOUD_API_KEY}`
**Base URL:** `https://console.jumpcloud.com`
