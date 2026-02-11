#!/usr/bin/env bash
# .compliance/scripts/cloudflare.sh
# Compliance evidence collection for Cloudflare
# Requires: CLOUDFLARE_API_TOKEN env var
# Config:   cloudflare.config.json { "account_id": "abc123" }
# Safety:   READ-ONLY API calls only (GET requests)
set -uo pipefail

# ── CLI check ──────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed. Install it with: apt-get install jq (Linux) or brew install jq (macOS)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
ACCOUNT_ID=$(jq -r '.account_id // empty' "$CONFIG")

OUT="${COMPLIANCE_EVIDENCE_DIR:-.compliance/evidence/saas}/$(basename "$0" .sh)-evidence.md"
mkdir -p "$(dirname "$OUT")"

{
  echo "# Cloudflare - SaaS Evidence"
  echo ""
  echo "> Scan date: $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "> Tool: Cloudflare"
  echo "> Account ID: ${ACCOUNT_ID:-not configured}"
  echo ""
  echo "| Control | Extracted Value | Tool | API Endpoint | Raw Evidence |"
  echo "|---------|----------------|------|-------------|-------------|"
} > "$OUT"

CF_API="https://api.cloudflare.com/client/v4"
AUTH=(-H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H "Content-Type: application/json")

# ── Verify Authentication ───────────────────────────────
verify=$(curl -sf "${AUTH[@]}" "$CF_API/user/tokens/verify" || echo '{"success":false}')
if echo "$verify" | jq -e '.success == true' > /dev/null 2>&1; then
  echo "| API Authentication | **verified** | Cloudflare | \`/user/tokens/verify\` | Token valid |" >> "$OUT"
else
  echo "| API Authentication | **FAILED** | Cloudflare | \`/user/tokens/verify\` | Token invalid or expired |" >> "$OUT"
  echo "" >> "$OUT"
  echo "*Scan aborted: Cloudflare API token not valid.*" >> "$OUT"
  echo "FAILED: cloudflare - API token not valid"
  exit 1
fi

# ── Zones ───────────────────────────────────────────────
zones=$(curl -sf "${AUTH[@]}" "$CF_API/zones?per_page=50" || echo '{"success":false}')
if echo "$zones" | jq -e '.success == true' > /dev/null 2>&1; then
  zone_count=$(echo "$zones" | jq '.result | length')
  echo "| Zones | **${zone_count} zones** | Cloudflare | \`/zones\` | ${zone_count} zones in account |" >> "$OUT"

  # Check SSL/TLS and security settings per zone (first 10)
  ssl_strict=0
  always_https=0
  checked=0
  for zone_id in $(echo "$zones" | jq -r '.result[].id' | head -10); do
    checked=$((checked + 1))

    # SSL mode
    ssl=$(curl -sf "${AUTH[@]}" "$CF_API/zones/$zone_id/settings/ssl" || echo '{"success":false}')
    ssl_mode=$(echo "$ssl" | jq -r '.result.value // "unknown"')
    if [ "$ssl_mode" = "strict" ] || [ "$ssl_mode" = "full" ]; then
      ssl_strict=$((ssl_strict + 1))
    fi

    # Always Use HTTPS
    https_setting=$(curl -sf "${AUTH[@]}" "$CF_API/zones/$zone_id/settings/always_use_https" || echo '{"success":false}')
    https_val=$(echo "$https_setting" | jq -r '.result.value // "off"')
    if [ "$https_val" = "on" ]; then
      always_https=$((always_https + 1))
    fi
  done
  echo "| SSL/TLS strict+ | **${ssl_strict} of ${checked} sampled** | Cloudflare | \`/zones/{id}/settings/ssl\` | ${ssl_strict} zones with full/strict SSL (first ${checked}) |" >> "$OUT"
  echo "| Always HTTPS | **${always_https} of ${checked} sampled** | Cloudflare | \`/zones/{id}/settings/always_use_https\` | ${always_https} zones with forced HTTPS (first ${checked}) |" >> "$OUT"
else
  echo "| Zones | **not accessible** | Cloudflare | \`/zones\` | Permission denied or error |" >> "$OUT"
fi

# ── WAF (Account level) ────────────────────────────────
if [ -n "$ACCOUNT_ID" ]; then
  waf=$(curl -sf "${AUTH[@]}" "$CF_API/accounts/$ACCOUNT_ID/firewall/access_rules/rules?per_page=1" || echo '{"success":false}')
  if echo "$waf" | jq -e '.success == true' > /dev/null 2>&1; then
    waf_total=$(echo "$waf" | jq '.result_info.total_count // 0')
    echo "| Firewall access rules | **${waf_total} rules** | Cloudflare | \`/accounts/{id}/firewall/access_rules\` | ${waf_total} account-level firewall rules |" >> "$OUT"
  fi
fi

# ── DNS Security ────────────────────────────────────────
if echo "$zones" | jq -e '.success == true' > /dev/null 2>&1; then
  dnssec_count=0
  checked=0
  for zone_id in $(echo "$zones" | jq -r '.result[].id' | head -10); do
    checked=$((checked + 1))
    dnssec=$(curl -sf "${AUTH[@]}" "$CF_API/zones/$zone_id/dnssec" || echo '{"success":false}')
    dnssec_status=$(echo "$dnssec" | jq -r '.result.status // "disabled"')
    if [ "$dnssec_status" = "active" ]; then
      dnssec_count=$((dnssec_count + 1))
    fi
  done
  echo "| DNSSEC | **${dnssec_count} of ${checked} sampled active** | Cloudflare | \`/zones/{id}/dnssec\` | ${dnssec_count} zones with DNSSEC enabled (first ${checked}) |" >> "$OUT"
fi

# ── Account Members ─────────────────────────────────────
if [ -n "$ACCOUNT_ID" ]; then
  members=$(curl -sf "${AUTH[@]}" "$CF_API/accounts/$ACCOUNT_ID/members?per_page=50" || echo '{"success":false}')
  if echo "$members" | jq -e '.success == true' > /dev/null 2>&1; then
    member_count=$(echo "$members" | jq '.result | length')
    admin_count=$(echo "$members" | jq '[.result[] | select(.roles[]?.name == "Administrator")] | length')
    echo "| Account members | **${member_count} members** | Cloudflare | \`/accounts/{id}/members\` | ${admin_count} administrators |" >> "$OUT"
  fi
fi

echo "" >> "$OUT"
echo "*Auto-generated by compliance-evidence scripts.*" >> "$OUT"
echo "OK: cloudflare evidence written to $OUT"
