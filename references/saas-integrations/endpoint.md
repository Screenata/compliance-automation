# SaaS Integration — Endpoint Management

Covers: Jamf Pro, Kandji, Microsoft Intune
TSC: CC6.5 (Data Management — encryption), CC6.8 (Endpoint Security), CC7.1 (Vulnerability Monitoring)

---

## Jamf Pro

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| Managed devices count | CC6.8 | `GET /api/v1/computers-inventory?section=GENERAL&page-size=1` | Bearer token |
| Compliance policies | CC6.8 | `GET /api/v2/computer-prestages` | Bearer token |
| FileVault encryption status | CC6.5 | `GET /api/v1/computers-inventory?section=DISK_ENCRYPTION` | Bearer token |
| OS update compliance | CC7.1 | `GET /api/v1/computers-inventory?section=OPERATING_SYSTEM` | Bearer token |

**Auth:** Bearer token via client credentials:
```bash
# In .compliance/scripts/jamf.sh — obtain token from client credentials
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
JAMF_URL=$(jq -r '.url' "$CONFIG")  # e.g., "https://company.jamfcloud.com"

TOKEN=$(curl -sf -X POST "$JAMF_URL/api/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$JAMF_CLIENT_ID&client_secret=$JAMF_CLIENT_SECRET&grant_type=client_credentials" \
  | jq -r '.access_token')
```

---

## Kandji

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| Device count | CC6.8 | `GET /api/v1/devices` | Bearer token |
| Blueprint (policy) count | CC6.8 | `GET /api/v1/blueprints` | Bearer token |
| Device compliance status | CC6.8 | Device details -> compliance status | Bearer token |

**Auth:** `Authorization: Bearer {KANDJI_API_TOKEN}`
**Base URL:** `https://{subdomain}.api.kandji.io`

---

## Microsoft Intune

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| Managed devices count | CC6.8 | `GET /v1.0/deviceManagement/managedDevices?$count=true` | Bearer token (MS Graph) |
| Compliance policies | CC6.8 | `GET /v1.0/deviceManagement/deviceCompliancePolicies` | Bearer token |
| Compliance status | CC6.8 | `GET /v1.0/deviceManagement/deviceCompliancePolicyDeviceStateSummary` | Bearer token |

**Auth:** MS Graph OAuth2 — use `azure/login@v2` action, then acquire token for Graph API.
