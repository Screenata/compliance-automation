#!/usr/bin/env bash
# .compliance/scripts/azure.sh
# Compliance evidence collection for Azure
# Requires: az CLI authenticated
# Config:   azure.config.json (co-located)
# Safety:   READ-ONLY commands only (list, show, get)
set -uo pipefail

# ── CLI check ──────────────────────────────────────────
if ! command -v az &>/dev/null; then
  echo "Skipping Azure (az CLI not installed)"
  exit 0
fi
if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed. Install it with: apt-get install jq (Linux) or brew install jq (macOS)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
SUBSCRIPTION=$(jq -r '.subscription // empty' "$CONFIG")

OUT="${COMPLIANCE_EVIDENCE_DIR:-.compliance/evidence/cloud}/azure-evidence.md"
mkdir -p "$(dirname "$OUT")"

{
  echo "# Azure Cloud Infrastructure Evidence"
  echo ""
  echo "> Scan date: $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "> Subscription: ${SUBSCRIPTION:-default}"
  echo ""
  echo "| Control | Extracted Value | Service | Region | Command | Raw Evidence |"
  echo "|---------|----------------|---------|--------|---------|-------------|"
} > "$OUT"

# ── Verify Authentication ───────────────────────────────
account_info=$(az account show -o json 2>&1 || echo '{"error": true}')
if echo "$account_info" | jq -e '.id' > /dev/null 2>&1; then
  sub_name=$(echo "$account_info" | jq -r '.name')
  sub_id=$(echo "$account_info" | jq -r '.id')
  echo "| Azure Subscription | **${sub_name}** | Account | global | \`az account show\` | ID: ${sub_id} |" >> "$OUT"
else
  echo "| Azure Authentication | **FAILED** | Account | global | \`az account show\` | Not authenticated - run az login |" >> "$OUT"
  echo "" >> "$OUT"
  echo "*Scan aborted: Azure credentials not configured.*" >> "$OUT"
  echo "FAILED: azure - credentials not configured"
  exit 1
fi

# Set subscription if specified
if [ -n "$SUBSCRIPTION" ]; then
  az account set --subscription "$SUBSCRIPTION" 2>/dev/null || true
fi

# ── Access Control (CC6.1-6.3) ──────────────────────────

# Conditional Access Policies
result=$(az ad conditional-access policy list -o json 2>&1 || echo '[]')
if echo "$result" | jq -e '.[0]' > /dev/null 2>&1; then
  ca_count=$(echo "$result" | jq 'length')
  enabled=$(echo "$result" | jq '[.[] | select(.state == "enabled")] | length')
  echo "| Conditional Access | **${ca_count} policies, ${enabled} enabled** | Azure AD | global | \`az ad conditional-access policy list\` | Conditional access policies |" >> "$OUT"
else
  echo "| Conditional Access | **not accessible** | Azure AD | global | \`az ad conditional-access policy list\` | Requires Azure AD Premium or permission |" >> "$OUT"
fi

# RBAC Role Assignments
result=$(az role assignment list --all -o json --query "[].{principal:principalName,role:roleDefinitionName,scope:scope}" 2>&1 || echo '[]')
if echo "$result" | jq -e '.[0]' > /dev/null 2>&1; then
  assignment_count=$(echo "$result" | jq 'length')
  role_count=$(echo "$result" | jq '[.[].role] | unique | length')
  owner_count=$(echo "$result" | jq '[.[] | select(.role == "Owner")] | length')
  echo "| RBAC assignments | **${assignment_count} assignments, ${role_count} distinct roles** | RBAC | global | \`az role assignment list\` | Owner assignments: ${owner_count} |" >> "$OUT"
else
  echo "| RBAC assignments | **not accessible** | RBAC | global | \`az role assignment list\` | Permission denied or error |" >> "$OUT"
fi

# ── Data Management (CC6.5-6.7) ─────────────────────────

# Storage Accounts
accounts=$(az storage account list -o json --query "[].{name:name,resourceGroup:resourceGroup}" 2>&1 || echo '[]')
acct_count=$(echo "$accounts" | jq 'length' 2>/dev/null || echo "0")
if [ "$acct_count" -gt 0 ]; then
  for i in $(seq 0 $((acct_count - 1))); do
    name=$(echo "$accounts" | jq -r ".[$i].name")
    rg=$(echo "$accounts" | jq -r ".[$i].resourceGroup")
    detail=$(az storage account show --name "$name" --resource-group "$rg" -o json 2>&1 || echo '{}')
    blob_enc=$(echo "$detail" | jq -r '.encryption.services.blob.enabled // false')
    key_source=$(echo "$detail" | jq -r '.encryption.keySource // "unknown"')
    min_tls=$(echo "$detail" | jq -r '.minimumTlsVersion // "unknown"')
    echo "| Storage ${name} | **blob:${blob_enc}, keys:${key_source}, TLS:${min_tls}** | Storage | global | \`az storage account show\` | Encryption config |" >> "$OUT"
  done
else
  echo "| Storage accounts | **none found** | Storage | global | \`az storage account list\` | No storage accounts |" >> "$OUT"
fi

# SQL Servers & Databases
servers=$(az sql server list -o json --query "[].{name:name,resourceGroup:resourceGroup}" 2>&1 || echo '[]')
srv_count=$(echo "$servers" | jq 'length' 2>/dev/null || echo "0")
if [ "$srv_count" -gt 0 ]; then
  for i in $(seq 0 $((srv_count - 1))); do
    srv_name=$(echo "$servers" | jq -r ".[$i].name")
    rg=$(echo "$servers" | jq -r ".[$i].resourceGroup")
    dbs=$(az sql db list --server "$srv_name" --resource-group "$rg" -o json --query "[?name != 'master'].{name:name,status:status}" 2>&1 || echo '[]')
    db_count=$(echo "$dbs" | jq 'length' 2>/dev/null || echo "0")
    if [ "$db_count" -gt 0 ]; then
      for j in $(seq 0 $((db_count - 1))); do
        db_name=$(echo "$dbs" | jq -r ".[$j].name")
        tde=$(az sql db tde show --database "$db_name" --server "$srv_name" --resource-group "$rg" -o json 2>&1 || echo '{}')
        tde_state=$(echo "$tde" | jq -r '.state // "unknown"')
        echo "| SQL DB ${srv_name}/${db_name} | **TDE:${tde_state}** | Azure SQL | global | \`az sql db tde show\` | Transparent Data Encryption |" >> "$OUT"
      done
    fi
  done
else
  echo "| SQL servers | **none found** | Azure SQL | global | \`az sql server list\` | No SQL servers |" >> "$OUT"
fi

# Key Vault
vaults=$(az keyvault list -o json --query "[].{name:name,resourceGroup:resourceGroup}" 2>&1 || echo '[]')
vault_count=$(echo "$vaults" | jq 'length' 2>/dev/null || echo "0")
if [ "$vault_count" -gt 0 ]; then
  for i in $(seq 0 $((vault_count - 1))); do
    vault_name=$(echo "$vaults" | jq -r ".[$i].name")
    detail=$(az keyvault show --name "$vault_name" -o json 2>&1 || echo '{}')
    soft_delete=$(echo "$detail" | jq -r '.properties.enableSoftDelete // false')
    purge_protect=$(echo "$detail" | jq -r '.properties.enablePurgeProtection // false')
    rbac_auth=$(echo "$detail" | jq -r '.properties.enableRbacAuthorization // false')
    echo "| Key Vault ${vault_name} | **softDelete:${soft_delete}, purgeProtection:${purge_protect}, RBAC:${rbac_auth}** | Key Vault | global | \`az keyvault show\` | Key management |" >> "$OUT"
  done
else
  echo "| Key Vault | **none found** | Key Vault | global | \`az keyvault list\` | No key vaults |" >> "$OUT"
fi

# ── Network Security (CC6.6-6.7) ────────────────────────

# Network Security Groups
nsgs=$(az network nsg list -o json 2>&1 || echo '[]')
nsg_count=$(echo "$nsgs" | jq 'length' 2>/dev/null || echo "0")
if [ "$nsg_count" -gt 0 ]; then
  open_rdp=$(echo "$nsgs" | jq '[.[].securityRules[] | select(.direction == "Inbound" and .access == "Allow" and .destinationPortRange == "3389" and (.sourceAddressPrefix == "*" or .sourceAddressPrefix == "Internet"))] | length' 2>/dev/null || echo "0")
  echo "| NSGs | **${nsg_count} groups** | Network | global | \`az network nsg list\` | Open RDP from Internet: ${open_rdp} |" >> "$OUT"
else
  echo "| NSGs | **none found** | Network | global | \`az network nsg list\` | No network security groups |" >> "$OUT"
fi

# Application Gateway (WAF)
gateways=$(az network application-gateway list -o json --query "[].{name:name,resourceGroup:resourceGroup}" 2>&1 || echo '[]')
gw_count=$(echo "$gateways" | jq 'length' 2>/dev/null || echo "0")
if [ "$gw_count" -gt 0 ]; then
  for i in $(seq 0 $((gw_count - 1))); do
    gw_name=$(echo "$gateways" | jq -r ".[$i].name")
    rg=$(echo "$gateways" | jq -r ".[$i].resourceGroup")
    detail=$(az network application-gateway show --name "$gw_name" --resource-group "$rg" -o json 2>&1 || echo '{}')
    min_tls=$(echo "$detail" | jq -r '.sslPolicy.minProtocolVersion // "default"')
    waf_enabled=$(echo "$detail" | jq -r '.webApplicationFirewallConfiguration.enabled // false')
    waf_mode=$(echo "$detail" | jq -r '.webApplicationFirewallConfiguration.firewallMode // "N/A"')
    echo "| App Gateway ${gw_name} | **TLS:${min_tls}, WAF:${waf_enabled}, mode:${waf_mode}** | App Gateway | global | \`az network application-gateway show\` | WAF config |" >> "$OUT"
  done
else
  echo "| App Gateway | **none found** | App Gateway | global | \`az network application-gateway list\` | No application gateways |" >> "$OUT"
fi

# Front Door
frontdoors=$(az network front-door list -o json 2>&1 || echo '[]')
fd_count=$(echo "$frontdoors" | jq 'length' 2>/dev/null || echo "0")
if [ "$fd_count" -gt 0 ]; then
  echo "| Front Door | **${fd_count} configured** | Front Door | global | \`az network front-door list\` | CDN/WAF front doors |" >> "$OUT"
else
  echo "| Front Door | **none found** | Front Door | global | \`az network front-door list\` | No front doors |" >> "$OUT"
fi

# ── Vulnerability & Monitoring (CC7.1-7.2) ───────────────

# Defender for Cloud
assessments=$(az security assessment list -o json --query "[].{name:displayName,status:status.code}" 2>&1 || echo '[]')
if echo "$assessments" | jq -e '.[0]' > /dev/null 2>&1; then
  total=$(echo "$assessments" | jq 'length')
  healthy=$(echo "$assessments" | jq '[.[] | select(.status == "Healthy")] | length')
  unhealthy=$(echo "$assessments" | jq '[.[] | select(.status == "Unhealthy")] | length')
  echo "| Defender assessments | **${total} total, ${healthy} healthy, ${unhealthy} unhealthy** | Defender | global | \`az security assessment list\` | Security posture |" >> "$OUT"
else
  echo "| Defender assessments | **not accessible** | Defender | global | \`az security assessment list\` | Defender not enabled or no permission |" >> "$OUT"
fi

# Activity Log Alerts
alerts=$(az monitor activity-log alert list -o json 2>&1 || echo '[]')
alert_count=$(echo "$alerts" | jq 'length' 2>/dev/null || echo "0")
echo "| Activity log alerts | **${alert_count} alerts** | Monitor | global | \`az monitor activity-log alert list\` | Monitoring alerts |" >> "$OUT"

# ── Footer ──────────────────────────────────────────────
echo "" >> "$OUT"
echo "*Values extracted from live Azure infrastructure. These represent point-in-time configuration. Re-scan and verify before audit submission.*" >> "$OUT"

echo "OK: azure evidence written to $OUT"
