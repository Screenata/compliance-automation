# Azure Cloud Scanning Patterns

For cloud scanning of Azure infrastructure.
**Pre-built script:** `assets/scripts/azure.sh` — copy to `.compliance/scripts/` and configure with `azure.config.json`.
See [cloud-shared.md](cloud-shared.md) for authentication, safety rules, and evidence formatting.

## Prerequisites

- Azure CLI installed (`az --version`)
- Authenticated (`az account show`)
- Subscription selected (`az account list --query "[?isDefault]" -o json`)
- Use `-o json` on all commands for parseable output

---

## Access Control (CC6.1-6.3)

### Conditional Access Policies

**Command:**
```bash
az ad conditional-access policy list -o json
```

Note: Requires Azure AD Premium. Skip if command fails with permission error.

**Extract from output:**
- Count of policies -> total conditional access policies
- `.displayName` -> policy names
- `.state` -> enabled / disabled / enabledForReportingButNotEnforced

**Use in policy text:**
- Instead of: "Conditional access policies are configured"
- Write: "**5 conditional access policies** are configured and **enabled** including MFA enforcement and location-based access (see `az ad conditional-access policy list`)."

### RBAC Role Assignments

**Command:**
```bash
az role assignment list --all -o json --query "[].{principal:principalName,role:roleDefinitionName,scope:scope}"
```

**Extract from output:**
- Count of assignments -> total RBAC assignments
- Count of unique `roleDefinitionName` -> distinct roles in use
- Flag any `Owner` or `Contributor` at subscription scope as notable

**Use in policy text:**
- Instead of: "Role-based access control is implemented"
- Write: "Azure RBAC has **34 role assignments** using **8 distinct roles**. **2 Owner assignments** exist at subscription level (see `az role assignment list`)."

### Azure AD MFA Registration

**Command:**
```bash
az ad user list --query "[].{name:displayName,mfa:strongAuthenticationMethods}" -o json
```

Note: MFA details may require Microsoft Graph API. If this command doesn't return MFA data, note "MFA status requires Microsoft Graph API or Azure Portal verification."

**Extract from output:**
- Count of users with non-empty `strongAuthenticationMethods` -> MFA-enrolled users
- Total user count -> denominator for MFA coverage

**Use in policy text:**
- Instead of: "MFA is required for all users"
- Write: "**45 of 50 Azure AD users** have MFA methods registered (see `az ad user list`). MFA enforcement is managed via conditional access policies."

---

## Data Management (CC6.5-6.7)

### Storage Account Encryption

**Discovery:**
```bash
az storage account list -o json --query "[].{name:name,resourceGroup:resourceGroup}"
```

**Inspection (per account):**
```bash
az storage account show --name ACCOUNT_NAME --resource-group RG -o json
```

**Extract from output:**
- `.encryption.services.blob.enabled` -> blob encryption (true/false)
- `.encryption.services.file.enabled` -> file encryption (true/false)
- `.encryption.keySource` -> `Microsoft.Storage` (platform-managed) or `Microsoft.Keyvault` (CMK)
- `.minimumTlsVersion` -> minimum TLS for storage access

**Use in policy text:**
- Instead of: "Storage is encrypted at rest"
- Write: "All **4 storage accounts** have **blob and file encryption enabled** using **platform-managed keys**. Minimum TLS version is **TLS1_2** (see `az storage account show`)."

### SQL Database Configuration

**Discovery:**
```bash
az sql server list -o json --query "[].{name:name,resourceGroup:resourceGroup}"
```

**Inspection:**
```bash
az sql db show --name DB_NAME --server SERVER --resource-group RG -o json
```

**Extract from output:**
- `.currentBackupStorageRedundancy` -> backup redundancy (Geo, Local, Zone)
- `.earliestRestoreDate` -> earliest point-in-time restore
- `.status` -> database status

**Additional — TDE status:**
```bash
az sql db tde show --database DB_NAME --server SERVER --resource-group RG -o json
```

**Extract from output:**
- `.state` -> Enabled/Disabled (Transparent Data Encryption)

**Use in policy text:**
- Instead of: "Database encryption and backups are configured"
- Write: "Azure SQL database uses **Transparent Data Encryption (enabled)** with **geo-redundant backup** storage (see `az sql db tde show`, `az sql db show`)."

### Key Vault Configuration

**Discovery:**
```bash
az keyvault list -o json --query "[].{name:name,resourceGroup:resourceGroup}"
```

**Inspection:**
```bash
az keyvault show --name VAULT_NAME -o json
```

**Extract from output:**
- `.properties.enableSoftDelete` -> soft delete enabled (true/false)
- `.properties.enablePurgeProtection` -> purge protection (true/false)
- `.properties.enableRbacAuthorization` -> RBAC authorization (true/false)

**Use in policy text:**
- Instead of: "Key management is configured"
- Write: "Azure Key Vault `prod-vault` has **soft delete enabled**, **purge protection enabled**, and uses **RBAC authorization** (see `az keyvault show`)."

---

## Network Security (CC6.6-6.7)

### Network Security Groups

**Command:**
```bash
az network nsg list -o json
```

**Extract from output:**
- Count of NSGs -> total network security groups
- `.securityRules[].name` -> rule names
- `.securityRules[].access` -> Allow/Deny
- `.securityRules[].direction` -> Inbound/Outbound
- `.securityRules[].destinationPortRange` -> port range
- `.securityRules[].sourceAddressPrefix` -> source (flag `*` or `Internet` as concern on non-80/443)

**Use in policy text:**
- Instead of: "Network access is controlled by security groups"
- Write: "**6 Network Security Groups** control traffic flow. Production NSGs restrict inbound to **ports 443 and 80** from the internet. WARNING: NSG `nsg-legacy` allows **inbound port 3389 from Internet** -- review recommended."

### Application Gateway (WAF + TLS)

**Discovery:**
```bash
az network application-gateway list -o json --query "[].{name:name,resourceGroup:resourceGroup}"
```

**Inspection:**
```bash
az network application-gateway show --name GW_NAME --resource-group RG -o json
```

**Extract from output:**
- `.sslPolicy.minProtocolVersion` -> minimum TLS version
- `.sslPolicy.policyType` -> Predefined/Custom
- `.webApplicationFirewallConfiguration.enabled` -> WAF enabled (true/false)
- `.webApplicationFirewallConfiguration.firewallMode` -> Detection/Prevention

**Use in policy text:**
- Instead of: "WAF and TLS are configured on the application gateway"
- Write: "Application Gateway enforces **TLS 1.2 minimum** with WAF in **Prevention mode** (see `az network application-gateway show`)."

### Front Door TLS

**Command:**
```bash
az network front-door list -o json
```

**Extract from output:**
- `.frontendEndpoints[].webApplicationFirewallPolicyLink` -> WAF policy attached
- `.routingRules[].acceptedProtocols` -> accepted protocols (Https, Http)

**Use in policy text:**
- Instead of: "CDN enforces encrypted connections"
- Write: "Azure Front Door accepts **HTTPS only** with WAF policy attached to all frontend endpoints (see `az network front-door list`)."

---

## Vulnerability & Monitoring (CC7.1-7.2)

### Defender for Cloud Assessments

**Command:**
```bash
az security assessment list -o json --query "[].{name:displayName,status:status.code}"
```

**Extract from output:**
- Count of assessments by status: Healthy, Unhealthy, NotApplicable
- Note unhealthy assessments as items requiring remediation

**Use in policy text:**
- Instead of: "Security assessments are performed"
- Write: "Microsoft Defender for Cloud shows **42 healthy assessments**, **3 unhealthy** requiring remediation (see `az security assessment list`)."

### Diagnostic Settings

**Command (per resource):**
```bash
az monitor diagnostic-settings list --resource RESOURCE_ID -o json
```

**Extract from output:**
- `.logs[].enabled` -> logging enabled per category (true/false)
- `.logs[].retentionPolicy.enabled` -> retention enabled (true/false)
- `.logs[].retentionPolicy.days` -> retention period (days)

**Use in policy text:**
- Instead of: "Diagnostic logging is configured"
- Write: "Diagnostic settings capture **audit and security logs** with **90-day retention** (see `az monitor diagnostic-settings list`)."

### Activity Log Alerts

**Command:**
```bash
az monitor activity-log alert list -o json
```

**Extract from output:**
- Count of alerts -> total activity log alerts
- `.name` -> alert names

**Use in policy text:**
- Instead of: "Activity monitoring is in place"
- Write: "**8 activity log alerts** monitor administrative operations and security events (see `az monitor activity-log alert list`)."

---

## Example Evidence Table

| Control | Extracted Value | Service | Region | Command | Raw Evidence |
|---------|----------------|---------|--------|---------|-------------|
| Conditional Access | **5 policies enabled** | Azure AD | global | `az ad conditional-access policy list` | 5 policies, state=enabled |
| RBAC | **34 assignments, 8 roles** | Azure RBAC | global | `az role assignment list` | 34 total assignments |
| Storage encryption | **enabled, platform keys, TLS 1.2** | Storage | eastus | `az storage account show` | `"enabled": true` |
| SQL TDE | **enabled** | Azure SQL | eastus | `az sql db tde show` | `"state": "Enabled"` |
| Key Vault | **soft delete + purge protection** | Key Vault | eastus | `az keyvault show` | `"enableSoftDelete": true` |
| NSGs | **6 groups** | Network | eastus | `az network nsg list` | 6 NSGs with rules |
| App Gateway WAF | **Prevention mode, TLS 1.2** | App Gateway | eastus | `az network application-gateway show` | `"firewallMode": "Prevention"` |
| Defender | **42 healthy, 3 unhealthy** | Defender | global | `az security assessment list` | Status counts |
