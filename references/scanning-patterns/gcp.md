# GCP Cloud Scanning Patterns

For cloud scanning of Google Cloud infrastructure.
**Pre-built script:** `assets/scripts/gcp.sh` — copy to `.compliance/scripts/` and configure with `gcp.config.json`.
See [cloud-shared.md](cloud-shared.md) for authentication, safety rules, and evidence formatting.

## Prerequisites

- Google Cloud SDK installed (`gcloud --version`)
- Authenticated (`gcloud auth list --filter=status:ACTIVE`)
- Active project set (`gcloud config get-value project`)
- Use `--format=json` on all commands for parseable output

---

## Access Control (CC6.1-6.3)

### Project IAM Policy

**Command:**
```bash
gcloud projects get-iam-policy PROJECT_ID --format=json
```

**Extract from output:**
- Count of unique `.bindings[].role` -> number of distinct IAM roles
- Count of unique members across all bindings -> total principals
- Flag any `allUsers` or `allAuthenticatedUsers` members as a security concern

**Use in policy text:**
- Instead of: "Access control is managed through IAM"
- Write: "GCP project uses **12 distinct IAM roles** across **28 principals**. No public access bindings (`allUsers`/`allAuthenticatedUsers`) detected (see `gcloud projects get-iam-policy`)."

### Organization IAM Policy

**Command:**
```bash
gcloud organizations get-iam-policy ORG_ID --format=json
```

Note: Requires org-level access. Skip if not available or command fails with permission error.

**Extract from output:**
- `.bindings[].role` -> org-level IAM roles
- Count of unique members -> org-level principals

**Use in policy text:**
- Instead of: "Organization-level access controls are in place"
- Write: "Organization IAM policy defines **8 roles** across **15 principals** at the org level (see `gcloud organizations get-iam-policy`)."

---

## Data Management (CC6.5-6.7)

### Cloud SQL Configuration

**Discovery:**
```bash
gcloud sql instances list --format=json
```

**Inspection (per instance):**
```bash
gcloud sql instances describe INSTANCE_NAME --format=json
```

**Extract from output:**
- `.settings.backupConfiguration.enabled` -> backup enabled (true/false)
- `.settings.backupConfiguration.startTime` -> backup window (UTC)
- `.settings.backupConfiguration.binaryLogEnabled` -> point-in-time recovery (true/false)
- `.settings.backupConfiguration.transactionLogRetentionDays` -> PITR retention (days)
- `.settings.dataDiskType` -> disk type (PD_SSD/PD_HDD)
- `.settings.storageAutoResize` -> auto-resize enabled (true/false)
- `.settings.ipConfiguration.requireSsl` -> SSL required for connections (true/false)
- `.databaseVersion` -> database version

**Use in policy text:**
- Instead of: "Database backups are performed with encryption"
- Write: "Cloud SQL instance `prod-postgres` has **automated daily backups** at **02:00 UTC**, **7-day point-in-time recovery**, and **SSL required** for all connections (see `gcloud sql instances describe`)."

### KMS Keys

**Discovery:**
```bash
gcloud kms keyrings list --location=LOCATION --format=json
```

**Inspection:**
```bash
gcloud kms keys list --keyring=KEYRING --location=LOCATION --format=json
```

**Extract from output:**
- `.name` -> key name (extract short name, not full resource path)
- `.purpose` -> ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, etc.
- `.primary.state` -> ENABLED/DISABLED
- `.rotationPeriod` -> rotation interval (e.g., `7776000s` = 90 days)
- `.nextRotationTime` -> next scheduled rotation

**Use in policy text:**
- Instead of: "Encryption keys are managed and rotated"
- Write: "**4 KMS keys** in use with **90-day automatic rotation** for encryption keys (see `gcloud kms keys list`)."

### Cloud Storage Bucket Configuration

**Discovery:**
```bash
gcloud storage buckets list --format=json
```

**Inspection (per bucket):**
```bash
gcloud storage buckets describe gs://BUCKET_NAME --format=json
```

**Extract from output:**
- `.default_kms_key` -> CMEK key reference (null = Google-managed)
- `.retention_policy.retention_period` -> retention period (seconds)
- `.versioning.enabled` -> object versioning (true/false)

**Use in policy text:**
- Instead of: "Object storage is encrypted"
- Write: "**6 Cloud Storage buckets** use Google-managed encryption. **2 buckets** use customer-managed KMS keys. Object versioning is **enabled** on production buckets (see `gcloud storage buckets describe`)."

---

## Network Security (CC6.6-6.7)

### SSL Policies

**Discovery:**
```bash
gcloud compute ssl-policies list --format=json
```

**Inspection:**
```bash
gcloud compute ssl-policies describe POLICY_NAME --format=json
```

**Extract from output:**
- `.minTlsVersion` -> minimum TLS version (TLS_1_0, TLS_1_1, TLS_1_2)
- `.profile` -> COMPATIBLE, MODERN, RESTRICTED, CUSTOM
- `.enabledFeatures[]` -> enabled cipher suites

**Use in policy text:**
- Instead of: "TLS is configured on load balancers"
- Write: "GCP SSL policy enforces **TLS 1.2 minimum** with **RESTRICTED** profile (see `gcloud compute ssl-policies describe`)."

### Firewall Rules

**Command:**
```bash
gcloud compute firewall-rules list --format=json
```

**Extract from output:**
- `.name` -> rule name
- `.direction` -> INGRESS/EGRESS
- `.allowed[].IPProtocol` -> protocol
- `.allowed[].ports[]` -> port ranges
- `.sourceRanges[]` -> source CIDR ranges
- Flag rules with `sourceRanges` containing `0.0.0.0/0` on ports other than 80/443

**Use in policy text:**
- Instead of: "Firewall rules restrict network access"
- Write: "**15 firewall rules** configured. Default deny-all ingress with explicit allow for **HTTPS (443)** and **HTTP (80)** only from public internet. WARNING: Rule `allow-ssh-legacy` permits **0.0.0.0/0 on port 22** -- review recommended."

### Cloud Armor (WAF)

**Discovery:**
```bash
gcloud compute security-policies list --format=json
```

**Backend association:**
```bash
gcloud compute backend-services list --format="json(name,securityPolicy)"
```

**Extract from output:**
- Security policy names and count
- `.securityPolicy` on backend services -> which backends have WAF (null = no WAF)

**Use in policy text:**
- Instead of: "Web application firewall protects endpoints"
- Write: "Cloud Armor WAF policy is attached to **3 of 5 backend services** (see `gcloud compute backend-services list`)."

---

## Vulnerability & Monitoring (CC7.1-7.2)

### Enabled Security Services

**Command:**
```bash
gcloud services list --enabled --filter="name:(containeranalysis OR securitycenter OR binaryauthorization)" --format=json
```

**Extract from output:**
- Presence of `containeranalysis.googleapis.com` -> container vulnerability scanning enabled
- Presence of `securitycenter.googleapis.com` -> Security Command Center enabled
- Presence of `binaryauthorization.googleapis.com` -> Binary Authorization enabled

**Use in policy text:**
- Instead of: "Vulnerability scanning services are enabled"
- Write: "GCP **Security Command Center** and **Container Analysis** are enabled for continuous vulnerability monitoring (see `gcloud services list --enabled`)."

### Security Command Center Findings

**Command:**
```bash
gcloud scc findings list ORGANIZATION_ID --format=json --filter="state=ACTIVE" --page-size=10
```

Note: Requires org-level access. Skip if not available.

**Extract from output:**
- Count of active findings by severity category (CRITICAL, HIGH, MEDIUM, LOW)

**Use in policy text:**
- Instead of: "Security findings are monitored"
- Write: "Security Command Center shows **0 critical**, **2 high**, and **5 medium** active findings (see `gcloud scc findings list`)."

---

## Incident Response (CC7.3-7.5)

### Log Sinks

**Command:**
```bash
gcloud logging sinks list --format=json
```

**Extract from output:**
- `.name` -> sink names
- `.destination` -> destination (BigQuery, Cloud Storage, Pub/Sub)
- `.filter` -> log filter criteria

**Use in policy text:**
- Instead of: "Logs are exported for analysis"
- Write: "**3 log sinks** export audit logs to BigQuery for retention and analysis (see `gcloud logging sinks list`)."

### Alerting Policies

**Command:**
```bash
gcloud alpha monitoring policies list --format=json
```

**Extract from output:**
- Count of policies -> total alerting policies
- `.displayName` -> policy names (list first 10)

**Use in policy text:**
- Instead of: "Monitoring alerts are configured"
- Write: "**12 alerting policies** monitor infrastructure health and security events (see `gcloud alpha monitoring policies list`)."

---

## Example Evidence Table

| Control | Extracted Value | Service | Region | Command | Raw Evidence |
|---------|----------------|---------|--------|---------|-------------|
| IAM roles | **12 distinct roles, 28 principals** | GCP IAM | global | `gcloud projects get-iam-policy` | 12 bindings |
| Cloud SQL backup | **daily, 7-day PITR** | Cloud SQL | us-central1 | `gcloud sql instances describe` | `"enabled": true` |
| KMS rotation | **90-day rotation** | Cloud KMS | us-central1 | `gcloud kms keys list` | `"rotationPeriod": "7776000s"` |
| SSL policy | **TLS 1.2, RESTRICTED** | Compute | global | `gcloud compute ssl-policies describe` | `"minTlsVersion": "TLS_1_2"` |
| Firewall rules | **15 rules, default deny** | Compute | global | `gcloud compute firewall-rules list` | 15 rules total |
| SCC enabled | **active** | Security Center | global | `gcloud services list --enabled` | Service present |
