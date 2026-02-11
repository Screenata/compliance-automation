#!/usr/bin/env bash
# .compliance/scripts/aws.sh
# Compliance evidence collection for AWS
# Requires: AWS credentials configured (env vars or AWS CLI profile)
# Config:   aws.config.json (co-located)
# Safety:   READ-ONLY commands only (describe, list, get)
set -uo pipefail

# ── CLI check ──────────────────────────────────────────
if ! command -v aws &>/dev/null; then
  echo "Skipping AWS (aws CLI not installed)"
  exit 0
fi
if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed. Install it with: apt-get install jq (Linux) or brew install jq (macOS)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
REGION=$(jq -r '.region // "us-east-1"' "$CONFIG")

export AWS_DEFAULT_REGION="$REGION"
export AWS_PAGER=""

OUT="${COMPLIANCE_EVIDENCE_DIR:-.compliance/evidence/cloud}/aws-evidence.md"
mkdir -p "$(dirname "$OUT")"

{
  echo "# AWS Cloud Infrastructure Evidence"
  echo ""
  echo "> Scan date: $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "> Region: ${REGION}"
  echo ""
  echo "| Control | Extracted Value | Service | Region | Command | Raw Evidence |"
  echo "|---------|----------------|---------|--------|---------|-------------|"
} > "$OUT"

# ── Verify Authentication ───────────────────────────────
identity=$(aws sts get-caller-identity --output json 2>&1 || echo '{"error": true}')
if echo "$identity" | jq -e '.Account' > /dev/null 2>&1; then
  account=$(echo "$identity" | jq -r '.Account')
  echo "| AWS Account | **${account}** | STS | global | \`aws sts get-caller-identity\` | Authenticated successfully |" >> "$OUT"
else
  echo "| AWS Authentication | **FAILED** | STS | global | \`aws sts get-caller-identity\` | Not authenticated - configure credentials |" >> "$OUT"
  echo "" >> "$OUT"
  echo "*Scan aborted: AWS credentials not configured.*" >> "$OUT"
  echo "FAILED: aws - credentials not configured"
  exit 1
fi

# ── Access Control (CC6.1-6.3) ──────────────────────────

# IAM Password Policy
result=$(aws iam get-account-password-policy --output json 2>&1 || echo '{"error": true}')
if echo "$result" | jq -e '.PasswordPolicy' > /dev/null 2>&1; then
  min_len=$(echo "$result" | jq -r '.PasswordPolicy.MinimumPasswordLength')
  max_age=$(echo "$result" | jq -r '.PasswordPolicy.MaxPasswordAge // "none"')
  require_upper=$(echo "$result" | jq -r '.PasswordPolicy.RequireUppercaseCharacters')
  require_lower=$(echo "$result" | jq -r '.PasswordPolicy.RequireLowercaseCharacters')
  require_numbers=$(echo "$result" | jq -r '.PasswordPolicy.RequireNumbers')
  require_symbols=$(echo "$result" | jq -r '.PasswordPolicy.RequireSymbols')
  reuse=$(echo "$result" | jq -r '.PasswordPolicy.PasswordReusePrevention // "none"')
  echo "| Password min length | **${min_len} characters** | IAM | global | \`aws iam get-account-password-policy\` | MinimumPasswordLength: ${min_len} |" >> "$OUT"
  echo "| Password complexity | **upper:${require_upper}, lower:${require_lower}, numbers:${require_numbers}, symbols:${require_symbols}** | IAM | global | \`aws iam get-account-password-policy\` | Complexity requirements |" >> "$OUT"
  if [ "$max_age" != "none" ] && [ "$max_age" != "0" ]; then
    echo "| Password expiry | **${max_age} days** | IAM | global | \`aws iam get-account-password-policy\` | MaxPasswordAge: ${max_age} |" >> "$OUT"
  fi
  if [ "$reuse" != "none" ]; then
    echo "| Password history | **${reuse} passwords** | IAM | global | \`aws iam get-account-password-policy\` | PasswordReusePrevention: ${reuse} |" >> "$OUT"
  fi
else
  echo "| Password policy | **not configured** | IAM | global | \`aws iam get-account-password-policy\` | No password policy set |" >> "$OUT"
fi

# MFA Status
result=$(aws iam get-account-summary --output json 2>&1 || echo '{}')
if echo "$result" | jq -e '.SummaryMap' > /dev/null 2>&1; then
  root_mfa=$(echo "$result" | jq -r '.SummaryMap.AccountMFAEnabled')
  mfa_devices=$(echo "$result" | jq -r '.SummaryMap.MFADevicesInUse')
  total_users=$(echo "$result" | jq -r '.SummaryMap.Users')
  if [ "$root_mfa" = "1" ]; then
    echo "| Root MFA | **enabled** | IAM | global | \`aws iam get-account-summary\` | AccountMFAEnabled: 1 |" >> "$OUT"
  else
    echo "| Root MFA | **DISABLED** | IAM | global | \`aws iam get-account-summary\` | AccountMFAEnabled: 0 - CRITICAL |" >> "$OUT"
  fi
  echo "| MFA devices | **${mfa_devices} of ${total_users} users** | IAM | global | \`aws iam get-account-summary\` | MFADevicesInUse: ${mfa_devices}, Users: ${total_users} |" >> "$OUT"
fi

# IAM Roles
result=$(aws iam list-roles --output json 2>&1 || echo '{"Roles": []}')
role_count=$(echo "$result" | jq '.Roles | length')
echo "| IAM roles | **${role_count} defined** | IAM | global | \`aws iam list-roles\` | ${role_count} roles including service roles |" >> "$OUT"

# ── Data Management (CC6.5-6.7) ─────────────────────────

# S3 Buckets & Encryption
buckets=$(aws s3api list-buckets --output json --query "Buckets[].Name" 2>&1 || echo '[]')
bucket_count=$(echo "$buckets" | jq 'length')
if [ "$bucket_count" -gt 0 ]; then
  encrypted=0
  unencrypted=0
  for bucket in $(echo "$buckets" | jq -r '.[]' | head -20); do
    enc=$(aws s3api get-bucket-encryption --bucket "$bucket" --output json 2>&1 || echo '{"error": true}')
    if echo "$enc" | jq -e '.ServerSideEncryptionConfiguration' > /dev/null 2>&1; then
      encrypted=$((encrypted + 1))
    else
      unencrypted=$((unencrypted + 1))
    fi
  done
  checked=$((encrypted + unencrypted))
  echo "| S3 buckets | **${bucket_count} total** | S3 | global | \`aws s3api list-buckets\` | ${encrypted} encrypted, ${unencrypted} unencrypted (sampled ${checked} of ${bucket_count}) |" >> "$OUT"
  echo "| S3 encryption | **${encrypted} of ${checked} sampled encrypted** | S3 | global | \`aws s3api get-bucket-encryption\` | Server-side encryption check (first 20) |" >> "$OUT"
fi

# RDS Instances
result=$(aws rds describe-db-instances --output json 2>&1 || echo '{"DBInstances": []}')
db_count=$(echo "$result" | jq '.DBInstances | length')
if [ "$db_count" -gt 0 ]; then
  for i in $(seq 0 $((db_count - 1))); do
    db_id=$(echo "$result" | jq -r ".DBInstances[$i].DBInstanceIdentifier")
    encrypted=$(echo "$result" | jq -r ".DBInstances[$i].StorageEncrypted")
    backup_ret=$(echo "$result" | jq -r ".DBInstances[$i].BackupRetentionPeriod")
    multi_az=$(echo "$result" | jq -r ".DBInstances[$i].MultiAZ")
    engine=$(echo "$result" | jq -r ".DBInstances[$i].Engine")
    echo "| RDS ${db_id} | **encrypted:${encrypted}, backup:${backup_ret}d, multi-AZ:${multi_az}** | RDS | ${REGION} | \`aws rds describe-db-instances\` | Engine: ${engine} |" >> "$OUT"
  done
else
  echo "| RDS instances | **none found** | RDS | ${REGION} | \`aws rds describe-db-instances\` | No RDS instances in region |" >> "$OUT"
fi

# KMS Keys
result=$(aws kms list-keys --output json 2>&1 || echo '{"Keys": []}')
key_count=$(echo "$result" | jq '.Keys | length')
if [ "$key_count" -gt 0 ]; then
  customer_keys=0
  rotation_enabled=0
  for key_id in $(echo "$result" | jq -r '.Keys[].KeyId' | head -10); do
    key_info=$(aws kms describe-key --key-id "$key_id" --output json 2>&1 || echo '{}')
    manager=$(echo "$key_info" | jq -r '.KeyMetadata.KeyManager // "unknown"')
    if [ "$manager" = "CUSTOMER" ]; then
      customer_keys=$((customer_keys + 1))
      rotation=$(aws kms get-key-rotation-status --key-id "$key_id" --output json 2>&1 || echo '{}')
      is_rotating=$(echo "$rotation" | jq -r '.KeyRotationEnabled // false')
      if [ "$is_rotating" = "true" ]; then
        rotation_enabled=$((rotation_enabled + 1))
      fi
    fi
  done
  echo "| KMS keys | **${customer_keys} customer-managed** | KMS | ${REGION} | \`aws kms list-keys\` | ${rotation_enabled} with rotation enabled |" >> "$OUT"
fi

# CloudWatch Log Groups
result=$(aws logs describe-log-groups --output json --limit 50 2>&1 || echo '{"logGroups": []}')
log_count=$(echo "$result" | jq '.logGroups | length')
if [ "$log_count" -gt 0 ]; then
  with_retention=$(echo "$result" | jq '[.logGroups[] | select(.retentionInDays != null)] | length')
  echo "| CloudWatch log groups | **${log_count} groups** | CloudWatch | ${REGION} | \`aws logs describe-log-groups\` | ${with_retention} with retention configured |" >> "$OUT"
fi

# ── Network Security (CC6.6-6.7) ────────────────────────

# Security Groups
result=$(aws ec2 describe-security-groups --output json 2>&1 || echo '{"SecurityGroups": []}')
sg_count=$(echo "$result" | jq '.SecurityGroups | length')
if [ "$sg_count" -gt 0 ]; then
  open_ssh=$(echo "$result" | jq '[.SecurityGroups[].IpPermissions[] | select(.FromPort == 22 and .ToPort == 22) | .IpRanges[] | select(.CidrIp == "0.0.0.0/0")] | length')
  echo "| Security groups | **${sg_count} groups** | EC2 | ${REGION} | \`aws ec2 describe-security-groups\` | Open SSH (0.0.0.0/0:22): ${open_ssh} |" >> "$OUT"
fi

# WAF
result=$(aws wafv2 list-web-acls --scope REGIONAL --output json 2>&1 || echo '{"WebACLs": []}')
waf_count=$(echo "$result" | jq '.WebACLs | length')
echo "| WAF Web ACLs | **${waf_count} regional** | WAF | ${REGION} | \`aws wafv2 list-web-acls\` | ${waf_count} Web ACLs configured |" >> "$OUT"

# ── Vulnerability & Monitoring (CC7.1-7.2) ───────────────

# GuardDuty
result=$(aws guardduty list-detectors --output json 2>&1 || echo '{"DetectorIds": []}')
gd_count=$(echo "$result" | jq '.DetectorIds | length')
if [ "$gd_count" -gt 0 ]; then
  echo "| GuardDuty | **enabled** | GuardDuty | ${REGION} | \`aws guardduty list-detectors\` | ${gd_count} detector(s) active |" >> "$OUT"
else
  echo "| GuardDuty | **not enabled** | GuardDuty | ${REGION} | \`aws guardduty list-detectors\` | No detectors found |" >> "$OUT"
fi

# Security Hub
result=$(aws securityhub describe-hub --output json 2>&1 || echo '{"error": true}')
if echo "$result" | jq -e '.HubArn' > /dev/null 2>&1; then
  echo "| Security Hub | **enabled** | SecurityHub | ${REGION} | \`aws securityhub describe-hub\` | Hub active |" >> "$OUT"
else
  echo "| Security Hub | **not enabled** | SecurityHub | ${REGION} | \`aws securityhub describe-hub\` | Not configured |" >> "$OUT"
fi

# CloudTrail
result=$(aws cloudtrail describe-trails --output json 2>&1 || echo '{"trailList": []}')
trail_count=$(echo "$result" | jq '.trailList | length')
if [ "$trail_count" -gt 0 ]; then
  multi_region=$(echo "$result" | jq '[.trailList[] | select(.IsMultiRegionTrail == true)] | length')
  log_validation=$(echo "$result" | jq '[.trailList[] | select(.LogFileValidationEnabled == true)] | length')
  echo "| CloudTrail | **${trail_count} trail(s)** | CloudTrail | global | \`aws cloudtrail describe-trails\` | Multi-region: ${multi_region}, Log validation: ${log_validation} |" >> "$OUT"
else
  echo "| CloudTrail | **not configured** | CloudTrail | global | \`aws cloudtrail describe-trails\` | No trails found |" >> "$OUT"
fi

# CloudWatch Alarms
result=$(aws cloudwatch describe-alarms --state-value OK --output json --query "MetricAlarms[].AlarmName" 2>&1 || echo '[]')
alarm_count=$(echo "$result" | jq 'length')
echo "| CloudWatch alarms | **${alarm_count} active** | CloudWatch | ${REGION} | \`aws cloudwatch describe-alarms\` | ${alarm_count} alarms in OK state |" >> "$OUT"

# ── Business Continuity (A1.2-A1.3) ─────────────────────

# Backup Plans
result=$(aws backup list-backup-plans --output json 2>&1 || echo '{"BackupPlansList": []}')
backup_count=$(echo "$result" | jq '.BackupPlansList | length')
if [ "$backup_count" -gt 0 ]; then
  plan_names=$(echo "$result" | jq -r '[.BackupPlansList[].BackupPlanName] | join(", ")' | head -c 80)
  echo "| Backup plans | **${backup_count} plans** | Backup | ${REGION} | \`aws backup list-backup-plans\` | Plans: ${plan_names} |" >> "$OUT"
else
  echo "| Backup plans | **none configured** | Backup | ${REGION} | \`aws backup list-backup-plans\` | No backup plans found |" >> "$OUT"
fi

# ── Footer ──────────────────────────────────────────────
echo "" >> "$OUT"
echo "*Values extracted from live AWS infrastructure. These represent point-in-time configuration. Re-scan and verify before audit submission.*" >> "$OUT"

echo "OK: aws evidence written to $OUT"
