# AWS Cloud Scanning Patterns

For cloud scanning of AWS infrastructure.
**Pre-built script:** `assets/scripts/aws.sh` — copy to `.compliance/scripts/` and configure with `aws.config.json`.
See [cloud-shared.md](cloud-shared.md) for authentication, safety rules, and evidence formatting.

## Prerequisites

- AWS CLI installed (`aws --version`)
- Authenticated (`aws sts get-caller-identity`)
- Use `--output json` on all commands for parseable output

---

## Access Control (CC6.1-6.3)

### IAM Password Policy

**Command:**
```bash
aws iam get-account-password-policy --output json
```

**Extract from output:**
- `.PasswordPolicy.MinimumPasswordLength` -> password minimum length
- `.PasswordPolicy.RequireUppercaseCharacters` -> uppercase required (true/false)
- `.PasswordPolicy.RequireLowercaseCharacters` -> lowercase required (true/false)
- `.PasswordPolicy.RequireNumbers` -> numbers required (true/false)
- `.PasswordPolicy.RequireSymbols` -> symbols required (true/false)
- `.PasswordPolicy.MaxPasswordAge` -> password expiry (days, 0 = no expiry)
- `.PasswordPolicy.PasswordReusePrevention` -> password history count

**Use in policy text:**
- Instead of: "Password policies are configured per organizational standards"
- Write: "AWS IAM enforces a minimum password length of **14 characters** with uppercase, lowercase, number, and symbol requirements. Passwords expire every **90 days** with **24 password history** (see `aws iam get-account-password-policy`)."

### MFA Status

**Command:**
```bash
aws iam get-account-summary --output json
```

**Extract from output:**
- `.SummaryMap.AccountMFAEnabled` -> root account MFA (1 = enabled)
- `.SummaryMap.MFADevicesInUse` -> total MFA devices active
- `.SummaryMap.Users` -> total IAM users

**Additional command:**
```bash
aws iam list-virtual-mfa-devices --output json
```

**Extract from output:**
- Count of `.VirtualMFADevices[]` -> number of virtual MFA devices
- `.VirtualMFADevices[].User.UserName` -> users with MFA (do NOT include serial numbers)

**Use in policy text:**
- Instead of: "Multi-factor authentication is required"
- Write: "Root account MFA is **enabled**. **12 of 15 IAM users** have MFA devices configured (see `aws iam get-account-summary`)."

### IAM Roles

**Command:**
```bash
aws iam list-roles --output json
```

**Extract from output:**
- Count of `.Roles[]` -> total role count
- `.Roles[].RoleName` -> role names (list first 10, note total if more)

**Use in policy text:**
- Instead of: "Role-based access control is implemented"
- Write: "AWS IAM has **23 defined roles** including service roles and cross-account access roles (see `aws iam list-roles`)."

---

## Data Management (CC6.5-6.7)

### S3 Bucket Encryption

**Discovery:**
```bash
aws s3api list-buckets --output json --query "Buckets[].Name"
```

**Inspection (for each bucket):**
```bash
aws s3api get-bucket-encryption --bucket BUCKET_NAME --output json
```

**Extract from output:**
- `.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm` -> encryption algorithm (`aws:kms` or `AES256`)
- `.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID` -> KMS key (redact to alias only)

**Use in policy text:**
- Instead of: "Data at rest is encrypted"
- Write: "All **8 S3 buckets** use server-side encryption: **6 use SSE-KMS** and **2 use SSE-S3 (AES-256)** (see `aws s3api get-bucket-encryption`)."

### RDS Encryption and Backups

**Command:**
```bash
aws rds describe-db-instances --output json
```

**Extract from output (per instance):**
- `.DBInstances[].DBInstanceIdentifier` -> instance name
- `.DBInstances[].StorageEncrypted` -> encryption status (true/false)
- `.DBInstances[].KmsKeyId` -> KMS key (redact to alias)
- `.DBInstances[].BackupRetentionPeriod` -> backup retention (days)
- `.DBInstances[].PreferredBackupWindow` -> backup window (UTC)
- `.DBInstances[].MultiAZ` -> multi-AZ deployment (true/false)
- `.DBInstances[].Engine` -> database engine
- `.DBInstances[].EngineVersion` -> engine version

**Use in policy text:**
- Instead of: "Database backups are performed regularly with encryption enabled"
- Write: "RDS instance `prod-db` uses **AES-256 encryption with KMS**, **30-day backup retention** during the **03:00-04:00 UTC window**, and **Multi-AZ deployment** is enabled (see `aws rds describe-db-instances`)."

### KMS Key Configuration

**Discovery:**
```bash
aws kms list-keys --output json
```

**Inspection (for each key):**
```bash
aws kms describe-key --key-id KEY_ID --output json
```
```bash
aws kms get-key-rotation-status --key-id KEY_ID --output json
```

**Extract from output:**
- `.KeyMetadata.KeyState` -> key state (Enabled/Disabled)
- `.KeyMetadata.KeyManager` -> AWS or CUSTOMER managed
- `.KeyRotationStatus` -> automatic rotation enabled (true/false)

**Use in policy text:**
- Instead of: "Encryption keys are managed and rotated"
- Write: "**3 customer-managed KMS keys** are in use with **automatic annual rotation enabled** (see `aws kms describe-key`)."

### CloudWatch Log Retention

**Command:**
```bash
aws logs describe-log-groups --output json
```

**Extract from output:**
- `.logGroups[].logGroupName` -> log group names
- `.logGroups[].retentionInDays` -> retention period (null = never expire)

**Use in policy text:**
- Instead of: "Logs are retained per policy requirements"
- Write: "CloudWatch log groups are configured with retention periods: application logs **90 days**, access logs **365 days**, audit logs **never expire** (see `aws logs describe-log-groups`)."

---

## Network Security (CC6.6-6.7)

### Load Balancer TLS Configuration

**Discovery:**
```bash
aws elbv2 describe-load-balancers --output json --query "LoadBalancers[].LoadBalancerArn"
```

**Inspection (for each ALB):**
```bash
aws elbv2 describe-listeners --load-balancer-arn ARN --output json
```

**Extract from output:**
- `.Listeners[].Protocol` -> protocol (HTTPS, HTTP)
- `.Listeners[].SslPolicy` -> SSL policy name (encodes TLS version)
- `.Listeners[].Port` -> listener port

SSL policy to TLS version mapping:
- `ELBSecurityPolicy-TLS13-*` -> TLS 1.3
- `ELBSecurityPolicy-TLS-1-2-*` -> TLS 1.2 minimum
- `ELBSecurityPolicy-2016-08` -> TLS 1.0 minimum (flag as concern)

**Use in policy text:**
- Instead of: "Data in transit is encrypted using TLS"
- Write: "Application Load Balancer enforces **TLS 1.2 minimum** via policy `ELBSecurityPolicy-TLS-1-2-2017-01` on HTTPS listener port 443 (see `aws elbv2 describe-listeners`)."

### Security Groups

**Command:**
```bash
aws ec2 describe-security-groups --output json
```

**Extract from output:**
- `.SecurityGroups[].GroupName` -> security group names
- `.SecurityGroups[].IpPermissions[]` -> inbound rules
  - `.IpProtocol`, `.FromPort`, `.ToPort` -> protocol and port range
  - `.IpRanges[].CidrIp` -> source CIDR
- Flag any rule with `CidrIp: "0.0.0.0/0"` on ports other than 80/443 as a security concern

**Use in policy text:**
- Instead of: "Network access is controlled by firewall rules"
- Write: "**12 security groups** are configured. Production groups restrict inbound access to **ports 443 (HTTPS) and 80 (HTTP) only** from public internet. WARNING: Security group `sg-legacy` allows **0.0.0.0/0 on port 22** -- review recommended."

### WAF Configuration

**Command:**
```bash
aws wafv2 list-web-acls --scope REGIONAL --output json
```

**Extract from output:**
- `.WebACLs[].Name` -> WAF ACL names
- Count of `.WebACLs[]` -> number of Web ACLs

**Use in policy text:**
- Instead of: "Web application firewall is deployed"
- Write: "AWS WAF is deployed with **2 Web ACLs** protecting production endpoints (see `aws wafv2 list-web-acls`)."

### CloudFront TLS

**Discovery:**
```bash
aws cloudfront list-distributions --output json --query "DistributionList.Items[].Id"
```

**Inspection:**
```bash
aws cloudfront get-distribution --id DISTRIBUTION_ID --output json
```

**Extract from output:**
- `.Distribution.DistributionConfig.ViewerCertificate.MinimumProtocolVersion` -> minimum TLS
- `.Distribution.DistributionConfig.ViewerCertificate.SSLSupportMethod` -> SNI or VIP

**Use in policy text:**
- Instead of: "CDN enforces encrypted connections"
- Write: "CloudFront distributions enforce **TLSv1.2_2021** minimum protocol version (see `aws cloudfront get-distribution`)."

---

## Vulnerability & Monitoring (CC7.1-7.2)

### ECR Image Scanning

**Command:**
```bash
aws ecr describe-repositories --output json
```

**Extract from output:**
- `.repositories[].repositoryName` -> repository names
- `.repositories[].imageScanningConfiguration.scanOnPush` -> scan on push (true/false)

**Use in policy text:**
- Instead of: "Container images are scanned for vulnerabilities"
- Write: "ECR repositories have **scan-on-push enabled** for **all 5 repositories** (see `aws ecr describe-repositories`)."

### Security Hub

**Command:**
```bash
aws securityhub describe-hub --output json
```

**Extract from output:**
- `.HubArn` -> if present, Security Hub is enabled
- `.AutoEnableControls` -> auto-enable new controls (true/false)

**Use in policy text:**
- Instead of: "Centralized security monitoring is enabled"
- Write: "AWS Security Hub is **enabled** with auto-enable controls active (see `aws securityhub describe-hub`)."

### GuardDuty

**Command:**
```bash
aws guardduty list-detectors --output json
```

**Extract from output:**
- Count of `.DetectorIds[]` -> number of detectors (>0 = enabled)

**Use in policy text:**
- Instead of: "Threat detection is configured"
- Write: "Amazon GuardDuty threat detection is **enabled** (see `aws guardduty list-detectors`)."

### AWS Config Rules

**Command:**
```bash
aws configservice describe-config-rules --output json
```

**Extract from output:**
- Count of `.ConfigRules[]` -> number of Config rules
- `.ConfigRules[].ConfigRuleName` -> rule names (list first 10, note total)

**Use in policy text:**
- Instead of: "Compliance monitoring rules are configured"
- Write: "AWS Config monitors compliance with **42 rules** including encryption, access, and logging requirements (see `aws configservice describe-config-rules`)."

---

## Business Continuity (A1.2-A1.3)

### AWS Backup Plans

**Command:**
```bash
aws backup list-backup-plans --output json
```

**Extract from output:**
- `.BackupPlansList[].BackupPlanName` -> plan names
- `.BackupPlansList[].BackupPlanId` -> plan IDs (for further inspection)

**Use in policy text:**
- Instead of: "Backup plans are in place"
- Write: "AWS Backup manages **3 backup plans**: `daily-production`, `weekly-databases`, `monthly-compliance` (see `aws backup list-backup-plans`)."

### RDS Multi-AZ

Reuse data from `aws rds describe-db-instances` in Data Management section above. Extract:
- `.DBInstances[].MultiAZ` -> high availability status
- `.DBInstances[].BackupRetentionPeriod` -> backup retention

---

## Incident Response (CC7.3-7.5)

### CloudWatch Alarms

**Command:**
```bash
aws cloudwatch describe-alarms --state-value OK --output json --query "MetricAlarms[].{Name:AlarmName,Metric:MetricName,Actions:AlarmActions}"
```

**Extract from output:**
- Count of alarms -> total monitoring alarms
- `.AlarmName` -> alarm names (list first 10)
- `.AlarmActions` -> SNS topic ARNs (redact to topic name only)

**Use in policy text:**
- Instead of: "Monitoring alerts are configured"
- Write: "**15 CloudWatch alarms** monitor system health and security metrics, routing notifications to SNS topics for the operations team (see `aws cloudwatch describe-alarms`)."

### CloudTrail

**Command:**
```bash
aws cloudtrail describe-trails --output json
```

**Extract from output:**
- `.trailList[].Name` -> trail names
- `.trailList[].IsMultiRegionTrail` -> multi-region (true/false)
- `.trailList[].LogFileValidationEnabled` -> log validation (true/false)
- `.trailList[].IsLogging` -> currently logging (true/false)

**Use in policy text:**
- Instead of: "Audit logging is enabled"
- Write: "CloudTrail is configured with **multi-region trail**, **log file validation enabled**, and **actively logging** (see `aws cloudtrail describe-trails`)."

### SNS Notification Topics

**Command:**
```bash
aws sns list-topics --output json
```

**Extract from output:**
- Count of `.Topics[]` -> number of notification topics
- `.Topics[].TopicArn` -> extract topic name from ARN (last segment after `:`)

**Use in policy text:**
- Instead of: "Alerting channels are configured"
- Write: "**8 SNS topics** are configured for alerting including `security-alerts`, `ops-critical`, and `incident-response` (see `aws sns list-topics`)."

---

## Change Management (CC8.1)

Note: Change management evidence primarily comes from codebase scanning (CI/CD, branch protection). AWS adds supplementary deployment pipeline evidence only if CodePipeline is used.

### CodePipeline

**Command:**
```bash
aws codepipeline list-pipelines --output json
```

**Extract from output:**
- `.pipelines[].name` -> pipeline names

**Use in policy text:**
- Instead of: "Deployment pipelines are configured"
- Write: "AWS CodePipeline manages **2 deployment pipelines**: `prod-deploy` and `staging-deploy` (see `aws codepipeline list-pipelines`)."

---

## Example Evidence Table

| Control | Extracted Value | Service | Region | Command | Raw Evidence |
|---------|----------------|---------|--------|---------|-------------|
| Password min length | **14 characters** | AWS IAM | global | `aws iam get-account-password-policy` | `"MinimumPasswordLength": 14` |
| Root MFA | **enabled** | AWS IAM | global | `aws iam get-account-summary` | `"AccountMFAEnabled": 1` |
| S3 encryption | **SSE-KMS (8 buckets)** | AWS S3 | us-east-1 | `aws s3api get-bucket-encryption` | `"SSEAlgorithm": "aws:kms"` |
| RDS encryption | **enabled, Multi-AZ** | AWS RDS | us-east-1 | `aws rds describe-db-instances` | `"StorageEncrypted": true` |
| RDS backup retention | **30 days** | AWS RDS | us-east-1 | `aws rds describe-db-instances` | `"BackupRetentionPeriod": 30` |
| TLS minimum | **TLS 1.2** | AWS ELB | us-east-1 | `aws elbv2 describe-listeners` | `"SslPolicy": "ELBSecurityPolicy-TLS-1-2-..."` |
| Security groups | **12 groups** | AWS EC2 | us-east-1 | `aws ec2 describe-security-groups` | Inbound rules reviewed |
| ECR scan on push | **enabled (5 repos)** | AWS ECR | us-east-1 | `aws ecr describe-repositories` | `"scanOnPush": true` |
| GuardDuty | **enabled** | GuardDuty | us-east-1 | `aws guardduty list-detectors` | 1 detector |
| CloudTrail | **multi-region, logging** | CloudTrail | global | `aws cloudtrail describe-trails` | `"IsMultiRegionTrail": true` |
