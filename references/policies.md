# Policy Definitions

This document contains all 17 policy definitions with their policy-specific questions, template hints, and evidence requirements. The policy content is framework-agnostic — framework-specific control mappings are in separate files:

- **SOC 2 TSC:** [frameworks/soc2.md](frameworks/soc2.md)
- **ISO 27001 Annex A:** [frameworks/iso27001.md](frameworks/iso27001.md)

When generating a policy, look up the policy ID in the relevant framework file(s) to get the control codes for the YAML frontmatter.

## 1. Governance & Board Oversight (GBO)

**ID:** `governance-board-oversight`

**Topics:** Board charter, expertise, meetings, cybersecurity briefings

**Questions to Ask:**
1. Do you have a formal board or advisory board?
   - Options: Yes, formal board | Yes, advisory board | No board yet
2. How often does the board receive security briefings?
   - Options: Quarterly | Semi-annually | Annually | Ad-hoc | Never
3. Does any board member have cybersecurity expertise?
   - Options: Yes | No, but we have advisors | No

**Template Hints:**
- Purpose: Establishes governance oversight for information security and risk management
- Scope: Board of directors, executive leadership, and management
- Key Procedures: Board meeting frequency, security briefing cadence, risk oversight responsibilities

**Related Policies:** risk-management, information-security-policy

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Board meeting minutes | Policy | Minutes showing security topics discussed. Must show: meeting date, attendees, security agenda item, decisions/actions taken |
| [ ] | Security briefing slides | Policy | Presentation materials from board briefings. Must show: date, security metrics/status, risk items discussed |
| [ ] | Board charter | Policy | Document defining board responsibilities. Must show: security oversight duties, review/approval date |
| [ ] | Board member bios | Policy | CVs/profiles showing expertise (if applicable). Must show: relevant security/risk experience for at least one member |

---

## 2. Organizational Structure (OSP)

**ID:** `organizational-structure`

**Topics:** Roles/responsibilities, org chart, job descriptions

**Questions to Ask:**
1. Do you have a dedicated security role (CISO, Security Lead)?
   - Options: Yes, full-time CISO/CSO | Yes, part-time security lead | No, shared responsibility
2. Are security responsibilities documented in job descriptions?
   - Options: Yes, all roles | Yes, security roles only | No
3. Do you maintain an organizational chart?
   - Options: Yes, current | Yes, outdated | No

**Template Hints:**
- Purpose: Defines the organizational structure and security responsibilities
- Scope: All employees and their reporting relationships
- Key Procedures: Security role definitions, reporting structure, job description requirements

**Related Policies:** human-resources, information-security-policy

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Organizational chart | Policy | Current org chart dated within audit period. Must show: all employees, reporting lines, date updated within audit period |
| [ ] | Job descriptions | Policy | Sample descriptions showing security responsibilities. Must show: role title, security duties section, version/date |
| [ ] | Security lead designation | Policy | Announcement, offer letter, or meeting minutes. Must show: named individual, security responsibilities, effective date |
| [ ] | HR system org view | Screenshot | Screenshot of organizational structure in HRIS. Must show: current date visible, employee hierarchy, department structure |

---

## 3. Code of Conduct & Ethics (CCE)

**ID:** `code-of-conduct`

**Topics:** Whistleblower policy, code of conduct, confidentiality agreements

**Questions to Ask:**
1. Do you have a written code of conduct?
   - Options: Yes, signed by all employees | Yes, but not signed | No
2. Do you have a whistleblower or ethics reporting mechanism?
   - Options: Yes, anonymous reporting available | Yes, but not anonymous | No
3. Do employees sign confidentiality/NDA agreements?
   - Options: Yes, all employees | Yes, some roles | No

**Template Hints:**
- Purpose: Establishes ethical standards and conduct expectations
- Scope: All employees, contractors, and third parties
- Key Procedures: Code of conduct acknowledgment, ethics violation reporting, confidentiality requirements

**Related Policies:** human-resources, information-security-policy

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Signed code of conduct | Policy | Employee-signed acknowledgment forms. Must show: employee name, signature/e-signature, date signed, document version |
| [ ] | Whistleblower procedure | Policy | Documented ethics reporting process. Must show: reporting channels, non-retaliation statement, investigation process |
| [ ] | NDA/confidentiality agreements | Policy | Signed agreements for employees. Must show: employee name, signature, date, confidentiality obligations |
| [ ] | Ethics reporting mechanism | Screenshot | Screenshot of anonymous reporting portal (if used). Must show: submission form, anonymity statement, current date |

---

## 4. Information Security Policy (ISP)

**ID:** `information-security-policy`

**Topics:** Security policies/procedures, annual review

**Questions to Ask:**
1. Do you have a documented information security policy?
   - Options: Yes, reviewed annually | Yes, not reviewed regularly | No
2. Do employees receive security awareness training?
   - Options: Yes, annually | Yes, at onboarding only | No
3. Who owns the security policy?
   - Options: CISO/Security Lead | CTO/Engineering | CEO/Founder | No designated owner

**Template Hints:**
- Purpose: Establishes the information security management framework
- Scope: All information assets and personnel
- Key Procedures: Policy review and approval, security awareness training, policy exception process

**Related Policies:** governance-board-oversight, risk-management

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Security policy document | Policy | Current approved information security policy. Must show: version number, approval signature, effective date within audit period |
| [ ] | Policy review records | Policy | Evidence of annual review and approval. Must show: review date, reviewer name, approval signature, changes made (if any) |
| [ ] | Training completion records | Log | Export showing employee training completion. Must show: employee names, completion dates, course name, 100% coverage |
| [ ] | Training platform dashboard | Screenshot | Screenshot of LMS showing completion rates. Must show: current date, completion percentage, total employees vs completed |

---

## 5. Incident Response (IRP)

**ID:** `incident-response`

**Topics:** Incident response procedures, testing, logging/tracking

**Questions to Ask:**
1. Do you have a designated incident response team?
   - Options: Yes, dedicated team | Yes, shared responsibilities | No formal team
2. What tools do you use for incident detection?
   - Options: SIEM | Log aggregation | Cloud-native monitoring | Manual review
3. How are incidents communicated internally?
   - Options: Slack/Teams channel | Email | On-call rotation | Ad-hoc
4. Have you conducted an incident response drill?
   - Options: Yes, within last year | Yes, over a year ago | No

**Template Hints:**
- Purpose: Establishes procedures for detecting, responding to, and recovering from security incidents
- Scope: All security events affecting company systems and data
- Key Procedures: Incident classification, escalation procedures, post-incident review

**Related Policies:** vulnerability-monitoring, external-communications

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | IR plan document | Policy | Documented incident response procedures. Must show: severity levels, escalation contacts, response timeframes, communication templates |
| [ ] | IR drill report | Policy | Post-drill report with findings and improvements. Must show: drill date, scenario tested, participants, findings, remediation actions |
| [ ] | Incident ticket examples | Workflow | Recording of incident handling in ticketing system. Must show: ticket creation, severity assignment, timeline, resolution, post-mortem |
| [ ] | Alerting configuration | Screenshot | Screenshot of monitoring/alerting tool setup. Must show: alert rules configured, notification channels, severity thresholds |
| [ ] | Incident log export | Log | Export of incidents handled during audit period. Must show: incident date, severity, response time, resolution time, root cause |

---

## 6. External Communications (ECP)

**ID:** `external-communications`

**Topics:** Product descriptions, support system, MSA/TOS, customer notifications

**Questions to Ask:**
1. How do customers report issues or security concerns?
   - Options: Dedicated security email | Support portal | General support only | No formal process
2. Do you have published Terms of Service and Privacy Policy?
   - Options: Yes, reviewed annually | Yes, not reviewed regularly | No
3. Do you have a customer breach notification process?
   - Options: Yes, documented | Informal process | No

**Template Hints:**
- Purpose: Establishes requirements for external communications regarding security matters
- Scope: All customer-facing communications and disclosures
- Key Procedures: Customer notification, security disclosure, public communications approval

**Related Policies:** incident-response, information-security-policy

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Terms of Service | Policy | Current published ToS document. Must show: effective date, security/data handling sections, customer obligations |
| [ ] | Privacy Policy | Policy | Current published privacy policy. Must show: effective date, data collection practices, retention periods, contact info |
| [ ] | Support portal | Screenshot | Screenshot of customer support/security contact options. Must show: security contact email/form, response time SLA (if stated) |
| [ ] | Breach notification template | Policy | Template for customer breach notifications. Must show: notification timeline, information included, contact methods |

---

## 7. Vendor Management (VMP)

**ID:** `vendor-management`

**Topics:** Vendor agreements, vendor risk program, third-party security

**Questions to Ask:**
1. Do you maintain a vendor inventory?
   - Options: Yes, actively maintained | Yes, outdated | No
2. Do you assess vendor security before contracting?
   - Options: Yes, formal assessment | Yes, informal review | No
3. Do vendor contracts include security requirements?
   - Options: Yes, standard clauses | Sometimes | No

**Template Hints:**
- Purpose: Establishes requirements for managing third-party vendor relationships
- Scope: All vendors with access to company data or systems
- Key Procedures: Vendor risk assessment, contract security requirements, ongoing vendor monitoring

**Related Policies:** risk-management, data-management

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Vendor inventory | Log | Spreadsheet/export of all vendors with data access. Must show: vendor name, data types accessed, risk tier, last review date |
| [ ] | Vendor assessment forms | Policy | Completed security questionnaires for key vendors. Must show: vendor name, assessment date, security controls evaluated, risk rating |
| [ ] | Vendor contracts | Policy | Sample contracts showing security clauses. Must show: data protection terms, breach notification requirements, audit rights |
| [ ] | Vendor SOC 2 reports | Policy | SOC 2 reports from critical vendors. Must show: report date within 12 months, scope covers services used, no critical exceptions |
| [ ] | Vendor review process | Workflow | Recording of vendor assessment workflow. Must show: intake form, risk evaluation, approval/rejection, contract execution |

---

## 8. Risk Management (RMP)

**ID:** `risk-management`

**Topics:** Risk identification, risk assessments, threat rating

**Questions to Ask:**
1. Do you conduct formal risk assessments?
   - Options: Yes, annually | Yes, ad-hoc | No
2. Do you maintain a risk register?
   - Options: Yes, actively maintained | Yes, outdated | No
3. Are risks assigned to owners?
   - Options: Yes, all risks | Yes, critical risks only | No

**Template Hints:**
- Purpose: Establishes the risk management framework and assessment process
- Scope: All identified risks affecting company operations
- Key Procedures: Risk identification, risk assessment methodology, risk treatment

**Related Policies:** governance-board-oversight, information-security-policy

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Risk register | Log | Current risk register with owners and status. Must show: risk description, likelihood, impact, owner, mitigation status, last updated date |
| [ ] | Risk assessment report | Policy | Annual/periodic risk assessment document. Must show: assessment date, methodology, identified risks, treatment decisions, approver |
| [ ] | Risk review meeting notes | Policy | Minutes from risk review discussions. Must show: meeting date, attendees, risks discussed, decisions made, action items |
| [ ] | Risk management tool | Screenshot | Screenshot of GRC/risk management platform. Must show: current date, risk dashboard, number of open/closed risks |

---

## 9. Change Management (CMP)

**ID:** `change-management`

**Topics:** Configuration management, SDLC, change authorization

**Questions to Ask:**
1. Do you require code review before merge?
   - Options: Yes, all changes | Most changes | Only for production | No
2. Do you have a staging environment?
   - Options: Yes | No | Partial
3. How are production deployments approved?
   - Options: PR approval | Change board | Self-approval | No formal process
4. Do you maintain a change log?
   - Options: Yes, automated | Yes, manual | No

**Template Hints:**
- Purpose: Establishes requirements for managing changes to systems and applications
- Scope: All changes affecting production systems
- Key Procedures: Change request and approval, testing requirements, rollback procedures

**Related Policies:** vulnerability-monitoring, information-security-policy

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | PR approval flow | Workflow | Recording of code review and merge process. Must show: PR creation, reviewer assignment, review comments, approval, merge to main |
| [ ] | Branch protection settings | Screenshot | GitHub/GitLab branch protection configuration. Must show: main branch protected, required reviewers ≥1, no direct pushes allowed |
| [ ] | Deployment pipeline | Screenshot | CI/CD pipeline showing approval gates. Must show: build/test stages, deployment approval step, production deployment |
| [ ] | Change log/release notes | Log | Export of changes deployed during audit period. Must show: change date, description, author, approver, deployment timestamp |
| [ ] | Staging environment | Screenshot | Screenshot showing separate staging environment. Must show: distinct URL/environment name, different from production |

---

## 10. Access Control (ACP)

**ID:** `access-control`

**Topics:** Access provisioning/deprovisioning, privileged access, MFA, access reviews

**Questions to Ask:**
1. What identity provider do you use?
   - Options: Okta | Google Workspace | Azure AD | AWS IAM Identity Center | Other
2. Is MFA enforced for all user accounts?
   - Options: Yes, all users | Admins only | Optional | Not yet
3. How often are access reviews performed?
   - Options: Quarterly | Semi-annually | Annually | Ad-hoc
4. How quickly is access revoked on termination?
   - Options: Same day | Within 24 hours | Within 1 week | No formal process

**Template Hints:**
- Purpose: Establishes requirements for managing access to information systems
- Scope: All employees, contractors, and third-party users
- Key Procedures: Access provisioning workflow, access review process, termination revocation

**Related Policies:** human-resources, vendor-management

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | MFA enforcement | Screenshot | IdP admin showing MFA required for all users. Must show: MFA policy enabled, scope = all users, no exceptions listed, enforcement mode (not optional) |
| [ ] | Access provisioning | Workflow | Recording of new user access request and approval. Must show: request ticket, manager approval, IT provisioning, access granted confirmation |
| [ ] | Access review completion | Log | Export showing completed access review with dates. Must show: reviewer name, review date, users reviewed, action taken (approved/revoked), 100% coverage |
| [ ] | Termination access revocation | Log | IdP logs showing timely deprovisioning. Must show: termination date, account disabled date, time delta within policy SLA |
| [ ] | User list export | Log | Current user list with roles and last login. Must show: all users, role/group assignments, last login date, status (active/disabled) |

---

## 11. Data Management (DMP)

**ID:** `data-management`

**Topics:** Data retention/disposal, backup, data classification, encryption at rest

**Questions to Ask:**
1. Do you have a data classification scheme?
   - Options: Yes | In progress | No
2. Is data encrypted at rest?
   - Options: Yes, all data | Sensitive data only | No
3. Do you have a data retention policy?
   - Options: Yes, documented | Informal | No
4. How is data disposed of?
   - Options: Secure deletion | Standard deletion | No formal process

**Template Hints:**
- Purpose: Establishes requirements for data classification, protection, and lifecycle
- Scope: All company data regardless of storage location
- Key Procedures: Data classification, encryption requirements, retention and disposal

**Related Policies:** access-control, network-security

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Data classification policy | Policy | Document defining classification levels. Must show: classification tiers (e.g., public/internal/confidential), handling requirements per tier, examples |
| [ ] | Encryption at rest settings | Screenshot | Cloud console showing encryption enabled. Must show: encryption status = enabled, key management (AWS KMS/GCP KMS), all data stores covered |
| [ ] | Backup configuration | Screenshot | Backup service showing schedule and retention. Must show: backup frequency, retention period, encryption enabled, last successful backup date |
| [ ] | Data retention schedule | Policy | Document defining retention periods by data type. Must show: data categories, retention period per category, deletion method, legal basis |
| [ ] | Secure deletion procedure | Policy | Documented data disposal process. Must show: deletion methods by storage type, verification steps, responsible party |

---

## 12. Physical Security (PSP)

**ID:** `physical-security`

**Topics:** Data center access, visitor management

**Questions to Ask:**
1. What is your primary office setup?
   - Options: Physical office | Co-working space | Fully remote | Hybrid
2. Where is your infrastructure hosted?
   - Options: Cloud only (AWS/GCP/Azure) | Co-located data center | On-premises | Hybrid
3. Do you have a visitor management process?
   - Options: Yes, formal sign-in | Informal | Not applicable | No

**Template Hints:**
- Purpose: Establishes requirements for physical security of facilities and assets
- Scope: All physical locations where company data is accessed or stored
- Key Procedures: Facility access controls, visitor management, data center requirements

**Related Policies:** access-control, data-management

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Cloud provider SOC 2 | Policy | AWS/GCP/Azure SOC 2 report (for cloud-only). Must show: report date within 12 months, services you use in scope, no critical exceptions |
| [ ] | Office access controls | Screenshot | Badge system or access control configuration. Must show: access control system in use, restricted areas defined, badge required for entry |
| [ ] | Visitor log | Log | Sample visitor sign-in records (if applicable). Must show: visitor name, date/time in, host employee, date/time out |
| [ ] | Data center compliance | Policy | Co-location provider's compliance certifications. Must show: SOC 2 or ISO 27001 certification, facility address matches your usage |

---

## 13. Vulnerability & Monitoring (VMP)

**ID:** `vulnerability-monitoring`

**Topics:** Vulnerability scans, penetration testing, log management, IDS, patching, anti-malware

**Questions to Ask:**
1. Do you perform vulnerability scanning?
   - Options: Yes, automated/continuous | Yes, periodic | No
2. Do you conduct penetration testing?
   - Options: Yes, annually | Yes, less frequently | No
3. How do you manage security logs?
   - Options: SIEM/centralized logging | Cloud-native logging | Basic logging | No centralized logs
4. How quickly are critical patches applied?
   - Options: Within 24 hours | Within 1 week | Within 30 days | No formal process

**Template Hints:**
- Purpose: Establishes requirements for vulnerability management and security monitoring
- Scope: All systems and applications in production
- Key Procedures: Vulnerability scanning, patch management, security monitoring

**Related Policies:** incident-response, change-management

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Vulnerability scan report | Log | Recent scan results from scanning tool. Must show: scan date within 30 days, systems scanned, vulnerabilities by severity, remediation status |
| [ ] | Penetration test report | Policy | Annual pentest report from third party. Must show: test date within 12 months, scope/methodology, findings, remediation recommendations |
| [ ] | Patch management records | Log | Evidence of timely patching. Must show: vulnerability disclosed date, patch applied date, time delta within policy SLA (e.g., critical <7 days) |
| [ ] | SIEM/logging dashboard | Screenshot | Screenshot of centralized logging setup. Must show: log sources configured, retention period, current date, sample alerts/queries |
| [ ] | Vulnerability remediation | Workflow | Recording of vulnerability triage and fix process. Must show: vulnerability intake, severity assignment, remediation ticket, verification, closure |

---

## 14. Network Security (NSP)

**ID:** `network-security`

**Topics:** Encryption in transit, firewall rules, network hardening

**Questions to Ask:**
1. Is all data encrypted in transit?
   - Options: Yes, TLS everywhere | Most connections | External only | No
2. Do you use firewalls or security groups?
   - Options: Yes, WAF + security groups | Security groups only | Basic firewall | No
3. Is your network segmented (prod/staging/dev)?
   - Options: Yes, fully segmented | Partially | No

**Template Hints:**
- Purpose: Establishes requirements for network security and data transmission protection
- Scope: All network infrastructure and data transmission
- Key Procedures: Encryption requirements, firewall management, network segmentation

**Related Policies:** data-management, access-control

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | TLS configuration | Screenshot | SSL Labs or similar showing TLS settings. Must show: grade A or B, TLS 1.2+ only, no weak ciphers, domain name visible, test date |
| [ ] | Firewall/security group rules | Screenshot | Cloud console showing security group config. Must show: inbound rules (minimal ports open), no 0.0.0.0/0 on sensitive ports, rule descriptions |
| [ ] | WAF configuration | Screenshot | WAF dashboard showing rules enabled. Must show: WAF active, rule sets enabled (OWASP/managed rules), domains protected |
| [ ] | Network diagram | Policy | Architecture diagram showing segmentation. Must show: network zones (prod/staging/dev), traffic flow, firewall/security group boundaries |

---

## 15. Business Continuity (BCP)

**ID:** `business-continuity`

**Topics:** BC/DR plans, testing, cybersecurity insurance

**Questions to Ask:**
1. Do you have documented BC/DR plans?
   - Options: Yes | In progress | No
2. Have you tested your recovery procedures?
   - Options: Yes, within last year | Yes, over a year ago | No
3. Do you have cybersecurity insurance?
   - Options: Yes | In process | No
4. How frequently is data backed up?
   - Options: Continuous/real-time | Daily | Weekly | No regular backups

**Template Hints:**
- Purpose: Establishes requirements for business continuity and disaster recovery
- Scope: All critical business systems and data
- Key Procedures: Recovery time objectives, backup procedures, DR testing schedule

**Related Policies:** data-management, incident-response

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | BC/DR plan document | Policy | Business continuity and disaster recovery plan. Must show: RTO/RPO targets, recovery procedures, communication plan, responsible parties |
| [ ] | DR test report | Policy | Results from most recent DR test. Must show: test date within 12 months, scenario tested, results vs RTO/RPO targets, lessons learned |
| [ ] | Backup verification | Screenshot | Screenshot showing successful backup/restore. Must show: backup completion status, timestamp, data restored successfully (test restore) |
| [ ] | Cyber insurance certificate | Policy | Certificate of insurance coverage. Must show: policy active, coverage amount, cyber/data breach coverage included, policy period |
| [ ] | RTO/RPO documentation | Policy | Documented recovery objectives. Must show: RTO and RPO per system/data type, business justification, stakeholder approval |

---

## 16. Human Resources (HRP)

**ID:** `human-resources`

**Topics:** Performance evaluations, background checks, security training, termination checklists

**Questions to Ask:**
1. Do you perform background checks for new hires?
   - Options: Yes, all employees | Yes, certain roles | No
2. Do employees receive security training?
   - Options: Yes, annually | Yes, at onboarding only | No
3. Do you have a termination checklist including access revocation?
   - Options: Yes, documented | Informal process | No
4. Do you conduct regular performance reviews?
   - Options: Yes, annually | Yes, semi-annually | Informal | No

**Template Hints:**
- Purpose: Establishes human resources requirements for security and accountability
- Scope: All employees throughout their employment lifecycle
- Key Procedures: Onboarding security requirements, security training, termination procedures

**Related Policies:** access-control, code-of-conduct

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | Background check policy | Policy | Documented background check requirements. Must show: check types performed (criminal, employment), when performed (pre-hire), applicable roles |
| [ ] | Training completion records | Log | Export of security training completions. Must show: employee name, training course, completion date, 100% employee coverage |
| [ ] | Termination checklist | Policy | Signed checklist template for offboarding. Must show: access revocation items, equipment return, exit interview, signatures/dates |
| [ ] | Performance review records | Log | Sample performance review documentation. Must show: review date, employee name, reviewer, security responsibilities addressed |
| [ ] | Onboarding checklist | Policy | New hire security onboarding checklist. Must show: policy acknowledgments, training assigned, access provisioning, equipment issued |

---

## 17. Mobile & Endpoint (MEP)

**ID:** `mobile-endpoint`

**Topics:** MDM, portable media encryption

**Questions to Ask:**
1. Do you use Mobile Device Management (MDM)?
   - Options: Yes, all devices | Yes, company devices only | No
2. Do you allow BYOD (Bring Your Own Device)?
   - Options: No, company devices only | Yes, with MDM | Yes, without MDM
3. Do you use endpoint protection/antivirus?
   - Options: Yes, managed solution | Yes, individual installs | No
4. Is disk encryption required on all devices?
   - Options: Yes, enforced | Yes, not enforced | No

**Template Hints:**
- Purpose: Establishes requirements for mobile devices and endpoint security
- Scope: All devices used to access company data
- Key Procedures: Device enrollment requirements, BYOD policy, endpoint security standards

**Related Policies:** access-control, data-management

**Evidence Requirements:**
| Status | Evidence | Type | Description |
|--------|----------|------|-------------|
| [ ] | MDM enrollment status | Screenshot | MDM console showing enrolled devices. Must show: total devices enrolled, enrollment status per device, compliance status, current date |
| [ ] | Disk encryption enforcement | Screenshot | MDM/endpoint tool showing encryption status. Must show: encryption policy enabled, 100% device compliance or exceptions listed |
| [ ] | Endpoint protection dashboard | Screenshot | Antivirus/EDR console showing coverage. Must show: protection active, devices covered, last scan date, threat detection status |
| [ ] | BYOD policy acknowledgment | Policy | Signed BYOD agreements (if applicable). Must show: employee name, signature, date, security requirements acknowledged |
| [ ] | Device inventory | Log | Export of all managed devices. Must show: device name/ID, owner, OS version, compliance status, last check-in date |
