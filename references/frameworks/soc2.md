# SOC 2 Trust Services Criteria — Control Mappings

This file maps each policy to its relevant SOC 2 Trust Services Criteria (TSC). Used by the agent to populate the `satisfies.TSC` field in policy YAML frontmatter when SOC 2 is selected.

## How to Use

When generating a policy for a user who selected SOC 2:
1. Look up the policy ID in the table below
2. Include all listed TSC codes in the policy's `satisfies.TSC` frontmatter
3. Reference the criteria descriptions in the policy body where appropriate

## Control Mappings by Policy

### governance-board-oversight

| TSC Code | Description |
|----------|-------------|
| CC1.1 | Demonstrates commitment to integrity and ethical values |
| CC1.2 | Board exercises oversight responsibility |
| CC1.3 | Management establishes structures and reporting lines |

### organizational-structure

| TSC Code | Description |
|----------|-------------|
| CC1.3 | Management establishes structures and reporting lines |
| CC1.4 | Demonstrates commitment to attract, develop, retain competent individuals |
| CC1.5 | Holds individuals accountable for internal control responsibilities |

### code-of-conduct

| TSC Code | Description |
|----------|-------------|
| CC1.1 | Demonstrates commitment to integrity and ethical values |
| CC1.4 | Demonstrates commitment to attract, develop, retain competent individuals |

### information-security-policy

| TSC Code | Description |
|----------|-------------|
| CC1.1 | Demonstrates commitment to integrity and ethical values |
| CC2.2 | Internally communicates information for internal control |
| CC5.1 | Selection and development of control activities |
| CC5.2 | Selection and development of general controls over technology |

### incident-response

| TSC Code | Description |
|----------|-------------|
| CC7.3 | Evaluates security events to determine failures |
| CC7.4 | Responds to identified security incidents |
| CC7.5 | Identifies and implements activities to recover from incidents |

### external-communications

| TSC Code | Description |
|----------|-------------|
| CC1.1 | Demonstrates commitment to integrity and ethical values |
| CC2.2 | Internally communicates information for internal control |
| CC2.3 | Communicates with external parties regarding internal control |

### vendor-management

| TSC Code | Description |
|----------|-------------|
| CC9.2 | Assesses and manages risks associated with vendors and business partners |

### risk-management

| TSC Code | Description |
|----------|-------------|
| CC3.1 | Specifies objectives to enable identification and assessment of risks |
| CC3.2 | Identifies and analyzes risks to objectives |
| CC3.3 | Considers potential for fraud in assessing risks |

### change-management

| TSC Code | Description |
|----------|-------------|
| CC8.1 | Authorizes, designs, develops, configures, documents, tests, approves, and implements changes |

### access-control

| TSC Code | Description |
|----------|-------------|
| CC6.1 | Implements logical access security software and architectures |
| CC6.2 | Registers and authorizes new users before issuing credentials |
| CC6.3 | Authorizes, modifies, or removes access to protected assets |

### data-management

| TSC Code | Description |
|----------|-------------|
| CC6.5 | Discontinues protections only after no longer necessary |
| CC6.6 | Implements logical access security against external threats |
| CC6.7 | Restricts transmission, movement, and removal of information |
| CC8.1 | Authorizes, designs, develops, configures, documents, tests, approves, and implements changes |

### physical-security

| TSC Code | Description |
|----------|-------------|
| CC6.4 | Restricts physical access to facilities and protected information assets |

### vulnerability-monitoring

| TSC Code | Description |
|----------|-------------|
| CC7.1 | Uses detection and monitoring to identify configuration changes |
| CC7.2 | Monitors system components for anomalies |

### network-security

| TSC Code | Description |
|----------|-------------|
| CC6.6 | Implements logical access security against external threats |
| CC6.7 | Restricts transmission, movement, and removal of information |
| CC7.1 | Uses detection and monitoring to identify configuration changes |

### business-continuity

| TSC Code | Description |
|----------|-------------|
| A1.2 | Authorizes, implements, operates, and monitors environmental protections |
| A1.3 | Tests recovery plan procedures supporting system recovery |
| CC7.4 | Responds to identified security incidents |

### human-resources

| TSC Code | Description |
|----------|-------------|
| CC1.4 | Demonstrates commitment to attract, develop, retain competent individuals |
| CC1.5 | Holds individuals accountable for internal control responsibilities |

### mobile-endpoint

| TSC Code | Description |
|----------|-------------|
| CC6.6 | Implements logical access security against external threats |
| CC6.7 | Restricts transmission, movement, and removal of information |
| CC6.8 | Implements controls to prevent or detect unauthorized or malicious software |

## Quick Reference

| Policy ID | TSC Codes |
|-----------|-----------|
| governance-board-oversight | CC1.1, CC1.2, CC1.3 |
| organizational-structure | CC1.3, CC1.4, CC1.5 |
| code-of-conduct | CC1.1, CC1.4 |
| information-security-policy | CC1.1, CC2.2, CC5.1, CC5.2 |
| incident-response | CC7.3, CC7.4, CC7.5 |
| external-communications | CC1.1, CC2.2, CC2.3 |
| vendor-management | CC9.2 |
| risk-management | CC3.1, CC3.2, CC3.3 |
| change-management | CC8.1 |
| access-control | CC6.1, CC6.2, CC6.3 |
| data-management | CC6.5, CC6.6, CC6.7, CC8.1 |
| physical-security | CC6.4 |
| vulnerability-monitoring | CC7.1, CC7.2 |
| network-security | CC6.6, CC6.7, CC7.1 |
| business-continuity | A1.2, A1.3, CC7.4 |
| human-resources | CC1.4, CC1.5 |
| mobile-endpoint | CC6.6, CC6.7, CC6.8 |
