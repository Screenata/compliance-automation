# SaaS Tool Auto-Detection Patterns

For: **Step 1, Question 13** — auto-detect SaaS tools before asking the user.
See [shared.md](shared.md) for general scanning guidelines.

## Safety Rules

- **NEVER read `.env` files** — they are gitignored and may contain secrets
- **ONLY read `.env.example`, `.env.sample`, `.env.template`** — these are safe templates committed to the repo
- Present detections as confirmations, not assumptions
- Always allow the user to add or remove from the detected list

## Detection Strategy

Run all detection patterns below, collect matches, then present a single confirmation prompt. Group results by category (Identity, Monitoring, etc.) to match the Q13 format. Include the source file and matched pattern for each detection so the user can verify.

---

## Layer 1: Environment Variable Templates

**Find files:**
```
Glob: .env.example, .env.sample, .env.template, .env.*.example, .env.*.sample, docker-compose.yml, docker-compose.yaml
```

### Identity & Access
```
Grep: OKTA_DOMAIN|OKTA_API_TOKEN|OKTA_ORG_URL|OKTA_CLIENT_ID  → Okta
Grep: AUTH0_DOMAIN|AUTH0_CLIENT_ID|AUTH0_CLIENT_SECRET|AUTH0_AUDIENCE  → Auth0
Grep: GOOGLE_SA_KEY|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_WORKSPACE  → Google Workspace
Grep: JUMPCLOUD_API_KEY|JUMPCLOUD_ORG_ID  → JumpCloud
```

### Monitoring & Alerting
```
Grep: DD_API_KEY|DD_APP_KEY|DATADOG_API_KEY|DATADOG_APP_KEY|DD_SITE  → Datadog
Grep: PAGERDUTY_API_TOKEN|PAGERDUTY_INTEGRATION_KEY|PD_API_KEY  → PagerDuty
Grep: NEW_RELIC_API_KEY|NEWRELIC_API_KEY|NEW_RELIC_LICENSE_KEY|NEW_RELIC_ACCOUNT_ID  → New Relic
Grep: SPLUNK_TOKEN|SPLUNK_HEC_TOKEN|SPLUNK_HOST  → Splunk
```

### Project & Change Management
```
Grep: JIRA_API_TOKEN|JIRA_EMAIL|JIRA_DOMAIN|JIRA_BASE_URL  → Jira
Grep: LINEAR_API_KEY|LINEAR_TEAM_ID  → Linear
```

### Communications
```
Grep: SLACK_BOT_TOKEN|SLACK_WEBHOOK|SLACK_API_TOKEN|SLACK_SIGNING_SECRET  → Slack
Grep: OPSGENIE_API_KEY  → Opsgenie
Grep: STATUSPAGE_API_KEY|STATUSPAGE_PAGE_ID  → Statuspage
```

### HR & People
```
Grep: BAMBOOHR_API_KEY|BAMBOOHR_SUBDOMAIN  → BambooHR
Grep: GUSTO_API_TOKEN|GUSTO_CLIENT_ID  → Gusto
Grep: RIPPLING_API_TOKEN  → Rippling
```

### Endpoint Management
```
Grep: JAMF_CLIENT_ID|JAMF_CLIENT_SECRET|JAMF_URL  → Jamf
Grep: KANDJI_API_TOKEN|KANDJI_SUBDOMAIN  → Kandji
Grep: INTUNE_CLIENT_ID|INTUNE_TENANT_ID  → Intune
```

### Security Scanning
```
Grep: SNYK_TOKEN|SNYK_ORG_ID  → Snyk
Grep: SONARCLOUD_TOKEN|SONAR_TOKEN|SONAR_PROJECT_KEY  → SonarCloud
```

---

## Layer 2: Package Manager Dependencies

**Find files:**
```
Glob: package.json, requirements.txt, Pipfile, go.mod, Gemfile, build.gradle, pom.xml, composer.json
```

**Extract values:**
```
Grep: @okta/okta-sdk-nodejs|@okta/okta-react|@okta/okta-auth-js|okta  → Okta
Grep: auth0-js|@auth0/auth0-react|@auth0/nextjs-auth0|auth0-python  → Auth0
Grep: dd-trace|@datadog/browser-rum|datadog-api-client|dogstatsd  → Datadog
Grep: newrelic|@newrelic/apollo-server-plugin|new_relic_agent  → New Relic
Grep: @slack/web-api|@slack/bolt|slack-sdk|slack_sdk  → Slack
Grep: @pagerduty/pdjs|pagerduty  → PagerDuty
Grep: @linear/sdk  → Linear
Grep: @octokit/rest|octokit  → GitHub
Grep: snyk  → Snyk (only if in devDependencies or scripts section)
```

---

## Layer 3: Terraform Providers

**Find files:**
```
Glob: **/*.tf
```

**Extract values:**
```
Grep: provider\s+"datadog"  → Datadog
Grep: provider\s+"pagerduty"  → PagerDuty
Grep: provider\s+"okta"  → Okta
Grep: provider\s+"auth0"  → Auth0
Grep: provider\s+"newrelic"  → New Relic
Grep: provider\s+"opsgenie"  → Opsgenie
Grep: provider\s+"github"  → GitHub
Grep: resource\s+"snyk_  → Snyk
```

---

## Layer 4: GitHub Actions / CI

**Find files:**
```
Glob: .github/workflows/*.yml, .github/workflows/*.yaml
```

**Extract values:**
```
Grep: snyk/actions|snyk-  → Snyk
Grep: sonarsource/sonarcloud|SonarSource/sonarcloud-github-action  → SonarCloud
Grep: DataDog/agent-github-action|datadog-ci  → Datadog
Grep: slackapi/slack-github-action  → Slack
Grep: atlassian/gajira  → Jira
```

---

## Layer 5: Tool-Specific Config Files

Check for known config files in the repo. Each match is a strong signal.

```
Glob: newrelic.js, newrelic.yml, newrelic.ini  → New Relic
Glob: datadog.yaml, datadog.yml  → Datadog
Glob: .snyk  → Snyk
Glob: sonar-project.properties, .sonarcloud.properties  → SonarCloud
Glob: .pagerduty.yml  → PagerDuty
```

---

## Layer 6: Docker Compose Services

**Find files:**
```
Glob: docker-compose.yml, docker-compose.yaml, docker-compose.*.yml, compose.yml, compose.yaml
```

**Extract values:**
```
Grep: image:\s*datadog/agent|gcr.io/datadoghq  → Datadog
Grep: image:\s*splunk/  → Splunk
Grep: image:\s*newrelic/  → New Relic
```

---

## Presentation Format

After running all layers, present results grouped by category:

```
I scanned your codebase and detected the following SaaS tools:

**Identity & Access:**
- Okta (found: OKTA_DOMAIN in .env.example, @okta/okta-sdk-nodejs in package.json)

**Monitoring & Alerting:**
- Datadog (found: DD_API_KEY in .env.example, provider "datadog" in infrastructure/main.tf)
- PagerDuty (found: PAGERDUTY_API_TOKEN in .env.example)

**Security Scanning:**
- Snyk (found: snyk/actions in .github/workflows/ci.yml, .snyk config file)
- SonarCloud (found: sonar-project.properties)

Are these correct? Any tools to add or remove?
(Or type "skip" for no SaaS integrations)
```

If nothing is detected across any layer, fall back to the manual Q13 prompt.
