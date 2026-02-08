# SaaS Integration — Security & Vulnerability Scanning

Covers: Snyk, SonarCloud / SonarQube
TSC: CC7.1-7.2 (Vulnerability Monitoring), CC8.1 (Change Management)

---

## Snyk

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| Monitored projects | CC7.1 | `GET /rest/orgs/{org_id}/projects?version=2024-01-23` | Bearer token |
| Open vulnerability count | CC7.1 | `GET /rest/orgs/{org_id}/issues?version=2024-01-23&status=open` | Bearer token |
| Vulnerability by severity | CC7.1 | Issues endpoint filtered by severity | Bearer token |

**Auth:** `Authorization: token {SNYK_TOKEN}`
**Base URL:** `https://api.snyk.io`

---

## SonarCloud / SonarQube

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| Quality gate status | CC8.1 | `GET /api/qualitygates/project_status?projectKey={key}` | Bearer token |
| Open vulnerabilities | CC7.1 | `GET /api/issues/search?types=VULNERABILITY&statuses=OPEN` | Bearer token |
| Code coverage | CC8.1 | `GET /api/measures/component?component={key}&metricKeys=coverage` | Bearer token |

**Auth:** `Authorization: Bearer {SONAR_TOKEN}`
