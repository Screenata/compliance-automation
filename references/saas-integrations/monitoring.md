# SaaS Integration — Monitoring & Alerting

Covers: Datadog, PagerDuty, New Relic, Splunk Cloud
TSC: CC7.1-7.2 (Vulnerability Monitoring), CC7.3-7.5 (Incident Response), A1.2 (Business Continuity)

---

## Datadog

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| Active monitors count | CC7.1 | `GET /api/v1/monitor` | API key + App key |
| Monitor status summary | CC7.1 | `GET /api/v1/monitor/search?query=status:alert` | API key + App key |
| Dashboards count | CC7.2 | `GET /api/v1/dashboard/lists/manual` | API key + App key |
| SLOs | A1.2 | `GET /api/v1/slo` | API key + App key |
| Downtime schedules | A1.2 | `GET /api/v2/downtime` | API key + App key |
| Security signals (SIEM) | CC7.1 | `POST /api/v2/security_monitoring/signals/search` | API key + App key |
| Log indexes | CC7.2 | `GET /api/v1/logs/config/indexes` | API key + App key |

**Auth:** Headers `DD-API-KEY: {key}` and `DD-APPLICATION-KEY: {key}`
**Base URL:** `https://api.datadoghq.com` (or `api.datadoghq.eu` for EU)
**Rate limit:** 300 requests/min for most endpoints.

**Script pattern (active monitors):**
```bash
#!/usr/bin/env bash
# .compliance/scripts/datadog.sh (excerpt)
# Requires: DATADOG_API_KEY, DATADOG_APP_KEY env vars
# Config:   datadog.config.json { "site": "datadoghq.com" }
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${SCRIPT_DIR}/$(basename "$0" .sh).config.json"
SITE=$(jq -r '.site // "datadoghq.com"' "$CONFIG")
BASE="https://api.${SITE}"

# ... (header/output setup per script-templates.md) ...

result=$(curl -sf \
  -H "DD-API-KEY: $DATADOG_API_KEY" \
  -H "DD-APPLICATION-KEY: $DATADOG_APP_KEY" \
  "$BASE/api/v1/monitor?page=0&page_size=1" || echo "[]")
total=$(echo "$result" | jq 'length')
alerting=$(curl -sf \
  -H "DD-API-KEY: $DATADOG_API_KEY" \
  -H "DD-APPLICATION-KEY: $DATADOG_APP_KEY" \
  "$BASE/api/v1/monitor/search?query=status:alert" | jq '.counts.status[] | select(.name == "Alert") | .count // 0' || echo "0")
echo "| Active monitors | **${total} total, ${alerting:-0} alerting** | Datadog | \`/api/v1/monitor\` | ${total} monitors, ${alerting:-0} alerting |" >> "$OUT"
```

---

## PagerDuty

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| Active incidents | CC7.3 | `GET /incidents?statuses[]=triggered&statuses[]=acknowledged` | Bearer token |
| Escalation policies | CC7.3 | `GET /escalation_policies` | Bearer token |
| Services count | CC7.1 | `GET /services` | Bearer token |
| On-call schedules | CC7.3 | `GET /schedules` | Bearer token |
| Incident response stats | CC7.3 | `GET /analytics/raw/incidents` (last 30 days) | Bearer token |

**Auth:** `Authorization: Token token={PAGERDUTY_API_TOKEN}`
**Base URL:** `https://api.pagerduty.com`
**Rate limit:** 960 requests/min (account plan dependent).

---

## New Relic

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| Alert policies | CC7.1 | NerdGraph: `{ actor { account(id: {id}) { alerts { policiesSearch { policies { name } } } } } }` | API key |
| Alert conditions count | CC7.1 | NerdGraph query | API key |
| Active violations | CC7.3 | NerdGraph: `openViolations` | API key |
| Monitored entities | CC7.1 | `GET /v2/applications.json` | API key |

**Auth:** `Api-Key: {NEWRELIC_API_KEY}` for REST, or NerdGraph (GraphQL) at `https://api.newrelic.com/graphql`

---

## Splunk Cloud

**Compliance evidence provided:**

| Evidence | Controls | API Endpoint | Method |
|----------|-----|-------------|--------|
| Saved searches (alerts) | CC7.1 | `GET /services/saved/searches?count=0` | Bearer token |
| Indexes | CC7.2 | `GET /services/data/indexes` | Bearer token |
| Inputs (log sources) | CC7.2 | `GET /services/data/inputs/all` | Bearer token |

**Auth:** Bearer token or basic auth
**Base URL:** `https://{instance}.splunkcloud.com:8089`
