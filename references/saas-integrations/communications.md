# SaaS Integration — Communications & Incident Response

Covers: Slack, Opsgenie, Statuspage
TSC: CC6.1 (Access Control — 2FA), CC7.2-7.3 (Monitoring & Incident Response), A1.2 (Business Continuity)

---

## Slack

**SOC 2 evidence provided:**

| Evidence | TSC | API Endpoint | Method |
|----------|-----|-------------|--------|
| Workspace settings (2FA) | CC6.1 | `GET /api/team.info` | Bearer token |
| Channel count (audit trail) | CC7.2 | `GET /api/conversations.list?types=public_channel&limit=1` | Bearer token |
| Incident channels | CC7.3 | `GET /api/conversations.list?types=public_channel` (filter by naming pattern) | Bearer token |

**Auth:** `Authorization: Bearer {SLACK_BOT_TOKEN}`
**Required scopes:** `team:read`, `channels:read`
**Rate limit:** Tier 2-3 (20-50 requests/min depending on method).

**Note:** Slack evidence is limited. Primary value is confirming 2FA enforcement at workspace level and existence of incident response channels.

---

## Opsgenie

**SOC 2 evidence provided:**

| Evidence | TSC | API Endpoint | Method |
|----------|-----|-------------|--------|
| Escalation policies | CC7.3 | `GET /v2/escalations` | GenieKey header |
| On-call schedules | CC7.3 | `GET /v2/schedules` | GenieKey header |
| Open alerts | CC7.3 | `GET /v2/alerts?status=open` | GenieKey header |
| Integrations | CC7.1 | `GET /v2/integrations` | GenieKey header |

**Auth:** `Authorization: GenieKey {OPSGENIE_API_KEY}`
**Base URL:** `https://api.opsgenie.com`

---

## Statuspage

**SOC 2 evidence provided:**

| Evidence | TSC | API Endpoint | Method |
|----------|-----|-------------|--------|
| Components monitored | A1.2 | `GET /v1/pages/{page_id}/components` | OAuth token |
| Active incidents | A1.2 | `GET /v1/pages/{page_id}/incidents/unresolved` | OAuth token |
| Uptime metrics | A1.2 | Component uptime from page data | OAuth token |

**Auth:** `Authorization: OAuth {STATUSPAGE_API_KEY}`
**Base URL:** `https://api.statuspage.io`
