# SaaS Integration — HR & People

Covers: BambooHR, Gusto, Rippling
TSC: CC1.4 (Personnel), CC6.2 (Access Revocation), CC6.8 (Endpoint Security)

**Privacy note:** Only extract aggregate counts and policy settings. Never include individual employee names, emails, SSNs, or salary information in evidence.

---

## BambooHR

**SOC 2 evidence provided:**

| Evidence | TSC | API Endpoint | Method |
|----------|-----|-------------|--------|
| Employee count | CC1.4 | `GET /api/gateway.php/{subdomain}/v1/employees/directory` | Basic auth |
| Recent terminations | CC6.2 | `GET /api/gateway.php/{subdomain}/v1/employees/directory` (filter by status) | Basic auth |
| Time-off policies | CC1.4 | `GET /api/gateway.php/{subdomain}/v1/meta/time_off/types` | Basic auth |

**Auth:** `Authorization: Basic {base64(api_key:x)}`
**Rate limit:** 200 requests/minute.

---

## Gusto

**SOC 2 evidence provided:**

| Evidence | TSC | API Endpoint | Method |
|----------|-----|-------------|--------|
| Company employees count | CC1.4 | `GET /v1/companies/{company_id}/employees` | Bearer token (OAuth2) |
| Active benefits | CC1.4 | `GET /v1/companies/{company_id}/benefits` | Bearer token |

**Auth:** OAuth2 bearer token

---

## Rippling

**SOC 2 evidence provided:**

| Evidence | TSC | API Endpoint | Method |
|----------|-----|-------------|--------|
| Employee count | CC1.4 | `GET /platform/api/employees` | Bearer token |
| Active policies | CC1.4 | `GET /platform/api/policies` | Bearer token |
| Device management | CC6.8 | `GET /platform/api/devices` | Bearer token |

**Auth:** `Authorization: Bearer {RIPPLING_API_TOKEN}`
