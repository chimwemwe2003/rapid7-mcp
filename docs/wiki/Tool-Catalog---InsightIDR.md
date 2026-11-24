# Tool Catalog - InsightIDR

This page covers InsightIDR investigation and log-hunting tools.

## Investigations

### `list_investigations`

**Use case:** Triage open incidents by priority and optionally restrict results to an ISO 8601
creation-time range with `start_date` and `end_date`. The API receives these as Rapid7
`start_time` and `end_time` ISO 8601 values. This differs from `query_logs`, which uses Unix
epoch milliseconds.

**Prompts:**

- "List OPEN investigations and prioritize CRITICAL/HIGH first."
- "Show current investigations and tell me which one should be handled first."
- "List investigations created between 2024-01-01T00:00:00Z and 2024-02-01T00:00:00Z."

### `get_monthly_report_data`

**Use case:** Build a month-specific SOC summary with investigation counts by priority,
malicious investigation totals, the 10 most frequent alert detection labels, and the 10 most
frequently represented targeted users.

Provide `year` and `month` (1-12). The report retrieves all investigation statuses and pages
through the full result set. Detection rule labels use rule-name fields when returned by Rapid7,
falling back to the alert type; targeted-user rankings include user fields available in the
investigation and alert responses.

### `get_investigation`

**Use case:** Deep-dive a single incident timeline.

**Prompts:**

- "Get investigation [id] and summarize timeline, alerts, and likely root cause."
- "For investigation [id], what should an analyst do in the next 30 minutes?"

## Log Search

### `query_logs`

**Use case:** Hunt IoCs and suspicious activity with LEQL.

**Prompts:**

- "Query logs for destination_ip 185.220.101.1 in the last 24h and summarize hits by source host."
- "Search logs for repeated failed SSH activity and identify top offending IPs."

## Threat Intelligence

### `list_indicators`

**Use case:** Pull known-bad IoCs from active feeds.

**Prompts:**

- "List IOC indicators of type DOMAIN and summarize notable threats."
- "Show active IP_ADDRESS indicators and suggest how to validate exposure in logs."

## Suggested chaining flow

1. `list_investigations` → 2. `get_investigation` → 3. `list_indicators` → 4. `query_logs`
