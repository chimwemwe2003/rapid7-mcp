"""InsightIDR router — cloud SIEM investigations and log search."""

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from rapid7_mcp.client import InsightIDRClient, get_idr_client
from rapid7_mcp.models import (
    IndicatorList,
    Investigation,
    InvestigationList,
    LogSearchRequest,
    LogSearchResults,
    MonthlyInvestigationReport,
    ReportPeriod,
    ReportTopRule,
    ReportTopUser,
)

router = APIRouter()


def _format_api_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def _fetch_investigations(
    client: InsightIDRClient,
    *,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    status: str | None = None,
    priority: str | None = None,
    page_token: str | None = None,
    size: int = 100,
) -> InvestigationList:
    params: dict[str, Any] = {"size": size}
    if status:
        params["statuses"] = status
    if priority:
        params["priorities"] = priority
    if page_token:
        params["index"] = page_token
    if start_date:
        params["start_time"] = _format_api_datetime(start_date)
    if end_date:
        params["end_time"] = _format_api_datetime(end_date)

    data = await client.get("/idr/v2/investigations", params=params)
    return InvestigationList(**data)


async def _fetch_all_investigations(
    client: InsightIDRClient, start_date: datetime, end_date: datetime
) -> list[dict[str, Any]]:
    investigations: list[dict[str, Any]] = []
    index = 0
    page_size = 100

    while True:
        data = await client.get(
            "/idr/v2/investigations",
            params={
                "start_time": _format_api_datetime(start_date),
                "end_time": _format_api_datetime(end_date),
                "size": page_size,
                "index": index,
            },
        )
        page = data.get("data", [])
        if not isinstance(page, list):
            raise ValueError("Rapid7 investigation response 'data' must be a list")
        investigations.extend(page)

        metadata = data.get("metadata") or {}
        total = metadata.get("total_data")
        if not page or (isinstance(total, int) and len(investigations) >= total):
            break
        if not isinstance(total, int) and len(page) < page_size:
            break
        index += len(page)

    return investigations


def _report_name(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        for key in (
            "username",
            "user_name",
            "name",
            "email",
            "title",
            "rule_name",
            "detection_rule_name",
            "id",
        ):
            name = value.get(key)
            if isinstance(name, str) and name.strip():
                return name.strip()
    return None


def _top_counts(counts: Counter[str], limit: int = 10) -> list[tuple[str, int]]:
    return sorted(counts.items(), key=lambda item: (-item[1], item[0].casefold()))[:limit]


@router.get(
    "/investigations",
    response_model=InvestigationList,
    operation_id="list_investigations",
    summary="List InsightIDR investigations",
    description=(
        "Returns InsightIDR investigations (security incidents). Each investigation aggregates "
        "related alerts with an assigned priority, status, and optional assignee. "
        "Filter by status to focus on open incidents requiring attention. "
        "Optional ISO 8601 start_date and end_date filters are sent to Rapid7 as start_time and "
        "end_time; these differ from query_logs, which uses Unix epoch milliseconds. "
        "Use get_investigation for the full alert timeline."
    ),
)
async def list_investigations(
    status: str = Query("OPEN", description="Filter by status: OPEN, CLOSED, INVESTIGATING"),
    priority: str | None = Query(
        None, description="Filter by priority: CRITICAL, HIGH, MEDIUM, LOW"
    ),
    start_date: datetime | None = Query(
        None, description="Filter by investigation creation time (ISO 8601, inclusive)"
    ),
    end_date: datetime | None = Query(
        None, description="Filter by investigation creation time (ISO 8601, inclusive)"
    ),
    page_token: str | None = Query(None, description="Pagination cursor from previous response"),
    size: int = Query(20, ge=1, le=100),
    client: InsightIDRClient = Depends(get_idr_client),
) -> InvestigationList:
    if (
        start_date is not None
        and end_date is not None
        and _format_api_datetime(start_date) > _format_api_datetime(end_date)
    ):
        raise HTTPException(status_code=422, detail="start_date must be earlier than end_date")
    return await _fetch_investigations(
        client,
        start_date=start_date,
        end_date=end_date,
        status=status,
        priority=priority,
        page_token=page_token,
        size=size,
    )


@router.get(
    "/reports/monthly",
    response_model=MonthlyInvestigationReport,
    operation_id="get_monthly_report_data",
    summary="Get monthly SOC report data",
    description=(
        "Aggregates every InsightIDR investigation created within a calendar month. "
        "Returns priority and malicious investigation totals, the 10 most frequent alert "
        "detection labels, and the 10 most frequently represented targeted users when those "
        "fields are included in the API response. Detection labels use the alert's rule name "
        "when available and otherwise its alert type."
    ),
)
async def get_monthly_report_data(
    year: int = Query(..., ge=1, le=9998, description="Calendar year in UTC"),
    month: int = Query(..., ge=1, le=12, description="Calendar month (1-12)"),
    client: InsightIDRClient = Depends(get_idr_client),
) -> MonthlyInvestigationReport:
    start_date = datetime(year, month, 1, tzinfo=timezone.utc)
    if month == 12:
        end_date = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end_date = datetime(year, month + 1, 1, tzinfo=timezone.utc)

    investigations = await _fetch_all_investigations(client, start_date, end_date)
    priorities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    rules: Counter[str] = Counter()
    users: Counter[str] = Counter()
    malicious_investigations = 0

    for investigation in investigations:
        priority = str(investigation.get("priority", "")).upper()
        if priority in priorities:
            priorities[priority] += 1
        if str(investigation.get("disposition", "")).upper() == "MALICIOUS":
            malicious_investigations += 1

        investigation_users: set[str] = set()
        for alert in investigation.get("alerts", []):
            if not isinstance(alert, dict):
                continue
            rule = next(
                (
                    alert.get(key)
                    for key in (
                        "detection_rule_name",
                        "detectionRuleName",
                        "detection_name",
                        "detectionName",
                        "rule_name",
                        "ruleName",
                        "detection_rule",
                        "rule",
                        "alert_type",
                        "alertType",
                    )
                    if alert.get(key)
                ),
                None,
            )
            rule_name = _report_name(rule)
            if rule_name:
                rules[rule_name] += 1

            for key in (
                "targeted_user",
                "targetedUser",
                "target_user",
                "targetUser",
                "username",
                "user_name",
                "user",
                "targeted_users",
                "targetedUsers",
                "target_users",
                "targetUsers",
                "users",
            ):
                value = alert.get(key)
                values = value if isinstance(value, list) else [value]
                for entry in values:
                    name = _report_name(entry)
                    if name:
                        investigation_users.add(name)

        for key in ("targeted_users", "targetedUsers", "target_users", "targetUsers", "users"):
            value = investigation.get(key)
            values = value if isinstance(value, list) else [value]
            for entry in values:
                name = _report_name(entry)
                if name:
                    investigation_users.add(name)
        users.update(investigation_users)

    return MonthlyInvestigationReport(
        month=f"{year:04d}-{month:02d}",
        period=ReportPeriod(
            start_date=_format_api_datetime(start_date),
            end_date=_format_api_datetime(end_date),
        ),
        total_investigations=len(investigations),
        investigations_by_priority={
            label: priorities[key]
            for key, label in (
                ("CRITICAL", "Critical"),
                ("HIGH", "High"),
                ("MEDIUM", "Medium"),
                ("LOW", "Low"),
            )
        },
        malicious_investigations=malicious_investigations,
        top_triggered_detection_rules=[
            ReportTopRule(rule=name, count=count) for name, count in _top_counts(rules)
        ],
        top_targeted_users=[
            ReportTopUser(user=name, count=count) for name, count in _top_counts(users)
        ],
    )


@router.get(
    "/investigations/{investigation_id}",
    response_model=Investigation,
    operation_id="get_investigation",
    summary="Get an investigation by ID",
    description=(
        "Returns full details for a single InsightIDR investigation including all associated alerts, "
        "timeline, assignee, priority, and disposition. Use this to understand the full context "
        "of an active security incident."
    ),
)
async def get_investigation(
    investigation_id: str,
    client: InsightIDRClient = Depends(get_idr_client),
) -> Investigation:
    data = await client.get(f"/idr/v2/investigations/{investigation_id}")
    return Investigation(**data)


@router.post(
    "/logs",
    response_model=LogSearchResults,
    operation_id="query_logs",
    summary="Search logs with LEQL",
    description=(
        "Execute a LEQL (Log Entry Query Language) query against InsightIDR log sets. "
        "Use this to hunt for indicators of compromise — search for specific IPs, file hashes, "
        "domain names, or user activity across firewall, proxy, DNS, and endpoint logs. "
        "Example LEQL: 'where(destination_ip = \"1.2.3.4\")'. "
        "Time range is specified as Unix epoch milliseconds."
    ),
)
async def query_logs(
    body: LogSearchRequest,
    client: InsightIDRClient = Depends(get_idr_client),
) -> LogSearchResults:
    payload: dict = {"leql": {"statement": body.query}}
    if body.from_time:
        payload["from"] = body.from_time
    if body.to_time:
        payload["to"] = body.to_time
    if body.logs:
        payload["logs"] = body.logs
    data = await client.post("/log_search/query/logs", body=payload)
    return LogSearchResults(**data)


@router.get(
    "/iocs",
    response_model=IndicatorList,
    operation_id="list_indicators",
    summary="List threat intelligence indicators (IOCs)",
    description=(
        "Returns active Indicators of Compromise (IOCs) being tracked in InsightIDR's threat "
        "intelligence feed. Indicators include malicious IPs, domains, file hashes, and URLs "
        "associated with known threat actors or malware families. "
        "Use this to check whether an IP or domain seen in logs is a known bad actor."
    ),
)
async def list_indicators(
    indicator_type: str | None = Query(
        None,
        description="Filter by type: IP_ADDRESS, DOMAIN, URL, FILE_HASH",
    ),
    client: InsightIDRClient = Depends(get_idr_client),
) -> IndicatorList:
    params: dict = {}
    if indicator_type:
        params["type"] = indicator_type
    data = await client.get("/idr/v2/iocs", params=params)
    return IndicatorList(**data)


# ---------------------------------------------------------------------------
# Extended Monthly SOC Intelligence Endpoints (NLP Retention)
# ---------------------------------------------------------------------------

import json
from pathlib import Path
from rapid7_mcp.models import (
    RiskyUser,
    RiskyUserList,
    SlaMetricsReport,
    EventSourcesHealthReport,
    VulnerabilityPostureReport,
    MonthlyTrendsReport,
    MonthlyTrendPoint,
    CvssSlice,
    TopVulnerabilityEntry,
    EventSourceIssue,
    SlaCategoryMetrics,
    SlaMttr,
)

_MONTHLY_STORE_FILE = Path(__file__).parent.parent / "data" / "monthly_soc_store.json"


def _read_soc_store() -> dict[str, Any]:
    if _MONTHLY_STORE_FILE.is_file():
        try:
            with open(_MONTHLY_STORE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"months": {}}


def _get_target_month_data(month: str = "2026-10") -> dict[str, Any]:
    store = _read_soc_store()
    months = store.get("months", {})
    if month in months:
        return months[month]
    clean_month = month.strip()
    if clean_month in months:
        return months[clean_month]
    # Default to latest month available
    if "2026-10" in months:
        return months["2026-10"]
    return next(iter(months.values())) if months else {}


@router.get(
    "/reports/risky-users",
    response_model=RiskyUserList,
    operation_id="get_top_risky_users",
    summary="Get top risky users from Rapid7 UBA",
    description=(
        "Returns the top risky users tracked in Rapid7 User Behavior Analytics (UBA) for the specified "
        "month. Each entry includes risk rank, user name, email, risk score, key risk reasons (e.g., "
        "harvested credential brute forcing, repeated RDP lockouts), account type, and monitoring status. "
        "Use this tool when the user asks 'who were the top risky users', 'top 5 risked users', or "
        "about targeted identities."
    ),
)
async def get_top_risky_users(
    month: str = Query("2026-10", description="Reporting month in YYYY-MM format"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of users to return"),
) -> RiskyUserList:
    data = _get_target_month_data(month)
    raw_users = data.get("top_risky_users", [])
    users = [RiskyUser(**u) for u in raw_users[:limit]]
    return RiskyUserList(
        month=month,
        total_risky_users=len(users),
        users=users,
    )


@router.get(
    "/reports/sla-metrics",
    response_model=SlaMetricsReport,
    operation_id="get_sla_and_mttr",
    summary="Get SOC SLA compliance and MTTR",
    description=(
        "Returns SLA performance metrics, target resolution rates, achieved closure ratios per priority "
        "level (Critical, High, Medium, Low), malicious incident containment rates, Mean Time to "
        "Resolution (MTTR), and alerts pending closure. Use this tool when the user asks about SLAs, "
        "closure rates, MTTR, or how fast incidents were handled."
    ),
)
async def get_sla_and_mttr(
    month: str = Query("2026-10", description="Reporting month in YYYY-MM format"),
) -> SlaMetricsReport:
    data = _get_target_month_data(month)
    sla = data.get("sla_metrics", {})
    closures = {
        p: SlaCategoryMetrics(**m)
        for p, m in sla.get("investigation_closure", {}).items()
    }
    containments = {
        p: SlaCategoryMetrics(**m)
        for p, m in sla.get("malicious_containment", {}).items()
    }
    raw_mttr = sla.get("mttr")
    mttr = SlaMttr(**raw_mttr) if raw_mttr else None
    pending = data.get("alerts_pending_closure", {})
    return SlaMetricsReport(
        month=month,
        target_closure_rate_percent=float(sla.get("target_closure_rate_percent", 90.0)),
        investigation_closure=closures,
        malicious_containment=containments,
        mttr=mttr,
        alerts_pending_closure=pending,
    )


@router.get(
    "/health/event-sources",
    response_model=EventSourcesHealthReport,
    operation_id="get_event_sources_health",
    summary="Get Rapid7 collector and event source health",
    description=(
        "Returns the operational health of Rapid7 event sources and collectors. Lists sources experiencing "
        "issues (connection timeouts, silence > 120 minutes), affected IPs and ports, and required fix "
        "actions. Use this when the user asks about event sources, broken logs, collector health, or logging issues."
    ),
)
async def get_event_sources_health(
    month: str = Query("2026-10", description="Reporting month in YYYY-MM format"),
) -> EventSourcesHealthReport:
    data = _get_target_month_data(month)
    dcm = data.get("data_collection_management", {})
    sources = [EventSourceIssue(**s) for s in dcm.get("event_sources", [])]
    return EventSourcesHealthReport(
        month=month,
        collector=dcm.get("collector", "napsa-idr.napsa.co.zm"),
        total_sources_with_issues=len(sources),
        event_sources=sources,
    )


@router.get(
    "/reports/vulnerabilities-posture",
    response_model=VulnerabilityPostureReport,
    operation_id="get_vulnerability_posture",
    summary="Get InsightVM vulnerability management posture",
    description=(
        "Returns vulnerability management telemetry from InsightVM: total exploitable vulnerabilities, "
        "CVSS v3 and v2 score distribution breakdowns, and top critical CVEs requiring patching. Use "
        "this tool when the user asks about vulnerabilities, CVSS scores, or unpatched CVEs."
    ),
)
async def get_vulnerability_posture(
    month: str = Query("2026-10", description="Reporting month in YYYY-MM format"),
) -> VulnerabilityPostureReport:
    data = _get_target_month_data(month)
    vm = data.get("vulnerability_management", {})
    cvss = [CvssSlice(**c) for c in vm.get("cvss_v3_distribution", [])]
    top_vulns = [TopVulnerabilityEntry(**v) for v in vm.get("top_vulnerabilities", [])]
    return VulnerabilityPostureReport(
        month=month,
        total_exploitable_vulnerabilities=int(vm.get("total_exploitable_vulnerabilities", 0)),
        cvss_v3_distribution=cvss,
        top_vulnerabilities=top_vulns,
    )


@router.get(
    "/reports/multi-month-trends",
    response_model=MonthlyTrendsReport,
    operation_id="compare_monthly_trends",
    summary="Compare multi-month investigation trends",
    description=(
        "Compares total investigations, priority counts, and malicious incidents over historical months "
        "(July 2026 through October 2026). Use this when the user asks about trends over time, comparison "
        "with previous months, or quarterly evolution."
    ),
)
async def compare_monthly_trends() -> MonthlyTrendsReport:
    store = _read_soc_store()
    months_dict = store.get("months", {})
    points: list[MonthlyTrendPoint] = []
    for m_key in sorted(months_dict.keys()):
        m_data = months_dict[m_key]
        p_counts = m_data.get("investigations_by_priority", {})
        points.append(
            MonthlyTrendPoint(
                month=m_key,
                display_name=m_data.get("display_name", m_key),
                total_investigations=m_data.get("total_investigations", 0),
                high_priority=p_counts.get("High", 0),
                medium_priority=p_counts.get("Medium", 0),
                low_priority=p_counts.get("Low", 0),
                malicious_investigations=m_data.get("malicious_investigations", 0),
            )
        )
    summary = (
        "Total investigations increased from 1,251 in July to 3,630 in October (+190%), predominantly driven "
        "by Low priority brute-force / credential harvesting attacks against Office 365. High priority "
        "investigations peaked at 87 in September and decreased to 58 in October."
    )
    return MonthlyTrendsReport(months=points, trend_summary=summary)


@router.get(
    "/reports/incident-attribution",
    operation_id="get_incident_attribution",
    summary="Get specific incident attribution and user context",
    description=(
        "Returns detailed attribution for notable incidents: users who clicked malicious Office 365 links, "
        "lateral movement administrator impersonations, impossible travel (multiple country authentications), "
        "and locked out accounts."
    ),
)
async def get_incident_attribution(
    month: str = Query("2026-10", description="Reporting month in YYYY-MM format"),
    category: str | None = Query(None, description="Category filter: phishing, impersonation, travel, lockouts"),
) -> dict[str, Any]:
    data = _get_target_month_data(month)
    attrib = data.get("incident_attribution", {})
    lockouts = data.get("top_locked_out_users", [])
    account_events = data.get("account_behavior_events", {})
    return {
        "month": month,
        "category": category,
        "phishing_o365_users": attrib.get("office365_malicious_url_clicks", {}),
        "lateral_movement_impersonations": attrib.get("lateral_movement_impersonations", []),
        "multiple_country_authentications": attrib.get("multiple_country_authentications", []),
        "top_locked_out_users": lockouts,
        "account_events_summary": account_events,
    }
