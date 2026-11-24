"""SOC Evaluation Suite: 30 Real-World Natural Language Queries.

Tests query understanding, tool planning, parameter extraction, time range
resolution, and persona fidelity across all SOC operational domains.
"""

from datetime import datetime, timezone
import pytest
from rapid7_mcp.agent import (
    plan_tool_execution_from_query,
    run_pebbles_agent,
    synthesize_pebbles_response,
)
from rapid7_mcp.response_schema import PebblesResponse
from rapid7_mcp.time_utils import resolve_soc_time_range


SOC_EVAL_QUERIES = [
    # Category 1: Investigations & Alerts Triage
    ("Show all open investigations for NAPSA", "rapid7_list_investigations", {"statuses": "OPEN"}),
    ("Which critical alerts are currently open?", "rapid7_list_investigations", {"priorities": "CRITICAL", "statuses": "OPEN"}),
    ("Show high priority investigations from last month", "rapid7_list_investigations", {"priorities": "HIGH"}),
    ("List closed investigations over the past 7 days", "rapid7_list_investigations", {"statuses": "CLOSED"}),
    ("Show unassigned alerts requiring triage", "rapid7_list_investigations", {}),
    ("Compare investigations by priority", "rapid7_list_investigations", {}),

    # Category 2: User Behavior Analytics (UBA) & Identity Risk
    ("Who were the top 5 risked users last month?", "rapid7_list_investigations", {}),
    ("Show suspicious login activity attributed to users", "rapid7_list_investigations", {}),
    ("Which accounts have active security investigations?", "rapid7_list_investigations", {}),
    ("Identify users associated with High priority alerts", "rapid7_list_investigations", {"priorities": "HIGH"}),

    # Category 3: Collectors, Event Sources & Health
    ("Which event sources currently have issues?", "rapid7_list_collectors", {}),
    ("Are all event collectors currently active and healthy?", "rapid7_list_collectors", {}),
    ("Check status of the NAPSA collector host", "rapid7_list_collectors", {}),
    ("Show offline collector nodes", "rapid7_list_collectors", {}),
    ("Verify version and hostnames of event sources", "rapid7_list_collectors", {}),

    # Category 4: InsightVM Vulnerabilities & Exploit Posture
    ("Show exploitable vulnerabilities by CVSS score", "rapid7_list_vulnerabilities", {}),
    ("Which critical vulnerabilities need immediate patching?", "rapid7_list_vulnerabilities", {"severity": "Critical"}),
    ("List severe vulnerabilities across the organization", "rapid7_list_vulnerabilities", {"severity": "Severe"}),
    ("Are there any known exploit CVEs open?", "rapid7_list_vulnerabilities", {}),
    ("Review vulnerability backlog and remediation status", "rapid7_list_vulnerabilities", {}),

    # Category 5: Endpoints, Domain Controllers & Assets
    ("Which domain controllers are registered as assets?", "rapid7_list_assets", {"search_term": "dc"}),
    ("Find assets running outdated server operating systems", "rapid7_list_assets", {}),
    ("Show all discovered endpoints in ZNBS infrastructure", "rapid7_list_assets", {}),
    ("List IP addresses and hostnames in the asset ledger", "rapid7_list_assets", {}),

    # Category 6: LEQL Log Search & Threat Hunting
    ("Show LEQL queries and threat intelligence hunting", "rapid7_query_log_search", {}),
    ("Search logs for failed login attempts in the past 24 hours", "rapid7_query_log_search", {"time_range": "LAST_24_HOURS"}),
    ("Run an LEQL query to find brute force spikes", "rapid7_query_log_search", {}),
    ("Query authentication event logs for anomalous activity", "rapid7_query_log_search", {}),

    # Category 7: SLA Compliance & Posture Reviews
    ("Did we meet our SLAs for High and Medium priority?", "rapid7_list_investigations", {}),
    ("Summarize overall security posture for executive review", "rapid7_list_investigations", {}),
]


@pytest.mark.parametrize("query,expected_tool,expected_arg_subset", SOC_EVAL_QUERIES)
def test_soc_evaluation_plan_routing(query, expected_tool, expected_arg_subset):
    tool, args, *_ = plan_tool_execution_from_query(query)
    assert tool == expected_tool, f"Query '{query}' routed to {tool}, expected {expected_tool}"
    for k, v in expected_arg_subset.items():
        assert args.get(k) == v, f"Query '{query}' expected arg {k}={v}, got {args.get(k)}"


def test_time_range_resolution():
    fixed_now = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)

    # 24 hours
    s, e, kw = resolve_soc_time_range("past 24 hours", now=fixed_now)
    assert kw == "LAST_24_HOURS"
    assert (e - s).total_seconds() == 86400

    # 7 days
    s, e, kw = resolve_soc_time_range("past 7 days", now=fixed_now)
    assert kw == "LAST_7_DAYS"
    assert (e - s).days == 7

    # Last month
    s, e, kw = resolve_soc_time_range("last month", now=fixed_now)
    assert kw == "LAST_30_DAYS"
    assert s.month == 10
    assert s.day == 1


def test_pebbles_response_grounding_and_first_person_tone():
    sample_records = [
        {"name": "NAPSA-Collector-01", "status": "ACTIVE", "version": "3.1.2", "host_name": "napsa-col01.zm"},
        {"name": "NAPSA-Collector-02", "status": "OFFLINE", "version": "3.1.0", "host_name": "napsa-col02.zm"},
    ]
    tool_result = {
        "endpoint": "/idr/v2/collectors",
        "parameters": {},
        "records": sample_records,
        "result_count": 2,
        "latency_ms": 95,
    }

    resp = synthesize_pebbles_response(
        query="Check status of collectors",
        client_name="NAPSA",
        tool_name="rapid7_list_collectors",
        tool_result=tool_result,
    )

    assert "I checked the event collectors" in resp.message
    assert "NAPSA" in resp.message
    assert "2 collector(s)" in resp.message
    assert resp.metrics[0].value == 2
    assert resp.metrics[1].value == 1  # 1 active
    assert resp.metrics[2].value == 1  # 1 offline
