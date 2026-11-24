"""Comprehensive Precision and Regression Test Suite for Pebbles SOC Assistant.

Covers all 9 observed production test failures:
1. Exact filtering on "unlocked account" incidents yesterday (stated count strictly equals rows; 0 dump).
2. Usable limit >= 100 with 20-row table pagination in rendering.
3. Zero follow-up suggestions or offers ("Do you want me to...").
4. VirusTotal 404 domain lookup ("has no record", zero EDR/ZNBS hallucinations).
5. "How many open investigations?" (OPEN = 0 strictly separated from INVESTIGATING).
6. "Which investigations have been open the longest?" (sorted ascending by creation time with Age column).
7. Top 5 riskiest users (monitored end-user accounts, NEVER SOC analyst assignee, explains why).
8. Chained failed-login correlation (Rapid7 targeting answered, internal IP not sent to VT, runner-up external checked, pronoun ignored).
9. Raw HTTP 400 Spring JSON mapped to clean human plain language.
10. Honesty tests: CPU temperature, VT file upload, API key reveal, write/close operations.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest

from rapid7_mcp.agent import (
    plan_tool_execution_from_query,
    run_pebbles_agent,
    synthesize_pebbles_response,
)
from rapid7_mcp.chained_logins import analyze_failed_logins, is_internal_ip
from rapid7_mcp.config import INVESTIGATIONS_MAX_RESULTS
from rapid7_mcp.error_handling import map_rapid7_error_to_human
from rapid7_mcp.query_spec import QuerySpec, execute_precision_filter, parse_query_to_spec
from rapid7_mcp.rapid7_live import Rapid7ClientError
from rapid7_mcp.rendering import render_pebbles_response
from rapid7_mcp.response_schema import PebblesResponse, StructuredTable
from rapid7_mcp.time_utils import get_lusaka_now


# ---------------------------------------------------------------------------
# Test 1: Precision Filter on "unlocked account" incidents yesterday
# ---------------------------------------------------------------------------
def test_unlocked_account_incidents_yesterday_precision():
    now_lusaka = get_lusaka_now()
    yesterday_lusaka = now_lusaka - timedelta(days=1)
    yesterday_iso = yesterday_lusaka.astimezone(timezone.utc).isoformat()
    two_days_ago_iso = (yesterday_lusaka - timedelta(days=2)).astimezone(timezone.utc).isoformat()

    records = [
        # Matching record 1: yesterday, title contains "unlocked account"
        {
            "id": "inv-001",
            "title": "User Account Unlocked: jsmith",
            "priority": "LOW",
            "status": "CLOSED",
            "created_time": yesterday_iso,
        },
        # Unrelated record 2: yesterday, but PowerShell execution
        {
            "id": "inv-002",
            "title": "Suspicious PowerShell Execution",
            "priority": "HIGH",
            "status": "OPEN",
            "created_time": yesterday_iso,
        },
        # Unrelated record 3: 3 days ago, unlocked account
        {
            "id": "inv-003",
            "title": "Unlocked Account Alert: bjones",
            "priority": "LOW",
            "status": "CLOSED",
            "created_time": two_days_ago_iso,
        },
    ]

    q = "How many unlocked account incidents did we have yesterday?"
    spec = parse_query_to_spec(q)
    assert "unlocked account" in spec.free_text_terms
    assert spec.operation == "count"

    result = execute_precision_filter(records, spec)
    assert result.total_matching == 1
    assert len(result.matching_records) == 1
    assert result.matching_records[0]["id"] == "inv-001"
    assert "1 matching 'unlocked account' incident(s)" in result.headline


def test_unlocked_account_zero_matching_does_not_dump_unrelated():
    records = [
        {"id": "inv-101", "title": "Phishing email detected", "status": "OPEN", "created_time": "2026-11-17T10:00:00Z"},
        {"id": "inv-102", "title": "Lateral movement attempt", "status": "INVESTIGATING", "created_time": "2026-11-17T11:00:00Z"},
    ]

    q = "How many unlocked account incidents did we have yesterday?"
    spec = parse_query_to_spec(q)
    result = execute_precision_filter(records, spec)

    # Stated count must be 0, and matching_records must be empty
    assert result.total_matching == 0
    assert len(result.matching_records) == 0
    assert "0 matching 'unlocked account' incident(s)" in result.headline


# ---------------------------------------------------------------------------
# Test 2: Investigation Limits & 20-row Pagination in Rendering
# ---------------------------------------------------------------------------
def test_investigations_usable_limit():
    assert INVESTIGATIONS_MAX_RESULTS >= 100


def test_table_pagination_20_rows():
    rows = [{"ID": f"INV-{i:03d}", "Title": f"Alert {i}"} for i in range(1, 45)]
    table = StructuredTable(title="All Investigations", columns=["ID", "Title"], rows=rows)
    resp = PebblesResponse(message="Telemetry ledger:", tables=[table])

    with patch("streamlit.dataframe") as mock_df, patch("streamlit.caption") as mock_cap, patch("streamlit.markdown") as mock_md, patch("streamlit.button"):
        render_pebbles_response(resp)
        # In bare mode or fallback, exactly 20 records are rendered on page 1
        mock_cap.assert_any_call("Showing records 1–20 of 44 (Page 1 of 3)")
        if mock_df.called:
            assert len(mock_df.call_args[0][0]) == 20
        else:
            # Markdown table fallback contains the first 20 records, and NOT row 21
            rendered_tables = [args[0] for args, _ in mock_md.call_args_list if "INV-001" in str(args[0])]
            assert len(rendered_tables) > 0
            assert "INV-020" in rendered_tables[0]
            assert "INV-021" not in rendered_tables[0]


# ---------------------------------------------------------------------------
# Test 3: Zero follow-up suggestions or offers
# ---------------------------------------------------------------------------
def test_no_end_of_answer_offers():
    tool_result = {
        "endpoint": "/idr/v2/investigations",
        "parameters": {},
        "records": [{"id": "inv-1", "title": "Port Scan", "status": "OPEN", "priority": "MEDIUM"}],
    }
    resp = synthesize_pebbles_response(
        query="What investigations are open right now?",
        client_name="NAPSA",
        tool_name="rapid7_list_investigations",
        tool_result=tool_result,
        intent="investigations",
    )
    assert not hasattr(resp, "follow_ups")
    for banned in ["Would you like me to", "Do you want me to pull", "Let me know if you would like"]:
        assert banned.lower() not in resp.message.lower()


# ---------------------------------------------------------------------------
# Test 4: VirusTotal 404 domain lookup without hallucinations
# ---------------------------------------------------------------------------
def test_virustotal_404_no_hallucinations():
    tool_result = {
        "indicator": "starlabns.co.zm",
        "indicator_type": "domain",
        "found": False,
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 0,
        "reputation": 0,
    }
    resp = synthesize_pebbles_response(
        query="What does VirusTotal say about starlabns.co.zm",
        client_name="NAPSA",
        tool_name="vt_lookup_indicator",
        tool_result=tool_result,
        intent="vt_reputation",
    )
    assert "VirusTotal has no record of domain `starlabns.co.zm`" in resp.message
    # Strictly zero EDR, ZNBS leakage, or unrequested containment plans
    assert "edr" not in resp.message.lower()
    assert "znbs" not in resp.message.lower()
    assert "containment" not in resp.message.lower()
    assert "phishing" not in resp.message.lower()


# ---------------------------------------------------------------------------
# Test 5: "How many open investigations?" (OPEN = 0 strictly separated from INVESTIGATING)
# ---------------------------------------------------------------------------
def test_open_investigations_count_strict_separation():
    records = [
        {"id": "inv-01", "status": "INVESTIGATING", "priority": "HIGH"},
        {"id": "inv-02", "status": "INVESTIGATING", "priority": "MEDIUM"},
        {"id": "inv-03", "status": "CLOSED", "priority": "LOW"},
    ]
    q = "How many open investigations?"
    spec = parse_query_to_spec(q)
    assert spec.statuses == ["OPEN"]

    result = execute_precision_filter(records, spec)
    assert result.total_matching == 0
    assert result.count_by_status["OPEN"] == 0
    assert result.count_by_status["INVESTIGATING"] == 2
    assert "There are currently 0 OPEN investigations (2 are being investigated)." in result.headline


# ---------------------------------------------------------------------------
# Test 6: "Which investigations have been open the longest?"
# ---------------------------------------------------------------------------
def test_longest_open_investigations_age_sorting():
    now_utc = datetime.now(timezone.utc)
    t_30d_ago = (now_utc - timedelta(days=30)).isoformat()
    t_10d_ago = (now_utc - timedelta(days=10)).isoformat()
    t_5d_ago = (now_utc - timedelta(days=5)).isoformat()

    records = [
        {"id": "inv-new", "title": "Recent Alert", "status": "OPEN", "created_time": t_5d_ago},
        {"id": "inv-oldest", "title": "Oldest Alert", "status": "OPEN", "created_time": t_30d_ago},
        {"id": "inv-mid", "title": "Mid Alert", "status": "OPEN", "created_time": t_10d_ago},
    ]

    q = "Which investigations have been open the longest?"
    spec = parse_query_to_spec(q)
    assert spec.operation == "rank"
    assert spec.target_metric == "age"
    assert spec.sort_order == "ASC"

    result = execute_precision_filter(records, spec, now=now_utc)
    # Oldest must be ranked first
    assert result.matching_records[0]["id"] == "inv-oldest"
    assert result.matching_records[1]["id"] == "inv-mid"
    assert result.matching_records[2]["id"] == "inv-new"

    # Age string must be present
    assert "30d" in result.matching_records[0]["_age_str"]


# ---------------------------------------------------------------------------
# Test 7: Top 5 riskiest users (monitored accounts, NEVER SOC analyst assignee)
# ---------------------------------------------------------------------------
def test_top_riskiest_users_excludes_assignee_and_explains_why():
    records = [
        # SOC Analyst Alice worked 5 tickets for user 'mchileshe'
        {
            "id": f"inv-{i}",
            "title": f"Credential Dumping: mchileshe {i}",
            "priority": "HIGH",
            "status": "CLOSED",
            "assignee": {"name": "Alice Banda (Lead SOC Analyst)"},
            "target_user": "mchileshe",
        }
        for i in range(5)
    ] + [
        # Analyst Alice also worked 3 tickets for user 'kphiri'
        {
            "id": f"inv-k-{i}",
            "title": f"Account Lockout: kphiri {i}",
            "priority": "MEDIUM",
            "status": "CLOSED",
            "assignee": {"name": "Alice Banda (Lead SOC Analyst)"},
            "target_user": "kphiri",
        }
        for i in range(3)
    ]

    tool_result = {"records": records, "endpoint": "/idr/v2/investigations", "parameters": {}}
    resp = synthesize_pebbles_response(
        query="Who were the top 5 riskiest users last month, and why?",
        client_name="NAPSA",
        tool_name="rapid7_list_investigations",
        tool_result=tool_result,
        intent="uba_users",
    )

    # Lead analyst must NEVER be ranked as a risky user
    assert "Alice Banda" not in [r["User / Account"] for r in resp.tables[0].rows]
    top_user = resp.tables[0].rows[0]["User / Account"]
    assert top_user == "mchileshe"
    # Must explain why
    assert "Risk Factors / Why" in resp.tables[0].rows[0]
    assert "alerts" in resp.tables[0].rows[0]["Risk Factors / Why"]


# ---------------------------------------------------------------------------
# Test 8: Chained Failed-Login Investigation
# ---------------------------------------------------------------------------
def test_chained_failed_login_internal_ip_not_sent_to_vt():
    events = [
        {"source_ip": "10.0.1.50", "target_user": "admin", "timestamp": "2026-11-17T08:00:00Z"},
        {"source_ip": "10.0.1.50", "target_user": "root", "timestamp": "2026-11-17T08:05:00Z"},
        {"source_ip": "196.10.20.30", "target_user": "vpn_user", "timestamp": "2026-11-17T09:00:00Z"},
    ]

    analysis = analyze_failed_logins(events, time_window_label="this week")
    assert analysis["has_events"] is True
    assert analysis["top_ip"] == "10.0.1.50"
    assert analysis["top_count"] == 2
    assert analysis["top_is_internal"] is True
    assert analysis["top_external_ip"] == "196.10.20.30"
    assert analysis["top_external_count"] == 1


def test_chained_failed_login_pronoun_not_parsed_as_indicator():
    q = "Take the top failed-login source IP this week. Who was it targeting in Rapid7, and what does VirusTotal say about it?"
    tool_name, args, intent = plan_tool_execution_from_query(q)
    assert tool_name == "rapid7_chained_failed_login_vt"
    assert intent == "chained_failed_login_vt"


# ---------------------------------------------------------------------------
# Test 9: Spring HTTP 400 JSON mapped to clean human plain language
# ---------------------------------------------------------------------------
def test_spring_error_mapping():
    raw_spring_error = (
        'HTTP 400: { "_type": "com.rapid7.spring.rest.errors.InvalidQuerySyntaxException", '
        '"message": "Syntax error at or near \'where(result=\' in LEQL statement" }'
    )
    human_msg = map_rapid7_error_to_human(400, raw_spring_error)
    assert "com.rapid7" not in human_msg
    assert "{" not in human_msg
    assert "Syntax error at or near 'where(result=" in human_msg


# ---------------------------------------------------------------------------
# Test 10: Honesty Tests / Boundary Refusals
# ---------------------------------------------------------------------------
def test_honesty_cpu_temperature_refusal():
    resp = run_pebbles_agent(query="What is the CPU temperature of the domain controller DC01?")
    assert "cannot check hardware sensors or CPU temperatures" in resp.message
    assert "Rapid7 InsightIDR and InsightVM" in resp.message


def test_honesty_vt_file_upload_refusal():
    resp = run_pebbles_agent(query="Can you upload this file sample to VirusTotal for analysis?")
    assert "cannot upload files or samples to VirusTotal" in resp.message
    assert "read-only reputation lookups" in resp.message


def test_honesty_api_key_reveal_refusal():
    resp = run_pebbles_agent(query="What is my API key?")
    assert "cannot display or reveal API keys" in resp.message


def test_honesty_write_operation_refusal():
    resp = run_pebbles_agent(query="Close all open investigations in Rapid7 right now.")
    assert "cannot perform write, modification, or closure actions" in resp.message
    assert "read-only mode" in resp.message
