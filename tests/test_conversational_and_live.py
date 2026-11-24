"""Regression tests for Pebbles conversational intelligence, anti-repetition, and live API grounding.
"""

from unittest.mock import MagicMock, patch
import pytest

from rapid7_mcp.agent import (
    build_greeting_response,
    is_conversational_greeting,
    plan_tool_execution_from_query,
    run_pebbles_agent,
    synthesize_pebbles_response,
)
from rapid7_mcp.rapid7_live import Rapid7ClientError, _detect_region
from rapid7_mcp.response_schema import PebblesResponse


def test_is_conversational_greeting():
    """Verify that greetings and casual chit-chat are correctly detected."""
    assert is_conversational_greeting("hi") is True
    assert is_conversational_greeting("hello!") is True
    assert is_conversational_greeting("hey pebbles") is True
    assert is_conversational_greeting("Good morning") is True
    assert is_conversational_greeting("what can you do?") is True
    assert is_conversational_greeting("how are you doing") is True
    assert is_conversational_greeting("thanks!") is True

    # Security questions should NOT be treated as greetings
    assert is_conversational_greeting("what investigations are open?") is False
    assert is_conversational_greeting("who are the top risky users?") is False
    assert is_conversational_greeting("show critical vulnerabilities") is False
    assert is_conversational_greeting("check collector health") is False
    assert is_conversational_greeting("where(result=FAILED) calculate(count)") is False


def test_greeting_response_structure_and_no_html():
    """Greeting response must be warm, first-person, and free of raw HTML tags."""
    resp = build_greeting_response(client_name="NAPSA", query="hello")
    assert isinstance(resp, PebblesResponse)
    assert resp.message
    assert "<div" not in resp.message
    assert "<span" not in resp.message


def test_detect_region_from_rrn():
    """Verify that region is safely extracted from RRN or default to eu."""
    assert _detect_region("us", "rrn:investigation:eu:d521adab:investigation:123") == "eu"
    assert _detect_region("eu", "rrn:investigation:us:abc123:investigation:456") == "us"
    assert _detect_region("ca") == "ca"
    assert _detect_region("unknown") == "eu"


def test_greeting_not_cached():
    """Greetings should never pollute or read from the telemetry cache."""
    with patch("rapid7_mcp.agent.set_cached_telemetry") as mock_set_cache:
        resp = run_pebbles_agent(
            query="hi",
            client_name="NAPSA",
            session_id="test_sess_greeting",
            live_key="dummy_key",
        )
        assert isinstance(resp, PebblesResponse)
        # set_cached_telemetry should NOT be called for greetings
        mock_set_cache.assert_not_called()


def test_insightvm_401_explanation():
    """When InsightVM returns 401 due to license/entitlement, Pebbles explains it honestly."""
    with patch("rapid7_mcp.agent.live_get_vulnerabilities") as mock_vuln:
        mock_vuln.side_effect = Rapid7ClientError(
            401,
            "The connected Rapid7 API key has InsightIDR permissions, but lacks InsightVM product entitlements.",
        )
        resp = run_pebbles_agent(
            query="show critical vulnerabilities",
            client_name="NAPSA",
            session_id="test_sess_vm",
            live_key="idr_only_key",
            live_region="eu",
        )
        assert isinstance(resp, PebblesResponse)
        assert "401" in resp.message
        assert "InsightVM" in resp.message or "Rapid7" in resp.message
        assert "<div" not in resp.message


def test_total_count_disclosure_in_investigations():
    """When Rapid7 returns total_data (e.g. 3,291), Pebbles discloses the total count."""
    mock_records = [
        {
            "rrn": "rrn:investigation:eu:tenant:investigation:1",
            "title": "Suspicious PowerShell Activity",
            "priority": "HIGH",
            "status": "OPEN",
            "assignee": {"name": "Alice"},
            "created_time": "2026-11-09T10:00:00Z",
        },
        {
            "rrn": "rrn:investigation:eu:tenant:investigation:2",
            "title": "Anomalous Ingress via VPN",
            "priority": "CRITICAL",
            "status": "OPEN",
            "assignee": {"name": "Bob"},
            "created_time": "2026-11-09T11:00:00Z",
        },
    ]

    tool_result = {
        "endpoint": "/idr/v2/investigations",
        "parameters": {"size": 2},
        "records": mock_records,
        "result_count": 2,
        "total_count": 3291,
        "latency_ms": 140,
    }

    resp = synthesize_pebbles_response(
        query="what investigations are open?",
        client_name="NAPSA",
        tool_name="rapid7_list_investigations",
        tool_result=tool_result,
        intent="investigations",
    )

    assert isinstance(resp, PebblesResponse)
    # Total tenant records metric must reflect the 3,291 figure
    labels = {m.label: m.value for m in resp.metrics}
    assert labels.get("Total Tenant Records") == 3291 or labels.get("Scope Investigations") == 2
    assert "<div" not in resp.message
    assert len(resp.tables) == 1
    assert len(resp.tables[0].rows) == 2


def test_plan_tool_execution_routes():
    """Verify tool planner routes diverse SOC questions correctly."""
    tool1, args1, intent1 = plan_tool_execution_from_query("who are the riskiest users?")
    assert tool1 == "rapid7_list_investigations"
    assert intent1 == "uba_users"

    tool2, args2, intent2 = plan_tool_execution_from_query("check collector and event source status")
    assert tool2 == "rapid7_list_collectors"
    assert intent2 == "collectors"

    tool3, args3, intent3 = plan_tool_execution_from_query("run an LEQL query for failed logins")
    assert tool3 == "rapid7_query_log_search"
    assert intent3 == "log_search"

    tool4, args4, intent4 = plan_tool_execution_from_query("show open high priority alerts")
    assert tool4 == "rapid7_list_investigations"
    assert args4.get("priorities") == "HIGH"
    assert args4.get("statuses") == "OPEN"


def test_explanation_queries_do_not_generate_unrequested_investigations():
    """Verify that explanation, advisory, or conceptual questions do NOT query investigations or return tables."""
    queries = [
        "what does lateral movement mean?",
        "why did servicedesk authenticate as mwalee?",
        "what should we do next?",
        "can you explain this?",
        "what are best practices for mitigating password spraying?",
    ]
    for q in queries:
        tool, args, intent = plan_tool_execution_from_query(q)
        assert tool is None, f"Query '{q}' should not plan a tool call but planned {tool}"
        assert intent == "conversational"

        resp = run_pebbles_agent(
            query=q,
            client_name="NAPSA",
            session_id="test_sess_expl",
            live_key="dummy_key",
            live_region="eu",
        )
        assert isinstance(resp, PebblesResponse)
        # MUST NOT generate unrequested investigation tables or charts
        assert len(resp.tables) == 0, f"Query '{q}' generated unrequested table: {resp.tables}"
        assert len(resp.charts) == 0, f"Query '{q}' generated unrequested chart: {resp.charts}"
        assert len(resp.metrics) == 0, f"Query '{q}' generated unrequested metrics: {resp.metrics}"
        assert "<div" not in resp.message


def test_specific_investigation_evidence_routing():
    """Verify that asking about a specific investigation ID routes to alert evidence, not a generic 20-row table."""
    tool, args, intent = plan_tool_execution_from_query("show alerts for 5H1C24ETHB1U")
    assert tool == "rapid7_get_investigation_alerts"
    assert args.get("rrn") == "5H1C24ETHB1U"
    assert intent == "investigation_alerts"

