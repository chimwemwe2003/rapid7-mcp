"""Unit tests for Pebbles SOC Agent."""

import pytest
from rapid7_mcp.agent import (
    plan_tool_execution_from_query,
    run_pebbles_agent,
    synthesize_pebbles_response,
)
from rapid7_mcp.response_schema import PebblesResponse


def test_query_planner_routing():
    # Collectors
    tool, args, intent = plan_tool_execution_from_query("Which event sources or collectors currently have issues?")
    assert tool == "rapid7_list_collectors"
    assert intent == "collectors"

    # Vulnerabilities
    tool, args, intent = plan_tool_execution_from_query("Show critical exploitable vulnerabilities by CVSS score")
    assert tool == "rapid7_list_vulnerabilities"
    assert args.get("severity") == "Critical"
    assert intent == "vulnerabilities"

    # LEQL Log Search
    tool, args, intent = plan_tool_execution_from_query("Show LEQL queries for failed logins")
    assert tool == "rapid7_query_log_search"
    assert "FAILED" in args["query"]
    assert intent == "log_search"

    # Assets
    tool, args, intent = plan_tool_execution_from_query("Which domain controllers are registered as assets?")
    assert tool == "rapid7_list_assets"
    assert intent == "assets"

    # Risky Users / UBA
    tool, args, intent = plan_tool_execution_from_query("Who were the top 5 risked users last month?")
    assert tool == "rapid7_list_investigations"
    assert intent == "uba_users"

    # SLA Compliance
    tool, args, intent = plan_tool_execution_from_query("Did we meet our SLAs for High and Medium priority?")
    assert tool == "rapid7_list_investigations"
    assert intent == "sla_compliance"

    # Investigations (default)
    tool, args, intent = plan_tool_execution_from_query("Show High priority open alerts")
    assert tool == "rapid7_list_investigations"
    assert args["priorities"] == "HIGH"
    assert args["statuses"] == "OPEN"
    assert intent == "investigations"


def test_greeting_response():
    resp = run_pebbles_agent(
        query="hi",
        client_name="NAPSA",
        session_id="test_sess_greet",
        live_key="",
        live_region="us",
    )
    assert isinstance(resp, PebblesResponse)
    assert "Pebbles" in resp.message or "NAPSA" in resp.message


def test_unauthenticated_agent_request():
    resp = run_pebbles_agent(
        query="Who were the top 5 risked users last month?",
        client_name="NAPSA",
        session_id="test_sess_anon",
        live_key="",
        live_region="us",
    )
    assert isinstance(resp, PebblesResponse)
    assert "don't have a verified Rapid7 API key" in resp.message
    assert "NAPSA" in resp.message


def test_synthesize_pebbles_response_no_html():
    tool_result = {
        "endpoint": "/idr/v2/investigations",
        "parameters": {"size": 2},
        "records": [
            {
                "id": "inv-001",
                "title": "Suspicious PowerShell Execution",
                "priority": "HIGH",
                "status": "OPEN",
                "assignee": {"name": "Mulenga Mwewa"},
            },
            {
                "id": "inv-002",
                "title": "Multiple Failed Logins",
                "priority": "MEDIUM",
                "status": "CLOSED",
                "assignee": {"name": "Chikwa Luputa"},
            },
        ],
        "result_count": 2,
        "latency_ms": 120,
    }

    resp = synthesize_pebbles_response("Show investigations", "NAPSA", "rapid7_list_investigations", tool_result)
    assert isinstance(resp, PebblesResponse)
    assert "<div" not in resp.message
    assert "<style" not in resp.message
    assert "NAPSA" in resp.message
    assert "I checked live InsightIDR telemetry" in resp.message
    assert len(resp.tables) == 1
    assert len(resp.tables[0].rows) == 2
    assert len(resp.sources) == 1
    assert resp.sources[0].tool_name == "rapid7_list_investigations"


def test_synthesize_pebbles_response_with_null_assignee_and_empty_fields():
    # Simulates genuine Rapid7 telemetry where assignee is null and fields are missing
    tool_result = {
        "endpoint": "/idr/v2/investigations",
        "parameters": {"size": 2},
        "records": [
            {
                "id": "inv-null-001",
                "title": None,
                "priority": None,
                "status": None,
                "assignee": None,  # Rapid7 returns null when unassigned
            },
            {
                "id": "inv-null-002",
                "title": "Alert Without Assignee Object",
                "priority": "HIGH",
                "status": "OPEN",
                # assignee key completely absent
            },
        ],
        "result_count": 2,
        "latency_ms": 80,
    }

    resp = synthesize_pebbles_response("what investigations are open?", "NAPSA", "rapid7_list_investigations", tool_result)
    assert isinstance(resp, PebblesResponse)
    assert resp.tables[0].rows[0]["Assignee"] == "Unassigned"
    assert resp.tables[0].rows[1]["Assignee"] == "Unassigned"
    assert resp.metrics[0].value == 2

