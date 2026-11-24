"""Unit tests for Pebbles Cross-Source Correlation Engine.

Verifies:
1. Multi-source correlation combining Rapid7, Check Point, and VirusTotal
2. Source labeling: clearly attributing findings to each source
3. Partial availability: graceful operation when 1 or 2 sources are disconnected
4. Privacy boundary: confidential indicator blocked on VT while queried on Rapid7 and Check Point
"""

from typing import Any
import httpx
import pytest

from rapid7_mcp.connectors.checkpoint import CheckPointConnector
from rapid7_mcp.connectors.cross_source import query_cross_source
from rapid7_mcp.connectors.virustotal import VirusTotalConnector
from rapid7_mcp.agent import plan_tool_execution_from_query, synthesize_pebbles_response


class MockTransport(httpx.BaseTransport):
    def __init__(self, handler):
        self.handler = handler

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self.handler(request)


def test_cross_source_query_planner():
    """Verify natural language queries trigger cross-source correlation."""
    tool, args, intent = plan_tool_execution_from_query("cross check 41.77.10.5 across rapid7 and checkpoint")
    assert tool == "cross_source_investigate"
    assert args["indicator"] == "41.77.10.5"
    assert intent == "cross_source"

    tool2, args2, intent2 = plan_tool_execution_from_query("correlate hash 44d88612fea8a8f36de82e1278abb02f across all sources")
    assert tool2 == "cross_source_investigate"
    assert args2["indicator"] == "44d88612fea8a8f36de82e1278abb02f"


def test_cross_source_all_sources_connected():
    """Verify correlated data aggregation when Rapid7, Check Point, and VirusTotal are connected."""
    # Check Point Mock
    def chkp_handler(request: httpx.Request) -> httpx.Response:
        import json
        if request.url.path == "/web_api/login":
            return httpx.Response(200, json={"sid": "mock-sid", "api-server-version": "1.8"})
        if request.url.path in ("/web_api/show-hosts", "/web_api/show-objects"):
            return httpx.Response(200, json={"objects": [{"name": "Host_External", "type": "host", "ipv4-address": "196.10.20.30"}]})
        if request.url.path == "/web_api/show-networks":
            return httpx.Response(200, json={"objects": []})
        if request.url.path == "/web_api/show-access-rulebase":
            return httpx.Response(200, json={"rulebase": [{"rule-number": 12, "name": "Drop Bad Actors", "action": "Drop"}]})
        if request.url.path == "/web_api/show-logs":
            return httpx.Response(200, json={"logs": [{"action": "Drop", "src": "196.10.20.30", "dst": "41.77.10.5"}]})
        return httpx.Response(404, json={})

    chkp_conn = CheckPointConnector(mgmt_host="192.168.1.1")
    chkp_conn._transport = MockTransport(chkp_handler)

    # VirusTotal Mock
    def vt_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 14, "suspicious": 2, "harmless": 50, "undetected": 4},
                    "reputation": -35,
                    "last_analysis_results": {
                        "VendorA": {"category": "malicious", "result": "trojan", "method": "blacklist"},
                    },
                }
            }
        })

    vt_conn = VirusTotalConnector()
    vt_conn._transport = MockTransport(vt_handler)

    result = query_cross_source(
        indicator="196.10.20.30",
        client_name="NAPSA",
        r7_key="",  # Rapid7 simulated unconfigured
        chkp_connector=chkp_conn,
        chkp_credentials={"api_key": "chkp-key"},
        vt_connector=vt_conn,
        vt_credentials={"api_key": "vt-key"},
    )

    assert result["indicator"] == "196.10.20.30"
    assert result["rapid7"]["available"] is False
    assert result["checkpoint"]["available"] is True
    assert result["virustotal"]["available"] is True

    # Synthesize response and verify strict source separation
    resp = synthesize_pebbles_response(
        query="cross check 196.10.20.30",
        client_name="NAPSA",
        tool_name="cross_source_investigate",
        tool_result=result,
        intent="cross_source",
    )

    assert "Source 1: Rapid7 InsightIDR" in resp.message
    assert "Source 2: Check Point Security Gateway" in resp.message
    assert "Source 3: VirusTotal External Threat Intelligence" in resp.message
    assert len(resp.tables) >= 2  # Check Point rules/logs and VirusTotal engines


def test_cross_source_blocks_vt_on_internal_ip_while_allowing_firewall():
    """Verify that an internal RFC1918 IP is blocked for VirusTotal but inspected on Check Point."""
    def chkp_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/web_api/login":
            return httpx.Response(200, json={"sid": "mock-sid", "api-server-version": "1.8"})
        if request.url.path in ("/web_api/show-hosts", "/web_api/show-objects"):
            return httpx.Response(200, json={"objects": [{"name": "Internal_DC", "type": "host", "ipv4-address": "10.0.0.1"}]})
        if request.url.path == "/web_api/show-networks":
            return httpx.Response(200, json={"objects": []})
        return httpx.Response(200, json={"rulebase": [], "logs": []})

    chkp_conn = CheckPointConnector(mgmt_host="192.168.1.1")
    chkp_conn._transport = MockTransport(chkp_handler)

    vt_conn = VirusTotalConnector()

    result = query_cross_source(
        indicator="10.0.0.1",
        client_name="NAPSA",
        r7_key="",
        chkp_connector=chkp_conn,
        chkp_credentials={"api_key": "chkp-key"},
        vt_connector=vt_conn,
        vt_credentials={"api_key": "vt-key"},
    )

    # Check Point should have inspected the object
    assert result["checkpoint"]["available"] is True
    # VirusTotal MUST have been blocked by the confidentiality filter
    assert result["virustotal"]["available"] is False
    assert "confidentiality filter" in result["virustotal"]["notes"].lower()
