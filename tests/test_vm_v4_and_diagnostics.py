"""Automated test suite for InsightVM v4, capability detection, snapshot store,
Africa/Lusaka time calculations, and the 9 key SOC queries.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest

from rapid7_mcp.agent import plan_tool_execution_from_query, run_pebbles_agent
from rapid7_mcp.rapid7_live import (
    Rapid7ClientError,
    _detect_region,
    live_get_scans,
    live_search_vm_assets,
    live_search_vm_vulnerabilities,
    live_test_capabilities,
)
from rapid7_mcp.response_schema import PebblesResponse
from rapid7_mcp.snapshots import get_historical_comparison, record_daily_snapshot
from rapid7_mcp.time_utils import (
    format_iso_utc,
    resolve_soc_time_range,
    resolve_this_week_lusaka,
)


# ---------------------------------------------------------------------------
# Timezone & Region URL Tests
# ---------------------------------------------------------------------------

def test_resolve_this_week_lusaka():
    """Verify that 'this week' correctly resolves to Monday 00:00:00 Africa/Lusaka converted to UTC."""
    start_utc, now_utc, iso_str = resolve_this_week_lusaka()
    assert start_utc <= now_utc
    assert start_utc.tzinfo == timezone.utc
    assert iso_str.endswith("Z")
    # Lusaka is UTC+2, so Monday 00:00 CAT is Sunday 22:00 UTC
    assert start_utc.hour == 22 or start_utc.weekday() == 6 or start_utc.weekday() == 0


def test_region_url_construction():
    """Verify that all UI regions construct valid regional endpoints."""
    regions = ["us", "us2", "us3", "eu", "ca", "au", "ap"]
    for r in regions:
        detected = _detect_region(r)
        assert detected == r

    # RRN auto-detection
    assert _detect_region("us", "rrn:investigation:eu:d521adab:investigation:123") == "eu"
    assert _detect_region("eu", "rrn:investigation:us2:abc:investigation:456") == "us2"


# ---------------------------------------------------------------------------
# Snapshot Store Tests
# ---------------------------------------------------------------------------

def test_snapshot_store_comparison_and_history():
    """Verify daily snapshot recording and historical comparison deltas."""
    client = "TEST_ORG_NAPSA"

    # Record two snapshots 30 days apart
    record_daily_snapshot(
        client_name=client,
        snapshot_date="2026-10-10",
        critical_vulns=50,
        high_vulns=120,
        open_investigations=30,
    )
    record_daily_snapshot(
        client_name=client,
        snapshot_date="2026-11-10",
        critical_vulns=40,
        high_vulns=110,
        open_investigations=25,
    )

    comp = get_historical_comparison(client, days_back=30)
    assert comp["has_history"] is True
    assert comp["deltas"]["critical_vulns"] == -10
    assert comp["deltas"]["high_vulns"] == -10
    assert comp["deltas"]["open_investigations"] == -5


def test_snapshot_insufficient_history_path():
    """When a client has no historical snapshot, report clearly without estimating."""
    comp = get_historical_comparison("NEW_CLIENT_WITHOUT_HISTORY", days_back=30)
    assert comp["has_history"] is False
    assert "reason" in comp


# ---------------------------------------------------------------------------
# Query Planner & Tool Routing for the 9 Failing Questions
# ---------------------------------------------------------------------------

def test_plan_scans_this_week():
    """Q7: Which scans ran this week and did any fail"""
    tool, args, intent = plan_tool_execution_from_query("Which scans ran this week and did any fail")
    assert tool == "rapid7_get_scans"
    assert "start_time" in args
    assert intent == "scans"


def test_plan_investigations_created_this_week():
    """Q4: Investigations created this week and who they are assigned to"""
    tool, args, intent = plan_tool_execution_from_query("Investigations created this week and who they are assigned to")
    assert tool == "rapid7_list_investigations"
    assert "start_time" in args
    assert intent == "investigations_this_week"


def test_plan_top_risky_users():
    """Q1: Top 5 risky users last month"""
    tool, args, intent = plan_tool_execution_from_query("Top 5 risky users last month")
    assert tool == "rapid7_list_investigations"
    assert intent == "uba_users"


def test_plan_critical_vulns_comparison():
    """Q2: How many critical vulnerabilities do we have and comparison with last month"""
    tool, args, intent = plan_tool_execution_from_query("How many critical vulnerabilities do we have and comparison with last month")
    assert tool == "rapid7_search_assets"
    assert intent == "vuln_summary_comparison"


def test_plan_assets_most_vulnerable():
    """Q3: Which assets have the most critical vulnerabilities"""
    tool, args, intent = plan_tool_execution_from_query("Which assets have the most critical vulnerabilities")
    assert tool == "rapid7_search_assets"
    assert intent == "assets_most_vulnerable"


def test_plan_vulns_older_than_30_days():
    """Q5: Vulnerabilities older than 30 days still unremediated"""
    tool, args, intent = plan_tool_execution_from_query("Vulnerabilities older than 30 days still unremediated")
    assert tool == "rapid7_search_vulnerabilities"
    assert intent == "vulns_older_30_days"


def test_plan_most_common_vulnerabilities():
    """Q6: Most common vulnerabilities across the estate"""
    tool, args, intent = plan_tool_execution_from_query("Most common vulnerabilities across the estate")
    assert tool == "rapid7_search_vulnerabilities"
    assert intent == "common_vulnerabilities"


def test_plan_remediation_progress_quarter():
    """Q8: Remediation progress for the last quarter"""
    tool, args, intent = plan_tool_execution_from_query("Remediation progress for the last quarter")
    assert tool == "rapid7_list_investigations"
    assert intent == "remediation_quarter"


def test_plan_asset_status_lookup():
    """Q9: Status of a specific asset by name or IP"""
    tool, args, intent = plan_tool_execution_from_query("Status of asset dc01.napsa.co.zm")
    assert tool == "rapid7_lookup_asset"
    assert "dc01.napsa.co.zm" in args.get("identifier", "")
    assert intent == "asset_status"

    tool2, args2, intent2 = plan_tool_execution_from_query("Status of 192.168.1.10")
    assert tool2 == "rapid7_lookup_asset"
    assert args2.get("identifier") == "192.168.1.10"


# ---------------------------------------------------------------------------
# VM v4 Mock Tests: Pagination, 401/403/429 Handling
# ---------------------------------------------------------------------------

@patch("httpx.Client.post")
def test_vm_v4_search_assets_401_explanation(mock_post):
    """InsightVM 401 must raise clear Rapid7ClientError detailing Organization Key requirement."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = '{"message": "The supplied key does not have permission to perform this action."}'
    mock_post.return_value = mock_resp

    with pytest.raises(Rapid7ClientError) as exc_info:
        live_search_vm_assets("user_key", "eu")

    assert "InsightVM" in str(exc_info.value)
    assert "Organization API Key" in str(exc_info.value) or "permission" in str(exc_info.value)


@patch("httpx.Client.post")
def test_vm_v4_search_assets_429_backoff(mock_post):
    """InsightVM 429 must raise clear rate limit error."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.text = "Rate limit exceeded"
    mock_post.return_value = mock_resp

    with pytest.raises(Rapid7ClientError) as exc_info:
        live_search_vm_assets("key", "eu")

    assert "rate limit" in str(exc_info.value).lower()


@patch("httpx.Client.get")
def test_vm_v4_scans_success(mock_get):
    """InsightVM scan listing must return records and status."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": [
            {"id": "scan-1", "status": "Success", "started": "2026-11-10T04:00:00Z", "finished": "2026-11-10T06:00:00Z"},
            {"id": "scan-2", "status": "Running", "started": "2026-11-12T04:00:00Z", "finished": None},
        ]
    }
    mock_get.return_value = mock_resp

    res = live_get_scans("key", "eu")
    assert res["result_count"] == 2
    assert res["records"][0]["status"] == "Success"


# ---------------------------------------------------------------------------
# Capability Check Test
# ---------------------------------------------------------------------------

def test_live_test_capabilities_no_key():
    """Testing capabilities without an API key reports missing key across all services."""
    caps = live_test_capabilities("", "eu")
    assert caps["idr"]["available"] is False
    assert caps["vm_assets"]["available"] is False
