"""Unit tests for Pebbles VirusTotal API v3 Threat Intelligence Connector.

Verifies:
1. Outbound data filter (RFC1918, CGNAT, loopback, internal domains, emails, usernames)
2. No-write guarantee (strictly no upload/submit/comment actions)
3. Rate limiter and daily quota enforcement
4. In-memory privacy-preserving indicator cache
5. Honest reporting semantics (0 detections != clean, not found != clean)
6. Secret scrubber for VT API keys
"""

import httpx
import pytest

from rapid7_mcp.audit import scrub_sensitive_data
from rapid7_mcp.connectors.virustotal import (
    OutboundDataFilter,
    OutboundFilterError,
    VirusTotalClientError,
    VirusTotalConnector,
    encode_vt_url_id,
)


class MockTransport(httpx.BaseTransport):
    """Mock HTTP transport for simulating VirusTotal API v3 responses."""

    def __init__(self, handler):
        self.handler = handler

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self.handler(request)


def test_outbound_data_filter_blocks_sensitive_indicators():
    """Verify that private IPs, CGNAT, internal domains, emails, and usernames are blocked."""
    filter_engine = OutboundDataFilter(internal_domains=["napsa.co.zm", "znbs.co.zm"])

    # RFC1918 Private IPs
    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("192.168.1.100")
    assert "RFC1918" in exc.value.reason or "internal" in str(exc.value).lower()

    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("10.50.2.1")
    assert "RFC1918" in exc.value.reason or "internal" in str(exc.value).lower()

    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("172.16.5.9")
    assert "RFC1918" in exc.value.reason or "internal" in str(exc.value).lower()

    # CGNAT 100.64.0.0/10
    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("100.64.10.20")
    assert "CGNAT" in exc.value.reason or "cgnat" in str(exc.value).lower()

    # Loopback
    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("127.0.0.1")
    assert "LOOPBACK" in exc.value.reason or "loopback" in str(exc.value).lower()

    # Link-local & Multicast
    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("169.254.1.1")
    assert "LINK_LOCAL" in exc.value.reason or "link-local" in str(exc.value).lower()

    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("224.0.0.1")
    assert "MULTICAST" in exc.value.reason or "multicast" in str(exc.value).lower()

    # Internal domains
    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("portal.napsa.co.zm")
    assert "INTERNAL_DOMAIN" in exc.value.reason or "internal" in str(exc.value).lower()

    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("dc01.znbs.co.zm")
    assert "INTERNAL_DOMAIN" in exc.value.reason or "internal" in str(exc.value).lower()

    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("server01.local")
    assert "INTERNAL_DOMAIN" in exc.value.reason or "internal" in str(exc.value).lower()

    # Email addresses
    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("analyst@napsa.co.zm")
    assert "EMAIL" in exc.value.reason or "email" in str(exc.value).lower()

    # Internal URLs
    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("http://intranet.napsa.co.zm/payroll")
    assert "URL_INTERNAL_DOMAIN" in exc.value.reason or "internal domain" in str(exc.value).lower()

    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("http://192.168.1.1/admin")
    assert "URL_INTERNAL_HOST" in exc.value.reason or "internal ip" in str(exc.value).lower()

    # Usernames / non-indicators
    with pytest.raises(OutboundFilterError) as exc:
        filter_engine.validate_indicator("john_doe")
    assert "LOCAL_HOSTNAME" in exc.value.reason or "INVALID_INDICATOR" in exc.value.reason or "internal" in str(exc.value).lower()


def test_outbound_data_filter_allows_valid_public_indicators():
    """Verify that public IPs, public domains, hashes, and public URLs pass validation."""
    filter_engine = OutboundDataFilter(internal_domains=["napsa.co.zm", "znbs.co.zm"])

    assert filter_engine.validate_indicator("8.8.8.8") == ("ip", "8.8.8.8")
    assert filter_engine.validate_indicator("1.1.1.1") == ("ip", "1.1.1.1")
    assert filter_engine.validate_indicator("github.com") == ("domain", "github.com")
    assert filter_engine.validate_indicator("44d88612fea8a8f36de82e1278abb02f") == ("file", "44d88612fea8a8f36de82e1278abb02f")
    assert filter_engine.validate_indicator("https://malicious-site.evil.com/payload") == ("url", "https://malicious-site.evil.com/payload")


def test_virustotal_no_write_guarantee():
    """Verify the connector explicitly forbids mutating tools (upload, submit, comment)."""
    connector = VirusTotalConnector()
    creds = {"api_key": "dummy-vt-key"}

    forbidden_tools = [
        "vt_upload_file",
        "vt_submit_url",
        "vt_post_comment",
        "vt_rescan_file",
    ]

    for tool in forbidden_tools:
        with pytest.raises(VirusTotalClientError) as exc:
            connector.execute_tool(tool, {}, creds)
        assert exc.value.status_code == 403
        assert "no-write guarantee" in exc.value.message.lower()


def test_virustotal_url_encoding():
    """Verify URL identifier is base64 URL-safe without padding '=' per VT v3 specification."""
    url = "https://example.com/test?param=1"
    encoded = encode_vt_url_id(url)
    assert "=" not in encoded
    # Must decode back cleanly
    import base64
    padded = encoded + "=" * (-len(encoded) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode()).decode()
    assert decoded == url


def test_virustotal_quota_and_rate_limiting():
    """Verify daily quota tracker stops queries before API exhaustion."""
    connector = VirusTotalConnector(api_tier="public", daily_quota=2)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5},
                    "reputation": 10,
                }
            }
        })

    connector._transport = MockTransport(mock_handler)
    creds = {"api_key": "dummy-vt-key"}

    # Query 1: allowed
    res1 = connector.lookup_indicator("8.8.8.8", creds)
    assert res1["found"] is True

    # Query 2: allowed
    res2 = connector.lookup_indicator("1.1.1.1", creds)
    assert res2["found"] is True

    # Query 3: quota exhausted (limit exceeded)
    with pytest.raises(VirusTotalClientError) as exc:
        connector.lookup_indicator("9.9.9.9", creds)
    assert exc.value.status_code == 429
    assert "daily quota" in exc.value.message.lower() or "exhausted" in exc.value.message.lower()


def test_virustotal_cache_privacy():
    """Verify cached indicator entries do not store keys or client names."""
    connector = VirusTotalConnector()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10},
                    "reputation": -20,
                    "last_analysis_results": {},
                }
            }
        })

    connector._transport = MockTransport(mock_handler)
    creds = {"api_key": "secret-super-key-vt-99"}

    res = connector.lookup_indicator("93.184.216.34", creds)
    cached = connector.cache.get("ip", "93.184.216.34")

    assert cached is not None
    # Ensure no API key or tenant credentials leaked into cache dict
    cache_dump = str(cached)
    assert "secret-super-key-vt-99" not in cache_dump
    assert "NAPSA" not in cache_dump


def test_virustotal_log_scrubber():
    """Verify VT API keys and Authorization headers are scrubbed."""
    raw_text = "VirusTotal call headers={'x-apikey': 'vt-super-secret-key-1234567890abcdef'}, status=200"
    scrubbed = scrub_sensitive_data(raw_text)
    assert "vt-super-secret-key-1234567890abcdef" not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_virustotal_verify_connection_dict_compatibility():
    """Verify verify_connection returns ConnectionStatus with dict-like .get() support."""
    connector = VirusTotalConnector()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"id": "8.8.8.8", "type": "ip_address", "attributes": {}}})

    connector._transport = MockTransport(mock_handler)
    status = connector.verify_connection({"api_key": "dummy-vt-key-12345678"})

    assert status.connected is True
    assert status.success is True
    assert status.get("success") is True
    assert status.get("connected") is True
    assert status.get("latency_ms") >= 0
    assert 0 <= status.get("daily_quota_remaining") <= 500
    assert "dumm" in status.get("masked_key")
    assert status.get("nonexistent", "fallback") == "fallback"


def test_virustotal_planner_routing_exact_question():
    """Verify 'What does VirusTotal say about starlabns.co.zm' routes to VT tool with exact domain."""
    from rapid7_mcp.agent import plan_tool_execution_from_query

    tool, args, intent = plan_tool_execution_from_query("What does VirusTotal say about starlabns.co.zm")
    assert tool == "vt_lookup_indicator"
    assert args.get("indicator") == "starlabns.co.zm"
    assert intent == "vt_reputation"


def test_virustotal_starlabns_404_no_hallucinations():
    """Verify 404 response for starlabns.co.zm contains no invented EDR, ZNBS, or containment plan."""
    from rapid7_mcp.agent import synthesize_pebbles_response

    tool_result = {
        "indicator": "starlabns.co.zm",
        "indicator_type": "domain",
        "found": False,
        "status": "NOT_FOUND",
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 0,
        "total_engines": 0,
        "reputation": 0,
        "last_analysis_date": "N/A",
    }

    resp = synthesize_pebbles_response(
        query="What does VirusTotal say about starlabns.co.zm",
        client_name="NAPSA",
        tool_name="vt_lookup_indicator",
        tool_result=tool_result,
        intent="vt_reputation",
    )

    msg = resp.message
    # Strictly says no record
    assert "VirusTotal has no record of domain `starlabns.co.zm`" in msg or "no record" in msg.lower()
    # Zero fabrication or cross-client leakage
    assert "EDR" not in msg
    assert "ZNBS" not in msg
    assert "we've been tracking" not in msg.lower()
    assert "containment" not in msg.lower()
    assert "phishing" not in msg.lower()
    assert "malware" not in msg.lower()


def test_virustotal_pronoun_rejection():
    """Verify pronouns like 'it' or 'that' are rejected and never sent as indicators."""
    from rapid7_mcp.connectors.virustotal import OutboundDataFilter, OutboundFilterError

    ofilter = OutboundDataFilter()
    with pytest.raises(OutboundFilterError) as exc_info:
        ofilter.classify_indicator("it")
    assert exc_info.value.error_code == "PRONOUN_INDICATOR"


