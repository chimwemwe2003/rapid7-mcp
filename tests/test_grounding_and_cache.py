"""Unit tests for Phase 2: Grounding, Cache Isolation, and Audit Scrubbing."""

import time
from rapid7_mcp.audit import scrub_sensitive_data
from rapid7_mcp.cache import (
    get_cached_telemetry,
    invalidate_session_cache,
    set_cached_telemetry,
)
from rapid7_mcp.grounding import enforce_grounded_message, verify_grounding


def test_audit_scrub_sensitive_credentials():
    payload = {
        "api_key": "secret-rapid7-user-key-12345",
        "X-Api-Key": "another-secret-token",
        "query": "where(user = 'admin')",
        "nested": {"password": "super-secret-password", "records": 10},
    }
    scrubbed = scrub_sensitive_data(payload)
    assert scrubbed["api_key"] == "[REDACTED]"
    assert scrubbed["X-Api-Key"] == "[REDACTED]"
    assert scrubbed["nested"]["password"] == "[REDACTED]"
    assert scrubbed["query"] == "where(user = 'admin')"
    assert scrubbed["nested"]["records"] == 10


def test_cache_user_isolation():
    user_a = "session_user_alice_123"
    user_b = "session_user_bob_456"
    client = "NAPSA"
    endpoint = "/idr/v2/investigations"
    params = {"size": 5}

    # Store for Alice
    set_cached_telemetry(user_a, client, endpoint, params, {"data": ["alert1", "alert2"]})

    # Bob must NOT see Alice's data
    assert get_cached_telemetry(user_b, client, endpoint, params) is None

    # Alice gets her cached data
    alice_data = get_cached_telemetry(user_a, client, endpoint, params)
    assert alice_data == {"data": ["alert1", "alert2"]}

    # Invalidate Alice's cache
    invalidate_session_cache(user_a)
    assert get_cached_telemetry(user_a, client, endpoint, params) is None


def test_cache_ttl_expiration():
    session = "session_temp_test"
    set_cached_telemetry(session, "NAPSA", "/test", {}, {"val": 42})
    # Immediate fetch succeeds
    assert get_cached_telemetry(session, "NAPSA", "/test", {}, ttl_seconds=0.1) == {"val": 42}
    time.sleep(0.15)
    # Post-TTL fetch expires and returns None
    assert get_cached_telemetry(session, "NAPSA", "/test", {}, ttl_seconds=0.1) is None


def test_grounding_verification_flags_hallucinated_cve_and_metrics():
    # Tool output contains only CVE-2026-1111 and count 5
    tool_payload = [{"cve": "CVE-2026-1111", "count": 5, "asset": "DC01"}]

    # Answer claims CVE-2026-9999 and count 476,361 (which are fabricated/hallucinated)
    hallucinated_msg = "Found critical CVE-2026-9999 with 476,361 vulnerable hosts."
    is_grounded, ungrounded = verify_grounding(hallucinated_msg, tool_payload)

    assert is_grounded is False
    assert "CVE-2026-9999" in ungrounded or "476,361" in ungrounded

    enforced = enforce_grounded_message(hallucinated_msg, tool_payload, "list_vulnerabilities")
    assert "Grounding Verification" in enforced


def test_grounding_verification_passes_corroborated_data():
    tool_payload = [{"name": "Chikwa", "score": 98, "cve": "CVE-2026-1111"}]
    truthful_msg = "I inspected Chikwa with risk score 98 and CVE-2026-1111."
    is_grounded, ungrounded = verify_grounding(truthful_msg, tool_payload)
    assert is_grounded is True
    assert len(ungrounded) == 0
