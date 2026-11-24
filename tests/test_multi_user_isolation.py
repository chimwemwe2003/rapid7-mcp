"""Test session isolation and security between multiple SOC analysts."""

from rapid7_mcp.cache import (
    clear_all_caches,
    get_cached_telemetry,
    invalidate_session_cache,
    set_cached_telemetry,
)


def test_multi_user_session_cache_isolation():
    clear_all_caches()

    session_a = "user_mwewa_session_001"
    session_b = "user_chikwa_session_002"

    query = "show open investigations"
    params = {"region": "us"}

    payload_a = {
        "message": "Session A telemetry for NAPSA",
        "metrics": [{"label": "Alerts", "value": 5, "delta": None}],
        "tables": [],
        "charts": [],
        "sources": [],
    }

    payload_b = {
        "message": "Session B telemetry for ZNBS",
        "metrics": [{"label": "Alerts", "value": 12, "delta": None}],
        "tables": [],
        "charts": [],
        "sources": [],
    }

    # Store cache for both sessions
    set_cached_telemetry(session_a, "NAPSA", query, params, payload_a)
    set_cached_telemetry(session_b, "ZNBS", query, params, payload_b)

    # Verify session A sees only A's data
    res_a = get_cached_telemetry(session_a, "NAPSA", query, params)
    assert res_a is not None
    assert res_a["message"] == "Session A telemetry for NAPSA"
    assert res_a["metrics"][0]["value"] == 5

    # Verify session B sees only B's data
    res_b = get_cached_telemetry(session_b, "ZNBS", query, params)
    assert res_b is not None
    assert res_b["message"] == "Session B telemetry for ZNBS"
    assert res_b["metrics"][0]["value"] == 12

    # Invalidate session A only
    invalidate_session_cache(session_a)
    assert get_cached_telemetry(session_a, "NAPSA", query, params) is None
    # Session B should still be intact
    assert get_cached_telemetry(session_b, "ZNBS", query, params) is not None
