"""Safe, user-scoped in-memory cache for Rapid7 telemetry.

Guarantees:
1. Two different users or sessions NEVER share cache entries.
2. Cache keys explicitly bind user session ID, client context (NAPSA/ZNBS), endpoint, and parameters.
3. Enforces a strict, short TTL (default: 120 seconds).
4. Provides explicit invalidate/refresh controls.
"""

import hashlib
import json
import time
from typing import Any

# Global store partitioned strictly by session_id: {session_id: {cache_key: (timestamp, data)}}
_SESSION_CACHE: dict[str, dict[str, tuple[float, Any]]] = {}
DEFAULT_TTL_SECONDS = 120.0


def _build_cache_key(client_context: str, endpoint: str, parameters: dict[str, Any]) -> str:
    """Deterministic hash of request parameters."""
    normalized_params = json.dumps(parameters, sort_keys=True)
    raw_str = f"{client_context}:{endpoint}:{normalized_params}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


def get_cached_telemetry(
    session_id: str,
    client_context: str,
    endpoint: str,
    parameters: dict[str, Any],
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
) -> Any | None:
    """Retrieve cached data only if it belongs to this exact user session and hasn't expired."""
    if not session_id:
        return None

    user_bucket = _SESSION_CACHE.get(session_id)
    if not user_bucket:
        return None

    key = _build_cache_key(client_context, endpoint, parameters)
    entry = user_bucket.get(key)
    if not entry:
        return None

    timestamp, cached_data = entry
    if time.time() - timestamp > ttl_seconds:
        # Expired
        del user_bucket[key]
        return None

    return cached_data


def set_cached_telemetry(
    session_id: str,
    client_context: str,
    endpoint: str,
    parameters: dict[str, Any],
    data: Any,
) -> None:
    """Store data strictly inside this user session's isolated cache bucket."""
    if not session_id:
        return

    if session_id not in _SESSION_CACHE:
        _SESSION_CACHE[session_id] = {}

    key = _build_cache_key(client_context, endpoint, parameters)
    _SESSION_CACHE[session_id][key] = (time.time(), data)


def invalidate_session_cache(session_id: str) -> None:
    """Purge all cached data for a specific user session (Refresh control or Disconnect)."""
    if session_id in _SESSION_CACHE:
        del _SESSION_CACHE[session_id]


def clear_all_caches() -> None:
    """Purge all cached sessions (used for test teardowns or server restarts)."""
    _SESSION_CACHE.clear()

