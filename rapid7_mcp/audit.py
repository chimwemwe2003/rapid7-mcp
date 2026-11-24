"""Audit logging for Pebbles SOC Assistant.

Logs all security inquiries, tools called, parameters, result sizes, and latencies.
Strictly redacts API keys, credentials, and authentication tokens.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
AUDIT_LOG_FILE = LOG_DIR / "pebbles_audit.log"

logger = logging.getLogger("pebbles_audit")
logger.setLevel(logging.INFO)

# Setup rotating/append file handler if not already present
if not logger.handlers:
    file_handler = logging.FileHandler(AUDIT_LOG_FILE, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s - %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

# Regex to scrub sensitive headers/keys across Rapid7, Check Point, and VirusTotal
SENSITIVE_KEY_REGEX = re.compile(
    r"(?i)(api[_-]?key|token|password|secret[_-]?key|secret|access[_-]?key|client[_-]?id|client[_-]?secret|authorization|bearer|x-api-key|x-apikey|x-chkp-sid|sid|api-key)[\"':\s=]+([a-zA-Z0-9_\-\.]{6,})"
)


def scrub_sensitive_data(data: Any) -> Any:
    """Recursively scrub sensitive keys and credentials from data structures."""
    if isinstance(data, dict):
        scrubbed = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(
                s in k_lower
                for s in [
                    "api_key",
                    "apikey",
                    "api-key",
                    "token",
                    "password",
                    "secret",
                    "secret_key",
                    "secretkey",
                    "access_key",
                    "accesskey",
                    "client_id",
                    "clientid",
                    "client_secret",
                    "auth",
                    "bearer",
                    "x-api-key",
                    "x-apikey",
                    "x-chkp-sid",
                    "sid",
                ]
            ):
                scrubbed[k] = "[REDACTED]"
            else:
                scrubbed[k] = scrub_sensitive_data(v)
        return scrubbed
    elif isinstance(data, list):
        return [scrub_sensitive_data(item) for item in data]
    elif isinstance(data, str):
        return SENSITIVE_KEY_REGEX.sub(r"\1=[REDACTED]", data)
    return data


def log_soc_request(
    session_id: str = "",
    client_context: str = "NAPSA",
    question: str = "",
    tools_called: list[str] | None = None,
    endpoints: list[str] | None = None,
    parameters: list[dict[str, Any]] | None = None,
    result_count: int = 0,
    latency_ms: int = 0,
    error: str | None = None,
    client_name: str | None = None,
    query: str | None = None,
    **kwargs: Any,
) -> None:
    """Write an audit entry for a SOC intelligence turn."""
    context = client_name or client_context or "NAPSA"
    user_query = query or question or ""
    tools = tools_called or []
    ends = endpoints or []
    params = parameters or []

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id[:8] if session_id else "anonymous",
        "client_context": context,
        "question": user_query,
        "tools_called": tools,
        "endpoints": ends,
        "parameters": [scrub_sensitive_data(p) for p in params],
        "result_count": result_count,
        "latency_ms": latency_ms,
        "status": "ERROR" if error else "SUCCESS",
        "error": error,
    }
    logger.info(json.dumps(entry))


def log_outbound_lookup(
    session_id: str = "",
    user: str = "analyst",
    client_name: str = "NAPSA",
    indicator_type: str = "",
    indicator: str = "",
    status: str = "ALLOWED",  # ALLOWED | BLOCKED | NOT_FOUND | ERROR
    reason: str = "",
    destination: str = "VirusTotal",
) -> None:
    """Audit-log every outbound threat intelligence lookup. Never records secrets."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "OUTBOUND_INTEL_LOOKUP",
        "session_id": session_id[:8] if session_id else "anonymous",
        "user": user,
        "client_name": client_name,
        "destination": destination,
        "indicator_type": indicator_type,
        "indicator": indicator,
        "status": status,
        "reason": reason,
    }
    logger.info(json.dumps(entry))
