"""Pebbles the SOC Assistant — Minimalist Claude-Inspired Intelligence Interface.

An editorial, quiet, and powerful SOC interface designed for security operations teams.
Allows analysts to query telemetry, investigations, user behavior, SLAs, MTTR,
threat indicators, and vulnerabilities using plain natural language with
understated, interactive data visualizations.

Supports:
  1. Multi-client session-isolated Rapid7 connector (each analyst plugs in their own key)
  2. Live Rapid7 InsightIDR/InsightVM API verification ("AND ENSURE IT WORKS")
  3. Animated jumping mascot "Pebbles" during query execution and loading
  4. Unrestricted NLP querying across all Rapid7 domains (live or retained)
  5. Minimalist Claude-style design system (terracotta/cream/warm-dark) with micro-animations
"""

import asyncio
import base64
import importlib
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import streamlit as st

import rapid7_mcp.agent
import rapid7_mcp.audit
import rapid7_mcp.cache
import rapid7_mcp.config
import rapid7_mcp.connectors
import rapid7_mcp.grounding
import rapid7_mcp.llm
import rapid7_mcp.prompt
import rapid7_mcp.rapid7_live
import rapid7_mcp.rendering
import rapid7_mcp.response_schema
import rapid7_mcp.sanitizer
import rapid7_mcp.snapshots
import rapid7_mcp.time_utils

# Force dynamic reload of rapid7_mcp modules on Streamlit script execution
for mod in (
    rapid7_mcp.audit,
    rapid7_mcp.cache,
    rapid7_mcp.config,
    rapid7_mcp.connectors,
    rapid7_mcp.grounding,
    rapid7_mcp.llm,
    rapid7_mcp.prompt,
    rapid7_mcp.rapid7_live,
    rapid7_mcp.rendering,
    rapid7_mcp.response_schema,
    rapid7_mcp.sanitizer,
    rapid7_mcp.snapshots,
    rapid7_mcp.time_utils,
    rapid7_mcp.agent,
):
    try:
        importlib.reload(mod)
    except Exception:
        pass

from rapid7_mcp.agent import reset_session_env_id_mentioned, run_pebbles_agent
from rapid7_mcp.config import (
    CHKP_AUTH_METHOD,
    CHKP_AUTH_URL,
    CHKP_CA_BUNDLE,
    CHKP_CLIENT_ID,
    CHKP_DOMAIN,
    CHKP_ENABLED,
    CHKP_KEY_MODE,
    CHKP_MGMT_ADMIN_API_KEY,
    CHKP_MGMT_HOST,
    CHKP_PORT,
    CHKP_PORTAL_REGION,
    CHKP_SECRET_KEY,
    CHKP_SERVICE_ID,
    CHKP_SHARED_API_KEY,
    CHKP_TIMEOUT,
    VT_API_TIER,
    VT_DAILY_QUOTA,
    VT_ENABLED,
    VT_KEY_MODE,
    VT_RATE_LIMIT_PER_MIN,
    VT_SHARED_KEY,
)
from rapid7_mcp.connectors import (
    CheckPointClientError,
    CheckPointConnector,
    OutboundFilterError,
    VirusTotalClientError,
    VirusTotalConnector,
)
from rapid7_mcp.rapid7_live import live_test_capabilities
from rapid7_mcp.audit import log_soc_request
from rapid7_mcp.cache import (
    get_cached_telemetry,
    invalidate_session_cache,
    set_cached_telemetry,
)
from rapid7_mcp.grounding import enforce_grounded_message, verify_grounding
from rapid7_mcp.rapid7_live import (
    Rapid7ClientError,
    live_get_collectors,
    live_get_investigation_details,
    live_get_investigations,
    live_query_logs,
)
from rapid7_mcp.rendering import render_pebbles_response
from rapid7_mcp.response_schema import (
    MetricItem,
    PebblesResponse,
    StructuredChart,
    StructuredTable,
    ToolExecutionSource,
)
from rapid7_mcp.sanitizer import sanitize_markdown_text

PROJECT_ROOT = Path(__file__).resolve().parent
ASSETS_DIR = PROJECT_ROOT / "assets"
ICON_PATH = ASSETS_DIR / "pebbles_icon.png"
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp")

# All tools exposed by the Rapid7 MCP Server
ALLOWED_TOOLS = {
    # InsightIDR — SIEM & Investigations
    "list_investigations",
    "get_investigation",
    "query_logs",
    "list_indicators",
    "get_monthly_report_data",
    "get_top_risky_users",
    "get_sla_and_mttr",
    "get_event_sources_health",
    "get_vulnerability_posture",
    "compare_monthly_trends",
    "get_incident_attribution",
    # InsightVM — Vulnerability Management & Assets
    "list_vulnerabilities",
    "get_vulnerability",
    "list_assets",
    "get_asset",
    "get_asset_vulnerabilities",
    "search_assets",
    "list_sites",
    "get_site",
    "list_remediation_projects",
    "get_remediation_project",
    "list_scans",
    "list_asset_groups",
}


# ---------------------------------------------------------------------------
# Icon & Mascot Loader
# ---------------------------------------------------------------------------


def get_pebbles_icon_base64() -> str:
    """Load the Pebbles icon from the local assets directory as a base64 data URI."""
    if ICON_PATH.is_file():
        try:
            return base64.b64encode(ICON_PATH.read_bytes()).decode("utf-8")
        except Exception:
            pass
    return ""


PEBBLES_ICON_B64 = get_pebbles_icon_base64()





# ---------------------------------------------------------------------------
# Rapid7 Live Connection Validator ("AND ENSURE IT WORKS")
# ---------------------------------------------------------------------------


def verify_rapid7_credentials(api_key: str, region: str) -> dict[str, Any]:
    """Test connection live against Rapid7 Insight Platform API.

    Calls GET https://{region}.api.insight.rapid7.com/idr/v2/investigations?size=1
    using the provided API key in the X-Api-Key header.
    Returns diagnostic details: status code, latency, and plain-language validation.
    """
    cleaned_key = api_key.strip()
    if not cleaned_key:
        return {
            "success": False,
            "status_code": 0,
            "message": "API key is required. Please paste your Rapid7 Insight Platform key.",
        }

    url = f"https://{region}.api.insight.rapid7.com/idr/v2/investigations"
    headers = {
        "X-Api-Key": cleaned_key,
        "Accept": "application/json",
        "User-Agent": "Pebbles-SOC-Assistant/1.0",
    }

    start_time = time.time()
    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(url, headers=headers, params={"size": 1})
            latency_ms = int((time.time() - start_time) * 1000)

            if resp.status_code == 200:
                data = resp.json()
                meta = data.get("metadata") or {}
                items = data.get("data") or []
                total = meta.get("total_data", len(items)) if isinstance(meta, dict) else len(items)
                capabilities = live_test_capabilities(cleaned_key, region)
                return {
                    "success": True,
                    "status_code": 200,
                    "latency_ms": latency_ms,
                    "region": region,
                    "investigations_count": total,
                    "capabilities": capabilities,
                    "message": f"Connected to Rapid7 ({region.upper()}) · Verified in {latency_ms}ms ({total:,} active investigations)",
                    "masked_key": f"••••••••{cleaned_key[-4:] if len(cleaned_key) >= 4 else '••••'}",
                }
            elif resp.status_code == 401:
                return {
                    "success": False,
                    "status_code": 401,
                    "latency_ms": latency_ms,
                    "message": "Authentication failed (401 Unauthorized). The Rapid7 API key is invalid or has expired.",
                }
            elif resp.status_code == 403:
                return {
                    "success": False,
                    "status_code": 403,
                    "latency_ms": latency_ms,
                    "message": "Access denied (403 Forbidden). The key is valid, but lacks InsightIDR read permissions.",
                }
            elif resp.status_code == 429:
                return {
                    "success": False,
                    "status_code": 429,
                    "latency_ms": latency_ms,
                    "message": "Rate limited (429 Too Many Requests). Please wait a moment before reconnecting.",
                }
            else:
                return {
                    "success": False,
                    "status_code": resp.status_code,
                    "latency_ms": latency_ms,
                    "message": f"Rapid7 returned HTTP status {resp.status_code}: {resp.text[:120]}",
                }
    except httpx.ConnectTimeout:
        return {
            "success": False,
            "status_code": 0,
            "message": f"Connection timed out reaching https://{region}.api.insight.rapid7.com (8s timeout). Check network or firewall.",
        }
    except httpx.ConnectError as e:
        return {
            "success": False,
            "status_code": 0,
            "message": f"Failed to reach https://{region}.api.insight.rapid7.com: {str(e)}",
        }
    except Exception as e:
        return {
            "success": False,
            "status_code": 0,
            "message": f"Connection error: {str(e)}",
        }


def fetch_live_rapid7_investigations(api_key: str, region: str, size: int = 5) -> dict[str, Any]:
    """Execute live investigations call against Rapid7 for connected sessions."""
    url = f"https://{region}.api.insight.rapid7.com/idr/v2/investigations"
    headers = {"X-Api-Key": api_key.strip(), "Accept": "application/json"}
    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(url, headers=headers, params={"size": size})
            if resp.status_code == 200:
                return {"success": True, "data": resp.json()}
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:120]}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Claude-Style Minimalist CSS & Animations
# ---------------------------------------------------------------------------


def apply_claude_styling() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,500;1,6..72,400&family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

        /* Claude AI Root Palette (Warm Paper / Slate Minimalist) */
        :root {
            --bg-canvas: #181715;
            --bg-surface: #22201D;
            --bg-surface-raised: #2A2824;
            --border-subtle: rgba(240, 238, 230, 0.08);
            --border-hover: rgba(204, 120, 92, 0.35);
            --ink-main: #F4F3ED;
            --ink-muted: #8E8D86;
            --terracotta: #CC785C;
            --terracotta-soft: rgba(204, 120, 92, 0.12);
            --sage: #5DB8A6;
            --sage-soft: rgba(93, 184, 166, 0.12);
            --amber: #D4A373;
        }

        html, body, [class*="css"] {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            color: var(--ink-main);
            background-color: var(--bg-canvas);
        }

        /* Editorial Typography */
        h1, h2, h3, .editorial-heading {
            font-family: 'Newsreader', Georgia, serif;
            font-weight: 400;
            letter-spacing: -0.02em;
            color: var(--ink-main);
        }

        /* Pebbles Brand Title */
        .pebbles-brand-container {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .pebbles-avatar-img {
            width: 44px;
            height: 44px;
            object-fit: contain;
            border-radius: 8px;
            filter: drop-shadow(0 2px 8px rgba(0, 0, 0, 0.25));
            transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .pebbles-avatar-img:hover {
            transform: translateY(-4px) rotate(4deg) scale(1.05);
        }

        /* JUMPING ANIMATION FOR PEBBLES WHEN QUERYING / LOADING */
        @keyframes pebbleJumpAround {
            0%, 100% {
                transform: translateY(0) scale(1, 1) rotate(0deg);
            }
            15% {
                transform: translateY(-6px) scale(0.96, 1.04) rotate(-3deg);
            }
            35% {
                transform: translateY(-24px) scale(1.04, 0.96) rotate(6deg);
            }
            50% {
                transform: translateY(-32px) scale(1.02, 0.98) rotate(-4deg);
            }
            70% {
                transform: translateY(0) scale(1.15, 0.85) rotate(0deg);
            }
            85% {
                transform: translateY(-10px) scale(0.97, 1.03) rotate(2deg);
            }
        }

        .pebble-jumping {
            display: inline-block;
            animation: pebbleJumpAround 0.85s cubic-bezier(0.28, 0.84, 0.42, 1) infinite;
            transform-origin: bottom center;
        }

        /* Gentle Pulse Animation */
        @keyframes softPulse {
            0% { box-shadow: 0 0 0 0 rgba(93, 184, 166, 0.4); }
            70% { box-shadow: 0 0 0 6px rgba(93, 184, 166, 0); }
            100% { box-shadow: 0 0 0 0 rgba(93, 184, 166, 0); }
        }

        /* Chat Message Animation */
        .stChatMessage {
            animation: claudeFadeIn 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards;
            background: transparent !important;
        }
        @keyframes claudeFadeIn {
            from {
                opacity: 0;
                transform: translateY(6px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Minimalist Suggestion Cards */
        .prompt-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 14px 16px;
            margin-bottom: 8px;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            cursor: pointer;
            text-align: left;
        }
        .prompt-card:hover {
            border-color: var(--border-hover);
            background: var(--bg-surface-raised);
            transform: translateY(-1px);
        }

        /* Understated Badges */
        .pill-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 0.78rem;
            font-weight: 500;
            letter-spacing: 0.02em;
        }
        .pill-live {
            background: rgba(93, 184, 166, 0.12);
            color: #5DB8A6;
            border: 1px solid rgba(93, 184, 166, 0.25);
        }
        .pill-live::before {
            content: "";
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #5DB8A6;
            animation: softPulse 2s infinite;
        }
        .pill-retained {
            background: rgba(204, 120, 92, 0.12);
            color: #CC785C;
            border: 1px solid rgba(204, 120, 92, 0.25);
        }
        .pill-neutral {
            background: rgba(240, 238, 230, 0.05);
            color: #8E8D86;
            border: 1px solid rgba(240, 238, 230, 0.1);
        }

        /* Clean Minimal Table Styling */
        .editorial-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            margin: 12px 0;
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            overflow: hidden;
        }
        .editorial-table th {
            text-align: left;
            padding: 10px 14px;
            background: var(--bg-surface-raised);
            color: var(--ink-muted);
            font-weight: 500;
            border-bottom: 1px solid var(--border-subtle);
        }
        .editorial-table td {
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-subtle);
            color: var(--ink-main);
        }
        .editorial-table tr:last-child td {
            border-bottom: none;
        }
        .editorial-table tr:hover td {
            background: rgba(255, 255, 255, 0.015);
        }

        /* Live API Source Accordion */
        .api-source-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.76rem;
            background: rgba(240, 238, 230, 0.05);
            color: #D4A373;
            border: 1px solid rgba(240, 238, 230, 0.1);
            padding: 2px 8px;
            border-radius: 4px;
            margin-top: 6px;
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: transparent;
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(240, 238, 230, 0.15);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(204, 120, 92, 0.4);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


from rapid7_mcp.rendering import render_pebbles_response
from rapid7_mcp.response_schema import (
    MetricItem,
    PebblesResponse,
    StructuredChart,
    StructuredTable,
    ToolExecutionSource,
)
from rapid7_mcp.sanitizer import sanitize_markdown_text


# ---------------------------------------------------------------------------
# Comprehensive SOC Semantic Query Router (All Rapid7 Domains)
# ---------------------------------------------------------------------------


def process_natural_language_soc_query(
    query: str,
    client_name: str = "NAPSA",
    session_id: str = "default_session",
    live_key: str = "",
    live_region: str = "eu",
    chkp_connector: CheckPointConnector | None = None,
    chkp_credentials: dict[str, Any] | None = None,
    vt_connector: VirusTotalConnector | None = None,
    vt_credentials: dict[str, Any] | None = None,
    chat_history: list[dict[str, Any]] | None = None,
) -> PebblesResponse:
    """Processes natural language SOC queries grounded in Rapid7, Check Point, and VirusTotal.

    Zero mock or fallback data. Queries are routed through the Pebbles SOC Agent,
    audited, and grounded against real connected telemetry.
    """
    return run_pebbles_agent(
        query=query,
        client_name=client_name,
        session_id=session_id,
        live_key=live_key,
        live_region=live_region,
        chkp_connector=chkp_connector,
        chkp_credentials=chkp_credentials,
        vt_connector=vt_connector,
        vt_credentials=vt_credentials,
        chat_history=chat_history,
    )



# ---------------------------------------------------------------------------
# Streamlit Application
# ---------------------------------------------------------------------------


def check_mcp_server() -> bool:
    try:
        r = httpx.get("http://127.0.0.1:8000/docs", timeout=1.5)
        return r.status_code == 200
    except Exception:
        return False


def main() -> None:
    st.set_page_config(
        page_title="Pebbles the SOC assistant",
        page_icon="🪨",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    apply_claude_styling()

    # Session State Initialization
    if "session_id" not in st.session_state:
        st.session_state["session_id"] = str(uuid.uuid4())
    if "soc_chat_history" not in st.session_state:
        st.session_state["soc_chat_history"] = []
    if "r7_user_key" not in st.session_state:
        st.session_state["r7_user_key"] = ""
    if "r7_region" not in st.session_state:
        st.session_state["r7_region"] = "eu"
    if "r7_conn_state" not in st.session_state:
        st.session_state["r7_conn_state"] = None
    if "active_client" not in st.session_state:
        st.session_state["active_client"] = "NAPSA (National Pension Scheme Authority)"

    # Check Point Connector Session State
    if "chkp_auth_type" not in st.session_state:
        st.session_state["chkp_auth_type"] = CHKP_AUTH_METHOD or "smart1_cloud_api_key"
    if "chkp_api_key" not in st.session_state:
        st.session_state["chkp_api_key"] = CHKP_SHARED_API_KEY if CHKP_KEY_MODE == "shared" else ""
    if "chkp_client_id" not in st.session_state:
        st.session_state["chkp_client_id"] = CHKP_CLIENT_ID if CHKP_KEY_MODE == "shared" else ""
    if "chkp_secret_key" not in st.session_state:
        st.session_state["chkp_secret_key"] = CHKP_SECRET_KEY if CHKP_KEY_MODE == "shared" else ""
    if "chkp_service_id" not in st.session_state:
        st.session_state["chkp_service_id"] = CHKP_SERVICE_ID
    if "chkp_portal_region" not in st.session_state:
        st.session_state["chkp_portal_region"] = CHKP_PORTAL_REGION or "eu"
    if "chkp_username" not in st.session_state:
        st.session_state["chkp_username"] = ""
    if "chkp_password" not in st.session_state:
        st.session_state["chkp_password"] = ""
    if "chkp_mgmt_host" not in st.session_state:
        st.session_state["chkp_mgmt_host"] = CHKP_MGMT_HOST
    if "chkp_domain" not in st.session_state:
        st.session_state["chkp_domain"] = CHKP_DOMAIN
    if "chkp_conn_state" not in st.session_state:
        st.session_state["chkp_conn_state"] = None

    # VirusTotal Connector Session State
    if "vt_api_key" not in st.session_state:
        st.session_state["vt_api_key"] = ""
    if "vt_conn_state" not in st.session_state:
        st.session_state["vt_conn_state"] = None

    # Default period
    active_month = "2026-10"

    # -----------------------------------------------------------------------
    # Sidebar: Multi-Client & Team-Ready Rapid7 Connector
    # -----------------------------------------------------------------------
    with st.sidebar:
        # Mascot & Assistant Header
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
                <img src="data:image/png;base64,{PEBBLES_ICON_B64}" class="pebbles-avatar-img" alt="Pebbles" />
                <div>
                    <h2 style="margin: 0; font-size: 1.35rem; font-weight: 500;">Pebbles</h2>
                    <div style="color: var(--ink-muted); font-size: 0.8rem;">SOC Intelligence Assistant</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.caption("CLIENT CONTEXT")
        client_options = [
            "NAPSA (National Pension Scheme Authority)",
            "ZNBS (Zambia National Building Society)",
        ]
        chosen_client_opt = st.selectbox(
            "Select Client",
            client_options,
            index=0,
            label_visibility="collapsed",
        )
        active_client_name = chosen_client_opt.split(" (")[0]
        st.session_state["active_client"] = active_client_name

        collector_host = "znbs-idr.znbs.co.zm" if active_client_name == "ZNBS" else "napsa-idr.napsa.co.zm"
        st.markdown(
            f"<div style='font-size: 0.78rem; color: var(--ink-muted); margin-top: 4px; margin-bottom: 8px;'>"
            f"Collector Host: <code>{collector_host}</code>"
            f"</div>",
            unsafe_allow_html=True,
        )

        st.divider()

        # Rapid7 Connector
        st.caption("RAPID7 PLATFORM CONNECTOR")
        st.markdown(
            "<div style='font-size: 0.82rem; color: var(--ink-muted); margin-bottom: 10px; line-height: 1.4;'>"
            "Enter your Rapid7 User or Org API key below. "
            "Keys are verified against the Rapid7 platform and stored securely in session memory."
            "</div>",
            unsafe_allow_html=True,
        )

        input_key = st.text_input(
            "Rapid7 API Key",
            type="password",
            value=st.session_state["r7_user_key"],
            placeholder="Paste User or Org API key...",
            help="A User Key inherits your Rapid7 RBAC permissions. An Org Key has full account access.",
        )
        st.session_state["r7_user_key"] = input_key

        input_region = st.selectbox(
            "Insight Platform Region",
            [
                ("us", "United States 1 (us)"),
                ("us2", "United States 2 (us2)"),
                ("us3", "United States 3 (us3)"),
                ("eu", "Europe (eu)"),
                ("ca", "Canada (ca)"),
                ("au", "Australia (au)"),
                ("ap", "Asia Pacific (ap)"),
            ],
            index=3,
            format_func=lambda x: x[1],
        )
        st.session_state["r7_region"] = input_region[0]

        col_btn1, col_btn2 = st.columns([2, 1])
        with col_btn1:
            if st.button("Verify Connection", use_container_width=True):
                with st.spinner("Pebbles is testing Rapid7 API credentials..."):
                    test_result = verify_rapid7_credentials(input_key, input_region[0])
                    st.session_state["r7_conn_state"] = test_result
        with col_btn2:
            if st.button("Disconnect", use_container_width=True):
                st.session_state["r7_user_key"] = ""
                st.session_state["r7_conn_state"] = None
                st.rerun()

        # Connection Status Feedback
        conn_state = st.session_state.get("r7_conn_state")
        if conn_state:
            if conn_state.get("success"):
                st.markdown(
                    f"""
                    <div style="background: rgba(93, 184, 166, 0.12); border: 1px solid rgba(93, 184, 166, 0.35); border-radius: 8px; padding: 10px 12px; margin-top: 10px;">
                        <div style="font-size: 0.82rem; font-weight: 500; color: #5DB8A6;">
                            🟢 Verified &amp; Connected
                        </div>
                        <div style="font-size: 0.76rem; color: var(--ink-muted); margin-top: 3px;">
                            {conn_state.get('masked_key')} · {conn_state.get('region', '').upper()} · {conn_state.get('latency_ms', 0)}ms
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                caps = conn_state.get("capabilities") or {}
                if caps and isinstance(caps, dict):
                    idr_cap = caps.get("idr") or {}
                    logs_cap = caps.get("logs") or {}
                    scans_cap = caps.get("scans") or {}
                    vm_cap = caps.get("vm_assets") or {}

                    idr_status = "🟢 Connected" if idr_cap.get("available") else "🔴 Offline"
                    logs_status = "🟢 Connected" if logs_cap.get("available") else "🔴 Offline"
                    scans_status = "🟢 Connected" if scans_cap.get("available") else "🔴 Offline"
                    vm_status = "🟢 Connected" if vm_cap.get("available") else "🟠 Restricted (401)"
                    st.markdown(
                        f"""
                        <div style="background: rgba(240, 238, 230, 0.03); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 8px 10px; margin-top: 6px; font-size: 0.74rem;">
                            <div style="color: var(--ink-muted); margin-bottom: 4px; font-weight: 500;">Product Capabilities:</div>
                            <div style="margin-top: 2px;">• IDR SIEM: <b>{idr_status}</b> ({idr_cap.get('details', '')})</div>
                            <div style="margin-top: 2px;">• Log Search (LEQL): <b>{logs_status}</b> ({logs_cap.get('details', '')})</div>
                            <div style="margin-top: 2px;">• VM Scans: <b>{scans_status}</b> ({scans_cap.get('details', '')})</div>
                            <div style="margin-top: 2px;">• VM Assets &amp; Vulns: <b>{vm_status}</b></div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    f"""
                    <div style="background: rgba(217, 93, 57, 0.12); border: 1px solid rgba(217, 93, 57, 0.35); border-radius: 8px; padding: 10px 12px; margin-top: 10px;">
                        <div style="font-size: 0.82rem; font-weight: 500; color: #D95D39;">
                            🔴 Connection Failed
                        </div>
                        <div style="font-size: 0.76rem; color: var(--ink-muted); margin-top: 3px;">
                            {conn_state.get('message', 'Check key and region')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # Check Point Connector
        st.divider()
        st.caption("CHECK POINT (QUANTUM SMART-1 CLOUD)")
        st.markdown(
            "<div style='font-size: 0.82rem; color: var(--ink-muted); margin-bottom: 10px; line-height: 1.4;'>"
            "Quantum Smart-1 Cloud via Infinity Portal Gateway. "
            "Enforces strictly read-only sessions, capability discovery, and dynamic tool registration."
            "</div>",
            unsafe_allow_html=True,
        )

        if CHKP_KEY_MODE.lower() == "shared":
            st.markdown(
                """
                <div style="background: rgba(93, 184, 166, 0.12); border: 1px solid rgba(93, 184, 166, 0.35); border-radius: 6px; padding: 6px 10px; margin-bottom: 8px; font-size: 0.74rem; color: #5DB8A6;">
                    🔒 <b>Shared Team Mode Active</b>: Credentials retrieved from server configuration.
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Primary Method: Infinity Portal API Key
        default_client_id = CHKP_CLIENT_ID if CHKP_KEY_MODE.lower() == "shared" else ""
        default_secret_key = CHKP_SECRET_KEY if CHKP_KEY_MODE.lower() == "shared" else ""
        default_mgmt_admin_key = CHKP_MGMT_ADMIN_API_KEY if CHKP_KEY_MODE.lower() == "shared" else ""

        c_client_id = st.text_input(
            "Portal Client ID",
            value=st.session_state.get("chkp_client_id", default_client_id),
            placeholder="Paste Infinity Portal Client ID...",
            help="Account API key Client ID generated for Quantum Smart-1 Cloud service.",
        )
        st.session_state["chkp_client_id"] = c_client_id

        c_secret = st.text_input(
            "Portal Secret Key",
            type="password",
            value=st.session_state.get("chkp_secret_key", default_secret_key),
            placeholder="Paste Infinity Portal Secret Key...",
            help="Account API key Secret Key (Access Key). Masked and stored in memory only.",
        )
        st.session_state["chkp_secret_key"] = c_secret

        c_auth_url = st.text_input(
            "Authentication URL",
            value=st.session_state.get("chkp_auth_url", CHKP_AUTH_URL),
            placeholder="https://cloudinfra-gw.portal.checkpoint.com",
            help="Regional portal gateway URL. Never assumed or hardcoded (e.g. EU: https://cloudinfra-gw.portal.checkpoint.com, US: https://cloudinfra-gw-us.portal.checkpoint.com).",
        )
        st.session_state["chkp_auth_url"] = c_auth_url

        c_service_id = st.text_input(
            "Environment / Service ID (Optional)",
            value=st.session_state.get("chkp_service_id", CHKP_SERVICE_ID),
            placeholder="e.g. 6b19ac60-97ac-4566-... (Leave blank for portal-level access)",
            help="An identifier, not a secret; found in Smart-1 Cloud under Settings > API & SmartConsole, or ask whoever manages the portal.",
        )
        st.session_state["chkp_service_id"] = c_service_id

        c_mgmt_admin_api_key = st.text_input(
            "Management Admin API Key (Optional)",
            type="password",
            value=st.session_state.get("chkp_mgmt_admin_api_key", default_mgmt_admin_key),
            placeholder="Optional tenant admin key...",
            help="Optional management administrator API key if required by your Smart-1 Cloud tenant.",
        )
        st.session_state["chkp_mgmt_admin_api_key"] = c_mgmt_admin_api_key

        chkp_domain_input = st.text_input(
            "MDS Domain (Optional)",
            value=st.session_state.get("chkp_domain", CHKP_DOMAIN or ""),
            placeholder="Leave blank for single domain",
        )
        st.session_state["chkp_domain"] = chkp_domain_input

        # Advanced / Alternative Methods Expander
        with st.expander("Advanced: Alternative / Legacy Auth (Direct Host or User/Pass)"):
            legacy_auth_type = st.selectbox(
                "Legacy Auth Mode",
                ["Direct Management URL + Admin API Key (Method A)", "Username & Password (Method C)"],
                index=0 if st.session_state.get("chkp_auth_type") != "username_password" else 1,
            )
            chkp_host_input = st.text_input(
                "Direct Management URL / Host",
                value=st.session_state.get("chkp_mgmt_host", CHKP_MGMT_HOST),
                placeholder="https://<host>/web_api or 192.168.1.100",
            )
            st.session_state["chkp_mgmt_host"] = chkp_host_input

            if "Method A" in legacy_auth_type:
                chkp_key = st.text_input(
                    "Direct Admin API Key",
                    type="password",
                    value=st.session_state.get("chkp_api_key", ""),
                    placeholder="Paste Check Point Admin API Key...",
                )
                st.session_state["chkp_api_key"] = chkp_key
            else:
                col_u1, col_u2 = st.columns(2)
                with col_u1:
                    chkp_u = st.text_input("Username", value=st.session_state.get("chkp_username", ""), placeholder="admin")
                    st.session_state["chkp_username"] = chkp_u
                with col_u2:
                    chkp_p = st.text_input("Password", type="password", value=st.session_state.get("chkp_password", ""), placeholder="Password...")
                    st.session_state["chkp_password"] = chkp_p

            use_legacy = st.checkbox("Use legacy/direct credentials instead of Infinity Portal Gateway", value=False)
            if use_legacy:
                st.session_state["chkp_auth_type"] = "smart1_cloud_api_key" if "Method A" in legacy_auth_type else "username_password"
            else:
                st.session_state["chkp_auth_type"] = "infinity_portal_api_key"

        if "chkp_auth_type" not in st.session_state:
            st.session_state["chkp_auth_type"] = "infinity_portal_api_key"

        is_chkp_connected = bool(
            st.session_state.get("chkp_conn_state")
            and (
                st.session_state["chkp_conn_state"].get("success")
                if hasattr(st.session_state["chkp_conn_state"], "get")
                else getattr(st.session_state["chkp_conn_state"], "connected", False)
            )
        )
        btn_verify_label = "Re-check Connection" if is_chkp_connected else "Verify Connection"

        col_chkp1, col_chkp2 = st.columns([2, 1])
        with col_chkp1:
            if st.button(btn_verify_label, use_container_width=True, key="btn_verify_chkp"):
                with st.spinner("Pebbles is probing Check Point Infinity Portal & Smart-1 Cloud..."):
                    chkp_conn = CheckPointConnector(
                        auth_url=st.session_state.get("chkp_auth_url", CHKP_AUTH_URL),
                        service_id=st.session_state.get("chkp_service_id", CHKP_SERVICE_ID),
                        mgmt_admin_api_key=st.session_state.get("chkp_mgmt_admin_api_key", ""),
                        domain=st.session_state.get("chkp_domain") or None,
                        ca_bundle=CHKP_CA_BUNDLE,
                        timeout=CHKP_TIMEOUT,
                        mgmt_host=st.session_state.get("chkp_mgmt_host", ""),
                        port=CHKP_PORT,
                    )
                    c_creds: dict[str, Any] = {
                        "auth_method": st.session_state.get("chkp_auth_type", "infinity_portal_api_key"),
                        "auth_url": st.session_state.get("chkp_auth_url", CHKP_AUTH_URL),
                        "client_id": st.session_state.get("chkp_client_id", ""),
                        "secret_key": st.session_state.get("chkp_secret_key", ""),
                        "service_id": st.session_state.get("chkp_service_id", ""),
                        "mgmt_admin_api_key": st.session_state.get("chkp_mgmt_admin_api_key", ""),
                        "domain": st.session_state.get("chkp_domain") or None,
                        "mgmt_host": st.session_state.get("chkp_mgmt_host", ""),
                        "api_key": st.session_state.get("chkp_api_key", ""),
                        "user": st.session_state.get("chkp_username", ""),
                        "password": st.session_state.get("chkp_password", ""),
                    }
                    res = chkp_conn.verify_connection(c_creds)
                    st.session_state["chkp_conn_state"] = res
                    # If an environment ID was discovered, update session state in place
                    if res.get("details", {}).get("discovered_service_id"):
                        st.session_state["chkp_service_id"] = res["details"]["discovered_service_id"]
        with col_chkp2:
            if st.button("Disconnect CP", use_container_width=True, key="btn_disc_chkp"):
                st.session_state["chkp_client_id"] = ""
                st.session_state["chkp_secret_key"] = ""
                st.session_state["chkp_service_id"] = ""
                st.session_state["chkp_mgmt_admin_api_key"] = ""
                st.session_state["chkp_api_key"] = ""
                st.session_state["chkp_username"] = ""
                st.session_state["chkp_password"] = ""
                st.session_state["chkp_conn_state"] = None
                reset_session_env_id_mentioned(st.session_state.get("session_id", ""))
                st.rerun()

        chkp_state = st.session_state.get("chkp_conn_state")
        if chkp_state:
            is_chkp_ok = chkp_state.get("success") if hasattr(chkp_state, "get") else getattr(chkp_state, "connected", False)
            if is_chkp_ok:
                access_tier = chkp_state.get("details", {}).get("access_level", "full_management")
                caps = chkp_state.get("capabilities", {})
                method_used = chkp_state.get("details", {}).get("auth_method") or "Verified Session"
                reg_tools = chkp_state.get("details", {}).get("registered_tools", [])
                scope_notice = chkp_state.get("details", {}).get("key_scope_notice", "")

                if access_tier == "portal_level":
                    tier_badge = "🟡 Check Point Connected (Portal Level - Limited)"
                    tier_color = "#D4A373"
                    tier_bg = "rgba(212, 163, 115, 0.12)"
                    tier_border = "rgba(212, 163, 115, 0.35)"
                elif access_tier == "other_service":
                    svc_name = chkp_state.get("details", {}).get("detected_service", "Other Service")
                    tier_badge = f"🔵 Check Point Connected ({svc_name})"
                    tier_color = "#4A90E2"
                    tier_bg = "rgba(74, 144, 226, 0.12)"
                    tier_border = "rgba(74, 144, 226, 0.35)"
                else:
                    tier_badge = "🟢 Check Point Connected (Full Management Access)"
                    tier_color = "#5DB8A6"
                    tier_bg = "rgba(93, 184, 166, 0.12)"
                    tier_border = "rgba(93, 184, 166, 0.35)"

                st.markdown(
                    f"""
                    <div style="background: {tier_bg}; border: 1px solid {tier_border}; border-radius: 8px; padding: 10px 12px; margin-top: 10px;">
                        <div style="font-size: 0.82rem; font-weight: 500; color: {tier_color};">
                            {tier_badge}
                        </div>
                        <div style="font-size: 0.76rem; color: var(--ink-muted); margin-top: 3px;">
                            {method_used} · {chkp_state.get('latency_ms', 0)}ms
                        </div>
                        <div style="font-size: 0.72rem; color: var(--ink-muted); margin-top: 6px;">
                            <i>Registered Tools ({len(reg_tools)}): {', '.join(reg_tools) if reg_tools else 'None'}</i>
                        </div>
                        {f'<div style="font-size: 0.70rem; color: #8F9BA8; margin-top: 5px; border-top: 1px dashed rgba(255,255,255,0.1); padding-top: 4px;">ℹ️ {scope_notice}</div>' if scope_notice else ''}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # Expandable Capability Panel: "What I can access"
                cap_panel_items = chkp_state.get("details", {}).get("capability_panel", [])
                with st.expander("What I can access", expanded=True):
                    if cap_panel_items:
                        for item in cap_panel_items:
                            lbl = item.get("label", "")
                            acc = item.get("accessible", False)
                            rsn = item.get("reason", "")
                            if acc:
                                st.markdown(f"<div style='font-size:0.75rem; margin-bottom:4px;'>✅ <b>{lbl}</b> — <span style='color:#5DB8A6;'>Accessible</span></div>", unsafe_allow_html=True)
                            else:
                                st.markdown(f"<div style='font-size:0.75rem; margin-bottom:4px;'>❌ <b>{lbl}</b> — <span style='color:var(--ink-muted);'>{rsn}</span></div>", unsafe_allow_html=True)
                    else:
                        st.markdown(
                            f"<div style='font-size:0.75rem; line-height: 1.5;'>"
                            f"• Gateways & Servers: {'✅ Visible' if caps.get('gateways_visible') else '❌ Unavailable (needs Environment ID)'}<br/>"
                            f"• Access & NAT Rules: {'✅ Visible' if caps.get('rules_visible') else '❌ Unavailable (needs Environment ID)'}<br/>"
                            f"• Threat Prevention: {'✅ Visible' if caps.get('threat_profiles_visible') else '❌ Unavailable (needs Environment ID)'}<br/>"
                            f"• Security Logs: {'✅ Accessible' if caps.get('logs_accessible') else '❌ Restricted (role lacks log access)'}<br/>"
                            f"• Infinity Gateway: {'✅ Accessible' if caps.get('portal_telemetry_accessible') else '❌ Restricted'}"
                            f"</div>",
                            unsafe_allow_html=True,
                        )

                    if access_tier == "portal_level":
                        st.markdown(
                            "<div style='font-size: 0.72rem; color: #D4A373; margin-top: 6px; padding: 5px 8px; background: rgba(212, 163, 115, 0.08); border-radius: 4px;'>"
                            "💡 <b>To unlock full access:</b> Add your Environment/Service ID in the field above and click Re-check Connection."
                            "</div>",
                            unsafe_allow_html=True,
                        )
            else:
                st.markdown(
                    f"""
                    <div style="background: rgba(217, 93, 57, 0.12); border: 1px solid rgba(217, 93, 57, 0.35); border-radius: 8px; padding: 10px 12px; margin-top: 10px;">
                        <div style="font-size: 0.82rem; font-weight: 500; color: #D95D39;">
                            🔴 Check Point Connection Failed
                        </div>
                        <div style="font-size: 0.76rem; color: var(--ink-muted); margin-top: 3px; line-height: 1.4;">
                            {chkp_state.get('message', 'Check host, port, credentials')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # VirusTotal Connector
        st.divider()
        st.caption("VIRUSTOTAL THREAT INTEL CONNECTOR")
        st.markdown(
            "<div style='font-size: 0.82rem; color: var(--ink-muted); margin-bottom: 10px; line-height: 1.4;'>"
            "Public indicator reputation (hashes, external IPs, domains, URLs). "
            "Internal indicators strictly filtered before lookup."
            "</div>",
            unsafe_allow_html=True,
        )

        vt_key_input = st.text_input(
            "VirusTotal API Key",
            type="password",
            value=st.session_state["vt_api_key"],
            placeholder="Paste VT API Key...",
            help="Free public tier permits 4 req/min and 500 req/day. Commercial SOC usage requires Enterprise license.",
        )
        st.session_state["vt_api_key"] = vt_key_input

        # Public Tier Badge / Warning
        if VT_API_TIER.lower() == "public":
            st.markdown(
                """
                <div style="background: rgba(212, 163, 115, 0.12); border: 1px solid rgba(212, 163, 115, 0.3); border-radius: 6px; padding: 6px 10px; margin-bottom: 8px; font-size: 0.74rem; color: #D4A373;">
                    ⚠️ <b>Public Free Tier</b>: 4 req/min, 500/day. VT Terms prohibit commercial SOC usage without an Enterprise license. Internal IPs/domains strictly filtered.
                </div>
                """,
                unsafe_allow_html=True,
            )

        col_vt1, col_vt2 = st.columns([2, 1])
        with col_vt1:
            if st.button("Verify VirusTotal", use_container_width=True):
                with st.spinner("Pebbles is testing VirusTotal API..."):
                    vt_conn = VirusTotalConnector(
                        api_tier=VT_API_TIER,
                        rate_limit_per_min=VT_RATE_LIMIT_PER_MIN,
                        daily_quota=VT_DAILY_QUOTA,
                    )
                    res = vt_conn.verify_connection({"api_key": vt_key_input})
                    st.session_state["vt_conn_state"] = res
        with col_vt2:
            if st.button("Disconnect VT", use_container_width=True):
                st.session_state["vt_api_key"] = ""
                st.session_state["vt_conn_state"] = None
                st.rerun()

        vt_state = st.session_state.get("vt_conn_state")
        if vt_state:
            if vt_state.get("success"):
                rem = vt_state.get("daily_quota_remaining", 500)
                st.markdown(
                    f"""
                    <div style="background: rgba(93, 184, 166, 0.12); border: 1px solid rgba(93, 184, 166, 0.35); border-radius: 8px; padding: 10px 12px; margin-top: 10px;">
                        <div style="font-size: 0.82rem; font-weight: 500; color: #5DB8A6;">
                            🟢 VirusTotal Connected
                        </div>
                        <div style="font-size: 0.76rem; color: var(--ink-muted); margin-top: 3px;">
                            {vt_state.get('masked_key')} · {rem} reqs remaining today · {vt_state.get('latency_ms', 0)}ms
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                    <div style="background: rgba(217, 93, 57, 0.12); border: 1px solid rgba(217, 93, 57, 0.35); border-radius: 8px; padding: 10px 12px; margin-top: 10px;">
                        <div style="font-size: 0.82rem; font-weight: 500; color: #D95D39;">
                            🔴 VirusTotal Failed
                        </div>
                        <div style="font-size: 0.76rem; color: var(--ink-muted); margin-top: 3px;">
                            {vt_state.get('message', 'Invalid API key')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.divider()

        col_act1, col_act2 = st.columns(2)
        with col_act1:
            if st.button("🔄 Refresh Cache", use_container_width=True, help="Purge cached Rapid7 telemetry for this session"):
                invalidate_session_cache(st.session_state["session_id"])
                st.toast("Session telemetry cache cleared.")
        with col_act2:
            if st.button("🗑️ Clear Chat", use_container_width=True):
                st.session_state["soc_chat_history"] = []
                st.rerun()

        with st.expander("🛠️ Diagnostics & Nodes", expanded=False):
            mcp_running = check_mcp_server()
            st.markdown(
                f"<div style='font-size: 0.8rem; color: var(--ink-muted); line-height: 1.6;'>"
                f"MCP Engine: <span style='color: {'#5DB8A6' if mcp_running else '#D4A373'};'>{'Online' if mcp_running else 'Ready'}</span><br>"
                f"Session ID: <code>{st.session_state['session_id'][:8]}••••</code><br>"
                f"Tenant: <b>{active_client_name}</b><br>"
                f"Collector: <code>{collector_host}</code>"
                f"</div>",
                unsafe_allow_html=True,
            )

    # -----------------------------------------------------------------------
    # Main Chat View
    # -----------------------------------------------------------------------
    conn_state = st.session_state.get("r7_conn_state")
    conn_is_ok = bool(conn_state.get("success") if hasattr(conn_state, "get") else getattr(conn_state, "connected", False)) if conn_state else False

    chkp_state_raw = st.session_state.get("chkp_conn_state")
    chkp_is_ok = bool(chkp_state_raw.get("success") if hasattr(chkp_state_raw, "get") else getattr(chkp_state_raw, "connected", False)) if chkp_state_raw else False

    vt_state_raw = st.session_state.get("vt_conn_state")
    vt_is_ok = bool(vt_state_raw.get("success") if hasattr(vt_state_raw, "get") else getattr(vt_state_raw, "connected", False)) if vt_state_raw else False

    # Header bar with Mascot & Title
    badges = []
    if conn_is_ok:
        badges.append('<span class="pill-badge pill-live">Rapid7 Connected</span>')
    if chkp_is_ok:
        badges.append('<span class="pill-badge pill-live" style="border-color: #5DB8A6; color: #5DB8A6;">Check Point Connected</span>')
    if vt_is_ok:
        badges.append('<span class="pill-badge pill-live" style="border-color: #5DB8A6; color: #5DB8A6;">VirusTotal Connected</span>')
    badge_html = " ".join(badges)

    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-subtle); padding-bottom: 16px; margin-bottom: 24px;">
            <div class="pebbles-brand-container">
                <img src="data:image/png;base64,{PEBBLES_ICON_B64}" class="pebbles-avatar-img" alt="Pebbles Icon" />
                <div>
                    <h1 style="margin: 0; font-size: 2.1rem; line-height: 1.2;">Pebbles the SOC assistant</h1>
                    <div style="color: var(--ink-muted); font-size: 0.88rem; margin-top: 2px;">
                        Natural language queries across Rapid7 SIEM, Check Point Firewall, and VirusTotal Intel for <b>{active_client_name}</b>
                    </div>
                </div>
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                {badge_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    chat_history = st.session_state["soc_chat_history"]

    # Empty State: Quiet, Editorial Prompts
    if not chat_history:
        st.markdown(
            """
            <div style="margin: 32px 0 24px 0;">
                <h2 style="font-size: 1.6rem; margin-bottom: 6px;">How can Pebbles assist your SOC team today?</h2>
                <div style="color: var(--ink-muted); font-size: 0.95rem;">
                    Ask anything about identity risk, attack detection rules, SLAs, event health, or live investigations.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Who were the top 5 risked users last month?", use_container_width=True):
                st.session_state["pending_input"] = "Who were the top 5 risked users last month?"
                st.rerun()
            if st.button("Did we meet our SLAs for High and Medium priority?", use_container_width=True):
                st.session_state["pending_input"] = "Did we meet our SLAs for High and Medium priority?"
                st.rerun()
            if st.button("Which event sources currently have issues?", use_container_width=True):
                st.session_state["pending_input"] = "Which event sources currently have issues?"
                st.rerun()
        with col2:
            if st.button("Show exploitable vulnerabilities by CVSS score", use_container_width=True):
                st.session_state["pending_input"] = "Show exploitable vulnerabilities by CVSS score"
                st.rerun()
            if st.button("Compare investigations over the last 4 months", use_container_width=True):
                st.session_state["pending_input"] = "Compare investigations over the last 4 months"
                st.rerun()
            if st.button("Show LEQL queries and threat intelligence hunting", use_container_width=True):
                st.session_state["pending_input"] = "Show LEQL queries and threat intelligence hunting"
                st.rerun()

    # Render History
    for msg in chat_history:
        role = msg["role"]
        with st.chat_message(role, avatar="🪨" if role == "assistant" else "👤"):
            if role == "assistant" and "response_obj" in msg:
                render_pebbles_response(msg["response_obj"])
            else:
                st.markdown(sanitize_markdown_text(msg["content"]))

    # Handle Input
    pending_text = st.session_state.pop("pending_input", None)
    user_query = st.chat_input("Ask Pebbles about security posture, investigations, or specific assets...") or pending_text

    if user_query:
        chat_history.append({"role": "user", "content": user_query})
        with st.chat_message("user", avatar="👤"):
            st.markdown(sanitize_markdown_text(user_query))

        with st.chat_message("assistant", avatar="🪨"):
            # ANIMATED JUMPING PEBBLES LOADING CARD
            loading_container = st.empty()
            loading_container.markdown(
                f"""
                <div style="display: flex; align-items: center; gap: 16px; padding: 18px 22px; background: var(--bg-surface); border: 1px solid var(--border-hover); border-radius: 14px; margin: 12px 0;">
                    <img src="data:image/png;base64,{PEBBLES_ICON_B64}" class="pebble-jumping" style="width: 50px; height: 50px; object-fit: contain;" alt="Pebbles Jumping" />
                    <div>
                        <div style="font-weight: 500; color: var(--ink-main); font-size: 1rem;">Pebbles is inspecting Rapid7 telemetry...</div>
                        <div style="color: var(--ink-muted); font-size: 0.82rem; margin-top: 2px;">
                            Jumping through {active_client_name} alerts, user behavior, and security logs
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Execution phase
            time.sleep(0.6)  # Graceful micro-animation pause

            chkp_conn = CheckPointConnector(
                auth_url=st.session_state.get("chkp_auth_url", CHKP_AUTH_URL),
                service_id=st.session_state.get("chkp_service_id", CHKP_SERVICE_ID),
                mgmt_admin_api_key=st.session_state.get("chkp_mgmt_admin_api_key", CHKP_MGMT_ADMIN_API_KEY),
                domain=st.session_state.get("chkp_domain", CHKP_DOMAIN),
                ca_bundle=CHKP_CA_BUNDLE,
                timeout=CHKP_TIMEOUT,
                mgmt_host=st.session_state.get("chkp_mgmt_host", CHKP_MGMT_HOST),
                port=CHKP_PORT,
            )
            # Restore verified capabilities from session probe
            if st.session_state.get("chkp_conn_state"):
                c_status = st.session_state["chkp_conn_state"]
                caps = c_status.get("capabilities", {})
                chkp_conn._confirmed_capabilities = {k for k, v in caps.items() if v is True}

            vt_conn = VirusTotalConnector(
                api_tier=VT_API_TIER,
                rate_limit_per_min=VT_RATE_LIMIT_PER_MIN,
                daily_quota=VT_DAILY_QUOTA,
            )

            chkp_credentials = {
                "auth_method": st.session_state.get("chkp_auth_type", "infinity_portal_api_key"),
                "auth_url": st.session_state.get("chkp_auth_url", CHKP_AUTH_URL),
                "client_id": st.session_state.get("chkp_client_id", CHKP_CLIENT_ID if CHKP_KEY_MODE.lower() == "shared" else ""),
                "secret_key": st.session_state.get("chkp_secret_key", CHKP_SECRET_KEY if CHKP_KEY_MODE.lower() == "shared" else ""),
                "service_id": st.session_state.get("chkp_service_id", CHKP_SERVICE_ID),
                "mgmt_admin_api_key": st.session_state.get("chkp_mgmt_admin_api_key", CHKP_MGMT_ADMIN_API_KEY if CHKP_KEY_MODE.lower() == "shared" else ""),
                "domain": st.session_state.get("chkp_domain", CHKP_DOMAIN),
                "mgmt_host": st.session_state.get("chkp_mgmt_host", CHKP_MGMT_HOST),
                "api_key": st.session_state.get("chkp_api_key", ""),
                "user": st.session_state.get("chkp_username", ""),
                "password": st.session_state.get("chkp_password", ""),
            }

            vt_credentials = None
            if st.session_state.get("vt_api_key"):
                vt_credentials = {"api_key": st.session_state["vt_api_key"]}

            resp: PebblesResponse = process_natural_language_soc_query(
                query=user_query,
                client_name=active_client_name,
                session_id=st.session_state["session_id"],
                live_key=st.session_state.get("r7_user_key", ""),
                live_region=st.session_state.get("r7_region", "eu"),
                chkp_connector=chkp_conn,
                chkp_credentials=chkp_credentials,
                vt_connector=vt_conn,
                vt_credentials=vt_credentials,
                chat_history=chat_history,
            )

            # Clear jumping loader and render response natively
            loading_container.empty()
            render_pebbles_response(resp)

            chat_history.append({
                "role": "assistant",
                "content": resp.message,
                "response_obj": resp,
            })


if __name__ == "__main__":
    main()
