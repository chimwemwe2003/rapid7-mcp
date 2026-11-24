"""Chained Failed-Login Investigation Engine for Rapid7 and VirusTotal.

Executes ordered multi-step correlation:
1. Identifies top failed-login source IP and targeted accounts in Rapid7 authentication telemetry.
2. Evaluates indicator boundary: internal RFC1918 / CGNAT / loopback addresses are NEVER sent to VirusTotal.
3. Evaluates external runner-up on VirusTotal if top IP is internal.
4. Formats clean, grounded, natural answers without policy banners or raw enum leakage.
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress
import logging
from typing import Any

from rapid7_mcp.connectors import OutboundFilterError, VirusTotalConnector

logger = logging.getLogger("pebbles.chained_logins")


def is_internal_ip(ip_str: str) -> bool:
    """Check if an IP string is private, loopback, link-local, multicast, or reserved."""
    clean = ip_str.strip()
    try:
        ip = ipaddress.ip_address(clean)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if ip in cgnat:
            return True
        return False
    except ValueError:
        return True  # If not a valid IP (e.g. internal hostname), treat as internal


def analyze_failed_logins(
    events: list[dict[str, Any]],
    time_window_label: str = "this week (since Monday 00:00 Africa/Lusaka time)",
    vt_connector: VirusTotalConnector | None = None,
    vt_credentials: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Analyze failed login events and correlate with VirusTotal in ordered steps."""
    if not events:
        return {
            "has_events": False,
            "time_window": time_window_label,
            "message": f"There were no failed login events recorded in Rapid7 authentication logs for {time_window_label}.",
        }

    # Aggregate by source IP
    ip_counts: Counter[str] = Counter()
    ip_targets: dict[str, Counter[str]] = defaultdict(Counter)
    ip_target_assets: dict[str, set[str]] = defaultdict(set)
    ip_first_seen: dict[str, str] = {}
    ip_last_seen: dict[str, str] = {}

    for evt in events:
        src = (
            evt.get("source_ip")
            or evt.get("source_address")
            or evt.get("src")
            or evt.get("ip")
            or "Unknown"
        )
        if src == "Unknown":
            continue

        ip_counts[src] += 1
        tgt_user = (
            evt.get("target_user")
            or evt.get("account")
            or evt.get("user")
            or evt.get("username")
            or "Unspecified Account"
        )
        ip_targets[src][tgt_user] += 1

        tgt_asset = evt.get("target_asset") or evt.get("hostname") or evt.get("asset")
        if tgt_asset:
            ip_target_assets[src].add(tgt_asset)

        ts = evt.get("timestamp") or evt.get("time") or evt.get("created_time")
        if ts:
            if src not in ip_first_seen or ts < ip_first_seen[src]:
                ip_first_seen[src] = str(ts)[:19].replace("T", " ")
            if src not in ip_last_seen or ts > ip_last_seen[src]:
                ip_last_seen[src] = str(ts)[:19].replace("T", " ")

    if not ip_counts:
        return {
            "has_events": False,
            "time_window": time_window_label,
            "message": f"No source IPs were identified in the failed login events for {time_window_label}.",
        }

    # Sort deterministically: highest count first, then lexicographically by IP
    sorted_ips = sorted(ip_counts.items(), key=lambda x: (-x[1], x[0]))
    top_ip, top_count = sorted_ips[0]

    # Check for ties for 1st place
    tied_ips = [ip for ip, cnt in sorted_ips if cnt == top_count]
    tie_note = ""
    if len(tied_ips) > 1:
        tie_note = f"There was a tie for first place between {', '.join(f'`{ip}`' for ip in tied_ips)} ({top_count} attempts each); selected `{top_ip}` deterministically."

    top_is_internal = is_internal_ip(top_ip)
    top_targets = ip_targets[top_ip].most_common(5)
    distinct_target_count = len(ip_targets[top_ip])
    top_assets = list(ip_target_assets[top_ip])[:3]
    first_seen = ip_first_seen.get(top_ip, "N/A")
    last_seen = ip_last_seen.get(top_ip, "N/A")

    # Second-place count for context
    runner_up = sorted_ips[1] if len(sorted_ips) > 1 else None

    # Find highest-ranked external IP
    external_candidates = [(ip, cnt) for ip, cnt in sorted_ips if not is_internal_ip(ip)]
    top_external_ip: str | None = None
    top_external_count = 0
    if external_candidates:
        top_external_ip, top_external_count = external_candidates[0]

    # VirusTotal step
    vt_result: dict[str, Any] | None = None
    vt_checked_ip: str | None = None
    vt_error_note = ""

    target_vt_ip = top_ip if not top_is_internal else top_external_ip

    if target_vt_ip and vt_connector and vt_credentials:
        vt_checked_ip = target_vt_ip
        try:
            vt_result = vt_connector.execute_tool(
                "vt_lookup_indicator",
                {"indicator": target_vt_ip},
                vt_credentials,
            )
        except OutboundFilterError as ofe:
            vt_error_note = f"I didn't send `{target_vt_ip}` to VirusTotal because it is an internal address."
        except Exception as vte:
            vt_error_note = f"VirusTotal query for `{target_vt_ip}` could not be completed ({str(vte)})."
    elif target_vt_ip and (not vt_connector or not vt_credentials):
        vt_checked_ip = target_vt_ip
        vt_error_note = "VirusTotal is not connected, so external threat reputation could not be queried."

    return {
        "has_events": True,
        "time_window": time_window_label,
        "top_ip": top_ip,
        "top_count": top_count,
        "top_is_internal": top_is_internal,
        "distinct_targets": distinct_target_count,
        "top_targets": top_targets,
        "top_assets": top_assets,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "tie_note": tie_note,
        "runner_up": runner_up,
        "top_external_ip": top_external_ip,
        "top_external_count": top_external_count,
        "vt_checked_ip": vt_checked_ip,
        "vt_result": vt_result,
        "vt_error_note": vt_error_note,
    }
