"""Cross-Source Correlation Engine for Pebbles SOC Assistant.

Correlates findings across:
1. Rapid7 InsightIDR / InsightVM (internal SIEM alerts, asset telemetry, investigations)
2. Check Point (firewall rule matches, network objects, gateway drop/accept logs)
3. VirusTotal (public indicator reputation, strictly filtered by outbound boundary)

Strictly labels data by source. Never presents inference as fact.
"""

from typing import Any
import logging

from rapid7_mcp.connectors.checkpoint import CheckPointConnector
from rapid7_mcp.connectors.virustotal import OutboundFilterError, VirusTotalConnector
from rapid7_mcp.rapid7_live import live_get_asset_telemetry, live_query_logs

logger = logging.getLogger("pebbles.connectors.cross_source")


def query_cross_source(
    indicator: str,
    client_name: str,
    r7_key: str = "",
    r7_region: str = "eu",
    chkp_connector: CheckPointConnector | None = None,
    chkp_credentials: dict[str, Any] | None = None,
    vt_connector: VirusTotalConnector | None = None,
    vt_credentials: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute correlated cross-source investigation across Rapid7, Check Point, and VirusTotal."""
    ident = indicator.strip()
    sources_summary: dict[str, Any] = {
        "indicator": ident,
        "client_name": client_name,
        "rapid7": {"available": False, "data": None, "notes": ""},
        "checkpoint": {"available": False, "data": None, "notes": ""},
        "virustotal": {"available": False, "data": None, "notes": ""},
    }

    # 1. Rapid7 Internal Telemetry
    if r7_key:
        try:
            r7_telemetry = live_get_asset_telemetry(r7_key, r7_region, ident)
            sources_summary["rapid7"]["available"] = True
            sources_summary["rapid7"]["data"] = r7_telemetry
            sources_summary["rapid7"]["notes"] = (
                f"Found {len(r7_telemetry.get('idr_alerts', []))} linked SIEM alert(s) in Rapid7."
            )
        except Exception as e:
            sources_summary["rapid7"]["notes"] = f"Rapid7 query error: {str(e)}"
    else:
        sources_summary["rapid7"]["notes"] = "Rapid7 not connected for this session."

    # 2. Check Point Firewall Objects & Logs
    if chkp_connector and chkp_credentials:
        access_tier = getattr(chkp_connector, "access_level", "full_management")
        if access_tier == "portal_level":
            sources_summary["checkpoint"]["available"] = True
            sources_summary["checkpoint"]["access_tier"] = "limited"
            sources_summary["checkpoint"]["data"] = {
                "portal_status": "Connected (Portal Level)",
                "service_id_required": True,
            }
            sources_summary["checkpoint"]["notes"] = (
                "Check Point connected at portal level (limited): Environment/Service ID is required for deep rule and log correlation. Portal gateway telemetry verified."
            )
        elif access_tier == "other_service":
            detected_svc = getattr(chkp_connector, "detected_service", "another service")
            sources_summary["checkpoint"]["available"] = True
            sources_summary["checkpoint"]["access_tier"] = "other_service"
            sources_summary["checkpoint"]["notes"] = (
                f"Check Point API key belongs to {detected_svc} (not Quantum Smart-1 Cloud). Firewall rule/log inspection unavailable."
            )
        else:
            try:
                # Check objects and access rules
                obj_res = chkp_connector.execute_tool("chkp_lookup_object", {"identifier": ident}, chkp_credentials)
                rule_res = chkp_connector.execute_tool("chkp_find_access_rules", {"search_term": ident}, chkp_credentials)
                log_res = chkp_connector.execute_tool("chkp_search_logs", {"filter": ident, "limit": 20}, chkp_credentials)

                sources_summary["checkpoint"]["available"] = True
                sources_summary["checkpoint"]["access_tier"] = "full"
                sources_summary["checkpoint"]["data"] = {
                    "objects": obj_res.get("records", []),
                    "matching_rules": rule_res.get("records", []),
                    "recent_logs": log_res.get("records", []),
                    "log_aggregations": log_res.get("aggregations", {}),
                }
                sources_summary["checkpoint"]["notes"] = (
                    f"Check Point identified {len(obj_res.get('records', []))} object(s), "
                    f"{len(rule_res.get('records', []))} matching access rule(s), and "
                    f"{len(log_res.get('records', []))} firewall log entry(ies)."
                )
            except Exception as e:
                sources_summary["checkpoint"]["notes"] = f"Check Point query error: {str(e)}"
    else:
        sources_summary["checkpoint"]["notes"] = "Check Point connector not configured or logged in."

    # 3. VirusTotal External Threat Intelligence (Strictly Public Indicators)
    if vt_connector and vt_credentials:
        try:
            vt_res = vt_connector.execute_tool("vt_lookup_indicator", {"indicator": ident}, vt_credentials)
            sources_summary["virustotal"]["available"] = True
            sources_summary["virustotal"]["data"] = vt_res
            if vt_res.get("found"):
                sources_summary["virustotal"]["notes"] = (
                    f"VirusTotal reports {vt_res.get('malicious_count', 0)} of "
                    f"{vt_res.get('total_engines', 0)} engines flagged this indicator as malicious "
                    f"(last analyzed {vt_res.get('last_analysis_date')})."
                )
            else:
                sources_summary["virustotal"]["notes"] = (
                    "VirusTotal has no prior record for this indicator (not previously scanned/analyzed)."
                )
        except OutboundFilterError as ofe:
            sources_summary["virustotal"]["available"] = False
            sources_summary["virustotal"]["notes"] = (
                f"VirusTotal lookup blocked by confidentiality filter: {ofe.args[0]}"
            )
        except Exception as e:
            sources_summary["virustotal"]["notes"] = f"VirusTotal query error: {str(e)}"
    else:
        sources_summary["virustotal"]["notes"] = "VirusTotal connector not connected or disabled."

    return sources_summary
