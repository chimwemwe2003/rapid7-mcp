"""Pebbles Multi-Platform SOC Connectors.

Connectors for:
- Check Point On-Prem Security Management Server
- VirusTotal Threat Intelligence (API v3)
- Rapid7 Insight Platform
"""

from rapid7_mcp.connectors.base import BaseConnector, ConnectionStatus, ToolDefinition
from rapid7_mcp.connectors.checkpoint import CheckPointConnector, CheckPointClientError
from rapid7_mcp.connectors.virustotal import (
    VirusTotalConnector,
    VirusTotalClientError,
    OutboundFilterError,
    OutboundDataFilter,
)
from rapid7_mcp.connectors.cross_source import query_cross_source

__all__ = [
    "BaseConnector",
    "ConnectionStatus",
    "ToolDefinition",
    "CheckPointConnector",
    "CheckPointClientError",
    "VirusTotalConnector",
    "VirusTotalClientError",
    "OutboundFilterError",
    "OutboundDataFilter",
    "query_cross_source",
]
