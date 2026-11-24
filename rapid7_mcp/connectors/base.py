"""Base Connector Interface for Pebbles Multi-Product SOC Assistant.

Standardizes lifecycle, capability discovery, credential isolation, and tool execution
across all integrated security platforms (Rapid7, Check Point, VirusTotal).
"""

from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field


class ConnectionStatus(BaseModel):
    """Normalized status report for a product connection."""
    connected: bool = False
    provider: str
    target: str = ""
    authenticated: bool = False
    read_only: bool = True
    latency_ms: int = 0
    message: str = ""
    capabilities: dict[str, Any] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.connected

    def get(self, key: str, default: Any = None) -> Any:
        if key == "success":
            return self.connected
        if key in self.__dict__:
            val = getattr(self, key)
            return val if val is not None else default
        if key in self.details:
            return self.details[key]
        if key in self.capabilities:
            return self.capabilities[key]
        return default

    def __getitem__(self, key: str) -> Any:
        res = self.get(key, KeyError)
        if res is KeyError:
            raise KeyError(key)
        return res


class ToolDefinition(BaseModel):
    """Specification of an allowed read-only tool exposed by a connector."""
    name: str
    description: str
    provider: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    read_only: bool = True


class BaseConnector(ABC):
    """Abstract base class that all security connectors must implement."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the security platform (e.g., 'Check Point', 'VirusTotal', 'Rapid7')."""
        pass

    @abstractmethod
    def verify_connection(self, credentials: dict[str, Any], **kwargs: Any) -> ConnectionStatus:
        """Probe the target API, check credentials, and assess read-only capability."""
        pass

    @abstractmethod
    def get_tools(self) -> list[ToolDefinition]:
        """Return the strict read-only tool allowlist for this connector."""
        pass

    @abstractmethod
    def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        credentials: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute a read-only tool call with server-side credential injection."""
        pass
