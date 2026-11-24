"""Check Point Quantum Smart-1 Cloud & Infinity Portal Connector.

Provides read-only access to Check Point Quantum Smart-1 Cloud strictly via the Infinity Portal Gateway:
- Authentication via Infinity Portal API Key (Client ID + Secret Key) exchanged at the regional Authentication URL
- Environment targeting via Smart-1 Cloud Environment/Service ID
- Read-only management session establishment via the portal gateway's management endpoint
- Support for optional management administrator API key if required by the cloud tenant

Strictly Enforces:
- No direct management server IP/host assumption (all requests route via Infinity Portal Gateway)
- Never assumes a region (uses the exact Authentication URL provided)
- Non-negotiable read-only sessions (`"read-only": True`)
- Automatic JWT token and session renewal before expiration
- Plain-language SOC diagnostic error translation:
  * secret or authentication URL lost
  * wrong regional Authentication URL
  * token expired (renewed automatically)
  * key for the wrong service (Harmony Endpoint, Harmony Email, CloudGuard)
  * missing or wrong Environment/Service ID (with environment discovery probe - UNVERIFIED)
  * user-scoped API key reporting (UNVERIFIED for automated management login)
- Capability-driven tool registration (only confirmed capabilities register tools)
- Strict write command blocking
- Africa/Lusaka timestamp localization and server-side log aggregations
"""

from datetime import datetime, timedelta, timezone
import json
import logging
import os
import re
import time
from typing import Any
import httpx

from rapid7_mcp.connectors.base import BaseConnector, ConnectionStatus, ToolDefinition
from rapid7_mcp.time_utils import format_iso_utc, resolve_soc_time_range

logger = logging.getLogger("pebbles.connectors.checkpoint")

# Standard regional gateway hints for user guidance
PORTAL_REGIONAL_GATEWAYS: dict[str, str] = {
    "Europe (Default)": "https://cloudinfra-gw.portal.checkpoint.com",
    "United States": "https://cloudinfra-gw-us.portal.checkpoint.com",
    "Asia-Pacific": "https://cloudinfra-gw.ap.portal.checkpoint.com",
    "Canada": "https://cloudinfra-gw.ca.portal.checkpoint.com",
    "India": "https://cloudinfra-gw.in.portal.checkpoint.com",
}

# Check Point Management API Command Allowlist (Strictly Read-Only)
ALLOWED_READONLY_COMMANDS = {
    "show-gateways-and-servers",
    "show-gateway",
    "show-hosts",
    "show-host",
    "show-networks",
    "show-network",
    "show-access-rulebase",
    "show-access-layers",
    "show-access-rule",
    "show-nat-rulebase",
    "show-nat-rule",
    "show-nat-layers",
    "show-threat-rulebase",
    "show-threat-profile",
    "show-threat-profiles",
    "show-threat-protections",
    "show-threat-protection",
    "show-logs",
    "show-session",
    "show-sessions",
    "show-domains",
    "show-domain",
    "show-services-tcp",
    "show-services-udp",
    "show-services-other",
}

# Explicit Write Command Denylist (Defensive safety net)
PROHIBITED_WRITE_PREFIXES = (
    "add-", "set-", "delete-", "publish", "discard", "install-policy",
    "block-ip", "run-script", "install-", "uninstall-", "assign-",
    "restore-", "backup-", "create-", "modify-", "enable-", "disable-",
)

# Access Levels for Capability-Tiered Connection
ACCESS_LEVEL_FULL_MANAGEMENT = "full_management"
ACCESS_LEVEL_PORTAL_LEVEL = "portal_level"
ACCESS_LEVEL_OTHER_SERVICE = "other_service"
ACCESS_LEVEL_NOT_AUTHENTICATED = "not_authenticated"

# Tool Name to Required Capability Mapping
TOOL_CAPABILITY_MAP: dict[str, str] = {
    "chkp_list_gateways": "gateways_visible",
    "chkp_lookup_object": "management_api_reachable",
    "chkp_find_access_rules": "rules_visible",
    "chkp_show_threat_protection": "threat_profiles_visible",
    "chkp_search_logs": "logs_accessible",
    "chkp_get_service_status": "portal_telemetry_accessible",
    "chkp_other_service_info": "other_service_accessible",
}


class CheckPointClientError(Exception):
    """Specific error raised for Check Point API issues with plain-language diagnostics."""
    def __init__(self, status_code: int, message: str, code: str = "CHKP_ERROR"):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.code = code


def _validate_command_safety(command: str) -> None:
    """Ensure command is strictly on the read-only allowlist and contains no write verbs."""
    cmd_clean = command.strip().lower()
    if cmd_clean not in ALLOWED_READONLY_COMMANDS:
        raise CheckPointClientError(
            status_code=403,
            message=f"Operation '{command}' is not in the allowed Check Point read-only toolset.",
            code="WRITE_PROHIBITED",
        )
    for prefix in PROHIBITED_WRITE_PREFIXES:
        if cmd_clean.startswith(prefix) or prefix in cmd_clean:
            raise CheckPointClientError(
                status_code=403,
                message=f"Write operation '{command}' is strictly forbidden on production infrastructure.",
                code="WRITE_PROHIBITED",
            )


def _format_lusaka_window(time_range: str) -> tuple[str, str, str]:
    """Convert relative time range to explicit ISO strings and human-readable Africa/Lusaka dates."""
    lusaka_tz = timezone(timedelta(hours=2))
    now = datetime.now(timezone.utc).astimezone(lusaka_tz)

    t = time_range.lower().strip()
    if t in ("last-hour", "last_hour", "1h", "hour"):
        start = now - timedelta(hours=1)
        label = "last-hour"
    elif t in ("today", "current_day"):
        start = datetime(now.year, now.month, now.day, 0, 0, 0, tzinfo=lusaka_tz)
        label = "today"
    elif t in ("yesterday",):
        yest = now - timedelta(days=1)
        start = datetime(yest.year, yest.month, yest.day, 0, 0, 0, tzinfo=lusaka_tz)
        label = "yesterday"
    elif t in ("last-7-days", "last_7_days", "week", "last-week"):
        start = now - timedelta(days=7)
        label = "last-7-days"
    else:
        start = now - timedelta(days=1)
        label = "last-24-hours"

    start_iso = start.strftime("%Y-%m-%dT%H:%M:%S")
    human_range = f"{start.strftime('%Y-%m-%d %H:%M')} to {now.strftime('%Y-%m-%d %H:%M')} (Africa/Lusaka UTC+2)"
    return label, human_range, start_iso


class CheckPointConnector(BaseConnector):
    """Connector for Check Point Quantum Smart-1 Cloud via Infinity Portal Gateway."""

    def __init__(
        self,
        auth_url: str = "https://cloudinfra-gw.portal.checkpoint.com",
        service_id: str = "",
        mgmt_admin_api_key: str = "",
        ca_bundle: str | None = None,
        timeout: float = 15.0,
        domain: str | None = None,
        transport: httpx.BaseTransport | None = None,
        # Backward-compatible parameters for legacy/direct callers
        mgmt_host: str = "",
        port: int = 443,
        portal_region: str = "",
        auth_method: str = "infinity_portal_api_key",
    ):
        self.auth_url = auth_url.strip() if auth_url else "https://cloudinfra-gw.portal.checkpoint.com"
        self.service_id = service_id.strip()
        self.mgmt_admin_api_key = mgmt_admin_api_key.strip()
        self.ca_bundle = ca_bundle
        self.timeout = timeout
        self.domain = domain
        self._transport = transport

        # Backward compatibility
        self.mgmt_host = mgmt_host.strip()
        self.port = port
        self.portal_region = portal_region.strip()
        self.auth_method = auth_method.strip()

        # Session & Capability-Tiered State
        self._active_sid: str = ""
        self._bearer_token: str = ""
        self._token_expires_at: float = 0.0
        self._session_expires_at: float = 0.0
        self._target_mgmt_url: str = ""
        self._cached_credentials: dict[str, Any] = {}
        self._confirmed_capabilities: set[str] = set()
        self.access_level: str = ACCESS_LEVEL_NOT_AUTHENTICATED
        self.detected_service: str = "Quantum Smart-1 Cloud"
        self.discovered_service_id: str = ""
        self.capability_reasons: dict[str, str] = {}

    @property
    def provider_name(self) -> str:
        return "Check Point"

    def _get_verify_context(self) -> bool | str:
        """Return CA bundle path or True for system cert store. Never False."""
        if self.ca_bundle and os.path.isfile(self.ca_bundle):
            return self.ca_bundle
        return True  # Strict system CA bundle, never unverified

    def _create_client(self) -> httpx.Client:
        kwargs: dict[str, Any] = {
            "verify": self._get_verify_context(),
            "timeout": self.timeout,
        }
        if getattr(self, "_transport", None) is not None:
            kwargs["transport"] = self._transport
        return httpx.Client(**kwargs)

    # -----------------------------------------------------------------------
    # Helper: Resolve Gateway and Token Endpoints
    # -----------------------------------------------------------------------

    def _resolve_portal_endpoints(self, auth_url_input: str) -> tuple[str, str]:
        """Derive the gateway base URL and external auth endpoint without assuming a region."""
        url_clean = auth_url_input.strip().rstrip("/")
        if not url_clean.startswith("http://") and not url_clean.startswith("https://"):
            url_clean = f"https://{url_clean}"

        if url_clean.endswith("/auth/external"):
            token_endpoint = url_clean
            gateway_base = url_clean[:-len("/auth/external")]
        else:
            token_endpoint = f"{url_clean}/auth/external"
            gateway_base = url_clean

        return gateway_base, token_endpoint

    def _resolve_environment_base(self, gateway_base: str, service_id_input: str) -> tuple[str, str]:
        """Resolve the Smart-1 Cloud environment management base path."""
        sid = service_id_input.strip()
        # If user passed a full environment URL:
        if sid.startswith("http://") or sid.startswith("https://"):
            clean_url = sid.rstrip("/")
            if clean_url.endswith("/web_api"):
                return clean_url, clean_url.split("/environments/")[-1].split("/")[0]
            return f"{clean_url}/web_api", clean_url.split("/environments/")[-1].split("/")[0]

        # Standard Infinity Portal MaaS routing:
        # {gateway_base}/app/maas/api/v2/environments/{service_id}/web_api
        return f"{gateway_base}/app/maas/api/v2/environments/{sid}/web_api", sid

    # -----------------------------------------------------------------------
    # Primary Authentication Flow: Infinity Portal API Key
    # -----------------------------------------------------------------------

    def login(self, credentials: dict[str, Any]) -> dict[str, Any]:
        """Perform a read-only login via the Infinity Portal Gateway.

        Flow:
        1. POST {Authentication URL} with Client ID and Secret Key to obtain JWT token.
        2. Resolve or probe Environment/Service ID.
        3. Use the token against portal gateway's management environment endpoint in read-only mode.
        4. Return session ID ('sid') for subsequent calls.
        """
        self._cached_credentials.update({k: v for k, v in credentials.items() if v})

        client_id = (
            credentials.get("client_id")
            or credentials.get("clientId")
            or self._cached_credentials.get("client_id")
            or self._cached_credentials.get("clientId")
        )
        secret_key = (
            credentials.get("secret_key")
            or credentials.get("secretKey")
            or credentials.get("access_key")
            or credentials.get("accessKey")
            or self._cached_credentials.get("secret_key")
            or self._cached_credentials.get("secretKey")
        )
        auth_url_val = (
            credentials.get("auth_url")
            or credentials.get("authentication_url")
            or self._cached_credentials.get("auth_url")
            or self.auth_url
        )
        service_id_val = (
            credentials.get("service_id")
            or credentials.get("serviceId")
            or credentials.get("environment_id")
            or self._cached_credentials.get("service_id")
            or self.service_id
        )
        mgmt_key = (
            credentials.get("mgmt_admin_api_key")
            or credentials.get("api_key")
            or self._cached_credentials.get("mgmt_admin_api_key")
            or self.mgmt_admin_api_key
        )
        domain = credentials.get("domain") or self._cached_credentials.get("domain") or self.domain

        # Cache credentials for seamless in-place upgrade when service_id is added later
        if client_id:
            self._cached_credentials["client_id"] = client_id
        if secret_key:
            self._cached_credentials["secret_key"] = secret_key
        if auth_url_val:
            self._cached_credentials["auth_url"] = auth_url_val
        if service_id_val:
            self._cached_credentials["service_id"] = service_id_val
        if mgmt_key:
            self._cached_credentials["mgmt_admin_api_key"] = mgmt_key
        if domain:
            self._cached_credentials["domain"] = domain

        # Fallback to Method A / Method C if explicit legacy credentials given
        if not client_id and (credentials.get("api_key") or credentials.get("user")):
            return self._fallback_legacy_login(credentials)

        # Check: secret or authentication URL lost
        if not secret_key or not client_id or not auth_url_val:
            raise CheckPointClientError(
                401,
                "Secret or Authentication URL lost: The secret key cannot be retrieved from Infinity Portal after initial generation. "
                "A portal administrator must generate a new Account API key under Global Settings > API Keys > New Account API Key "
                "(Service: Quantum Smart-1 Cloud) and provide the Client ID, Secret Key, and Authentication URL.",
                code="CREDENTIALS_LOST",
            )

        gateway_base, token_endpoint = self._resolve_portal_endpoints(auth_url_val)

        # Step 1: POST {Authentication URL} to obtain JWT token
        token = ""
        try:
            with self._create_client() as client:
                auth_resp = client.post(
                    token_endpoint,
                    json={"clientId": client_id.strip(), "accessKey": secret_key.strip()},
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                )

                if auth_resp.status_code == 200:
                    data = auth_resp.json()
                    token = (
                        data.get("data", {}).get("token")
                        or data.get("token")
                        or data.get("csrf")
                        or ""
                    )
                elif auth_resp.status_code in (400, 401):
                    raise CheckPointClientError(
                        401,
                        "Authentication Failed: Invalid Infinity Portal Client ID or Secret Key.",
                        code="AUTH_FAILED",
                    )
                elif auth_resp.status_code == 403:
                    raise CheckPointClientError(
                        403,
                        "Infinity Portal API Key is revoked, expired, or access is forbidden.",
                        code="KEY_REVOKED",
                    )
                elif auth_resp.status_code == 404:
                    raise CheckPointClientError(
                        404,
                        f"Wrong regional Authentication URL: Could not reach the authentication endpoint at '{token_endpoint}'. "
                        f"Verify that the regional gateway matches your Infinity Portal tenant region "
                        f"(e.g. EU: https://cloudinfra-gw.portal.checkpoint.com, US: https://cloudinfra-gw-us.portal.checkpoint.com, "
                        f"AP: https://cloudinfra-gw.ap.portal.checkpoint.com).",
                        code="WRONG_REGIONAL_AUTH_URL",
                    )
                else:
                    raise CheckPointClientError(
                        auth_resp.status_code,
                        f"Infinity Portal Authentication returned HTTP {auth_resp.status_code}: {auth_resp.text[:140]}",
                    )
        except httpx.ConnectError as e:
            raise CheckPointClientError(
                502,
                f"Wrong regional Authentication URL: Failed to establish a secure connection to '{token_endpoint}'. "
                f"Verify the Authentication URL and regional gateway settings: {str(e)}",
                code="WRONG_REGIONAL_AUTH_URL",
            )
        except httpx.TimeoutException:
            raise CheckPointClientError(504, f"Authentication request timed out reaching '{token_endpoint}'.", code="TIMEOUT")

        if not token:
            raise CheckPointClientError(500, "Infinity Portal authentication succeeded but no JWT token was returned.", code="NO_TOKEN")

        self._bearer_token = token
        self._token_expires_at = time.time() + 1800  # Token lifetime is typically 30 minutes

        # Step 2: Handle optional Environment/Service ID via discovery probe (UNVERIFIED)
        if not service_id_val:
            discovered_id = self._probe_list_environments(gateway_base, token)
            if discovered_id:
                service_id_val = discovered_id
                self.discovered_service_id = discovered_id
                self.service_id = discovered_id
                self._cached_credentials["service_id"] = discovered_id
                logger.info("Auto-discovered Smart-1 Cloud environment: %s", discovered_id)
            else:
                # PORTAL-LEVEL ACCESS TIER (No environment ID configured or discovered)
                # Invariant: The no-ID path NEVER calls management endpoints!
                self.access_level = ACCESS_LEVEL_PORTAL_LEVEL
                self.service_id = ""
                self._active_sid = ""
                self._target_mgmt_url = ""
                self._confirmed_capabilities = {"portal_telemetry_accessible"}
                self.capability_reasons = {
                    "management_api_reachable": "Needs the Environment/Service ID",
                    "gateways_visible": "Needs the Environment/Service ID",
                    "rules_visible": "Needs the Environment/Service ID",
                    "threat_profiles_visible": "Needs the Environment/Service ID",
                    "logs_accessible": "Needs the Environment/Service ID",
                    "domains_visible": "Needs the Environment/Service ID",
                    "portal_telemetry_accessible": "Accessible",
                }
                return {
                    "sid": "",
                    "token": token,
                    "read_only": True,
                    "access_level": ACCESS_LEVEL_PORTAL_LEVEL,
                    "auth_method": "Infinity Portal API Key (Portal Level)",
                    "target_mgmt_url": "",
                    "service_id": "",
                    "login_time": time.time(),
                }

        # Step 3: Target the portal gateway's management environment endpoint
        env_mgmt_base, clean_sid = self._resolve_environment_base(gateway_base, service_id_val)
        login_url = f"{env_mgmt_base}/login"

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        payload: dict[str, Any] = {
            "read-only": True,
            "session-name": "Pebbles SOC Assistant",
            "session-description": "Read-only investigative query session for Pebbles AI",
            "session-timeout": 600,
        }
        if mgmt_key:
            payload["api-key"] = mgmt_key.strip()
        if domain:
            payload["domain"] = domain.strip()

        # Step 4: Perform the documented management login in read-only mode
        try:
            with self._create_client() as client:
                resp = client.post(login_url, json=payload, headers=headers)

                if resp.status_code == 200:
                    res_data = resp.json()
                    sid = res_data.get("sid", token)
                    self._active_sid = sid
                    self._target_mgmt_url = env_mgmt_base
                    self.service_id = clean_sid
                    self.access_level = ACCESS_LEVEL_FULL_MANAGEMENT
                    timeout_sec = float(res_data.get("session-timeout", 600))
                    self._session_expires_at = time.time() + timeout_sec

                    return {
                        "sid": sid,
                        "token": token,
                        "read_only": res_data.get("read-only", True),
                        "uid": res_data.get("uid", ""),
                        "session_timeout": timeout_sec,
                        "login_time": time.time(),
                        "access_level": ACCESS_LEVEL_FULL_MANAGEMENT,
                        "auth_method": "Infinity Portal API Key (Smart-1 Cloud Gateway)",
                        "target_mgmt_url": env_mgmt_base,
                        "service_id": clean_sid,
                    }

                elif resp.status_code in (401, 403):
                    err_json = resp.json() if "application/json" in resp.headers.get("Content-Type", "") else {}
                    err_msg = str(err_json.get("message", resp.text[:140]))

                    # Detect IP blocked
                    if "client is not allowed" in err_msg.lower() or "client ip" in err_msg.lower():
                        raise CheckPointClientError(
                            403,
                            "Management API Access Blocked by IP: The Check Point Management API rejected the connection from Pebbles' IP address. "
                            "Since we do not have SmartConsole administrative access to change server settings, please ask your Check Point administrator "
                            "to whitelist Pebbles' server IP under Manage & Settings > Blades > Management API > Advanced Settings > Trusted Clients.",
                            code="IP_BLOCKED",
                        )

                    # Detect Key for the Wrong Service
                    self.access_level = ACCESS_LEVEL_OTHER_SERVICE
                    self.detected_service = "Harmony Endpoint / CloudGuard"
                    self.capability_reasons = {
                        "management_api_reachable": "Service not supported by this key",
                        "gateways_visible": "Service not supported by this key",
                        "rules_visible": "Service not supported by this key",
                        "threat_profiles_visible": "Service not supported by this key",
                        "logs_accessible": "Service not supported by this key",
                        "domains_visible": "Service not supported by this key",
                        "other_service_accessible": "Accessible",
                    }
                    raise CheckPointClientError(
                        403,
                        "Wrong Service Key: The API key successfully authenticated with Check Point Infinity Portal, "
                        "but was not issued for Quantum Smart-1 Cloud (token issued, but management login rejected with HTTP 403/401). "
                        "It appears to belong to another Infinity service such as Harmony Endpoint, Harmony Email & Collaboration, "
                        "or CloudGuard. Please ask your Infinity Portal administrator to create an Account API Key under "
                        "Service: Quantum Smart-1 Cloud with a Read-Only role.",
                        code="WRONG_SERVICE_KEY",
                    )

                elif resp.status_code == 404:
                    raise CheckPointClientError(
                        404,
                        f"Missing or wrong Environment/Service ID: Could not locate the Smart-1 Cloud management environment '{clean_sid}' "
                        f"on portal gateway '{gateway_base}'. Request the exact Service Identifier (UUID) from your Check Point administrator "
                        f"(found in Smart-1 Cloud under Settings > General > API & SmartConsole).",
                        code="INVALID_SERVICE_ID",
                    )

                else:
                    raise CheckPointClientError(
                        resp.status_code,
                        f"Smart-1 Cloud Management login failed with HTTP {resp.status_code}: {resp.text[:140]}",
                    )

        except httpx.ConnectError as e:
            raise CheckPointClientError(
                502,
                f"Network or TLS Failure reaching Smart-1 Cloud management environment at '{login_url}': {str(e)}",
                code="TLS_OR_NETWORK_ERROR",
            )
        except httpx.TimeoutException:
            raise CheckPointClientError(
                504,
                f"Management login timed out reaching '{login_url}' ({self.timeout}s timeout).",
                code="TIMEOUT",
            )

    # -----------------------------------------------------------------------
    # Environment Listing Probe (UNVERIFIED)
    # -----------------------------------------------------------------------

    def _probe_list_environments(self, gateway_base: str, token: str) -> str:
        """Attempt to discover available Smart-1 Cloud environments via the portal API (UNVERIFIED).
        
        Strict Safety Invariant:
        Discovery is strictly read-only and MUST NEVER call POST, PUT, PATCH, or DELETE.
        Only GET requests are permitted.
        """
        probe_paths = [
            f"{gateway_base}/app/maas/api/v2/environments",
            f"{gateway_base}/app/maas/api/v1/environments",
            f"{gateway_base}/app/maas/api/v2/service/info",
        ]
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        for p in probe_paths:
            try:
                with self._create_client() as client:
                    resp = client.get(p, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        envs = data.get("environments", []) or data.get("data", [])
                        if isinstance(envs, list) and len(envs) > 0:
                            first_env = envs[0]
                            if isinstance(first_env, dict):
                                env_id = first_env.get("id") or first_env.get("serviceId") or first_env.get("environmentId")
                                if env_id:
                                    logger.info("Auto-discovered Smart-1 Cloud environment: %s", env_id)
                                    return str(env_id).strip()
                            elif isinstance(first_env, str):
                                return first_env.strip()
                        elif isinstance(data, dict):
                            svc_id = data.get("serviceId") or data.get("environmentId") or data.get("id")
                            if svc_id:
                                return str(svc_id).strip()
            except Exception:
                continue
        return ""

    # -----------------------------------------------------------------------
    # Legacy / Direct Login Fallback (For direct URL/API key setups)
    # -----------------------------------------------------------------------

    def _fallback_legacy_login(self, credentials: dict[str, Any]) -> dict[str, Any]:
        """Fallback for direct management URL + API Key or User/Password."""
        host = credentials.get("mgmt_host") or self.mgmt_host
        api_key = credentials.get("api_key") or credentials.get("api-key")
        user = credentials.get("user") or credentials.get("username")
        password = credentials.get("password")
        domain = credentials.get("domain") or self.domain

        if not host:
            raise CheckPointClientError(400, "Management Host or Service ID is required.", code="NO_HOST_CONFIGURED")

        url = f"https://{host.replace('https://', '').rstrip('/')}/web_api/login"
        payload: dict[str, Any] = {
            "read-only": True,
            "session-name": "Pebbles SOC Assistant",
            "session-timeout": 600,
        }
        if api_key:
            payload["api-key"] = api_key.strip()
        elif user and password:
            payload["user"] = user.strip()
            payload["password"] = password.strip()
        if domain:
            payload["domain"] = domain

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        try:
            with self._create_client() as client:
                resp = client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    sid = data.get("sid", "")
                    self._active_sid = sid
                    self._target_mgmt_url = url.replace("/login", "")
                    self._session_expires_at = time.time() + float(data.get("session-timeout", 600))
                    return {
                        "sid": sid,
                        "read_only": True,
                        "login_time": time.time(),
                        "auth_method": "Direct Management API",
                        "target_mgmt_url": self._target_mgmt_url,
                    }
                elif resp.status_code in (400, 401):
                    raise CheckPointClientError(
                        401,
                        "Invalid Check Point credentials or key revoked / expired. Please verify your username, password, or Admin API key.",
                        code="AUTH_FAILED",
                    )
                elif resp.status_code == 403:
                    err_text = resp.text.lower()
                    if "client is not allowed" in err_text or "client ip" in err_text:
                        raise CheckPointClientError(
                            403,
                            "Management API Access Blocked by IP: The Check Point Management API rejected the connection from Pebbles' IP address. "
                            "Please ask your Check Point administrator to whitelist Pebbles' server IP under Manage & Settings > Blades > Management API > Advanced Settings > Trusted Clients.",
                            code="IP_BLOCKED",
                        )
                    raise CheckPointClientError(
                        403,
                        "Insufficient Role Permissions: Administrator profile lacks access to perform this operation or access the System Data domain.",
                        code="INSUFFICIENT_PERMISSIONS",
                    )
                elif resp.status_code == 429:
                    raise CheckPointClientError(
                        429,
                        "Rate Limited / Server Busy: Check Point Management API is experiencing high load or rate limiting. Retrying with backoff...",
                        code="RATE_LIMITED",
                    )
                else:
                    raise CheckPointClientError(resp.status_code, f"Direct Check Point login failed: {resp.text[:140]}")
        except httpx.ConnectError as e:
            raise CheckPointClientError(502, f"Network error connecting to {host}: {str(e)}", code="TLS_OR_NETWORK_ERROR")

    # -----------------------------------------------------------------------
    # Session & Token Automatic Renewal
    # -----------------------------------------------------------------------

    def _ensure_valid_session(self) -> str:
        """Automatically renew token and session before expiration."""
        is_session_expiring = time.time() >= self._session_expires_at - 60
        is_token_expiring = self._token_expires_at > 0 and (time.time() >= self._token_expires_at - 60)

        if not self._active_sid or is_session_expiring or is_token_expiring:
            if self._cached_credentials:
                logger.info("Check Point token/session close to expiration. Automatically renewing via Infinity Portal Gateway...")
                info = self.login(self._cached_credentials)
                self._active_sid = info.get("sid", "")
            else:
                raise CheckPointClientError(401, "Check Point session expired and no cached credentials to renew.", code="SESSION_EXPIRED")
        return self._active_sid

    def logout(self, sid: str = "") -> bool:
        """Terminate the active session on Check Point and discard local tokens."""
        active_sid = sid or self._active_sid
        target_url = self._target_mgmt_url
        self._active_sid = ""
        self._bearer_token = ""
        self._token_expires_at = 0.0
        self._session_expires_at = 0.0
        self._target_mgmt_url = ""
        self._cached_credentials = {}
        self._confirmed_capabilities.clear()

        if not active_sid or not target_url:
            return True

        logout_endpoint = f"{target_url.rstrip('/')}/logout"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-chkp-sid": active_sid.strip(),
        }
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"

        try:
            with self._create_client() as client:
                resp = client.post(logout_endpoint, json={}, headers=headers)
                return resp.status_code == 200
        except Exception as e:
            logger.warning("Error logging out of Check Point: %s", e)
            return False

    # -----------------------------------------------------------------------
    # Command Dispatch with Session Header
    # -----------------------------------------------------------------------

    def send_command(
        self,
        command: str,
        payload: dict[str, Any] | None = None,
        sid: str | dict[str, Any] = "",
    ) -> dict[str, Any]:
        """Send a verified read-only command with the returned session ID in the documented header."""
        _validate_command_safety(command)

        active_sid = ""
        if isinstance(sid, dict):
            active_sid = self.login(sid).get("sid", "")
        elif sid:
            active_sid = str(sid).strip()
        else:
            active_sid = self._ensure_valid_session()

        if not active_sid:
            raise CheckPointClientError(401, "No active Check Point session token ('sid'). Login required.", code="NO_SESSION")

        if not self._target_mgmt_url:
            if self.mgmt_host:
                self._target_mgmt_url = f"https://{self.mgmt_host.replace('https://', '').rstrip('/')}/web_api"
            elif self.service_id:
                gw, _ = self._resolve_portal_endpoints(self.auth_url)
                self._target_mgmt_url, _ = self._resolve_environment_base(gw, self.service_id)
            else:
                raise CheckPointClientError(400, "No active Smart-1 Cloud environment URL established.", code="NO_ENV_URL")

        url = f"{self._target_mgmt_url.rstrip('/')}/{command.strip().lstrip('/')}"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-chkp-sid": active_sid,
        }
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"

        body = payload or {}
        start_time = time.time()

        try:
            with self._create_client() as client:
                resp = client.post(url, json=body, headers=headers)
                latency = int((time.time() - start_time) * 1000)

                if resp.status_code == 200:
                    data = resp.json()
                    return {"success": True, "data": data, "latency_ms": latency}
                elif resp.status_code in (401, 403):
                    err_json = resp.json() if "application/json" in resp.headers.get("Content-Type", "") else {}
                    err_msg = str(err_json.get("message", resp.text[:140]))
                    raise CheckPointClientError(
                        resp.status_code,
                        f"Check Point Session expired or unauthorized for '{command}': {err_msg}",
                        code="SESSION_UNAUTHORIZED",
                    )
                elif resp.status_code == 429:
                    raise CheckPointClientError(
                        429,
                        "Rate Limited / Server Busy: Check Point Management API is currently rate limiting requests or busy.",
                        code="RATE_LIMITED",
                    )
                else:
                    raise CheckPointClientError(
                        resp.status_code,
                        f"Check Point command '{command}' failed with HTTP {resp.status_code}: {resp.text[:140]}",
                    )
        except httpx.TimeoutException:
            raise CheckPointClientError(504, f"Command '{command}' timed out on Smart-1 Cloud gateway.", code="TIMEOUT")
        except httpx.ConnectError as e:
            raise CheckPointClientError(502, f"Network or TLS error during '{command}': {str(e)}", code="TLS_OR_NETWORK_ERROR")

    # -----------------------------------------------------------------------
    # Verification & Capability Probe
    # -----------------------------------------------------------------------

    def get_capability_panel_data(self) -> list[dict[str, Any]]:
        """Return structured capability list for sidebar UI and diagnostics."""
        items = [
            ("Management API Access", "management_api_reachable"),
            ("Security Gateways & Servers", "gateways_visible"),
            ("Access & NAT Policy Rules", "rules_visible"),
            ("Threat Prevention Profiles", "threat_profiles_visible"),
            ("Security Log Search", "logs_accessible"),
            ("Infinity Portal Gateway Telemetry", "portal_telemetry_accessible"),
        ]
        panel = []
        for label, cap_key in items:
            is_ok = cap_key in self._confirmed_capabilities
            reason = self.capability_reasons.get(cap_key, "Accessible" if is_ok else "Unavailable")
            panel.append({
                "label": label,
                "capability": cap_key,
                "accessible": is_ok,
                "reason": reason,
            })
        return panel

    def verify_connection(self, credentials: dict[str, Any], **kwargs: Any) -> ConnectionStatus:
        """Probe Check Point credentials, read-only session, and component capabilities."""
        start = time.time()
        caps: dict[str, Any] = {
            "authenticated": False,
            "read_only": False,
            "management_api_reachable": False,
            "gateways_visible": False,
            "rules_visible": False,
            "nat_rules_visible": False,
            "threat_profiles_visible": False,
            "logs_accessible": False,
            "domains_visible": False,
            "portal_telemetry_accessible": False,
            "other_service_accessible": False,
        }

        try:
            login_info = self.login(credentials)
            sid = login_info.get("sid", "")
            caps["authenticated"] = True
            caps["read_only"] = login_info.get("read_only", True)
            method_used = login_info.get("auth_method", "Infinity Portal Gateway API Key")
            service_id = login_info.get("service_id") or self.service_id
            access_tier = login_info.get("access_level", self.access_level)

            if access_tier == ACCESS_LEVEL_PORTAL_LEVEL:
                caps["portal_telemetry_accessible"] = True
                self._confirmed_capabilities = {"portal_telemetry_accessible"}
                latency_ms = int((time.time() - start) * 1000)
                msg = (
                    f"Connected to Check Point Infinity Portal in {latency_ms}ms at Portal Level (Limited). "
                    "Environment/Service ID is optional; providing it unlocks full management API access (gateways, rules, logs)."
                )
                return ConnectionStatus(
                    connected=True,
                    provider=self.provider_name,
                    target="Infinity Portal Gateway [Smart-1 Cloud]",
                    authenticated=True,
                    read_only=True,
                    latency_ms=latency_ms,
                    message=msg,
                    capabilities=caps,
                    details={
                        "access_level": ACCESS_LEVEL_PORTAL_LEVEL,
                        "auth_method": method_used,
                        "login_time": login_info.get("login_time"),
                        "service_id": "",
                        "discovered_service_id": self.discovered_service_id,
                        "auth_url": self.auth_url,
                        "registered_tools": [t.name for t in self.get_tools()],
                        "capability_reasons": dict(self.capability_reasons),
                        "capability_panel": self.get_capability_panel_data(),
                        "upgrade_hint": "An identifier, not a secret; found in Smart-1 Cloud under Settings > API & SmartConsole, or ask whoever manages the portal.",
                    },
                )

            # FULL MANAGEMENT ACCESS PROBING
            caps["management_api_reachable"] = True
            caps["portal_telemetry_accessible"] = True
            self.capability_reasons["management_api_reachable"] = "Accessible"
            self.capability_reasons["portal_telemetry_accessible"] = "Accessible"

            # Probe 1: Gateways & Servers
            try:
                gw_res = self.send_command("show-gateways-and-servers", {"limit": 1}, sid)
                caps["gateways_visible"] = gw_res.get("success", False)
                total_gw = gw_res.get("data", {}).get("total", 0)
                caps["gateways_count"] = total_gw
                self.capability_reasons["gateways_visible"] = "Accessible" if caps["gateways_visible"] else "Administrator profile lacks gateway view permission"
            except Exception as e:
                logger.info("Gateway probe failed: %s", e)
                self.capability_reasons["gateways_visible"] = "Administrator profile lacks gateway view permission"

            # Probe 2: Access Rulebase
            try:
                rule_res = self.send_command("show-access-rulebase", {"name": "Network", "limit": 1}, sid)
                caps["rules_visible"] = rule_res.get("success", False)
                self.capability_reasons["rules_visible"] = "Accessible" if caps["rules_visible"] else "Administrator profile lacks policy view permission"
            except Exception as e:
                logger.info("Access Rulebase probe failed: %s", e)
                self.capability_reasons["rules_visible"] = "Administrator profile lacks policy view permission"

            # Probe 2b: NAT Rulebase
            try:
                nat_res = self.send_command("show-nat-rulebase", {"limit": 1}, sid)
                caps["nat_rules_visible"] = nat_res.get("success", False)
            except Exception as e:
                logger.info("NAT Rulebase probe failed: %s", e)

            # Probe 3: Threat Profiles
            try:
                threat_res = self.send_command("show-threat-rulebase", {"name": "Threat Prevention", "limit": 1}, sid)
                caps["threat_profiles_visible"] = threat_res.get("success", False)
                self.capability_reasons["threat_profiles_visible"] = "Accessible" if caps["threat_profiles_visible"] else "Threat Prevention blade not enabled"
            except Exception as e:
                logger.info("Threat Prevention probe failed: %s", e)
                self.capability_reasons["threat_profiles_visible"] = "Threat Prevention blade not enabled"

            # Probe 4: Log Access
            try:
                log_res = self.send_command("show-logs", {"new-query": {"time-frame": "last-hour", "max-logs-per-request": 1}}, sid)
                caps["logs_accessible"] = log_res.get("success", False)
                self.capability_reasons["logs_accessible"] = "Accessible" if caps["logs_accessible"] else "Key's role lacks log access"
            except Exception as e:
                logger.info("Log probe failed: %s", e)
                self.capability_reasons["logs_accessible"] = "Key's role lacks log access"

            # Probe 5: Domains
            try:
                dom_res = self.send_command("show-domains", {"limit": 1}, sid)
                caps["domains_visible"] = dom_res.get("success", False)
                self.capability_reasons["domains_visible"] = "Accessible" if caps["domains_visible"] else "Multi-domain management not active"
            except Exception:
                self.capability_reasons["domains_visible"] = "Single domain environment"

            # Update confirmed capabilities for dynamic tool registration
            self._confirmed_capabilities = {k for k, v in caps.items() if v is True}

            latency_ms = int((time.time() - start) * 1000)
            target_desc = f"Smart-1 Cloud [{service_id or 'Cloud'}]"

            msg = (
                f"Connected to Check Point {target_desc} in {latency_ms}ms via {method_used} (Full Management Access). "
                f"Read-Only Session Active. Confirmed: "
                f"Gateways={'Yes' if caps['gateways_visible'] else 'No'}, "
                f"Rules={'Yes' if caps['rules_visible'] else 'No'}, "
                f"Logs={'Yes' if caps['logs_accessible'] else 'No'}."
            )

            return ConnectionStatus(
                connected=True,
                provider=self.provider_name,
                target=target_desc,
                authenticated=True,
                read_only=caps["read_only"],
                latency_ms=latency_ms,
                message=msg,
                capabilities=caps,
                details={
                    "sid": sid,
                    "access_level": ACCESS_LEVEL_FULL_MANAGEMENT,
                    "auth_method": method_used,
                    "login_time": login_info.get("login_time"),
                    "service_id": service_id,
                    "discovered_service_id": self.discovered_service_id,
                    "auth_url": self.auth_url,
                    "target_mgmt_url": self._target_mgmt_url,
                    "registered_tools": [t.name for t in self.get_tools()],
                    "capability_reasons": dict(self.capability_reasons),
                    "capability_panel": self.get_capability_panel_data(),
                    "key_scope_notice": "Account API Key (Service: Quantum Smart-1 Cloud). User-scoped keys UNVERIFIED for automated management.",
                },
            )

        except CheckPointClientError as e:
            latency_ms = int((time.time() - start) * 1000)
            if e.code == "WRONG_SERVICE_KEY":
                self.access_level = ACCESS_LEVEL_OTHER_SERVICE
                self.detected_service = "Harmony Endpoint / CloudGuard"
                self._confirmed_capabilities = {"other_service_accessible"}
                caps["authenticated"] = True
                caps["read_only"] = True
                caps["other_service_accessible"] = True
                self.capability_reasons = {
                    "management_api_reachable": "Service not supported by this key",
                    "gateways_visible": "Service not supported by this key",
                    "rules_visible": "Service not supported by this key",
                    "threat_profiles_visible": "Service not supported by this key",
                    "logs_accessible": "Service not supported by this key",
                    "domains_visible": "Service not supported by this key",
                    "other_service_accessible": "Accessible",
                }
                return ConnectionStatus(
                    connected=True,
                    provider=self.provider_name,
                    target=f"Infinity Portal [{self.detected_service}]",
                    authenticated=True,
                    read_only=True,
                    latency_ms=latency_ms,
                    message=e.message,
                    capabilities=caps,
                    details={
                        "access_level": ACCESS_LEVEL_OTHER_SERVICE,
                        "detected_service": self.detected_service,
                        "registered_tools": [t.name for t in self.get_tools()],
                        "capability_reasons": dict(self.capability_reasons),
                        "capability_panel": self.get_capability_panel_data(),
                        "error_code": e.code,
                    },
                )

            self.access_level = ACCESS_LEVEL_NOT_AUTHENTICATED
            self._confirmed_capabilities.clear()
            return ConnectionStatus(
                connected=False,
                provider=self.provider_name,
                target=f"Smart-1 Cloud [{self.service_id or 'Cloud'}]",
                authenticated=False,
                read_only=True,
                latency_ms=latency_ms,
                message=e.message,
                capabilities=caps,
                details={"error_code": e.code, "access_level": ACCESS_LEVEL_NOT_AUTHENTICATED},
            )
        except Exception as ex:
            latency_ms = int((time.time() - start) * 1000)
            self.access_level = ACCESS_LEVEL_NOT_AUTHENTICATED
            self._confirmed_capabilities.clear()
            return ConnectionStatus(
                connected=False,
                provider=self.provider_name,
                target=f"Smart-1 Cloud [{self.service_id or 'Cloud'}]",
                authenticated=False,
                read_only=True,
                latency_ms=latency_ms,
                message=f"Unexpected connection error: {str(ex)}",
                capabilities=caps,
                details={"error_code": "UNEXPECTED", "access_level": ACCESS_LEVEL_NOT_AUTHENTICATED},
            )

    # -----------------------------------------------------------------------
    # Dynamic Capability-Driven Tool Registration
    # -----------------------------------------------------------------------

    def get_tools(self) -> list[ToolDefinition]:
        """Return allowed read-only tools for Check Point, filtered by verified capabilities."""
        if not self._confirmed_capabilities:
            return []

        all_tools = [
            ToolDefinition(
                name="chkp_list_gateways",
                description="List all security gateways and management servers in the Check Point estate with status and versions.",
                provider=self.provider_name,
                parameters={
                    "limit": {"type": "integer", "description": "Max results to return (capped at 50).", "default": 20},
                },
            ),
            ToolDefinition(
                name="chkp_lookup_object",
                description="Look up a host, network, or IP object in the Check Point database.",
                provider=self.provider_name,
                parameters={
                    "identifier": {"type": "string", "description": "IP address, subnet, or object name.", "required": True},
                },
            ),
            ToolDefinition(
                name="chkp_find_access_rules",
                description="Find access control and NAT rules matching a specific IP, subnet, or service.",
                provider=self.provider_name,
                parameters={
                    "search_term": {"type": "string", "description": "IP address, host name, or service to filter rules by.", "required": True},
                    "layer": {"type": "string", "description": "Access layer name (defaults to 'Network').", "default": "Network"},
                    "include_nat": {"type": "boolean", "description": "Whether to also search the NAT rulebase (defaults to True).", "default": True},
                    "limit": {"type": "integer", "description": "Max rules to inspect (capped at 50).", "default": 25},
                },
            ),
            ToolDefinition(
                name="chkp_show_threat_protection",
                description="Show threat prevention profiles and threat rulebase configuration.",
                provider=self.provider_name,
                parameters={
                    "profile_name": {"type": "string", "description": "Specific threat profile name (optional)."},
                },
            ),
            ToolDefinition(
                name="chkp_search_logs",
                description="Search firewall and threat logs with time range, filter criteria, and server-side aggregation.",
                provider=self.provider_name,
                parameters={
                    "time_range": {"type": "string", "description": "Time window: 'last-hour', 'today', 'yesterday', 'last-7-days', or explicit ISO date."},
                    "filter": {"type": "string", "description": "Check Point log filter expression, e.g. 'action:Drop', 'src:192.168.1.10'."},
                    "blade": {"type": "string", "description": "Filter by blade name, e.g. 'Network Security', 'Threat Prevention'."},
                    "limit": {"type": "integer", "description": "Max logs to retrieve (capped at 100 per request, max 500).", "default": 50},
                },
            ),
            ToolDefinition(
                name="chkp_get_service_status",
                description="Inspect Check Point Infinity Portal service health, regional gateway endpoint, and connection tier.",
                provider=self.provider_name,
                parameters={},
            ),
            ToolDefinition(
                name="chkp_other_service_info",
                description="Report telemetry capabilities and configuration guidance for non-Smart-1 Cloud Infinity service keys (e.g. Harmony Endpoint, CloudGuard).",
                provider=self.provider_name,
                parameters={},
            ),
        ]

        registered = []
        for t in all_tools:
            req_cap = TOOL_CAPABILITY_MAP.get(t.name)
            if req_cap and req_cap in self._confirmed_capabilities:
                registered.append(t)
        return registered

    # -----------------------------------------------------------------------
    # Tool Execution
    # -----------------------------------------------------------------------

    def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        credentials: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute a read-only Check Point tool call with active session management."""
        req_cap = TOOL_CAPABILITY_MAP.get(tool_name)
        if self._confirmed_capabilities and req_cap and req_cap not in self._confirmed_capabilities:
            reason = self.capability_reasons.get(req_cap, "not accessible with current credentials")
            raise CheckPointClientError(
                403,
                f"Tool '{tool_name}' is unavailable because '{req_cap}' is restricted ({reason}). Contact your Check Point administrator.",
                code="CAPABILITY_UNAVAILABLE",
            )

        # Handle portal-level telemetry tool
        if tool_name == "chkp_get_service_status":
            return {
                "status": "online",
                "access_level": self.access_level,
                "regional_gateway": self.auth_url,
                "service_id": self.service_id,
                "discovered_service_id": self.discovered_service_id,
                "management_tools_unlocked": self.access_level == ACCESS_LEVEL_FULL_MANAGEMENT,
                "message": (
                    "Full management access active." if self.access_level == ACCESS_LEVEL_FULL_MANAGEMENT
                    else "Connected at portal level (limited). Add an Environment/Service ID in the sidebar to unlock gateway, policy, and log tools."
                ),
            }

        # Handle other-service inspection tool
        if tool_name == "chkp_other_service_info":
            return {
                "detected_service": self.detected_service,
                "access_level": ACCESS_LEVEL_OTHER_SERVICE,
                "guidance": (
                    f"This API key was issued for {self.detected_service}. To access Quantum Smart-1 Cloud firewall tools, "
                    "a portal administrator must generate an Account API Key under Service: Quantum Smart-1 Cloud."
                ),
                "available_service_capabilities": [
                    "Endpoint posture and quarantine telemetry" if "endpoint" in self.detected_service.lower() else "Cloud posture telemetry"
                ],
            }

        sid = kwargs.get("sid") or credentials.get("sid")
        if not sid:
            login_info = self.login(credentials)
            sid = login_info.get("sid", "")

        if tool_name == "chkp_list_gateways":
            limit = min(int(arguments.get("limit", 20)), 50)
            res = self.send_command("show-gateways-and-servers", {"limit": limit, "details-level": "standard"}, sid)
            data = res.get("data", {})
            objects = data.get("objects", [])
            total = data.get("total", len(objects))

            rows = []
            for obj in objects:
                ipv4 = obj.get("ipv4-address") or "N/A"
                gw_type = obj.get("type") or "gateway"
                version = obj.get("version") or "Check Point Gaia"
                status = obj.get("status") or "Online"
                rows.append({
                    "Name": obj.get("name", "Gateway"),
                    "IPv4 Address": ipv4,
                    "Type": gw_type,
                    "OS / Version": version,
                    "Status": status,
                })

            return {
                "provider": self.provider_name,
                "tool_name": tool_name,
                "endpoint": "/app/maas/api/v2/environments/.../web_api/show-gateways-and-servers",
                "parameters": arguments,
                "records": rows,
                "result_count": len(rows),
                "total_count": total,
                "latency_ms": res.get("latency_ms", 0),
            }

        elif tool_name == "chkp_lookup_object":
            ident = arguments.get("identifier", "").strip()
            host_res = None
            try:
                host_res = self.send_command("show-hosts", {"filter": ident, "limit": 10}, sid)
            except Exception:
                pass

            net_res = None
            try:
                net_res = self.send_command("show-networks", {"filter": ident, "limit": 10}, sid)
            except Exception:
                pass

            records = []
            if host_res and host_res.get("success"):
                for h in host_res.get("data", {}).get("objects", []):
                    records.append({
                        "Name": h.get("name"),
                        "Type": "Host",
                        "IPv4 Address": h.get("ipv4-address") or "N/A",
                        "NAT": "Configured" if h.get("nat-settings") else "None",
                        "Comments": str(h.get("comments") or "")[:60],
                    })

            if net_res and net_res.get("success"):
                for n in net_res.get("data", {}).get("objects", []):
                    records.append({
                        "Name": n.get("name"),
                        "Type": "Network Subnet",
                        "Subnet": f"{n.get('subnet4')}/{n.get('mask-length4')}",
                        "NAT": "Configured" if n.get("nat-settings") else "None",
                        "Comments": str(n.get("comments") or "")[:60],
                    })

            return {
                "provider": self.provider_name,
                "tool_name": tool_name,
                "endpoint": "Smart-1 Cloud show-hosts & show-networks",
                "parameters": arguments,
                "records": records,
                "result_count": len(records),
                "total_count": len(records),
                "latency_ms": (host_res.get("latency_ms", 0) if host_res else 0),
            }

        elif tool_name == "chkp_find_access_rules":
            search_term = arguments.get("search_term", "").strip()
            layer = arguments.get("layer", "Network")
            limit = min(int(arguments.get("limit", 25)), 50)
            include_nat = bool(arguments.get("include_nat", True))

            payload = {
                "name": layer,
                "filter": search_term,
                "limit": limit,
                "details-level": "standard",
            }
            res = self.send_command("show-access-rulebase", payload, sid)
            rulebase = res.get("data", {}).get("rulebase", [])
            total = res.get("data", {}).get("total", len(rulebase))

            rules = []
            for item in rulebase:
                rule = item.get("rule", item)
                action = rule.get("action", {}).get("name", "Unknown") if isinstance(rule.get("action"), dict) else str(rule.get("action", ""))
                rule_num = rule.get("rule-number") or rule.get("name") or "Rule"
                sources = [s.get("name", "Any") for s in rule.get("source", [])] if isinstance(rule.get("source"), list) else ["Any"]
                destinations = [d.get("name", "Any") for d in rule.get("destination", [])] if isinstance(rule.get("destination"), list) else ["Any"]
                services = [svc.get("name", "Any") for svc in rule.get("service", [])] if isinstance(rule.get("service"), list) else ["Any"]

                rules.append({
                    "Rule #": str(rule_num),
                    "Type": "Access Rule",
                    "Name": rule.get("name") or "Untitled",
                    "Action": action,
                    "Source": ", ".join(sources[:3]),
                    "Destination": ", ".join(destinations[:3]),
                    "Service / Port": ", ".join(services[:3]),
                    "Track / Log": rule.get("track", {}).get("type", {}).get("name", "Log") if isinstance(rule.get("track"), dict) else "Log",
                })

            if include_nat:
                try:
                    nat_res = self.send_command("show-nat-rulebase", {"filter": search_term, "limit": 10}, sid)
                    nat_rules = nat_res.get("data", {}).get("rulebase", [])
                    for item in nat_rules:
                        rule = item.get("rule", item)
                        rules.append({
                            "Rule #": str(rule.get("rule-number", "NAT")),
                            "Type": "NAT Rule",
                            "Name": rule.get("name") or "NAT Rule",
                            "Action": "NAT",
                            "Source": str(rule.get("original-source", {}).get("name", "Any")),
                            "Destination": str(rule.get("original-destination", {}).get("name", "Any")),
                            "Service / Port": str(rule.get("original-service", {}).get("name", "Any")),
                            "Track / Log": "Log",
                        })
                except Exception:
                    pass

            return {
                "provider": self.provider_name,
                "tool_name": tool_name,
                "endpoint": "Smart-1 Cloud show-access-rulebase & show-nat-rulebase",
                "parameters": arguments,
                "records": rules,
                "result_count": len(rules),
                "total_count": total,
                "latency_ms": res.get("latency_ms", 0),
            }

        elif tool_name == "chkp_show_threat_protection":
            res = self.send_command("show-threat-rulebase", {"name": "Threat Prevention", "limit": 20}, sid)
            rulebase = res.get("data", {}).get("rulebase", [])
            profiles = []
            for r in rulebase:
                action = r.get("action", {}).get("name", "Prevent") if isinstance(r.get("action"), dict) else "Active"
                profiles.append({
                    "Rule Name": r.get("name") or "Threat Rule",
                    "Action Profile": action,
                    "Protected Scope": str(r.get("protected-scope", "All Gateways")),
                    "Track": r.get("track", {}).get("name", "Log") if isinstance(r.get("track"), dict) else "Log",
                })

            return {
                "provider": self.provider_name,
                "tool_name": tool_name,
                "endpoint": "Smart-1 Cloud show-threat-rulebase",
                "parameters": arguments,
                "records": profiles,
                "result_count": len(profiles),
                "total_count": len(profiles),
                "latency_ms": res.get("latency_ms", 0),
            }

        elif tool_name == "chkp_search_logs":
            requested_limit = int(arguments.get("limit", 50))
            total_limit = min(max(1, requested_limit), 500)
            batch_size = min(total_limit, 100)

            time_range = arguments.get("time_range", "last-24-hours")
            log_filter = arguments.get("filter", "")
            blade = arguments.get("blade")
            if blade:
                log_filter = f"{log_filter} blade:\"{blade}\"".strip()

            chkp_timeframe, lusaka_range, _ = _format_lusaka_window(time_range)

            payload = {
                "new-query": {
                    "time-frame": chkp_timeframe,
                    "filter": log_filter,
                    "max-logs-per-request": batch_size,
                }
            }

            res = self.send_command("show-logs", payload, sid)
            logs_raw = res.get("data", {}).get("logs", [])
            total_logs = res.get("data", {}).get("total", len(logs_raw))

            action_counts: dict[str, int] = {}
            src_counts: dict[str, int] = {}
            dst_counts: dict[str, int] = {}
            blade_counts: dict[str, int] = {}

            formatted_logs = []
            for l in logs_raw[:total_limit]:
                action = l.get("action") or "Unknown"
                action_counts[action] = action_counts.get(action, 0) + 1

                src = l.get("src") or "Unknown"
                src_counts[src] = src_counts.get(src, 0) + 1

                dst = l.get("dst") or "Unknown"
                dst_counts[dst] = dst_counts.get(dst, 0) + 1

                bld = l.get("blade") or "Firewall"
                blade_counts[bld] = blade_counts.get(bld, 0) + 1

                formatted_logs.append({
                    "Timestamp": l.get("time") or "N/A",
                    "Action": action,
                    "Source IP": src,
                    "Destination IP": dst,
                    "Service": str(l.get("service") or l.get("s_port") or "N/A"),
                    "Rule": str(l.get("rule_name") or l.get("rule") or "N/A"),
                    "Blade": bld,
                    "Gateway": l.get("orig") or "Check Point",
                })

            is_truncated = total_logs > len(formatted_logs)
            return {
                "provider": self.provider_name,
                "tool_name": tool_name,
                "endpoint": "Smart-1 Cloud show-logs",
                "parameters": arguments,
                "resolved_time_range_lusaka": lusaka_range,
                "records": formatted_logs,
                "result_count": len(formatted_logs),
                "total_count": total_logs,
                "truncated": is_truncated,
                "truncation_note": f"Showing {len(formatted_logs)} of {total_logs} logs" if is_truncated else f"Showing {len(formatted_logs)} logs",
                "aggregations": {
                    "actions": action_counts,
                    "blades": blade_counts,
                    "top_sources": sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5],
                    "top_destinations": sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:5],
                },
                "latency_ms": res.get("latency_ms", 0),
            }

        else:
            raise CheckPointClientError(404, f"Check Point tool '{tool_name}' not recognized.")
