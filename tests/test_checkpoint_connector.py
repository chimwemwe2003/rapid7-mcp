"""Unit tests for Pebbles Check Point Security Management & Quantum Smart-1 Cloud Connector.

Comprehensive test coverage across:
1. Authentication Methods A, B, and C (mocked):
   - Method A: Smart-1 Cloud / Management API URL + API Key
   - Method B: Infinity Portal API Key (Client ID + Secret Key) -> JWT token -> Smart-1 Cloud
   - Method C: Username + Password against Management URL
2. Wrong-Service Key Error detection (key for Harmony Endpoint/Email/CloudGuard)
3. Automatic session and JWT token renewal
4. Plain-language SOC diagnostic error mappings:
   - Wrong credentials / revoked / expired
   - Management API IP blocked (instruction to admin)
   - Insufficient role permissions (e.g. System Data domain)
   - Invalid Service ID or Portal Region
   - Network or TLS failure
   - Rate limiting or server busy
5. Capability-driven tool registration (tools absent when capability probe fails)
6. Command allowlist and strict write blocking
7. Log scrubbing and credential isolation
8. Log search bounds, max-logs-per-request, Africa/Lusaka timestamp localization
9. Per-user credential and session isolation
"""

import json
import time
from typing import Any
import httpx
import pytest

from rapid7_mcp.audit import scrub_sensitive_data
from rapid7_mcp.agent import reset_session_env_id_mentioned, run_pebbles_agent
from rapid7_mcp.connectors.checkpoint import (
    ACCESS_LEVEL_FULL_MANAGEMENT,
    ACCESS_LEVEL_NOT_AUTHENTICATED,
    ACCESS_LEVEL_OTHER_SERVICE,
    ACCESS_LEVEL_PORTAL_LEVEL,
    CheckPointClientError,
    CheckPointConnector,
)
from rapid7_mcp.connectors.cross_source import query_cross_source


class MockTransport(httpx.BaseTransport):
    """Mock HTTP transport for simulating Check Point and Infinity Portal responses."""

    def __init__(self, handler):
        self.handler = handler

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self.handler(request)


# ---------------------------------------------------------------------------
# 1. Authentication Methods A, B, and C
# ---------------------------------------------------------------------------

def test_checkpoint_login_method_a():
    """Method A: Smart-1 Cloud / Management API URL + API key logging in read-only."""
    login_payloads = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/web_api/login"):
            data = json.loads(request.content.decode())
            login_payloads.append(data)
            return httpx.Response(200, json={"sid": "mock-chkp-sid-method-a", "read-only": True, "session-timeout": 600})
        return httpx.Response(404, json={"message": "Not found"})

    connector = CheckPointConnector(mgmt_host="corp-gw.maas.checkpoint.com")
    connector._transport = MockTransport(mock_handler)

    login_info = connector.login({"api_key": "secret-admin-key-abc", "domain": "SMC_Domain"})
    assert login_info["sid"] == "mock-chkp-sid-method-a"
    assert login_info["read_only"] is True
    assert login_payloads[0]["read-only"] is True
    assert login_payloads[0]["api-key"] == "secret-admin-key-abc"
    assert login_payloads[0]["domain"] == "SMC_Domain"


def test_checkpoint_login_method_b_portal_jwt():
    """Method B: Infinity Portal API Key (Client ID + Secret Key) -> JWT token -> Smart-1 Cloud."""
    portal_auth_called = []
    smart1_login_called = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        # Step 1: Infinity Portal /auth/external
        if "/auth/external" in request.url.path:
            body = json.loads(request.content.decode())
            portal_auth_called.append(body)
            assert body["clientId"] == "my-client-id-123"
            assert body["accessKey"] == "my-secret-key-456"
            return httpx.Response(200, json={"data": {"token": "mock-jwt-bearer-token-xyz"}})

        # Step 2: Smart-1 Cloud /web_api/login
        if "/web_api/login" in request.url.path:
            auth_header = request.headers.get("Authorization")
            assert auth_header == "Bearer mock-jwt-bearer-token-xyz"
            body = json.loads(request.content.decode())
            smart1_login_called.append(body)
            assert body["read-only"] is True
            return httpx.Response(200, json={"sid": "smart1-cloud-sid-789", "read-only": True, "session-timeout": 600})

        return httpx.Response(404, json={"message": "Not found"})

    connector = CheckPointConnector(
        portal_region="eu",
        service_id="smart1-env-uuid-001",
    )
    connector._transport = MockTransport(mock_handler)

    creds = {
        "auth_method": "infinity_portal_api_key",
        "client_id": "my-client-id-123",
        "secret_key": "my-secret-key-456",
        "service_id": "smart1-env-uuid-001",
        "portal_region": "eu",
    }
    login_info = connector.login(creds)
    assert login_info["sid"] == "smart1-cloud-sid-789"
    assert login_info["token"] == "mock-jwt-bearer-token-xyz"
    assert len(portal_auth_called) == 1
    assert len(smart1_login_called) == 1


def test_checkpoint_login_method_c_user_pass():
    """Method C: Username + Password against Management URL logging in read-only."""
    login_payloads = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/web_api/login"):
            data = json.loads(request.content.decode())
            login_payloads.append(data)
            return httpx.Response(200, json={"sid": "mock-userpass-sid", "read-only": True, "session-timeout": 600})
        return httpx.Response(404, json={"message": "Not found"})

    connector = CheckPointConnector(mgmt_host="192.168.1.100")
    connector._transport = MockTransport(mock_handler)

    login_info = connector.login({"user": "sec_analyst", "password": "SuperSecretPassword!", "domain": "Default"})
    assert login_info["sid"] == "mock-userpass-sid"
    assert login_payloads[0]["read-only"] is True
    assert login_payloads[0]["user"] == "sec_analyst"
    assert login_payloads[0]["password"] == "SuperSecretPassword!"


# ---------------------------------------------------------------------------
# 2. Wrong-Service Key Error Handling
# ---------------------------------------------------------------------------

def test_checkpoint_wrong_service_key_error():
    """When an Infinity Portal key belongs to Harmony Endpoint or CloudGuard, explain and halt."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        if "/auth/external" in request.url.path:
            # Token exchange succeeds at the portal level
            return httpx.Response(200, json={"data": {"token": "jwt-harmony-endpoint-token"}})
        if "/web_api/login" in request.url.path:
            # Smart-1 Cloud rejects key as unauthorized for this service
            return httpx.Response(
                403,
                json={"code": "ERR_UNAUTHORIZED_SERVICE", "message": "API key does not have access to Quantum Smart-1 Cloud"},
            )
        return httpx.Response(404, json={})

    connector = CheckPointConnector(service_id="smart1-env-uuid-001")
    connector._transport = MockTransport(mock_handler)

    with pytest.raises(CheckPointClientError) as exc_info:
        connector.login({
            "client_id": "harmony-client-id",
            "secret_key": "harmony-secret-key",
            "service_id": "smart1-env-uuid-001",
        })

    assert exc_info.value.status_code == 403
    assert exc_info.value.code == "WRONG_SERVICE_KEY"
    assert "Wrong Service Key" in exc_info.value.message
    assert "Harmony Endpoint" in exc_info.value.message
    assert "Quantum Smart-1 Cloud" in exc_info.value.message


# ---------------------------------------------------------------------------
# 3. Session and Token Automatic Renewal
# ---------------------------------------------------------------------------

def test_checkpoint_session_auto_renewal():
    """Verify session is renewed before expiration when sending commands."""
    login_count = 0
    command_headers = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal login_count
        if request.url.path.endswith("/web_api/login"):
            login_count += 1
            return httpx.Response(
                200,
                json={"sid": f"sid-generation-{login_count}", "read-only": True, "session-timeout": 600},
            )
        if request.url.path.endswith("/web_api/show-gateways-and-servers"):
            command_headers.append(request.headers.get("x-chkp-sid"))
            return httpx.Response(200, json={"objects": [{"name": "GW-01", "ipv4-address": "10.0.0.1"}]})
        return httpx.Response(404, json={})

    connector = CheckPointConnector(mgmt_host="192.168.1.50")
    connector._transport = MockTransport(mock_handler)

    creds = {"api_key": "auto-renew-test-key"}
    # Initial login
    connector.login(creds)
    assert login_count == 1
    assert connector._active_sid == "sid-generation-1"

    # Send command: uses active session
    res1 = connector.send_command("show-gateways-and-servers", {})
    assert res1["success"] is True
    assert command_headers[-1] == "sid-generation-1"
    assert login_count == 1

    # Simulate expiration by setting expiry to past
    connector._session_expires_at = time.time() - 10

    # Sending next command should auto-renew session
    res2 = connector.send_command("show-gateways-and-servers", {})
    assert res2["success"] is True
    assert login_count == 2
    assert command_headers[-1] == "sid-generation-2"
    assert connector._active_sid == "sid-generation-2"


# ---------------------------------------------------------------------------
# 4. Plain-Language SOC Error Mapping
# ---------------------------------------------------------------------------

def test_checkpoint_error_classifications():
    """Verify plain-language SOC diagnostic mapping for all required error modes."""
    def make_connector(status_code: int, response_json: dict[str, Any]):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code, json=response_json)
        c = CheckPointConnector(mgmt_host="192.168.1.50")
        c._transport = MockTransport(handler)
        return c

    # 1. Invalid credentials / revoked / expired
    c1 = make_connector(400, {"code": "err_login_failed", "message": "Authentication failed"})
    with pytest.raises(CheckPointClientError) as exc1:
        c1.login({"user": "admin", "password": "wrong"})
    assert exc1.value.code == "AUTH_FAILED"
    assert "Invalid Check Point credentials" in exc1.value.message

    # 2. IP Not Allowed (requires administrator action)
    c2 = make_connector(403, {"message": "Client IP not allowed in management server API configuration"})
    with pytest.raises(CheckPointClientError) as exc2:
        c2.login({"api_key": "valid-key"})
    assert exc2.value.code == "IP_BLOCKED"
    assert "Management API Access Blocked by IP" in exc2.value.message
    assert "Trusted Clients" in exc2.value.message

    # 3. Insufficient role permissions (e.g. System Data domain or blade permissions)
    c3 = make_connector(403, {"message": "Administrator profile lacks access to System Data domain"})
    with pytest.raises(CheckPointClientError) as exc3:
        c3.login({"api_key": "valid-key"})
    assert exc3.value.code == "INSUFFICIENT_PERMISSIONS"
    assert "Insufficient Role Permissions" in exc3.value.message

    # 4. Rate Limiting (429)
    c4 = make_connector(429, {"message": "Too many requests"})
    with pytest.raises(CheckPointClientError) as exc4:
        c4.login({"api_key": "valid-key"})
    assert exc4.value.code == "RATE_LIMITED"
    assert "Rate Limited / Server Busy" in exc4.value.message


def test_checkpoint_credentials_lost_error():
    """Verify CREDENTIALS_LOST is raised when Secret Key or Client ID is missing/lost."""
    connector = CheckPointConnector()
    # Missing secret key
    with pytest.raises(CheckPointClientError) as exc_info:
        connector.login({
            "client_id": "portal-client-id-001",
            "service_id": "service-uuid-123",
            "auth_url": "https://cloudinfra-gw.portal.checkpoint.com",
        })
    assert exc_info.value.code == "CREDENTIALS_LOST"
    assert "Secret or Authentication URL lost" in exc_info.value.message
    assert "portal administrator must generate a new Account API key" in exc_info.value.message


def test_checkpoint_wrong_regional_auth_url_error():
    """Verify WRONG_REGIONAL_AUTH_URL is raised on 404 endpoint or network connect failure."""
    # Sub-case A: Regional gateway 404 on /auth/external
    def mock_handler_404(request: httpx.Request) -> httpx.Response:
        if "/auth/external" in request.url.path:
            return httpx.Response(404, json={"message": "Endpoint not found"})
        return httpx.Response(500)

    c1 = CheckPointConnector(auth_url="https://cloudinfra-gw-wrong.portal.checkpoint.com")
    c1._transport = MockTransport(mock_handler_404)
    with pytest.raises(CheckPointClientError) as exc1:
        c1.login({
            "client_id": "cid",
            "secret_key": "skey",
            "service_id": "sid",
            "auth_url": "https://cloudinfra-gw-wrong.portal.checkpoint.com",
        })
    assert exc1.value.code == "WRONG_REGIONAL_AUTH_URL"
    assert "Wrong regional Authentication URL" in exc1.value.message
    assert "Verify that the regional gateway matches" in exc1.value.message

    # Sub-case B: ConnectError reaching regional gateway
    def mock_handler_connect_err(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Regional gateway DNS resolution failed")

    c2 = CheckPointConnector(auth_url="https://cloudinfra-gw-unreachable.portal.checkpoint.com")
    c2._transport = MockTransport(mock_handler_connect_err)
    with pytest.raises(CheckPointClientError) as exc2:
        c2.login({
            "client_id": "cid",
            "secret_key": "skey",
            "service_id": "sid",
            "auth_url": "https://cloudinfra-gw-unreachable.portal.checkpoint.com",
        })
    assert exc2.value.code == "WRONG_REGIONAL_AUTH_URL"
    assert "Failed to establish a secure connection" in exc2.value.message


# ---------------------------------------------------------------------------
# Capability-Tiered Connection Tests
# ---------------------------------------------------------------------------

def test_checkpoint_access_level_tools_registration():
    """Verify each access level registers exactly the tools confirmed by its probe."""
    # 1. Full Management Access
    def mock_full(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/auth/external" in path:
            return httpx.Response(200, json={"data": {"token": "jwt-full"}})
        if "/web_api/login" in path:
            return httpx.Response(200, json={"sid": "full-sid", "read-only": True, "session-timeout": 600})
        if "/web_api/show-gateways-and-servers" in path:
            return httpx.Response(200, json={"objects": [{"name": "gw-1"}], "total": 1})
        if "/web_api/show-access-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-nat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-threat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-logs" in path:
            return httpx.Response(200, json={"logs": [], "total": 0})
        if "/web_api/show-domains" in path:
            return httpx.Response(200, json={"objects": []})
        return httpx.Response(404)

    conn_full = CheckPointConnector(auth_url="https://cloudinfra-gw.portal.checkpoint.com", service_id="smart1-uuid-001")
    conn_full._transport = MockTransport(mock_full)
    status_full = conn_full.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": "smart1-uuid-001"})
    assert status_full.connected is True
    assert conn_full.access_level == ACCESS_LEVEL_FULL_MANAGEMENT
    tools_full = [t.name for t in conn_full.get_tools()]
    assert "chkp_list_gateways" in tools_full
    assert "chkp_find_access_rules" in tools_full
    assert "chkp_search_logs" in tools_full
    assert "chkp_get_service_status" in tools_full

    # 2. Portal-Level Access (No Environment ID)
    def mock_portal(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/auth/external" in path:
            return httpx.Response(200, json={"data": {"token": "jwt-portal"}})
        if "/environments" in path:
            return httpx.Response(404, json={"message": "No environments"})
        return httpx.Response(404)

    conn_portal = CheckPointConnector(auth_url="https://cloudinfra-gw.portal.checkpoint.com", service_id="")
    conn_portal._transport = MockTransport(mock_portal)
    status_portal = conn_portal.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": ""})
    assert status_portal.connected is True
    assert conn_portal.access_level == ACCESS_LEVEL_PORTAL_LEVEL
    tools_portal = [t.name for t in conn_portal.get_tools()]
    assert tools_portal == ["chkp_get_service_status"]
    assert "chkp_list_gateways" not in tools_portal
    assert "chkp_search_logs" not in tools_portal

    # 3. Other-Service Access (e.g. Harmony Endpoint)
    def mock_other(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/auth/external" in path:
            return httpx.Response(200, json={"data": {"token": "jwt-other"}})
        if "/web_api/login" in path:
            return httpx.Response(403, json={"code": "ERR_UNAUTHORIZED_SERVICE", "message": "Key belongs to Harmony Endpoint"})
        return httpx.Response(404)

    conn_other = CheckPointConnector(auth_url="https://cloudinfra-gw.portal.checkpoint.com", service_id="smart1-uuid-001")
    conn_other._transport = MockTransport(mock_other)
    status_other = conn_other.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": "smart1-uuid-001"})
    assert status_other.connected is True
    assert conn_other.access_level == ACCESS_LEVEL_OTHER_SERVICE
    tools_other = [t.name for t in conn_other.get_tools()]
    assert tools_other == ["chkp_other_service_info"]
    assert "chkp_list_gateways" not in tools_other

    # 4. Not Authenticated
    conn_unauth = CheckPointConnector()
    assert conn_unauth.access_level == ACCESS_LEVEL_NOT_AUTHENTICATED
    assert conn_unauth.get_tools() == []


def test_checkpoint_no_id_never_calls_management_endpoints():
    """Verify that when no Environment ID is configured, NO management endpoints are ever called."""
    requested_paths = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if "/auth/external" in request.url.path:
            return httpx.Response(200, json={"data": {"token": "jwt-no-id"}})
        if "/environments" in request.url.path:
            return httpx.Response(404)
        return httpx.Response(404)

    connector = CheckPointConnector(service_id="")
    connector._transport = MockTransport(mock_handler)

    status = connector.verify_connection({
        "client_id": "client-123",
        "secret_key": "secret-456",
        "auth_url": "https://cloudinfra-gw.portal.checkpoint.com",
        "service_id": "",
    })

    assert status.connected is True
    assert connector.access_level == ACCESS_LEVEL_PORTAL_LEVEL

    # Verify strictly NO management endpoints were called
    for path in requested_paths:
        assert "/web_api" not in path
        assert "/login" not in path
        assert "show-" not in path


def test_checkpoint_adding_id_later_upgrades_without_reentering_secrets():
    """Verify adding the Environment ID later upgrades the connection in place without re-entering secrets."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/auth/external" in path:
            return httpx.Response(200, json={"data": {"token": "jwt-upgrade-token"}})
        if "/web_api/login" in path:
            return httpx.Response(200, json={"sid": "upgraded-sid-999", "read-only": True, "session-timeout": 600})
        if path.endswith("/environments") or "/environments?" in path:
            return httpx.Response(404)
        if "/web_api/show-gateways-and-servers" in path:
            return httpx.Response(200, json={"objects": [{"name": "gw-upgraded"}], "total": 1})
        if "/web_api/show-access-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-nat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-threat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-logs" in path:
            return httpx.Response(200, json={"logs": [], "total": 0})
        if "/web_api/show-domains" in path:
            return httpx.Response(200, json={"objects": []})
        return httpx.Response(404)

    connector = CheckPointConnector(service_id="")
    connector._transport = MockTransport(mock_handler)

    # Initial verification without service ID -> Portal Level
    status1 = connector.verify_connection({
        "client_id": "stored-client-id",
        "secret_key": "stored-secret-key",
        "service_id": "",
    })
    assert status1.connected is True
    assert connector.access_level == ACCESS_LEVEL_PORTAL_LEVEL
    assert "chkp_list_gateways" not in [t.name for t in connector.get_tools()]

    # Later: user enters ONLY the Environment ID without re-typing secret key
    status2 = connector.verify_connection({
        "service_id": "smart1-uuid-upgraded",
    })
    assert status2.connected is True
    assert connector.access_level == ACCESS_LEVEL_FULL_MANAGEMENT
    assert connector.service_id == "smart1-uuid-upgraded"
    assert "chkp_list_gateways" in [t.name for t in connector.get_tools()]


def test_checkpoint_discovery_succeeds_fails_and_unsupported():
    """Verify discovery flow behavior when discovery succeeds, fails, or is unsupported."""
    # Subcase A: Discovery succeeds
    def mock_disc_ok(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/auth/external" in path:
            return httpx.Response(200, json={"data": {"token": "jwt-disc"}})
        if "/environments" in path:
            return httpx.Response(200, json={"environments": [{"id": "discovered-env-uuid-111"}]})
        if "/web_api/login" in path:
            return httpx.Response(200, json={"sid": "disc-sid", "read-only": True, "session-timeout": 600})
        if "/web_api/show-gateways-and-servers" in path:
            return httpx.Response(200, json={"objects": [{"name": "gw-disc"}], "total": 1})
        if "/web_api/show-access-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-nat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-threat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-logs" in path:
            return httpx.Response(200, json={"logs": [], "total": 0})
        if "/web_api/show-domains" in path:
            return httpx.Response(200, json={"objects": []})
        return httpx.Response(404)

    conn_a = CheckPointConnector(service_id="")
    conn_a._transport = MockTransport(mock_disc_ok)
    status_a = conn_a.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": ""})
    assert status_a.connected is True
    assert conn_a.access_level == ACCESS_LEVEL_FULL_MANAGEMENT
    assert conn_a.discovered_service_id == "discovered-env-uuid-111"

    # Subcase B: Discovery fails (empty list)
    def mock_disc_empty(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/auth/external" in path:
            return httpx.Response(200, json={"data": {"token": "jwt-disc-empty"}})
        if "/environments" in path:
            return httpx.Response(200, json={"environments": []})
        return httpx.Response(404)

    conn_b = CheckPointConnector(service_id="")
    conn_b._transport = MockTransport(mock_disc_empty)
    status_b = conn_b.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": ""})
    assert status_b.connected is True
    assert conn_b.access_level == ACCESS_LEVEL_PORTAL_LEVEL
    assert conn_b.service_id == ""

    # Subcase C: Discovery unsupported (HTTP 404 or 500)
    def mock_disc_unsupported(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/auth/external" in path:
            return httpx.Response(200, json={"data": {"token": "jwt-disc-unsupported"}})
        if "/environments" in path:
            return httpx.Response(500, json={"message": "Not implemented"})
        return httpx.Response(404)

    conn_c = CheckPointConnector(service_id="")
    conn_c._transport = MockTransport(mock_disc_unsupported)
    status_c = conn_c.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": ""})
    assert status_c.connected is True
    assert conn_c.access_level == ACCESS_LEVEL_PORTAL_LEVEL


def test_checkpoint_no_discovery_call_can_be_write():
    """Verify that all discovery probe requests use GET only and never write verbs."""
    methods_used = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if "/environments" in request.url.path or "/service/info" in request.url.path:
            methods_used.append(request.method)
        if "/auth/external" in request.url.path:
            return httpx.Response(200, json={"data": {"token": "jwt-write-safety-check"}})
        return httpx.Response(404)

    connector = CheckPointConnector(service_id="")
    connector._transport = MockTransport(mock_handler)
    connector.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": ""})

    assert len(methods_used) > 0
    for m in methods_used:
        assert m == "GET"
        assert m not in ("POST", "PUT", "PATCH", "DELETE")


def test_checkpoint_capability_panel_reasons():
    """Verify capability panel generates exact one-line reasons per failure mode."""
    # 1. Panel reasons when at portal level (missing Environment ID)
    def mock_portal(request: httpx.Request) -> httpx.Response:
        if "/auth/external" in request.url.path:
            return httpx.Response(200, json={"data": {"token": "jwt-panel-test"}})
        return httpx.Response(404)

    conn_p = CheckPointConnector(service_id="")
    conn_p._transport = MockTransport(mock_portal)
    conn_p.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": ""})
    panel_p = {item["capability"]: item for item in conn_p.get_capability_panel_data()}

    assert panel_p["gateways_visible"]["accessible"] is False
    assert "Needs the Environment/Service ID" in panel_p["gateways_visible"]["reason"]
    assert panel_p["rules_visible"]["accessible"] is False
    assert "Needs the Environment/Service ID" in panel_p["rules_visible"]["reason"]
    assert panel_p["portal_telemetry_accessible"]["accessible"] is True

    # 2. Panel reasons when full management but logs restricted
    def mock_no_logs(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/auth/external" in path:
            return httpx.Response(200, json={"data": {"token": "jwt-logs-test"}})
        if "/web_api/login" in path:
            return httpx.Response(200, json={"sid": "logs-sid", "read-only": True, "session-timeout": 600})
        if "/web_api/show-gateways-and-servers" in path:
            return httpx.Response(200, json={"objects": [{"name": "gw-1"}], "total": 1})
        if "/web_api/show-access-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-nat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-threat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-logs" in path:
            return httpx.Response(403, json={"message": "Permission denied for logs"})
        if "/web_api/show-domains" in path:
            return httpx.Response(200, json={"objects": []})
        return httpx.Response(404)

    conn_nl = CheckPointConnector(service_id="smart1-uuid-001")
    conn_nl._transport = MockTransport(mock_no_logs)
    conn_nl.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": "smart1-uuid-001"})
    panel_nl = {item["capability"]: item for item in conn_nl.get_capability_panel_data()}

    assert panel_nl["gateways_visible"]["accessible"] is True
    assert panel_nl["logs_accessible"]["accessible"] is False
    assert "Key's role lacks log access" in panel_nl["logs_accessible"]["reason"]

    # 3. Panel reasons when key belongs to other service
    def mock_other_svc(request: httpx.Request) -> httpx.Response:
        if "/auth/external" in request.url.path:
            return httpx.Response(200, json={"data": {"token": "jwt-other-svc"}})
        if "/web_api/login" in request.url.path:
            return httpx.Response(403, json={"code": "ERR_UNAUTHORIZED_SERVICE", "message": "Key for wrong service"})
        return httpx.Response(404)

    conn_os = CheckPointConnector(service_id="smart1-uuid-001")
    conn_os._transport = MockTransport(mock_other_svc)
    conn_os.verify_connection({"client_id": "cid", "secret_key": "sec", "service_id": "smart1-uuid-001"})
    panel_os = {item["capability"]: item for item in conn_os.get_capability_panel_data()}

    assert panel_os["gateways_visible"]["accessible"] is False
    assert "Service not supported by this key" in panel_os["gateways_visible"]["reason"]


def test_pebbles_states_limit_once_not_repeatedly():
    """Verify Pebbles states the missing Environment ID limit at most once per session."""
    session_id = "test-session-honesty-001"
    reset_session_env_id_mentioned(session_id)

    conn = CheckPointConnector()
    conn.access_level = ACCESS_LEVEL_PORTAL_LEVEL
    creds = {"client_id": "cid-test", "secret_key": "sec-test"}

    # Query 1: Asks for firewall rules
    resp1 = run_pebbles_agent(
        query="Show Check Point firewall access rules for 10.0.0.1",
        session_id=session_id,
        chkp_connector=conn,
        chkp_credentials=creds,
    )
    # Must explain missing environment ID and how to unlock it
    assert "Environment/Service ID" in resp1.message
    assert "Settings > API & SmartConsole" in resp1.message
    assert "portal administrator" in resp1.message
    assert "Rapid7" in resp1.message or "VirusTotal" in resp1.message

    # Query 2: Asks for firewall logs in the same session
    resp2 = run_pebbles_agent(
        query="Search Check Point firewall logs for drops",
        session_id=session_id,
        chkp_connector=conn,
        chkp_credentials=creds,
    )
    # Must NOT repeat the long explanation or instructions
    assert "Environment/Service ID has not been provided" in resp2.message
    assert "Settings > API & SmartConsole" not in resp2.message
    assert "portal administrator" not in resp2.message


def test_cross_source_labels_checkpoint_limited_or_full():
    """Verify cross-source lookups label Check Point as 'limited' or 'full'."""
    # 1. Limited (Portal Level)
    conn_lim = CheckPointConnector()
    conn_lim.access_level = ACCESS_LEVEL_PORTAL_LEVEL
    res_lim = query_cross_source(
        "196.10.20.30",
        client_name="test-client",
        chkp_connector=conn_lim,
        chkp_credentials={"client_id": "c"},
    )
    assert res_lim["checkpoint"]["available"] is True
    assert res_lim["checkpoint"]["access_tier"] == "limited"
    assert "limited" in res_lim["checkpoint"]["notes"].lower()

    # 2. Full Management
    def mock_full_cs(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/web_api/login" in path:
            return httpx.Response(200, json={"sid": "cs-sid", "read-only": True, "session-timeout": 600})
        if "/web_api/show-host" in path or "/web_api/show-network" in path or "/web_api/show-hosts" in path:
            return httpx.Response(200, json={"objects": [{"name": "host-196-10-20-30"}]})
        if "/web_api/show-access-rulebase" in path:
            return httpx.Response(200, json={"rulebase": [{"name": "Block Malicious"}]})
        if "/web_api/show-logs" in path:
            return httpx.Response(200, json={"logs": [{"action": "Drop", "src": "196.10.20.30"}]})
        return httpx.Response(404)

    conn_full = CheckPointConnector(mgmt_host="192.168.1.50")
    conn_full.access_level = ACCESS_LEVEL_FULL_MANAGEMENT
    conn_full._transport = MockTransport(mock_full_cs)

    res_full = query_cross_source(
        "196.10.20.30",
        client_name="test-client",
        chkp_connector=conn_full,
        chkp_credentials={"api_key": "valid-key"},
    )
    assert res_full["checkpoint"]["available"] is True
    assert res_full["checkpoint"]["access_tier"] == "full"


def test_checkpoint_key_scope_notice():
    """Verify verify_connection reports key scope notice with user-scoped key UNVERIFIED status."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/auth/external" in path:
            return httpx.Response(200, json={"data": {"token": "jwt-token-scope-test"}})
        if "/web_api/login" in path:
            return httpx.Response(200, json={"sid": "scope-probe-sid", "read-only": True, "session-timeout": 600})
        if "/web_api/show-gateways-and-servers" in path:
            return httpx.Response(200, json={"objects": [{"name": "gw-1"}], "total": 1})
        if "/web_api/show-access-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-nat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-threat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-logs" in path:
            return httpx.Response(200, json={"logs": [], "total": 0})
        if "/web_api/show-domains" in path:
            return httpx.Response(200, json={"objects": []})
        return httpx.Response(404)

    conn = CheckPointConnector(
        auth_url="https://cloudinfra-gw.portal.checkpoint.com",
        service_id="service-uuid-456",
    )
    conn._transport = MockTransport(mock_handler)

    status = conn.verify_connection({
        "client_id": "cid",
        "secret_key": "skey",
        "auth_url": "https://cloudinfra-gw.portal.checkpoint.com",
        "service_id": "service-uuid-456",
    })

    assert status.connected is True
    details = status.details
    assert "key_scope_notice" in details
    assert "Account API Key" in details["key_scope_notice"]
    assert "UNVERIFIED" in details["key_scope_notice"]


# ---------------------------------------------------------------------------
# 5. Capability-Driven Tool Registration
# ---------------------------------------------------------------------------

def test_checkpoint_capability_driven_tool_registration():
    """Verify tools are registered ONLY if the capability probe confirmed access."""
    def mock_handler_all_ok(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/web_api/login" in path:
            return httpx.Response(200, json={"sid": "probe-sid", "read-only": True})
        if "/web_api/show-gateways-and-servers" in path:
            return httpx.Response(200, json={"objects": [{"name": "gw-1"}], "total": 1})
        if "/web_api/show-access-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-nat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-threat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-logs" in path:
            return httpx.Response(200, json={"logs": [], "total": 0})
        if "/web_api/show-domains" in path:
            return httpx.Response(200, json={"objects": []})
        return httpx.Response(404, json={})

    conn_all = CheckPointConnector(mgmt_host="192.168.1.50")
    conn_all._transport = MockTransport(mock_handler_all_ok)
    status_all = conn_all.verify_connection({"api_key": "good-key"})

    assert status_all.connected is True
    tools_all = [t.name for t in conn_all.get_tools()]
    assert "chkp_list_gateways" in tools_all
    assert "chkp_find_access_rules" in tools_all
    assert "chkp_show_threat_protection" in tools_all
    assert "chkp_search_logs" in tools_all
    assert "chkp_lookup_object" in tools_all

    # Now simulate a scenario where Log Access fails (insufficient log permissions)
    def mock_handler_no_logs(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/web_api/login" in path:
            return httpx.Response(200, json={"sid": "probe-sid", "read-only": True})
        if "/web_api/show-gateways-and-servers" in path:
            return httpx.Response(200, json={"objects": [{"name": "gw-1"}], "total": 1})
        if "/web_api/show-access-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-nat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-threat-rulebase" in path:
            return httpx.Response(200, json={"rulebase": []})
        if "/web_api/show-logs" in path:
            # Log blade disabled or unauthorized
            return httpx.Response(403, json={"code": "ERR_FORBIDDEN", "message": "Permission denied for logs"})
        if "/web_api/show-domains" in path:
            return httpx.Response(200, json={"objects": []})
        return httpx.Response(404, json={})

    conn_no_logs = CheckPointConnector(mgmt_host="192.168.1.50")
    conn_no_logs._transport = MockTransport(mock_handler_no_logs)
    status_no_logs = conn_no_logs.verify_connection({"api_key": "good-key"})

    assert status_no_logs.connected is True
    tools_no_logs = [t.name for t in conn_no_logs.get_tools()]
    # Gateways and rules must be present
    assert "chkp_list_gateways" in tools_no_logs
    assert "chkp_find_access_rules" in tools_no_logs
    # chkp_search_logs MUST BE ABSENT because probe confirmed logs_accessible is False!
    assert "chkp_search_logs" not in tools_no_logs

    # Attempting to execute chkp_search_logs must raise CAPABILITY_UNAVAILABLE
    with pytest.raises(CheckPointClientError) as exc_tool:
        conn_no_logs.execute_tool("chkp_search_logs", {}, {"sid": "probe-sid"})
    assert exc_tool.value.status_code == 403
    assert exc_tool.value.code == "CAPABILITY_UNAVAILABLE"


# ---------------------------------------------------------------------------
# 6. Command Allowlist and Strict Write Blocking
# ---------------------------------------------------------------------------

def test_checkpoint_write_commands_blocked():
    """Verify the strict read-only allowlist rejects mutation commands."""
    connector = CheckPointConnector(mgmt_host="192.168.1.50")
    creds = {"api_key": "dummy-key"}

    forbidden_commands = [
        "add-host",
        "set-host",
        "delete-host",
        "set-access-rule",
        "delete-access-rule",
        "publish",
        "install-policy",
        "discard",
        "block-ip",
        "set-threat-profile",
        "run-script",
    ]

    for cmd in forbidden_commands:
        with pytest.raises(CheckPointClientError) as exc_info:
            connector.send_command(cmd, {}, creds)
        assert exc_info.value.status_code == 403
        assert "read-only" in exc_info.value.message.lower() or "forbidden" in exc_info.value.message.lower()


# ---------------------------------------------------------------------------
# 7. Credential Isolation and Log Scrubbing
# ---------------------------------------------------------------------------

def test_checkpoint_log_scrubber():
    """Ensure Check Point API keys, passwords, client IDs, and session IDs are scrubbed."""
    raw_text = (
        "CheckPoint Auth: api-key=cp-secret-998811, password='MyStrongPassword123!', "
        "sid='chkp-session-token-xyz', x-chkp-sid: token-abc-def, "
        "clientId: 'client-id-secret-999', secretKey: 'top-secret-infinity-key-888'"
    )
    scrubbed = scrub_sensitive_data(raw_text)

    assert "cp-secret-998811" not in scrubbed
    assert "MyStrongPassword123!" not in scrubbed
    assert "chkp-session-token-xyz" not in scrubbed
    assert "token-abc-def" not in scrubbed
    assert "top-secret-infinity-key-888" not in scrubbed
    assert "[REDACTED]" in scrubbed


# ---------------------------------------------------------------------------
# 8. Log Bounds, max-logs-per-request, Africa/Lusaka Range
# ---------------------------------------------------------------------------

def test_checkpoint_search_logs_time_and_bounds():
    """Verify log query enforces limits, respects max-logs-per-request, and localizes time."""
    captured_payloads = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/web_api/login"):
            return httpx.Response(200, json={"sid": "mock-sid", "read-only": True})
        if request.url.path.endswith("/web_api/show-logs"):
            body = json.loads(request.content.decode())
            captured_payloads.append(body)
            # max-logs-per-request check
            max_logs = body.get("new-query", {}).get("max-logs-per-request", 0)
            assert max_logs <= 100
            return httpx.Response(200, json={
                "logs": [
                    {
                        "time": "2026-11-16T22:00:00Z",
                        "action": "Drop",
                        "src": "196.10.20.30",
                        "dst": "41.77.10.5",
                        "service": "443",
                        "blade": "Network Security",
                        "rule_name": "Block Inbound Malicious",
                    },
                    {
                        "time": "2026-11-16T22:05:00Z",
                        "action": "Accept",
                        "src": "41.77.10.5",
                        "dst": "8.8.8.8",
                        "service": "53",
                        "blade": "DNS",
                        "rule_name": "Outbound DNS",
                    },
                ],
                "total": 2,
            })
        return httpx.Response(404, json={})

    connector = CheckPointConnector(mgmt_host="192.168.1.50")
    connector._transport = MockTransport(mock_handler)

    res = connector.execute_tool(
        "chkp_search_logs",
        {"filter": "action:Drop", "time_range": "last-24-hours", "blade": "Network Security", "limit": 200},
        {"sid": "mock-sid"},
    )

    assert "records" in res
    assert len(res["records"]) == 2
    assert "resolved_time_range_lusaka" in res
    assert "Africa/Lusaka UTC+2" in res["resolved_time_range_lusaka"]

    # Verify blade filter was passed in query
    last_body = captured_payloads[-1]
    assert 'blade:"Network Security"' in last_body["new-query"]["filter"]

    # Verify aggregation
    aggs = res["aggregations"]
    assert aggs["actions"]["Drop"] == 1
    assert aggs["actions"]["Accept"] == 1
    assert any(ip == "196.10.20.30" for ip, count in aggs["top_sources"])


# ---------------------------------------------------------------------------
# 9. Per-User Session Isolation
# ---------------------------------------------------------------------------

def test_checkpoint_per_user_session_isolation():
    """Verify distinct connector instances maintain separate credentials and session tokens."""
    c1 = CheckPointConnector(mgmt_host="192.168.1.50")
    c2 = CheckPointConnector(mgmt_host="192.168.1.60")

    c1._active_sid = "user-alice-session-111"
    c2._active_sid = "user-bob-session-222"

    assert c1._active_sid != c2._active_sid
    c1.logout()
    assert c1._active_sid == ""
    assert c2._active_sid == "user-bob-session-222"
