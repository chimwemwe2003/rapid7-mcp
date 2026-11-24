"""Unit tests verifying strict read-only enforcement for Rapid7 API operations."""

import pytest
import httpx
from unittest.mock import MagicMock, patch

from rapid7_mcp.rapid7_live import (
    ALLOWED_POST_SEARCH_ENDPOINTS,
    ALLOWED_READONLY_HTTP_METHODS,
    PROHIBITED_WRITE_VERBS,
    Rapid7ReadOnlyError,
    execute_rapid7_request,
    validate_rapid7_readonly,
)
from rapid7_mcp.agent import run_pebbles_agent


class TestRapid7ReadOnlyEnforcement:
    """Test suite ensuring zero write/mutation operations are permitted to Rapid7."""

    def test_prohibited_http_methods_rejected(self):
        """PUT, PATCH, DELETE must be rejected unconditionally."""
        for method in ("PUT", "PATCH", "DELETE", "put", "patch", "delete"):
            with pytest.raises(Rapid7ReadOnlyError) as exc_info:
                validate_rapid7_readonly(
                    method=method,
                    url_or_path="https://us.api.insight.rapid7.com/idr/v2/investigations/123",
                )
            assert exc_info.value.status_code == 403
            assert exc_info.value.code == "READ_ONLY_VIOLATION"
            assert "strictly forbidden" in exc_info.value.message

    def test_unapproved_post_endpoints_rejected(self):
        """POST is forbidden unless targeting an approved search/query endpoint."""
        forbidden_post_targets = [
            "https://us.api.insight.rapid7.com/idr/v2/investigations",
            "https://us.api.insight.rapid7.com/api/3/scans",
            "https://us.api.insight.rapid7.com/idr/v2/comments",
            "https://us.api.insight.rapid7.com/vm/v4/integration/assets/delete",
        ]
        for url in forbidden_post_targets:
            with pytest.raises(Rapid7ReadOnlyError) as exc_info:
                validate_rapid7_readonly(method="POST", url_or_path=url)
            assert exc_info.value.status_code == 403
            assert "POST operation" in exc_info.value.message or "contains mutation verb" in exc_info.value.message

    def test_prohibited_mutation_verbs_in_path_rejected(self):
        """Any URL path containing prohibited mutation verbs must raise Rapid7ReadOnlyError."""
        for verb in PROHIBITED_WRITE_VERBS:
            test_url = f"https://us.api.insight.rapid7.com/idr/v2/investigations/test-id{verb}"
            with pytest.raises(Rapid7ReadOnlyError) as exc_info:
                validate_rapid7_readonly(method="GET", url_or_path=test_url)
            assert exc_info.value.status_code == 403
            assert "contains mutation verb" in exc_info.value.message

    def test_payload_mutation_action_rejected(self):
        """Payloads specifying write commands must be blocked."""
        malicious_payloads = [
            {"action": "close", "reason": "false positive"},
            {"command": "delete"},
            {"operation": "modify", "id": 123},
        ]
        allowed_url = "https://us.api.insight.rapid7.com/vm/v4/integration/assets"
        for payload in malicious_payloads:
            with pytest.raises(Rapid7ReadOnlyError) as exc_info:
                validate_rapid7_readonly(method="POST", url_or_path=allowed_url, json_body=payload)
            assert exc_info.value.status_code == 403
            assert "prohibited mutation action" in exc_info.value.message

    def test_approved_get_and_post_endpoints_permitted(self):
        """Valid read-only endpoints must pass without raising exceptions."""
        allowed_cases = [
            ("GET", "https://us.api.insight.rapid7.com/idr/v2/investigations"),
            ("GET", "https://us.api.insight.rapid7.com/idr/v2/investigations/abc-123"),
            ("GET", "https://us.api.insight.rapid7.com/idr/v2/investigations/abc-123/alerts"),
            ("GET", "https://us.api.insight.rapid7.com/vm/v4/integration/scan"),
            ("GET", "https://us.rest.logs.insight.rapid7.com/management/logsets"),
            ("GET", "https://us.rest.logs.insight.rapid7.com/query/logsets/xyz"),
            ("POST", "https://us.api.insight.rapid7.com/vm/v4/integration/assets"),
            ("POST", "https://us.api.insight.rapid7.com/vm/v4/integration/vulnerabilities"),
        ]
        for method, url in allowed_cases:
            # Should not raise
            validate_rapid7_readonly(method=method, url_or_path=url)

    def test_execute_rapid7_request_intercepts_write_without_network_call(self):
        """execute_rapid7_request must block mutations before calling httpx.Client.request."""
        mock_client = MagicMock(spec=httpx.Client)

        with pytest.raises(Rapid7ReadOnlyError):
            execute_rapid7_request(
                client=mock_client,
                method="PATCH",
                url="https://us.api.insight.rapid7.com/idr/v2/investigations/123",
                json={"status": "CLOSED"},
            )

        # Assert client.request was never called
        mock_client.request.assert_not_called()

    def test_agent_refuses_close_all_open_investigations(self):
        """Agent must politely refuse write actions like closing investigations."""
        res = run_pebbles_agent(
            query="Close all open investigations",
            client_name="Acme Bank",
            live_key="test-key-1234",
            live_region="us",
        )
        answer = res.message
        # Must refuse write action politely and explain read-only posture
        assert "read-only" in answer.lower() or "read only" in answer.lower() or "cannot perform write" in answer.lower()
