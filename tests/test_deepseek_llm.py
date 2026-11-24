"""Unit tests for DeepSeek LLM integration."""

from unittest.mock import MagicMock, patch
import pytest

from rapid7_mcp.llm import (
    call_deepseek,
    _format_messages_for_openai,
    _post_deepseek,
    call_llm_conversational,
)


class TestDeepSeekIntegration:
    """Test suite for DeepSeek REST API client and fallback mechanism."""

    def test_format_messages_for_openai(self):
        """Ensure conversation history and telemetry context are properly formatted for OpenAI schema."""
        history = [
            {"role": "user", "content": "Hello Pebbles"},
            {"role": "assistant", "content": "Hello! How can I assist you with security operations?"},
        ]
        msgs = _format_messages_for_openai(
            system_instruction="You are Pebbles.",
            chat_history=history,
            current_query="Check open investigations",
            telemetry_context="Found 3 open investigations",
        )
        assert len(msgs) == 4
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == "You are Pebbles."
        assert msgs[1]["role"] == "user"
        assert msgs[2]["role"] == "assistant"
        assert msgs[3]["role"] == "user"
        assert "Found 3 open investigations" in msgs[3]["content"]

    @patch("rapid7_mcp.llm.httpx.Client")
    def test_post_deepseek_success(self, mock_client_cls):
        """Mock successful DeepSeek API call."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "DeepSeek conversational response for SOC.",
                    }
                }
            ]
        }
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        reply = _post_deepseek(
            api_key="sk-test-deepseek-1234",
            messages=[{"role": "user", "content": "Hi"}],
            model="deepseek-chat",
        )
        assert reply == "DeepSeek conversational response for SOC."

    @patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test-mock-deepseek"})
    @patch("rapid7_mcp.llm.call_deepseek")
    def test_call_llm_conversational_uses_deepseek(self, mock_deepseek):
        """When DEEPSEEK_API_KEY is present, call_llm_conversational should use DeepSeek."""
        mock_deepseek.return_value = "Pebbles reporting via DeepSeek."

        reply = call_llm_conversational(
            query="Hello Pebbles",
            client_name="ZNBS",
        )
        assert "DeepSeek" in reply
        mock_deepseek.assert_called()
