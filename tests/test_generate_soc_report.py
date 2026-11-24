"""Tests for the monthly SOC report generator."""

from scripts import generate_soc_report
from scripts.generate_soc_report import build_prompt, prepare_report_data


def test_prepare_report_data_calculates_critical_high_and_mttr() -> None:
    report = {
        "investigations_by_priority": {"Critical": 2, "High": 3, "Medium": 4, "Low": 5},
        "average_time_to_close": {"value": 90, "unit": "minutes"},
    }

    assert prepare_report_data(report)["derived_metrics"] == {
        "critical_high_findings": 5,
        "mttr_hours": 1.5,
    }


def test_prepare_report_data_leaves_unavailable_metrics_absent() -> None:
    assert prepare_report_data({"month": "2024-01"})["derived_metrics"] == {}


def test_build_prompt_requires_all_requested_markdown_sections() -> None:
    prompt = build_prompt({"month": "2024-01"})

    assert "## Executive Summary" in prompt
    assert "## SLA Metrics & MTTR" in prompt
    assert "## Notable Security Incidents" in prompt
    assert "## MITRE ATT&CK Mapping" in prompt


def test_generate_report_uses_configured_openai_compatible_endpoint(monkeypatch) -> None:
    request: dict = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"choices": [{"message": {"content": "## Executive Summary\nReport"}}]}

    def fake_post(url: str, **kwargs):
        request["url"] = url
        request.update(kwargs)
        return FakeResponse()

    monkeypatch.setattr(generate_soc_report.httpx, "post", fake_post)

    markdown = generate_soc_report.generate_report(
        {"month": "2024-01"},
        "test-key",
        "deepseek-flash",
        "https://api.deepseek.com/",
    )

    assert markdown.startswith("## Executive Summary")
    assert request["url"] == "https://api.deepseek.com/chat/completions"
    assert request["headers"]["Authorization"] == "Bearer test-key"
    assert request["json"]["model"] == "deepseek-flash"
