"""Unit tests for Phase 1: Rendering, Response Schema, and Sanitization."""

from rapid7_mcp.response_schema import (
    MetricItem,
    PebblesResponse,
    StructuredChart,
    StructuredTable,
    ToolExecutionSource,
)
from rapid7_mcp.sanitizer import (
    format_markdown_bar_chart,
    format_markdown_table,
    sanitize_markdown_text,
)


def test_pebbles_response_schema_validation():
    resp = PebblesResponse(
        message="Here is the telemetry summary for NAPSA.",
        metrics=[MetricItem(label="Active Alerts", value=42, delta="+3")],
        tables=[
            StructuredTable(
                title="Critical Assets",
                columns=["Asset", "IP", "Risk"],
                rows=[{"Asset": "DC01", "IP": "10.0.0.1", "Risk": "Critical"}],
            )
        ],
        charts=[
            StructuredChart(
                chart_type="bar",
                title="Alert Severity",
                x_axis="Severity",
                y_axis="Count",
                data=[{"Severity": "High", "Count": 12}],
            )
        ],
        sources=[
            ToolExecutionSource(
                tool_name="list_investigations",
                endpoint="/idr/v2/investigations",
                parameters={"size": 10},
                result_count=1,
                latency_ms=120,
            )
        ],
    )
    assert resp.message == "Here is the telemetry summary for NAPSA."
    assert len(resp.metrics) == 1
    assert len(resp.tables) == 1
    assert len(resp.charts) == 1
    assert len(resp.sources) == 1


def test_sanitizer_blocks_raw_html_div_markup():
    raw_llm_output = (
        '<div style="background: var(--bg-surface); border: 1px solid red;">\n'
        "    <h3>Security Alert</h3>\n"
        "    <p>Suspicious activity detected on asset DC01.</p>\n"
        "</div>"
    )
    cleaned = sanitize_markdown_text(raw_llm_output)

    # Must never contain <div, <h3, <p, or style=
    assert "<div" not in cleaned
    assert "style=" not in cleaned
    assert "<h3" not in cleaned
    assert "<p" not in cleaned
    assert "Security Alert" in cleaned
    assert "Suspicious activity detected on asset DC01." in cleaned


def test_sanitizer_removes_stray_code_fences_and_indented_blocks():
    indented_raw = (
        "    <div style=\"padding: 10px;\">\n"
        "        4-space indented text that markdown turns into a code block\n"
        "    </div>"
    )
    cleaned = sanitize_markdown_text(indented_raw)
    assert "<div" not in cleaned
    # Line should be dedented so CommonMark doesn't treat it as an indented code block
    assert not cleaned.startswith("    ")
    assert "4-space indented text" in cleaned


def test_table_formatting_clean():
    headers = ["Host", "Status", "CVEs"]
    rows = [
        {"Host": "SRV-SQL01", "Status": "Online", "CVEs": "CVE-2026-1234"},
        {"Host": "SRV-WEB02", "Status": "Vulnerable", "CVEs": "CVE-2026-5678"},
    ]
    md = format_markdown_table(headers, rows)
    assert "| Host | Status | CVEs |" in md
    assert "| SRV-SQL01 | Online | CVE-2026-1234 |" in md
    assert "<table" not in md
