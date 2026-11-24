"""Tests for HTML sanitizer and markdown table/chart formatting."""

from rapid7_mcp.sanitizer import (
    format_markdown_bar_chart,
    format_markdown_table,
    sanitize_markdown_text,
)


def test_sanitize_html_tags_removed():
    raw = '<div style="background: var(--bg-surface);">Hello <span>world</span></div>'
    cleaned = sanitize_markdown_text(raw)
    assert "<div" not in cleaned
    assert "style=" not in cleaned
    assert "<span>" not in cleaned
    assert "Hello world" in cleaned


def test_sanitize_strips_indented_code_block_markup():
    raw = """
    <div style="padding: 10px;">
        Alert details here
    </div>
"""
    cleaned = sanitize_markdown_text(raw)
    assert "<div" not in cleaned
    assert "Alert details here" in cleaned


def test_format_markdown_table():
    headers = ["User", "Risk Score", "Status"]
    rows = [
        {"User": "Alice", "Risk Score": 95, "Status": "Active"},
        {"User": "Bob", "Risk Score": 80, "Status": "Investigating"},
    ]
    md = format_markdown_table(headers, rows)
    assert "| User | Risk Score | Status |" in md
    assert "| Alice | 95 | Active |" in md
    assert "| Bob | 80 | Investigating |" in md


def test_format_markdown_bar_chart():
    data = [
        {"Rule": "Brute Force", "Count": 100},
        {"Rule": "Mimikatz", "Count": 50},
    ]
    chart_md = format_markdown_bar_chart("Top Rules", data, "Rule", "Count")
    assert "**Top Rules**" in chart_md
    assert "100" in chart_md
    assert "50" in chart_md
    assert "█" in chart_md
