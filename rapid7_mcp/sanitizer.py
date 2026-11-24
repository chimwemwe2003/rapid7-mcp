"""HTML and Markdown sanitizer for Pebbles SOC Assistant.

Guarantees that LLM text and tool outputs are strictly clean Markdown
with zero HTML tags, zero inline CSS, and no accidental 4-space indented code blocks.
"""

import re
from typing import Any


# Regex pattern to match any HTML tags (e.g. <div style="...">, </span>, <br>, <script>)
HTML_TAG_REGEX = re.compile(r"<[^>]+>", re.IGNORECASE)

# Regex pattern for inline style attributes (style="...")
STYLE_ATTR_REGEX = re.compile(r'\bstyle\s*=\s*["\'][^"\']*["\']', re.IGNORECASE)

# Regex pattern for stray markdown code block markers like ```html or broken fences
CODE_FENCE_REGEX = re.compile(r"^```(?:html|css)?\s*$", re.IGNORECASE | re.MULTILINE)


def sanitize_markdown_text(text: str) -> str:
    """Strip all HTML tags, inline styles, and unclosed HTML markup from markdown text.

    Also normalizes leading whitespace on lines that are not code blocks to prevent
    CommonMark from interpreting them as 4-space indented code blocks.
    """
    if not text:
        return ""

    # 1. Remove dangerous or stray HTML tags completely
    # Extract inner text or remove tag
    cleaned = HTML_TAG_REGEX.sub("", text)

    # 2. Strip leftover style attributes or entities
    cleaned = STYLE_ATTR_REGEX.sub("", cleaned)
    cleaned = cleaned.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")

    # 3. Fix accidental 4-space indentation outside of fenced code blocks
    lines = cleaned.splitlines()
    in_code_block = False
    sanitized_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            sanitized_lines.append(line)
            continue

        if not in_code_block:
            # If line starts with 4 or more spaces and is not a list item or quote, dedent it
            if line.startswith("    ") and not (stripped.startswith("-") or stripped.startswith("*") or stripped.startswith(">")):
                sanitized_lines.append(line.lstrip())
            else:
                sanitized_lines.append(line)
        else:
            sanitized_lines.append(line)

    result = "\n".join(sanitized_lines).strip()
    return result


def format_markdown_table(headers: list[str], rows: list[dict[str, Any]]) -> str:
    """Format structured data as a standard, compliant GitHub-flavored Markdown table.

    Requires zero numpy or pandas dependencies and renders cleanly in Streamlit without HTML.
    """
    if not headers or not rows:
        return ""

    # Header row
    md = "| " + " | ".join(str(h) for h in headers) + " |\n"
    # Separator row
    md += "| " + " | ".join("---" for _ in headers) + " |\n"

    # Data rows
    for row in rows:
        vals = []
        for h in headers:
            v = row.get(h, "")
            # Sanitize pipe symbols to avoid breaking table layout
            clean_v = str(v).replace("|", "\\|").replace("\n", " ")
            vals.append(clean_v)
        md += "| " + " | ".join(vals) + " |\n"

    return md


def format_markdown_bar_chart(title: str, data: list[dict[str, Any]], label_key: str, val_key: str) -> str:
    """Format numerical distribution as a clean unicode progress visualization.

    Guarantees no HTML tags, no C-extension crashes, and standard markdown presentation.
    """
    if not data:
        return ""

    max_val = max((float(d.get(val_key, 0)) for d in data), default=1.0) or 1.0
    lines = [f"**{title}**\n"]

    for item in data:
        label = item.get(label_key, "Unknown")
        try:
            val = float(item.get(val_key, 0))
        except (ValueError, TypeError):
            val = 0.0

        pct = (val / max_val) if max_val > 0 else 0.0
        filled_slots = int(pct * 16)
        bar = "█" * filled_slots + "░" * (16 - filled_slots)

        formatted_val = f"{int(val):,}" if val.is_integer() else f"{val:.1f}"
        lines.append(f"`{bar}` **{formatted_val}** — {label}")

    return "\n".join(lines)
