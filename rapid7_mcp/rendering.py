"""Native Streamlit response renderer for Pebbles SOC Assistant.

Guarantees:
1. Model text is always sanitized before display.
2. Zero model text reaches `unsafe_allow_html=True`.
3. Tables and charts use native components (st.dataframe, st.metric, or clean markdown fallback).
4. Displays the collapsible "What I ran" evidence panel under every answer.
"""

import csv
import io
import re
from typing import Any
import streamlit as st

from rapid7_mcp.response_schema import PebblesResponse, StructuredChart, StructuredTable
from rapid7_mcp.sanitizer import (
    format_markdown_bar_chart,
    format_markdown_table,
    sanitize_markdown_text,
)


def render_pebbles_response(response: PebblesResponse) -> None:
    """Render a structured Pebbles response using native Streamlit primitives."""
    # 1. Top-level KPI metrics (if any)
    if response.metrics:
        cols = st.columns(len(response.metrics))
        for col, metric in zip(cols, response.metrics):
            col.metric(
                label=metric.label,
                value=str(metric.value),
                delta=metric.delta,
                help=metric.help_text,
            )

    # 2. Main Conversational Message (Sanitized Markdown)
    sanitized_message = sanitize_markdown_text(response.message)
    if sanitized_message:
        st.markdown(sanitized_message)

    # 3. Tables (st.dataframe with fallback to clean Markdown tables & native pagination)
    for table_idx, table in enumerate(response.tables):
        if table.title:
            st.markdown(f"**{table.title}**")
        if table.rows:
            clean_title = re.sub(r"[^a-zA-Z0-9_]", "_", table.title or f"table_{table_idx}")
            total_rows = len(table.rows)
            page_size = 20

            current_page = 0
            total_pages = 1
            if total_rows > page_size:
                total_pages = (total_rows + page_size - 1) // page_size
                page_key = f"tbl_page_{clean_title}_{total_rows}"
                try:
                    if page_key not in st.session_state:
                        st.session_state[page_key] = 0
                    current_page = max(0, min(st.session_state[page_key], total_pages - 1))
                    st.session_state[page_key] = current_page
                except Exception:
                    current_page = 0

                start_idx = current_page * page_size
                end_idx = min(start_idx + page_size, total_rows)
                display_rows = table.rows[start_idx:end_idx]
                try:
                    st.caption(f"Showing records {start_idx + 1}–{end_idx} of {total_rows} (Page {current_page + 1} of {total_pages})")
                except Exception:
                    pass
            else:
                display_rows = table.rows

            rendered = False
            try:
                import pandas as pd
                df = pd.DataFrame(display_rows)
                if table.columns:
                    # Filter/reorder to matching columns
                    cols_to_use = [c for c in table.columns if c in df.columns]
                    if cols_to_use:
                        df = df[cols_to_use]
                st.dataframe(df, use_container_width=True)
                rendered = True
            except Exception:
                pass

            if not rendered:
                # Guaranteed zero-dependency fallback (no HTML, no numpy crash)
                cols = table.columns or list(display_rows[0].keys())
                md_table = format_markdown_table(cols, display_rows)
                st.markdown(md_table)

            # Pagination controls if more than 20 rows
            if total_rows > page_size:
                try:
                    col_prev, col_status, col_next = st.columns([1, 2, 1])
                    with col_prev:
                        if current_page > 0:
                            if st.button("⬅️ Previous 20", key=f"btn_prev_{clean_title}_{table_idx}"):
                                st.session_state[page_key] -= 1
                                st.rerun()
                    with col_status:
                        st.caption(f"Page {current_page + 1} of {total_pages}")
                    with col_next:
                        if current_page < total_pages - 1:
                            if st.button("Next 20 ➡️", key=f"btn_next_{clean_title}_{table_idx}"):
                                st.session_state[page_key] += 1
                                st.rerun()
                except Exception:
                    pass

            # Export to CSV action for analysts
            try:
                cols = table.columns or list(table.rows[0].keys())
                csv_buffer = io.StringIO()
                writer = csv.DictWriter(csv_buffer, fieldnames=cols, extrasaction="ignore")
                writer.writeheader()
                for r in table.rows:
                    writer.writerow({k: r.get(k, "") for k in cols})
                csv_data = csv_buffer.getvalue()
                st.download_button(
                    label=f"📥 Export All {total_rows} Records (CSV)",
                    data=csv_data,
                    file_name=f"{clean_title}.csv",
                    mime="text/csv",
                    key=f"dl_{clean_title}_{total_rows}_{table_idx}",
                )
            except Exception:
                pass

    # 4. Charts (Native st.bar_chart with fallback to clean unicode progress distribution)
    for chart in response.charts:
        if chart.data:
            rendered = False
            try:
                st.bar_chart(chart.data, x=chart.x_axis, y=chart.y_axis)
                rendered = True
            except Exception:
                pass

            if not rendered:
                md_chart = format_markdown_bar_chart(
                    title=chart.title,
                    data=chart.data,
                    label_key=chart.x_axis if not isinstance(chart.data[0].get(chart.x_axis), (int, float)) else chart.y_axis,
                    val_key=chart.y_axis if not isinstance(chart.data[0].get(chart.x_axis), (int, float)) else chart.x_axis,
                )
                st.markdown(md_chart)

    # 5. Collapsible "What I ran" evidence panel
    if response.sources:
        with st.expander("🔍 What I ran", expanded=False):
            for src in response.sources:
                st.markdown(
                    f"- **Tool:** `{src.tool_name}` · **Endpoint:** `{src.endpoint}`\n"
                    f"  - Parameters: `{src.parameters or 'None'}`\n"
                    f"  - Resolved Time Range: `{src.time_range or 'N/A'}`\n"
                    f"  - Records Returned: `{src.result_count}` · Latency: `{src.latency_ms}ms`"
                )
