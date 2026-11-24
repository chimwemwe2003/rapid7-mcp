"""Typed response schema for Pebbles SOC Assistant.

Enforces structured, grounded responses from the LLM and tool layer.
No HTML, CSS, or inline styles are allowed anywhere in this schema.
"""

from typing import Any, Literal
from pydantic import BaseModel, Field


class TableColumn(BaseModel):
    name: str
    display_name: str | None = None
    column_type: Literal["text", "number", "badge", "progress", "datetime"] = "text"
    format_spec: str | None = None


class StructuredTable(BaseModel):
    title: str | None = None
    columns: list[str] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    total_count: int | None = None


class StructuredChart(BaseModel):
    chart_type: Literal["bar", "line", "area"] = "bar"
    title: str
    x_axis: str
    y_axis: str
    data: list[dict[str, Any]] = Field(default_factory=list)


class MetricItem(BaseModel):
    label: str
    value: str | int | float
    delta: str | None = None
    help_text: str | None = None


class ToolExecutionSource(BaseModel):
    tool_name: str
    endpoint: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    time_range: str | None = None
    result_count: int = 0
    latency_ms: int = 0


class PebblesResponse(BaseModel):
    message: str = Field(description="Conversational markdown answer. Strictly no HTML/CSS tags.")
    metrics: list[MetricItem] = Field(default_factory=list, description="Top-level KPI metrics.")
    tables: list[StructuredTable] = Field(default_factory=list, description="Structured tabular data.")
    charts: list[StructuredChart] = Field(default_factory=list, description="Visual distribution charts.")
    sources: list[ToolExecutionSource] = Field(default_factory=list, description="Evidence / API calls executed.")
