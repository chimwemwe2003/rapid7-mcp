"""Structured Query Specification and Precision Execution Engine for Pebbles.

Ensures that filtering, counting, sorting, age calculations, and free-text matching
are executed deterministically in code. The LLM never counts, filters, or ranks by reading
raw lists.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any

from rapid7_mcp.config import INVESTIGATIONS_MAX_RESULTS
from rapid7_mcp.time_utils import format_iso_utc, get_lusaka_now, resolve_soc_time_range


@dataclass
class QuerySpec:
    entity: str = "investigations"  # investigations, scans, vulnerabilities, users, logs
    operation: str = "list"         # count, list, rank, detail, summary
    statuses: list[str] = field(default_factory=list)      # ["OPEN"], ["INVESTIGATING"], ["CLOSED"]
    priorities: list[str] = field(default_factory=list)    # ["CRITICAL"], ["HIGH"], etc.
    free_text_terms: list[str] = field(default_factory=list)  # e.g. ["unlocked account"]
    start_time_utc: str | None = None
    end_time_utc: str | None = None
    time_label: str = ""
    sort_field: str = "created_time"
    sort_order: str = "DESC"        # "ASC" for oldest/longest, "DESC" for newest
    limit: int = INVESTIGATIONS_MAX_RESULTS
    top_n: int | None = None
    target_metric: str | None = None  # e.g. "age", "failures", "vulnerabilities"
    interpretation: str = ""


@dataclass
class QueryResult:
    spec: QuerySpec
    matching_records: list[dict[str, Any]]
    total_matching: int
    count_by_status: dict[str, int]
    matched_terms: list[str]
    interpretation: str
    headline: str
    rows_with_computed_fields: list[dict[str, Any]]


def parse_query_to_spec(query: str) -> QuerySpec:
    """Parse natural language query into a deterministic QuerySpec."""
    q = query.lower().strip()
    spec = QuerySpec()

    # 1. Operation detection
    if any(q.startswith(w) for w in ["how many", "count", "number of"]) or "how many" in q:
        spec.operation = "count"
    elif any(k in q for k in ["longest open", "open the longest", "oldest", "longest pending"]):
        spec.operation = "rank"
        spec.target_metric = "age"
        spec.sort_field = "created_time"
        spec.sort_order = "ASC"  # Oldest created first
    elif any(k in q for k in ["top ", "highest", "most", "rank"]):
        spec.operation = "rank"
        m = re.search(r"\btop\s+(\d+)\b", q)
        if m:
            spec.top_n = int(m.group(1))
    else:
        spec.operation = "list"

    # 2. Time range resolution (in Lusaka timezone)
    start_utc, end_utc, range_kw = resolve_soc_time_range(q)
    if "yesterday" in q:
        spec.start_time_utc = format_iso_utc(start_utc)
        spec.end_time_utc = format_iso_utc(end_utc)
        spec.time_label = "yesterday (Africa/Lusaka)"
        spec.interpretation = f"Interpreted 'yesterday' as {start_utc.strftime('%Y-%m-%d %H:%M')} to {end_utc.strftime('%Y-%m-%d %H:%M')} UTC."
    elif "today" in q or "24 hour" in q:
        spec.start_time_utc = format_iso_utc(start_utc)
        spec.end_time_utc = format_iso_utc(end_utc)
        spec.time_label = "today"
    elif "this week" in q:
        spec.start_time_utc = format_iso_utc(start_utc)
        spec.end_time_utc = format_iso_utc(end_utc)
        spec.time_label = "this week (since Monday Lusaka)"
        spec.interpretation = f"Interpreted 'this week' as since Monday 00:00 Africa/Lusaka time ({format_iso_utc(start_utc)})."
    elif "last month" in q:
        spec.start_time_utc = format_iso_utc(start_utc)
        spec.end_time_utc = format_iso_utc(end_utc)
        spec.time_label = "last month"
        spec.interpretation = f"Interpreted 'last month' as {start_utc.strftime('%B %Y')} ({format_iso_utc(start_utc)} to {format_iso_utc(end_utc)})."

    # 3. Status semantics: OPEN vs INVESTIGATING vs CLOSED
    # Official InsightIDR documentation specifies: OPEN, INVESTIGATING, CLOSED
    if "open" in q:
        # If user explicitly asks for "open", strictly target OPEN
        spec.statuses = ["OPEN"]
        if not spec.interpretation and ("unresolved" in q or "active" in q):
            spec.interpretation = "Focusing strictly on OPEN investigations (excluding items already undergoing investigation)."
    elif "investigating" in q or "being investigated" in q:
        spec.statuses = ["INVESTIGATING"]
    elif "closed" in q or "resolved" in q:
        spec.statuses = ["CLOSED"]
    elif "active" in q or "unresolved" in q:
        spec.statuses = ["OPEN", "INVESTIGATING"]
        spec.interpretation = "Interpreted 'active/unresolved' as including both OPEN and INVESTIGATING statuses."

    # 4. Priorities
    if "critical" in q:
        spec.priorities.append("CRITICAL")
    if "high" in q:
        spec.priorities.append("HIGH")
    if "medium" in q:
        spec.priorities.append("MEDIUM")
    if "low" in q:
        spec.priorities.append("LOW")

    # 5. Free-text matching terms (e.g. "unlocked account", "brute force", "powershell")
    free_text_candidates = [
        "unlocked account",
        "account unlocked",
        "account lockout",
        "locked account",
        "failed login",
        "brute force",
        "powershell",
        "privilege escalation",
        "anomalous",
        "lateral movement",
        "beaconing",
    ]
    # Sort by length descending to match longest phrases first (e.g. "unlocked account" before "locked account")
    free_text_candidates.sort(key=len, reverse=True)
    for cand in free_text_candidates:
        if cand in q:
            if not any(cand in existing for existing in spec.free_text_terms):
                spec.free_text_terms.append(cand)

    # If no predefined candidate matched, check for quoted phrases
    quoted = re.findall(r"['\"]([^'\"]+)['\"]", query)
    for q_term in quoted:
        cand = q_term.lower()
        if not any(cand in existing for existing in spec.free_text_terms):
            spec.free_text_terms.append(cand)

    return spec


def _parse_iso_datetime(val: Any) -> datetime | None:
    """Safely parse ISO timestamp into UTC datetime."""
    if not val or not isinstance(val, str):
        return None
    try:
        clean = val.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _format_age(created_dt: datetime, now: datetime) -> str:
    """Format timedelta into human-readable age string."""
    delta = now - created_dt
    days = delta.days
    hours = delta.seconds // 3600
    minutes = (delta.seconds % 3600) // 60

    if days > 0:
        return f"{days}d {hours}h"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{max(1, minutes)}m"


def execute_precision_filter(
    records: list[dict[str, Any]],
    spec: QuerySpec,
    now: datetime | None = None,
) -> QueryResult:
    """Execute deterministic filtering, counting, sorting, and age calculation in code."""
    now_utc = now if now else datetime.now(timezone.utc)
    status_counts = {"OPEN": 0, "INVESTIGATING": 0, "CLOSED": 0}

    # Count across all retrieved records for status context
    for r in records:
        st = (r.get("status") or "OPEN").upper()
        if st in status_counts:
            status_counts[st] += 1

    filtered: list[dict[str, Any]] = []
    matched_terms: set[str] = set()

    for r in records:
        if not isinstance(r, dict):
            continue

        # Status filter (records with null/missing status default to OPEN)
        if spec.statuses:
            r_st = (r.get("status") or ("OPEN" if "OPEN" in spec.statuses else "")).upper()
            if r_st not in spec.statuses:
                continue

        # Priority filter
        if spec.priorities:
            r_pr = str(r.get("priority", "")).upper()
            if r_pr not in spec.priorities:
                continue

        # Time range filter
        if spec.start_time_utc or spec.end_time_utc:
            created_str = r.get("created_time")
            created_dt = _parse_iso_datetime(created_str)
            if created_dt:
                if spec.start_time_utc:
                    s_dt = _parse_iso_datetime(spec.start_time_utc)
                    if s_dt and created_dt < s_dt:
                        continue
                if spec.end_time_utc:
                    e_dt = _parse_iso_datetime(spec.end_time_utc)
                    if e_dt and created_dt > e_dt:
                        continue

        # Free text matching against title, rrn, and alert names
        if spec.free_text_terms:
            title = str(r.get("title", "")).lower()
            rrn = str(r.get("rrn", "")).lower()
            combined_text = f"{title} {rrn}"

            term_matched = False
            for term in spec.free_text_terms:
                # Word-boundary or token match
                tokens = term.split()
                if all(tok in combined_text for tok in tokens):
                    term_matched = True
                    matched_terms.add(term)
                    break

            if not term_matched:
                continue

        filtered.append(r)

    # Computed fields (Age, formatted dates)
    augmented_rows: list[dict[str, Any]] = []
    for r in filtered:
        created_dt = _parse_iso_datetime(r.get("created_time"))
        age_str = _format_age(created_dt, now_utc) if created_dt else "N/A"
        age_days = (now_utc - created_dt).total_seconds() / 86400 if created_dt else 0.0

        augmented = dict(r)
        augmented["_age_str"] = age_str
        augmented["_age_days"] = age_days
        augmented["_created_dt"] = created_dt
        augmented_rows.append(augmented)

    # Sorting
    if spec.sort_field == "created_time":
        reverse = (spec.sort_order.upper() == "DESC")
        augmented_rows.sort(
            key=lambda x: x["_created_dt"] or datetime.min.replace(tzinfo=timezone.utc),
            reverse=reverse,
        )

    # Top N slicing
    limit = spec.top_n if spec.top_n is not None else spec.limit
    final_rows = augmented_rows[:limit]
    total_matching = len(filtered)

    # Construct precision headline
    headline = ""
    if spec.operation == "count":
        if spec.free_text_terms:
            terms_label = f"matching '{', '.join(spec.free_text_terms)}'"
            time_label = f" {spec.time_label}" if spec.time_label else ""
            headline = f"We had {total_matching} {terms_label} incident(s){time_label}."
        elif spec.statuses == ["OPEN"]:
            investigating_ctx = f" ({status_counts['INVESTIGATING']} are being investigated)" if status_counts['INVESTIGATING'] > 0 else ""
            headline = f"There are currently {total_matching} OPEN investigations{investigating_ctx}."
        else:
            headline = f"There are {total_matching} investigations matching your criteria."
    elif spec.operation == "rank" and spec.target_metric == "age":
        headline = f"Here are the {len(final_rows)} oldest unresolved investigations, ranked by age:"

    return QueryResult(
        spec=spec,
        matching_records=final_rows,
        total_matching=total_matching,
        count_by_status=status_counts,
        matched_terms=list(matched_terms),
        interpretation=spec.interpretation,
        headline=headline,
        rows_with_computed_fields=final_rows,
    )
