"""Date and time range utilities for Rapid7 SOC queries.

Translates human time expressions like 'this week', 'last month', 'older than 30 days',
'last quarter' into UTC ISO-8601 timestamps and LEQL time range parameters.
Default timezone context: Africa/Lusaka (CAT, UTC+2).
"""

from datetime import datetime, timedelta, timezone
from typing import Tuple
import zoneinfo

LUSAKA_TZ = zoneinfo.ZoneInfo("Africa/Lusaka")


def get_lusaka_now() -> datetime:
    """Current timestamp in Africa/Lusaka (UTC+2)."""
    return datetime.now(LUSAKA_TZ)


def resolve_this_week_lusaka(now_lusaka: datetime | None = None) -> Tuple[datetime, datetime, str]:
    """Resolve 'this week' to Monday 00:00:00 Lusaka time, converted to UTC.

    Returns: (start_utc, now_utc, iso_utc_string)
    """
    if now_lusaka is None:
        now_lusaka = get_lusaka_now()

    monday_lusaka = (now_lusaka - timedelta(days=now_lusaka.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    start_utc = monday_lusaka.astimezone(timezone.utc)
    now_utc = now_lusaka.astimezone(timezone.utc)
    return start_utc, now_utc, format_iso_utc(start_utc)


def resolve_soc_time_range(
    phrase: str,
    now: datetime | None = None,
) -> Tuple[datetime, datetime, str]:
    """Resolves human phrases to (start_utc, end_utc, leql_range_keyword).

    Examples:
        - "this week" -> (Monday 00:00:00 Lusaka in UTC, now_utc, "LAST_7_DAYS")
        - "last 24 hours" -> (now - 24h, now, "LAST_24_HOURS")
        - "last month" -> (start_of_last_month, end_of_last_month, "LAST_30_DAYS")
        - "older than 30 days" -> (now - 30d, now, "OLDER_THAN_30_DAYS")
        - "last quarter" -> (now - 90d, now, "LAST_90_DAYS")
    """
    if now is None:
        now_utc = datetime.now(timezone.utc)
    else:
        if now.tzinfo is None:
            now_utc = now.replace(tzinfo=timezone.utc)
        else:
            now_utc = now.astimezone(timezone.utc)

    now = now_utc
    q = phrase.lower().strip()
    now_lusaka = now.astimezone(LUSAKA_TZ)

    if "this week" in q:
        start_utc, now_utc_ret, _ = resolve_this_week_lusaka(now_lusaka)
        return start_utc, now_utc_ret, "LAST_7_DAYS"

    if "yesterday" in q:
        y_lusaka = now_lusaka - timedelta(days=1)
        start_lusaka = y_lusaka.replace(hour=0, minute=0, second=0, microsecond=0)
        end_lusaka = y_lusaka.replace(hour=23, minute=59, second=59, microsecond=0)
        return start_lusaka.astimezone(timezone.utc), end_lusaka.astimezone(timezone.utc), "LAST_24_HOURS"

    if "today" in q:
        start_lusaka = now_lusaka.replace(hour=0, minute=0, second=0, microsecond=0)
        return start_lusaka.astimezone(timezone.utc), now_lusaka.astimezone(timezone.utc), "LAST_24_HOURS"

    if "24 hour" in q:
        start_utc = (now_utc - timedelta(hours=24))
        return start_utc, now_utc, "LAST_24_HOURS"

    if "7 day" in q or "week" in q:
        start_utc = (now - timedelta(days=7))
        return start_utc, now, "LAST_7_DAYS"

    if "last month" in q or "previous month" in q:
        first_of_current = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_day_prev = first_of_current - timedelta(days=1)
        start_of_prev = last_day_prev.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_of_prev = last_day_prev.replace(hour=23, minute=59, second=59, microsecond=0)
        return start_of_prev, end_of_prev, "LAST_30_DAYS"

    if "30 day" in q or "month" in q:
        start = now - timedelta(days=30)
        return start, now, "LAST_30_DAYS"

    if "90 day" in q or "quarter" in q or "3 month" in q or "4 month" in q:
        days = 120 if "4 month" in q else 90
        start = now - timedelta(days=days)
        return start, now, "LAST_90_DAYS"

    # Default to past 30 days
    start = now - timedelta(days=30)
    return start, now, "LAST_30_DAYS"


def format_iso_utc(dt: datetime) -> str:
    """Format datetime as ISO 8601 UTC string (e.g. 2026-11-08T22:00:00Z)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
