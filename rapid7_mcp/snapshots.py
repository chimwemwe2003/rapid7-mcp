"""Daily Telemetry Snapshot Store for Trend and Historical Comparisons.

Maintains client-scoped daily summaries (vulnerability counts by severity,
investigation counts, remediation numbers) in a lightweight local SQLite database.
Prevents estimation or hallucination when month-over-month or quarterly comparisons are requested.
"""

import datetime
import logging
import os
import sqlite3
from typing import Any

logger = logging.getLogger("pebbles.snapshots")

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "snapshots.db")


def _get_connection() -> sqlite3.Connection:
    """Initialize database and table schema if not present."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS daily_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT NOT NULL,
                snapshot_date TEXT NOT NULL,
                critical_vulns INTEGER DEFAULT 0,
                high_vulns INTEGER DEFAULT 0,
                medium_vulns INTEGER DEFAULT 0,
                low_vulns INTEGER DEFAULT 0,
                total_vulns INTEGER DEFAULT 0,
                open_investigations INTEGER DEFAULT 0,
                closed_investigations INTEGER DEFAULT 0,
                successful_scans INTEGER DEFAULT 0,
                failed_scans INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(client_name, snapshot_date)
            )
            """
        )
    return conn


def record_daily_snapshot(
    client_name: str,
    snapshot_date: str | None = None,
    critical_vulns: int = 0,
    high_vulns: int = 0,
    medium_vulns: int = 0,
    low_vulns: int = 0,
    open_investigations: int = 0,
    closed_investigations: int = 0,
    successful_scans: int = 0,
    failed_scans: int = 0,
) -> None:
    """Record or update a single daily snapshot for a client organization."""
    if not snapshot_date:
        snapshot_date = datetime.date.today().isoformat()

    total_vulns = critical_vulns + high_vulns + medium_vulns + low_vulns
    try:
        conn = _get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO daily_snapshots (
                    client_name, snapshot_date, critical_vulns, high_vulns,
                    medium_vulns, low_vulns, total_vulns, open_investigations,
                    closed_investigations, successful_scans, failed_scans
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(client_name, snapshot_date) DO UPDATE SET
                    critical_vulns=excluded.critical_vulns,
                    high_vulns=excluded.high_vulns,
                    medium_vulns=excluded.medium_vulns,
                    low_vulns=excluded.low_vulns,
                    total_vulns=excluded.total_vulns,
                    open_investigations=excluded.open_investigations,
                    closed_investigations=excluded.closed_investigations,
                    successful_scans=excluded.successful_scans,
                    failed_scans=excluded.failed_scans
                """,
                (
                    client_name,
                    snapshot_date,
                    critical_vulns,
                    high_vulns,
                    medium_vulns,
                    low_vulns,
                    total_vulns,
                    open_investigations,
                    closed_investigations,
                    successful_scans,
                    failed_scans,
                ),
            )
        conn.close()
    except Exception as e:
        logger.warning(f"Could not record daily snapshot for {client_name}: {e}")


def get_historical_comparison(
    client_name: str,
    days_back: int = 30,
) -> dict[str, Any]:
    """Retrieve historical comparison between the latest snapshot and a previous date.

    Returns comparison dict with deltas, or indicates insufficient history.
    """
    try:
        conn = _get_connection()
        today = datetime.date.today()
        target_past_date = (today - datetime.timedelta(days=days_back)).isoformat()

        # Latest available snapshot
        latest_row = conn.execute(
            """
            SELECT * FROM daily_snapshots
            WHERE client_name = ?
            ORDER BY snapshot_date DESC
            LIMIT 1
            """,
            (client_name,),
        ).fetchone()

        if not latest_row:
            conn.close()
            return {
                "has_history": False,
                "reason": "No snapshots recorded yet for this client.",
                "days_available": 0,
            }

        # Past snapshot closest to target date
        past_row = conn.execute(
            """
            SELECT * FROM daily_snapshots
            WHERE client_name = ? AND snapshot_date <= ?
            ORDER BY snapshot_date DESC
            LIMIT 1
            """,
            (client_name, target_past_date),
        ).fetchone()

        # Count total snapshot days recorded
        total_days = conn.execute(
            "SELECT COUNT(*) as cnt FROM daily_snapshots WHERE client_name = ?",
            (client_name,),
        ).fetchone()["cnt"]

        conn.close()

        if not past_row:
            first_row = conn.execute(
                """
                SELECT MIN(snapshot_date) as min_date FROM daily_snapshots
                WHERE client_name = ?
                """,
                (client_name,),
            ).fetchone() if False else None  # connection already closed

            return {
                "has_history": False,
                "reason": f"Only {total_days} day(s) of telemetry snapshots recorded. Comparison requires {days_back} days.",
                "days_available": total_days,
                "latest_snapshot": dict(latest_row),
            }

        # Calculate actual delta
        crit_delta = latest_row["critical_vulns"] - past_row["critical_vulns"]
        high_delta = latest_row["high_vulns"] - past_row["high_vulns"]
        total_delta = latest_row["total_vulns"] - past_row["total_vulns"]
        inv_delta = latest_row["open_investigations"] - past_row["open_investigations"]

        return {
            "has_history": True,
            "days_analyzed": days_back,
            "current_date": latest_row["snapshot_date"],
            "comparison_date": past_row["snapshot_date"],
            "current": dict(latest_row),
            "past": dict(past_row),
            "deltas": {
                "critical_vulns": crit_delta,
                "high_vulns": high_delta,
                "total_vulns": total_delta,
                "open_investigations": inv_delta,
            },
        }

    except Exception as e:
        logger.warning(f"Error reading snapshot comparison: {e}")
        return {
            "has_history": False,
            "reason": str(e),
            "days_available": 0,
        }
