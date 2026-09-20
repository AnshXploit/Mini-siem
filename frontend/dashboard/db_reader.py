"""
db_reader.py
------------
All database access for the dashboard lives in this one file.

Why this file exists (for your viva):
- It keeps every SQL query in one place, so app.py never writes raw SQL.
- It enforces the "read-only + one allowed write" rule from the project
  contract: every function here either SELECTs data, or performs the
  single permitted UPDATE (changing an alert's status). Nothing in this
  file ever INSERTs or DELETEs a row — that is the backend's job only.
- sqlite3 is part of the Python standard library, so there is nothing
  extra to install to talk to the database.

Path handling:
- The database lives at data/siem.db, ONE LEVEL UP from this dashboard/
  folder (i.e. at the project root). We compute that path relative to
  this file's own location, so it works no matter what directory you
  run `streamlit run` from.
"""

import os
import sqlite3
from pathlib import Path
from contextlib import contextmanager

# --- Path setup -------------------------------------------------------
# This file is at: <project_root>/dashboard/db_reader.py
# The default DB is at: <project_root>/data/siem.db
DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DASHBOARD_DIR.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "siem.db"


def get_db_path() -> Path:
    """
    Returns the target SQLite database path.
    Can be overridden via SIEM_DB_PATH environment variable.
    If SIEM_DB_PATH is not set and data/siem_demo.db exists, defaults to the disposable demo database
    to avoid reading or modifying production data/siem.db unexpectedly.
    """
    env_path = os.getenv("SIEM_DB_PATH")
    if env_path:
        return Path(env_path)
    demo_path = PROJECT_ROOT / "data" / "siem_demo.db"
    if demo_path.exists():
        return demo_path
    return DEFAULT_DB_PATH


@contextmanager
def get_connection():
    """
    Open a SQLite connection as a context manager, so it's always closed
    properly even if an error happens mid-query.

    row_factory = sqlite3.Row lets us access columns by name (row["severity"])
    instead of by numeric index (row[4]), which makes the rest of the code
    much easier to read.
    """
    db_path = get_db_path()
    if not db_path.exists():
        raise FileNotFoundError(
            f"Database not found at {db_path}. "
            f"Run seed_test_data.py to create a disposable test database, "
            f"or ensure the detection backend has initialized the database."
        )
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def _table_exists(conn, table_name: str) -> bool:
    """Helper to check if a table exists in the database."""
    res = conn.execute(
        "SELECT COUNT(*) AS c FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return bool(res and res["c"] > 0)


# --- Summary metrics ----------------------------------------------------

def get_alert_summary():
    """
    Returns a dict with:
        total_alerts: int
        new_count: int
        severity_counts: dict like {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    Used for the metrics row at the top of the dashboard.
    """
    with get_connection() as conn:
        if not _table_exists(conn, "alerts"):
            return {
                "total_alerts": 0,
                "new_count": 0,
                "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            }

        total_alerts = conn.execute(
            "SELECT COUNT(*) AS c FROM alerts"
        ).fetchone()["c"]

        new_count = conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE status = 'NEW'"
        ).fetchone()["c"]

        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
        ).fetchall()

        # Start every severity at 0 so the UI never has to guess a missing key
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for row in severity_rows:
            severity_counts[row["severity"]] = row["c"]

        return {
            "total_alerts": total_alerts,
            "new_count": new_count,
            "severity_counts": severity_counts,
        }


# --- Alerts ---------------------------------------------------------------

def get_all_alerts():
    """
    Returns every alert, most recent first, as a list of dicts.
    """
    with get_connection() as conn:
        if not _table_exists(conn, "alerts"):
            return []
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def update_alert_status(alert_id: int, new_status: str):
    """
    The ONLY write operation the dashboard is allowed to perform:
    updating the status column of one existing alert row.

    new_status must be one of NEW / ACKNOWLEDGED / RESOLVED to match the
    CHECK constraint in the schema. We validate here too, so a bug in the
    UI can't send garbage into the database.
    """
    allowed = {"NEW", "ACKNOWLEDGED", "RESOLVED"}
    if new_status not in allowed:
        raise ValueError(f"new_status must be one of {allowed}, got {new_status!r}")

    with get_connection() as conn:
        if not _table_exists(conn, "alerts"):
            raise ValueError("Alerts table does not exist in database.")

        res = conn.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?",
            (new_status, alert_id),
        )
        if res.rowcount == 0:
            raise ValueError(f"No alert found with alert_id = {alert_id}")
        conn.commit()


# --- Events & Evidence Traceability -----------------------------------------

def get_all_events():
    """
    Returns every row from the events table, most recent first, as a list
    of plain dicts. Filtering/sorting for the table happens in app.py using
    pandas, so this function just hands back everything.
    """
    with get_connection() as conn:
        if not _table_exists(conn, "events"):
            return []
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def get_alert_events(alert_id: int):
    """
    Returns all event records linked to a specific alert via the alert_events table.
    This fulfills the requirement for evidence traceability (NFR2, Section 4.5/6.6/7.7).
    """
    with get_connection() as conn:
        if not _table_exists(conn, "alert_events") or not _table_exists(conn, "events"):
            return []
        query = """
            SELECT e.*
            FROM events e
            JOIN alert_events ae ON e.event_id = ae.event_id
            WHERE ae.alert_id = ?
            ORDER BY e.timestamp ASC
        """
        rows = conn.execute(query, (alert_id,)).fetchall()
        return [dict(row) for row in rows]

