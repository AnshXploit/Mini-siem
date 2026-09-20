"""
seed_test_data.py
------------------
SAFE TEST & DEMO DATA FIXTURES - DOES NOT TOUCH PRODUCTION DATA.

This script creates a disposable demonstration database (defaulting to data/siem_demo.db)
for testing and developing the dashboard without modifying or wiping production data in data/siem.db.

Key Safety Rules:
1. By default, this script writes ONLY to data/siem_demo.db.
2. It NEVER deletes rows from data/siem.db unless explicitly instructed with --force-overwrite-prod.
3. It sets up all 3 tables matching the project specification:
   - events (with destination_port and protocol)
   - alerts (with detection_source)
   - alert_events (linking alerts to supporting events for evidence traceability)

Usage:
    python dashboard/seed_test_data.py
    python dashboard/seed_test_data.py --db-path data/custom_test.db
"""

import sys
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone

DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DASHBOARD_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"
PROD_DB_PATH = DATA_DIR / "siem.db"
DEFAULT_DEMO_DB_PATH = DATA_DIR / "siem_demo.db"

# --- Exact schema matching Mini SIEM Report Section 4.5 ---------------------
SCHEMA_SQL = """
DROP TABLE IF EXISTS alert_events;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS events;

CREATE TABLE events (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    destination_ip  TEXT,
    destination_port INTEGER,
    protocol        TEXT,
    event_type      TEXT NOT NULL,
    service         TEXT NOT NULL,
    message         TEXT NOT NULL,
    raw_log         TEXT
);

CREATE TABLE alerts (
    alert_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    alert_type      TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    event_count     INTEGER NOT NULL,
    evidence        TEXT,
    status          TEXT NOT NULL DEFAULT 'NEW' CHECK(status IN ('NEW','ACKNOWLEDGED','RESOLVED')),
    detection_source TEXT DEFAULT 'RULE' CHECK(detection_source IN ('RULE','ML','BOTH'))
);

CREATE TABLE alert_events (
    alert_id        INTEGER NOT NULL,
    event_id        INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id),
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);
"""


def iso_now_minus(seconds_ago: int) -> str:
    """Returns an ISO 8601 UTC timestamp, `seconds_ago` seconds before now."""
    ts = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return ts.isoformat(timespec="seconds")


def build_fake_events():
    """
    Believable security events: an SSH brute-force attempt from 10.0.0.5,
    followed by benign web activity and an isolated SSH failure.
    """
    events = []

    # 5 failed SSH logins from 10.0.0.5
    for i in range(5):
        seconds_ago = 300 - (i * 25)
        events.append({
            "timestamp": iso_now_minus(seconds_ago),
            "source_ip": "10.0.0.5",
            "destination_ip": "192.168.56.10",
            "destination_port": 22,
            "protocol": "TCP",
            "event_type": "SSH_FAILED_LOGIN",
            "service": "SSH",
            "message": "Failed password for user admin from 10.0.0.5 port 51422 ssh2",
            "raw_log": f"Sep 12 09:3{i}:01 webserver sshd[142{i}]: Failed password for admin from 10.0.0.5 port 51422 ssh2",
        })

    # Successful login after brute-force
    events.append({
        "timestamp": iso_now_minus(150),
        "source_ip": "10.0.0.5",
        "destination_ip": "192.168.56.10",
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "SSH_SUCCESS_LOGIN",
        "service": "SSH",
        "message": "Accepted password for admin from 10.0.0.5 port 51430 ssh2",
        "raw_log": "Sep 12 09:35:10 webserver sshd[1430]: Accepted password for admin from 10.0.0.5 port 51430 ssh2",
    })

    # Benign web traffic
    events.append({
        "timestamp": iso_now_minus(90),
        "source_ip": "172.16.0.22",
        "destination_ip": "192.168.56.10",
        "destination_port": 80,
        "protocol": "TCP",
        "event_type": "HTTP_REQUEST",
        "service": "HTTP",
        "message": "GET /index.html 200",
        "raw_log": '172.16.0.22 - - [12/Sep/2026:09:36:30] "GET /index.html HTTP/1.1" 200 512',
    })

    # Isolated SSH failure
    events.append({
        "timestamp": iso_now_minus(60),
        "source_ip": "203.0.113.9",
        "destination_ip": "192.168.56.10",
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "SSH_FAILED_LOGIN",
        "service": "SSH",
        "message": "Failed password for user root from 203.0.113.9 port 22110 ssh2",
        "raw_log": "Sep 12 09:37:40 webserver sshd[1512]: Failed password for root from 203.0.113.9 port 22110 ssh2",
    })

    return events


def build_fake_alerts():
    """
    Fake alerts in NEW, ACKNOWLEDGED, and RESOLVED states.
    """
    return [
        {
            "timestamp": iso_now_minus(150),
            "alert_type": "SSH_BRUTE_FORCE",
            "source_ip": "10.0.0.5",
            "severity": "HIGH",
            "event_count": 5,
            "evidence": "5 failed SSH logins from 10.0.0.5 within 120 seconds",
            "status": "NEW",
            "detection_source": "RULE",
        },
        {
            "timestamp": iso_now_minus(3600),
            "alert_type": "SSH_BRUTE_FORCE",
            "source_ip": "198.51.100.14",
            "severity": "MEDIUM",
            "event_count": 3,
            "evidence": "3 failed SSH logins from 198.51.100.14 within 90 seconds",
            "status": "ACKNOWLEDGED",
            "detection_source": "RULE",
        },
        {
            "timestamp": iso_now_minus(86400),
            "alert_type": "SSH_BRUTE_FORCE",
            "source_ip": "192.0.2.55",
            "severity": "CRITICAL",
            "event_count": 12,
            "evidence": "12 failed SSH logins from 192.0.2.55 within 60 seconds across 2 accounts",
            "status": "RESOLVED",
            "detection_source": "RULE",
        },
    ]


def seed(target_db_path: Path = None, force_overwrite_prod: bool = False, all_new: bool = False) -> Path:
    """
    Seeds disposable test data into target_db_path.
    Prevents accidental wiping of production data/siem.db.
    """
    if target_db_path is None:
        target_db_path = DEFAULT_DEMO_DB_PATH
    else:
        target_db_path = Path(target_db_path).resolve()

    if target_db_path == PROD_DB_PATH.resolve() and not force_overwrite_prod:
        raise PermissionError(
            f"SAFETY LOCK: Refusing to delete or overwrite production database at {PROD_DB_PATH}.\n"
            f"To run tests or view demo data safely, use a disposable database path (e.g. {DEFAULT_DEMO_DB_PATH}).\n"
            f"If you intentionally want to wipe data/siem.db, pass force_overwrite_prod=True."
        )

    target_db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(target_db_path))
    try:
        conn.executescript(SCHEMA_SQL)

        inserted_event_ids = []
        for e in build_fake_events():
            cursor = conn.execute(
                """INSERT INTO events
                   (timestamp, source_ip, destination_ip, destination_port, protocol, event_type, service, message, raw_log)
                   VALUES (:timestamp, :source_ip, :destination_ip, :destination_port, :protocol, :event_type, :service, :message, :raw_log)""",
                e,
            )
            inserted_event_ids.append((e, cursor.lastrowid))

        inserted_alert_ids = []
        for a in build_fake_alerts():
            if all_new:
                a = {**a, "status": "NEW"}
            cursor = conn.execute(
                """INSERT INTO alerts
                   (timestamp, alert_type, source_ip, severity, event_count, evidence, status, detection_source)
                   VALUES (:timestamp, :alert_type, :source_ip, :severity, :event_count, :evidence, :status, :detection_source)""",
                a,
            )
            inserted_alert_ids.append((a, cursor.lastrowid))

        # Link the 5 SSH_FAILED_LOGIN events from 10.0.0.5 to the first alert (SSH_BRUTE_FORCE)
        first_alert_id = inserted_alert_ids[0][1]
        for e_dict, e_id in inserted_event_ids:
            if e_dict["source_ip"] == "10.0.0.5" and e_dict["event_type"] == "SSH_FAILED_LOGIN":
                conn.execute(
                    "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                    (first_alert_id, e_id),
                )

        conn.commit()
        print(f"[SAFE SEED] Successfully seeded test fixtures to {target_db_path}")
        print(f"  - Created {len(inserted_event_ids)} events")
        print(f"  - Created {len(inserted_alert_ids)} alerts")
        print(f"  - Linked {conn.execute('SELECT COUNT(*) FROM alert_events').fetchone()[0]} supporting evidence rows in alert_events table")
        return target_db_path
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Seed disposable test data for Mini SIEM dashboard.")
    parser.add_argument(
        "--db-path",
        type=str,
        default=str(DEFAULT_DEMO_DB_PATH),
        help=f"Target database path (default: {DEFAULT_DEMO_DB_PATH})",
    )
    parser.add_argument(
        "--force-overwrite-prod",
        action="store_true",
        help="Explicitly permit wiping production data/siem.db",
    )
    parser.add_argument(
        "--all-new",
        action="store_true",
        help="Start every alert as NEW for a fresh triage demonstration",
    )
    args = parser.parse_args()

    try:
        seeded_path = seed(Path(args.db_path), force_overwrite_prod=args.force_overwrite_prod, all_new=args.all_new)
        print(f"\nTo launch the Streamlit dashboard with this demo database, run:\n")
        print(f"    SIEM_DB_PATH=\"{seeded_path}\" python3 -m streamlit run dashboard/app.py\n")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
