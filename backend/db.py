import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "siem.db"
SCHEMA_PATH = Path(__file__).parent.parent / "config" / "schema.sql"


def setup_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print(f"Database ready at: {DB_PATH}")


def save_event(event: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO events (timestamp, source_ip, destination_ip, event_type, service, message, raw_log)
        VALUES (:timestamp, :source_ip, :destination_ip, :event_type, :service, :message, :raw_log)
        """,
        {
            "timestamp": event["timestamp"],
            "source_ip": event["source_ip"],
            "destination_ip": event.get("destination_ip"),
            "event_type": event["event_type"],
            "service": event["service"],
            "message": event["message"],
            "raw_log": event.get("raw_log"),
        },
    )
    conn.commit()
    conn.close()


def save_alert(alert: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO alerts (timestamp, alert_type, source_ip, severity, event_count, evidence, status)
        VALUES (:timestamp, :alert_type, :source_ip, :severity, :event_count, :evidence, 'NEW')
        """,
        alert,
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    setup_database()
