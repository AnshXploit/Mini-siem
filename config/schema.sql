CREATE TABLE IF NOT EXISTS events (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    destination_ip  TEXT,
    event_type      TEXT NOT NULL,
    service         TEXT NOT NULL,
    message         TEXT NOT NULL,
    raw_log         TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    alert_type      TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    event_count     INTEGER NOT NULL,
    evidence        TEXT,
    status          TEXT NOT NULL DEFAULT 'NEW' CHECK(status IN ('NEW','ACKNOWLEDGED','RESOLVED'))
);
