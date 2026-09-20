"""
test_dashboard_db.py
---------------------
Unit and integration test suite for the Mini SIEM dashboard database read/status-update layer,
safe seed script, and evidence traceability schema.

All tests use disposable SQLite databases in temporary directories and NEVER touch production data/siem.db.
"""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

# Add project root and dashboard directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"

import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(DASHBOARD_DIR))

import db_reader as db
from seed_test_data import seed, PROD_DB_PATH, DEFAULT_DEMO_DB_PATH, SCHEMA_SQL


class TestDashboardDatabaseLayer(unittest.TestCase):

    def setUp(self):
        """Set up a disposable temporary SQLite database file for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_siem.db"
        os.environ["SIEM_DB_PATH"] = str(self.test_db_path)

    def tearDown(self):
        """Clean up environment and temporary files."""
        if "SIEM_DB_PATH" in os.environ:
            del os.environ["SIEM_DB_PATH"]
        self.temp_dir.cleanup()

    def test_db_path_override(self):
        """Verify get_db_path respects SIEM_DB_PATH env var."""
        self.assertEqual(db.get_db_path(), self.test_db_path)

    def test_seed_disposable_database(self):
        """Verify seed script creates all 3 tables and populates data safely on disposable DB."""
        seeded_path = seed(self.test_db_path)
        self.assertTrue(seeded_path.exists())

        conn = sqlite3.connect(str(self.test_db_path))
        conn.row_factory = sqlite3.Row
        try:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            self.assertIn("events", tables)
            self.assertIn("alerts", tables)
            self.assertIn("alert_events", tables)

            events_count = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
            alerts_count = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
            links_count = conn.execute("SELECT COUNT(*) AS c FROM alert_events").fetchone()["c"]

            self.assertEqual(events_count, 8)
            self.assertEqual(alerts_count, 3)
            self.assertEqual(links_count, 5)
        finally:
            conn.close()

    def test_get_alert_summary(self):
        """Verify get_alert_summary calculates metrics accurately."""
        seed(self.test_db_path)
        summary = db.get_alert_summary()

        self.assertEqual(summary["total_alerts"], 3)
        self.assertEqual(summary["new_count"], 1)
        self.assertEqual(summary["severity_counts"]["HIGH"], 1)
        self.assertEqual(summary["severity_counts"]["MEDIUM"], 1)
        self.assertEqual(summary["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(summary["severity_counts"]["LOW"], 0)

    def test_get_all_alerts_and_events(self):
        """Verify get_all_alerts and get_all_events return dict lists ordered by timestamp DESC."""
        seed(self.test_db_path)

        alerts = db.get_all_alerts()
        self.assertEqual(len(alerts), 3)
        self.assertIn("alert_id", alerts[0])
        self.assertIn("severity", alerts[0])
        self.assertIn("status", alerts[0])

        events = db.get_all_events()
        self.assertEqual(len(events), 8)
        self.assertIn("event_id", events[0])
        self.assertIn("event_type", events[0])

    def test_get_alert_events_traceability(self):
        """Verify evidence traceability linking through alert_events table."""
        seed(self.test_db_path)
        alerts = db.get_all_alerts()
        first_alert = [a for a in alerts if a["source_ip"] == "10.0.0.5"][0]

        linked_events = db.get_alert_events(first_alert["alert_id"])
        self.assertEqual(len(linked_events), 5)
        for evt in linked_events:
            self.assertEqual(evt["source_ip"], "10.0.0.5")
            self.assertEqual(evt["event_type"], "SSH_FAILED_LOGIN")

    def test_update_alert_status_persistent(self):
        """Verify persistent alert status changes (NEW -> ACKNOWLEDGED -> RESOLVED)."""
        seed(self.test_db_path)
        alerts = db.get_all_alerts()
        new_alert = [a for a in alerts if a["status"] == "NEW"][0]
        alert_id = new_alert["alert_id"]

        # Step 1: ACKNOWLEDGE
        db.update_alert_status(alert_id, "ACKNOWLEDGED")
        updated_alerts = db.get_all_alerts()
        target = [a for a in updated_alerts if a["alert_id"] == alert_id][0]
        self.assertEqual(target["status"], "ACKNOWLEDGED")

        # Step 2: RESOLVE
        db.update_alert_status(alert_id, "RESOLVED")
        updated_alerts = db.get_all_alerts()
        target = [a for a in updated_alerts if a["alert_id"] == alert_id][0]
        self.assertEqual(target["status"], "RESOLVED")

    def test_update_alert_status_invalid_value(self):
        """Verify updating alert status with an invalid value raises ValueError."""
        seed(self.test_db_path)
        with self.assertRaises(ValueError):
            db.update_alert_status(1, "INVALID_STATUS")

    def test_update_alert_status_nonexistent_id(self):
        """Verify updating alert status for a non-existent alert_id raises ValueError."""
        seed(self.test_db_path)
        with self.assertRaises(ValueError):
            db.update_alert_status(99999, "ACKNOWLEDGED")

    def test_safety_lock_protects_prod_db(self):
        """Verify that seed() refuses to delete or overwrite production data/siem.db without force flag."""
        with self.assertRaises(PermissionError):
            seed(target_db_path=PROD_DB_PATH, force_overwrite_prod=False)

    def test_empty_database_handling(self):
        """Verify graceful empty structures returned when database file exists but has no rows or tables."""
        conn = sqlite3.connect(str(self.test_db_path))
        conn.close()

        summary = db.get_alert_summary()
        self.assertEqual(summary["total_alerts"], 0)
        self.assertEqual(summary["new_count"], 0)
        self.assertEqual(len(db.get_all_alerts()), 0)
        self.assertEqual(len(db.get_all_events()), 0)
        self.assertEqual(len(db.get_alert_events(1)), 0)


if __name__ == "__main__":
    unittest.main()
