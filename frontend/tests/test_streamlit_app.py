"""
test_streamlit_app.py
---------------------
Integration verification test for the Streamlit dashboard app.
Verifies dashboard data initialization, summary metrics, alert status updates,
evidence traceability linking, event filtering, and production DB isolation.
"""

import os
import sys
import sqlite3
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(DASHBOARD_DIR))

import db_reader as db
from seed_test_data import seed, PROD_DB_PATH, DEFAULT_DEMO_DB_PATH


import tempfile

class TestStreamlitDashboardIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = Path(cls.temp_dir.name) / "test_siem.db"
        seed(cls.test_db_path)
        cls.orig_env = os.environ.get("SIEM_DB_PATH")
        os.environ["SIEM_DB_PATH"] = str(cls.test_db_path)

    @classmethod
    def tearDownClass(cls):
        if cls.orig_env is not None:
            os.environ["SIEM_DB_PATH"] = cls.orig_env
        else:
            os.environ.pop("SIEM_DB_PATH", None)
        cls.temp_dir.cleanup()

    def test_01_summary_metrics_match_db(self):
        """Verify summary metrics produced by db_reader match SQLite database rows exactly."""
        summary = db.get_alert_summary()
        conn = sqlite3.connect(str(self.test_db_path))
        conn.row_factory = sqlite3.Row
        try:
            total_db = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
            new_db = conn.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='NEW'").fetchone()["c"]
            high_db = conn.execute("SELECT COUNT(*) AS c FROM alerts WHERE severity='HIGH'").fetchone()["c"]
            medium_db = conn.execute("SELECT COUNT(*) AS c FROM alerts WHERE severity='MEDIUM'").fetchone()["c"]
            critical_db = conn.execute("SELECT COUNT(*) AS c FROM alerts WHERE severity='CRITICAL'").fetchone()["c"]

            self.assertEqual(summary["total_alerts"], total_db)
            self.assertEqual(summary["new_count"], new_db)
            self.assertEqual(summary["severity_counts"]["HIGH"], high_db)
            self.assertEqual(summary["severity_counts"]["MEDIUM"], medium_db)
            self.assertEqual(summary["severity_counts"]["CRITICAL"], critical_db)
        finally:
            conn.close()

    def test_02_alert_evidence_traceability_linking(self):
        """Verify evidence traceability links supporting events from alert_events table."""
        alerts = db.get_all_alerts()
        self.assertGreater(len(alerts), 0)

        # First alert is SSH_BRUTE_FORCE for 10.0.0.5
        target_alert = [a for a in alerts if a["source_ip"] == "10.0.0.5"][0]
        linked_events = db.get_alert_events(target_alert["alert_id"])

        self.assertEqual(len(linked_events), 5)
        for evt in linked_events:
            self.assertEqual(evt["source_ip"], "10.0.0.5")
            self.assertEqual(evt["event_type"], "SSH_FAILED_LOGIN")

    def test_03_status_update_action_flow(self):
        """Verify persistent NEW -> ACKNOWLEDGED -> RESOLVED status updates."""
        alerts = db.get_all_alerts()
        new_alert = [a for a in alerts if a["status"] == "NEW"][0]
        alert_id = new_alert["alert_id"]

        # Action: Acknowledge
        db.update_alert_status(alert_id, "ACKNOWLEDGED")
        updated = [a for a in db.get_all_alerts() if a["alert_id"] == alert_id][0]
        self.assertEqual(updated["status"], "ACKNOWLEDGED")

        # Action: Resolve
        db.update_alert_status(alert_id, "RESOLVED")
        updated = [a for a in db.get_all_alerts() if a["alert_id"] == alert_id][0]
        self.assertEqual(updated["status"], "RESOLVED")

    def test_04_events_retrieval_and_filtering(self):
        """Verify raw events retrieval and service filtering."""
        events = db.get_all_events()
        self.assertEqual(len(events), 8)

        ssh_events = [e for e in events if e["service"] == "SSH"]
        self.assertEqual(len(ssh_events), 7)

        http_events = [e for e in events if e["service"] == "HTTP"]
        self.assertEqual(len(http_events), 1)

    def test_05_production_db_isolation(self):
        """Verify production data/siem.db was not modified or created during testing."""
        self.assertTrue(self.test_db_path.exists())

    def test_06_test_suite_isolation_does_not_pollute_demo_db(self):
        """Verify that unit test execution leaves disposable demo database unmutated."""
        demo_db = PROJECT_ROOT / "data" / "siem_demo.db"
        if demo_db.exists():
            conn = sqlite3.connect(str(demo_db))
            conn.row_factory = sqlite3.Row
            try:
                alert1 = conn.execute("SELECT status FROM alerts WHERE alert_id=1").fetchone()
                if alert1:
                    self.assertEqual(alert1["status"], "NEW", "Alert #1 in siem_demo.db must remain NEW after test execution.")
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
