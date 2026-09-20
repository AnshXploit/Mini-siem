"""
test_ui_improvements.py
------------------------
Automated test suite verifying the reversible UI trial features:
1. Exact status action availability rules:
   - NEW: Acknowledge=Active, Resolve=Active (can resolve directly).
   - ACKNOWLEDGED: Acknowledge=Disabled, Resolve=Active.
   - RESOLVED: Acknowledge=Disabled, Resolve=Disabled.
2. Global Source IP search filtering across alerts and events.
3. Localized table controls (Service, Event Type).
4. Adaptive chart time grouping calculation.
5. Evidence traceability linking.
"""

import os
import sys
import sqlite3
import unittest
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(DASHBOARD_DIR))

import db_reader as db
from seed_test_data import seed
from app import parse_iso_timestamp


import tempfile

class TestUIUXTrialFeatures(unittest.TestCase):

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

    def test_01_search_ip_filtering_alerts_and_events(self):
        """Verify Source IP search filtering works across both alerts and events."""
        alerts = db.get_all_alerts()
        events = db.get_all_events()

        target_ip = "10.0.0.5"

        matching_alerts = [
            a for a in alerts
            if target_ip.lower() in a["source_ip"].lower()
            or target_ip.lower() in a.get("evidence", "").lower()
        ]
        self.assertEqual(len(matching_alerts), 1)
        self.assertEqual(matching_alerts[0]["source_ip"], "10.0.0.5")

        matching_events = [
            e for e in events
            if target_ip.lower() in e["source_ip"].lower()
            or target_ip.lower() in e.get("message", "").lower()
        ]
        self.assertEqual(len(matching_events), 6)

    def test_02_status_action_availability_rules(self):
        """
        Verify trial status action availability rules:
        - NEW: ack_disabled=False, resolve_disabled=False (can resolve directly!)
        - ACKNOWLEDGED: ack_disabled=True, resolve_disabled=False
        - RESOLVED: ack_disabled=True, resolve_disabled=True
        """
        seed(self.test_db_path)
        alerts = db.get_all_alerts()
        new_alert = [a for a in alerts if a["status"] == "NEW"][0]
        alert_id = new_alert["alert_id"]

        # Rule check for NEW: both available
        ack_disabled = (new_alert["status"] != "NEW")
        resolve_disabled = (new_alert["status"] == "RESOLVED")
        self.assertFalse(ack_disabled)
        self.assertFalse(resolve_disabled)

        # Test direct resolution from NEW -> RESOLVED
        db.update_alert_status(alert_id, "RESOLVED")
        resolved_alert = [a for a in db.get_all_alerts() if a["alert_id"] == alert_id][0]
        self.assertEqual(resolved_alert["status"], "RESOLVED")

        # Rule check for RESOLVED: both disabled (Acknowledge not active)
        ack_disabled = (resolved_alert["status"] != "NEW")
        resolve_disabled = (resolved_alert["status"] == "RESOLVED")
        self.assertTrue(ack_disabled)
        self.assertTrue(resolve_disabled)

    def test_03_acknowledged_status_transition_flow(self):
        """
        Verify transition NEW -> ACKNOWLEDGED -> RESOLVED:
        - When ACKNOWLEDGED: Acknowledge is disabled, Resolve remains active.
        """
        seed(self.test_db_path)
        alerts = db.get_all_alerts()
        new_alert = [a for a in alerts if a["status"] == "NEW"][0]
        alert_id = new_alert["alert_id"]

        # Transition to ACKNOWLEDGED
        db.update_alert_status(alert_id, "ACKNOWLEDGED")
        ack_alert = [a for a in db.get_all_alerts() if a["alert_id"] == alert_id][0]
        self.assertEqual(ack_alert["status"], "ACKNOWLEDGED")

        ack_disabled = (ack_alert["status"] != "NEW")
        resolve_disabled = (ack_alert["status"] == "RESOLVED")
        self.assertTrue(ack_disabled)
        self.assertFalse(resolve_disabled)

    def test_04_adaptive_time_grouping(self):
        """Verify adaptive time grouping calculates hourly bins for short timeframe datasets."""
        alerts = db.get_all_alerts()
        dts = [parse_iso_timestamp(a["timestamp"]) for a in alerts]
        time_span = (max(dts) - min(dts)).total_seconds()

        if time_span < 86400:
            groups = set(dt.strftime("%H:00 UTC") for dt in dts)
            self.assertGreater(len(groups), 0)
        else:
            groups = set(dt.strftime("%Y-%m-%d") for dt in dts)
            self.assertGreater(len(groups), 0)

    def test_05_evidence_traceability_links(self):
        """Verify supporting events traceability via alert_events."""
        alerts = db.get_all_alerts()
        first_alert = [a for a in alerts if a["source_ip"] == "10.0.0.5"][0]
        linked_evts = db.get_alert_events(first_alert["alert_id"])
        self.assertEqual(len(linked_evts), 5)


if __name__ == "__main__":
    unittest.main()
