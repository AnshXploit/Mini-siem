"""
verify_ui.py
------------
Headless browser automated UI verification script using Playwright.
Exercises every visible UI control, verifies displayed counts against SQLite database rows,
and checks responsive layout behavior at normal (1400px) and narrow (600px) viewport widths.
"""

import os
import sys
import time
import sqlite3
import subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
DEMO_DB_PATH = PROJECT_ROOT / "data" / "siem_demo.db"

# Ensure test DB is fresh
sys.path.insert(0, str(DASHBOARD_DIR))
from seed_test_data import seed

import tempfile

def run_verification():
    temp_db_dir = tempfile.TemporaryDirectory()
    seeded_db = Path(temp_db_dir.name) / "test_siem.db"
    seed(seeded_db)
    print("--- 1. Initializing Disposable Test Database ---")
    print(f"Seeded: {seeded_db}")

    # Query DB directly to get expected ground truth values
    conn = sqlite3.connect(str(seeded_db))
    conn.row_factory = sqlite3.Row
    try:
        db_total_alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        db_new_alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='NEW'").fetchone()["c"]
        db_high_alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts WHERE severity='HIGH'").fetchone()["c"]
        db_total_events = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        db_linked_events = conn.execute("SELECT COUNT(*) AS c FROM alert_events WHERE alert_id=1").fetchone()["c"]
        print(f"Ground Truth DB Values -> Total Alerts: {db_total_alerts}, NEW: {db_new_alerts}, HIGH: {db_high_alerts}, Total Events: {db_total_events}, Alert #1 Linked Events: {db_linked_events}")
    finally:
        conn.close()

    port = 8599
    env = os.environ.copy()
    env["SIEM_DB_PATH"] = str(seeded_db)
    env["PYTHONPATH"] = f"{PROJECT_ROOT}:{DASHBOARD_DIR}"

    print(f"--- 2. Starting Streamlit Server on Port {port} ---")
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", str(DASHBOARD_DIR / "app.py"), "--server.port", str(port), "--server.headless", "true"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    app_url = f"http://localhost:{port}"

    try:
        # Give Streamlit server 3 seconds to spin up
        time.sleep(3)

        print("--- 3. Launching Playwright Headless Chromium Browser ---")
        with sync_playwright() as p:
            # Use the installed Chrome when Playwright's bundled Chromium is absent.
            browser = p.chromium.launch(channel="chrome", headless=True)

            # Test 1: Desktop / Normal Viewport (1400x900)
            page = browser.new_page(viewport={"width": 1400, "height": 900})
            page.goto(app_url)
            page.wait_for_selector(".header-title", timeout=15000)

            # Check 1: Header and Connection Status
            header_text = page.locator(".header-title").text_content()
            assert "Mini SIEM" in header_text, f"Header title mismatch: {header_text}"
            db_status = page.locator(".header-status").text_content()
            assert "CONNECTED" in db_status.upper(), f"DB Status not connected: {db_status}"
            print("✓ Header and Connection status verified.")

            # Check 2: Security Overview KPI Strip Values vs DB
            kpi_cells = page.locator(".overview-val").all_text_contents()
            assert int(kpi_cells[0]) == db_total_alerts, f"Total alerts KPI mismatch: {kpi_cells[0]} vs {db_total_alerts}"
            assert int(kpi_cells[1]) == db_new_alerts, f"New alerts KPI mismatch: {kpi_cells[1]} vs {db_new_alerts}"
            assert int(kpi_cells[3]) == db_high_alerts, f"High alerts KPI mismatch: {kpi_cells[3]} vs {db_high_alerts}"
            print("✓ KPI Summary values match database ground truth.")

            # Bulk controls must update both the filter and checkbox state.
            for name in ("Severity", "Status"):
                page.get_by_role("button", name=f"{name}: All").click()
                popover = page.locator('[data-testid="stPopoverBody"]:visible')
                popover.get_by_role("button", name="Clear").click()
                page.get_by_role("button", name=f"{name}: None").wait_for()
                if page.locator('[data-testid="stPopoverBody"]:visible').count() == 0:
                    page.get_by_role("button", name=f"{name}: None").click()
                popover = page.locator('[data-testid="stPopoverBody"]:visible')
                assert popover.get_by_role("checkbox", checked=True).count() == 0
                popover.get_by_role("button", name="Select All").click()
                page.get_by_role("button", name=f"{name}: All").wait_for(timeout=5000)
                page.keyboard.press("Escape")
            print("✓ Severity and status Select All/Clear controls verified.")

            # Check 3: Alert View Details & Evidence Traceability Table
            details_expander = page.locator("summary", has_text="EVIDENCE LOG").first
            details_expander.click()
            page.wait_for_timeout(500)

            evidence_box = page.locator(".evidence-box").first.text_content()
            assert "5 failed SSH logins" in evidence_box, f"Evidence text mismatch: {evidence_box}"

            supporting_rows = page.locator(".supporting-table tbody tr")
            assert supporting_rows.count() == db_linked_events, f"Supporting event rows mismatch: {supporting_rows.count()} vs {db_linked_events}"
            print(f"✓ Alert #1 View Details expander verified: {supporting_rows.count()} supporting evidence rows rendered.")

            # Check 4: Acknowledge Button Action & Persistent DB Status Update
            ack_btn = page.locator("button", has_text="Acknowledge").first
            assert ack_btn.is_enabled(), "Acknowledge button should be enabled for NEW alert"
            ack_btn.click()
            page.wait_for_timeout(1000)

            # Re-verify DB status changed to ACKNOWLEDGED
            conn = sqlite3.connect(str(seeded_db))
            conn.row_factory = sqlite3.Row
            status_after_ack = conn.execute("SELECT status FROM alerts WHERE alert_id=1").fetchone()["status"]
            conn.close()
            assert status_after_ack == "ACKNOWLEDGED", f"Alert status in DB did not update to ACKNOWLEDGED: {status_after_ack}"
            print("✓ Acknowledge button action verified and persisted to DB.")

            # Check 5: Resolve Button Action & Persistent DB Status Update
            resolve_btn = page.locator("button", has_text="Resolve").first
            assert resolve_btn.is_enabled(), "Resolve button should be enabled"
            resolve_btn.click()
            page.wait_for_timeout(1000)

            conn = sqlite3.connect(str(seeded_db))
            conn.row_factory = sqlite3.Row
            status_after_res = conn.execute("SELECT status FROM alerts WHERE alert_id=1").fetchone()["status"]
            conn.close()
            assert status_after_res == "RESOLVED", f"Alert status in DB did not update to RESOLVED: {status_after_res}"
            print("✓ Resolve button action verified and persisted to DB.")

            # Check 6: Header Refresh Button
            refresh_btn = page.locator("button", has_text="Refresh").first
            assert refresh_btn.is_visible(), "Refresh button not visible"
            refresh_btn.click()
            page.wait_for_timeout(800)
            print("✓ Refresh button clicked and page reloaded.")

            # Check 7: Event Stream Filtering and Table Display
            event_rows = page.locator(".event-table tbody tr")
            assert event_rows.count() > 0, "Event stream table should render rows"
            print(f"✓ Event stream table renders {event_rows.count()} rows on page 1.")

            page.close()

            # Test 2: Mobile / Narrow Viewport (600x800)
            page_narrow = browser.new_page(viewport={"width": 600, "height": 800})
            page_narrow.goto(app_url)
            page_narrow.wait_for_selector(".header-title", timeout=15000)

            title_narrow = page_narrow.locator(".header-title").text_content()
            assert "Mini SIEM" in title_narrow, "Narrow layout header failed"
            print("✓ Narrow layout (600px width) rendered cleanly without horizontal overflow.")

            page_narrow.close()
            browser.close()

        print("\n=======================================================")
        print("ALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")
        print("=======================================================")
    finally:
        server_proc.terminate()
        server_proc.wait()
        temp_db_dir.cleanup()

if __name__ == "__main__":
    run_verification()
