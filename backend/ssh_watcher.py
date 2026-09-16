"""
SSH Watcher

What this does, in plain terms:
1. Runs a command that shows SSH login attempts as they happen, live.
2. Reads each line one at a time.
3. Checks if the line is a "failed login" or "successful login".
4. If it is, pulls out the important info (who, from where, when).
5. Saves it to the shared database.
6. Checks if it completes a brute-force pattern (3+ failures from the
   same IP within 2 minutes) and raises an alert if so.
"""

import re
import subprocess
from datetime import datetime, timezone

from db import setup_database, save_event, save_alert
from detector import check_for_brute_force

# This regex looks for lines like:
#   Failed password for invalid user user from ::1 port 44816 ssh2
#   Failed password for ansh from 192.168.1.5 port 44816 ssh2
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (invalid user )?(?P<username>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)"
)

# This regex looks for lines like:
#   Accepted password for ansh from ::1 port 49988 ssh2
SUCCESS_LOGIN_PATTERN = re.compile(
    r"Accepted password for (?P<username>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)"
)


def parse_line(line: str) -> dict | None:
    """
    Takes one raw log line. Returns a clean dictionary if it's something
    we care about, or None if it's a line we should ignore (like the
    "Server listening on port 22" startup message).
    """
    failed_match = FAILED_LOGIN_PATTERN.search(line)
    if failed_match:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": failed_match.group("source_ip"),
            "event_type": "SSH_FAILED_LOGIN",
            "service": "ssh",
            "message": f"Failed login attempt for user '{failed_match.group('username')}'",
            "raw_log": line.strip(),
        }

    success_match = SUCCESS_LOGIN_PATTERN.search(line)
    if success_match:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": success_match.group("source_ip"),
            "event_type": "SSH_SUCCESS_LOGIN",
            "service": "ssh",
            "message": f"Successful login for user '{success_match.group('username')}'",
            "raw_log": line.strip(),
        }

    return None  # not a line we care about


def watch_ssh_logs():
    """
    Runs journalctl in "follow" mode (like `tail -f`) so we see new SSH
    log lines the instant they happen, and processes each one.
    """
    print("Watching SSH logs live... (press Ctrl+C to stop)")
    print("Try logging in with a wrong password in another terminal to test.\n")

    # -f means "follow" (keep watching for new lines, like tail -f)
    # -u ssh means "only show logs from the ssh service"
    # -n 0 means "don't show old history, only new lines from now on"
    process = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-n", "0", "--no-pager"],
        stdout=subprocess.PIPE,
        text=True,
    )

    for line in process.stdout:
        event = parse_line(line)
        if event:
            print("EVENT DETECTED:")
            for key, value in event.items():
                print(f"   {key}: {value}")
            save_event(event)

            alert = check_for_brute_force(event)
            if alert:
                print("\n🚨 ALERT: BRUTE FORCE DETECTED 🚨")
                for key, value in alert.items():
                    print(f"   {key}: {value}")
                save_alert(alert)

            print()


if __name__ == "__main__":
    setup_database()
    watch_ssh_logs()
