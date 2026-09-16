from datetime import datetime, timedelta, timezone

FAILED_ATTEMPT_THRESHOLD = 3
TIME_WINDOW_SECONDS = 120
ALERT_COOLDOWN_SECONDS = 60

_failed_attempts_by_ip: dict[str, list[datetime]] = {}
_last_alert_time_by_ip: dict[str, datetime] = {}


def check_for_brute_force(event: dict) -> dict | None:
    if event["event_type"] != "SSH_FAILED_LOGIN":
        return None

    source_ip = event["source_ip"]
    now = datetime.now(timezone.utc)

    _failed_attempts_by_ip.setdefault(source_ip, []).append(now)

    cutoff = now - timedelta(seconds=TIME_WINDOW_SECONDS)
    _failed_attempts_by_ip[source_ip] = [
        t for t in _failed_attempts_by_ip[source_ip] if t > cutoff
    ]

    recent_failures = _failed_attempts_by_ip[source_ip]

    if len(recent_failures) < FAILED_ATTEMPT_THRESHOLD:
        return None

    last_alert = _last_alert_time_by_ip.get(source_ip)
    if last_alert and (now - last_alert).total_seconds() < ALERT_COOLDOWN_SECONDS:
        return None

    _last_alert_time_by_ip[source_ip] = now

    return {
        "timestamp": now.isoformat(),
        "alert_type": "SSH_BRUTE_FORCE",
        "source_ip": source_ip,
        "severity": "HIGH",
        "event_count": len(recent_failures),
        "evidence": f"{len(recent_failures)} failed SSH logins from {source_ip} within {TIME_WINDOW_SECONDS} seconds",
    }
