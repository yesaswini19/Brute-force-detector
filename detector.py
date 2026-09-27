"""
detector.py
-----------
Core brute-force login detection engine.

Logic:
- Every login attempt (success/failure) is recorded with a timestamp, IP and username.
- For each IP (and separately for each username), we look at failed attempts inside a
  sliding time window (default: 5 failed attempts within 60 seconds).
- If the threshold is crossed, the IP (or username) is flagged as "under attack" and
  automatically blocked for a cooldown period (default: 5 minutes).
- All attempts and alerts are persisted to logs/login_attempts.log and logs/alerts.log
  so the system can be audited or fed into other tools (SIEM, fail2ban, etc.).
"""

import json
import os
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Vercel's filesystem is read-only except for /tmp. Locally, use a normal
# "logs" folder next to the code so files are easy to find.
if os.environ.get("VERCEL"):
    LOG_DIR = "/tmp/logs"
else:
    LOG_DIR = os.path.join(BASE_DIR, "logs")

ATTEMPTS_LOG = os.path.join(LOG_DIR, "login_attempts.log")
ALERTS_LOG = os.path.join(LOG_DIR, "alerts.log")

os.makedirs(LOG_DIR, exist_ok=True)


class BruteForceDetector:
    def __init__(
        self,
        failed_attempt_threshold: int = 5,
        window_seconds: int = 60,
        block_seconds: int = 300,
    ):
        self.failed_attempt_threshold = failed_attempt_threshold
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds

        # ip/username -> deque of failed-attempt timestamps
        self._failed_by_ip = defaultdict(deque)
        self._failed_by_user = defaultdict(deque)

        # ip/username -> unblock timestamp (epoch). Present = currently blocked.
        self._blocked_ips = {}
        self._blocked_users = {}

        # Full history kept in memory for the dashboard (most recent first)
        self._history = deque(maxlen=500)
        self._alerts = deque(maxlen=200)

        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def is_blocked(self, ip: str, username: str) -> bool:
        with self._lock:
            self._expire_blocks()
            return ip in self._blocked_ips or username in self._blocked_users

    def record_attempt(self, ip: str, username: str, success: bool) -> dict:
        """
        Record a login attempt and run detection. Returns a result dict describing
        what happened (blocked / allowed / newly_flagged).
        """
        now = time.time()
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip,
            "username": username,
            "success": success,
        }

        with self._lock:
            self._expire_blocks()

            # Already blocked? Reject immediately without counting a new "failure window" entry.
            if ip in self._blocked_ips or username in self._blocked_users:
                event["result"] = "blocked"
                self._append_history(event)
                self._write_log(ATTEMPTS_LOG, event)
                return event

            if success:
                # A successful login clears the failure streak for that ip/username.
                self._failed_by_ip[ip].clear()
                self._failed_by_user[username].clear()
                event["result"] = "success"
            else:
                self._failed_by_ip[ip].append(now)
                self._failed_by_user[username].append(now)
                self._trim_window(self._failed_by_ip[ip], now)
                self._trim_window(self._failed_by_user[username], now)

                ip_count = len(self._failed_by_ip[ip])
                user_count = len(self._failed_by_user[username])

                flagged_reason = None
                if ip_count >= self.failed_attempt_threshold:
                    self._blocked_ips[ip] = now + self.block_seconds
                    flagged_reason = f"IP {ip} exceeded {ip_count} failed attempts in {self.window_seconds}s"
                if user_count >= self.failed_attempt_threshold:
                    self._blocked_users[username] = now + self.block_seconds
                    reason2 = f"user '{username}' exceeded {user_count} failed attempts in {self.window_seconds}s"
                    flagged_reason = f"{flagged_reason}; {reason2}" if flagged_reason else reason2

                if flagged_reason:
                    event["result"] = "failed_and_blocked"
                    alert = {
                        "timestamp": event["timestamp"],
                        "ip": ip,
                        "username": username,
                        "reason": flagged_reason,
                        "block_seconds": self.block_seconds,
                    }
                    self._alerts.appendleft(alert)
                    self._write_log(ALERTS_LOG, alert)
                else:
                    event["result"] = "failed"

            self._append_history(event)
            self._write_log(ATTEMPTS_LOG, event)
            return event

    def get_dashboard_state(self) -> dict:
        with self._lock:
            self._expire_blocks()
            return {
                "history": list(self._history),
                "alerts": list(self._alerts),
                "blocked_ips": [
                    {"ip": ip, "unblocks_in": round(ts - time.time(), 1)}
                    for ip, ts in self._blocked_ips.items()
                ],
                "blocked_users": [
                    {"username": u, "unblocks_in": round(ts - time.time(), 1)}
                    for u, ts in self._blocked_users.items()
                ],
                "config": {
                    "failed_attempt_threshold": self.failed_attempt_threshold,
                    "window_seconds": self.window_seconds,
                    "block_seconds": self.block_seconds,
                },
            }

    def unblock_all(self):
        with self._lock:
            self._blocked_ips.clear()
            self._blocked_users.clear()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _trim_window(self, dq: deque, now: float):
        while dq and now - dq[0] > self.window_seconds:
            dq.popleft()

    def _expire_blocks(self):
        now = time.time()
        for d in (self._blocked_ips, self._blocked_users):
            expired = [k for k, unblock_ts in d.items() if unblock_ts <= now]
            for k in expired:
                del d[k]

    def _append_history(self, event: dict):
        self._history.appendleft(event)

    @staticmethod
    def _write_log(path: str, record: dict):
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\n")
