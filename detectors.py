"""
detectors.py
------------
Lightweight, stateful heuristics for flagging suspicious traffic.

These are intentionally simple (this is a learning/portfolio project,
not a production IDS -- that's what the Suricata task is for). The goal
is to demonstrate understanding of *why* certain traffic patterns matter:

  - Port scan detection   -> many distinct destination ports from one
                              source IP in a short time window
  - Plaintext credentials -> HTTP payloads carrying obvious
                              username/password fields
  - High-risk ports       -> traffic touching ports commonly abused
                              (Telnet, RDP, SMB, etc.)
"""

import re
import time
from collections import defaultdict, deque

# Ports that are frequently targeted/abused and worth flagging on sight.
HIGH_RISK_PORTS = {21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5900}

# Crude but effective patterns for spotting plaintext creds in HTTP bodies.
CREDENTIAL_PATTERNS = [
    re.compile(r"(user(name)?|login)\s*=\s*[^&\s]+", re.IGNORECASE),
    re.compile(r"pass(word)?\s*=\s*[^&\s]+", re.IGNORECASE),
]


class PortScanDetector:
    """
    Tracks (src_ip -> recent destination ports) in a sliding time window.
    If one source touches more than `threshold` distinct ports inside
    `window_seconds`, we call it a likely port scan.
    """

    def __init__(self, threshold: int = 15, window_seconds: int = 10):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # src_ip -> deque of (timestamp, dst_port)
        self._activity: dict[str, deque] = defaultdict(deque)
        self._already_flagged: set[str] = set()

    def observe(self, src_ip: str, dst_port: int) -> str | None:
        if src_ip is None or dst_port is None:
            return None

        now = time.time()
        history = self._activity[src_ip]
        history.append((now, dst_port))

        # Drop entries older than the window.
        while history and now - history[0][0] > self.window_seconds:
            history.popleft()

        distinct_ports = {p for _, p in history}

        if len(distinct_ports) >= self.threshold:
            if src_ip not in self._already_flagged:
                self._already_flagged.add(src_ip)
                return (
                    f"Possible port scan from {src_ip}: "
                    f"{len(distinct_ports)} distinct ports in "
                    f"{self.window_seconds}s"
                )
            return None  # already alerted for this IP recently

        if src_ip in self._already_flagged and len(distinct_ports) < 3:
            # Activity died down -- allow re-flagging if it starts again.
            self._already_flagged.discard(src_ip)

        return None


def check_credentials(payload_preview: str | None) -> str | None:
    """Return an alert string if a payload looks like it contains
    plaintext login credentials, else None."""
    if not payload_preview:
        return None
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(payload_preview):
            return "Plaintext credential pattern detected in payload"
    return None


def check_high_risk_port(dst_port: int | None) -> str | None:
    """Return an alert string if the destination port is one we
    consider high-risk, else None."""
    if dst_port in HIGH_RISK_PORTS:
        return f"Traffic to high-risk port {dst_port}"
    return None
