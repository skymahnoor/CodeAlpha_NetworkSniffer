"""
capture.py
----------
The core capture engine. Wires together parsing, detection, display,
and logging around Scapy's sniff() loop. This is the only module that
talks to Scapy directly for live capture.
"""

from collections import Counter
from scapy.all import sniff

from .parsers import parse_packet
from .detectors import PortScanDetector, check_credentials, check_high_risk_port
from .display import print_packet
from .logger import SessionLogger


class SnifferSession:
    """
    Encapsulates one capture session: holds running statistics,
    detector state, and the logger, and exposes a single callback
    (`handle_packet`) for Scapy to invoke per packet.
    """

    def __init__(self, verbose: bool = False, log_dir: str = "logs", quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self.logger = SessionLogger(output_dir=log_dir)
        self.port_scan_detector = PortScanDetector()

        self.total_packets = 0
        self.protocol_counts = Counter()
        self.unique_src_ips = set()
        self.src_ip_counts = Counter()
        self.alert_count = 0

    def handle_packet(self, pkt):
        info = parse_packet(pkt)
        if info is None:
            return  # non-IP packet, e.g. ARP -- skip for this project's scope

        self.total_packets += 1
        self.protocol_counts[info["protocol"]] += 1

        if info["src_ip"]:
            self.unique_src_ips.add(info["src_ip"])
            self.src_ip_counts[info["src_ip"]] += 1

        alerts = self._run_detectors(info)
        self.alert_count += len(alerts)

        self.logger.record(info, alerts)

        if not self.quiet:
            print_packet(info, alerts, verbose=self.verbose)

    def _run_detectors(self, info: dict) -> list[str]:
        alerts = []

        scan_alert = self.port_scan_detector.observe(info["src_ip"], info["dst_port"])
        if scan_alert:
            alerts.append(scan_alert)

        cred_alert = check_credentials(info.get("payload_preview"))
        if cred_alert:
            alerts.append(cred_alert)

        risk_alert = check_high_risk_port(info.get("dst_port"))
        if risk_alert:
            alerts.append(risk_alert)

        return alerts

    def summary(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "protocol_counts": dict(self.protocol_counts),
            "unique_src_ips": self.unique_src_ips,
            "alert_count": self.alert_count,
            "top_talkers": self.src_ip_counts.most_common(5),
        }

    def finalize(self):
        """Flush logs to disk. Call this when capture stops."""
        return self.logger.flush()


def start_capture(interface: str, bpf_filter: str | None, session: SnifferSession,
                   packet_count: int = 0):
    """
    Start a blocking Scapy sniff() loop.

    packet_count = 0 means "capture indefinitely until interrupted",
    matching Scapy's own convention for sniff(count=0).
    """
    sniff(
        iface=interface,
        filter=bpf_filter,
        prn=session.handle_packet,
        store=False,         # don't keep packets in memory -- we already
                              # extract what we need in handle_packet
        count=packet_count,
    )
