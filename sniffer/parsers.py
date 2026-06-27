"""
parsers.py
----------
Turns raw Scapy packets into clean, structured dictionaries.
Keeping this separate from capture.py means the capture engine
doesn't need to know anything about packet internals -- it just
hands packets here and gets back simple data.
"""

from datetime import datetime
from scapy.all import IP, IPv6, TCP, UDP, ICMP, Ether, Raw, DNS, DNSQR

# Well-known ports -> human-readable service names.
# Not exhaustive on purpose -- just enough to make CLI output readable.
PORT_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}


def service_name(port: int) -> str:
    """Map a port number to a readable service name, or '' if unknown."""
    return PORT_SERVICES.get(port, "")


def parse_packet(pkt) -> dict | None:
    """
    Extract the fields we care about from a single Scapy packet.

    Returns a flat dict describing the packet, or None if the packet
    doesn't have a layer we're interested in (e.g. non-IP traffic).
    This keeps every downstream consumer (display, logger, detectors)
    working with the same simple shape instead of touching Scapy directly.
    """
    info = {
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
        "dst_mac": pkt[Ether].dst if pkt.haslayer(Ether) else None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "length": len(pkt),
        "flags": None,
        "payload_preview": None,
        "dns_query": None,
    }

    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        info["src_ip"] = ip_layer.src
        info["dst_ip"] = ip_layer.dst
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
        info["src_ip"] = ip_layer.src
        info["dst_ip"] = ip_layer.dst
    else:
        # Not an IP packet (e.g. ARP) -- nothing more we extract for now.
        return None

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info["protocol"] = "TCP"
        info["src_port"] = tcp.sport
        info["dst_port"] = tcp.dport
        info["flags"] = str(tcp.flags)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        info["protocol"] = "UDP"
        info["src_port"] = udp.sport
        info["dst_port"] = udp.dport
    elif pkt.haslayer(ICMP):
        info["protocol"] = "ICMP"
    else:
        info["protocol"] = "OTHER"

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            info["dns_query"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        except Exception:
            pass

    if pkt.haslayer(Raw):
        try:
            raw_bytes = bytes(pkt[Raw].load)
            text = raw_bytes.decode(errors="ignore")
            # Keep it short -- this is a preview for the CLI, not a dump.
            printable = "".join(c if c.isprintable() else "." for c in text)
            info["payload_preview"] = printable[:120]
        except Exception:
            info["payload_preview"] = None

    return info
