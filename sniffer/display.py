"""
display.py
----------
All terminal presentation logic lives here, using `rich` for color
and layout. Keeping this separate means capture.py stays focused on
packet handling instead of being cluttered with print formatting.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

console = Console()

PROTOCOL_COLORS = {
    "TCP": "cyan",
    "UDP": "magenta",
    "ICMP": "yellow",
    "OTHER": "white",
}


def print_banner(interface: str, bpf_filter: str | None):
    console.print(
        Panel.fit(
            f"[bold green]CodeAlpha Network Sniffer[/bold green]\n"
            f"Interface: [bold]{interface}[/bold]\n"
            f"Filter: [bold]{bpf_filter or 'none (all traffic)'}[/bold]\n"
            f"[dim]Press Ctrl+C to stop[/dim]",
            border_style="green",
        )
    )


def print_packet(info: dict, alerts: list[str], verbose: bool = False):
    """Print a single packet as one readable line, plus any alerts."""
    proto = info["protocol"] or "OTHER"
    color = PROTOCOL_COLORS.get(proto, "white")

    src = f"{info['src_ip']}:{info['src_port']}" if info["src_port"] else info["src_ip"]
    dst = f"{info['dst_ip']}:{info['dst_port']}" if info["dst_port"] else info["dst_ip"]

    line = Text()
    line.append(f"[{info['timestamp']}] ", style="dim")
    line.append(f"{proto:<6}", style=f"bold {color}")
    line.append(f" {src or '?':<22} -> {dst or '?':<22} ", style="white")
    line.append(f"{info['length']}B", style="dim")

    if info.get("dns_query"):
        line.append(f"  DNS query: {info['dns_query']}", style="bright_blue")

    console.print(line)

    if verbose and info.get("payload_preview"):
        console.print(f"    payload: {info['payload_preview']!r}", style="dim italic")

    for alert in alerts:
        console.print(f"    [!] {alert}", style="bold red")


def print_summary(stats: dict):
    """Print an end-of-session summary table."""
    table = Table(title="Capture Summary", show_header=True, header_style="bold green")
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    table.add_row("Total packets", str(stats["total_packets"]))
    table.add_row("TCP packets", str(stats["protocol_counts"].get("TCP", 0)))
    table.add_row("UDP packets", str(stats["protocol_counts"].get("UDP", 0)))
    table.add_row("ICMP packets", str(stats["protocol_counts"].get("ICMP", 0)))
    table.add_row("Other packets", str(stats["protocol_counts"].get("OTHER", 0)))
    table.add_row("Unique source IPs", str(len(stats["unique_src_ips"])))
    table.add_row("Alerts raised", str(stats["alert_count"]))

    console.print(table)

    if stats["top_talkers"]:
        talkers_table = Table(title="Top Source IPs", header_style="bold cyan")
        talkers_table.add_column("Source IP")
        talkers_table.add_column("Packets", justify="right")
        for ip, count in stats["top_talkers"]:
            talkers_table.add_row(ip, str(count))
        console.print(talkers_table)
