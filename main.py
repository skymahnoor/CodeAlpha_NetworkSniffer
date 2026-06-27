#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship -- Task 1: Basic Network Sniffer

A command-line packet sniffer built with Scapy. Captures live traffic,
parses Ethernet/IP/TCP/UDP/ICMP/DNS layers, flags suspicious activity
(port scans, plaintext credentials, high-risk ports), and logs every
session to JSON + CSV for later review.

Usage:
    sudo python3 main.py --interface eth0
    sudo python3 main.py --interface eth0 --filter "tcp port 80"
    sudo python3 main.py --interface eth0 --count 200 --verbose
    sudo python3 main.py --list-interfaces

Note: raw packet capture requires root privileges on Linux.
"""

import argparse
import sys

from scapy.all import get_if_list

from sniffer.capture import SnifferSession, start_capture
from sniffer.display import print_banner, print_summary, console


def parse_args():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Network Sniffer -- live traffic capture & analysis"
    )
    parser.add_argument(
        "-i", "--interface", type=str, default=None,
        help="Network interface to sniff on (e.g. eth0, wlan0)"
    )
    parser.add_argument(
        "-f", "--filter", type=str, default=None,
        help="BPF filter string, e.g. 'tcp', 'udp port 53', 'host 192.168.1.1'"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (0 = run until Ctrl+C)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show payload previews for each packet"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress per-packet output; only show the final summary"
    )
    parser.add_argument(
        "--log-dir", type=str, default="logs",
        help="Directory to write JSON/CSV session logs (default: logs/)"
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List available network interfaces and exit"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list_interfaces:
        console.print("[bold]Available interfaces:[/bold]")
        for iface in get_if_list():
            console.print(f"  - {iface}")
        sys.exit(0)

    if not args.interface:
        console.print(
            "[bold red]Error:[/bold red] no interface specified. "
            "Use --interface <name> or --list-interfaces to see options.",
            style="red",
        )
        sys.exit(1)

    session = SnifferSession(verbose=args.verbose, log_dir=args.log_dir, quiet=args.quiet)
    print_banner(args.interface, args.filter)

    try:
        start_capture(args.interface, args.filter, session, packet_count=args.count)
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture stopped by user.[/yellow]")
    except PermissionError:
        console.print(
            "\n[bold red]Permission denied.[/bold red] "
            "Raw packet capture needs root -- try running with sudo.",
        )
        sys.exit(1)
    except OSError as e:
        console.print(f"\n[bold red]Capture error:[/bold red] {e}")
        sys.exit(1)
    finally:
        json_path, csv_path = session.finalize()
        console.print()
        print_summary(session.summary())
        console.print(f"\n[dim]Logs saved to:[/dim] {json_path}, {csv_path}")


if __name__ == "__main__":
    main()
