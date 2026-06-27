# CodeAlpha_NetworkSniffer

A Python-based network packet sniffer and traffic analyzer built with **Scapy**, as part of the **CodeAlpha Cybersecurity Internship** (Task 1: Basic Network Sniffer).

It captures live network traffic, parses it down to the protocol layer, displays it in a clean color-coded terminal view, flags suspicious activity in real time, and logs every session to JSON/CSV for later review.

## Features

- **Live packet capture** on any network interface, with optional BPF filtering (`tcp`, `udp port 53`, `host 192.168.1.1`, etc.)
- **Protocol parsing** for Ethernet, IP, TCP, UDP, ICMP, and DNS layers
- **Color-coded CLI output** (via `rich`) — protocol, source/destination, packet size, DNS queries
- **Real-time threat detection:**
  - Port scan detection (sliding time-window heuristic — flags a source IP touching many distinct ports too quickly)
  - Plaintext credential detection (catches obvious `username=` / `password=` patterns in unencrypted HTTP traffic)
  - High-risk port alerts (Telnet, RDP, SMB, FTP, and other commonly abused services)
- **Session logging** — every capture is saved as structured JSON and CSV for later analysis or reporting
- **Capture summary** — protocol breakdown, unique source IPs, top talkers, and total alerts at the end of every session

## Project Structure

```
CodeAlpha_NetworkSniffer/
├── sniffer/
│   ├── capture.py      # Core capture engine (wires everything together)
│   ├── parsers.py      # Raw packet -> structured dict
│   ├── detectors.py    # Suspicious activity heuristics
│   ├── display.py       # Rich-based CLI output
│   └── logger.py         # JSON/CSV session logging
├── main.py                # CLI entry point
├── requirements.txt
└── README.md
```

## Installation

```bash
git clone https://github.com/<your-username>/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
pip install -r requirements.txt
```

Requires Python 3.10+ and Linux (raw socket capture needs root privileges).

## Usage

List available interfaces:

```bash
sudo python3 main.py --list-interfaces
```

Start sniffing on an interface:

```bash
sudo python3 main.py --interface eth0
```

Apply a BPF filter (only capture HTTP traffic):

```bash
sudo python3 main.py --interface eth0 --filter "tcp port 80"
```

Capture a fixed number of packets with payload previews:

```bash
sudo python3 main.py --interface eth0 --count 200 --verbose
```

Run quietly and only see the end-of-session summary:

```bash
sudo python3 main.py --interface eth0 --quiet
```

All sessions are logged automatically to `logs/capture_<timestamp>.json` and `.csv`.

## Example Output

```
CodeAlpha Network Sniffer
Interface: eth0
Filter: tcp port 80

[14:22:01.118] TCP    10.0.0.5:51000       -> 93.184.216.34:80     85B
    payload: 'username=admin&password=hunter2'
    [!] Plaintext credential pattern detected in payload
[14:22:01.140] TCP    10.0.0.99:12345      -> 10.0.0.1:14          54B
    [!] Possible port scan from 10.0.0.99: 15 distinct ports in 10s

Capture Summary
┌────────────────────┬───────┐
│ Total packets       │   22  │
│ TCP packets          │   22  │
│ Unique source IPs    │    3  │
│ Alerts raised         │    3  │
└────────────────────┴───────┘
```

## How the Detection Logic Works

- **Port scan detection** keeps a per-source-IP sliding window (default: 10 seconds) of destination ports seen. If a single source touches 15+ distinct ports within that window, it's flagged — this mirrors how real scanners (e.g. Nmap SYN scans) behave on the wire.
- **Credential detection** performs lightweight regex matching against decoded payload text, looking for common form-encoded `username=`/`password=` patterns sent over plaintext HTTP. This is a teaching example of why HTTPS matters — anyone sniffing the same network segment can read these in cleartext.
- **High-risk ports** is a static lookup against commonly abused services (Telnet, RDP, SMB, FTP, etc.) that are frequent initial-access or lateral-movement vectors in real intrusions.

## Disclaimer

This tool is for educational purposes and authorized testing only — run it only on networks you own or have explicit permission to monitor. Capturing traffic on networks without authorization is illegal in most jurisdictions.

## Author

Built by Moonlight as part of the CodeAlpha Cybersecurity Internship.
