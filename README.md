# Personal Firewall (Python + iptables + Scapy)

A lightweight, advanced personal firewall for Linux, featuring:
- Rule engine (allow/block) with direction, protocol, IP/ports, interface, priority, logging
- Profiles (e.g., home, office, public)
- iptables enforcement (kernel-level)
- Scapy packet monitoring and logging
- Suspicious activity detection and auto-block (port-scan defense)
- CLI and optional Tkinter GUI for live monitoring
- YAML configuration with live reload

## Requirements
- Linux with iptables
- Python 3.8+
- Root privileges required for enforcement/monitoring
- Packages:
  - scapy
  - PyYAML
  - tabulate (CLI pretty output)
  - Tkinter (standard library; optional GUI)

Install dependencies:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
