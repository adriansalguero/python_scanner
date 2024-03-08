# Simple Port Scanner

A simple Python script for scanning open ports on a host or within a network using ICMP ping, DNS resolution, or traditional port scanning.

## Features

- **Port Scanning:** Scan for open ports on a specific host or network range.
- **ICMP Ping:** Check the reachability of hosts using ICMP Echo Request.
- **DNS Resolution:** Resolve IP addresses to hostnames.

## Usage

# Install Dependencies
pip install -r requirements.txt

# Basic Usage
By default, the script creates a tcp packet to probe ports but you can also use it to check name resolution or ICMP packets

python portscan.py --host <HOST_OR_CIDR> --ports <PORT_RANGE>

  # ICMP Ping
  python portscan.py --host <HOST_OR_CIDR> --ping
  # DNS Resolution
  python portscan.py --host <HOST_OR_CIDR> --dns

## Examples
### Port Scanning
python portscan.py --host 192.168.1.1 --ports 80-100

### Host Scanning
python portscan.py --host 192.168.1.10/24 --ping

python portscan.py --host 192.168.1.0/16 --dns
