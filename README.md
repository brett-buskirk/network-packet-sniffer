# Network Packet Sniffer

A cross-platform packet capture utility that decodes and displays network traffic. Built with Python using raw sockets.

## Features

- **Packet Decoding**: Parses IP, TCP, UDP, and ICMP headers with human-readable output
- **Filtering**: Filter by protocol, port, source IP, or destination IP
- **Multiple Output Formats**: Human-readable, JSON, or raw bytes
- **Pcap Export**: Save captures to pcap format for analysis in Wireshark
- **Statistics**: Track packet counts, bytes, protocols, and top talkers
- **Hex Dump**: Optional hex dump display for packet inspection
- **Cross-Platform**: Works on Linux and Windows

## Requirements

- Python 3.6+
- Root/Administrator privileges (required for raw sockets)

## Installation

```bash
git clone https://github.com/brett-buskirk/sniffer.git
cd sniffer
```

No additional dependencies required - uses only Python standard library.

## Usage

```bash
sudo python3 sniffer.py [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--host`, `-H` | Host IP address to listen on (default: auto-detect) |
| `--count`, `-c` | Number of packets to capture (0 = unlimited) |
| `--protocol`, `-p` | Filter by protocol: `tcp`, `udp`, or `icmp` |
| `--port` | Filter by port number (source or destination) |
| `--src-ip` | Filter by source IP address |
| `--dst-ip` | Filter by destination IP address |
| `--output`, `-o` | Output format: `human`, `json`, or `raw` |
| `--hex`, `-x` | Show hex dump of packets |
| `--save`, `-s` | Save packets to pcap file |
| `--quiet`, `-q` | Suppress output, only show statistics |
| `--no-stats` | Do not show statistics at end |
| `--interface`, `-i` | Network interface to capture on (Linux only, default: auto-detect) |

### Examples

```bash
# Capture packets continuously until Ctrl+C
sudo python3 sniffer.py

# Capture exactly 10 packets
sudo python3 sniffer.py --count 10

# Capture only TCP traffic
sudo python3 sniffer.py --protocol tcp

# Capture HTTP traffic (port 80)
sudo python3 sniffer.py --protocol tcp --port 80

# Capture HTTPS traffic with hex dump
sudo python3 sniffer.py --protocol tcp --port 443 --hex

# Output in JSON format (useful for scripting)
sudo python3 sniffer.py --output json --count 5

# Save capture to pcap file for Wireshark
sudo python3 sniffer.py --save capture.pcap --count 100

# Quiet mode - only show statistics
sudo python3 sniffer.py --quiet --count 50

# Filter by specific source IP
sudo python3 sniffer.py --src-ip 192.168.1.100

# Capture on a specific network interface
sudo python3 sniffer.py --interface eth0
```

### Capturing Localhost Traffic

To capture traffic from local development servers, use the loopback interface:

```bash
# Capture all localhost traffic
sudo python3 sniffer.py --interface lo

# Capture traffic on a specific port (e.g., dev server on port 3000)
sudo python3 sniffer.py --interface lo --port 3000

# Capture localhost API traffic on port 8080
sudo python3 sniffer.py --interface lo --port 8080 --protocol tcp

# Save localhost traffic for analysis
sudo python3 sniffer.py -i lo --port 5174 --save localhost.pcap
```

## Sample Output

### Human-Readable (default)

```
[2026-01-26T10:30:45.123456] TCP 192.168.1.100:54321 -> 142.250.80.46:443
  Flags: [SYN] Seq: 123456789 Ack: 0 Win: 65535
  TTL: 64 ID: 12345 Len: 60

[2026-01-26T10:30:45.234567] TCP 142.250.80.46:443 -> 192.168.1.100:54321
  Flags: [SYN,ACK] Seq: 987654321 Ack: 123456790 Win: 65535
  TTL: 117 ID: 0 Len: 60
```

### JSON Output

```json
{"timestamp": "2026-01-26T10:30:45.123456", "version": 4, "header_length": 20, "ttl": 64, "protocol": 6, "protocol_name": "TCP", "src_ip": "192.168.1.100", "dst_ip": "142.250.80.46", "src_port": 54321, "dst_port": 443, "flag_names": ["SYN"], "raw_hex": "..."}
```

### Statistics Summary

```
============================================================
CAPTURE STATISTICS
============================================================
Duration: 10.25 seconds
Total packets: 150
Total bytes: 12450
Packets/sec: 14.63

Protocols:
  TCP: 120
  UDP: 25
  ICMP: 5

Top 5 Source IPs:
  192.168.1.100: 75
  142.250.80.46: 45
  8.8.8.8: 20
  192.168.1.1: 10

Top 5 Destination IPs:
  142.250.80.46: 80
  192.168.1.100: 50
  8.8.8.8: 15
  192.168.1.255: 5
============================================================
```

## Platform Notes

### Linux
- Requires root privileges (`sudo`)
- Uses `AF_PACKET` sockets to capture all IP traffic (TCP, UDP, ICMP)
- Supports interface selection with `--interface` (e.g., `eth0`, `lo`, `wlan0`)
- Auto-detects default interface from routing table

### Windows
- Requires Administrator privileges
- Uses `AF_INET` raw sockets with promiscuous mode enabled via `SIO_RCVALL`
- Binds to IP address instead of interface name

## License

MIT License
