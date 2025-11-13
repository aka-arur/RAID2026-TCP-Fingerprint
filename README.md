# TCP Fingerprinting Analysis

Network measurement research project implementing TCP fingerprinting techniques.

## Overview

TCP fingerprinting analyzes TCP/IP stack characteristics to identify remote systems and detect anomalous network behavior.

## Features

- Large-scale network scanning with zmap
- Protocol-specific banner grabbing with zgrab2
- Multi-protocol support (Modbus, S7comm, DNP3, IEC-104, Veeder-Root)
- TCP window size and Scaling Factor-based analysis
- Honeypot detection

## Requirements

- zmap (network scanner)
- zgrab2 (banner grabber)
- Python 3.7+ with scapy (optional, for PCAP generation)

## Configuration

**Important:** Adapt all file paths and environment variables to your specific environment. Default paths may vary based on your system configuration.

- Set `SCAN_PATH` environment variable for scan data directory
- Set `INTERFACE` environment variable for network interface (default: eth0)

## Usage

**Note:** Before running the manager scripts, ensure that directories `logs/`, `meta/`, and `results/` exist in your working directory.

Follow this workflow for complete TCP fingerprinting analysis:

### Step 1: Collect Alive IP Addresses

Use `manager-zmap.sh` to scan for responsive hosts:

```bash
# Scan specific protocol
./manager-zmap.sh -P <protocol>

# Scan all protocols (highly recommended)
./manager-zmap.sh -P all

# Supported protocols: modbus, s7comm, iec104, gast, dnp3, all
```

### Step 2: Parse Results by Protocol

Use `zmap-parse.py` to break down results by port/protocol (recommended when using `--all` option):

```bash
python3 zmap-parse.py -f <zmap_output.jsonl>
```

### Step 3: Application Interaction

Use `manager-zgrab.sh` to perform banner grabbing and collect application-layer data:

```bash
# Standard protocol scan
./manager-zgrab.sh -P <protocol> -f <input_file>

# Custom banner grabbing
./manager-zgrab.sh -P <protocol> -f <input_file> -c

# Ethical scanning mode (recommended for critical infrastructure)
./manager-zgrab.sh -P <protocol> -f <input_file> --ethical

# Custom rate limiting
./manager-zgrab.sh -P <protocol> -f <input_file> -s 500 --server-rate-limit 10

# Supported protocols: s7comm, modbus, dnp3, iec104, gast
```

**Ethical Scanning Options:**
- `--ethical`: Enables rate-limited scanning (~10-15 devices/sec, 80-85% network noise reduction)
  - Configured for critical infrastructure: 400 senders, 10 conn/s/IP, 2000 DNS/s, 20s timeout
- `--server-rate-limit N`: Limit connections per second per target IP (default: 20)
- `--dns-rate-limit N`: Limit DNS lookups per second (default: 10000)
- `-s, --senders N`: Number of concurrent senders (default: 3000)
- `-t, --timeout N`: Connection timeout in seconds (default: 15)

**Scan Time Estimates (300K devices):**
- Default mode: ~1-2 hours (~75 devices/sec)
- Ethical mode: ~6-8 hours (~10-15 devices/sec)

This generates JSONL logs with application responses.

### Step 4: Merge and Filter Data

Use `merge-logs.py` to combine zmap TCP statistics with zgrab payload data while applying noise-elimination filters:

```bash
# Standard merge with filtering
python3 merge-logs.py -P <protocol> window-ttl.jsonl zgrab_data.jsonl <window_threshold>

# Generate PCAP for manual tshark filtering
python3 merge-logs.py -P <protocol> window-ttl.jsonl zgrab_data.jsonl <window_threshold> --pcap
```

The `--pcap` flag allows you to apply additional protocol-specific filters manually using tshark.

### Step 5: Extract Honeypot IPs

Use `filter-applier.py` to identify and extract IP addresses flagged as honeypots:

```bash
python3 filter-applier.py -P <protocol> <input.jsonl>
```
