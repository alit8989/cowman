# COWMAN 🛡️

**Terminal SOC & Network Security Command Center**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Architecture: Clean Modular](https://img.shields.io/badge/architecture-Clean%20Modular-brightgreen.svg)](#architecture)
[![Code Style: Typed](https://img.shields.io/badge/typing-pydantic%20v2-blueviolet.svg)](#technology)
[![Test Suite](https://img.shields.io/badge/tests-42%20passed-success.svg)](#testing)

COWMAN is a lightweight, production-quality **Security Operations Center (SOC) and network monitoring command center running entirely inside your terminal**. 

Built for cybersecurity analysts, network engineers, and system administrators, COWMAN unifies local network inventory discovery, authorized service auditing, real-time bandwidth telemetry, DNS exfiltration detection, defensive event correlation, and dynamic topology reconstruction into a single dark-themed terminal workstation.

---

## Command Center Preview

Running `cowman` with no arguments launches the interactive SOC command console:

```text
┌──────────────────────────────────────────────────────────────┐
│ COWMAN v1.0.0                         ● SYSTEM ONLINE        │
│ Interface: Wi-Fi   IP: 192.168.1.20   Gateway: 192.168.1.1   │
└──────────────────────────────────────────────────────────────┘

 [1] Network Overview
 [2] Device Discovery
 [3] Port Analysis
 [4] Traffic Monitor
 [5] DNS Monitor
 [6] Security Events
 [7] Network Topology
 [8] Reports
 [9] Event Replay
 [0] Exit

cowman >
```

---

## Core Capabilities

### 1. Network Telemetry & Host Configuration (`cowman info`, `cowman interfaces`)
* Enumerates all physical and virtual network interfaces (IP, Netmask, Broadcast, MAC, MTU, Status UP/DOWN, Duplex, Link Speed).
* Resolves active gateway, nameservers, local routing tables, and interface I/O counters (sent/received MB).
* Accurately distinguishes primary active egress interfaces across Windows, macOS, and Linux.

### 2. Authorized Local Device Discovery (`cowman discover`)
* Multi-engine discovery pipeline: Scapy ARP ping + non-root system ARP table harvesting + asynchronous socket ping sweep.
* Offline Organizationally Unique Identifier (OUI) MAC vendor resolution (Apple, Intel, Dell, HP, Raspberry Pi, Espressif, Cisco, TP-Link, Netgear, etc.).
* Automated reverse DNS lookup and heuristic device classification (`Router`, `Laptop`, `Phone`, `Server`, `IoT`).
* Persists discovered devices and tracks first seen / last seen timestamps in SQLite.
* Automatically triggers `NEW_DEVICE_DETECTED` and `DEVICE_STATUS_CHANGED` security events.

### 3. Port & Service Analysis (`cowman ports <host>`)
* Concurrently audits target TCP ports using non-blocking asynchronous socket connections.
* Safe, non-intrusive, passive service banner grabbing (HTTP Server headers, SSH/FTP/SMTP greetings).
* Correlates open ports against dangerous/plaintext services (e.g. Telnet 23, FTP 21, SMB 445, VNC 5900).
* Strictly operates only on explicitly authorized targets—**strictly zero exploitation, credential brute-forcing, or evasion tactics**.

### 4. Real-Time Traffic & Socket Telemetry (`cowman monitor`)
* Live terminal dashboard powered by Rich Live display.
* Monitors bandwidth rates (KB/s, MB/s) and packet throughput (pkts/sec) with delta tracking.
* Inspects active operating system sockets (TCP ESTABLISHED, LISTEN, TIME_WAIT, UDP).
* Resolves remote endpoints and associated process names/PIDs.

### 5. DNS Monitoring & Tunneling Detection (`cowman dns`)
* Captures and parses DNS query activity (UDP/TCP port 53).
* Computes Shannon Entropy per domain label to detect Domain Generation Algorithms (DGA).
* Inspects domain name length and hex/base64 subdomains to identify potential DNS tunneling and data exfiltration.

### 6. Modular Defensive Security Engine (`cowman events`)
* Rule-based engine categorizing events into standard severity levels: `INFO`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.
* Evaluates events such as:
  * **New Device Detected** (unrecognized MAC/IP on local segment)
  * **Device Offline/Online Transitions**
  * **Unexpected Exposed Services** (plaintext or administrative ports)
  * **Network Interface State Changes**
  * **DNS Anomalies** (high entropy, abnormal length, tunneling indicators)
  * **Traffic & Socket Surges** (bandwidth saturation, socket volume spikes)
* Strictly adheres to professional defensive language ("unexpected", "anomalous", "potentially suspicious").

### 7. Dynamic Topology Reconstruction (`cowman topology`)
* Computes network hierarchy from discovered inventory:
  ```text
                   INTERNET
                       │   
            ROUTER (192.168.1.1)
                       │   
       ┌───────────┬───────────┬───────────┐
       │           │           │           │
     LAPTOP      PHONE       SERVER       IOT
  ```
* Generates both clean ASCII box-drawing diagrams and interactive color-coded Rich Trees with host indicators and vendors.

### 8. Chronological Event Replay (`cowman replay`)
* Replays historical defensive events in chronological sequence.
* Supports customizable time windows (`--from`, `--to`) and simulated animated playback speed (`--speed`).

### 9. Multi-Format Audit Reports (`cowman report`)
* Exports comprehensive executive summaries, host inventories, open ports, and security events to:
  * **Markdown** (`.md`)
  * **JSON** (`.json`)
  * **CSV** (`.csv`)

---

## Architecture

COWMAN follows a clean, decoupled modular architecture:

```text
cowman/
├── pyproject.toml              # Build & dependency metadata (PEP 621)
├── README.md                   # Command center documentation
├── LICENSE                     # MIT License
├── config.example.toml         # Default TOML configuration template
├── src/
│   └── cowman/
│       ├── main.py             # CLI executable entrypoint
│       ├── cli/
│       │   ├── app.py          # Main Typer application & subcommands
│       │   ├── commands/       # Discrete CLI command handlers
│       │   │   ├── info.py
│       │   │   ├── interfaces.py
│       │   │   ├── discover.py
│       │   │   ├── ports.py
│       │   │   ├── monitor.py
│       │   │   ├── dns.py
│       │   │   ├── topology.py
│       │   │   ├── events.py
│       │   │   ├── replay.py
│       │   │   └── report.py
│       │   └── ui/             # Rich terminal presentation layer
│       │       ├── console.py
│       │       ├── themes.py
│       │       ├── banners.py
│       │       ├── formatters.py
│       │       └── dashboard.py
│       ├── core/               # Configuration, logging, domain models
│       │   ├── config.py
│       │   ├── models.py
│       │   └── logger.py
│       ├── network/            # Networking, scanning & telemetry engines
│       │   ├── interfaces.py
│       │   ├── oui.py
│       │   ├── scanner.py
│       │   ├── ports.py
│       │   ├── monitor.py
│       │   ├── dns_sniffer.py
│       │   └── topology.py
│       ├── security/           # Defensive rule evaluation engine
│       │   ├── severity.py
│       │   ├── rules.py
│       │   └── engine.py
│       ├── storage/            # SQLAlchemy ORM & SQLite repositories
│       │   ├── database.py
│       │   ├── models.py
│       │   └── repository.py
│       └── utils/              # Platform detection, time & export helpers
│           ├── platform.py
│           ├── time.py
│           └── export.py
└── tests/                      # Pytest unit & integration test suite
```

---

## Installation

### Prerequisites
* Python 3.12 or newer
* Optional: Npcap (Windows) or root/`CAP_NET_RAW` (Linux) for raw packet sniffing

### Install in Editable Mode
```bash
git clone https://github.com/example/cowman.git
cd cowman
pip install -e .
```

Verify installation:
```bash
cowman --version
```

---

## CLI Reference & Usage

| Command | Description |
|:---|:---|
| `cowman` | Launch interactive dark SOC-style terminal dashboard |
| `cowman info` | Display host network telemetry, gateway, DNS servers, and connection stats |
| `cowman interfaces` | List all physical and virtual interfaces with operational statistics |
| `cowman discover` | Discover active hosts on local subnet, resolving hostnames and vendors |
| `cowman ports <host>` | Audit exposed TCP ports and banners on an authorized target host |
| `cowman monitor` | Stream live interface throughput, packets/sec, and active sockets |
| `cowman dns` | Inspect recorded DNS query logs or capture live DNS queries (`--live`) |
| `cowman topology` | Render dynamic network topology diagram and Rich tree |
| `cowman events` | Query and filter defensive security audit logs and anomalies |
| `cowman replay` | Replay recorded network events chronologically (`--from`, `--to`) |
| `cowman report` | Generate audit reports in Markdown, JSON, or CSV (`--output`) |

### Example Commands

#### Scan Open Services
```bash
cowman ports 192.168.1.1 -p 21,22,23,80,443,8080
```

#### Real-Time Traffic Monitoring
```bash
cowman monitor --interval 1.0 --duration 10
```

#### Query High Severity Security Events
```bash
cowman events --severity HIGH
cowman events --type DNS --limit 20
cowman events --from 24h
```

#### Chronological Event Replay
```bash
cowman replay --from 2h --speed 1.5
```

#### Export Executive Audit Report
```bash
cowman report --format markdown --output audit-report.md
cowman report --format json --output telemetry.json
cowman report --format csv --output inventory.csv
```

---

## Configuration

COWMAN automatically checks for configuration in:
1. `--config <path>` command-line option
2. `COWMAN_CONFIG` environment variable
3. `./cowman.toml`
4. `~/.cowman/config.toml`

Copy `config.example.toml` to customize settings:

```bash
mkdir -p ~/.cowman
cp config.example.toml ~/.cowman/config.toml
```

---

## Defensive Security & Ethical Notice

COWMAN is built strictly for **authorized defensive operations, internal infrastructure audits, and educational security research**. 
* Never audit hosts or networks without explicit written permission from the asset owner.
* COWMAN strictly avoids exploitation, credential attacks, persistence, stealth/evasion, or destructive actions.

---

## Testing

Run the full pytest suite:

```bash
pytest
```

Run with verbose coverage output:

```bash
pytest -v
```

---

## License

MIT License. Copyright (c) 2026 COWMAN Project Contributors. See [LICENSE](LICENSE) for details.
