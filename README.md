# WiFi Framework - Real Wi-Fi Penetration-Testing and Security-Assessment Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-268BDB.svg)](https://www.kali.org/)

A production-ready, adaptive, evidence-driven Wi-Fi security assessment framework designed around real Kali Linux wireless tooling.

## Operational Philosophy & Assessment Architecture

This project is designed as a **real Wi-Fi penetration-testing and security-assessment framework**, not as a collection of simulated demonstrations, command wrappers, or placeholder tool integrations. Its purpose is to perform genuine assessments against networks and wireless environments for which the operator has explicit authorization.

The framework treats Wi-Fi penetration testing as an **adaptive investigation** rather than a fixed sequence of commands. It does not blindly execute every available tool in a predetermined order. Instead, it continuously:

1. Maintains an internal model of the observed wireless environment
2. Determines what information is currently known
3. Identifies important uncertainties
4. Evaluates which available action can provide useful additional evidence
5. Selects and executes that action
6. Uses result as new evidence that can alter subsequent decisions

### Key Principles

- **Real Tool Execution**: Every capability corresponds to functioning implementation invoking real underlying utility
- **Adaptive Assessment**: State-driven rather than tool-driven, `Observe → Model → Identify uncertainty → Select action → Parameterize → Execute → Parse → Verify → Update → Re-evaluate`
- **Evidence and Verification**: Raw output is not authoritative finding; observations parsed into structured evidence with confidence, verification before confirmed findings
- **Capability-Aware Execution**: Verifies interface, OS, driver, privileges, tool version before execution
- **Non-Sequential Tool Usage**: Tool selection determined by assessment state, not existence of tool
- **Experience and Learning**: Maintains experience record for heuristic improvement
- **Auditability**: Every action reconstructable from execution history
- **Scope and Authorization**: Preserves defined assessment scope, prevents silent expansion

## Architecture Overview

```
Raw Tool (e.g., airodump-ng)
    ↓
Adapter (translates structured params → valid invocation)
    ↓
Capability (higher-level operation exposed to decision engine)
    ↓
Evidence Parser (converts raw output → structured observations)
    ↓
World Model (internal model of wireless environment)
    ↓
Planner (identifies uncertainties, selects actions)
    ↓
Executor (capability-aware execution)
    ↓
Audit & Experience
```

### Core Components

- **Models**: Evidence, Finding (hypothesis/supported/verified/refuted), Capability metadata, World Model, Assessment State, Scope
- **Execution**: Capability Registry, Tool Adapters, Capability Checker, Executor with real subprocess execution
- **Planning**: Uncertainty Identifier, Action Selector, Assessment Planner with heuristic scoring
- **Audit**: Audit Logger with full traceability - what was discovered, which observation produced evidence, which operation generated it, when, and how verified
- **Experience**: Experience Store tracking information gain, cost, verification outcome
- **Tools**: 30+ adapters covering Kali wireless toolchain
- **Parsers**: Structured parsers for iw, airodump-ng, wash, tshark, nmap, etc.

## Supported Toolchain (Kali Linux Wireless Toolchain)

### 1. Wireless Interface and Radio Management
- `airmon-ng` - monitor mode management
- `iw` - low-level wireless config
- `iwconfig` - legacy interface inspection
- `rfkill` - radio block management
- `ethtool` - driver information

### 2. Wireless Discovery and Reconnaissance
- `Kismet` - passive reconnaissance (long-running observation source)
- `airodump-ng` - wireless discovery
- `wash` - WPS discovery
- `horst` - lightweight monitor
- `wavemon` - signal information

### 3. Wireless Packet Capture and Analysis
- `tshark` - CLI Wireshark engine
- `tcpdump` - packet capture
- `dumpcap` - Wireshark capture engine

### 4. Protocol and Packet Analysis
- `Scapy` - programmable packet manipulation
- `macchanger` - MAC configuration
- `bettercap` - network assessment framework

### 5. WPS Assessment
- `reaver`, `bully`, `pixiewps` - correlated with observed WPS state

### 6. WPA/WPA2/WPA3 and Authentication Assessment
- `hcxdumptool` - capture collection
- `hcxpcapngtool` - material conversion
- `hashcat`, `john` - offline credential assessment (controlled)

### 7. Wireless/Network Discovery Beyond Radio Layer
- `nmap`, `arp-scan`, `netdiscover`, `fping`, `dig`, `dnsenum`, `dnsrecon`

### 8. Service and Network Enumeration
- `smbclient`, `curl`, `openssl s_client`, etc.

## Installation

### Requirements
- Python 3.10+
- Linux (Kali Linux recommended)
- Root privileges for wireless operations
- Wireless adapter with monitor mode support (for active assessment)

### Install from source

```bash
git clone https://github.com/alexland361-eng/WiFi.git
cd WiFi
pip install -e .
# Or with dev dependencies
pip install -e ".[dev]"
```

### Verify installation

```bash
wifi-assess --list-capabilities
wifi-assess --discover-only
```

## Usage

### Basic Discovery

```bash
# Discover interfaces and capabilities
wifi-assess --discover-only

# List all capabilities and availability
wifi-assess --list-capabilities

# List system interfaces
wifi-assess --list-interfaces
```

### Authorized Assessment

```bash
# Assess with authorized SSIDs
wifi-assess --ssid MyNetwork --ssid CorpWiFi --max-iterations 30

# With BSSIDs and channels
wifi-assess --bssid 00:11:22:33:44:55 --channel 6 --channel 11

# With network scope (after wireless access)
wifi-assess --ssid MyNetwork --network 192.168.1.0/24 --max-iterations 50

# With specific interface
wifi-assess --interface wlan0mon --ssid MyNetwork

# Strict scope mode (even passive observation limited to authorized)
wifi-assess --ssid MyNetwork --strict

# Custom config file
wifi-assess --config config/default.yaml

# Verbose output with custom output dir
wifi-assess --ssid MyNetwork -v --output /tmp/my_audit
```

### Scope Definition

Create a YAML config:

```yaml
authorized_ssids:
  - "MyNetwork"
  - "Corp.*"

authorized_bssids:
  - "00:11:22:33:44:55"

authorized_channels:
  - 1
  - 6
  - 11

authorized_networks:
  - "192.168.1.0/24"

description: "Authorized assessment for MyNetwork"
allow_broadcast_discovery: true
strict_mode: false
```

Then run:

```bash
wifi-assess --config my_scope.yaml
```

## Tool Capability Model

Every registered tool exposes machine-readable metadata:

```yaml
tool:
  name: airodump-ng
  category: wireless_observation
  tool_binary: airodump-ng

requirements:
  operating_system:
    - linux
  interface:
    required: true
  capabilities:
    - monitor_mode
  privileges:
    - root

inputs:
  - interface
  - channel
  - bssid

outputs:
  - access_points
  - clients
  - channels
  - signal_observations

operational_properties:
  mode: active_observation
  persistent: true
  invasive: false
  requires_authorization: true

failure_conditions:
  - interface_unavailable
  - unsupported_driver
  - insufficient_privileges
  - timeout
```

## Assessment Flow Example

```
Observed:
    WPS information unavailable

Potential capabilities:
    wash
    reaver
    bully
    pixiewps

Planner:
    determine whether WPS is actually present
        ↓
    collect required evidence
        ↓
    select appropriate assessment capability
        ↓
    execute
        ↓
    verify
        ↓
    update state
```

## Auditability

Every meaningful action is reconstructable:

```json
{
  "assessment_id": "...",
  "scope": {...},
  "execution_history": [
    {
      "capability_name": "airodump-ng",
      "interface": "wlan0mon",
      "parameters": {"channel": 6},
      "raw_command": "airodump-ng -c 6 -w /tmp/airodump_... wlan0mon",
      "exit_code": 0,
      "duration_seconds": 30.5,
      "evidence_ids": ["..."]
    }
  ],
  "evidences": [
    {
      "id": "...",
      "timestamp": "...",
      "type": "access_point",
      "source_tool": "airodump-ng",
      "parsed_data": {"bssid": "00:11:22:33:44:55", "ssid": "MyNetwork"},
      "confidence": 0.85
    }
  ],
  "finding_traces": [
    {
      "finding_id": "...",
      "title": "Access Point Discovered",
      "evidence_chain": [
        {
          "evidence_id": "...",
          "timestamp": "...",
          "tool": "airodump-ng",
          "raw_command": "..."
        }
      ]
    }
  ]
}
```

## Development

### Project Structure

```
src/wifi_framework/
├── core/
│   ├── models/          # Evidence, Finding, Capability, World Model, Scope, Assessment State
│   ├── execution/       # Registry, Adapter Base, Executor, Capability Checker
│   ├── planning/        # Planner, Uncertainty Identifier, Action Selector
│   ├── audit/           # Audit Logger
│   ├── experience/      # Experience Store
│   └── engine/          # Assessment Engine (main loop)
├── tools/
│   ├── adapters/        # 30+ real tool adapters
│   └── registry_loader.py
├── parsers/             # Structured parsers
├── utils/               # System, validation
└── cli/                 # CLI

config/
├── default.yaml
└── capabilities/

tests/
docs/
```

### Running Tests

```bash
pip install -e ".[dev]"
pytest -v
pytest --cov=wifi_framework
```

### Code Quality

- Production-ready, no placeholders
- Real tool execution with timeout handling, failure reporting
- Input validation, security-first (no shell=True, sanitized args)
- Capability-aware execution
- Scope enforcement
- Auditability

## Security and Authorization

**This framework is intended for authorized security assessment only.**

- Operational controls preserve defined assessment scope
- Prevents decision engine from silently expanding scope
- Distinguishes assets inside authorized scope from unrelated networks
- Invasive actions require authorization check
- Audit log provides full traceability

**Never use against networks without explicit authorization.**

## Documentation

- `docs/ARCHITECTURE.md` - Detailed architecture
- `docs/TOOL_MODEL.md` - Tool capability model
- `docs/OPERATIONAL_PHILOSOPHY.md` - Philosophy and assessment approach
- `CHANGELOG.md` - Incremental changes
- `AGENT-EXPERIENCE.md` - Development experiences and learnings

## Changelog and Experience Tracking

See `CHANGELOG.md` and `AGENT-EXPERIENCE.md` for detailed incremental changes and development experiences.

## License

MIT License - see LICENSE file.

## References

- Kali Linux Wireless Tools: https://www.kali.org/tools/
- Aircrack-ng Suite: https://www.aircrack-ng.org/
- Kismet: https://www.kismetwireless.net/
- Scapy: https://scapy.net/
- Wireshark/tshark: https://www.wireshark.org/
- Bettercap: https://www.bettercap.org/

## Contributing

This project follows Senior Developer standards:
- Production-ready code only
- Thorough research before implementation
- Security-first
- Minimal justified dependencies
- Preserve existing work
- Verification honesty

See `AGENT-EXPERIENCE.md` for development workflow.
