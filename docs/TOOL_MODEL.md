# Tool Capability Model

## Overview

Every registered tool exposes machine-readable metadata enabling planner to determine usability.

## Schema

```yaml
tool:
  name: airodump-ng
  display_name: airodump-ng - Wireless Discovery
  category: wireless_observation
  tool_binary: airodump-ng
  version: "1.0"
  description: "Wireless network and client observation..."

requirements:
  operating_systems:
    - linux
  interface_required: true
  interface_capabilities:
    - monitor_mode
  privileges:
    - root
  min_tool_version: null
  dependencies:
    - iw
  hardware: []

inputs:
  - interface
  - optional_channel
  - optional_bssid

outputs:
  - access_points
  - clients
  - channels
  - signal_observations
  - authentication_observations

operational_properties:
  mode: active_observation
  persistent: true
  estimated_duration_seconds: 30
  produces_pcap: true
  invasive: false
  requires_authorization: true

failure_conditions:
  - interface_unavailable
  - unsupported_driver
  - insufficient_privileges
  - invalid_parameters
  - timeout

tags:
  - wireless
  - discovery
  - aircrack

references:
  - https://www.aircrack-ng.org/doku.php?id=airodump-ng
```

## Categories

- `wireless_interface`: Interface discovery and management (iw, iwconfig, airmon-ng, ethtool)
- `radio_management`: Radio block management (rfkill)
- `wireless_observation`: Wireless discovery (airodump-ng, kismet, horst, wavemon)
- `wps_discovery`: WPS discovery (wash)
- `packet_capture`: Packet capture (tshark, tcpdump, dumpcap)
- `protocol_analysis`: Protocol analysis (scapy, macchanger, bettercap, mitmproxy)
- `wps_assessment`: WPS assessment (reaver, bully, pixiewps)
- `wpa_assessment`: WPA assessment (hcxdumptool, hcxpcapngtool)
- `credential_assessment`: Credential assessment (hashcat, john)
- `network_discovery`: Network discovery (nmap, arp-scan, netdiscover, fping, dig, dnsenum, dnsrecon)
- `service_enumeration`: Service enumeration (smbclient, curl, openssl, etc.)
- `vulnerability_assessment`: Vulnerability assessment (openvas, nuclei, nikto)
- `framework`: Frameworks (metasploit, impacket, responder)

## Requirements

- **operating_systems**: List of OS (linux, windows, darwin)
- **interface_required**: Bool
- **interface_capabilities**: List of required capabilities (monitor_mode, injection)
- **privileges**: List (root, net_admin)
- **min_tool_version**: Optional version string
- **dependencies**: Other tools required
- **hardware**: Hardware requirements

## Inputs

List of input parameters. Convention:
- Required inputs: `interface`, `bssid`, `target`, `domain`, etc.
- Optional inputs: `optional_channel`, `optional_ssid`, etc.

Common inputs:
- `interface`: Wireless interface name
- `channel`: Channel number
- `bssid`, `target_bssid`, `ap_mac`: BSSID
- `ssid`, `essid`: SSID
- `target`, `target_ip`, `ip`: IP or hostname
- `domain`: DNS domain
- `hash_file`, `input_file`: File paths
- `wordlist`: Wordlist file

## Outputs

List of evidence types produced.

Common outputs:
- `interfaces`: Interface information
- `access_points`: AP observations
- `clients`: Client observations
- `channels`: Channel observations
- `signal_observations`: Signal strength
- `wps_observations`: WPS observations
- `capture`: Packet capture
- `handshake`: Handshake material
- `network_hosts`: Network hosts
- `network_services`: Network services
- `dns_observation`: DNS observations
- `credential_observation`: Cracked credentials
- `vulnerability`: Vulnerabilities

## Operational Properties

- **mode**: `active_observation`, `passive_observation`, `active_testing`, `offline_analysis`, `configuration`
- **persistent**: Bool - does it run continuously?
- **estimated_duration_seconds**: Optional estimated duration
- **produces_pcap**: Bool
- **invasive**: Bool - does it send packets / affect environment?
- **requires_authorization**: Bool

## Failure Conditions

List of possible failure reasons:
- `interface_unavailable`: Interface doesn't exist
- `unsupported_driver`: Driver doesn't support required capability
- `insufficient_privileges`: Need root but not running as root
- `invalid_parameters`: Parameter validation failed
- `timeout`: Execution timed out
- `tool_not_found`: Tool binary not found
- `tool_failed_exit_X`: Tool failed with exit code X

## Adapter Implementation

Each tool has an adapter class implementing:

```python
class MyAdapter(ToolAdapterBase):
    def build_command(self, interface, parameters) -> List[str]:
        # Translate structured params → valid invocation
        # Return list args, not shell string

    def parse_output(self, raw_output, error_output, exit_code, parameters, interface) -> List[Evidence]:
        # Convert raw output → structured observations
        # Must never fabricate

    def custom_parameter_validation(self, parameters) -> (valid, errors):
        # Validate params

    def custom_requirement_check(self, interface, parameters) -> (ok, reason):
        # Additional checks
```

## Registration

Adapters register via `register(registry)` function:

```python
METADATA = ToolCapabilityMetadata(...)
ADAPTER_CLASS = MyAdapter

def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
```

And via `registry_loader.load_all_adapters()` which imports all adapter modules and calls their register.

## Tool Selection

Framework must never interpret presence of tool as requirement to execute it.

Example:

```
Observed: WPS information unavailable

Potential capabilities: wash, reaver, bully, pixiewps

Planner:
    determine whether WPS is actually present
        ↓
    collect required evidence (e.g., wash for discovery)
        ↓
    select appropriate assessment capability (e.g., reaver if WPS enabled and in scope)
        ↓
    execute
        ↓
    verify
        ↓
    update state
```

- Discovering IP does not automatically justify running every network scanner
- Framework determines what information is missing, whether target in scope, whether capability appropriate, whether existing evidence already answers question

## Raw Tool vs Framework Capability

- **Raw tool**: Actual Kali/Linux executable (e.g., `airodump-ng` binary)
- **Adapter**: Integration layer translating structured state → tool's native interface (e.g., `AirodumpNgAdapter`)
- **Capability**: Higher-level operation exposed to decision engine (e.g., `wireless_observation` with metadata)
- **Evidence parser**: Converts raw output → structured observations (e.g., `parse_airodump_csv`)

```
airodump-ng (raw tool)
     ↓
airodump adapter (build_command, parse_output)
     ↓
wireless_observation capability (metadata)
     ↓
structured observations (Evidence)
     ↓
world model
```

This allows replacing underlying tools without changing decision engine.

## Operational Integrity

Tool considered implemented only when real execution path, parameter handling, output collection, parsing, failure handling, capability requirements implemented and tested against real environment.

Not counted as completed:

- placeholder adapters
- fabricated command output
- simulated discoveries as real results
- hard-coded vulnerability findings
- command templates without execution support
- parser stubs
- empty attack modules
- undocumented limitations

Objective: functioning assessment system where every reported observation can be traced back to actual operation performed by actual supported tool or directly implemented capability.
