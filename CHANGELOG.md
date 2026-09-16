# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-16

### Added
- Initial production-ready implementation of WiFi Framework
- Core models:
  - Evidence model with structured representation, timestamps, sources, confidence
  - Finding model distinguishing hypothesis, supported, verified, refuted, unresolved
  - Capability model with machine-readable metadata (requirements, inputs, outputs, operational properties, failure conditions)
  - World Model maintaining internal model of wireless environment (APs, clients, hosts, channels, SSIDs)
  - Assessment State central state machine with phase transitions, execution history
  - Scope model with authorization enforcement (SSID, BSSID, channel, network, host), regex support, strict mode
- Execution layer:
  - ToolAdapterBase abstract base with real subprocess execution, requirement checking, parameter validation, failure interpretation
  - CapabilityChecker verifying OS, tool availability, privileges, interface, dependencies
  - CapabilityRegistry with auto-discovery and global registry
  - CapabilityExecutor with parameter generation from state, capability-aware execution, audit integration
  - Registry loader loading all 30+ adapters
- Tool adapters (real implementations):
  - Interface: iw (dev, list), iwconfig, airmon-ng, rfkill, ethtool
  - Discovery: airodump-ng (with CSV parsing and temp file handling), wash, kismet, horst, wavemon
  - Capture: tshark (JSON and fields), tcpdump, dumpcap
  - WPS: reaver, bully, pixiewps
  - WPA: hcxdumptool, hcxpcapngtool, hashcat, john
  - Network: nmap (normal, grepable, XML), arp-scan, netdiscover, fping, dig
  - Enumeration: curl, openssl s_client, smbclient (generic)
  - Protocol: macchanger, bettercap, scapy (with direct library execution fallback)
- Parsers:
  - iw (dev, list, link)
  - airodump-ng CSV with AP and client sections
  - wash WPS discovery
  - tshark JSON and fields
  - nmap grepable, normal, XML
- Planning:
  - UncertaintyIdentifier identifying interface discovery, capability discovery, wireless observation, AP identification, hidden SSID, WPS state, client discovery, network hosts, handshake capture, verification uncertainties with priority
  - ActionSelector scoring capabilities based on availability, required list match, useful outputs, invasiveness, recent execution, experience scores, scope, duration
  - AssessmentPlanner implementing adaptive loop, phase transition suggestions, continuation logic
- Audit:
  - AuditLogger logging scope, capabilities, actions, executions, evidences, findings, phase transitions, verification, generating full traceability report with finding traces
- Experience:
  - ExperienceStore tracking actions, state, params, results, info gain, cost, verification, persisting to JSONL, providing capability stats and scores for heuristic planning
- Engine:
  - AssessmentEngine main orchestrator implementing Observe→Model→Identify uncertainty→Select action→Parameterize→Execute→Parse→Verify→Update→Re-evaluate loop, interface discovery, capability discovery, scope enforcement, findings generation from world model, verification via multi-tool correlation
- CLI:
  - Full argparse CLI with scope definition via args and YAML config, discover-only mode, list capabilities, list interfaces, verbose, strict mode, output dir, max iterations, timeout
  - Scope validation
  - Examples and operational philosophy in help
- Utils:
  - system: OS info, root check, tool availability, interface existence, run_command with timeout, version parsing
  - validation: MAC, SSID, channel, interface, IP, CIDR, parameter validation, sanitization
- Config:
  - default.yaml with example scope
- Documentation:
  - README with operational philosophy, architecture overview, toolchain list, installation, usage, capability model, auditability, security
  - ARCHITECTURE.md (planned)
  - TOOL_MODEL.md (planned)
  - OPERATIONAL_PHILOSOPHY.md (planned)
- Project setup:
  - pyproject.toml with dependencies (pyyaml), optional scapy, dev pytest, entry point wifi-assess
  - requirements.txt
  - Folder structure with clear module boundaries

### Security
- No shell=True in subprocess execution, list args only
- Input validation for MAC, SSID, channel, interface, IP, CIDR
- Privilege checks before execution
- Scope enforcement for invasive actions
- Sanitization for command args (defense in depth)

### Operational Integrity
- Every operational capability corresponds to functioning implementation
- Real tool execution path, parameter handling, output collection, parsing, failure handling, capability requirements implemented
- No placeholder adapters, no fabricated output, no simulated discoveries as real results
- Explicit reporting of unavailable capabilities with reasons
- Auditability with full traceability

## [Unreleased]

### Planned
- Additional parsers for more tools (horst, wavemon, kismet logs, hcxdumptool status)
- More detailed verification workflows (e.g., re-scan with different tool for AP confirmation)
- Greenbone/OpenVAS, Nuclei, Nikto adapters for vulnerability assessment phase
- Metasploit, Impacket, Responder framework adapters
- Web UI for assessment visualization
- AI-based decision system as optional planner
- Integration tests with real hardware (requires physical wireless adapter)
- Performance benchmarks for large-scale assessments
