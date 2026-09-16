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

## [0.2.0] - 2026-09-16

### Added - Deep Research & Fullest Potential Usage
- **RESEARCH.md**: Comprehensive deep research document covering all Kali wireless toolchain tools with real usage, flags, output formats, operational characteristics, sources, and how framework leverages each tool's fullest potential per adaptive philosophy
- **New adapters after deep research (46 total capabilities, up from 30)**:
  - `aireplay-ng`: Active wireless testing with injection test, deauth, fakeauth, arpreplay actions; highly invasive with strict scope enforcement; parses injection working/failure, acks, BSSID not found
  - `aircrack-ng`: Capture analysis and key-recovery with wordlist, BSSID filtering, mode; parses KEY FOUND
  - `airdecap-ng`: Authorized capture decryption with ESSID, BSSID, password; parses decrypted count
  - `airbase-ng`: AP simulation/testing with ESSID, channel, BSSID; evidence type ACCESS_POINT
  - `termshark`: Terminal Wireshark with interface and read_file support
  - `mitmproxy`: HTTP/HTTPS interception via mitmdump/mitmproxy/mitmweb with write_file, read_file, listen_port; relevant after wireless access reaches app layer
  - `dnsenum`: DNS enumeration with dnsserver, wordlist, enum, whois; parses A records, NS, IPs
  - `dnsrecon`: DNS reconnaissance with scan types std, rvl, brt, etc.
  - `smbmap`: SMB share enumeration with user, password, recursive listing
  - `enum4linux-ng`: Comprehensive SMB enumeration with -A all
  - `nbtscan`: NetBIOS scanning with IP, NetBIOS name parsing
  - `snmpwalk`: SNMP enumeration with version, community, OID
  - `nuclei`: Template-based vuln scanning with severity, templates, output; parses [severity] [template] [url]
  - `nikto`: Web server assessment with port, output; parses OSVDB findings
- **Enhanced existing adapters** to use fullest potential:
  - `iw`: Now supports subcommands link, info, scan via parameters (not just dev)
  - `airodump-ng`: Documented --berlin, --wps, --output-format pcap, --write-interval, BSSID filtering, channel filtering; handles temp file lifecycle with multiple formats
  - `wash`: Documented survey passive mode, JSON output, ignore FCS, channel filtering; correlates with WPS state
  - `tshark`: Documented BPF capture filter vs Wireshark display filter distinction, JSON vs fields, count, duration; useful for verification with specific filters (EAPOL, beacon)
  - `bettercap`: Documented caplet and eval for granular capability exposure rather than opaque run everything
  - `scapy`: Documented as programmatic component, direct library execution with stdout capture, fallback to subprocess
  - `reaver/bully/pixiewps`: Documented pixie dust attack flow, correlation with wash discovery, verification via second tool
  - `hcxdumptool/hcxpcapngtool/hashcat/john`: Documented distinction between capture acquisition, material conversion, offline analysis, verification phases
  - `nmap`: Documented 3 output formats (normal, grepable -oG -, XML -oX -), scan types, timing, scripts; parser handles all 3
  - `curl/openssl/smbclient`: Documented as relevant only when wireless assessment transitions to service enumeration after access, with port-based selection (curl only when 80/443 open)

### Changed
- Registry loader now loads 46 capabilities covering full Kali toolchain per deep research
- Test `test_registry_loading` now expects >=40 capabilities and checks 27 expected including new ones

### Security
- Maintained security-first: no shell=True, input validation for new adapters (BSSID, ESSID, domain, target), scope enforcement for invasive (aireplay-ng, airbase-ng, nuclei, nikto)
- Deep research ensures each tool's operational characteristics (invasive, persistent, produces_pcap, requires_authorization) accurately modeled in metadata

### Documentation
- RESEARCH.md with sources: Kali Tools docs, Aircrack-ng docs, Wireshark docs, Scapy docs, tool --help, man pages, GitHub repos
- Each tool section explains real usage, output, operational characteristics, and framework's adaptive usage

## [Unreleased]

### Planned
- Additional adapters: wpaclean, airdecloak-ng, ivstools, packetforge-ng, airdriver-ng, airserv-ng, wget, ftp, ldapsearch, rpcclient, Greenbone/OpenVAS, Metasploit, Impacket, Responder
- More detailed parsers for horst, wavemon, kismet logs, hcxdumptool status
- Verification workflows: re-scan with different tool, signal correlation
- Web UI for assessment visualization
- AI-based decision system as optional planner
- Integration tests with real hardware
- Performance benchmarks
