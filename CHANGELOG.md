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

## [0.3.0] - 2026-09-16

### Added - Advanced Tool Handling and Management with Deep Research Confirmation
- **ToolManager** (`src/wifi_framework/core/execution/tool_manager.py`): Advanced tool handling with deep research
  - ToolInfo with version parsing (multiple flags --version, -v, -V, version), operational check via --help, dependency tracking, caching 60s
  - InterfaceCapability with driver via ethtool -i, monitor via iw list * monitor, injection via aireplay-ng --test, channels via iw list * MHz [channel], MAC via /sys/class/net, up via operstate/ip link
  - get_capability_status with deep interface checks (monitor, injection) and driver info for controlled failure and replanning
  - Tool chains for objectives: handshake_capture, wpa_crack, wps_assessment, wireless_discovery, network_discovery, dns_enumeration, service_enumeration, vulnerability_assessment, interface_setup - reflecting real assessment flow not blind execution
  - Resource management: temp file/dir creation and cleanup for pcap, csv, kismet logs
  - to_dict for audit

- **InterfaceManager** (`src/wifi_framework/core/execution/interface_manager.py`): Lifecycle management with deep research
  - list_interfaces via /sys/class/net
  - get_interface_info deep via ToolManager → InterfaceInfo
  - set_interface_up/down via ip link with ifconfig fallback
  - set_channel via iw dev set channel with iwconfig fallback, validation 1-196
  - create_monitor_interface via airmon-ng start (parses monitor name via regex on [phy0]wlan0mon) then iw set type monitor then iwconfig mode Monitor fallback - handles driver quirks
  - remove_monitor_interface via airmon-ng stop, iw set type managed, iw dev del
  - change_mac via macchanger -r or -m with down/up handling, parses New MAC, for authorized MAC filtering tests
  - unblock_rfkill via rfkill unblock all/wifi
  - get_supported_channels via iw list * MHz [channel] regex

- **DependencyResolver** (`src/wifi_framework/core/execution/dependency_resolver.py`): Execution order and alternatives
  - resolve_dependencies recursively with cycle avoidance via visited set, finds provider capability by tool_binary
  - get_execution_plan for objectives with duplicate removal preserving order
  - check_tool_chain_feasibility with missing and reasons for controlled failure
  - suggest_alternatives via output overlap (e.g., if airodump missing, suggest tshark/kismet/horst that produce access_points)
  - to_dict for audit

- **Enhanced Engine discovery** (`src/wifi_framework/core/engine/assessment_engine.py`):
  - discover_interfaces now uses ToolManager deep scan for driver/monitor/injection, plus iw dev, iwconfig, rfkill evidence, prints driver/monitor/injection/up per interface
  - discover_capabilities uses ToolManager deep tool discovery (58 binaries) and deep capability status, logs tool_manager_state and dependency_resolver, shows tool chains feasibility per objective

- **CLI --list-capabilities deep** (`src/wifi_framework/cli/main.py`):
  - Deep tool discovery with path/version/operational
  - Deep interface discovery with driver/monitor/injection/MAC
  - Tool chains feasibility per objective
  - Detailed list with invasive/persistent/requires_auth/needs/references/alternatives if unavailable

- **New adapters after deep research (58 total, +12 from 46)**:
  - `airserv-ng`: Remote wireless interface access -d -c -p -v, persistent, for distributed assessment
  - `packetforge-ng`: Packet construction -0 -a BSSID -h client -k src_ip -l dst_ip -y fragment.xor -w custom.cap, invasive, produces pcap
  - `wpaclean`: WPA capture cleanup cleaned.cap capture.cap, offline analysis
  - `airdecloak-ng`: Cloaked frame analysis -i pcap --ssid, reveals hidden SSIDs, parses decloaked SSID
  - `ldapsearch`: LDAP enumeration -x -h host -b base filter, parses DN entries
  - `rpcclient`: RPC enumeration -U user%pass host -c enumdomusers, parses user/rid/group
  - `ftp`: FTP enumeration via curl ftp://host/, parses listing
  - `wget`: HTTP retrieval -qO- url, -r recursive, parses content length/snippet
  - `openvas`: OpenVAS/Greenbone vuln assessment --version, gvm-cli socket --xml, requires allow_scan for safety
  - `metasploit`: Vuln validation via msfconsole -q -x use module; set RHOSTS; check; exit, default check not run, requires allow_run for exploitation, parses vulnerable/session opened
  - `impacket`: Protocol implementations via impacket-psexec, impacket-secretsdump with user:pass@target, parses potential access
  - `responder`: Auth capture via responder -I iface -w -r -f, parses captured NTLM hashes [SMB] [HTTP]

- **Tool handling philosophy**: Tools as specialized instruments, not interchangeable wrappers, each with capabilities, prerequisites, inputs, outputs, operational characteristics, evidence types. Framework does NOT assume every tool should be executed. Selection determined by state, hardware, scope, evidence, uncertainties. Example WPS flow from spec implemented. Tool may be re-selected if new evidence useful, skipped if already established.

### Changed
- Registry loader now loads 58 capabilities covering full Kali toolchain per deep research and tool management
- Test `test_registry_loading` now expects >=50 capabilities and checks 46 expected including all new
- Core execution __init__ now exports ToolManager, InterfaceManager, DependencyResolver
- Engine now uses ToolManager, InterfaceManager, DependencyResolver for advanced handling

### Security
- Maintained security-first: no shell=True, validation for new adapters (BSSID, ESSID, domain, target), scope enforcement for invasive (aireplay-ng deauth, airbase-ng AP simulation, packetforge-ng, nuclei, nikto, metasploit run, impacket, responder), safety for metasploit (check default) and openvas (allow_scan)

### Documentation
- TOOL_HANDLING.md with deep research, operational integrity, resource management, auditability, security, verification
- RESEARCH.md already covers all tools with real usage, flags, output, operational characteristics, sources, adaptive usage

## [0.4.0] - 2026-09-16

### Added - Explicit Data Contract Layer

Subsystems no longer call each other's internals: they exchange versioned, validated, immutable
messages. See `docs/DATA_CONTRACTS.md` for the full reference and `docs/CONTRACT_LAYER_PLAN.md`
for the milestone plan this release completes.

- **`src/wifi_framework/contracts/` package** - ten contracts, all at version `1.0`, importing
  nothing from `core/` so engines stay independently replaceable:
  - `base.py`: `BaseContract` with the common envelope (`schema`, `version`, `message_id`,
    `assessment_id`, `timestamp`, `source_engine`, `correlation_id`, `extensions`), two wire forms
    (`to_message()` enveloped / `to_dict()` flat), content digests, and typed-field normalisation
    on both construction and parsing
  - `registry.py`: `ContractRegistry` performing Semantic-Versioning major-version negotiation;
    an unsupported major version raises `UnsupportedContractVersion` rather than being guessed at
  - `world_state.py`: `world-state` with interface/AP/client/network projections, observation
    refs, capability states with availability reasons, uncertainty refs, execution summary and
    planner hints
  - `ai.py`: `planning-context` and `decision-proposal`; a proposal **cannot carry a command** -
    parsing one that does raises, so an AI layer can never invoke a shell
  - `action.py`: `action-request` (objective, target, reason, prerequisites, expected outputs,
    origin, verification requirement) and `action-validation-result` (approved/rejected/deferred
    with per-stage checks and a structured rejection reason)
  - `execution.py`: `execution-result` with `ExecutionStatus` split into `TERMINAL_EXECUTED`
    (success, partial, failed, timeout, cancelled) and `TERMINAL_NOT_EXECUTED` (unsupported,
    rejected), plus `FailureCategory` and its `RETRIABLE` subset
  - `evidence.py`: `evidence-set` with `Observation` carrying full `Provenance`
    (execution → action → assessment → correlation → tool → artifacts)
  - `verification.py`: `verification-request`/`verification-result` with `Claim`, `ClaimType`,
    `VerificationStatus` (verified, supported, unresolved, contradicted, refuted, stale),
    `VerificationMethod` and `EvidenceRequirement`
  - `experience.py`: `experience-record` with `ActionOutcome` and `ExecutionOutcomeCost`
- **World Model contract boundary** (`core/world/`): `WorldStatePublisher` projects the
  authoritative state into `world-state` (stable uncertainty ids derived from type and subjects
  only, staleness flags, scope flags, hypotheses/findings split, capability availability with
  preserved reasons); `WorldModelApplier` is the only writer from contracts back into the model
  and refuses evidence the contract did not declare
- **Policy layer** (`core/policy/validator.py`): `ActionPolicy` validates an `action-request`
  through structural → scope → capability → parameters and returns an `action-validation-result`,
  distinguishing `rejected` (must not run) from `deferred` (cannot run here right now), with
  `ParameterRule` families for MAC, SSID, channel, IP, CIDR, interface, path and domain values
- **Execution Gateway** (`core/execution/gateway.py`): prepares a request into a concrete
  invocation, runs the real tool, and reports an `execution-result`; `classify_failure` maps
  adapter reasons onto structured categories
- **Artifact Store** (`core/execution/artifacts.py`): tool output is referenced, not inlined -
  `ArtifactRef` records path, size and SHA-256, enforces a 32 MiB cap and discloses truncation
- **Evidence Engine** (`core/evidence/engine.py`): turns executions into attributed, scoped
  observations, declares parse problems instead of hiding them, and emits deduplicated
  `verification-request`s per (subject, claim) so ten observations of one AP open one cycle
- **Verification Engine** (`core/verification/engine.py`): judges claims with noisy-OR
  aggregation over de-duplicated independent sources, freshness checks and contradiction
  detection; returns `action-request`s when more evidence is needed and never executes a tool
- **Decision Engine** (`core/decision/`): `WorldStateView` and `ContractRegistryView` make
  `world-state` authoritative for capability availability during planning
- **Experience Engine** (`core/experience/engine.py`): builds `experience-record`s where
  `gain = saturation(new_observations) × status_factor × verification_factor`
- **Correlation chains**: `AuditLogger.correlation_chains()` reconstructs
  `assessment_id → action_id → execution_id → evidence_ids → verification_ids → finding_ids` per
  execution; `contract_catalogue()` lists producers and supported versions. Both are included in
  every generated report, and each contract is audited under a `contract:<schema>` event
- **Model fields** (additive): `Evidence.action_id`/`correlation_id`;
  `ExecutionRecord.action_id`/`correlation_id`/`status`/`artifact_ids`

### Changed

- `AssessmentEngine` now runs the whole loop through contracts: publish `world-state` → service
  pending verification actions → plan → prepare → validate → execute → evidence → verify →
  experience → re-evaluate. `run_single_action` accepts either an `action-request` or a legacy
  dict; `legacy_action_to_request` bridges older callers
- Environment bootstrap (`iw dev`, `iwconfig`, `rfkill`) is expressed as an `action-request` with
  objective `discover_interfaces` and runs through the same pipeline, so **every** execution in
  the history carries an `action_id` and is traceable. A tool that is not installed now yields
  `unsupported` rather than a failed-looking execution
- Policy check order matches specification section 11: scope is judged **before** capability, so
  an out-of-scope request reports the scope refusal even when the tool is also missing
- Refusals now suppress capabilities instead of being re-requested: permanent for scope denial,
  unknown capability and unsafe parameters; a 3-iteration cooldown for transient refusals
  (`BLOCK_COOLDOWN_ITERATIONS`). Blocked capabilities are projected out of the `world-state` view
  the Decision Engine plans from, while the published record of the environment is unchanged
- `ActionSelector` gained a relevance gate: a capability that produces none of the outputs an
  uncertainty needs is unselectable (score `-1.0`) rather than merely unattractive. This
  implements "the presence of a tool is not a requirement to execute it" - previously `curl`
  could be selected to resolve "no access points observed"
- `ExecutionGateway.prepare()` attributes a refusal to the most fundamental blocker: a missing
  binary is reported as `tool_not_found` instead of `interface_unavailable`, and is blocked
  permanently rather than looking retriable
- `pyproject.toml`: `pythonpath = ["src"]` for pytest, so the suite runs from a clean checkout
  without an install step; package version aligned with the changelog (0.1.0 → 0.4.0)

### Fixed

- **`WorldStateView` crashed on any observation** (`core/decision/state_view.py` read
  `observation.tags`, a field `ObservationRef` does not have). Every assessment that had observed
  anything failed at planning; tags are now rebuilt from the contract's `in_scope`/`stale`
  projections
- `WorldStatePublisher` inferred `in_scope=True` from the presence of *any* tag, asserting a scope
  authorisation nobody had granted. Only an explicit `in_scope`/`out_of_scope` tag now states it
- `AssessmentScope.is_wireless_asset_authorized` could wave an unauthorised BSSID through because
  an empty SSID allowlist made the SSID check vacuously true. An identifier now grants
  authorisation only when the operator actually used it to define scope; the documented
  "either declared identifier matches" behaviour is preserved
- Evidence sets from a timed-out execution are now marked `incomplete`, matching the partial
  observations they carry
- `ActionPolicy` no longer double-reports a missing interface: interface requirements are owned by
  the capability stage (which also knows whether it exists, is up and supports monitor mode), so
  an environmental gap yields a deferral the engine can act on instead of a hard rejection
- Contracts built in-process now coerce nested fields to their declared types exactly as parsed
  ones do, so consumers never have to defend against both shapes

### Security

- Fail-closed invasiveness: a capability that cannot be resolved is treated as invasive, because
  an unknown capability cannot be shown to be passive
- Unsafe parameter values (argument injection, control characters, shell metacharacters, path
  traversal, bytes) are rejected and never retried; a merely missing target stays retriable
- Scope-refused and parameter-refused actions never reach the tool - proven by stub binaries that
  record their own invocations
- Still no `shell=True` anywhere; commands remain argument lists and `pyyaml` remains the only
  third-party runtime dependency

### Documentation

- `docs/DATA_CONTRACTS.md`: envelope, catalogue, validation levels, execution states, policy
  order, correlation chains, artifacts, subsystem boundaries and invariants, module map, how to
  add a contract, and an explicit verification-honesty statement
- `docs/ARCHITECTURE.md`: new Contract Layer section with the message-flow diagram, contract
  table and invariants; Testing section replaced with the actual suites and their coverage
- `docs/CONTRACT_LAYER_PLAN.md`: verification honesty statement completed

### Testing

- 24 pre-existing test functions pass **unmodified**; the suite grows from 24 to 242 tests. The one
  pre-existing file touched is `tests/test_scope.py`, extended with 5 additive regression tests for
  the scope fix above (54 insertions, 0 deletions - no existing assertion was changed)
- New suites: `test_contracts.py` (49), `test_policy.py` (30), `test_world_state.py` (34),
  `test_verification_engine.py` (29), `test_evidence_engine.py` (28),
  `test_contract_pipeline.py` (25), `test_audit.py` (18)
- `test_audit.py` proves the M6 acceptance criterion directly: the correlation chain reaches
  `finding_ids` and `verification_ids` for every finding, findings from other executions are not
  falsely linked, and an unattributed execution stays honestly unattributed
- `test_contract_pipeline.py` drives the **production** adapters, parsers, gateway and policy
  through real `subprocess` calls against stub binaries on `PATH`, covering success, non-zero
  exit, permission failure, timeout, malformed output, missing tool, scope refusal, unsafe
  parameters and the complete loop
- Full suite runs in ~4s and requires no wireless hardware and no Kali tools

### Known limitations

- Behaviour depending on real wireless hardware, monitor mode, packet injection or the presence of
  Kali tools (`airodump-ng`, `wash`, `reaver`, `hcxdumptool`, `nmap`, …) is implemented but
  **not field-verified**; this sandbox has no wireless tooling
- A timed-out run reports `timeout` rather than `partial` for adapters that decline to parse
  output from a non-zero exit (e.g. `iw`). Capture tools writing to files
  (`airodump-ng --write`, `hcxdumptool`) are how partial output reaches the model
- With no network scope declared, `is_ip_authorized` permits passive discovery of any host. This
  is pre-0.4.0 `AssessmentScope` semantics, deliberately left unchanged here; tightening it is a
  behavioural decision for the maintainer

## [Unreleased]

### Planned
- Additional adapters: airdriver-ng, ivstools (can be added similarly), Wireshark GUI (not suitable for automation but could add adapter for --help)
- More detailed parsers for horst, wavemon, kismet logs, hcxdumptool status counters
- Web UI for assessment visualization
- AI-based decision system as optional planner
- Integration tests with real hardware on Kali
- Performance benchmarks for large-scale assessments
- Decide whether an undeclared network scope should permit passive discovery of arbitrary hosts
  (see Known limitations above)
