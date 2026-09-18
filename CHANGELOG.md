# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- WPA3/SAE posture foundation based on the Dragonblood research: authoritative AKM, RSN/RSNX, PMF, SAE-group, PWE, and hostapd/wpa_supplicant version models in `core.models.wpa3`.
- Pure RSN/RSNX byte and `iw` text decoders. RSN parsing distinguishes MFPR bit 6 from MFPC bit 7, rejects unknown OUIs as known AKMs, and leaves absent fields unknown.
- `iw_scan` passive capability and `parse_iw_scan`, with real `iw dev <interface> scan` execution and access-point evidence. Transition mode, H2E advertisement, PMF posture, and malformed BSSID reporting are wired into evidence.
- WPA configuration audit parser for `sae_groups`, `sae_pwe`, PMF, anti-clogging threshold, Transition Disable, and AKM settings. Password and SAE secret values are never retained.
- Passive `hostapd_cli` and `wpa_cli` control-client audit capabilities. Secret-valued lines are sanitized before entering `Evidence.raw_output`, not merely ignored by the parser.
- Offline `sae_capture_analysis` capability using tshark JSON and an explicit SAE dissector-field parser. Observed groups can now complete the group posture from an authorized capture without transmitting frames.
- Assessment re-evaluation updates an existing unresolved WPA3 finding when later capture/configuration evidence resolves it, without downgrading independently verified findings.
- `docs/WPA3_DRAGONBLOOD.md` documenting research grounding, evidence limits, remediation, and the explicit non-implementation of credential recovery, commit floods, rogue-AP downgrade, and EAP-pwd reflection tools.
- 41 focused WPA3 posture, RSN, `iw scan`, control-client audit, offline SAE-capture, configuration-audit, world-model, and assessment-integration tests.

### Security
- Passive observations never invent SAE groups, PWE mode, implementation version, or Transition Disable status. Unsupported active attack claims remain unresolved rather than being promoted to verified findings.

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
    *(correction, 0.4.0: the `sanitize_command_arg` helper shipped here was a no-op and was never
    called - the sanitisation control this line claims did not exist. Removed in 0.4.0; the real
    control is `ActionPolicy` rejecting unsafe values. See the 0.4.0 Security section.)*
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
  *(correction, 0.4.0: never implemented - see the note above and the 0.4.0 Security section)*

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
  *(correction, 0.4.0: true for `ToolManager` and `DependencyResolver`, which the engine calls
  throughout discovery, capability status and tool-chain feasibility. **Not** true for
  `InterfaceManager`: the engine constructs one at `assessment_engine.py:107` and the CLI another at
  `main.py:204`, but no method of it is called anywhere in the package - verified by an AST sweep
  over all 119 modules. Its hardware-mutating operations (monitor-mode creation, MAC change,
  interface up/down, channel set, rfkill unblock) are therefore **operator-invoked only**, which is
  the intended design: the loop detects a missing capability and defers, it does not reconfigure the
  radio on its own initiative. See the 0.4.0 Known limitations and `docs/ARCHITECTURE.md`.
  `tests/test_validation.py::test_the_autonomous_loop_never_mutates_radio_hardware` now pins that
  boundary.)*

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

- **A malformed BSSID in the operator's scope silently authorised a different network**
  (`core/models/scope.py`, `utils/validation.py`). Both `AssessmentScope._normalize_mac` and
  `utils.validation.normalize_mac` "cleaned" an address by stripping *every* non-hex character with
  `re.sub(r"[^0-9a-fA-F]", "", mac)` and then accepting whatever 12 hex digits remained. So
  `AABBCCDDEEFFGG` normalised to `AA:BB:CC:DD:EE:FF` - an address nobody wrote.

  Because that copy sits in the authorisation path, the consequence was scope widening: the
  allowlist ended up containing a network the operator never named, `AssessmentScope.validate()`
  returned **no error** (the normalisation had "succeeded"), and the CLI proceeded. Demonstrated
  before the fix:

  ```
  AssessmentScope(authorized_bssids=["AABBCCDDEEFFGG"]).validate()          -> []
  ...is_bssid_authorized("AA:BB:CC:DD:EE:FF")                               -> True
  ```

  Normalisation now removes only surrounding whitespace and the two separator characters - the
  things that cannot change *which* address a value denotes - and rejects everything else. The same
  input now yields `['Invalid BSSID format: AABBCCDDEEFFGG']`, an empty allowlist, and CLI exit 1
  with no report written. Refusing a malformed scope entry is the only safe behaviour for an
  identifier that decides what may be attacked; guessing at it is how an assessment ends up touching
  a neighbour's access point.
- **`scope.py` kept a second, drifted copy of MAC normalisation.** `AssessmentScope._normalize_mac`
  and `utils.validation.normalize_mac` were independent implementations of the same rule, which is
  how the bug above existed in the authorisation path while `validate_mac` answered differently for
  identical input. The scope method now delegates to the shared function, so the allowlist and the
  parameter validator cannot disagree. `tests/test_validation.py::test_scope_and_validator_agree_on_what_a_bssid_is`
  asserts the agreement across twelve spellings, valid and invalid.
- **`validate_mac` and `normalize_mac` disagreed about what a MAC address is.** `validate_mac`
  matched a regex and then fell back to its own character-stripping count, so it accepted inputs the
  normaliser would reshape. `validate_mac` now delegates to `normalize_mac`: one definition, one
  answer.
- **A trailing newline was accepted in an interface name** (`utils/validation.py`). The pattern used
  `^...$`, and in Python `$` also matches immediately *before a trailing newline*, so
  `validate_interface("wlan0\n")` returned `(True, "")`. Interface names are interpolated into
  `/sys/class/net/{interface}` and passed to tools as written, so the value checked was not the
  value used. Patterns are now anchored `\A...\Z`.
- **`.` and `..` were accepted as interface names.** Both match the legitimate character class
  (dots are valid - `eth0.100` is a VLAN subinterface), and `check_interface_exists` builds
  `/sys/class/net/{interface}`, where `/sys/class/net/..` **exists** - so a traversal value was
  reported as a present interface. A name whose dot-separated segments include an empty one is now
  refused, which rejects `.` and `..` while leaving `eth0.100` and `wlan0mon` valid.
- **`check_interface_exists` reported nonexistent interfaces as present** (`utils/system.py`). It
  interpolated its argument straight into `os.path.exists(f"/sys/class/net/{interface}")`, so `""`,
  `"."` and `".."` all returned `True` - the directory itself and its parent exist. Fourteen call
  sites gate on this answer (`InterfaceManager.change_mac`, monitor-mode setup, `ExecutionAdapter`
  preparation, the capability and tool managers), so a false positive let an operation proceed
  against a path that is not an interface and the caller's "interface does not exist" branch never
  ran. The name is now validated before it reaches the filesystem, which also removes any traversal
  possibility at that call site. Verified post-fix: `""`, `"."`, `".."`, `"..."`, `"wlan0\n"`,
  `None` and `b"eth0"` all return `False`, every interface from `get_interface_list()` still returns
  `True`, and `--discover-only` still finds `eth0`.
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
- `DecisionEngine.accept_proposal` silently substituted a different tool when a proposal named an
  implementation that is not available (an AI proposing `reaver` would get `wash` with no record of
  the swap). The substitution is still performed - running an available alternative is legitimate -
  but it is now recorded in the returned problems, which the audit trail persists either way.
  "Why this tool and not another" is one of the questions the trail has to answer
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
- **Removed `utils.validation.sanitize_command_arg`, a no-op that documented a control which did
  not exist.** The function iterated over a list of shell metacharacters, discarded each match with
  `pass`, and returned its argument unchanged. It had zero callers, was absent from
  `utils/__init__.py`'s `__all__`, and was referenced by no test - yet four documents (README,
  ARCHITECTURE, IMPLEMENTATION_PLAN twice, and the 0.1.0 changelog twice) cited "sanitized args" as
  a security control. A reader auditing this framework's injection defences would have found a
  function whose name promised protection and whose body delivered none.

  It was **not** replaced with a working sanitiser, because sanitising here would be the wrong
  control. Commands reach `subprocess.run` as an argv list and are never parsed by a shell, so
  there is nothing to escape; and rewriting a target identifier is actively dangerous - an SSID
  legitimately contains `$` or `&`, so a "sanitised" SSID would aim the assessment at a network the
  operator never authorised. The correct control is the one already implemented and tested:
  `ActionPolicy._check_value` **rejects** the action (non-retriably) on control characters, shell
  metacharacters, `-`-prefixed values and path traversal.

  The forbidden-character sets now live in one place, `utils.validation.CONTROL_CHARS` and
  `SHELL_METACHARACTERS`, which `ActionPolicy` imports instead of redefining - previously the two
  copies could drift, and the documentation described neither. `tests/test_validation.py` pins the
  arrangement: the sets are non-empty, the policy layer's constants *are* those objects, no
  `sanitize_command_arg` exists, and no module in the package passes `shell=True`.

  The 0.1.0 changelog entries were annotated rather than deleted: the record of a claim being made
  and later corrected is more useful than a changelog that was quietly edited to look right.

### Documentation

- `docs/DATA_CONTRACTS.md`: envelope, catalogue, validation levels, execution states, policy
  order, correlation chains, artifacts, subsystem boundaries and invariants, module map, how to
  add a contract, and an explicit verification-honesty statement
- `docs/ARCHITECTURE.md`: new Contract Layer section with the message-flow diagram, contract
  table and invariants; Testing section replaced with the actual suites and their coverage
- `docs/CONTRACT_LAYER_PLAN.md`: verification honesty statement completed

### Testing

- 24 pre-existing test functions pass **unmodified**; the suite grows from 24 to 380 tests. The one
  pre-existing file touched is `tests/test_scope.py`, extended with 5 additive regression tests for
  the scope fix above (54 insertions, 0 deletions - no existing assertion was changed)
- New suites: `test_validation.py` (116), `test_contracts.py` (49), `test_world_state.py` (34),
  `test_policy.py` (30), `test_verification_engine.py` (29), `test_evidence_engine.py` (28),
  `test_contract_pipeline.py` (25), `test_decision_engine.py` (22), `test_audit.py` (18)
- `test_validation.py` covers the input validators and the security fixes above. Three of its tests
  are structural guards rather than behaviour checks: the forbidden-character sets are *the same
  objects* the policy layer uses (identity, not equality - a duplicate tuple would pass an equality
  check and then drift), no `sanitize_command_arg` exists to be mistaken for a control, and no
  module in the package passes `shell=True` to any call, verified by walking the AST of all 119
  modules so the phrase appearing in a comment or string cannot produce a false pass or a false
  alarm. `utils/validation.py` goes from 37% to 100% statement coverage
- `test_audit.py` proves the M6 acceptance criterion directly: the correlation chain reaches
  `finding_ids` and `verification_ids` for every finding, findings from other executions are not
  falsely linked, and an unattributed execution stays honestly unattributed
- `test_decision_engine.py` covers the AI-layer seam: the planning context is a narrowed projection
  that forwards no raw observations and no commands, out-of-scope assets are excluded, bulk
  sections are truncated, and `accept_proposal` refuses structurally invalid, cross-assessment and
  unfulfillable proposals while resolving category-level ones. Its final test proves
  **acceptance is not authorisation** - a proposal the Decision Engine accepts is then refused by
  the policy layer on scope
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
- **The framework never reconfigures the radio.** `InterfaceManager` implements monitor-mode
  creation, MAC changes, interface up/down, channel setting and rfkill unblocking, and is exported
  for operator use - but no code path in the package calls it (verified by an AST sweep over all
  119 modules). The engine and the CLI each construct one and never invoke a method. Active
  assessment therefore **requires the operator to establish monitor mode first**
  (`airmon-ng start wlan0`); see README "Interface preparation".

  This is intended, not an oversight: those operations are disruptive and not reliably reversible
  mid-assessment, so they belong to a human who has decided to make them. The consequence is worth
  stating plainly though - on an interface that is not in monitor mode, every monitor-requiring
  capability defers with `monitor_mode_unavailable`. That deferral is *retriable*, so the capability
  is suppressed for `BLOCK_COOLDOWN_ITERATIONS` (3) iterations and then becomes eligible again,
  which means an assessment left running against an unprepared interface will cycle
  defer → cooldown → defer until it exhausts `--max-iterations`. It will not fabricate results to
  fill the gap, and each deferral is recorded in `execution_history` and the audit trail, but it
  also will not fix the interface itself. `tests/test_validation.py::test_the_autonomous_loop_never_mutates_radio_hardware`
  pins the boundary so wiring it up later is a conscious decision.

## [0.4.1] - 2026-09-17

### Added
- **Continuous integration** (`.github/workflows/tests.yml`): the unit suite on Python 3.10, 3.11
  and 3.12, plus a separate job that verifies `InterfaceManager` against **real `mac80211_hwsim`
  radios**. Runners boot an Azure kernel (`6.17.0-1022-azure`) built with `CONFIG_MODULES=y`,
  `CONFIG_WIRELESS=y` and cfg80211/mac80211 as modules, but with `CONFIG_MAC80211_HWSIM` absent
  entirely - so no distro package can supply it. `scripts/build_hwsim.sh` compiles the driver
  out-of-tree against the running kernel's headers, pre-loads cfg80211 and mac80211 (whose symbols
  are absent from `/proc/kallsyms` until loaded, which is why a bare `insmod` failed with "Unknown
  symbol"), installs into `/lib/modules/$KREL/extra` and lets `modprobe` order the dependencies.
  Source download retries with backoff and falls back to the API host after one run was lost to a
  single refused connection.
- **`scripts/verify_wireless_hardware.py`**: drives the real module and confirms every result
  against a source the framework does not control - type and channel from `iw dev <if> info`, MAC
  from `/sys/class/net/<if>/address`, link state from `ip link`, blocks from `rfkill list`. A method
  reporting success without changing the radio fails. Includes a negative control (a nonexistent
  interface must be refused), checks that a randomised MAC carries the locally-administered bit,
  isolates each check so one exception cannot hide the rest, and restores the original MAC, type and
  link state. Preflight fails loudly with `lsmod`/`dmesg`/`iw` diagnostics rather than passing
  vacuously. Runs by hand on a Kali box with a physical adapter; 17/17 checks pass on hwsim.
- **`scripts/remote_hwsim.py`**: wrapper for a remote hwsim execution API, for iterating without a
  CI round trip. Endpoint comes from `HWSIM_ENDPOINT` rather than being hardcoded - a tunnel URL is
  ephemeral and private, and committing one puts a stale secret in history. **Usable only from a
  machine with normal internet access**: the dev sandbox's egress is restricted to PyPI and GitHub,
  so it cannot reach any tunnel from any provider. CI supersedes this path entirely.
- **`tests/test_interface_manager.py`** (39 tests): pins all four fixes below using output captured
  verbatim from the runner. Suite 380 -> 419. `tool_manager.py` coverage 58% -> 68%,
  `interface_manager.py` 13% -> 32%.

### Fixed
Four defects in interface discovery and channel handling, found by verifying against real radios.
None were reachable from the unit suite, which never queried the same interface twice, never ran
where `iw` exists, and never parsed multi-radio output.

- **The interface cache raised `AttributeError` on every hit.** `check_interface_deep` reads
  `.last_checked` from the cached value, but `InterfaceCapability` never declared that field - only
  `ToolInfo` did. Any second lookup of the same interface crashed, for existing and absent
  interfaces alike, so the cache had never worked. This is what killed `change_mac`: it calls
  `check_interface_deep` on an interface `get_interface_info` had already cached. Reproduced locally
  before fixing.
- **Interface type was detected only when `iw list` failed.** `cap.type` was assigned inside the
  `else` branch of that check, so on every working system the type kept its `"unknown"` default.
  Confirmed empirically: the framework reported `unknown` for an interface the kernel reported as
  `managed`, and again for `wlan1mon` which the kernel reported as `monitor`. That also made the
  injection probe unreachable, since its guard is `cap.type == "monitor"` - `supports_injection`
  could never become true on real hardware. Type and channel now come from `iw dev <if> info`
  unconditionally, parsed with an anchored `^\s*type\s+(\S+)` so AP, mesh point and IBSS are
  captured rather than only the two literals previously handled.
- **`get_supported_channels` ignored its `interface` argument**, parsing the whole `iw list` output
  and merging every radio's channels, and it counted channels the driver marks `disabled`. Now scoped
  to the owning phy and excluding disabled channels. Two separate format problems had to be fixed to
  get there: current `iw` opens each block with `Wiphy phy0` rather than the older `phy#0`, and
  current `iw list` does not enumerate interfaces at all, so the phy is resolved from
  `/sys/class/net/<if>/phy80211` instead - authoritative, and correct for the virtual interfaces
  `airmon-ng` creates. Block matching is by header equality, so `phy1` cannot select a `phy10` block.
  When neither resolution works it falls back to the full output, so a partial answer is returned
  rather than nothing. The `iw list` timeout also rose from 5s to 15s, which was too tight with
  several radios.
- **Frequencies are printed with a decimal place by current `iw`** (`* 2412.0 MHz [1]`), which 6 GHz
  half-channel spacing requires. The parser expected `\d+ MHz`, matched `2412`, then met the decimal
  point where whitespace was required and failed - on every line, silently, returning an empty
  channel list. Both forms are now accepted.

### Notes
- **A lesson recorded deliberately:** the synthetic fixtures used the older integer form
  `* 2412 MHz [1]`, so unit tests passed while the real radio returned nothing at all. Test data
  derived from assumption rather than observation encodes the assumption. The fixtures added here are
  verbatim runner output, and the harness diagnostic that found this was itself buggy first - it
  truncated a joined string to 12 characters and reported `STBC Tx <= 8`, a line from the STBC
  capability section, instead of any frequency line.
- **What hwsim still does not verify:** packet injection against a physical driver (`aireplay-ng
  --test`), chipset and driver quirks, and capture under real conditions. A virtual radio exercises
  the software path up to the driver boundary. `supports_injection` is therefore implemented and
  reachable now, but not field-proven. See `docs/ARCHITECTURE.md`.
- The dev sandbox cannot run any of this: its kernel is built with `CONFIG_MODULES` unset, so it
  cannot load a module at all, and `CONFIG_WIRELESS` unset besides. That is why verification moved to
  CI rather than being a local convenience.

## [0.5.0] - 2026-09-17

### Security
- **`ScapyAdapter` no longer executes caller-supplied code.** The adapter previously
  `exec()`-ed a `script` parameter built from request data, which made it an arbitrary
  code-execution primitive reachable through the normal capability path — any caller able to
  influence adapter parameters could run Python with the framework's privileges, including root
  during a wireless assessment. Replaced with a bounded, declarative operation set (`version`,
  `sniff`). `script`, `code`, `source`, `expr` and `lambda` parameters are now rejected with
  `invalid_parameters` before any Scapy import, so a refused request has no side effects at all.
  `build_command` returns a fixed argv and never interpolates caller data.
- **Regression guard**: `tests/test_validation.py::test_no_module_executes_caller_supplied_code`
  walks every module under `src/` with `ast` and fails the suite if any bare `exec`, `eval` or
  `compile` call reappears. Verified by temporarily reintroducing one — the sweep caught it and
  reported the file and line.
- 51 new tests in `tests/test_scapy_adapter.py` pin the boundary: hostile payloads refused, no
  side effects on refusal, `build_command` safety, parameter validation ranges, and the
  requirement check.

### Fixed
- **Wrong relative-import depth in `ScapyAdapter`**: `from ...execution.adapter_base` resolved to
  `wifi_framework.tools.execution` rather than `wifi_framework.core.execution`, raising
  `ModuleNotFoundError`. Because that is an `ImportError` subclass, a broad `except ImportError`
  misreported it as a missing optional dependency and fell through to the base-class path, which
  looks for a `scapy` *binary* on `PATH`. The adapter's success path was therefore unreachable —
  every call failed with "Requirements not met". All imports in the module are now absolute.
- **Scapy modelled as a binary dependency**: `dependencies=["scapy"]` was checked with
  `check_tool_available`, which probes executables on `PATH` and can never match a Python library.
  Removed from metadata; `custom_requirement_check` now uses `importlib.util.find_spec("scapy")`.
- **Version detection**: `scapy.all.__version__` does not exist in Scapy 2.7, so the adapter
  reported `unknown`. Now read from `importlib.metadata`.

### Added
- **`scripts/verify_scapy_capture.py`** — proves the framework can actually put 802.11 frames on
  the medium and read them back, which `InterfaceManager` verification does not cover. Two
  `mac80211_hwsim` radios are placed in monitor mode on the same channel; 12 probe requests are
  injected from one and captured on the other. Each run carries a unique marker as the SSID so
  frames are unmistakably ours.
  - Three *independent* captures, because the point is not to trust the code under test: a
    stdlib-only `AF_PACKET` socket records raw bytes and is searched for the marker (this is what
    proves transmission traversed the medium, sharing no code with Scapy or the framework); the
    framework's `ScapyAdapter` runs concurrently and is checked on success, `frames_captured`,
    recorded interface and evidence production; the two are cross-checked, so an adapter reporting
    frames the medium never carried is a failure.
  - Also re-runs the code-parameter refusal against real hardware, confirming the security fix
    holds outside the unit suite.
  - Fails loudly rather than vacuously if fewer than two radios exist — testing one radio against
    itself would pass without proving anything.
- CI runs the above in the `wireless verification` job and surfaces results as annotations
  (`capture-injection-result`, `capture-failed-checks`), on the same reasoning as the
  `InterfaceManager` run: job logs sit on Azure blob storage that is not reachable from the dev
  sandbox, while annotations are.

### Changed
- CI installs the `full` extra in both jobs so Scapy-dependent tests and the capture verification
  actually run instead of silently skipping.
- Runtime dependencies are unchanged: `pyyaml` only. Scapy remains optional behind `full`.

### Verification (CI run 35201134582, all jobs green)
- Unit suite **471/471** on Python 3.10, 3.11 and 3.12 (was 419).
- `InterfaceManager` against real radios: **17/17**.
- Raw capture and frame injection against real radios: **12/12**, including
  `raw AF_PACKET capture received traffic`, `injected marker arrived over the air`,
  `marker received more than once (repeated transmission)`, `ScapyAdapter captured frames`,
  `adapter capture is consistent with the independent capture`, and
  `adapter still refuses a code parameter on real hardware`.

### Known limitations
- These are **virtual** radios. What is proven is the software path: monitor mode, 802.11 framing,
  raw socket capture, transmission between two interfaces, and the adapter's contract. What is not
  proven is anything physical — real RF propagation, chipset and driver injection limits, capture
  under real-world noise, or behaviour against actual access points and clients. See
  `docs/ARCHITECTURE.md`.
- `hwsim` radios forward frames to each other on a shared channel regardless of the MAC addresses
  used, so this verifies framing and the capture path, not association or authentication state
  machines.

## [0.5.1] - 2026-09-17

Hardening pass over the execution, persistence and privilege paths, following an
external architecture review. Every fix has a test that was confirmed to fail when the
fix is reverted. No production behaviour was loosened: `root` still means uid 0, scope
enforcement is unchanged, and the engines still communicate only through contracts.

### Fixed

#### Execution
- **Tool binaries are resolved once and the resolved path is executed** (`0cae7ac`).
  `check_tool_available` resolved a name with `shutil.which`, the gateway resolved it
  again to decide whether to refuse, and `run_command` handed the bare *name* to
  `Popen` - which searches `PATH` a second time inside the kernel. Any of the three
  could disagree with the others if `PATH` changed or a writable directory earlier in
  it gained an executable in between. `run_command` now resolves immediately before
  the spawn and executes that absolute path; the gateway and the availability check
  share the resolver; `ToolRef.path` falls back to it so the audit trail records a
  path rather than `null`.
- **Non-absolute names containing a path separator are refused.** `shutil.which`
  treats `./evil` as relative to the working directory, so a capability declaration -
  or a tool parameter, since the Impacket adapter derives its command name from
  `parameters["impacket_tool"]` - could select a file planted in the cwd instead of an
  installed binary. Absolute paths are still honoured. All 59 declared `tool_binary`
  values are bare names; a test asserts none is malformed.
- `resolve_binary` accepts an optional `allowed_dirs` to pin resolution to a known
  toolchain. It scopes the search rather than filtering its result, so a pinned
  directory is not shadowed into invisibility by an unpinned one earlier on `PATH`.

#### Privileges
- **Linux capabilities are checked, not just uid 0** (`3140960`). Every privileged gate
  asked `is_root()`, but administering a wireless interface needs `CAP_NET_ADMIN` and
  opening a raw capture socket needs `CAP_NET_RAW` - neither needs a root uid.
  Concretely: `ToolManager` skipped the `aireplay-ng --test` injection probe for any
  non-root process, so `supports_injection` stayed unknown and every packet-injection
  capability looked unavailable; `InterfaceManager` skipped the `airmon-ng` path on the
  same condition and fell through to `iw` calls it attempted unconditionally anyway.
- `utils/system.py` gains `CAPABILITY_BITS`, `decode_capability_mask`,
  `effective_capabilities`, `has_capability`, `normalize_privilege_token` and
  `satisfies_privileges`. The bit table is verified against the installed
  `include/uapi/linux/capability.h` by a test that parses the header and fails on any
  disagreement (skipped where no header is installed).
- `core/models/capability.py` documented `privileges` as "e.g. root, net_admin";
  nothing implemented the second form. Both `cap_net_admin` and `net_admin` spellings
  now work. **`root` keeps its strict meaning** - loosening it would have weakened a
  control on 19 capabilities at once on the strength of an assumption about what each
  tool needs. An unrecognised token fails closed rather than passing, and a test
  asserts every `privileges` value declared across the 38 adapters is evaluable.
- `ToolManager.holds_capabilities()` treats root as holding the full set, since the
  capability list is read once at construction.
- Privilege refusals are prefixed with the token `insufficient_privileges`, which the
  gateway and adapter base already map to that failure category, and now state what the
  process *does* hold. A malformed declaration deliberately carries no such prefix,
  because elevating cannot fix it.

#### Persistence and secrets
- **Operator secrets are kept out of the persisted audit trail** (`c217f50`). The
  adapters put secrets directly into command lines - `aircrack-ng` a passphrase from
  `parameters["password"]` or `parameters["key"]`, `reaver` a WPS PIN, Impacket
  `user:pass@host`, `smbclient` `user%password`, `snmpwalk` a community string - and the
  audit logger wrote all of it verbatim, making the trail a credential file. New
  `utils/redaction.py`, applied in `AuditLogger.log_event` (the single point every audit
  record passes through, so a new event type cannot leak by forgetting to filter) and in
  `save_report`. In-memory contracts stay exact. Each filtered record carries a
  `redaction` block naming the masked fields.
  - Matching is on whole name tokens, never substrings: a substring rule would mask
    `passive` (a netdiscover boolean) and `keyspace`. Non-secret paths (`hash_file`,
    `wordlist`, `potfile_disable`) and usernames are preserved, so the record still says
    what ran against what.
  - Secrets accumulate across the trail. A passphrase is supplied at parameterisation
    and appears in a command line at execution; masking each event independently leaked
    it through the later one.
  - **Tool output is not masked.** `john.py` and `hashcat.py` build
    `parsed_data["cracked"] = [{"password": ...}]` and `aircrack.py` parses
    `KEY FOUND! [ ... ]` - a sensitive-named field inside an evidence container holds the
    passphrase the assessment *recovered*. Harvesting and field masking therefore stop at
    an evidence-container boundary, while value substitution does not, so a supplied
    secret a tool echoes into its own stdout is still masked.
  - Captured WPS values (`pke`, `pkr`, `e_nonce`, `r_nonce`, `e_hash1`, `e_hash2`) are
    not masked: they come from frames transmitted in the clear, so they are evidence, and
    masking them would break reproducibility while protecting nothing. `authkey` is
    masked as derived key material.
  - A test scans every adapter source for secret-shaped parameter names and fails if one
    is neither masked nor explicitly accounted for.
- **Artifacts and audit files are owner-only** (`89358e9`). Both were created with the
  umask default - 0755 directories, 0644 files - leaving captured traffic and audit
  logs world-readable. Now 0700/0600, set at creation via `os.open` rather than by a
  later `chmod`. `ensure_private_dir` refuses to reuse an existing directory owned by
  another uid, so a hostile `/tmp` pre-creation cannot redirect the trail.
- **Audit write failures are visible** (`89358e9`). `except OSError: pass` meant an
  assessment whose trail silently stopped being recorded still looked auditable.
  Failures are collected on `AuditLogger.write_failures`.

#### Contracts
- **Message digests are deterministic across processes** (`ea968e8`). `digest()` and
  `message_digest()` used `json.dumps(..., default=str)`, so any object without a
  serialiser contributed its `repr` - which embeds a memory address. The same message
  hashed to `e6743abb...` in one process and `7cae5367...` in another while the
  docstring promised a stable identifier. `to_jsonable` now substitutes a stable type
  name, and `default=str` is gone so an unserialisable object fails loudly instead of
  hashing to an address.
- **Recorded commands preserve argument boundaries** (`251bd07`).
  `contracts/execution.py` promises the recorded command can be re-run by an auditor
  without reinterpretation, but it was reconstructed with `raw_command.split()`, which
  turns an SSID such as "Office Network" into two elements. `AdapterExecutionResult`
  now carries the `argv` actually passed to subprocess, and `gateway.recorded_command`
  prefers it. A library adapter such as Scapy records `argv=[]` rather than a
  fabricated invocation split out of a prose description.

#### Capability discovery
- **`InterfaceCapability.chipset` is populated** (`567427c`). The field was read by five
  callers - the gateway, `InterfaceManager`, the world-model publisher and the decision
  engine's state view - and assigned by none, so every `WorldState` published
  `chipset: null`. The branch meant to fill it read `bus-info` from `ethtool -i` under a
  comment claiming it "often contains chipset hint"; `bus-info` is a bus *address*
  (`usb001::003`), and the body was `pass`. `detect_chipset` now reads the identifiers
  sysfs actually provides, in preference order: USB `PRODUCT=<vendor>/<product>` from
  the uevent, PCI vendor/device files, `MODALIAS`, then the driver name. Results are
  prefixed with how they were derived (`usb:cf8:3007`, `pci:0x10ec:0x8812`,
  `modalias:...`) so a consumer can tell a hardware identifier from a guess.
  `bus_info` is retained separately for what it actually is.
- **Discovery failures are recorded** (`567427c`). Five `except Exception: pass`
  handlers in deep discovery now append to `InterfaceCapability.discovery_errors`.
  Best-effort discovery is correct, but "not observed" and "observed absent" are
  different facts and a framework built on that distinction should not collapse them.

#### Validation
- **The interface named in an `ActionRequest` is validated for all 38 adapters**
  (`66a6e70`). `ToolAdapterBase.execute` passed the interface straight to
  `build_command` without checking it against `validate_interface`, so an interpolated
  interface name reached a command line unvalidated. The gap was narrow - the Decision
  Engine validates upstream - but the base class is the enforcement point that does not
  depend on the caller behaving.
- **The Scapy adapter checks the interface contract before probing for the library**
  (`66a6e70`). Validation order was environment-dependent: with Scapy absent the
  interface error surfaced, with it present the same request produced a different
  failure. Two tests failed in one environment and passed in the other.

### Added
- `tests/test_binary_resolution.py` (11 tests), `tests/test_privilege_capabilities.py`
  (22), `tests/test_redaction.py` (75), `tests/test_contradictory_evidence.py` (13),
  `tests/test_capability_discovery.py` (11), `tests/test_storage_permissions.py` (8),
  `tests/test_process_supervision.py` (8), plus digest-determinism and argv tests.
  Suite: 471 -> 634 tests.
- `scripts/exercise_framework.py` (`34ea0a4`): a 13-stage runner that exercises the
  whole framework on a machine with real radios, bounded by safety checks. Intended for
  an operator's VM; the sandbox has no wireless hardware.

### Verified, not changed
- **Contradictory evidence is preserved and detected** (`3776c38`). Raised in review as
  an open question. Measured through the real pipeline: both observations survive in
  `state.evidences`, `AccessPoint.encryption` accumulates to `['WPA2', 'WEP']` rather
  than taking the last value, and an equal-strength disagreement yields `contradicted`
  at half the supporting confidence with `details.contradiction` naming the disagreeing
  observation and two action requests for more evidence. A stronger contradiction
  refutes; a weaker one is still recorded. Time-varying scalars (channel, signal) do
  take the latest value, which is correct for radio state, and the superseded
  observation is retained. No production change; 13 tests pin it, 11 of which fail when
  either preservation layer is broken.
- Process teardown (`594554c`): a timed-out command's whole process group is
  terminated, SIGTERM then SIGKILL. Measured - previously a grandchild survived the
  timeout.

### Declined
Recorded so the reasoning is available rather than lost:
- A separate `CommandPolicy` dataclass. It would duplicate the existing `ActionPolicy`,
  which already validates interface names, scope and parameters, and the review's own
  recommendation warns against duplicate validation and multiple sources of truth.
- Redesigning the planner around an information-gain metric, and a planner benchmark
  harness. Research-scale work with no measured defect behind it, and it needs a
  ground-truth scenario set defined first.
- Property-based testing. It would add `hypothesis` as a dependency;
  `scripts/exercise_framework.py` already fuzzes 11 parsers against 14 malformed inputs.
- Coverage gated in CI. Ruff and mypy landed in 0.6.0: ruff blocking on everything the
  project selects except the two categories recorded as deferred debt in `pyproject.toml`,
  and mypy gated against growth past `.mypy-baseline`. Coverage is measured by the
  `unit-tests` job but not enforced, because a threshold picked without a baseline is a
  number that gets adjusted until it passes.

## [0.6.0] - 2026-09-17

Silent-failure audit, followed by the first enforced lint and type gate. The pass started
from one question applied across the codebase: *what happens when this handler's `except`
branch runs?* Nineteen sites swallowed a failure and continued. Most were legitimate -
numeric coercion with a sensible default, a sysfs read on hardware that may not exist -
but six were defects, and every one of them had the same shape: a failure that made the
framework report less than it knew, so an operator or the World Model saw an empty result
instead of a broken one.

The gate then found a seventh defect that no amount of reading had surfaced: a mixed
IPv4/IPv6 authorized scope crashed the network scope check.

Measuring coverage afterwards found an eighth, in one of the two modules with no coverage at
all - and it was the most consequential of the eight: the documented `--config` path never
reached the authorization checks, so the framework refused invasive actions against assets
the operator had explicitly authorized. Testing it led to the other uncovered module and a
ninth: the parsers that recognize a MAC address were not asking the framework's one authority
on the subject, so `parse_wash` recorded BSSIDs that authority rejects and dropped ones it
accepts.

Every fix is mutation-checked - reverted in place, its tests confirmed to fail, restored.

### Fixed

#### Silent failures that made the framework report less than it knew

- **A truncated or malformed tool document was reported as an empty result** (`db29cff`).
  `parse_nmap_xml` caught `ET.ParseError` and returned no hosts; `parse_tshark_json` caught
  `JSONDecodeError` and returned no packets. A capture stopped mid-write and a scan that
  genuinely found nothing were indistinguishable downstream, and the World Model recorded
  "no hosts observed" as a fact about the network. Both parsers now take an optional
  `issues` list and append what went wrong; `AdapterExecutionResult` and `ExecutionResult`
  carry `parse_warnings`, and `EvidenceEngine` folds them into `EvidenceSet.parse_issues`,
  which reaches the assessment report. A parse problem is not an execution failure: the
  tool ran and exited 0, so the action is not marked failed and not retried.
- **airodump-ng screen output was parsed by a loop that discarded its own result**
  (`1979737`). `parse_airodump_text` matched a BSSID regex on every line into a local
  variable and then `pass`, returning two empty lists unconditionally. It was the live
  fallback, not dead code: with no `--write` CSV found, an assessment that failed to read a
  busy capture recorded "no access points observed". Screen output is now parsed for real
  using the column offsets in the header the tool printed, which is what makes it survive
  the layout differences between versions (`PWR RXQ` versus `PWR`). Two fields are
  deliberately *not* extracted, because a wrong value becomes fabricated evidence: client
  probe requests and associations, where `Rate` prints as `0e- 1` and the probe text does
  not start under its header, so slicing returned `stNetwork` for `TestNetwork`. The CSV
  parser's three bare `except Exception: continue` blocks now report too.
- **Failed permission restrictions were invisible** (`475b176`). `tighten_file_mode` caught
  `OSError` and returned nothing, so a capture left world-readable had no signal anywhere -
  silently undoing the reason the file was created owner-only. It now returns whether the
  file is actually restricted, verified by reading the resulting mode rather than trusting
  that `chmod` succeeded. `ensure_private_dir` was also inconsistent: tightening an existing
  directory raised a bare `PermissionError`, while the same failure on a newly created one
  was swallowed - and every fresh assessment takes the second path. Both now go through
  `require_private`, which verifies the outcome and raises with the path and actual mode.
- **Files the framework adopts were never restricted** (`475b176`). `ArtifactStore.register_file`
  recorded a file the tool wrote itself - an airodump-ng pcap, a kismet log - at whatever
  mode the tool's umask produced, typically 0644. A pcap holds whole conversations rather
  than a summary of them, so restricting only framework-written files left the most
  sensitive artifacts of all world-readable. Adoption is now best effort and recorded
  rather than fatal: the file may belong to another uid if the tool ran elevated, and an
  artifact worth keeping is worth keeping with a warning attached.
- **An authorization entry that failed to parse vanished** (`ccf7329`). An invalid BSSID or
  network CIDR was dropped in `AssessmentScope.__post_init__` with a comment saying
  validation would catch it - but `validate()` is called from one place, the CLI. A scope
  built programmatically, which is how the engine and every script build one, never reported
  anything. The direction is fail-safe, since a dropped entry narrows what is authorized,
  but the result is an operator who believes `192.168.1.0/24` is authorized, watches every
  action against it get refused, and sees a reason that looks like a scope violation rather
  than a typo. Dropped entries are recorded on the scope and carried in `to_dict()`, which
  is what `log_scope` writes.
- **`AssessmentScope.validate()` raised on the input it exists to report** (`ccf7329`). The
  channel check was `1 <= ch <= 196`, so a channel declared as a string raised `TypeError` -
  a crash in the one function whose job is to say "this scope is malformed". It now coerces
  through a helper that reports instead of raising, and refuses a value that does not
  survive the round trip: `int(6.5)` is 6, a valid channel, so a naive coercion would have
  rounded a malformed declaration into an authorized one.
- **A `--config` scope file never reached the authorization checks** - the most
  consequential defect in this release, and the reason the CLI now has tests.
  `load_scope_from_args` constructed the `AssessmentScope` from command-line arguments and
  then extended its lists from the YAML config. But `AssessmentScope` compiles its matchers in
  `__post_init__` - the SSID patterns, the normalized BSSID set, the parsed networks - so
  config entries landed in the public lists and never in the matchers the checks actually
  read. The documented config path therefore refused invasive actions against assets the
  operator had *explicitly authorized* ("SSID=MyNetwork not in authorized scope", while that
  is exactly what the config said), and refused every network action against authorized
  networks. Passive discovery still worked, because an empty scope permits it, so the failure
  only appeared once an assessment tried to act on something - which is why it survived
  reading, review and 772 tests. Every source is now merged before the scope is constructed.

  Two related defects went with it. `list.extend` on a string iterates its characters, so a
  config written as `authorized_ssids: MyNetwork` instead of a one-item list would have
  authorized the individual characters `M`, `y`, `N` ... - a scope matching nothing real while
  looking like it had parsed; a config value that is not a list is now refused with a message
  naming the key. And an unrecognized config key is reported rather than ignored, because a
  typo like `authorized_ssid` silently narrows the authorization the operator believes they
  granted. The same construction-order fix also restored `validate()`'s visibility: rewritten
  earlier in this pass to report entries dropped *at construction*, it had become blind to
  anything added afterwards.
- **Three parsers decided for themselves what a MAC address is** - the ninth defect, found
  by writing tests for the eighth. `utils/validation.normalize_mac` is the framework's one
  answer to that question, and it earned the role the hard way: an earlier version stripped
  non-hex characters, so `AABBCCDDEEFFGG` became `AA:BB:CC:DD:EE:FF` - a *different* address -
  and an operator's scope allowlist quietly authorized a network nobody had named.

  `parse_wash` took the 17 hex-or-colon characters its row pattern captured as an address
  unchanged, so `:::::::::::::::::` and `AABBCCDDEEFF00112` were recorded as BSSIDs; its
  fallback branch used an unanchored `re.match`, so `AA:BB:CC:DD:EE:FFGG` was recorded with
  the trailing garbage attached. A BSSID decides what may be attacked, and an identifier the
  scope rule rejects can never match an authorized entry - so those rows became access points
  in the world model that no authorization could ever cover, and they said so nowhere. The
  same fallback was colon-only, so the dash form, which the canonical rule *accepts*, was
  dropped without a word: an AP wash really did report, missing from the results. Both
  branches now normalize, and what they refuse is reported through `parse_warnings` - the
  channel the nmap and tshark adapters already had, and which wash was the only parser left
  out of. Banner text and stderr are still not reported, so the list stays readable.

  `parsers/base.py` kept its own regexes. They accepted mixed separators
  (`AA:BB-CC:DD-EE:FF`), extracted `00:11:22:33:44:55` from an eight-group run that is not an
  address, and returned both `1.2.3.4` and `5.6.7.8` from `1.2.3.4.5.6.7.8` plus
  `999.999.999.999`, because `\d{1,3}` has the right shape and the wrong range. Nothing in
  production calls these helpers, so this was a trap rather than an active defect - but they
  are the obvious place to reach for when a tool's output format is unknown, which is exactly
  when a hand-rolled regex diverges from the rule the rest of the framework uses. They now
  locate candidates and let `normalize_mac` and `validate_ip` decide.
- **A malformed channel or signal was dropped with no trace in the world model**
  (carried forward as a known limitation from 0.5.1). `AccessPoint.update_from_evidence`
  and `WirelessClient.update_from_evidence` each caught `(ValueError, TypeError)` and
  `pass`ed, so the entity kept its previous value and nothing recorded that the newest
  observation was unreadable. A field that was never observed and a field whose latest
  observation failed were indistinguishable in `WorldModel.to_dict()` - which is what the
  audit trail and the assessment report are built from. Both now record the field, the
  offending value and the value kept, on a new `parse_errors` list that is carried into the
  dump. Entries are deduplicated, because a world model is long-lived and an access point
  seen on every sweep of a long capture would otherwise accumulate one identical entry per
  sweep. Coercion also stopped truncating: `int(6.5)` is 6, so a fractional channel was
  silently rounded into a channel the access point is not on.
- **A mixed IPv4/IPv6 authorized scope crashed the network scope check** (found by mypy).
  `IPv4Network.subnet_of(IPv6Network)` raises `TypeError` rather than returning False, and
  the comparison sat outside the surrounding `try`. With both families authorized, an
  in-scope IPv6 address raised instead of returning True and an out-of-scope IPv4 address
  raised instead of being refused - and whether it raised depended on the order the entries
  were declared, because an entry that matched first returned before the mismatched one was
  reached. `in` handles a version mismatch safely, which is why `is_ip_authorized` never had
  this bug; a test pins that distinction so a future change from one to the other cannot
  reintroduce it.

#### A validator that validated nothing

- **`ToolAdapterBase.validate_parameters` enforced nothing** (`f1f3981`). It computed the
  capability's required inputs into a local variable, discarded it, and returned
  `custom_parameter_validation` - whose default accepts everything and whose docstring
  claimed it checked metadata inputs. An adapter invoked without an input it cannot work
  with went on to build a command line missing that argument, and the tool's own complaint
  arrived as a runtime failure instead of a refusal naming the missing input.

  Two things had to be settled before enforcing was safe. `interface` reaches `execute()` as
  its own argument rather than as a key in `parameters`, so checking `parameters` alone
  would have refused every normal invocation of the 30 capabilities that declare an
  interface - which is plausibly why the variable was left unused rather than wired up. And
  enforcement is only sound if metadata and implementation agree on names, so the AST of all
  58 adapters was walked, comparing declared non-optional inputs against the parameter keys
  their own `build_command` reads: zero mismatches.

  This is not redundant with the adapters' own hooks. For `aireplay-ng`, `airmon-ng` and
  `rfkill` the base check is the *only* thing that catches a missing required `action`. Both
  layers report rather than one short-circuiting, so an operator sees every problem with an
  invocation at once.

#### Other defects found by reading the discarded values

- `AuditLogger.save_report` wrapped the report write in `try: ... except OSError as e:
  raise` - a handler that re-raises unchanged, binding a name nothing reads (`f1f3981`).
- `VerificationEngine.request_for_finding` built the sorted set of tools behind a finding and
  never used it. Nothing in `VerificationRequest` takes a tool list;
  `min_independent_sources` is a count the verifier computes from the evidence it gathers
  itself. Removed rather than inventing a field to justify it (`f1f3981`).
- `cmd_list_capabilities` constructed an `InterfaceManager` and never used it (`f1f3981`).
- `test_scope_enforcer_strict` built a strict-mode enforcer and asserted nothing about it, so
  the test named for strict mode only ever exercised `allow_broadcast_discovery`. It now
  asserts what strict mode alone does and does not do: passive observation of an unauthorized
  SSID is still permitted, acting on it is not (`f1f3981`).
- `utils/validation.validate_parameters` annotated its `validators` argument as
  `Dict[str, callable]`, using the builtin function as a type (`f1f3981`).

### Added

- **`ExecutionResult.parse_warnings`**, separate from `warnings`. Parse problems rode the
  general warning list first, but the Evidence Engine now folds that list into
  `EvidenceSet.parse_issues` - so any general advisory, including the new permission
  warnings, would have been reported as an extraction problem. A test asserts a general
  warning does not become a parse issue (`475b176`).
- **`utils.system.require_private(path, mode)`**, raising `RuntimeError` with the path and
  the actual mode when a directory stays group- or other-accessible. Verifies the outcome
  rather than the syscall, so a filesystem that ignores `chmod` is not an error when the
  mode is already correct (`475b176`).
- **Permission failures surface in three places rather than one**, because a list nobody
  reads is the same as no list: `ArtifactStore.permission_failures`,
  `permission_failure_count` in the store's stats (printed in the assessment summary), and a
  warning on `ExecutionResult` naming the file, which reaches the audit trail (`475b176`).
- **`AssessmentScope.invalid_bssids` / `invalid_networks`**, recorded at construction and
  carried in `to_dict()`, so the audit trail shows what was requested *and* what was
  unusable without depending on a caller remembering to call `validate()` (`ccf7329`).
- **19 CLI tests** (`tests/test_cli.py`), the first for `cli/main.py`, taking it from 0% to
  55% statement coverage (178 statements, none covered, before the fix; 184 after). They pin the parser/loader
  coupling - every attribute `load_scope_from_args` reads must exist on the parser's
  namespace, which nothing else connects, since `--network` and `--host` are stored under
  different dests than the loader's names - the config path, the string-instead-of-list
  refusal, and `main()`'s dispatch, including that running with no scope warns the operator
  rather than silently taking the widest reading.
- **Coverage gated at its measured baseline** (`--cov-fail-under=68` in the CI coverage
  step). The total is 69.13% with scapy, which this job installs, and 68.78% without. The
  threshold is 68 rather than 69 because of a disagreement inside pytest-cov, recorded in the
  workflow comment: the exit code compares `round(total, precision=0)` against the threshold
  while the terminal message compares the raw total. A threshold sitting between the two
  environments' totals therefore prints a red "FAIL Required test coverage of 69% not reached.
  Total coverage: 68.78%" *and* exits 0 in the lower one - a gate that reports failure while
  passing, which is worse than no gate, because it teaches an operator to distrust red text in
  the one place designed to produce it. 68 is the highest threshold at which both comparisons
  agree in both environments, so the effective floor is 67.5%: enough to catch a module losing
  its tests (`cli/main.py` alone is 184 statements, ~2%), not enough to catch a handful.
  Measured rather than inferred, in all four combinations - with scapy 68 green and 69 green,
  without scapy 68 green and 69 red - and re-measured when the parser tests moved the total,
  because a threshold chosen against one baseline can drift out of agreement with the next.
- **46 parser-identity tests** (`tests/test_parser_identity.py`), taking `parsers/base.py`
  from 0% to 100% and `parsers/wash.py` to 94%. The invariant they assert is that every
  address a parser emits is a *fixed point* of `normalize_mac` - re-normalizing it changes
  nothing, because it is already in the one canonical form - which is what makes a parsed
  address and an authorized address meet. One test carries that end to end: a dash-form row
  wash reports, parsed, matched against a scope entry the operator wrote, invasive action
  allowed.
- **`wash` joined the `parse_warnings` channel** (`parse_wash` and `wash_to_evidences` take an
  optional `issues` list; the adapter forwards it), following the nmap and tshark convention.
  Reports distinguish "not a MAC address" from "a MAC address only in bare form, which this
  line does not establish", because those send an operator looking in different directions -
  one at a corrupt capture, one at a tool emitting a format the parser did not expect.
- **`cli.main.SCOPE_CONFIG_KEYS`**, the recognized `--config` keys, so an unrecognized one
  can be reported.
- **`utils.validation.integral_int(value)`** - a whole number or `None`, refusing rather
  than truncating. Used by both `AssessmentScope._channel_number` and the world model
  entities, so a channel *declared* in an authorization scope and a channel *observed* into
  the world model cannot disagree about what counts as a whole number. `nan` and `inf` are
  refused without a special case, via `float.is_integer`.
- **`AccessPoint.parse_errors` / `WirelessClient.parse_errors`**, carried into `to_dict()`.
- **A lint and type gate** (`quality-gate` CI job). `ruff check src tests scripts` is
  blocking on everything the project selects except the two categories recorded as deferred
  debt in `pyproject.toml`, each with the count measured when the gate was introduced.
  `scripts/check_type_baseline.py` gates mypy against *growth* rather than against zero: the
  34 remaining findings are recorded in `.mypy-baseline`, so a new one fails the build and
  the file is lowered when an old one is fixed. A gate that fails on day one is a gate
  nobody runs.

### Changed

- **The project's own lint configuration is enforced for the first time.** `pyproject.toml`
  selected E, F, W and C90 at line-length 100, but nothing ran it, so 722 findings had
  accumulated. All the correctness classes are now clear: 71 unused imports, 13 computed-and-
  discarded locals, 9 f-strings with no placeholders, 4 ambiguous `l` loop variables
  (indistinguishable from `1` in a terminal), 6 imports stranded mid-file, and a dead
  `csv_path` assignment duplicating the first entry of the `possible_paths` list below it.
- **mypy findings reduced from 194 to 33**, by fixing rather than suppressing: implicit-
  Optional parameters made explicit (`interface: str = None` is an annotation that lies,
  across 40 sites), and the heterogeneous dicts annotated. The second change cascaded -
  annotating `parsed: Dict[str, Any]` removed 21 `union-attr` findings at once, because
  mypy had been inferring a union for every value read back out of a dict literal holding
  mixed types. That reduction is what exposed the IPv6 scope defect above.
- `E501` (574 lines over 100 characters) and `C901` (45 functions over the McCabe budget)
  are deferred with the reason and the measured count recorded in `pyproject.toml`, not
  silently ignored. Reflowing 574 lines by hand risks mangling docstrings, and reformatting
  the whole tree would produce a diff larger than the code it describes. Satisfying C901
  means refactoring 45 functions, and a behaviour-preserving refactor of that size is exactly
  where regressions hide; each needs its own change with its own tests.

- **`parse_wash`'s two `except ValueError` handlers around `int(channel)` and `int(dbm)` are
  unreachable**: the row pattern already constrains both groups to digits, so `int()` cannot
  fail. Left in place deliberately - they are insurance if that pattern is ever loosened, and
  no test can distinguish them from their absence, which is what makes them unfixable debt
  rather than a defect. Recorded here so the 4 uncovered lines in `parsers/wash.py` are not
  mistaken for a gap someone forgot to fill.

### Tests

- 837 passing with scapy installed, 783 plus 3 skipped without. Up from 650 at 0.5.1.
  Total statement coverage 69.13% with scapy (9440 statements, 2914 missed) and 68.78%
  without (2947 missed). Both modules that had no coverage at the start of the pass now have
  tests: `cli/main.py` at 55% and `parsers/base.py` at 100%.
  CI green on all five jobs: unit tests on py3.10/3.11/3.12, the new lint and type gate, and
  the mac80211_hwsim wireless job (12/12 capture and injection checks against real radios).
- `scripts/exercise_framework.py` reports 61/69 with 11 skipped, unchanged - the 8 failures
  and 11 skips are the sandbox having no wireless hardware and none of the 52 declared tools
  installed, each recorded with the reason rather than counted as a pass.
- New tests: 16 for parse-problem reporting, 17 for storage permissions, 18 for malformed
  scope entries and `validate()`, 26 for the channel scope-gate coupling, 18 for airodump
  screen output and CSV failures, 14 for declared-input enforcement, 6 for mixed-family
  scope, 11 for unreadable world-model values, 27 for `integral_int`, 19 for the CLI, 46 for
  parser identity. Each batch mutation-checked - restoring the three silent `except: pass`
  handlers fails 9 tests, restoring the construct-then-mutate scope loading fails 4 including
  the config regression test, and the parser batch was checked by reverting each of its four
  parts separately: the unvalidated row field fails 4 tests, the unanchored fallback 10, the
  old `base.py` regexes 14, and removing the adapter's `parse_warnings` wiring 1.
- The channel scope gate skips a channel it cannot coerce to `int()`, with a comment saying
  parameter validation reports it. That is correct today - both sides do the identical
  conversion catching the identical exceptions - but nothing pinned it, and if parameter
  validation ever accepted a value `int()` rejects, an out-of-scope channel would pass both
  checks. 26 tests now pin both halves, measured through the real policy rather than
  inferred. Breaking the coupling fails 12 of them, including an end-to-end scope case.

## [Unreleased]

### Planned
- Additional adapters: airdriver-ng, ivstools (can be added similarly), Wireshark GUI (not suitable for automation but could add adapter for --help)
- More detailed parsers for horst, wavemon, kismet logs, hcxdumptool status counters
- Web UI for assessment visualization
- AI-based decision system as optional planner
- Field verification on physical adapters, including the injection probe (`aireplay-ng --test`) and
  chipset-specific monitor-mode behaviour. hwsim verification landed in 0.4.1; it covers the software
  path up to the driver boundary and cannot substitute for real RF.
- Performance benchmarks for large-scale assessments
- Decide whether an undeclared network scope should permit passive discovery of arbitrary hosts
  (see Known limitations above)
