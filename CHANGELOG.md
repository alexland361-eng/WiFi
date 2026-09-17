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
