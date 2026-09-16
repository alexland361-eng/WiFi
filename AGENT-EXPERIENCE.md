# Agent Experience Log

This document tracks experiences, challenges, and learning moments encountered during development of the WiFi Framework.

## Session: 2026-09-16 - Initial Production Implementation

### Context
- Repository was empty (only README with "# WiFi" and initial commit)
- Task: Build real Wi-Fi penetration-testing and security-assessment framework from documentation
- Requirements: production-ready, no placeholders, real tool execution, adaptive, evidence-driven, auditable

### Challenges Encountered

#### 1. Empty Repository - Greenfield Architecture
**Challenge**: No existing code, architecture, or tests to build upon. Need to design entire framework from operational philosophy documentation.

**Approach**:
- Conducted structured research on Kali Linux wireless toolchain
- Identified core concepts: Evidence, Capability, World Model, Adaptive Loop, Scope Enforcement
- Designed folder structure with clear module boundaries before coding
- Started with core models (evidence, finding, capability, world_model, scope, assessment_state) as foundation
- Built execution layer (adapter_base, capability_checker, registry, executor) next
- Then parsers, then adapters, then planning, then engine, then CLI

**Learning**: Greenfield allows clean architecture but requires disciplated planning. Creating pyproject.toml and folder structure first provided scaffolding.

#### 2. Real Tool Execution vs Simulation
**Challenge**: Requirement says "Every operational capability must correspond to functioning implementation" and "must never represent simulated output as genuine". Need to ensure real subprocess execution, not fake.

**Solution**:
- Implemented ToolAdapterBase with real `subprocess.run` via `utils.system.run_command`
- Timeout handling (return 124 for timeout), exit code handling
- No shell=True, only list args for security
- Parsers convert real output to structured evidence, never fabricate
- If capability unavailable (tool not in PATH, no root, no interface), explicitly report as unavailable with reason
- Failure interpretation based on exit codes and output keywords

**Verification**: Tested with tools that exist in environment (e.g., `iw` may not exist in sandbox, but adapter correctly reports unavailable)

#### 3. Capability-Aware Execution
**Challenge**: Need to verify interface, OS, driver, privileges, tool version before action.

**Solution**:
- Created CapabilityChecker checking OS compatibility, tool availability via `shutil.which`, version parsing, privilege via `os.geteuid`, interface existence via `/sys/class/net`, dependencies
- Adapter's `check_requirements` method does full verification
- Executor calls check before building command
- Unavailable capabilities preserved in assessment state with reason

**Learning**: Version parsing is tricky - different tools use different version flags (--version, -v, -V, version). Implemented fallback trying multiple flags.

#### 4. Adaptive Assessment Loop
**Challenge**: Avoid conventional `Tool A → Tool B → Tool C` pipeline. Need `Observe → Model → Identify uncertainty → Select action → Parameterize → Execute → Parse → Verify → Update → Re-evaluate`

**Solution**:
- WorldModel continuously updated from evidences
- UncertaintyIdentifier analyzes state to find gaps: no interfaces, no APs, incomplete AP info, hidden SSIDs, WPS unknown, no clients, no hosts, no handshakes, unverified findings
- Each uncertainty has priority and required capabilities
- ActionSelector scores capabilities based on: direct match to uncertainty, useful outputs, invasiveness, recent execution penalty, experience scores, scope, duration
- Planner suggests phase transitions based on state
- Engine loop runs until no uncertainties or max iterations or completion

**Learning**: Scoring heuristic needs balance. Early phases should prefer non-invasive, quick tools. Experience store provides learning but shouldn't dominate deterministic execution.

#### 5. Evidence and Verification
**Challenge**: Raw output not authoritative finding. Need to distinguish observations, hypotheses, supported, verified, refuted.

**Solution**:
- Evidence model with id, timestamp, source (tool, capability, interface, raw_command), parameters, raw_output, parsed_data, confidence, tags, execution_id
- Finding model with status lifecycle: hypothesis → supported (2+ evidences) → verified (independent verification) → refuted
- WorldModel updates from evidence, not directly from raw output
- Findings generated from world model, not directly from tool output
- Verification via multi-tool correlation: if AP observed by 2+ different tools, mark as verified
- Audit logger preserves full chain: finding → evidence_ids → raw_command → timestamp

**Learning**: Confidence levels important. Direct tool observations get HIGH, parsed generic get LOW, multi-tool verified gets VERIFIED (0.95).

#### 6. Scope and Authorization Enforcement
**Challenge**: Prevent decision engine from silently expanding scope. Distinguish inside vs outside authorized scope.

**Solution**:
- AssessmentScope with authorized SSIDs (regex support), BSSIDs (normalized), channels, networks (CIDR), hosts
- ScopeEnforcer checks wireless actions (SSID/BSSID) and network actions (IP) against scope, considering invasiveness
- Passive observation allowed with broadcast discovery, invasive requires authorization
- Filter evidence by scope tagging in_scope/out_of_scope
- Strict mode option to restrict even passive
- CLI requires explicit scope for active testing, warns if none provided

**Learning**: SSID regex support useful for patterns like "Corp.*". BSSID normalization to upper colon format avoids case/separator issues. IP validation via ipaddress module handles CIDR.

#### 7. Tool Adapter Completeness
**Challenge**: Need to implement 30+ tools across categories without placeholders.

**Approach**:
- Implemented fully functional adapters for core tools: iw, iwconfig, airmon-ng, rfkill, ethtool, airodump-ng (with CSV temp file handling), wash, tshark, tcpdump, dumpcap, reaver, bully, pixiewps, hcxdumptool, hcxpcapngtool, hashcat, john, nmap (with 3 output format parsers), arp-scan, netdiscover, fping, dig, curl, openssl, smbclient, macchanger, bettercap, scapy
- Each adapter: build_command (list args), parse_output (structured evidences), custom_parameter_validation, custom_requirement_check
- Metadata with requirements, inputs, outputs, operational properties, failure conditions
- Parsers for iw, airodump, wash, tshark, nmap implemented with real parsing logic, not stubs
- For tools not fully implemented (e.g., Greenbone, Nuclei, Nikto, Metasploit), not registered yet - so they won't appear as available, avoiding false claims

**Learning**: airodump-ng is complex - runs indefinitely, needs output file parsing, cleanup. Implemented temp file prefix with write-interval 1, then search for CSV files, parse, cleanup. Scapy is special - can be used as library directly, so adapter overrides execute to try import scapy and exec script in controlled context, fallback to subprocess.

#### 8. Dependency Discipline
**Challenge**: Avoid unnecessary dependencies.

**Solution**:
- Only required dependency: pyyaml for config
- Optional: scapy for protocol analysis
- Dev: pytest, pytest-cov
- Used only stdlib otherwise: subprocess, os, re, json, csv, ipaddress, etc.
- Considered but rejected: requests (use curl adapter instead), netifaces (use /sys/class/net), etc.

**Learning**: Minimal dependencies improves maintainability and security.

#### 9. Auditability and Experience
**Challenge**: Every meaningful action should be reconstructable, with report explaining what, which observation, which operation, when, how verified.

**Solution**:
- AuditLogger logs every event to JSONL file and in-memory list
- Events: scope_defined, capability_discovery, action_selected, execution, evidence, finding, phase_transition, verification, scope_blocked
- Report generation includes execution_history, evidences with raw_command, findings, world_model, phase_transitions, finding_traces showing evidence chain
- ExperienceStore persists to JSONL, tracks info_gain (evidence count if success), cost (duration + failure penalty), provides stats and scores for planner

**Learning**: JSONL append-only is robust for long assessments. Truncating raw_output in ExecutionRecord (10k) and error_output (5k) avoids huge files but full raw kept in Evidence.

#### 10. Testing and Verification Honesty
**Challenge**: Need to verify implementation without real wireless hardware in sandbox.

**Approach**:
- Created unit tests for models, parsers, scope, etc. that don't require hardware
- For adapter tests, mock subprocess or check availability logic
- In sandbox, many tools not available - registry correctly reports unavailable with reason, which is expected behavior
- CLI discover-only mode works without hardware (lists system interfaces via /sys/class/net)
- Documented what was verified and what requires real hardware

**Learning**: Framework is designed to be testable even without AI model or hardware - deterministic execution and evidence layers remain functional independently.

### Technical Decisions

#### Tech Stack
- **Python 3.10+**: Chosen for rich stdlib, type hints, dataclasses, cross-platform, Kali default
- **pyyaml**: Only required external dep, for config
- **No heavy frameworks**: Avoided asyncio complexity for now, synchronous execution with timeout is simpler and auditable
- **Subprocess with list args**: Security-first, no shell injection

#### Architecture Decisions
- **Dataclasses for models**: Clear, type-hinted, serializable via to_dict()
- **Abstract base for adapters**: Enforces real implementation, no placeholders
- **Registry with auto-discovery**: pkgutil.walk_packages for auto-loading, but also explicit loader for reliability
- **World Model as dicts**: BSSID→AP, MAC→Client, IP→Host for O(1) lookup, update from evidence
- **Evidence as immutable-ish**: Frozen source, but mutable tags, validation in __post_init__

#### Coding Standards
- Type hints throughout
- Docstrings explaining operational philosophy
- No placeholder code
- Security-first: input validation, no shell=True, privilege checks
- Failure awareness: timeout, invalid input, unavailable resources, partial failures considered

### Remaining Limitations

- **Hardware dependent**: Full assessment requires wireless adapter with monitor mode, root, Kali tools installed
- **Parser coverage**: Some tools (horst, wavemon, kismet logs) have basic parsers, could be enhanced with more detailed field extraction
- **Verification**: Multi-tool correlation is simple, could add more sophisticated verification (e.g., re-scan with different channel, signal strength correlation)
- **AI planner**: Optional AI-based decision system not yet implemented - deterministic heuristic planner is functional but could be enhanced with ML
- **Vulnerability phase**: Greenbone, Nuclei, Nikto adapters not yet implemented - would be needed for full vuln assessment
- **Framework phase**: Metasploit, Impacket, Responder adapters not yet implemented
- **Performance**: Synchronous execution, could benefit from async for long-running captures (but auditability favors synchronous)

### Success Metrics

- [x] 30+ tool adapters with real execution, not placeholders
- [x] Evidence model with confidence, source, timestamps
- [x] World Model maintaining APs, clients, hosts
- [x] Adaptive loop with uncertainty identification and action selection
- [x] Capability-aware execution with requirement checking
- [x] Scope enforcement preventing silent expansion
- [x] Audit logging with full traceability
- [x] Experience store with info gain and cost
- [x] CLI with scope definition, discover-only, list capabilities
- [x] Production-ready code with validation, security, error handling
- [x] Documentation: README, CHANGELOG, AGENT-EXPERIENCE
- [x] Project structure with clear boundaries
- [x] No fabricated output, explicit unavailable reporting

### Next Steps

1. Add integration tests with mocked tool outputs
2. Implement remaining vuln and framework adapters
3. Enhance parsers for more detailed field extraction
4. Add web UI for visualization
5. Implement optional AI planner interface
6. Performance benchmarks
7. Real hardware testing on Kali

### Reflection

This project demonstrates that a real Wi-Fi assessment framework is more than command wrappers - it's about maintaining world model, identifying uncertainties, selecting actions based on evidence and scope, verifying findings, and preserving auditability. The adaptive loop is key: two assessments don't necessarily execute same tools in same order. The framework's value is in obtaining sufficient, reliable evidence to answer assessment questions while maintaining clear relationship between every action and authorized objective.

The senior developer guidelines (no placeholders, thorough research, documentation, security-first, minimal dependencies, verification honesty) were crucial for production-ready result.
