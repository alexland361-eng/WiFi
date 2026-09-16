# Implementation Plan - WiFi Framework

## Scope and Requirements

### Primary Objective
Build a real Wi-Fi penetration-testing and security-assessment framework that performs genuine assessments against authorized wireless environments, with adaptive, evidence-driven orchestration rather than fixed command sequences.

### Functional Requirements
- **FR1**: Real tool execution - every capability must invoke real underlying utility and parse actual output, no simulation
- **FR2**: Adaptive assessment - state-driven loop: Observe→Model→Identify uncertainty→Select action→Parameterize→Execute→Parse→Verify→Update→Re-evaluate
- **FR3**: Evidence model - structured evidence with identifiers, timestamps, sources, parameters, confidence
- **FR4**: Verification - distinguish observations, hypotheses, supported, verified, refuted findings
- **FR5**: Capability-aware execution - verify interface, OS, driver, privileges, tool version before execution
- **FR6**: Scope enforcement - preserve authorized scope, prevent silent expansion, distinguish in-scope vs out-of-scope
- **FR7**: Auditability - reconstructable execution history, report explaining what, which observation, which operation, when, how verified
- **FR8**: Experience and learning - track actions, state, params, results, info gain, cost, verification for heuristic improvement
- **FR9**: Kali toolchain support - 30+ tools across interface, discovery, capture, WPS, WPA, network, enumeration, protocol categories
- **FR10**: CLI - authorized assessment with SSID/BSSID/channel/network/host scope, discover-only, list capabilities

### Non-Functional Requirements
- **NFR1**: Production-ready, no placeholders, complete, tested, purposeful code
- **NFR2**: Security-first - no shell=True, input validation, privilege checks, least privilege
- **NFR3**: Minimal dependencies - only pyyaml required, optional scapy
- **NFR4**: Maintainability - clean module boundaries, clear interfaces, documentation
- **NFR5**: Testability - deterministic execution and evidence layers functional without AI/hardware
- **NFR6**: Compatibility - Linux (Kali), Python 3.10+

### Acceptance Criteria
- [x] All tool adapters with real execution path, not placeholders
- [x] Evidence model with confidence, source, timestamp
- [x] World model maintaining APs, clients, hosts
- [x] Adaptive loop with uncertainty identification and action selection
- [x] Capability-aware execution with requirement checking
- [x] Scope enforcement preventing silent expansion
- [x] Audit logging with full traceability
- [x] Experience store with info gain and cost
- [x] CLI with scope definition, discover-only, list capabilities
- [x] 24 unit tests passing
- [x] Documentation: README, CHANGELOG, AGENT-EXPERIENCE, ARCHITECTURE, TOOL_MODEL, OPERATIONAL_PHILOSOPHY
- [x] No fabricated output, explicit unavailable reporting

## Architecture Overview

### High-Level Architecture
```
Raw Tool → Adapter → Capability → Parser → Evidence → World Model → Planner → Executor → Audit/Experience
```

### Module Breakdown
- **core/models**: Evidence, Finding, Capability, WorldModel, AssessmentState, Scope
- **core/execution**: Registry, AdapterBase, Checker, Executor
- **core/planning**: UncertaintyIdentifier, ActionSelector, Planner
- **core/audit**: AuditLogger
- **core/experience**: ExperienceStore
- **core/engine**: AssessmentEngine (main loop)
- **tools/adapters**: 30+ real adapters
- **parsers**: Structured parsers
- **utils**: System, validation
- **cli**: CLI

### Data Flow
1. CLI parses scope → AssessmentScope
2. Engine discovers interfaces via iw, iwconfig → InterfaceInfo → AssessmentState.interfaces
3. Engine discovers capabilities via registry checker → available/unavailable
4. Loop:
   - UncertaintyIdentifier identifies gaps from world_model, evidences, findings
   - ActionSelector scores available capabilities for each uncertainty
   - Planner selects best action
   - ScopeEnforcer checks if action allowed (invasive requires authorization)
   - Executor generates params from state, validates, checks requirements, builds command, executes real tool, parses output to evidences, updates state, logs execution, adds to experience
   - WorldModel updates from evidences
   - Findings generated from world_model
   - Periodic verification via multi-tool correlation
   - Phase transition suggestion
5. AuditLogger generates report with finding traces

## Tech Stack Decisions

| Decision | Choice | Justification |
|----------|--------|---------------|
| Language | Python 3.10+ | Rich stdlib, type hints, dataclasses, Kali default, Scapy support |
| Dependency | pyyaml only | Minimal, for config, reduces attack surface, maintenance |
| Optional | scapy | For protocol analysis, but not required for core |
| Execution | subprocess.run list args | Security - no shell injection, timeout handling |
| Models | dataclasses | Clear, type-hinted, serializable, no heavy ORM |
| Registry | pkgutil auto-discovery + explicit loader | Reliability, testability |
| Testing | pytest | Standard, simple |
| CLI | argparse | Stdlib, no extra dep, sufficient |
| Persistence | JSONL for audit/experience | Append-only, robust, human-readable |

**Rejected alternatives**:
- asyncio: Complexity for auditability, synchronous with timeout simpler
- requests: Use curl adapter instead, keep deps minimal
- netifaces: Use /sys/class/net, avoid extra dep
- Click/Typer: argparse sufficient, avoid extra dep
- SQLAlchemy: Dataclasses + dict sufficient, avoid complexity

## Coding Standards and Quality Gates

### Standards
- **Production-ready only**: No placeholders, no TODO, complete implementations
- **Type hints**: Throughout, for IDE and maintainability
- **Docstrings**: Explaining operational philosophy and purpose
- **Security-first**: No shell=True, input validation, privilege checks, sanitization
- **Failure awareness**: Timeout, invalid input, unavailable resources, partial failures considered
- **Minimal justified changes**: Simplest implementation satisfying requirements, no unnecessary abstractions
- **Preserve existing work**: Never overwrite unrelated user work
- **Verification honesty**: Report what verified, what not, limitations

### Quality Gates
- **Unit tests**: 24 tests covering models, parsers, scope, planner, adapters, executor - all passing
- **Integration**: CLI discover-only works without hardware, lists capabilities with availability
- **Security**: Checked for shell injection, input validation for MAC, IP, channel, interface
- **Documentation**: README, CHANGELOG, AGENT-EXPERIENCE, ARCHITECTURE, TOOL_MODEL, OPERATIONAL_PHILOSOPHY, IMPLEMENTATION_PLAN
- **Operational integrity**: Every capability has real execution path, no fabricated output

## Deliverables and Acceptance Criteria

### Deliverables
1. **Source code**: `src/wifi_framework/` with all modules, 30+ adapters, parsers, engine, CLI
2. **Config**: `config/default.yaml`
3. **Tests**: `tests/` with 24 tests
4. **Docs**: `README.md`, `CHANGELOG.md`, `AGENT-EXPERIENCE.md`, `docs/ARCHITECTURE.md`, `docs/TOOL_MODEL.md`, `docs/OPERATIONAL_PHILOSOPHY.md`, `docs/IMPLEMENTATION_PLAN.md`
5. **Project files**: `pyproject.toml`, `requirements.txt`, `LICENSE`
6. **CLI entry point**: `wifi-assess` command

### Acceptance Criteria
- `pip install -e .` succeeds
- `wifi-assess --list-capabilities` lists 30+ capabilities with availability
- `wifi-assess --discover-only` discovers interfaces and reports unavailable with reasons
- `pytest tests -v` 24 passed
- No placeholder code (grep for TODO, placeholder, fake, simulated)
- Every adapter has build_command returning list, parse_output returning List[Evidence], real subprocess execution
- Audit report generated with finding traces
- Scope enforcement blocks unauthorized invasive actions

## Risk and Mitigation Plan

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Wireless hardware not available in sandbox | Cannot test real wireless execution | High | Implement capability checker that reports unavailable with reason, not failure; unit tests mock; discover-only works without hardware; document hardware requirement |
| Tool not installed (e.g., airodump-ng) | Capability unavailable | High | Registry reports unavailable explicitly, preserves in state, planner avoids; CLI shows status; not counted as failure |
| Parser fails on unexpected output format | Evidence not created, assessment incomplete | Medium | Parsers have fallback (generic evidence), try multiple output formats (nmap has 3 parsers), error handling with try/except, never fabricate |
| Scope creep - adding unnecessary features | Complexity, maintenance burden | Medium | Strictly follow operational philosophy, record improvements as recommendations not implementations, minimal justified changes |
| Security - shell injection via params | Critical - RCE | Low | No shell=True, only list args, input validation for MAC, IP, channel, interface, sanitization defense in depth |
| Privilege escalation - requires root but not running as root | Execution fails | Medium | Check is_root before execution, report insufficient_privileges, failure_conditions includes it |
| Timeout - tool runs indefinitely (e.g., airodump-ng) | Hangs assessment | High | Executor has timeout param, run_command handles TimeoutExpired returning 124, failure_conditions includes timeout, cleanup temp files |
| Experience store corruption | Learning affected | Low | JSONL append-only, try/except on load, ignore malformed lines |
| Large output - memory exhaustion | OOM | Low | Truncate raw_output in ExecutionRecord (10k) and error_output (5k), but keep full in Evidence; limit packets parsed (e.g., first 100) |

## Changelog and Experience Tracking Workflow

### Changelog (CHANGELOG.md)
- Format: Keep a Changelog, Semantic Versioning
- Sections: Added, Changed, Fixed, Security, etc.
- Each version with date and detailed incremental changes
- Unreleased section for planned

### Experience Tracking (AGENT-EXPERIENCE.md)
- Each session with context, challenges, approach, learning
- Technical decisions with justification
- Remaining limitations
- Success metrics
- Reflection

### Workflow
1. Before coding: Inspect existing code, architecture, dependencies, tests (guideline 12)
2. During coding: Maintain CHANGELOG.md with incremental changes, AGENT-EXPERIENCE.md with challenges
3. After coding: Verify via pytest, CLI, manual checks; report what verified, what not (guideline 21); self-review for correctness, security, maintainability, complexity, regressions, compatibility, requirements (guideline 22)
4. Commit: Preserve existing work, minimal justified changes, no unnecessary overwrites (guidelines 13, 14, 19)

## Sample Folder Structure

```
.
├── README.md
├── CHANGELOG.md
├── AGENT-EXPERIENCE.md
├── LICENSE
├── pyproject.toml
├── requirements.txt
├── config/
│   └── default.yaml
├── src/
│   └── wifi_framework/
│       ├── __init__.py
│       ├── __main__.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── models/
│       │   │   ├── __init__.py
│       │   │   ├── evidence.py
│       │   │   ├── finding.py
│       │   │   ├── capability.py
│       │   │   ├── world_model.py
│       │   │   ├── assessment_state.py
│       │   │   └── scope.py
│       │   ├── execution/
│       │   │   ├── __init__.py
│       │   │   ├── adapter_base.py
│       │   │   ├── capability_checker.py
│       │   │   ├── registry.py
│       │   │   └── executor.py
│       │   ├── planning/
│       │   │   ├── __init__.py
│       │   │   ├── uncertainty.py
│       │   │   ├── action_selector.py
│       │   │   └── planner.py
│       │   ├── audit/
│       │   │   ├── __init__.py
│       │   │   └── logger.py
│       │   ├── experience/
│       │   │   ├── __init__.py
│       │   │   └── store.py
│       │   └── engine/
│       │       ├── __init__.py
│       │       └── assessment_engine.py
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── registry_loader.py
│       │   └── adapters/
│       │       ├── __init__.py
│       │       ├── interface/ (iw, iwconfig, airmon, rfkill, ethtool)
│       │       ├── discovery/ (airodump, wash, kismet, horst, wavemon)
│       │       ├── capture/ (tshark, tcpdump, dumpcap)
│       │       ├── wps/ (reaver, bully, pixiewps)
│       │       ├── wpa/ (hcxdumptool, hcxpcapngtool, hashcat, john)
│       │       ├── network/ (nmap, arp-scan, netdiscover, fping, dig)
│       │       ├── enumeration/ (curl, openssl, smbclient)
│       │       └── protocol/ (macchanger, bettercap, scapy)
│       ├── parsers/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── iw.py
│       │   ├── airodump.py
│       │   ├── wash.py
│       │   ├── tshark.py
│       │   └── nmap.py
│       ├── utils/
│       │   ├── __init__.py
│       │   ├── system.py
│       │   └── validation.py
│       └── cli/
│           ├── __init__.py
│           └── main.py
├── tests/
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_parsers.py
│   ├── test_scope.py
│   ├── test_planner.py
│   ├── test_adapters.py
│   └── test_executor.py
└── docs/
    ├── ARCHITECTURE.md
    ├── TOOL_MODEL.md
    ├── OPERATIONAL_PHILOSOPHY.md
    └── IMPLEMENTATION_PLAN.md
```

## Minimal End-to-End Starter Implementation Outline

### Step 1: Project Scaffolding (30 min)
```bash
mkdir -p src/wifi_framework/core/models src/wifi_framework/core/execution ...
touch src/wifi_framework/__init__.py ...
cat > pyproject.toml << 'EOF'
[project]
name = "wifi-framework"
...
EOF
```

### Step 2: Core Models (2 hours)
- Implement Evidence with from_tool_output factory, confidence validation, to_dict
- Finding with lifecycle methods (add_evidence, support, verify, refute)
- Capability metadata with requirements, inputs, outputs, operational properties
- WorldModel with AP, Client, Host, update from evidence
- AssessmentState with evidence, findings, execution history, phase transitions
- Scope with regex SSID, normalized BSSID, CIDR IP, validation, enforcer

### Step 3: Utils (30 min)
- system: get_os_info, is_root, check_tool_available (shutil.which + version flags), check_interface_exists (/sys/class/net), run_command (subprocess.run timeout)
- validation: MAC regex, normalize_mac, SSID, channel, interface, IP, CIDR, parameters, sanitization

### Step 4: Execution Layer (2 hours)
- ToolAdapterBase: abstract build_command, parse_output, check_requirements (OS, tool, version, interface, privileges, deps, custom), validate_parameters, execute (validate→check→build→run→parse→interpret failure), interpret_failure
- CapabilityChecker: check OS, tool, privileges, interface, deps
- CapabilityRegistry: register, get_metadata, get_adapter, check_availability, get_available/unavailable, auto_discover
- Executor: generate_parameters_from_state (interface from state, channel from authorized/observed, bssid from APs in scope, etc.), execute (generate→get adapter→adapter.execute→create ExecutionRecord→add to state)

### Step 5: Parsers (1.5 hours)
- iw: parse_iw_dev (phy, interface, addr, ssid, type, channel), parse_iw_list (monitor support)
- airodump: parse_airodump_csv (split sections by blank line, DictReader, AP and client, handle ESSID vs Probed ESSIDs substring bug)
- wash: regex for BSSID, channel, dBm, WPS version, locked, vendor, ESSID
- tshark: JSON and fields
- nmap: grepable (Host: ... Ports: ...), normal (Nmap scan report, PORT lines), XML (ET)

### Step 6: Tool Adapters (4 hours)
For each tool:
- Define METADATA with requirements, inputs, outputs, operational_properties, failure_conditions
- Implement Adapter class: build_command (list args), parse_output (structured evidences), custom_parameter_validation, custom_requirement_check
- Register via register(registry)

Start with core: iw_dev, iw_list, iwconfig, airmon-ng, rfkill, ethtool, airodump-ng (temp file handling), wash, tshark, nmap, etc.

### Step 7: Planning (1.5 hours)
- UncertaintyIdentifier: identify gaps (no interfaces, no APs, incomplete APs, hidden SSIDs, WPS unknown, no clients, no hosts, no handshakes, unverified findings) with priority and required capabilities
- ActionSelector: score_capability (availability, required list match +10, useful outputs +5, non-invasive +2, recent penalty -5, experience, scope, duration), select_action (best score), select_interface (monitor capable)
- Planner: plan_next_action (identify uncertainties→select interface→select action), should_continue (iteration limit, phase, no uncertainties), suggest_phase_transition (heuristic)

### Step 8: Audit and Experience (1 hour)
- AuditLogger: log_event (JSONL append), log_scope, capability_discovery, action_selection, execution, evidence, finding, phase_transition, verification, generate_report (with finding traces), save_report
- ExperienceStore: ExperienceRecord dataclass, add (info_gain=evidence_count if success else 0, cost=duration+10 if failure), get_capability_stats, get_experience_scores, persist JSONL, load with try/except

### Step 9: Engine (2 hours)
- AssessmentEngine: __init__ (registry, state, executor, planner, audit, experience, scope_enforcer, load experience scores), discover_interfaces (iw_dev, iwconfig, /sys/class/net), discover_capabilities, run_single_action (scope enforcement check→log action→executor.execute→log execution/evidences→add experience), verify_findings (multi-tool correlation), update_findings_from_world_model (AP→Finding, check weak encryption, WPS), run (loop: should_continue→plan→select interface→run_single_action→update_findings→periodic verification→phase transition, final verification, report)

### Step 10: CLI (1 hour)
- argparse with --ssid, --bssid, --channel, --network, --host (append), --interface, --max-iterations, --timeout, --discover-only, --list-capabilities, --list-interfaces, --scope-description, --strict, --output, --config, --verbose
- load_scope_from_args (from args and YAML config, validation)
- cmd_list_capabilities, cmd_discover_only, main (registry, scope, audit, experience, engine.run, handle KeyboardInterrupt with partial report)

### Step 11: Tests and Docs (1.5 hours)
- Tests: test_models (evidence, finding, scope, world_model), test_parsers (iw, airodump, wash, nmap), test_scope (enforcer), test_planner (uncertainty, scoring), test_adapters (registry loading, metadata, availability), test_executor (echo adapter)
- Docs: README (philosophy, architecture, toolchain, installation, usage, capability model, auditability, security), CHANGELOG, AGENT-EXPERIENCE, ARCHITECTURE, TOOL_MODEL, OPERATIONAL_PHILOSOPHY, IMPLEMENTATION_PLAN
- Verify: pytest, CLI --list-capabilities, --discover-only

### Total Estimated Time: ~15 hours

### Reproducible Approach
1. Clone repo
2. Create folder structure
3. Implement in order: models → utils → execution → parsers → adapters → planning → audit/experience → engine → CLI → tests → docs
4. After each module, run relevant tests
5. Maintain CHANGELOG and AGENT-EXPERIENCE incrementally
6. Final verification: pytest, CLI commands, check for placeholders (grep TODO, placeholder, fake)
7. Document what verified, what not, limitations

## Verification

### What Was Verified
- [x] 24 unit tests passing (models, parsers, scope, planner, adapters, executor)
- [x] CLI --list-capabilities shows 30+ capabilities with availability status
- [x] CLI --discover-only discovers system interfaces via /sys/class/net and reports unavailable tools with reasons
- [x] No placeholders (grep for TODO, placeholder, fake, simulated - none found except in docs explaining what not to do)
- [x] Real subprocess execution with timeout, no shell=True
- [x] Input validation for MAC, IP, channel, interface
- [x] Scope enforcement blocks unauthorized invasive actions
- [x] Audit report generated with finding traces

### What Was Not Verified (Requires Hardware)
- [ ] Full assessment with real wireless adapter in monitor mode (requires physical adapter, root, Kali tools)
- [ ] airodump-ng actual capture and CSV parsing with real hardware
- [ ] wash WPS discovery with real APs
- [ ] hcxdumptool handshake capture
- [ ] nmap network discovery after wireless access
- [ ] Integration test with real APs in authorized scope

### Limitations
- Hardware dependent for full assessment
- Some parsers basic (horst, wavemon, kismet logs)
- Verification simple (multi-tool correlation), could be enhanced
- No AI planner yet (deterministic heuristic only)
- Vulnerability and framework adapters not yet implemented (OpenVAS, Nuclei, Nikto, Metasploit, etc.)
- Synchronous execution, could benefit from async for long-running captures

## Conclusion

This implementation provides production-ready foundation for real Wi-Fi assessment framework with adaptive, evidence-driven orchestration, capability-aware execution, scope enforcement, auditability, and experience learning. It treats tools as specialized instruments, not interchangeable wrappers, and maintains clear relationship between every action and authorized objective. The framework is operational, inspectable, and testable even without AI model or hardware, with deterministic execution and evidence layers remaining functional independently.
