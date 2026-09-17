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

Since 0.4.0 the subsystems communicate **only** through explicit, versioned data contracts
(`docs/DATA_CONTRACTS.md`). No engine knows how another engine works internally.

```
                    world-state
   ┌──────────────┐ ───────────► ┌──────────────┐
   │ World Model  │              │   Decision   │
   │  publisher   │ ◄─────────── │    Engine    │
   │  + applier   │              └──────┬───────┘
   └──────▲───────┘                     │ action-request
          │                             ▼
          │ evidence-set         ┌──────────────┐  action-validation-result
          │                      │    Policy    │ ─────────────┐
   ┌──────┴───────┐              └──────────────┘              ▼
   │   Evidence   │                                     ┌──────────────┐
   │    Engine    │                                     │  Execution   │
   └──────▲───────┘                                     │   Gateway    │
          │        verification-request                 └──────┬───────┘
          │      ┌────────────────┐                             │ execution-result
          └──────│  Verification  │ ◄───────────────────────────┘
                 │     Engine     │ ──► action-request (never executes a tool)
                 └───────┬────────┘
                         │ verification-result
                 ┌───────▼────────┐
                 │   Experience   │ ──► experience-record (a hint, never a fact)
                 └────────────────┘
```

At the tool boundary the layering is unchanged:

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

- **Contracts**: ten versioned messages (`world-state`, `planning-context`, `decision-proposal`,
  `action-request`, `action-validation-result`, `execution-result`, `evidence-set`,
  `verification-request`, `verification-result`, `experience-record`) with a common envelope,
  three validation levels, Semantic-Versioning negotiation and content digests
- **Models**: Evidence, Finding (hypothesis/supported/verified/refuted), Capability metadata, World Model, Assessment State, Scope
- **World Model boundary**: `WorldStatePublisher` (projects state into `world-state`) and
  `WorldModelApplier` (the only writer back into the model)
- **Policy**: `ActionPolicy` validating scope → capability → parameters, distinguishing
  *rejected* (must not run) from *deferred* (cannot run here right now)
- **Execution**: Capability Registry, Tool Adapters, Capability Checker, Executor with real
  subprocess execution, `ExecutionGateway` producing `execution-result`, and an `ArtifactStore`
  that hashes and references tool output instead of inlining it
- **Evidence**: `EvidenceEngine` producing attributed, scoped observations with declared parse
  problems, and deduplicated verification requests
- **Verification**: `VerificationEngine` requiring two independent sources for `verified`,
  detecting contradiction and staleness, and asking for more evidence without executing anything
- **Decision**: `DecisionEngine` planning from `world-state` through `WorldStateView` and
  `ContractRegistryView`
- **Planning**: Uncertainty Identifier, Action Selector (with a relevance gate), Assessment Planner
- **Audit**: Audit Logger with full traceability - every contract logged, plus correlation chains
  `assessment_id → action_id → execution_id → evidence_ids → verification_ids → finding_ids`
- **Experience**: Experience Store and `ExperienceEngine` tracking information gain versus cost
- **Tools**: 58 adapters covering the Kali wireless toolchain
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

Since 0.4.0 the report also carries the contract trail and an explicit correlation chain:

```json
{
  "contracts": {
    "execution-result": {"producer": "execution", "supported_major_versions": [1]}
  },
  "correlation_chains": [
    {
      "assessment_id": "...",
      "action_id": "...",
      "execution_id": "...",
      "correlation_id": "...",
      "capability": "airodump-ng",
      "status": "success",
      "timestamp": "...",
      "evidence_ids": ["..."],
      "verification_ids": ["..."],
      "artifact_ids": ["..."],
      "finding_ids": ["..."]
    }
  ]
}
```

Every execution carries an `action_id`, including environment bootstrap (`iw dev`, `iwconfig`,
`rfkill`), so no execution in the history is unattributable. Each contract is also written to the
audit log as a `contract:<schema>` event, and every refusal as an `action_rejected` event carrying
its structured reason.

Tool output is referenced rather than inlined: `artifact_ids` point at files stored under
`<output>/artifacts/<assessment_id>/`, each hashed with SHA-256 and flagged if it exceeded the size
cap.

## Development

### Project Structure

```
src/wifi_framework/
├── contracts/         # Ten versioned contracts; imports nothing from core/
│   ├── base.py        #   envelope, digests, version negotiation, typed-field normalisation
│   ├── registry.py    #   ContractRegistry (major-version negotiation)
│   ├── validation.py  #   ValidationIssue, ValidationLevel, require_* helpers
│   ├── common.py      #   ArtifactRef, EntityRef, ToolRef, InterfaceRef, Provenance
│   └── world_state.py, ai.py, action.py, execution.py, evidence.py,
│       verification.py, experience.py
├── core/
│   ├── models/        # Evidence, Finding, Capability, World Model, Scope, Assessment State
│   ├── world/         # WorldStatePublisher (producer), WorldModelApplier (consumer)
│   ├── policy/        # ActionPolicy → action-validation-result
│   ├── decision/      # DecisionEngine, WorldStateView, ContractRegistryView
│   ├── execution/     # Registry, Adapter Base, Executor, Checker, Gateway, ArtifactStore,
│   │                  #   ToolManager, InterfaceManager, DependencyResolver
│   ├── evidence/      # EvidenceEngine → evidence-set + verification-request
│   ├── verification/  # VerificationEngine → verification-result
│   ├── planning/      # Planner, Uncertainty Identifier, Action Selector
│   ├── audit/         # Audit Logger (contract trail, correlation chains, report)
│   ├── experience/    # Experience Store, ExperienceEngine → experience-record
│   └── engine/        # Assessment Engine (the orchestrating loop)
├── tools/
│   ├── adapters/      # 58 real tool adapters
│   └── registry_loader.py
├── parsers/           # Structured parsers
├── utils/             # System, validation
└── cli/               # CLI

config/
├── default.yaml
└── capabilities/

tests/                 # 378 tests
docs/
```

### Running Tests

```bash
pip install -e ".[dev]"
pytest -v
pytest --cov=wifi_framework
```

`pythonpath = ["src"]` is configured in `pyproject.toml`, so the suite also runs from a clean
checkout with no install step:

```bash
python -m pytest          # 378 tests, ~4s
```

The suite requires **no wireless hardware and no Kali tools**: capability availability is supplied
through state rather than probed, and the end-to-end tests drive the production adapters and
parsers through real `subprocess` calls against stub binaries placed on `PATH`. Those stubs are
fixtures - they exercise framework code and say nothing about any real environment.

### Code Quality

- Production-ready, no placeholders
- Real tool execution with timeout handling, failure reporting
- Input validation, security-first: commands are argv lists and `shell=True` is never used, so no
  argument is ever interpreted by a shell. Unsafe values are **rejected, not rewritten** - the
  policy layer refuses control characters, shell metacharacters, `-`-prefixed values (argument
  injection) and path traversal as non-retriable. Silently "sanitizing" a target identifier would
  be worse: an SSID legitimately contains `$` or `&`, and mutating it would aim the assessment at a
  network the operator never authorised
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
- Policy runs scope **before** capability, so an out-of-scope request is reported as a scope
  refusal and never retried - even if the tool is also missing
- A capability that cannot be resolved is treated as **invasive** (fail closed): an unknown
  capability cannot be shown to be passive
- Unsafe parameter values (argument injection, control characters, shell metacharacters, path
  traversal) are rejected and never retried
- Refused actions never reach the tool, which the test suite proves with stubs that record their
  own invocations
- Out-of-scope observations are tagged and cannot drive verification or findings

**Never use against networks without explicit authorization.**

## Documentation

- `docs/DATA_CONTRACTS.md` - The contract layer: envelope, catalogue, validation, versioning,
  correlation chains, subsystem invariants
- `docs/ARCHITECTURE.md` - Detailed architecture
- `docs/OPERATIONAL_PHILOSOPHY.md` - Philosophy and assessment approach
- `docs/TOOL_MODEL.md` - Tool capability model
- `docs/TOOL_HANDLING.md` - Tool handling, resource management, operational integrity
- `docs/RESEARCH.md` - Per-tool research: real usage, flags, output, failure modes, sources
- `docs/IMPLEMENTATION_PLAN.md` - Implementation plan
- `docs/CONTRACT_LAYER_PLAN.md` - The 0.4.0 contract-layer plan, milestones and its
  verification-honesty statement
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
