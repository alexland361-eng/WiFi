# Architecture

## Overview

WiFi Framework is designed as a real Wi-Fi penetration-testing and security-assessment framework with adaptive, evidence-driven orchestration.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Assessment Engine                            │
│  Observe → Model → Identify Uncertainty → Select Action →       │
│  Parameterize → Execute → Parse → Verify → Update → Re-evaluate │
└─────────────────────────────────────────────────────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌───────────────┐        ┌──────────────┐        ┌──────────────┐
│   Planning    │        │  Execution   │        │    World     │
│               │        │              │        │    Model     │
│ - Uncertainty │        │ - Registry   │        │              │
│   Identifier  │        │ - Executor   │        │ - APs        │
│ - Action      │        │ - Adapters   │        │ - Clients    │
│   Selector    │        │ - Checker    │        │ - Hosts      │
│ - Planner     │        │              │        │ - Channels   │
└───────────────┘        └──────────────┘        └──────────────┘
        │                        │                        │
        └────────────────────────┼────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Evidence & Finding & Audit & Experience            │
│                                                                 │
│  Evidence (structured, confidence, source, timestamp)           │
│  Finding (hypothesis → supported → verified → refuted)          │
│  Audit Logger (full traceability)                               │
│  Experience Store (info gain, cost, verification)               │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Tool Adapters (30+)                          │
│                                                                 │
│  Interface: iw, iwconfig, airmon-ng, rfkill, ethtool            │
│  Discovery: airodump-ng, wash, kismet, horst, wavemon           │
│  Capture: tshark, tcpdump, dumpcap                              │
│  WPS: reaver, bully, pixiewps                                   │
│  WPA: hcxdumptool, hcxpcapngtool, hashcat, john                 │
│  Network: nmap, arp-scan, netdiscover, fping, dig               │
│  Enum: curl, openssl, smbclient                                 │
│  Protocol: macchanger, bettercap, scapy                         │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Real Kali Tools                              │
│  Actual binaries invoked via subprocess, real output parsed     │
└─────────────────────────────────────────────────────────────────┘
```

## Contract Layer

Since 0.4.0 the subsystems above do not call each other's internals. They exchange **versioned,
validated, immutable messages**, and the message is the interface. The full reference — envelope,
catalogue, validation levels, versioning rules, correlation chains — lives in
[DATA_CONTRACTS.md](DATA_CONTRACTS.md).

```
        world-state                      action-request
   ┌────────────────┐   ┌──────────┐   ┌──────────────┐   ┌──────────────┐
   │  World Model   │──►│ Decision │──►│    Policy    │──►│  Execution   │
   │ publisher +    │   │  Engine  │   │  (validate)  │   │   Gateway    │
   │ applier        │   └──────────┘   └──────────────┘   └──────┬───────┘
   └───────▲────────┘  action-validation-result                  │
           │                                             execution-result
           │ evidence-set                                        ▼
   ┌───────┴────────┐   verification-request   ┌──────────────────────┐
   │    Evidence    │─────────────────────────►│    Verification      │
   │     Engine     │◄─────────────────────────│      Engine          │
   └────────────────┘   verification-result    └──────────┬───────────┘
                                                          │
                                               ┌──────────▼───────────┐
                                               │     Experience       │
                                               └──────────────────────┘
```

Ten contracts, all at version `1.0`:

| Contract | Producer | Purpose |
|---|---|---|
| `world-state` | World Model | The authoritative projection the Decision Engine plans from |
| `planning-context` | Decision | Constrained view handed to an AI/planner layer |
| `decision-proposal` | AI | A proposed capability and target — **never a command** |
| `action-request` | Decision | What to do, why, against which target |
| `action-validation-result` | Policy | approved / rejected / deferred, with a structured reason |
| `execution-result` | Execution | What actually ran, what it returned, where the output is |
| `evidence-set` | Evidence | Attributed, scoped observations plus declared extraction problems |
| `verification-request` | Evidence | A claim that must not be trusted on one source |
| `verification-result` | Verification | verified / supported / unresolved / contradicted / refuted / stale |
| `experience-record` | Experience | Information gain versus cost, as a ranking hint only |

Invariants enforced by code and pinned by tests:

* `WorldModelApplier` is the **only** writer from contracts into the World Model; evidence not
  declared in an `evidence-set` is refused rather than applied.
* The Evidence Engine never decides the next action; the Verification Engine never executes a tool
  (it returns an `action-request` for the Decision Engine to schedule).
* A single observation can never reach `verified` — two independent sources are required.
* Out-of-scope observations are tagged and generate no verification requests.
* A tool that was never invoked reports `unsupported`/`rejected` with `exit_code = None`, never a
  fabricated failure and never a silent skip.
* `contracts/` imports nothing from `core/`, which is what keeps engines independently replaceable.

## Core Models

### Evidence

Fundamental unit of world model.

```python
@dataclass
class Evidence:
    id: str (uuid)
    timestamp: datetime (tz-aware)
    evidence_type: EvidenceType (interface, AP, client, WPS, capture, handshake, etc.)
    source: EvidenceSource (tool_name, capability, interface, raw_command)
    parameters: Dict (input params)
    raw_output: str (full output)
    parsed_data: Dict (structured)
    confidence: float (0.0-1.0)
    interface: Optional[str]
    tags: List[str] (in_scope, out_of_scope)
    execution_id: str
```

- Raw output never authoritative finding by itself
- Parsed into structured evidence with identifiers, timestamps, sources, confidence

### Finding

Security finding reasoned from evidence.

```python
class FindingStatus(Enum):
    HYPOTHESIS = "hypothesis"      # Initial guess
    SUPPORTED = "supported"        # Multiple evidences
    VERIFIED = "verified"          # Independent verification succeeded
    REFUTED = "refuted"            # Contradicted
    UNRESOLVED = "unresolved"
    CONFIRMED = "confirmed"

@dataclass
class Finding:
    id, title, description
    category: FindingCategory (wireless, WPS, auth, encryption, network, etc.)
    severity: FindingSeverity (info, low, medium, high, critical)
    status: FindingStatus
    confidence: float
    evidence_ids: List[str]
    affected_assets: List[str] (BSSID, SSID, IP)
    details: Dict
    verification_method, verified_at, verification_evidence_ids
```

### Capability Metadata

Machine-readable metadata for every tool.

```python
@dataclass
class ToolCapabilityMetadata:
    name: str (e.g., airodump-ng)
    display_name: str
    category: CapabilityCategory
    description: str
    tool_binary: str (actual executable)
    requirements: CapabilityRequirements (OS, interface, privileges, version, deps)
    inputs: List[str] (e.g., interface, channel, bssid)
    outputs: List[str] (e.g., access_points, clients)
    operational_properties: OperationalProperties (mode, persistent, invasive, etc.)
    failure_conditions: List[str]
```

Example YAML:

```yaml
tool:
  name: airodump-ng
  category: wireless_observation
requirements:
  operating_system: [linux]
  interface: {required: true}
  capabilities: [monitor_mode]
inputs: [interface, channel, observation_scope]
outputs: [access_points, clients, channels, signal_observations]
operational_properties:
  mode: active_observation
  persistent: true
failure_conditions: [interface_unavailable, unsupported_driver, ...]
```

### World Model

Internal model of observed wireless environment.

```python
@dataclass
class AccessPoint:
    bssid, ssid, channel, frequency, signal_strength
    encryption, cipher, authentication
    wps_enabled, wps_locked, manufacturer
    first_seen, last_seen, evidence_ids, client_macs, is_hidden

@dataclass
class WirelessClient:
    mac, associated_bssid, ssid_probed, signal_strength, evidence_ids

@dataclass
class NetworkHost:
    ip, mac, hostname, os_guess, open_ports, services

@dataclass
class WorldModel:
    access_points: Dict[bssid, AP]
    clients: Dict[mac, Client]
    network_hosts: Dict[ip, Host]
    channels_observed: Set[int]
    ssids_observed: Set[str]
    evidence_count, last_updated

    def update(evidence: Evidence): ...
```

Continuously updated with new evidence.

### Assessment State

Central state machine.

```python
@dataclass
class AssessmentState:
    id, created_at, updated_at, phase: AssessmentPhase
    scope: AssessmentScope
    world_model: WorldModel
    interfaces: Dict[name, InterfaceInfo]
    available_capabilities: Dict[name, ToolCapabilityMetadata]
    unavailable_capabilities: Dict[name, reason]
    evidences: List[Evidence]
    findings: List[Finding]
    execution_history: List[ExecutionRecord]
    uncertainties: List[Dict]
    objectives: List[str]

    def add_evidence(ev): world_model.update(ev)
    def add_finding(f)
    def add_execution(record)
    def transition_phase(new_phase, reason)
```

### Scope

Authorization model.

```python
@dataclass
class AssessmentScope:
    authorized_ssids: List[str] (supports regex)
    authorized_bssids: List[str] (normalized upper colon)
    authorized_channels: List[int]
    authorized_networks: List[str] (CIDR)
    authorized_hosts: List[str]
    description, allow_broadcast_discovery, strict_mode

    def is_ssid_authorized(ssid) -> bool (regex match)
    def is_bssid_authorized(bssid) -> bool (normalized)
    def is_ip_authorized(ip) -> bool (CIDR check)
    def is_wireless_asset_authorized(ssid, bssid) -> bool
    def validate() -> List[errors]

class ScopeEnforcer:
    def check_wireless_action_allowed(ssid, bssid, invasive) -> (allowed, reason)
    def check_network_action_allowed(target_ip, invasive) -> (allowed, reason)
    def filter_evidence_by_scope(evidence_list) (tags in_scope/out_of_scope)
```

## Execution Layer

### ToolAdapterBase

Abstract base for all adapters.

```python
class ToolAdapterBase(ABC):
    def check_requirements(interface, params) -> (ok, reason):
        # Check OS, tool availability, version, interface, privileges, deps, custom

    def validate_parameters(params) -> (valid, errors)

    @abstractmethod
    def build_command(interface, params) -> List[str]:
        # Translate structured params → valid tool invocation
        # Must return list args, not shell string

    @abstractmethod
    def parse_output(raw_output, error_output, exit_code, params, interface) -> List[Evidence]:
        # Convert raw output → structured observations
        # Must never fabricate discoveries

    def execute(interface, params, timeout) -> AdapterExecutionResult:
        # Full flow: validate → check requirements → build command → run_command → parse → interpret failure

    def interpret_failure(exit_code, stdout, stderr) -> Optional[reason]
```

- Real execution via `utils.system.run_command` (subprocess.run, timeout, no shell=True)
- Every capability must be functioning implementation, not placeholder

### CapabilityChecker

Verifies if capability usable in current environment.

```python
class CapabilityChecker:
    def check(capability, interface) -> (available, reason, details):
        # OS check, tool availability (shutil.which), privileges (os.geteuid), interface (/sys/class/net), deps
```

### CapabilityRegistry

Registry of all capabilities.

```python
class CapabilityRegistry:
    def register(metadata, adapter_class)
    def get_metadata(name) -> Optional[Metadata]
    def get_adapter_instance(name) -> Optional[Adapter]
    def check_availability(name, interface) -> (ok, reason, details)
    def get_available_capabilities(interface) -> Dict
    def get_unavailable_capabilities(interface) -> Dict[name, reason]
    def auto_discover_adapters(package_name)
```

Global registry via `get_global_registry()`.

### CapabilityExecutor

Capability-aware execution with parameter generation from state.

```python
class CapabilityExecutor:
    def generate_parameters_from_state(capability_name, state, overrides) -> Dict:
        # Automatically derive params from state:
        # - interface from state.interfaces (prefer monitor capable if required)
        # - channel from authorized or observed
        # - bssid from discovered APs in scope
        # - ssid from observed
        # - ip from network hosts in scope
        # Overrides win

    def execute(capability_name, interface, params, timeout, state) -> ExecutionResult:
        # Generate params from state if not fully specified
        # Get adapter, execute via adapter
        # Create ExecutionRecord, add to state, add evidences to state
```

## Planning Layer

### UncertaintyIdentifier

Identifies what is known, what is unknown.

```python
class UncertaintyIdentifier:
    def identify(state) -> List[Dict]:
        # Returns list of:
        # {
        #   type: interface_discovery, capability_discovery, wireless_observation, ap_identification, hidden_ssid, wps_state, client_discovery, network_hosts, handshake_capture, verification
        #   priority: 10 (highest) to 1 (lowest)
        #   description: str
        #   required_capabilities: List[str]
        #   context: Dict (bssids, channels, etc.)
        # }
        # Sorted by priority descending
```

### ActionSelector

Selects appropriate capability based on evidence, scope, capabilities, uncertainties.

```python
class ActionSelector:
    def score_capability(capability, uncertainty, state, interface) -> (score, reason):
        # Score based on:
        # - Availability (if unavailable, -1)
        # - Direct match to required_capabilities (+10)
        # - Useful outputs matching uncertainty type (+5 per output)
        # - Non-invasive (+2, +3 early phases)
        # - Recent execution penalty (-5 if executed 2+ times recently)
        # - Experience scores (+ experience * 2)
        # - Scope: if needs BSSID but no authorized APs in world model, -3
        # - Duration: short +1, long -1 when many uncertainties

    def select_action(state, uncertainties, interface) -> Optional[Dict]:
        # For each uncertainty in priority order, for each available capability, score
        # Return best action: {capability_name, metadata, interface, parameters, uncertainty, score, reason}

    def select_interface(state, capability) -> Optional[str]:
        # If capability requires interface, pick best from state.interfaces (prefer monitor capable)
```

### AssessmentPlanner

Adaptive planner.

```python
class AssessmentPlanner:
    def __init__(self, registry):
        self.uncertainty_identifier = UncertaintyIdentifier()
        self.action_selector = ActionSelector(registry)

    def plan_next_action(state, interface) -> Optional[Dict]:
        # Identify uncertainties, select interface, select action

    def should_continue(state, max_iterations) -> bool:
        # Check iteration limit, phase completed/failed, no uncertainties, only low priority left

    def suggest_phase_transition(state) -> Optional[AssessmentPhase]:
        # Heuristic: initializing → interface_discovery → capability_discovery → wireless_observation → wps_assessment → authentication_assessment → asset_identification → network_discovery → service_enumeration → vulnerability_assessment → verification → reporting → completed
```

## Audit and Experience

### AuditLogger

Every meaningful action reconstructable.

```python
class AuditLogger:
    def __init__(self, log_dir, assessment_id):
        # Ensure log dir exists, events list

    def log_event(event_type, data, timestamp):
        # Append to events list, write JSONL to file

    def log_scope(scope)
    def log_capability_discovery(available, unavailable)
    def log_action_selection(action)
    def log_execution(record)
    def log_evidence(evidence)
    def log_finding(finding)
    def log_state_transition(from_phase, to_phase, reason)
    def log_verification(finding_id, method, success, evidence_id)

    def generate_report(state) -> Dict:
        # Includes assessment_id, scope, summary, execution_history, evidences (with raw_command), findings, world_model, phase_transitions, finding_traces (evidence chain per finding)

    def save_report(state, output_path) -> str:
        # JSON dump to file
```

### ExperienceStore

Maintains experience for learning.

```python
@dataclass
class ExperienceRecord:
    id, timestamp, capability_name, tool_binary, interface, parameters, state_summary, uncertainty_type, success, exit_code, duration_seconds, evidence_count, information_gain, cost, failure_reason, verification_supported

class ExperienceStore:
    def __init__(self, store_path):
        # Load existing from JSONL

    def add(...) -> ExperienceRecord:
        # info_gain = evidence_count if success else 0
        # cost = duration + 10 if failure
        # Persist to JSONL

    def get_capability_stats() -> Dict[cap, {total_executions, success_count, total_info_gain, total_cost, avg_duration, success_rate, avg_info_gain}]

    def get_experience_scores() -> Dict[cap, score]:
        # score = (avg_info_gain * success_rate) / (avg_duration/10 + 1)

    def update_verification(capability_name, verification_supported)
```

## Engine

### AssessmentEngine

Main orchestrator implementing adaptive loop.

```python
class AssessmentEngine:
    def __init__(self, scope, registry, audit_logger, experience_store, assessment_state):
        # Setup registry (auto-discover), state, executor, planner, audit, experience, scope_enforcer
        # Load experience scores into state.extra

    def discover_interfaces() -> List[InterfaceInfo]:
        # Execute iw_dev and iwconfig, build InterfaceInfo from evidences and /sys/class/net

    def discover_capabilities(interface) -> (available, unavailable):
        # Registry get_available/unavailable, log

    def run_single_action(action, timeout) -> bool:
        # Scope enforcement check (wireless and network, invasive)
        # If blocked, log scope_blocked and return False
        # Log action selection, execute via executor, log execution and evidences, add to experience, update experience scores

    def verify_findings():
        # For each hypothesis finding, check if AP has 2+ evidences from different tools → verify via multi_tool_correlation

    def update_findings_from_world_model():
        # For each AP in world model, if no existing finding, create Finding (wireless, check weak encryption → high severity, encryption category, check WPS enabled → medium severity WPS finding)

    def run(max_iterations, timeout_per_action, auto_discover) -> AssessmentState:
        # Print start, scope
        # Transition to interface_discovery
        # If auto_discover: discover_interfaces, discover_capabilities, transition to capability_discovery, wireless_observation
        # Loop iteration:
        #   Check should_continue
        #   Plan next action
        #   If no action: check phase transition, if none, break
        #   Select interface for action if needed
        #   run_single_action
        #   update_findings_from_world_model
        #   Every 5 iterations: verify_findings
        #   Check phase transition
        # Final verification, transition to reporting, generate report, transition to completed
```

## CLI

- argparse with --ssid, --bssid, --channel, --network, --host (multiple), --interface, --max-iterations, --timeout, --discover-only, --list-capabilities, --list-interfaces, --scope-description, --strict, --output, --config, --verbose
- Scope from args and YAML config, validation
- Commands: list_capabilities, discover_only, full assessment
- Handles KeyboardInterrupt with partial report

## Security

- No shell=True, only list args
- Input validation for MAC, SSID, channel, interface, IP, CIDR
- Privilege checks
- Scope enforcement for invasive
- Reject rather than rewrite: `utils.validation` defines the forbidden character sets once
  (`CONTROL_CHARS`, `SHELL_METACHARACTERS`) and `ActionPolicy` imports them, turning a match into a
  non-retriable rejection. Argument values are never mutated - a rewritten BSSID or SSID would
  redirect the assessment at a target the operator did not authorise
- **No autonomous hardware mutation.** The loop never creates a monitor interface, changes a MAC,
  brings an interface up or down, retunes a channel or unblocks rfkill. `InterfaceManager`
  implements all of these and is exported for an operator to call explicitly, but nothing on the
  autonomous path invokes it - the engine and the CLI each construct one and never call a method
  (verified by an AST sweep over all 119 modules, pinned by
  `tests/test_validation.py::test_the_autonomous_loop_never_mutates_radio_hardware`). These actions
  are disruptive and not reliably reversible mid-assessment, so they belong to a human who has
  decided to make them, not to a loop choosing its next action.

  The loop's alternative is to **detect and defer**: a capability needing monitor mode on an
  interface that lacks it yields a *retriable* `monitor_mode_unavailable` deferral, suppressed for
  `BLOCK_COOLDOWN_ITERATIONS` (3) iterations and then eligible again, so an operator who enables
  monitor mode during a run can be picked up by a later iteration. The operator must establish
  monitor mode before active assessment - see README "Interface preparation".

## Testing

380 tests (`pytest` from a clean checkout; `pythonpath = ["src"]` is configured in
`pyproject.toml`, so no install step is needed):

| Suite | Tests | Covers |
|---|---|---|
| `test_validation.py` | 116 | Input validators, the single-sourced forbidden-character rule, the interface-existence gate, no-shell and no-autonomous-hardware-mutation AST sweeps, and that a malformed scope BSSID authorises nothing |
| `test_contracts.py` | 49 | Envelope, both wire forms, version negotiation, digests, every semantic rule |
| `test_world_state.py` | 34 | Publication, staleness, stable gap ids, hypotheses/findings split, applier |
| `test_policy.py` | 30 | Scope / capability / parameter stages, fail-closed invasiveness, refusals |
| `test_verification_engine.py` | 29 | Noisy-OR aggregation, all six verification states, freshness, contradiction |
| `test_evidence_engine.py` | 28 | Provenance, scope tagging, verification-request generation, no fabrication |
| `test_contract_pipeline.py` | 25 | The full loop against a **real subprocess** (stub binaries on `PATH`) |
| `test_decision_engine.py` | 22 | AI-layer seam: narrowed planning context, proposal intake, acceptance ≠ authorisation |
| `test_audit.py` | 18 | Contract trail, refusal logging, and the correlation chain reaching findings |
| `test_scope.py` | 8 | Pre-0.4.0 scope tests plus 5 additive regressions for the scope fix |
| `test_models/parsers/adapters/planner/executor.py` | 21 | Pre-0.4.0 suites, unmodified |

The integration suite puts stub binaries on `PATH` and drives the production adapters, parsers,
gateway and policy through real `subprocess` calls. Stubs record their own invocations, which lets
the tests prove a negative: that a scope-refused action never reached the tool.

**What cannot be verified without hardware:** monitor mode, packet injection, and any behaviour
depending on the presence of Kali tools (`airodump-ng`, `wash`, `reaver`, `hcxdumptool`, `nmap`).
Those paths are implemented, not field-verified.

## Future

- Vulnerability adapters (OpenVAS, Nuclei, Nikto)
- Framework adapters (Metasploit, Impacket, Responder)
- Web UI
- AI planner
- Async execution
- Integration tests with real hardware
