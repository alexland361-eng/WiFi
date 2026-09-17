# Data Contracts

Version 0.4.0 introduces an explicit contract layer: the subsystems of this framework no longer
call each other's internals. They exchange **versioned, validated, immutable messages**, and the
message is the interface.

> Core rule (specification section 3): *no engine may know how another engine works internally.*
> A contract is what makes that rule enforceable rather than aspirational.

---

## 1. Why contracts

Before 0.4.0 the loop was a set of direct method calls: the planner reached into the registry,
the engine mutated the world model, and evidence handling was inlined in the orchestrator. That
works, but it has three costs this project cannot afford:

1. **No enforceable boundary.** Nothing stopped one subsystem from depending on another's
   internals, so replacing or testing a subsystem in isolation was not possible.
2. **No auditability guarantee.** A finding could be promoted without a record of which
   execution produced the evidence that justified it.
3. **No way to express "we do not know".** A failed tool run and a successful run with no
   observations looked the same to the caller.

Contracts address all three: every exchange is a typed object that validates itself, names its
producer, carries its provenance, and is written to the audit trail.

---

## 2. The common envelope

Every contract extends `BaseContract` (`src/wifi_framework/contracts/base.py`) and therefore
carries the same metadata:

| Field            | Type       | Meaning                                                          |
|------------------|------------|------------------------------------------------------------------|
| `schema`         | str        | Contract name, e.g. `"execution-result"`                         |
| `version`        | str        | `MAJOR.MINOR` produced by this implementation (all are `1.0`)    |
| `message_id`     | str        | Unique id of this message                                        |
| `assessment_id`  | str        | **Mandatory.** Identity is never inferred from filenames or globals |
| `timestamp`      | datetime   | Timezone-aware; naive timestamps are rejected                    |
| `source_engine`  | str        | Producer subsystem; defaults to the contract's declared owner    |
| `correlation_id` | str        | Links related messages into one causal chain                     |
| `extensions`     | dict       | Unknown fields from a newer producer, preserved for forward compatibility |

The envelope is deliberately close to [CloudEvents 1.0](https://cloudevents.io): `schema`≈`type`,
`version`≈`specversion`, `message_id`≈`id`, `source_engine`≈`source`, `timestamp`≈`time`,
`payload`≈`data`, with `correlation_id` as an extension attribute.

### Two wire forms

```python
message = contract.to_message()   # canonical: envelope + nested "payload"
flat    = contract.to_dict()      # flat: envelope fields merged with payload
```

Both parse back to an identical object. `to_message()` is what the audit trail stores; `to_dict()`
exists for logs and human inspection.

---

## 3. Contract catalogue

| Contract                   | Version | Producer       | Consumer(s)                        | Module            |
|----------------------------|---------|----------------|------------------------------------|-------------------|
| `world-state`              | 1.0     | World Model    | Decision Engine, orchestrator      | `world_state.py`  |
| `planning-context`         | 1.0     | Decision       | AI/planner layer                   | `ai.py`           |
| `decision-proposal`        | 1.0     | AI             | Decision Engine                    | `ai.py`           |
| `action-request`           | 1.0     | Decision       | Policy, Execution                  | `action.py`       |
| `action-validation-result` | 1.0     | Policy         | Orchestrator, Decision             | `action.py`       |
| `execution-result`         | 1.0     | Execution      | Evidence, World Model, Experience  | `execution.py`    |
| `evidence-set`             | 1.0     | Evidence       | World Model, Verification          | `evidence.py`     |
| `verification-request`     | 1.0     | Evidence       | Verification                       | `verification.py` |
| `verification-result`      | 1.0     | Verification   | World Model, Experience            | `verification.py` |
| `experience-record`        | 1.0     | Experience     | Decision Engine (as a hint)        | `experience.py`   |

The live catalogue is available at runtime:

```python
from wifi_framework.core.audit.logger import AuditLogger
AuditLogger.contract_catalogue()   # {schema: {producer, supported_major_versions}}
```

### Versioning rules

Following [Semantic Versioning 2.0.0](https://semver.org):

* **MAJOR** — breaking change. A consumer **must reject** a major version it does not support
  (`UnsupportedContractVersion`); it must never guess at the meaning of fields it does not know.
* **MINOR** — backward-compatible addition. Accepted within the same major.
* Unknown payload fields from a newer producer are preserved in `extensions` and re-emitted on
  serialisation, so an older consumer cannot silently strip a newer producer's data.

---

## 4. Validation

Validation is layered (`ValidationLevel`), and a caller chooses how deep to go:

| Level          | Checks                                                                     |
|----------------|----------------------------------------------------------------------------|
| `structural`   | Required fields present and non-empty, types correct, timestamps aware     |
| `semantic`     | Internal consistency — e.g. a `failed` execution must carry a failure record |
| `operational`  | Environment — tool availability, privileges, interface state               |

```python
validation = contract.validate()                       # structural + semantic
validation = contract.validate([ValidationLevel.STRUCTURAL])
validation.ok, validation.issues, validation.error_messages
```

Semantic rules exist to make dishonest states unrepresentable. Examples:

* `execution-result`: `failed` without a `failure` record is invalid; `success` **with** a failure
  record is invalid; a status in `TERMINAL_NOT_EXECUTED` must not claim an `exit_code`.
* `verification-result`: `verified` requires ≥2 independent sources and confidence at or above the
  required threshold; `unresolved` must state what evidence is missing; `refuted` must cite the
  contradicting evidence; `conclusion.state` must equal `status`.
* `decision-proposal`: **cannot carry a command**. An AI layer may propose a capability and a
  target; it may never invoke a shell.

---

## 5. Execution states

```
TERMINAL_EXECUTED     = success, partial, failed, timeout, cancelled
TERMINAL_NOT_EXECUTED = unsupported, rejected
```

The distinction is the framework's honesty guarantee. A tool that was never invoked reports
`unsupported` or `rejected` with `exit_code = None` — never a fabricated failure code, and never
a silent skip.

`FailureCategory` classifies why:

```
tool_not_found, tool_version, capability_unavailable, unsupported_driver,
interface_unavailable, radio_blocked, insufficient_privileges, permission_denied,
scope_denied, invalid_parameters, parser_error, tool_error, timeout, cancelled, internal_error

RETRIABLE = timeout, tool_error, interface_unavailable, radio_blocked, internal_error
```

**Timeout versus partial.** A run stopped by its timeout is `partial` only if it produced real
observations; otherwise it is `timeout`. Note that `subprocess` does return output written before
the kill, but adapters such as `IwDevAdapter` decline to parse output from a non-zero exit, so a
timed-out `iw dev` is reported as `timeout`. Capture tools that write to files
(`airodump-ng --write`, `hcxdumptool`) are how partial output reaches the model in practice.

---

## 6. Policy check order

`ActionPolicy.validate()` runs four stages in the specification's order and short-circuits:

```
structural → resolve capability metadata → scope → capability → parameters
```

Two kinds of "no" are distinguished:

| Verdict      | Meaning                                              | Retriable |
|--------------|------------------------------------------------------|-----------|
| `rejected`   | Must not run: out of scope, wrong capability, unsafe parameter | Mostly no |
| `deferred`   | Legitimate, but cannot run in this environment right now | Yes, briefly |

* A **scope** denial is always a hard rejection and is never retried: no change of circumstance
  authorises an unauthorised target.
* **Capability unavailability** is deferred. `capability_unavailable` (the binary is unusable) is
  treated as non-retriable; `interface_down`, `monitor_mode_unavailable`, `interface_required`,
  `interface_unknown` and `insufficient_privileges` stay retriable because the environment can
  change mid-assessment (a monitor-mode VIF created by `airmon-ng` is the common case).
* **Unsafe parameters** (`argument_injection_risk`, `control_character`, `shell_metacharacter`,
  `path_traversal`, `bytes_parameter`) are never retried — the value came from observed state and
  would be regenerated identically. A merely *missing* target is retriable, because later
  discovery can supply it.
* Scope is checked **before** capability, so an out-of-scope request is reported as a scope
  refusal even if the tool is also missing. The operator sees the real reason.

**Fail-closed invasiveness.** When a capability cannot be resolved, it is treated as *invasive*,
because an unknown capability cannot be shown to be passive. Treating it as passive would let an
unresolvable request through the scope gate.

---

## 7. Correlation and causality

Every message carries `correlation_id`, and the identifiers compose into a chain:

```
assessment_id → action_id → execution_id → evidence_ids → verification_ids → finding_ids
```

This mirrors [W3C PROV-O](https://www.w3.org/TR/prov-o/): an observation `wasGeneratedBy` an
execution, which `used` an action, and a finding `wasDerivedFrom` observations.

`AuditLogger.correlation_chains(state)` reconstructs the chain per execution and it is included in
every generated report:

```python
{
  "assessment_id": "...", "action_id": "...", "execution_id": "...",
  "correlation_id": "...", "capability": "iw_dev", "status": "unsupported",
  "timestamp": "...", "evidence_ids": [...], "verification_ids": [...],
  "artifact_ids": [...], "finding_ids": [...]
}
```

Every execution in the history carries an `action_id` — including environment bootstrap
(`iw dev`, `iwconfig`, `rfkill`), which is expressed as an `action-request` with objective
`DISCOVER_INTERFACES` so that no execution is unattributable.

The audit trail also records each contract under `contract:<schema>` events, plus
`action_rejected` events carrying the structured refusal reason.

---

## 8. Artifacts

Tool output is **referenced, not inlined**. `ExecutionResult` carries `ArtifactRef` objects:

```
id, kind (stdout|stderr|file|capture), path, sha256, bytes, created_at, truncated, media_type
```

`ArtifactStore` (`core/execution/artifacts.py`) writes them under
`<artifact_dir>/<assessment_id>/`, hashes them, enforces a size cap (32 MiB by default) and
discloses truncation. A truncated artifact raises a parse issue in the `evidence-set`, so a
consumer knows the observation may be incomplete.

---

## 9. Subsystem boundaries

```
                       ┌──────────────────────────┐
                       │      orchestrator        │
                       │   AssessmentEngine.run   │
                       └────────────┬─────────────┘
        world-state                 │ action-request
   ┌────────────────┐               ▼
   │  World Model   │◄──────  ┌───────────┐  action-validation-result
   │  (publisher +  │         │  Policy   │──────────────┐
   │   applier)     │         └───────────┘              ▼
   └───────▲────────┘                            ┌──────────────┐
           │ evidence-set                        │  Execution   │
   ┌───────┴────────┐   verification-request     │  (gateway +  │
   │    Evidence    │──────────────────┐         │  artifacts)  │
   │     Engine     │                  ▼         └──────┬───────┘
   └───────▲────────┘         ┌──────────────┐          │ execution-result
           │                  │ Verification │◄─────────┘
           └──────────────────│    Engine    │  verification-result
                              └──────┬───────┘
                                     │
                              ┌──────▼───────┐
                              │  Experience  │──► experience-record (hint only)
                              └──────────────┘
```

Invariants that the code enforces and the tests pin:

* **`WorldModelApplier` is the only writer** from contracts into the World Model. Evidence not
  declared in an `evidence-set` is refused, not applied.
* **The Evidence Engine never decides the next action.** It produces observations and
  `verification-request`s.
* **The Verification Engine never executes a tool.** When it needs more evidence it returns an
  `action-request` (origin `verification`, objective `resolve_verification_requirement`) for the
  Decision Engine to schedule.
* **Experience is a hint, never a fact.** Experience scores travel in `world-state.planner_hints`,
  kept separate from observed state so a ranking prior cannot be mistaken for an observation.
* **A single observation can never become `verified`.** Two independent sources are required.
* **Out-of-scope observations cannot drive conclusions.** They are tagged `out_of_scope` and
  generate no verification requests.

---

## 10. Module map

```
src/wifi_framework/
├── contracts/                  # the contract layer (no imports from core/)
│   ├── base.py                 # BaseContract, envelope, digests, version negotiation
│   ├── envelope.py             # ids, timestamps, EngineId, ContractVersion
│   ├── registry.py             # ContractRegistry: major-version negotiation
│   ├── validation.py           # ValidationIssue, ValidationLevel, require_* helpers
│   ├── errors.py               # ContractValidationError, UnsupportedContractVersion, ...
│   ├── common.py               # ArtifactRef, EntityRef, ToolRef, InterfaceRef, Provenance
│   ├── world_state.py          # world-state
│   ├── ai.py                   # planning-context, decision-proposal
│   ├── action.py               # action-request, action-validation-result
│   ├── execution.py            # execution-result, ExecutionStatus, FailureCategory
│   ├── evidence.py             # evidence-set, Observation, ObservationType
│   ├── verification.py         # verification-request/-result, Claim, VerificationStatus
│   └── experience.py           # experience-record, ActionOutcome, ExecutionOutcomeCost
└── core/
    ├── world/                  # state_publisher.py (producer), applier.py (consumer)
    ├── policy/validator.py     # ActionPolicy → action-validation-result
    ├── execution/gateway.py    # ExecutionGateway → execution-result
    ├── execution/artifacts.py  # ArtifactStore
    ├── evidence/engine.py      # EvidenceEngine → evidence-set + verification-request
    ├── verification/engine.py  # VerificationEngine → verification-result
    ├── decision/               # DecisionEngine, WorldStateView, ContractRegistryView
    ├── experience/engine.py    # ExperienceEngine → experience-record
    └── engine/                 # AssessmentEngine: the orchestrating loop
```

`contracts/` imports nothing from `core/`. That is the dependency rule which keeps engines
independently replaceable.

---

## 11. Adding or changing a contract

1. Define the dataclass in the owning module; set `SCHEMA`, `VERSION`, `PRODUCER` and
   `REQUIRED_PAYLOAD_FIELDS`.
2. Add nested types to `_coerce_payload` so construction and parsing yield identical shapes
   (`BaseContract._normalise_typed_fields` runs it for both paths).
3. Add semantic rules in `extra_structural_issues` / `semantic_issues` — prefer making dishonest
   states unrepresentable over documenting them.
4. Register it in `contracts/registry.py` so version negotiation knows about it.
5. Bump `VERSION`: MINOR for an additive change, MAJOR for a breaking one (and update every
   consumer, since a MAJOR bump means old consumers will reject the message).
6. Add tests to `tests/test_contracts.py` covering the envelope, both wire forms, round-tripping,
   version rejection and every semantic rule.

---

## 12. Verification honesty

What is verified by the test suite in an environment with **no wireless hardware and no Kali
tools**:

* contract serialisation, validation, version negotiation and digests;
* policy decisions across scope, capability and parameter stages;
* evidence normalisation, scope tagging and verification-request generation;
* the verification state machine (verified / supported / unresolved / contradicted / refuted /
  stale) and its noisy-OR aggregation;
* world-state publication, staleness, correlation chains and the applier;
* the **full engine loop against a real subprocess** (stub binaries on `PATH`, driving the
  production adapters and parsers).

What is **not** verified and must not be claimed: any behaviour depending on real wireless
hardware, monitor mode, packet injection, or the presence of Kali tools (`airodump-ng`, `wash`,
`reaver`, `hcxdumptool`, `nmap`, …). Those code paths are *implemented, not field-verified*.
