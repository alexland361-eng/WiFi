# Contract-First Architecture: Plan, Milestones and Acceptance Criteria

Status: **approved for implementation** (this document is the auditable plan of record for v0.4.0)
Owner: framework core
Supersedes: nothing. Extends `IMPLEMENTATION_PLAN.md` (which remains valid for v0.1.0–v0.3.0).

---

## 1. Why this work exists (justification)

The project specification defines the framework as **five subsystems communicating through
explicit, versioned data contracts**:

> No engine may know how another engine works internally. It may only depend on the
> documented contract exposed by that engine.

Inspection of the repository at commit `3c4f51d` (v0.3.0) established the following
**verified** gaps. Each was confirmed by reading the source and by
`grep -rn "WorldState|ActionRequest|EvidenceSet|VerificationRequest|VerificationResult|PlanningContext|DecisionProposal|correlation_id|message_id" src/`
returning **zero matches**.

| # | Spec requirement | State at v0.3.0 | Evidence |
|---|---|---|---|
| G1 | Common envelope (`schema`, `version`, `message_id`, `assessment_id`, `timestamp`, `source_engine`, `correlation_id`, `payload`) | Absent | no `contracts/` package exists |
| G2 | Contract versioning; consumers reject unsupported major versions | Absent | no version negotiation code |
| G3 | `WorldState` contract produced by World Model | Absent | `WorldModel.to_dict()` is an ad-hoc dump, not a contract |
| G4 | Decision Engine consumes `WorldState`, not model internals | **Violated** | `AssessmentPlanner.plan_next_action(state: AssessmentState)` reads `state.world_model`, `state.evidences`, `state.findings` directly |
| G5 | `ActionRequest` contract (capability, not shell command) | Absent | planner returns a plain `dict` with `capability_name` |
| G6 | Policy layer: scope → capability → parameter validation producing `ActionValidationResult` | **Partially inline** | scope check hardcoded in `AssessmentEngine.run_single_action`; no capability/parameter validation stage; no structured rejection |
| G7 | `ExecutionResult` contract with `accepted/running/success/partial/failed/timeout/cancelled/unsupported/rejected` | Absent | `executor.ExecutionResult` is a plain class with only `success: bool` |
| G8 | Artifact references (`stdout_artifact`, `stderr_artifact`, `artifacts[]`) | Absent | stdout truncated inline into `ExecutionRecord.raw_output[:10000]`, losing data |
| G9 | Evidence Engine as a subsystem producing `EvidenceSet` | Absent | parsing happens inside each adapter; no `EvidenceSet` |
| G10 | Verification Engine producing `VerificationRequest`/`VerificationResult` | **Fused** | `AssessmentEngine.verify_findings()` is a 20-line heuristic inside the orchestrator |
| G11 | `VerificationActionRequest` routed back through the planner (verification never executes tools) | Absent | no such path |
| G12 | `ExperienceRecord` contract with `state_before`/`state_after` hashes | Absent | `experience/store.py:ExperienceRecord` has no state hashing |
| G13 | AI contracts `PlanningContext` / `DecisionProposal` behind validation | Absent | listed as "Planned" in CHANGELOG |
| G14 | Correlation chain `assessment_id → action_id → execution_id → evidence_id → verification_id` | **Partial** | `Evidence.execution_id` exists; `action_id` and `verification_id` do not |
| G15 | Three-level validation (structural / semantic / operational) | Absent | only ad-hoc `validate_parameters` in adapters |

Nothing in this list disputes the quality of the existing adapters, parsers or planner
heuristics. Those are preserved untouched (guideline 13). The work is to **add the contract
layer and route the existing subsystems through it**.

## 2. Scope

### In scope
1. `src/wifi_framework/contracts/` — envelope, versioning, validation, and the ten contracts of
   the specification's ownership table.
2. Five subsystem boundaries that own/produce those contracts:
   `core/world` (WorldState publisher), `core/decision` (ActionRequest producer),
   `core/policy` (ActionValidationResult), `core/evidence` (EvidenceSet),
   `core/verification` (VerificationRequest/Result).
3. Artifact store so execution output is referenced, not truncated.
4. Correlation and causality chain across all messages.
5. Rewiring `AssessmentEngine` so the adaptive loop runs *through* the contracts.
6. Tests that exercise the contract loop end-to-end using a real executable fixture.
7. Documentation: `docs/DATA_CONTRACTS.md`, architecture/changelog/experience updates.

### Out of scope (recorded as recommendations, not implemented — guideline 19)
- New tool adapters (`airdriver-ng`, `ivstools`), GUI tooling.
- Parsers for `horst`, `wavemon`, Kismet logs, `hcxdumptool` counters.
- Web UI, real AI planner backends, benchmarks.
- Any change to adapter `build_command`/`parse_output` behaviour.

## 3. Architecture

```
                        ASSESSMENT OBJECTIVE (AssessmentScope)
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │ WORLD MODEL  core/models      │  owns assessment truth
                    │ + core/world.StatePublisher   │  publishes WorldState
                    └───────────────┬───────────────┘
                                    │ WorldState 1.0
                                    ▼
                    ┌───────────────────────────────┐
                    │ DECISION ENGINE core/decision │  WorldStateView (read-only projection)
                    │  reuses planning/ heuristics  │  optional DecisionProposal 1.0
                    └───────────────┬───────────────┘
                                    │ ActionRequest 1.0
                                    ▼
                    ┌───────────────────────────────┐
                    │ EXECUTION ENGINE core/exec    │  prepare(): derive params, pick tool
                    │  ExecutionGateway+Artifacts   │
                    └───────┬───────────────┬───────┘
              prepared      │               │  ExecutionResult 1.0
              ActionRequest ▼               ▼
                    ┌───────────────┐  ┌───────────────────────┐
                    │ POLICY        │  │ EVIDENCE ENGINE       │
                    │ core/policy   │  │ core/evidence         │
                    └───────┬───────┘  └───────────┬───────────┘
        ActionValidationResult│                    │ EvidenceSet 1.0
              (approve/reject)│                    ├──────────────────────┐
                              ▼                    ▼                      ▼
                        execute / reject    ┌──────────────┐      WORLD MODEL
                                            │ VERIFICATION │      (apply observations)
                                            │ core/verif.  │
                                            └──────┬───────┘
                              VerificationResult 1.0│  VerificationActionRequest
                                    ┌───────────────┴──────────────► DECISION ENGINE
                                    ▼                                        (never executes tools)
                              WORLD MODEL / FINDINGS
                                    │
                                    ▼
                          EXPERIENCE (ExperienceRecord 1.0, state hashes)
```

### Ordering question and its resolution

Spec §11 requires `ActionRequest → scope → capability → parameter validation → execution`,
but the philosophy document requires parameters to be *derived from assessment state*, which
is an Execution Engine responsibility ("the Execution Engine is responsible for determining
how that capability is implemented"). These two rules cannot both hold if validation runs
before derivation.

**Resolution (documented, deterministic):** execution is split into two stages.

1. `ExecutionGateway.prepare(ActionRequest)` — no side effects: resolves the implementing
   tool, derives parameters from state, selects the interface, and returns a *prepared*
   ActionRequest whose `parameters` are concrete.
2. `ActionPolicy.validate(prepared_request)` — scope, capability and parameter checks on the
   concrete values. Only an `approved` result reaches `ExecutionGateway.run()`.

This preserves both rules and keeps validation before any real invocation.

### Decision Engine boundary

The Decision Engine receives **only** a `WorldState` message. `core/decision/state_view.py`
builds a read-only projection (`WorldStateView`) from that message, which exposes exactly the
attributes the existing `UncertaintyIdentifier` / `ActionSelector` / `AssessmentPlanner`
already consume. The existing heuristic modules are therefore reused unchanged, but they now
operate on contract data rather than on live model objects.

Capability *metadata* is not duplicated into the contract payload: `WorldState.capabilities`
carries names plus availability, and the view resolves metadata through the injected
`CapabilityRegistry` (the registry is the Decision Engine's own catalogue of what can be
requested, not World Model state).

`WorldStateView` is disposable. The planner writes its computed uncertainties onto the view;
that write never propagates to the World Model, satisfying "the Decision Engine guarantees
that it will treat the received state as read-only".

## 4. Tech stack decisions

| Decision | Choice | Justification |
|---|---|---|
| New dependencies | **none** | Contracts use stdlib `dataclasses`, `enum`, `uuid`, `hashlib`, `json`, `datetime`. Guideline 16. |
| Contract representation | frozen/immutable dataclasses | Spec §16 requires immutable messages. |
| Envelope shape | CloudEvents 1.0-aligned | `schema`≈`type`, `version`≈`specversion`, `message_id`≈`id`, `source_engine`≈`source`, `timestamp`≈`time`, `payload`≈`data`, `correlation_id` = extension attribute. CloudEvents requires `specversion`, `id`, `source`, `type` and treats `time` as RFC 3339 — the same discipline the spec asks for. |
| Versioning | SemVer `MAJOR.MINOR` | Major = breaking, minor = compatible addition; consumers reject unknown majors. |
| Provenance model | W3C PROV-aligned | `wasGeneratedBy` → `provenance.execution_id`; `used` → `derived_from` artifacts; `wasDerivedFrom` → observation ← evidence ← execution ← action. PROV-O is a W3C Recommendation (2013-04-30) defining Entity/Activity/Agent with exactly these relations. |
| Evidence combination | noisy-OR over independent sources | `c = 1 − Π(1 − cᵢ)`; standard combination under source independence, which the "different tool" independence rule establishes. |
| Artifacts | files + SHA-256 manifest | Integrity and auditability without inflating contract messages. |

Sources consulted: CloudEvents 1.0 attribute set (cloudevents.io / CloudEvents SDK docs,
Google Cloud "CloudEvents — JSON event format"); Semantic Versioning 2.0.0 rules for
MAJOR/MINOR/PATCH; W3C PROV-O overview (Entity, Activity, Agent, `wasGeneratedBy`, `used`,
`wasAssociatedWith`, `wasDerivedFrom`).

## 5. Milestones

| M | Deliverable | Acceptance criteria |
|---|---|---|
| M1 | `contracts/` package: envelope, errors, common refs, base contract, validation, registry | Every contract serialises to enveloped **and** flat form and round-trips; unsupported major version raises; naive timestamps rejected |
| M2 | Ten contracts of the ownership table | Field sets match spec §3–§13; all enums match the spec's listed states |
| M3 | `core/execution/artifacts.py` | stdout/stderr/files stored with sha256, size, manifest; execution result carries references |
| M4 | `core/world`, `core/policy`, `core/evidence`, `core/verification`, `core/decision` | Each produces/consumes only its contracts; verification never invokes a tool |
| M5 | `AssessmentEngine` rewired through contracts; legacy methods preserved | v0.3.0 public methods still work; 24 pre-existing tests still pass unmodified |
| M6 | Correlation chain + audit contract trail | Report contains `assessment_id → action_id → execution_id → evidence_id → verification_id` for every finding |
| M7 | Tests | New contract/policy/evidence/verification/integration tests pass; end-to-end loop proven with a real executable fixture |
| M8 | Docs | `docs/DATA_CONTRACTS.md`, ARCHITECTURE + README updates, CHANGELOG 0.4.0, AGENT-EXPERIENCE entry |

## 6. Quality gates

1. `pytest` green (pre-existing 24 tests **unmodified** + new suites).
2. No new runtime dependency; `pyyaml` remains the only required third-party import.
3. No `shell=True`; commands stay argument lists.
4. Every new module imports cleanly on a machine with **no** wireless hardware and **no**
   Kali tools (this repository's CI-equivalent condition), because contracts and engines must
   be testable independently of tool availability.
5. No dead code: every contract has a producer, a consumer and a test.
6. Failure honesty: a failed execution stays `failed`; an unavailable capability yields
   `unsupported`, never a fabricated success.

## 7. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Rewiring the engine regresses v0.3.0 behaviour | High | Keep all legacy signatures; run the pre-existing suite unmodified as the regression gate; `run_single_action` accepts both dict and ActionRequest |
| `WorldStateView` shim drifts from planner expectations | Medium | Integration test plans from a **serialised→deserialised** WorldState, so any missing field fails loudly |
| Contract boilerplate becomes junk abstraction | Medium | One generic serialiser in `base.py`; contracts declare fields only |
| Cannot verify against real radios in this sandbox | High (honesty) | Explicitly report as **not verified**; tests use a real executable fixture and are labelled as fixtures, never as assessment data |
| Artifact files fill disk | Low | Size cap + truncation flag recorded in the artifact metadata |

## 8. Verification honesty statement (completed at M8)

### Environment

Python 3.11.2, Debian sandbox, **no wireless hardware and no Kali toolchain**. The only relevant
binaries present are `curl`, `wget`, `ftp`, `openssl` and `sh`; all 54 wireless capabilities report
unavailable. Tests were run with `.venv/bin/python -m pytest` from the repository root.

### What was verified

| Claim | How it was verified |
|---|---|
| M1–M2: contracts serialise in both wire forms, round-trip, negotiate versions, reject naive timestamps | `tests/test_contracts.py` — 49 tests |
| M3: artifacts stored with sha256 and size, referenced from `execution-result` | `test_contract_pipeline.py::test_artifacts_are_written_to_disk_and_hashed` reads the file back and recomputes the hash |
| M4: each subsystem produces/consumes only its contracts; verification never invokes a tool | `test_evidence_engine.py` (28), `test_verification_engine.py` (29), `test_world_state.py` (34), `test_policy.py` (30) |
| M5: v0.3.0 public methods still work; the 24 pre-existing tests pass **unmodified** | All 24 pre-existing test *functions* are unchanged (`test_adapters` 3, `test_executor` 1, `test_models` 8, `test_parsers` 6, `test_planner` 3, `test_scope` 3). One pre-existing file was extended: `tests/test_scope.py` gained 5 additive regression tests for the scope fix below (54 insertions, **0 deletions**). Full run: 224 passed |
| M6: correlation chain per execution and contract catalogue in every report | `test_contract_pipeline.py::test_correlation_chain_links_action_to_execution_to_evidence`; a live CLI run produced a report whose `correlation_chains` entries all carry an `action_id` |
| M7: end-to-end loop proven against a real executable | `test_contract_pipeline.py` (23 tests) puts stub binaries on `PATH` and drives the production `IwDevAdapter`, `parsers/iw.py`, gateway and policy through real `subprocess` calls |
| Quality gates 1–6 | 224 tests pass in ~4s; `pyyaml` is still the only third-party runtime import; no `shell=True` (grep-verified); every module imports with no tools installed; a missing tool yields `unsupported`, never a fabricated success |

### What was **not** verified and must not be claimed

* Any behaviour depending on real wireless hardware: monitor mode, packet injection, channel
  hopping, driver/chipset capability detection, RF behaviour.
* Any behaviour depending on the presence of Kali tools — `airodump-ng`, `wash`, `reaver`, `bully`,
  `pixiewps`, `hcxdumptool`, `hcxpcapngtool`, `hashcat`, `john`, `tshark`, `kismet`, `nmap` and the
  remaining adapters. Their adapters, parsers and metadata are implemented and unit-tested where
  that is possible without the binary, but the end-to-end paths are **implemented, not
  field-verified**.
* Real handshake capture, WPS PIN recovery, credential cracking and de-authentication effects.
  These require hardware, a target in scope, and explicit written authorisation.
* Performance at scale (many APs/clients, long captures, large pcap files).

### Stub-binary tests are fixtures, not assessment data

The integration suite's stub `iw` prints a canned `iw dev` transcript. It exercises the framework's
real parsing, execution, evidence, verification and audit code — it does **not** demonstrate that a
radio was observed, and no output from it may be read as a security finding about any environment.
