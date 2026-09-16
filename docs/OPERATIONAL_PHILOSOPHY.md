# Operational Philosophy & Assessment Architecture

## Philosophy

This project is designed as a **real Wi-Fi penetration-testing and security-assessment framework**, not as a collection of simulated demonstrations, command wrappers, or placeholder tool integrations. Its purpose is to perform genuine assessments against networks and wireless environments for which the operator has explicit authorization.

The framework treats Wi-Fi penetration testing as an **adaptive investigation** rather than a fixed sequence of commands. It does not blindly execute every available tool in a predetermined order. Instead, it continuously maintains an internal model of the observed wireless environment, determines what information is currently known, identifies important uncertainties, evaluates which available action can provide useful additional evidence, and then selects and executes that action. The result of every execution becomes new evidence that can alter subsequent decisions.

## Real Tool Execution

Every operational capability exposed by the framework must correspond to a functioning implementation. When a tool is declared as supported, the framework must be capable of invoking the real underlying utility against the real wireless interface and processing its actual output. Tool adapters are responsible for translating structured parameters from the decision engine into valid tool invocations and converting the resulting output into structured observations.

The framework must never represent simulated output as genuine assessment data. It must not fabricate discoveries, pretend that an attack or verification succeeded, or provide an unfinished adapter behind a completed feature. If a capability is unavailable because of hardware, driver, operating-system, privilege, tool-version, or other environmental limitations, the framework must explicitly report the capability as unavailable and preserve that information in the assessment state.

## Adaptive Assessment

The assessment process is state-driven rather than tool-driven. A typical execution may begin with interface and capability discovery, followed by wireless observation and asset identification. From the resulting evidence, the framework determines which information remains unknown or insufficiently verified. It then selects an appropriate real capability, automatically derives and validates its parameters from the current assessment state, executes the operation, parses the result, and updates the world model.

Consequently, two assessments do not necessarily execute the same tools in the same order. An action that is useful in one environment may be unnecessary, redundant, unsupported, or inappropriate in another. The framework therefore selects actions according to the current evidence and assessment objective rather than following a rigid pipeline.

## Evidence and Verification

Raw command output is not treated as an authoritative finding by itself. Observations are parsed into structured evidence containing relevant identifiers, timestamps, sources, parameters, and confidence information. Where a conclusion requires confirmation, the framework can perform an independent verification step before promoting an observation into a confirmed finding.

The assessment state therefore distinguishes between observations, hypotheses, supported findings, verified findings, and refuted or unresolved hypotheses. This prevents transient wireless observations, incomplete scans, parser errors, and ambiguous results from automatically becoming definitive security findings.

## Capability-Aware Execution

Before an action is executed, the framework verifies that the selected wireless interface, operating system, driver, privileges, installed tool version, and current environment satisfy the action's requirements. Tool parameters are generated from structured state rather than blindly copied from static command templates.

This allows the framework to adapt to real environmental differences. An unavailable capability results in a controlled failure and replanning rather than an arbitrary command attempt. Parameter generation, validation, execution, timeout handling, output collection, and failure reporting are all treated as first-class parts of the execution system.

## Non-Sequential Tool Usage

The framework deliberately avoids the conventional model of:

`Tool A → Tool B → Tool C → Tool D`

Instead, it operates as an iterative observation-and-decision loop:

`Observe → Model → Identify uncertainty → Select action → Parameterize → Execute → Parse → Verify → Update → Re-evaluate`

A previously used tool may be selected again if new evidence makes it useful. Conversely, a tool may be skipped entirely when the required information has already been established through another observation. Tool selection is therefore determined by the state of the assessment rather than by the existence of the tool itself.

## Experience and Learning

The framework maintains an experience record describing previous actions, the state in which they were executed, their parameters, their results, their information gain, their execution cost, and whether subsequent verification supported the resulting conclusion. This experience can later be used by heuristic planners, statistical models, or optional AI-based decision systems to improve future action selection.

Learning is not required for the fundamental assessment engine to operate. The deterministic execution and evidence layers remain functional independently, while AI and learning components act as additional decision-making capabilities. This separation ensures that the framework remains operational, inspectable, and testable even when an AI model is unavailable.

## Auditability

Every meaningful assessment action should be reconstructable from the recorded execution history. The framework records the assessment scope, discovered capabilities, selected actions, generated parameters, execution results, observations, verification operations, state transitions, and final findings.

The resulting report should therefore explain not only **what was discovered**, but also **which real observation produced the evidence, which operation generated it, when it occurred, and how the framework verified or qualified the conclusion**.

## Scope and Authorization

The framework is intended for authorized security assessment of wireless environments. Operational controls must preserve the defined assessment scope and prevent the decision engine from silently expanding it. The system should clearly distinguish assets inside the authorized scope from unrelated wireless networks or devices observed in the surrounding radio environment.

The objective is not to maximize the number of commands executed. The objective is to obtain sufficient, reliable evidence to answer the assessment questions while maintaining a clear relationship between every action and the authorized assessment objective.

## Kali Linux Wireless Toolchain

The framework is designed around the real wireless-security tooling available on Kali Linux. Tools are treated as specialized instruments rather than interchangeable command wrappers. Each tool is registered with its capabilities, prerequisites, input parameters, output formats, operational characteristics, and the types of evidence it can produce.

The framework does not assume that every tool should be executed during every assessment. Tool selection is determined by the current assessment state, available hardware capabilities, authorized scope, existing evidence, and unresolved information requirements.

### Tool Categories

1. **Wireless Interface and Radio Management**: aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng, etc.), iw, iwconfig, rfkill, ethtool
2. **Wireless Discovery and Reconnaissance**: Kismet (long-running), airodump-ng, wash, horst, wavemon
3. **Wireless Packet Capture and Analysis**: Wireshark, tshark, tcpdump, dumpcap, termshark
4. **Protocol and Packet Analysis**: Scapy, macchanger, bettercap, mitmproxy
5. **WPS Assessment**: reaver, bully, pixiewps (correlated with observed WPS state)
6. **WPA/WPA2/WPA3 and Authentication Assessment**: hcxdumptool, hcxpcapngtool, hashcat, john (distinguish capture acquisition, material conversion, offline analysis, verification)
7. **Wireless/Network Discovery Beyond Radio Layer**: Nmap, arp-scan, netdiscover, fping, dnsenum, dnsrecon, dig
8. **Service and Network Enumeration**: smbclient, smbmap, enum4linux-ng, ldapsearch, snmpwalk, nbtscan, rpcclient, ftp, curl, wget, openssl s_client
9. **Vulnerability Assessment**: Greenbone/OpenVAS, Nuclei, Nikto (only when prerequisites satisfied)
10. **Framework and Credential Utilities**: Metasploit, Impacket, Responder (broader network-security phase)

## Tool Capability Model

Every registered tool should expose machine-readable metadata:

```yaml
tool:
  name: airodump-ng
  category: wireless_observation

requirements:
  operating_system:
    - linux

  interface:
    required: true

  capabilities:
    - monitor_mode

inputs:
  - interface
  - channel
  - observation_scope

outputs:
  - access_points
  - clients
  - channels
  - signal_observations
  - authentication_observations

operational_properties:
  mode: active_observation
  persistent: true

failure_conditions:
  - interface_unavailable
  - unsupported_driver
  - insufficient_privileges
  - invalid_parameters
  - timeout
```

The exact schema can differ between tools, but every adapter must provide enough information for the planner to determine whether the tool is actually usable.

## Tool Selection

The framework must never interpret the presence of a tool as a requirement to execute it.

For example:

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

Likewise, discovering an IP address does not automatically justify running every network scanner installed on Kali. The framework should determine what information is missing, whether the target is inside the authorized scope, whether a capability is appropriate, and whether existing evidence already answers the relevant question.

## Raw Tool vs Framework Capability

The framework maintains a strict distinction between:

**Raw tool**: The actual Kali/Linux executable or software component.

**Adapter**: The integration layer that translates structured framework state into the tool's native interface.

**Capability**: The higher-level operation exposed to the decision engine.

**Evidence parser**: The component that converts raw tool output into structured observations.

For example:

```
airodump-ng
     ↓
airodump adapter
     ↓
wireless_observation capability
     ↓
structured observations
     ↓
world model
```

This architecture allows the framework to replace or combine underlying tools without changing the decision engine.

## Operational Integrity

A tool is considered implemented only when its real execution path, parameter handling, output collection, parsing, failure handling, and capability requirements have been implemented and tested against the corresponding real environment.

The framework therefore does not count any of the following as completed functionality:

* placeholder adapters
* fabricated command output
* simulated discoveries presented as real results
* hard-coded vulnerability findings
* command templates without execution support
* parser stubs
* empty attack modules
* undocumented tool limitations

The objective is a functioning assessment system in which every reported observation can be traced back to an actual operation performed by an actual supported tool or a directly implemented capability.
