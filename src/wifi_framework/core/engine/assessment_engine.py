"""
Assessment engine - main orchestrator.

Implements iterative observation-and-decision loop:
Observe → Model → Identify uncertainty → Select action → Parameterize → Execute → Parse → Verify → Update → Re-evaluate

A previously used tool may be selected again if new evidence makes it useful.
Conversely, a tool may be skipped entirely when required information has already
been established through another observation.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..models.assessment_state import AssessmentState, AssessmentPhase, InterfaceInfo
from ..models.scope import AssessmentScope, ScopeEnforcer
from ..models.finding import Finding, FindingCategory, FindingSeverity, FindingStatus
from ..models.evidence import EvidenceType
from ..execution.registry import CapabilityRegistry, get_global_registry
from ..execution.executor import CapabilityExecutor
from ..planning.planner import AssessmentPlanner
from ..audit.logger import AuditLogger
from ..experience.store import ExperienceStore
from ...utils.system import get_interface_list, get_os_info
from ...tools.registry_loader import load_all_adapters


class AssessmentEngine:
    """
    Main assessment engine.

    Adaptive, state-driven, capability-aware, auditable.
    """

    def __init__(
        self,
        scope: AssessmentScope,
        registry: CapabilityRegistry = None,
        audit_logger: AuditLogger = None,
        experience_store: ExperienceStore = None,
        assessment_state: AssessmentState = None,
    ):
        self.scope = scope
        self.scope_enforcer = ScopeEnforcer(scope)

        # Registry
        if registry is None:
            registry = get_global_registry()
            load_all_adapters(registry)
        self.registry = registry

        # State
        if assessment_state is None:
            self.state = AssessmentState(scope=scope)
        else:
            self.state = assessment_state

        # Executor
        self.executor = CapabilityExecutor(registry, self.state)

        # Planner
        self.planner = AssessmentPlanner(registry)

        # Audit
        if audit_logger is None:
            audit_logger = AuditLogger(assessment_id=self.state.id)
        self.audit_logger = audit_logger
        self.audit_logger.log_scope(scope)

        # Experience
        if experience_store is None:
            experience_store = ExperienceStore()
        self.experience_store = experience_store

        # Load experience scores into state for planner
        self.state.extra["experience_scores"] = self.experience_store.get_experience_scores()

    def discover_interfaces(self) -> List[InterfaceInfo]:
        """Discover wireless interfaces using iw and iwconfig."""
        print("[*] Discovering wireless interfaces...")

        # Use iw dev
        result = self.executor.execute("iw_dev", timeout=10, state=self.state)
        if result.success:
            print(f"    Found {len(result.evidences)} interface observations via iw")

        # Use iwconfig
        result2 = self.executor.execute("iwconfig", timeout=10, state=self.state)
        if result2.success:
            print(f"    Found {len(result2.evidences)} interface observations via iwconfig")

        # Build InterfaceInfo from evidences and system
        interfaces = {}

        # Get system interfaces
        sys_ifaces = get_interface_list()
        for iface_name in sys_ifaces:
            # Skip loopback
            if iface_name == "lo":
                continue

            # Check if we have evidence for this interface
            info = InterfaceInfo(name=iface_name, type="unknown")

            # Look for evidence
            for ev in self.state.evidences:
                if ev.evidence_type == EvidenceType.INTERFACE:
                    if ev.parsed_data.get("name") == iface_name:
                        info.type = ev.parsed_data.get("type", info.type)
                        info.mac = ev.parsed_data.get("mac") or ev.parsed_data.get("addr")
                        info.driver = ev.parsed_data.get("driver")
                        info.channel = ev.parsed_data.get("channel")
                        info.frequency = ev.parsed_data.get("frequency")
                        # Check for monitor support from iw list if available
                        if ev.parsed_data.get("supports_monitor"):
                            info.supports_monitor = True

            interfaces[iface_name] = info

        # Also parse evidences that have interface names not in sys list (like mon interfaces)
        for ev in self.state.evidences:
            if ev.evidence_type == EvidenceType.INTERFACE:
                name = ev.parsed_data.get("name")
                if name and name not in interfaces:
                    info = InterfaceInfo(name=name, type=ev.parsed_data.get("type", "unknown"))
                    info.mac = ev.parsed_data.get("mac")
                    interfaces[name] = info

        self.state.interfaces = interfaces

        print(f"[+] Discovered {len(interfaces)} interfaces: {list(interfaces.keys())}")

        return list(interfaces.values())

    def discover_capabilities(self, interface: str = None):
        """Discover available capabilities in current environment."""
        print("[*] Discovering tool capabilities...")

        available = self.registry.get_available_capabilities(interface)
        unavailable = self.registry.get_unavailable_capabilities(interface)

        self.state.available_capabilities = available
        self.state.unavailable_capabilities = unavailable

        self.audit_logger.log_capability_discovery(available, unavailable)

        print(f"[+] Available capabilities: {len(available)}")
        print(f"    Unavailable: {len(unavailable)}")
        for name, reason in list(unavailable.items())[:5]:
            print(f"      - {name}: {reason}")
        if len(unavailable) > 5:
            print(f"      ... and {len(unavailable)-5} more")

        return available, unavailable

    def run_single_action(self, action: Dict[str, Any], timeout: int = 60) -> bool:
        """Execute single planned action."""
        cap_name = action["capability_name"]
        interface = action.get("interface")
        params = action.get("parameters", {})
        uncertainty = action.get("uncertainty", {})

        print(f"[*] Executing: {cap_name} (interface={interface}) - {action.get('reason','')}")

        # Scope enforcement check
        # If action involves BSSID/SSID, check if allowed
        ssid = params.get("ssid")
        bssid = params.get("bssid") or params.get("target_bssid") or params.get("ap_mac")
        target_ip = params.get("target") or params.get("target_ip") or params.get("ip")

        # Get capability metadata to check if invasive
        meta = self.registry.get_metadata(cap_name)
        invasive = meta.operational_properties.invasive if meta else False

        if bssid or ssid:
            allowed, reason = self.scope_enforcer.check_wireless_action_allowed(ssid, bssid, invasive)
            if not allowed:
                print(f"[!] Scope enforcement blocked: {reason}")
                self.audit_logger.log_event(
                    "scope_blocked",
                    {"capability": cap_name, "ssid": ssid, "bssid": bssid, "reason": reason},
                )
                return False
        elif target_ip:
            allowed, reason = self.scope_enforcer.check_network_action_allowed(target_ip, invasive)
            if not allowed:
                print(f"[!] Scope enforcement blocked: {reason}")
                self.audit_logger.log_event(
                    "scope_blocked",
                    {"capability": cap_name, "target_ip": target_ip, "reason": reason},
                )
                return False

        self.audit_logger.log_action_selection(action)

        # Execute
        result = self.executor.execute(
            capability_name=cap_name, interface=interface, parameters=params, timeout=timeout, state=self.state
        )

        # Log execution
        if self.state.execution_history:
            last_record = self.state.execution_history[-1]
            self.audit_logger.log_execution(last_record)

        # Log evidences
        for ev in result.evidences:
            self.audit_logger.log_evidence(ev)

        # Experience
        self.experience_store.add(
            capability_name=cap_name,
            tool_binary=result.tool_binary,
            interface=interface,
            parameters=params,
            state_summary=self.state.world_model.summary(),
            uncertainty_type=uncertainty.get("type"),
            success=result.success,
            exit_code=result.exit_code,
            duration_seconds=result.duration,
            evidence_count=len(result.evidences),
            failure_reason=result.failure_reason,
        )

        # Update experience scores in state
        self.state.extra["experience_scores"] = self.experience_store.get_experience_scores()

        if result.success:
            print(f"[+] {cap_name} succeeded, {len(result.evidences)} evidences")
        else:
            print(f"[-] {cap_name} failed: {result.failure_reason}")

        return result.success

    def verify_findings(self):
        """Perform independent verification step before promoting observation to confirmed finding."""
        print("[*] Verifying findings...")

        # Simple verification: for each hypothesis, try to find supporting evidence via different tool
        for finding in self.state.findings:
            if finding.status == FindingStatus.HYPOTHESIS:
                # Example: if finding is about AP existence, verify via second scan with different tool
                if finding.category == FindingCategory.WIRELESS:
                    # Try to verify AP via tshark or second airodump
                    bssid = finding.affected_assets[0] if finding.affected_assets else None
                    if bssid and bssid in self.state.world_model.access_points:
                        # We have at least one evidence, look for second independent evidence
                        ap = self.state.world_model.access_points[bssid]
                        if len(ap.evidence_ids) >= 2:
                            # Different tools?
                            tools = set()
                            for ev_id in ap.evidence_ids:
                                ev = next((e for e in self.state.evidences if e.id == ev_id), None)
                                if ev:
                                    tools.add(ev.source.tool_name)
                            if len(tools) >= 2:
                                # Verified by multiple tools
                                # Find second evidence
                                second_ev_id = ap.evidence_ids[1]
                                finding.verify(second_ev_id, method="multi_tool_correlation")
                                self.audit_logger.log_verification(finding.id, "multi_tool_correlation", True, second_ev_id)
                                print(f"    Verified finding {finding.id} via multi-tool correlation")

    def update_findings_from_world_model(self):
        """Generate findings from world model."""
        # AP findings
        for bssid, ap in self.state.world_model.access_points.items():
            # Check if we already have finding for this AP
            existing = [f for f in self.state.findings if bssid in f.affected_assets and f.category == FindingCategory.WIRELESS]
            if existing:
                continue

            # Create finding for new AP
            finding = Finding(
                title=f"Access Point Discovered: {ap.ssid or bssid}",
                description=f"Discovered AP BSSID {bssid} SSID {ap.ssid} on channel {ap.channel} with encryption {ap.encryption}",
                category=FindingCategory.WIRELESS,
                severity=FindingSeverity.INFO,
                status=FindingStatus.HYPOTHESIS,
                confidence=0.7,
                affected_assets=[bssid],
                details=ap.to_dict(),
                evidence_ids=ap.evidence_ids,
            )

            # Check for weak encryption
            if ap.encryption:
                weak_enc = [e for e in ap.encryption if e in ["WEP", "WPA", ""]]
                if weak_enc:
                    finding.severity = FindingSeverity.HIGH
                    finding.title = f"Weak Encryption Detected: {ap.ssid or bssid}"
                    finding.description += f" Weak encryption: {weak_enc}"
                    finding.category = FindingCategory.ENCRYPTION

            # Check for WPS enabled
            if ap.wps_enabled:
                wps_finding = Finding(
                    title=f"WPS Enabled: {ap.ssid or bssid}",
                    description=f"AP {bssid} has WPS enabled, which may be vulnerable",
                    category=FindingCategory.WPS,
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.HYPOTHESIS,
                    confidence=0.8,
                    affected_assets=[bssid],
                    details=ap.to_dict(),
                    evidence_ids=ap.evidence_ids,
                )
                self.state.add_finding(wps_finding)
                self.audit_logger.log_finding(wps_finding)

            self.state.add_finding(finding)
            self.audit_logger.log_finding(finding)

    def run(self, max_iterations: int = 50, timeout_per_action: int = 60, auto_discover: bool = True) -> AssessmentState:
        """
        Run full adaptive assessment.

        Implements Observe → Model → Identify uncertainty → Select action → Parameterize → Execute → Parse → Verify → Update → Re-evaluate loop.
        """
        print(f"[=== Starting WiFi Assessment {self.state.id} ===]")
        print(f"Scope: {self.scope.to_dict()}")

        self.state.transition_phase(AssessmentPhase.INTERFACE_DISCOVERY, "Starting assessment")
        self.audit_logger.log_state_transition("initializing", "interface_discovery", "Starting")

        if auto_discover:
            self.discover_interfaces()
            self.discover_capabilities()

            self.state.transition_phase(AssessmentPhase.CAPABILITY_DISCOVERY, "Interfaces discovered")
            self.audit_logger.log_state_transition("interface_discovery", "capability_discovery", "Interfaces discovered")

            self.state.transition_phase(AssessmentPhase.WIRELESS_OBSERVATION, "Capabilities discovered")
            self.audit_logger.log_state_transition("capability_discovery", "wireless_observation", "Capabilities discovered")

        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            print(f"\n[--- Iteration {iteration} Phase: {self.state.phase.value} ---]")

            # Check if should continue
            if not self.planner.should_continue(self.state, max_iterations):
                print("[*] Planner suggests assessment complete")
                break

            # Plan next action
            action = self.planner.plan_next_action(self.state)

            if not action:
                print("[*] No further actions planned, checking phase transition")
                next_phase = self.planner.suggest_phase_transition(self.state)
                if next_phase:
                    print(f"[*] Transitioning phase {self.state.phase.value} -> {next_phase.value}")
                    old_phase = self.state.phase.value
                    self.state.transition_phase(next_phase, "Planner suggested transition")
                    self.audit_logger.log_state_transition(old_phase, next_phase.value, "Planner suggested")
                    if next_phase == AssessmentPhase.COMPLETED:
                        break
                    continue
                else:
                    print("[*] No phase transition, assessment complete")
                    break

            # Select interface for action if needed
            if not action.get("interface") and action.get("capability_metadata"):
                iface = self.planner.action_selector.select_interface(self.state, action["capability_metadata"])
                action["interface"] = iface

            # Execute action
            self.run_single_action(action, timeout=timeout_per_action)

            # Update findings from world model
            self.update_findings_from_world_model()

            # Periodic verification
            if iteration % 5 == 0:
                self.verify_findings()

            # Check for phase transition
            next_phase = self.planner.suggest_phase_transition(self.state)
            if next_phase and next_phase != self.state.phase:
                print(f"[*] Phase transition suggested: {self.state.phase.value} -> {next_phase.value}")
                old_phase = self.state.phase.value
                self.state.transition_phase(next_phase, "Automatic phase progression")
                self.audit_logger.log_state_transition(old_phase, next_phase.value, "Automatic")

        # Final verification
        self.verify_findings()

        self.state.transition_phase(AssessmentPhase.REPORTING, "Assessment loop completed")
        self.audit_logger.log_state_transition(self.state.phase.value, "reporting", "Loop completed")

        # Generate final report
        report_path = self.audit_logger.save_report(self.state)
        print(f"\n[=== Assessment Completed ===]")
        print(f"Report saved to: {report_path}")
        print(f"Summary: {self.state.summary()}")

        self.state.transition_phase(AssessmentPhase.COMPLETED, "Report generated")
        self.audit_logger.log_state_transition("reporting", "completed", "Report generated")

        return self.state
