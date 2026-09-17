"""
ActionRequest validation: structural, scope, capability and parameter checks.

Security rationale for the parameter rules (guideline 15):

* Commands are always argument lists, never shell strings, so classic shell injection is not
  reachable. The residual risk is **argument injection**: a value such as ``--essid`` or
  ``-w /etc/x`` supplied as a parameter would be interpreted by the tool as an option. Any
  identifier-like value beginning with ``-`` is therefore rejected outright.
* Control characters (newline, NUL, carriage return) are rejected in every string parameter:
  they cannot appear in a legitimate BSSID, SSID, IP or path, and they corrupt both tool
  invocations and the audit log.
* Paths are checked for shell metacharacters and rejected when they attempt to escape the
  assessment working directory via ``..``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from ...contracts.action import ActionRequest, ActionValidationResult, ValidationCheckRecord, ValidationStatus
from ...contracts.envelope import EngineId
from ...contracts.validation import ValidationIssue, ValidationLevel
from ...utils.system import is_root
from ...utils.validation import (
    CONTROL_CHARS as _CONTROL_CHARS,
    SHELL_METACHARACTERS as _METACHARACTERS,
    validate_channel,
    validate_cidr,
    validate_interface,
    validate_ip,
    validate_mac,
    validate_ssid,
)
from ..models.assessment_state import AssessmentState
from ..models.scope import AssessmentScope, ScopeEnforcer

# The forbidden-character sets are defined once, in utils.validation, and imported above: they are
# the documented statement of the rule, and keeping a second copy here would let the enforcement and
# the documentation drift apart. Values matching them are rejected, never rewritten - see the
# comment at the definition site for why sanitising a target identifier would be worse than refusing.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9._-]+$")

#: Parameter names that identify a wireless asset.
_BSSID_KEYS = ("bssid", "target_bssid", "ap_mac", "ap", "client_mac", "mac", "sta")
_SSID_KEYS = ("ssid", "essid", "target_ssid")
_IP_KEYS = ("target_ip", "ip", "host_ip", "gateway", "dnsserver")
_NETWORK_KEYS = ("network", "cidr", "subnet", "range")
_INTERFACE_KEYS = ("interface", "iface", "dev")
_PATH_KEYS = ("wordlist", "path", "file", "input_file", "output", "output_file", "write_file", "read_file", "capture_file", "pcap", "templates", "template")
_DOMAIN_KEYS = ("domain", "hostname", "host", "target_host", "url")


@dataclass(frozen=True)
class ParameterRule:
    """A named rule applied to one parameter family."""

    name: str
    keys: Tuple[str, ...]
    validator: Optional[Callable[[Any], Tuple[bool, str]]] = None
    #: Reject values that begin with ``-`` (argument injection).
    reject_leading_dash: bool = True
    #: Reject path traversal / metacharacters.
    path_like: bool = False


#: The rule set, in evaluation order.
PARAMETER_RULES: List[ParameterRule] = (
    ParameterRule("mac_address", _BSSID_KEYS, validate_mac),
    ParameterRule("ssid", _SSID_KEYS, validate_ssid),
    ParameterRule("channel", ("channel", "channels", "c"), validate_channel),
    ParameterRule("ip_address", _IP_KEYS, validate_ip),
    ParameterRule("network", _NETWORK_KEYS, validate_cidr),
    ParameterRule("interface", _INTERFACE_KEYS, validate_interface),
    ParameterRule("path", _PATH_KEYS, None, path_like=True),
    ParameterRule("domain", _DOMAIN_KEYS, None),
)


class PolicyDecision:
    """Helpers for building a structured verdict."""

    @staticmethod
    def check(check_type: str, issues: List[ValidationIssue], detail: str = "") -> ValidationCheckRecord:
        if issues:
            return ValidationCheckRecord(
                type=check_type,
                status="failed",
                detail=detail or "; ".join(issue.message for issue in issues),
                issues=[issue.to_dict() for issue in issues],
            )
        return ValidationCheckRecord(type=check_type, status="passed", detail=detail or "ok")

    @staticmethod
    def issue(level: str, code: str, message: str, field_name: Optional[str] = None) -> ValidationIssue:
        return ValidationIssue(level=level, code=code, message=message, field=field_name)


class ActionPolicy:
    """Validates ActionRequests against scope, capabilities and parameter safety."""

    def __init__(self, registry: Optional[Any] = None, scope: Optional[AssessmentScope] = None) -> None:
        self.registry = registry
        self.scope = scope

    # ------------------------------------------------------------------ public

    def validate(
        self,
        action: ActionRequest,
        state: Optional[AssessmentState] = None,
        *,
        scope: Optional[AssessmentScope] = None,
    ) -> ActionValidationResult:
        """
        Run the full validation chain over one ActionRequest.

        Returns an ``action-validation-result`` contract. Validation short-circuits: a request
        that is not structurally valid is never judged on scope, because its fields cannot be
        trusted yet.
        """
        effective_scope = scope or self.scope or (state.scope if state else None) or AssessmentScope()
        enforcer = ScopeEnforcer(effective_scope)
        checks: List[ValidationCheckRecord] = []
        rejection: Optional[Dict[str, Any]] = None
        status = ValidationStatus.APPROVED
        metadata = None

        # 1. structural -------------------------------------------------------
        structural = action.validate([ValidationLevel.STRUCTURAL])
        checks.append(PolicyDecision.check("structural", structural.issues))
        if not structural.ok:
            return self._result(
                action,
                status=ValidationStatus.REJECTED,
                checks=checks,
                rejection={
                    "code": "invalid_contract",
                    "stage": "structural",
                    "reason": "ActionRequest failed structural validation",
                    "issues": [issue.to_dict() for issue in structural.issues],
                    "retriable": False,
                },
            )

        # 2. resolve capability metadata --------------------------------------
        # Metadata is resolved before the scope check because invasiveness - the property that
        # decides whether an action needs explicit authorisation - comes from it. If the
        # capability cannot be resolved at all, invasiveness fails *closed*: an unknown
        # capability is treated as invasive rather than being waved through as passive.
        implementation, metadata = self._resolve_metadata(action, state)

        # 3. scope (specification section 11 puts scope first) ----------------
        scope_issues = self._check_scope(action, metadata, enforcer, effective_scope)
        checks.append(PolicyDecision.check("scope", scope_issues))
        if scope_issues:
            # Scope denial is always a hard rejection: the framework must never expand the
            # authorised scope, and a retry cannot make an out-of-scope target in-scope.
            return self._result(
                action,
                status=ValidationStatus.REJECTED,
                checks=checks,
                rejection={
                    "code": scope_issues[0].code,
                    "stage": "scope",
                    "reason": scope_issues[0].message,
                    "issues": [issue.to_dict() for issue in scope_issues],
                    "retriable": False,
                },
                implementation=implementation,
                interface=action.interface,
                validated_parameters=action.parameters,
            )

        # 4. capability -------------------------------------------------------
        capability_issues = self._check_capability(action, state, metadata, implementation)
        checks.append(PolicyDecision.check("capability", capability_issues))
        blocking = [issue for issue in capability_issues if issue.code not in _DEFERRABLE_CODES]
        deferrable = [issue for issue in capability_issues if issue.code in _DEFERRABLE_CODES]
        if blocking:
            return self._result(
                action,
                status=ValidationStatus.REJECTED,
                checks=checks,
                rejection={
                    "code": blocking[0].code,
                    "stage": "capability",
                    "reason": blocking[0].message,
                    "issues": [issue.to_dict() for issue in blocking],
                    "retriable": False,
                },
                implementation=implementation,
            )
        if deferrable:
            status = ValidationStatus.DEFERRED
            # A capability whose tool is unusable will not become usable mid-assessment, so the
            # Decision Engine should stop asking for it. Interface state and privileges can
            # change (monitor mode enabled, assessment re-run with rights), so those stay
            # retriable and are suppressed only for a cooldown.
            rejection = {
                "code": deferrable[0].code,
                "stage": "capability",
                "reason": deferrable[0].message,
                "issues": [issue.to_dict() for issue in deferrable],
                "retriable": deferrable[0].code != "capability_unavailable",
            }

        # 5. parameters -------------------------------------------------------
        parameter_issues = self._check_parameters(action, metadata, state)
        checks.append(PolicyDecision.check("parameters", parameter_issues))
        if parameter_issues:
            # A value that looks like argument injection or path traversal must never be
            # retried: it comes from observed state and would be regenerated unchanged. A merely
            # missing or malformed target can become valid once more is discovered, so that
            # rejection is retriable and only cooled down.
            unsafe = any(issue.code in _UNSAFE_PARAMETER_CODES for issue in parameter_issues)
            return self._result(
                action,
                status=ValidationStatus.REJECTED,
                checks=checks,
                rejection={
                    "code": parameter_issues[0].code,
                    "stage": "parameters",
                    "reason": parameter_issues[0].message,
                    "issues": [issue.to_dict() for issue in parameter_issues],
                    "retriable": not unsafe,
                },
                implementation=implementation,
                interface=action.interface,
                validated_parameters=action.parameters,
            )

        return self._result(
            action,
            status=status,
            checks=checks,
            rejection=rejection,
            implementation=implementation,
            interface=action.interface,
            validated_parameters=action.parameters,
            confidence=1.0 if status == ValidationStatus.APPROVED else 0.5,
        )

    # ---------------------------------------------------------------- capability

    def _registry_for(self, state: Optional[AssessmentState]) -> Any:
        if state is not None and getattr(state, "registry", None) is not None:
            return state.registry
        return self.registry

    def _resolve_metadata(
        self, action: ActionRequest, state: Optional[AssessmentState]
    ) -> Tuple[Optional[str], Any]:
        """Resolve the registered capability that would implement this request."""
        registry = self._registry_for(state)
        implementation = action.implementation or action.capability
        if registry is None:
            return implementation, None
        return implementation, registry.get_metadata(implementation)

    def _check_capability(
        self,
        action: ActionRequest,
        state: Optional[AssessmentState],
        metadata: Optional[Any] = None,
        implementation: Optional[str] = None,
    ) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        registry = self._registry_for(state)
        if registry is None:
            issues.append(
                PolicyDecision.issue(
                    ValidationLevel.SEMANTIC.value,
                    "no_registry",
                    "capability validation requires a capability registry",
                )
            )
            return issues

        if implementation is None:
            implementation, metadata = self._resolve_metadata(action, state)
        if metadata is None:
            issues.append(
                PolicyDecision.issue(
                    ValidationLevel.SEMANTIC.value,
                    "unknown_capability",
                    f"capability '{implementation}' is not registered",
                    "capability",
                )
            )
            return issues

        # Is the requested capability actually what this tool provides?
        if not self._capability_matches(metadata, action.capability):
            issues.append(
                PolicyDecision.issue(
                    ValidationLevel.SEMANTIC.value,
                    "capability_mismatch",
                    f"'{implementation}' (category {metadata.category.value}) cannot fulfil "
                    f"requested capability '{action.capability}'",
                    "capability",
                )
            )

        # Can it produce what the Decision Engine expects?
        if action.expected_outputs:
            missing = [output for output in action.expected_outputs if output not in metadata.outputs]
            if missing:
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.SEMANTIC.value,
                        "expected_outputs_unavailable",
                        f"'{implementation}' does not produce {missing}",
                        "expected_outputs",
                    )
                )

        # Availability: prefer the discovery results already in state (cheap), fall back to a
        # live registry probe when capability discovery has not run yet.
        available, reason = self._availability(implementation, action.interface, metadata, state, registry)
        if not available:
            issues.append(
                PolicyDecision.issue(
                    ValidationLevel.OPERATIONAL.value,
                    "capability_unavailable",
                    f"'{implementation}' is unavailable: {reason}",
                    "implementation",
                )
            )

        # Interface requirements.
        if metadata.requirements.interface_required:
            if not action.interface:
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.OPERATIONAL.value,
                        "interface_required",
                        f"'{implementation}' requires an interface but none was selected",
                        "interface",
                    )
                )
            elif state is not None and state.interfaces and action.interface not in state.interfaces:
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.OPERATIONAL.value,
                        "interface_unknown",
                        f"interface '{action.interface}' was not discovered in this environment",
                        "interface",
                    )
                )
            elif state is not None and "monitor_mode" in metadata.requirements.interface_capabilities:
                info = state.interfaces.get(action.interface)
                if info is not None and not info.supports_monitor:
                    issues.append(
                        PolicyDecision.issue(
                            ValidationLevel.OPERATIONAL.value,
                            "monitor_mode_unavailable",
                            f"interface '{action.interface}' does not support monitor mode",
                            "interface",
                        )
                    )
                if info is not None and not info.is_up:
                    issues.append(
                        PolicyDecision.issue(
                            ValidationLevel.OPERATIONAL.value,
                            "interface_down",
                            f"interface '{action.interface}' is down",
                            "interface",
                        )
                    )

        # Privileges.
        if "root" in metadata.requirements.privileges and not is_root():
            issues.append(
                PolicyDecision.issue(
                    ValidationLevel.OPERATIONAL.value,
                    "insufficient_privileges",
                    f"'{implementation}' requires root privileges",
                    "privileges",
                )
            )

        return issues

    @staticmethod
    def _capability_matches(metadata: Any, capability: str) -> bool:
        """True when the registered tool can legitimately fulfil the requested capability."""
        if capability == metadata.name:
            return True
        category = metadata.category.value if hasattr(metadata.category, "value") else str(metadata.category)
        if capability == category:
            return True
        if capability in metadata.outputs:
            return True
        return False

    @staticmethod
    def _availability(
        implementation: str,
        interface: Optional[str],
        metadata: Any,
        state: Optional[AssessmentState],
        registry: Any,
    ) -> Tuple[bool, str]:
        if state is not None and implementation in state.available_capabilities:
            return True, "reported available by capability discovery"
        if state is not None and implementation in state.unavailable_capabilities:
            return False, state.unavailable_capabilities[implementation]
        if state is not None and (state.available_capabilities or state.unavailable_capabilities):
            # Discovery ran and this capability is in neither map: treat as unavailable rather
            # than assume it works.
            return False, "not present in capability discovery results"
        return registry.check_availability(implementation, interface)[:2]

    # --------------------------------------------------------------------- scope

    def _check_scope(
        self,
        action: ActionRequest,
        metadata: Any,
        enforcer: ScopeEnforcer,
        scope: AssessmentScope,
    ) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        # Fail closed: when the capability cannot be resolved we cannot know whether it transmits,
        # so it is treated as invasive and must be explicitly authorised. Treating an unknown
        # capability as passive would let an unresolvable request through the scope gate.
        invasive = True if metadata is None else bool(metadata.operational_properties.invasive)
        params = action.parameters or {}

        ssid = self._first(params, _SSID_KEYS)
        bssid = self._first(params, _BSSID_KEYS)
        target_ip = self._first(params, _IP_KEYS)
        network = self._first(params, _NETWORK_KEYS)
        target = params.get("target")

        # An explicit target reference on the request counts as an identifier too.
        if action.target and action.target.id:
            value = str(action.target.id)
            if action.target.type == "access_point" and not bssid:
                bssid = value
            elif action.target.type == "host" and not target_ip:
                target_ip = value
            elif action.target.type == "network" and not network:
                network = value

        wireless_identified = bool(ssid or bssid)
        if wireless_identified:
            allowed, reason = enforcer.check_wireless_action_allowed(ssid, bssid, invasive)
            if not allowed:
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.OPERATIONAL.value,
                        "scope_denied_wireless",
                        reason,
                        "target",
                    )
                )
        if target_ip:
            allowed, reason = enforcer.check_network_action_allowed(str(target_ip), invasive)
            if not allowed:
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.OPERATIONAL.value,
                        "scope_denied_network",
                        reason,
                        "target_ip",
                    )
                )
        if network and not self._network_in_scope(str(network), scope, invasive):
            issues.append(
                PolicyDecision.issue(
                    ValidationLevel.OPERATIONAL.value,
                    "scope_denied_network",
                    f"network '{network}' is not within the authorised networks",
                    "network",
                )
            )
        if target and isinstance(target, str) and not wireless_identified and not target_ip and not network:
            # A free-form target (host, URL, domain) must still be inside scope when the scope
            # restricts hosts or networks; otherwise an invasive action could reach anything.
            host = self._host_from_target(target)
            if host and scope.authorized_networks or scope.authorized_hosts:
                if not enforcer.check_network_action_allowed(host, invasive)[0]:
                    issues.append(
                        PolicyDecision.issue(
                            ValidationLevel.OPERATIONAL.value,
                            "scope_denied_target",
                            f"target '{target}' is not within the authorised scope",
                            "target",
                        )
                    )

        # Channel scope: authorised_channels restricts which channels may be used.
        channel = params.get("channel")
        if channel is not None and scope.authorized_channels:
            try:
                if int(channel) not in scope.authorized_channels:
                    issues.append(
                        PolicyDecision.issue(
                            ValidationLevel.OPERATIONAL.value,
                            "scope_denied_channel",
                            f"channel {channel} is not in authorised channels {scope.authorized_channels}",
                            "channel",
                        )
                    )
            except (TypeError, ValueError):
                pass  # reported by parameter validation

        # Invasive actions with no identifiable target cannot be scope-checked at all.
        if invasive and not (wireless_identified or target_ip or network or target):
            if scope.authorized_ssids or scope.authorized_bssids or scope.authorized_networks or scope.authorized_hosts:
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.OPERATIONAL.value,
                        "invasive_without_target",
                        "an invasive action must name a target so scope can be enforced",
                        "target",
                    )
                )

        return issues

    @staticmethod
    def _network_in_scope(network: str, scope: AssessmentScope, invasive: bool) -> bool:
        if not scope.authorized_networks:
            return not (invasive and scope.strict_mode)
        import ipaddress

        try:
            candidate = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return False
        for authorised in scope.authorized_networks:
            try:
                allowed_network = ipaddress.ip_network(authorised, strict=False)
            except ValueError:
                continue
            if allowed_network.version != candidate.version:
                # ``subnet_of`` raises TypeError across address families rather than
                # returning False, and this comparison sits outside the try above. A
                # scope authorizing both an IPv4 and an IPv6 network therefore crashed
                # the check - and whether it crashed depended on declaration order,
                # because an entry that matched first returned before the mismatched
                # one was reached. An address is never inside an authorization of the
                # other family, so the pair is simply not a match.
                continue
            # The family check above establishes what mypy cannot narrow from an int
            # attribute comparison: both operands are the same address family here.
            # isinstance narrowing does not help either, since mypy will not correlate
            # the types of two variables across branches. The invariant is tested
            # (test_policy.py, mixed-family scope) rather than asserted.
            if candidate.subnet_of(allowed_network) or candidate == allowed_network:  # type: ignore[arg-type]
                return True
        return False

    @staticmethod
    def _host_from_target(target: str) -> Optional[str]:
        """Best-effort extraction of a host from a free-form target string."""
        text = target.strip()
        if "://" in text:
            text = text.split("://", 1)[1]
        text = text.split("/", 1)[0]
        if "@" in text:
            text = text.rsplit("@", 1)[1]
        text = text.split(":", 1)[0]
        return text or None

    @staticmethod
    def _first(params: Dict[str, Any], keys: Tuple[str, ...]) -> Optional[Any]:
        for key in keys:
            value = params.get(key)
            if value not in (None, ""):
                return value
        return None

    # ---------------------------------------------------------------- parameters

    def _check_parameters(
        self, action: ActionRequest, metadata: Any, state: Optional[AssessmentState]
    ) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        params = action.parameters or {}

        for key, value in params.items():
            issues.extend(self._check_value(key, value))

        # Rule-specific validation.
        for rule in PARAMETER_RULES:
            for key in rule.keys:
                if key not in params or params[key] in (None, ""):
                    continue
                value = params[key]
                if rule.validator is None:
                    continue
                # ``channel`` may legitimately be a list; validate each element.
                values = value if isinstance(value, (list, tuple)) and key in ("channel", "channels") else [value]
                for item in values:
                    ok, message = rule.validator(item)
                    if not ok:
                        issues.append(
                            PolicyDecision.issue(
                                ValidationLevel.SEMANTIC.value,
                                f"invalid_{rule.name}",
                                f"parameter '{key}': {message}",
                                key,
                            )
                        )

        # Declared inputs of the capability that the request never supplied. Only enforced for
        # a prepared request: before preparation, parameters are derived by the Execution Engine.
        if action.prepared and metadata is not None:
            supplied = dict(params)
            # The interface has a dedicated contract field. The Execution Engine resolves it as
            # ``request.interface or parameters["interface"]``, so policy must accept either
            # placement or it would reject a correctly prepared request.
            if action.interface and not supplied.get("interface"):
                supplied["interface"] = action.interface
            required = [
                name
                for name in metadata.inputs
                if name in _REQUIRED_INPUT_NAMES
                and supplied.get(name) in (None, "")
                # Interface requirements are owned by the capability stage, which also knows
                # whether the interface exists, is up and supports monitor mode. Re-reporting a
                # missing interface here would turn an environmental gap ("no monitor interface
                # yet") into a hard rejection instead of a deferral the engine can act on.
                and not (name == "interface" and metadata.requirements.interface_required)
            ]
            for name in required:
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.SEMANTIC.value,
                        "missing_parameter",
                        f"capability '{metadata.name}' requires parameter '{name}'",
                        name,
                    )
                )

        # Domain-like values get a shape check (no validator in the rule set).
        for key in _DOMAIN_KEYS:
            value = params.get(key)
            if isinstance(value, str) and value and not _HOSTNAME_RE.match(self._strip_scheme(value)):
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.SEMANTIC.value,
                        "invalid_domain",
                        f"parameter '{key}' is not a valid host/domain/URL: {value!r}",
                        key,
                    )
                )
        return issues

    @staticmethod
    def _strip_scheme(value: str) -> str:
        text = value.split("://", 1)[1] if "://" in value else value
        return text.split("/", 1)[0]

    @staticmethod
    def _check_value(key: str, value: Any) -> List[ValidationIssue]:
        """Checks that apply to every parameter regardless of its family."""
        issues: List[ValidationIssue] = []
        if isinstance(value, bytes):
            issues.append(
                PolicyDecision.issue(
                    ValidationLevel.SEMANTIC.value,
                    "bytes_parameter",
                    f"parameter '{key}' must be text, not bytes",
                    key,
                )
            )
            return issues
        if not isinstance(value, str):
            if isinstance(value, (list, tuple)):
                for index, item in enumerate(value):
                    issues.extend(ActionPolicy._check_value(f"{key}[{index}]", item))
            elif isinstance(value, dict):
                for sub_key, item in value.items():
                    issues.extend(ActionPolicy._check_value(f"{key}.{sub_key}", item))
            return issues

        for char in _CONTROL_CHARS:
            if char in value:
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.SEMANTIC.value,
                        "control_character",
                        f"parameter '{key}' contains a control character",
                        key,
                    )
                )
                break
        for token in _METACHARACTERS:
            if token in value:
                issues.append(
                    PolicyDecision.issue(
                        ValidationLevel.SEMANTIC.value,
                        "shell_metacharacter",
                        f"parameter '{key}' contains {token!r}, which is not permitted",
                        key,
                    )
                )
                break
        if value.startswith("-"):
            # Argument injection: the tool would read this value as one of its own options.
            issues.append(
                PolicyDecision.issue(
                    ValidationLevel.SEMANTIC.value,
                    "argument_injection_risk",
                    f"parameter '{key}' begins with '-' and would be parsed as an option: {value!r}",
                    key,
                )
            )
        if ".." in value.split("/") or value.startswith("/") and ".." in value:
            issues.append(
                PolicyDecision.issue(
                    ValidationLevel.SEMANTIC.value,
                    "path_traversal",
                    f"parameter '{key}' attempts to traverse directories: {value!r}",
                    key,
                )
            )
        return issues

    # -------------------------------------------------------------------- result

    def _result(
        self,
        action: ActionRequest,
        *,
        status: str,
        checks: List[ValidationCheckRecord],
        rejection: Optional[Dict[str, Any]] = None,
        implementation: Optional[str] = None,
        interface: Optional[str] = None,
        validated_parameters: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
    ) -> ActionValidationResult:
        return ActionValidationResult(
            assessment_id=action.assessment_id,
            source_engine=EngineId.POLICY.value,
            correlation_id=action.correlation_id,
            action_id=action.action_id,
            status=status,
            checks=checks,
            rejection=rejection,
            validated_parameters=dict(validated_parameters or {}),
            implementation=implementation,
            interface=interface,
            confidence=confidence,
        )


#: Capability failures that mean "not now" rather than "never".
_DEFERRABLE_CODES = {
    "capability_unavailable",
    "interface_required",
    "interface_unknown",
    "interface_down",
    "monitor_mode_unavailable",
    "insufficient_privileges",
}

#: Parameter problems that indicate an unsafe value rather than an incomplete one. These are
#: never retriable: the value came from observed state and would be regenerated identically.
_UNSAFE_PARAMETER_CODES = {
    "argument_injection_risk",
    "control_character",
    "shell_metacharacter",
    "path_traversal",
    "bytes_parameter",
}

#: Inputs that must be present on a prepared request when the capability declares them.
_REQUIRED_INPUT_NAMES = {"interface", "bssid", "target_bssid", "ssid", "target_ip", "ip", "target", "domain"}
