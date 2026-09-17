"""
Tests for ``utils.validation`` - the input validators and the forbidden-character rule.

Two things are pinned here beyond the validators' own behaviour:

1. The forbidden-character sets are defined **once**, in ``utils.validation``, and ``ActionPolicy``
   imports those very objects. Two copies would drift, and the documentation would describe
   neither.
2. There is no ``sanitize_command_arg``. A function by that name shipped in 0.1.0, did nothing, and
   let four documents claim a sanitisation control that did not exist. It must not return quietly:
   the framework *rejects* unsafe values rather than rewriting them, because a rewritten SSID or
   BSSID would aim an assessment at a target the operator never authorised.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import wifi_framework
from wifi_framework.core.policy import validator as policy_validator
from wifi_framework.utils import validation
from wifi_framework.utils.validation import (
    CONTROL_CHARS,
    SHELL_METACHARACTERS,
    normalize_mac,
    validate_channel,
    validate_cidr,
    validate_interface,
    validate_ip,
    validate_mac,
    validate_parameters,
    validate_ssid,
)

PACKAGE_ROOT = Path(wifi_framework.__file__).parent


# ------------------------------------------------------------------------- MAC / BSSID


@pytest.mark.parametrize(
    "value",
    [
        "AA:BB:CC:DD:EE:FF",
        "aa:bb:cc:dd:ee:ff",
        "AA-BB-CC-DD-EE-FF",
        "AABBCCDDEEFF",  # 12 hex digits, no separators
        "00:11:22:33:44:55",
    ],
)
def test_valid_mac_forms_are_accepted(value):
    ok, message = validate_mac(value)
    assert ok is True
    assert message == ""


@pytest.mark.parametrize(
    "value,reason",
    [
        ("", "empty"),
        ("AA:BB:CC:DD:EE", "too short"),
        ("AA:BB:CC:DD:EE:FF:00", "too long"),
        ("AA:BB:CC:DD:EE:GG", "non-hex"),
        ("not-a-mac", "garbage"),
        ("AA:BB:CC:DD:EE:F", "truncated octet"),
    ],
)
def test_invalid_mac_forms_are_rejected(value, reason):
    ok, message = validate_mac(value)
    assert ok is False, reason
    assert message


def test_mixed_separators_are_rejected():
    """
    Tightened in 0.4.0. ``AA:BB-CC:DD-EE:FF`` used to pass, because the old implementation stripped
    every non-hex character and only counted what was left. Accepting it required accepting the
    stripping that also turned ``AABBCCDDEEFFGG`` into a different, valid-looking address. Each
    accepted spelling is now exact: colons, dashes, or bare - never a mixture.
    """
    assert validate_mac("AA:BB-CC:DD-EE:FF")[0] is False
    assert normalize_mac("AA:BB-CC:DD-EE:FF") is None


def test_rejection_message_names_the_offending_value():
    assert "not-a-mac" in validate_mac("not-a-mac")[1]


@pytest.mark.parametrize(
    "value,expected",
    [
        ("aabbccddeeff", "AA:BB:CC:DD:EE:FF"),
        ("AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF"),
        ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"),
        ("  AA:BB:CC:DD:EE:FF  ", "AA:BB:CC:DD:EE:FF"),
    ],
)
def test_normalize_mac_returns_upper_colon_form(value, expected):
    assert normalize_mac(value) == expected


@pytest.mark.parametrize("value", ["", None, "AA:BB:CC", "AABBCCDDEEFFGG"])
def test_normalize_mac_returns_none_when_it_cannot_normalise(value):
    """``None`` rather than a guess: callers must not receive a fabricated address."""
    assert normalize_mac(value) is None


def test_normalize_is_idempotent():
    once = normalize_mac("aabbccddeeff")
    assert normalize_mac(once) == once


# ------------------------------------------------------------------------------- SSID


def test_ssid_within_the_32_byte_limit_is_valid():
    assert validate_ssid("TestNet")[0] is True


def test_empty_ssid_is_valid_because_hidden_networks_exist():
    ok, message = validate_ssid("")
    assert ok is True
    assert message == ""


def test_ssid_longer_than_32_is_rejected():
    ok, message = validate_ssid("a" * 33)
    assert ok is False
    assert "33" in message and "32" in message


def test_ssid_of_exactly_32_is_accepted():
    assert validate_ssid("a" * 32)[0] is True


def test_none_ssid_is_rejected_rather_than_treated_as_empty():
    ok, message = validate_ssid(None)
    assert ok is False
    assert "None" in message


def test_ssid_with_shell_metacharacters_passes_the_validator_and_is_stopped_by_policy():
    """
    Deliberate division of labour, pinned so it is not mistaken for a hole.

    ``validate_ssid`` checks *shape* only. A network legitimately named ``Cafe$WiFi`` must stay
    usable, so this validator accepts it; refusing it is the policy layer's job when the value is
    about to be handed to a tool. Rewriting it here would corrupt a real SSID.
    """
    assert validate_ssid("Cafe$WiFi")[0] is True
    issues = policy_validator.ActionPolicy._check_value("ssid", "Cafe$WiFi; rm -rf /")
    assert any(issue.code == "shell_metacharacter" for issue in issues)


# ------------------------------------------------------------------------------ channel


@pytest.mark.parametrize("value", [1, 6, 11, 36, 149, 196, "6", "196"])
def test_channels_in_range_are_valid(value):
    assert validate_channel(value)[0] is True


@pytest.mark.parametrize("value", [0, -1, 197, 1000])
def test_channels_out_of_range_are_rejected(value):
    ok, message = validate_channel(value)
    assert ok is False
    assert "1-196" in message


@pytest.mark.parametrize("value", [None, "six", "", [], {}])
def test_non_integer_channel_is_rejected(value):
    ok, message = validate_channel(value)
    assert ok is False
    assert "integer" in message


def test_channel_boundaries_are_inclusive():
    assert validate_channel(1)[0] is True
    assert validate_channel(196)[0] is True
    assert validate_channel(0)[0] is False
    assert validate_channel(197)[0] is False


# ---------------------------------------------------------------------------- interface


@pytest.mark.parametrize("value", ["wlan0", "wlan0mon", "eth0.100", "mon_0", "wlx00c0ca"])
def test_plausible_interface_names_are_valid(value):
    assert validate_interface(value)[0] is True


def test_empty_interface_is_rejected():
    assert validate_interface("")[0] is False


@pytest.mark.parametrize(
    "value",
    [
        "wlan0mon; rm -rf /",  # injection attempt
        "wlan0 && id",
        "wlan0`id`",
        "$(whoami)",
        "wlan 0",  # space
        "/etc/passwd",
        "..",
        "wlan0\n",
    ],
)
def test_interface_names_with_metacharacters_are_rejected(value):
    """This validator is the first line of defence: the name is also used to build paths."""
    ok, message = validate_interface(value)
    assert ok is False, value
    assert "Invalid interface name" in message


def test_interface_name_at_the_linux_ifnamsiz_limit():
    assert validate_interface("a" * 15)[0] is True
    ok, message = validate_interface("a" * 16)
    assert ok is False
    assert "too long" in message


# -------------------------------------------------------------------------------- IP/CIDR


@pytest.mark.parametrize("value", ["192.168.1.1", "10.0.0.1", "8.8.8.8", "::1", "fe80::1"])
def test_valid_addresses_are_accepted(value):
    assert validate_ip(value)[0] is True


@pytest.mark.parametrize("value", ["999.1.1.1", "192.168.1", "not-an-ip", "", "192.168.1.1/24"])
def test_invalid_addresses_are_rejected(value):
    assert validate_ip(value)[0] is False


@pytest.mark.parametrize("value", ["192.168.1.0/24", "10.0.0.0/8", "192.168.1.5/24", "::1/128"])
def test_valid_networks_are_accepted(value):
    assert validate_cidr(value)[0] is True


def test_host_bits_are_tolerated_because_scope_entries_are_written_by_humans():
    """``strict=False`` is intentional: ``192.168.1.5/24`` is how operators write scope."""
    assert validate_cidr("192.168.1.5/24")[0] is True


@pytest.mark.parametrize("value", ["192.168.1.0/33", "/24", "not-a-cidr", ""])
def test_invalid_networks_are_rejected(value):
    assert validate_cidr(value)[0] is False


# ------------------------------------------------------------------- validate_parameters


def test_all_required_parameters_present_is_valid():
    ok, errors = validate_parameters({"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6}, ["bssid", "channel"])
    assert ok is True
    assert errors == []


def test_missing_required_parameter_is_reported():
    ok, errors = validate_parameters({"channel": 6}, ["bssid", "channel"])
    assert ok is False
    assert errors == ["Missing required parameter: bssid"]


def test_present_but_none_counts_as_missing():
    """A parameter explicitly set to ``None`` was not supplied."""
    ok, errors = validate_parameters({"bssid": None}, ["bssid"])
    assert ok is False
    assert errors == ["Missing required parameter: bssid"]


def test_every_missing_parameter_is_reported_not_just_the_first():
    ok, errors = validate_parameters({}, ["bssid", "channel", "interface"])
    assert ok is False
    assert len(errors) == 3


def test_custom_validators_are_applied():
    ok, errors = validate_parameters(
        {"bssid": "not-a-mac", "channel": 6},
        ["bssid"],
        {"bssid": validate_mac, "channel": validate_channel},
    )
    assert ok is False
    assert errors == ["Parameter bssid: Invalid MAC format: not-a-mac"]


def test_custom_validators_pass_on_good_values():
    ok, errors = validate_parameters(
        {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6},
        ["bssid", "channel"],
        {"bssid": validate_mac, "channel": validate_channel},
    )
    assert ok is True
    assert errors == []


def test_validators_are_skipped_for_absent_or_none_values():
    """A validator must not be asked to judge a value that was never supplied."""
    ok, errors = validate_parameters({}, [], {"bssid": validate_mac})
    assert ok is True
    assert errors == []

    ok, errors = validate_parameters({"bssid": None}, [], {"bssid": validate_mac})
    assert ok is True
    assert errors == []


def test_multiple_validator_failures_are_all_reported():
    ok, errors = validate_parameters(
        {"bssid": "nope", "channel": 999},
        [],
        {"bssid": validate_mac, "channel": validate_channel},
    )
    assert ok is False
    assert len(errors) == 2


# ------------------------------------------------- the forbidden-character rule, single-sourced


def test_forbidden_character_sets_are_defined_once_and_shared_with_the_policy_layer():
    """
    ``ActionPolicy`` must import these objects, not redefine them.

    Identity (not equality) is asserted on purpose: a second tuple with the same contents would
    pass an equality check and then drift.
    """
    assert policy_validator._CONTROL_CHARS is CONTROL_CHARS
    assert policy_validator._METACHARACTERS is SHELL_METACHARACTERS


def test_forbidden_character_sets_are_not_empty():
    """An empty set would silently disable the control while every test still passed."""
    assert CONTROL_CHARS
    assert SHELL_METACHARACTERS


@pytest.mark.parametrize("char", ["\n", "\r", "\x00"])
def test_control_characters_are_listed(char):
    assert char in CONTROL_CHARS


@pytest.mark.parametrize("token", [";", "&", "|", "`", "$(", ">", "<"])
def test_shell_metacharacters_are_listed(token):
    assert token in SHELL_METACHARACTERS


def test_the_policy_layer_rejects_every_listed_character():
    """The sets are not decorative: each entry actually produces a rejection."""
    for char in CONTROL_CHARS:
        issues = policy_validator.ActionPolicy._check_value("ssid", f"TestNet{char}X")
        assert any(issue.code == "control_character" for issue in issues), repr(char)
    for token in SHELL_METACHARACTERS:
        issues = policy_validator.ActionPolicy._check_value("ssid", f"TestNet{token}X")
        assert any(issue.code == "shell_metacharacter" for issue in issues), repr(token)


# ------------------------------------------------------------------ the removed no-op guard


def test_no_sanitize_command_arg_helper_exists():
    """
    Removed in 0.4.0: it iterated over dangerous characters, discarded each match, and returned its
    input unchanged, while four documents cited it as a security control.

    If sanitisation is ever genuinely needed it must be a real control with tests - not a function
    whose name promises protection and whose body delivers none.
    """
    assert not hasattr(validation, "sanitize_command_arg")
    assert "sanitize_command_arg" not in getattr(validation, "__all__", [])


def test_no_module_in_the_package_invokes_a_shell():
    """
    The structural reason rejection is sufficient: nothing is ever handed to a shell.

    Checked by parsing the AST of every module rather than grepping, so a `shell=True` hidden in a
    kwargs dict, a comment or a string cannot slip through - and so the defensive comment in
    ``utils/validation.py`` that mentions the phrase is not mistaken for a call.
    """
    offenders = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is not False:
                        offenders.append(f"{path.relative_to(PACKAGE_ROOT)}:{node.lineno}")
    assert offenders == []


def test_no_module_executes_caller_supplied_code():
    """
    ``exec``/``eval``/``compile`` on data is an arbitrary-code-execution primitive that bypasses
    every other control in this codebase: the policy layer rejects shell metacharacters, but pure
    Python needs none of them, and the no-shell sweep above cannot see it because no shell is
    involved. ``ScapyAdapter`` used to ``exec()`` a ``script`` parameter with full ``__builtins__``;
    this pins that the pattern cannot come back.

    Only bare-name calls are matched, so ``re.compile(...)`` - an attribute access, used widely and
    legitimately - is not flagged.
    """
    offenders = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id in ("exec", "eval", "compile"):
                offenders.append(f"{path.relative_to(PACKAGE_ROOT)}:{node.lineno} {node.func.id}()")
    assert offenders == [], f"dynamic code execution found: {offenders}"


def test_a_malformed_scope_bssid_does_not_authorise_a_different_network():
    """
    The security consequence of strict normalisation, pinned at the layer where it matters.

    ``AssessmentScope`` builds its allowlist by normalising each authorised BSSID. While
    normalisation stripped every non-hex character, a malformed entry was silently *repaired* into
    a different valid address: authorising ``AABBCCDDEEFFGG`` granted access to
    ``AA:BB:CC:DD:EE:FF``, a network the operator never named, and ``validate()`` reported no error
    because the normalisation had "succeeded".

    A framework whose purpose is to keep an assessment inside its authorised scope must refuse
    malformed scope, not guess at it.
    """
    from wifi_framework.core.models.scope import AssessmentScope

    scope = AssessmentScope(authorized_bssids=["AABBCCDDEEFFGG"])

    # The malformed entry is reported rather than silently accepted.
    assert scope.validate(), "a malformed authorised BSSID must be reported by validate()"
    # Nothing was authorised by it - least of all the address it happens to reduce to.
    assert scope._bssid_set == set()
    assert scope.is_bssid_authorized("AA:BB:CC:DD:EE:FF") is False
    assert scope.is_wireless_asset_authorized(None, "AA:BB:CC:DD:EE:FF") is False


def test_scope_and_validator_agree_on_what_a_bssid_is():
    """
    The allowlist and the parameter validator must not disagree.

    ``AssessmentScope._normalize_mac`` used to be a second, independent implementation; it drifted
    into the bug above while ``validate_mac`` answered differently for the same input. Now both go
    through one definition, so a value the scope accepts is a value the policy layer accepts.
    """
    from wifi_framework.core.models.scope import AssessmentScope

    for value in [
        "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "AABBCCDDEEFF",
        "  AA:BB:CC:DD:EE:FF  ",
        "AABBCCDDEEFFGG", "AA:BB:CC:DD:EE:FF\n", "AA:BB-CC:DD-EE:FF", "", "not-a-mac",
        "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:FF:00",
    ]:
        assert (AssessmentScope._normalize_mac(value) is not None) == validate_mac(value)[0], value


def test_valid_wellformed_scope_still_normalises_into_the_allowlist():
    """Strictness must not break the ordinary case: separator variants of one address all match."""
    from wifi_framework.core.models.scope import AssessmentScope

    scope = AssessmentScope(authorized_bssids=["aa:bb:cc:dd:ee:ff"])
    assert scope.validate() == []
    assert scope._bssid_set == {"AA:BB:CC:DD:EE:FF"}
    for spelling in ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "AABBCCDDEEFF"]:
        assert scope.is_bssid_authorized(spelling) is True, spelling


def test_whitespace_is_stripped_from_addresses_but_not_from_interface_names():
    """
    A deliberate asymmetry, pinned because it looks like an inconsistency.

    Surrounding whitespace cannot change *which* address ``"  AA:BB:CC:DD:EE:FF  "`` denotes, so
    stripping it is safe and convenient - values arrive from CSV parsers and tool output. An
    interface name is not normalised before use: it is interpolated into ``/sys/class/net/<name>``
    and into argv as written, so ``validate_interface`` refuses a name carrying a newline instead of
    quietly accepting a value that will be used in a different form than the one that was checked.
    """
    assert validate_mac("  AA:BB:CC:DD:EE:FF  ")[0] is True
    assert normalize_mac("\tAA:BB:CC:DD:EE:FF\n") == "AA:BB:CC:DD:EE:FF"

    assert validate_interface("wlan0\n")[0] is False
    assert validate_interface(" wlan0 ")[0] is False


def test_a_newline_inside_an_address_is_not_stripped():
    """``strip()`` trims the ends only; embedded garbage still means the value is not an address."""
    assert validate_mac("AA:BB:CC\n:DD:EE:FF")[0] is False
    assert normalize_mac("AA:BB:CC:DD:EE:FF\nrm -rf /") is None


# ------------------------------------------------------- the interface-existence gate


def test_nonexistent_and_malformed_interface_names_do_not_exist():
    """
    ``check_interface_exists`` interpolates its argument into ``/sys/class/net/{interface}``.

    Before the fix, ``""``, ``"."`` and ``".."`` all returned ``True`` - the directory itself and
    its parent satisfy ``os.path.exists`` - so fourteen call sites that gate on this answer would
    proceed as though a nonexistent interface were present, and the caller's "interface does not
    exist" branch never ran.
    """
    from wifi_framework.utils.system import check_interface_exists

    for name in ["", ".", "..", "...", "wlan0\n", " wlan0 ", "../../etc/passwd", "eth0/../../etc",
                 "definitely-not-an-interface-xyz", "/etc/passwd"]:
        assert check_interface_exists(name) is False, repr(name)


def test_check_interface_exists_rejects_non_string_input():
    from wifi_framework.utils.system import check_interface_exists

    for value in [None, 0, [], {}, b"eth0"]:
        assert check_interface_exists(value) is False, repr(value)


def test_a_real_interface_is_still_reported_as_present():
    """The fix must not turn the gate into a constant ``False``."""
    from wifi_framework.utils.system import check_interface_exists, get_interface_list

    present = get_interface_list()
    assert present, "expected at least one network interface on this machine"
    for name in present:
        assert check_interface_exists(name) is True, name


def test_the_traversal_target_exists_but_is_not_reported_as_an_interface():
    """
    Pins the exact defect rather than just the outcome: the path really does exist, so the only
    thing preventing a false positive is the validation, not the filesystem.
    """
    import os
    import sys

    from wifi_framework.utils.system import check_interface_exists

    if sys.platform != "linux" or not os.path.isdir("/sys/class/net"):
        pytest.skip("requires Linux /sys/class/net")

    assert os.path.exists("/sys/class/net/..") is True
    assert os.path.exists("/sys/class/net/") is True
    assert check_interface_exists("..") is False
    assert check_interface_exists("") is False


def test_validating_the_gate_does_not_break_monitor_interface_name_construction():
    """
    Regression guard for the fix itself.

    ``InterfaceManager`` derives monitor-interface candidates by concatenation - ``interface + "mon"``
    and ``interface + "mon0"`` - and gates each on ``check_interface_exists``. Adding validation to
    that gate must not change the answer for any name those call sites can legitimately produce, or
    monitor-mode detection would silently stop finding interfaces.

    Compared differentially against the pre-fix behaviour (a bare ``os.path.exists`` interpolation)
    across every derivable name plus malformed inputs: the only differences are ``""``, ``"."`` and
    ``".."``, which is the intended fix.
    """
    import os

    from wifi_framework.utils.system import check_interface_exists, get_interface_list

    def pre_fix(name) -> bool:
        try:
            return os.path.exists(f"/sys/class/net/{name}")
        except Exception:
            return False

    bases = get_interface_list() + ["wlan0", "wlan1", "wlx00c0ca123456", "eth0"]
    derivable = {f"{base}{suffix}" for base in bases for suffix in ("", "mon", "mon0")}
    malformed = {"", ".", "..", "...", "wlan0\n", " wlan0 ", "../../etc/passwd", "eth0/../../etc"}

    changed_legitimate = []
    for name in sorted(derivable):
        if pre_fix(name) != check_interface_exists(name):
            changed_legitimate.append(name)
    assert changed_legitimate == [], f"fix altered legitimate names: {changed_legitimate}"

    # And the malformed set is exactly what the fix is for.
    assert all(check_interface_exists(name) is False for name in malformed)
    assert {name for name in malformed if pre_fix(name) and not check_interface_exists(name)} <= {
        "", ".", ".."
    }


#: ``InterfaceManager`` operations that change radio or hardware state. Each is disruptive and not
#: reliably reversible mid-assessment: a changed MAC, a downed interface, a monitor VIF, an rfkill
#: unblock.
HARDWARE_MUTATING_METHODS = {
    "change_mac",
    "create_monitor_interface",
    "remove_monitor_interface",
    "set_interface_down",
    "set_interface_up",
    "set_channel",
    "unblock_rfkill",
}


def test_the_autonomous_loop_never_mutates_radio_hardware():
    """
    The assessment loop must not change hardware state on its own initiative.

    ``InterfaceManager`` implements monitor-mode creation, MAC changes, interface up/down, channel
    setting and rfkill unblocking. It is exported for an **operator** to call explicitly, and the
    engine constructs one - but nothing in the autonomous path invokes it. That is deliberate: these
    actions are disruptive and not reliably reversible, so they belong to the operator, not to a
    loop deciding what to do next.

    What the loop does instead is *detect and defer*: when a capability needs monitor mode and the
    interface does not support it, the policy layer returns ``monitor_mode_unavailable`` as a
    retriable deferral (see ``test_policy.py::test_monitor_mode_gap_is_deferred_but_retriable``), so
    the assessment waits for the operator to establish monitor mode rather than establishing it
    itself.

    Swept by AST over every module under ``core/`` except ``interface_manager.py`` itself, so a
    future refactor that wires one of these into the loop fails here and forces the decision to be
    made consciously. Matched on method name, which is why the names are specific.
    """
    core_root = PACKAGE_ROOT / "core"
    offenders = []
    for path in sorted(core_root.rglob("*.py")):
        if path.name == "interface_manager.py":
            continue  # the implementation calls its own helpers
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in HARDWARE_MUTATING_METHODS:
                offenders.append(f"{path.relative_to(PACKAGE_ROOT)}:{node.lineno} .{node.attr}")
    assert offenders == [], f"autonomous loop mutates hardware: {offenders}"


def test_interface_manager_remains_available_for_explicit_operator_use():
    """
    The counterpart guard: deferring is only safe because the operator has a supported way to act.

    If ``InterfaceManager`` were removed or unexported, the loop's "wait for the operator" behaviour
    would leave monitor mode unreachable through the framework entirely.
    """
    from wifi_framework.core.execution import InterfaceManager, __all__ as execution_all

    assert "InterfaceManager" in execution_all
    for method in HARDWARE_MUTATING_METHODS:
        assert callable(getattr(InterfaceManager, method)), method


def test_run_command_takes_an_argv_list_not_a_string():
    """The single execution entry point accepts a list; a shell string would be a type error."""
    import inspect

    from wifi_framework.utils.system import run_command

    signature = inspect.signature(run_command)
    assert signature.parameters["cmd"].annotation in ("list[str]", list)


# --------------------------------------------------------------------------
# Interface names are validated on the way in, for every adapter
# --------------------------------------------------------------------------


def test_a_supplied_interface_is_validated_even_when_the_capability_does_not_require_one():
    """``interface_required=False`` must not mean "do not validate".

    The interface name is interpolated into argv and into ``/sys/class/net/<name>``
    paths. ``check_requirements`` only validated it when the capability declared an
    interface mandatory, so an adapter with ``interface_required=False`` handed an
    unchecked name straight to ``build_command`` and then ran it.

    The stub below uses ``echo``, which exists everywhere, so a validation gap is
    observable rather than masked by a missing tool: without the base-class check the
    call succeeds and the poisoned name is echoed back.

    This is defence in depth, not a live exploit: argv is a list and nothing in
    ``src/`` uses ``shell=True``, so a ``;`` reaches the tool as a literal character,
    and ``ActionPolicy`` already validates ``interface`` before dispatch.
    """
    from typing import Any, Dict, List

    from wifi_framework.core.execution.adapter_base import ToolAdapterBase
    from wifi_framework.core.models.capability import (
        CapabilityRequirements,
        OperatingSystem,
        ToolCapabilityMetadata,
    )
    from wifi_framework.core.models.evidence import Evidence

    class _EchoInterfaceAdapter(ToolAdapterBase):
        def build_command(self, interface, parameters) -> List[str]:
            return ["echo", interface]

        def parse_output(self, raw_output, error_output, exit_code, parameters, interface) -> List[Evidence]:
            return []

    adapter = _EchoInterfaceAdapter(
        ToolCapabilityMetadata(
            name="echo_iface_probe",
            display_name="Echo interface probe",
            category=None,
            description="test stub",
            tool_binary="echo",
            requirements=CapabilityRequirements(
                operating_systems=[OperatingSystem.LINUX],
                interface_required=False,
            ),
        )
    )

    poison = "wlan0; touch /tmp/adapter_base_poison"
    result = adapter.execute(interface=poison, parameters={}, timeout=10)

    assert result.success is False, (
        "the poisoned interface reached execution: "
        f"reason={result.failure_reason!r} output={result.raw_output!r}"
    )
    assert "Interface validation failed" in (result.failure_reason or "")
    assert not (result.raw_command or ""), "the command must never be built"


def test_a_traversal_interface_name_is_refused_before_a_command_is_built():
    """``../../etc/passwd`` must never reach an argv or a /sys path."""
    from typing import List

    from wifi_framework.core.execution.adapter_base import ToolAdapterBase
    from wifi_framework.core.models.capability import (
        CapabilityRequirements,
        OperatingSystem,
        ToolCapabilityMetadata,
    )
    from wifi_framework.core.models.evidence import Evidence

    class _EchoInterfaceAdapter(ToolAdapterBase):
        def build_command(self, interface, parameters) -> List[str]:
            return ["echo", interface]

        def parse_output(self, raw_output, error_output, exit_code, parameters, interface) -> List[Evidence]:
            return []

    adapter = _EchoInterfaceAdapter(
        ToolCapabilityMetadata(
            name="echo_iface_probe_2",
            display_name="Echo interface probe",
            category=None,
            description="test stub",
            tool_binary="echo",
            requirements=CapabilityRequirements(
                operating_systems=[OperatingSystem.LINUX],
                interface_required=False,
            ),
        )
    )

    for bad in ("../../etc/passwd", "wlan0\n", "wlan0 && id", "$(id)", "a" * 300):
        result = adapter.execute(interface=bad, parameters={}, timeout=10)
        assert result.success is False, f"{bad!r} was accepted"
        assert "Interface validation failed" in (result.failure_reason or ""), f"{bad!r}: {result.failure_reason!r}"


def test_no_real_adapter_lets_a_poisoned_interface_reach_its_command_line():
    """Sweep every registered adapter as a backstop to the stub tests above."""
    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.tools.registry_loader import load_all_adapters

    registry = load_all_adapters(CapabilityRegistry())
    poison = "wlan0; touch /tmp/adapter_sweep_poison"

    leaked = []
    for name in registry.list_capabilities():
        adapter = registry.get_adapter_instance(name)
        if adapter is None:
            continue
        result = adapter.execute(interface=poison, parameters={}, timeout=5)
        if poison in (getattr(result, "raw_command", "") or ""):
            leaked.append(name)

    assert not leaked, f"poisoned interface reached argv for: {leaked}"
