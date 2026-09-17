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


def test_run_command_takes_an_argv_list_not_a_string():
    """The single execution entry point accepts a list; a shell string would be a type error."""
    import inspect

    from wifi_framework.utils.system import run_command

    signature = inspect.signature(run_command)
    assert signature.parameters["cmd"].annotation in ("list[str]", list)
