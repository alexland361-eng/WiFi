"""Tests for scope enforcement."""
from wifi_framework.core.models.scope import AssessmentScope, ScopeEnforcer


def test_scope_enforcer_wireless():
    scope = AssessmentScope(authorized_ssids=["MyNetwork"], authorized_bssids=["00:11:22:33:44:55"])
    enforcer = ScopeEnforcer(scope)

    # Passive should be allowed with broadcast discovery
    allowed, reason = enforcer.check_wireless_action_allowed("MyNetwork", "00:11:22:33:44:55", invasive=False)
    assert allowed

    # Invasive with authorized should be allowed
    allowed, reason = enforcer.check_wireless_action_allowed("MyNetwork", "00:11:22:33:44:55", invasive=True)
    assert allowed

    # Invasive with unauthorized should be blocked
    allowed, reason = enforcer.check_wireless_action_allowed("Other", "AA:BB:CC:DD:EE:FF", invasive=True)
    assert not allowed
    assert "not in authorized scope" in reason


def test_scope_enforcer_network():
    scope = AssessmentScope(authorized_networks=["192.168.1.0/24"])
    enforcer = ScopeEnforcer(scope)

    allowed, _ = enforcer.check_network_action_allowed("192.168.1.1", invasive=True)
    assert allowed

    allowed, _ = enforcer.check_network_action_allowed("10.0.0.1", invasive=True)
    assert not allowed


def test_unauthorized_bssid_is_not_waved_through_by_an_empty_ssid_list():
    """
    Regression guard for scope enforcement.

    An operator who authorises specific BSSIDs has defined scope by BSSID. An access point whose
    BSSID is absent from that list must not become authorised merely because no SSID restriction
    was declared - an empty list means "not used to define scope", not "anything goes".
    """
    scope = AssessmentScope(authorized_bssids=["00:11:22:33:44:55"])

    assert scope.is_wireless_asset_authorized("Neighbour", "AA:BB:CC:DD:EE:FF") is False
    assert scope.is_wireless_asset_authorized(None, "AA:BB:CC:DD:EE:FF") is False
    assert scope.is_wireless_asset_authorized("Neighbour", "00:11:22:33:44:55") is True

    enforcer = ScopeEnforcer(scope)
    allowed, reason = enforcer.check_wireless_action_allowed("Neighbour", "AA:BB:CC:DD:EE:FF", invasive=True)
    assert not allowed
    assert "not in authorized scope" in reason


def test_unauthorized_ssid_is_not_waved_through_by_an_empty_bssid_list():
    scope = AssessmentScope(authorized_ssids=["MyNetwork"])

    assert scope.is_wireless_asset_authorized("Other", "AA:BB:CC:DD:EE:FF") is False
    # An AP identified only by BSSID cannot be matched against an SSID allowlist.
    assert scope.is_wireless_asset_authorized(None, "AA:BB:CC:DD:EE:FF") is False
    assert scope.is_wireless_asset_authorized("MyNetwork", "AA:BB:CC:DD:EE:FF") is True


def test_either_declared_identifier_still_authorizes_when_both_are_declared():
    """The documented "either matches" intent is preserved for identifiers actually declared."""
    scope = AssessmentScope(authorized_ssids=["MyNetwork"], authorized_bssids=["00:11:22:33:44:55"])

    # SSID match alone (a different BSSID of the same authorised network).
    assert scope.is_wireless_asset_authorized("MyNetwork", "AA:BB:CC:DD:EE:FF") is True
    # BSSID match alone (a hidden AP that is explicitly authorised by address).
    assert scope.is_wireless_asset_authorized(None, "00:11:22:33:44:55") is True
    assert scope.is_wireless_asset_authorized("Other", "00:11:22:33:44:55") is True
    # Neither declared identifier matches.
    assert scope.is_wireless_asset_authorized("Other", "AA:BB:CC:DD:EE:FF") is False


def test_undeclared_scope_authorizes_everything_for_discovery():
    """With no restrictions at all, discovery is unrestricted (unchanged, non-strict default)."""
    scope = AssessmentScope()
    assert scope.is_wireless_asset_authorized("Anything", "AA:BB:CC:DD:EE:FF") is True
    assert scope.is_wireless_asset_authorized(None, None) is True


def test_bssid_matching_is_case_insensitive():
    scope = AssessmentScope(authorized_bssids=["aa:bb:cc:dd:ee:ff"])
    assert scope.is_wireless_asset_authorized(None, "AA:BB:CC:DD:EE:FF") is True


def test_scope_enforcer_strict():
    scope = AssessmentScope(authorized_ssids=["MyNetwork"], strict_mode=True)
    enforcer = ScopeEnforcer(scope)

    # In strict mode, even passive with unauthorized should be blocked if allow_broadcast_discovery False
    scope2 = AssessmentScope(authorized_ssids=["MyNetwork"], strict_mode=True, allow_broadcast_discovery=False)
    enforcer2 = ScopeEnforcer(scope2)

    allowed, _ = enforcer2.check_wireless_action_allowed("Other", "AA:BB:CC:DD:EE:FF", invasive=False)
    assert not allowed


# --------------------------------------------------- malformed scope entries
#
# An authorization entry that fails to parse narrows the scope silently: the operator
# believes a network is authorized, it is not, and every action against it is refused
# for a reason that looks like a scope violation rather than a typo. The direction is
# fail-safe, so this is an auditability defect rather than a security hole - but the
# trail must say what was dropped.

import json
import os

import pytest

from wifi_framework.core.audit.logger import AuditLogger


def test_an_invalid_network_is_recorded_as_dropped():
    scope = AssessmentScope(
        authorized_networks=["10.0.0.0/24", "not-a-network", "192.168.1.0/33"]
    )
    assert scope.invalid_networks == ["not-a-network", "192.168.1.0/33"]
    assert [str(network) for network in scope._network_objects] == ["10.0.0.0/24"]


def test_an_invalid_bssid_is_recorded_as_dropped():
    scope = AssessmentScope(authorized_bssids=["not-a-mac", "aa:bb:cc:dd:ee:ff"])
    assert scope.invalid_bssids == ["not-a-mac"]
    assert scope._bssid_set == {"AA:BB:CC:DD:EE:FF"}


def test_dropping_an_entry_does_not_change_what_is_authorized():
    """The drop is fail-safe: the valid entry still authorizes, and an address outside
    every declared network is still refused."""
    scope = AssessmentScope(
        authorized_networks=["10.0.0.0/24", "not-a-network"],
        authorized_bssids=["AA:BB:CC:DD:EE:FF", "not-a-mac"],
    )
    assert scope.is_ip_authorized("10.0.0.5") is True
    assert scope.is_ip_authorized("11.0.0.5") is False
    assert ScopeEnforcer(scope).scope.is_wireless_asset_authorized(None, "AA:BB:CC:DD:EE:FF")


def test_a_clean_scope_reports_no_dropped_entries():
    scope = AssessmentScope(
        authorized_networks=["10.0.0.0/24"],
        authorized_bssids=["AA:BB:CC:DD:EE:FF"],
        authorized_channels=[1, 6, 11],
    )
    assert scope.invalid_networks == []
    assert scope.invalid_bssids == []
    assert scope.validate() == []


def test_the_dropped_entries_reach_the_audit_trail(tmp_path):
    """`to_dict` is what `log_scope` records, so this is where the silence becomes
    visible - without depending on a caller remembering to call `validate()`."""
    logger = AuditLogger(log_dir=str(tmp_path / "audit"))
    logger.log_scope(
        AssessmentScope(
            authorized_networks=["10.0.0.0/24", "not-a-network"],
            authorized_bssids=["AA:BB:CC:DD:EE:FF", "not-a-mac"],
        )
    )
    assert logger.write_failures == []

    trail = os.path.join(logger.log_dir, logger.assessment_id + ".jsonl")
    recorded = json.loads(open(trail, "r", encoding="utf-8").read().strip())
    scope_record = recorded["data"]["scope"]

    assert scope_record["invalid_networks"] == ["not-a-network"]
    assert scope_record["invalid_bssids"] == ["not-a-mac"]
    # The requested entries are still recorded too; the trail shows both.
    assert scope_record["authorized_networks"] == ["10.0.0.0/24", "not-a-network"]


# --------------------------------------------------------- validate() must not raise


@pytest.mark.parametrize(
    "channels,expected_errors",
    [
        ([6], []),
        ([1, 196], []),
        (["6"], []),
        ([0], ["Invalid channel: 0"]),
        ([197], ["Invalid channel: 197"]),
        ([999], ["Invalid channel: 999"]),
        (["abc"], ["Invalid channel: abc"]),
        ([None], ["Invalid channel: None"]),
        ([True], ["Invalid channel: True"]),
        ([6.5], ["Invalid channel: 6.5"]),
        ([[]], 1),
    ],
)
def test_validate_reports_a_malformed_channel_instead_of_raising(channels, expected_errors):
    """`validate()` is the function that reports malformed scope, so malformed scope
    crashing it is the one failure it must not have. `1 <= ch <= 196` raised TypeError
    on a channel declared as a string - exactly the input it exists to report."""
    errors = AssessmentScope(authorized_channels=channels).validate()
    if isinstance(expected_errors, int):
        assert len(errors) == expected_errors
    else:
        assert errors == expected_errors


def test_a_fractional_channel_is_refused_rather_than_truncated():
    """`int(6.5)` is 6, a valid channel, so a naive coercion would round a malformed
    declaration into an authorized one."""
    scope = AssessmentScope(authorized_channels=[6.5])
    assert scope.validate() == ["Invalid channel: 6.5"]
    assert scope._channel_number(6.5) is None
    assert scope._channel_number("6") == 6
    assert scope._channel_number(6) == 6


def test_validate_reports_every_problem_class_together():
    scope = AssessmentScope(
        authorized_bssids=["AA:BB:CC:DD:EE:FF", "zz:zz"],
        authorized_networks=["10.0.0.0/24", "10.0.0.0/33"],
        authorized_channels=[6, 400],
    )
    errors = scope.validate()
    assert errors == [
        "Invalid BSSID format: zz:zz",
        "Invalid network CIDR: 10.0.0.0/33",
        "Invalid channel: 400",
    ]
