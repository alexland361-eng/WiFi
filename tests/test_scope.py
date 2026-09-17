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
