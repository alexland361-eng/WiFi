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


def test_scope_enforcer_strict():
    scope = AssessmentScope(authorized_ssids=["MyNetwork"], strict_mode=True)
    enforcer = ScopeEnforcer(scope)

    # In strict mode, even passive with unauthorized should be blocked if allow_broadcast_discovery False
    scope2 = AssessmentScope(authorized_ssids=["MyNetwork"], strict_mode=True, allow_broadcast_discovery=False)
    enforcer2 = ScopeEnforcer(scope2)

    allowed, _ = enforcer2.check_wireless_action_allowed("Other", "AA:BB:CC:DD:EE:FF", invasive=False)
    assert not allowed
