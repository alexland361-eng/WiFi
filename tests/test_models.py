"""Tests for core models."""
import pytest

from wifi_framework.core.models.evidence import Evidence, EvidenceType, ConfidenceLevel
from wifi_framework.core.models.finding import Finding, FindingStatus, FindingCategory, FindingSeverity
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.core.models.world_model import AccessPoint, WirelessClient, WorldModel


def test_evidence_creation():
    ev = Evidence.from_tool_output(
        tool_name="iw",
        capability="test",
        evidence_type=EvidenceType.INTERFACE,
        raw_output="test output",
        parsed_data={"name": "wlan0"},
        parameters={},
        confidence=ConfidenceLevel.HIGH,
    )
    assert ev.evidence_type == EvidenceType.INTERFACE
    assert ev.confidence == ConfidenceLevel.HIGH
    assert ev.parsed_data["name"] == "wlan0"
    assert ev.timestamp.tzinfo is not None


def test_evidence_confidence_validation():
    with pytest.raises(ValueError):
        Evidence(confidence=1.5)


def test_finding_lifecycle():
    finding = Finding(
        title="Test AP",
        description="Test",
        category=FindingCategory.WIRELESS,
        severity=FindingSeverity.INFO,
        status=FindingStatus.HYPOTHESIS,
        affected_assets=["00:11:22:33:44:55"],
    )
    assert finding.status == FindingStatus.HYPOTHESIS

    # Add evidence
    finding.add_evidence("ev1")
    assert "ev1" in finding.evidence_ids

    # Support with second evidence should promote to SUPPORTED
    finding.support("ev2")
    assert finding.status == FindingStatus.SUPPORTED

    # Verify
    finding.verify("ev3", method="test")
    assert finding.status == FindingStatus.VERIFIED
    assert finding.verification_method == "test"


def test_scope_ssid_authorization():
    scope = AssessmentScope(authorized_ssids=["MyNetwork", "Corp.*"])
    assert scope.is_ssid_authorized("MyNetwork")
    assert scope.is_ssid_authorized("CorpWiFi")
    assert not scope.is_ssid_authorized("OtherNetwork")

    # Empty scope should allow all when not strict
    empty_scope = AssessmentScope()
    assert empty_scope.is_ssid_authorized("Anything")

    strict_scope = AssessmentScope(strict_mode=True)
    assert not strict_scope.is_ssid_authorized("Anything")


def test_scope_bssid_authorization():
    scope = AssessmentScope(authorized_bssids=["00:11:22:33:44:55"])
    assert scope.is_bssid_authorized("00:11:22:33:44:55")
    assert scope.is_bssid_authorized("00-11-22-33-44-55")  # Different separator
    assert scope.is_bssid_authorized("001122334455")  # No separator
    assert not scope.is_bssid_authorized("AA:BB:CC:DD:EE:FF")


def test_scope_ip_authorization():
    scope = AssessmentScope(authorized_networks=["192.168.1.0/24"])
    assert scope.is_ip_authorized("192.168.1.1")
    assert scope.is_ip_authorized("192.168.1.254")
    assert not scope.is_ip_authorized("10.0.0.1")


def test_scope_validation():
    scope = AssessmentScope(authorized_bssids=["invalid"], authorized_networks=["invalid"], authorized_channels=[999])
    errors = scope.validate()
    assert len(errors) == 3


def test_world_model_update():
    wm = WorldModel()

    ev = Evidence.from_tool_output(
        tool_name="airodump-ng",
        capability="wireless_observation",
        evidence_type=EvidenceType.ACCESS_POINT,
        raw_output="test",
        parsed_data={
            "bssid": "00:11:22:33:44:55",
            "ssid": "TestNetwork",
            "channel": 6,
            "encryption": ["WPA2"],
        },
        parameters={},
    )

    wm.update(ev)
    assert len(wm.access_points) == 1
    assert "00:11:22:33:44:55" in wm.access_points
    ap = wm.access_points["00:11:22:33:44:55"]
    assert ap.ssid == "TestNetwork"
    assert ap.channel == 6
    assert "WPA2" in ap.encryption


# ------------------------------------- values an entity could not read
#
# A malformed channel or signal used to be dropped by `except (ValueError, TypeError):
# pass`. The entity kept its previous value and nothing recorded that the newest
# observation was unreadable, so a field that was never observed and a field whose latest
# observation failed looked identical in the world model dump - and the dump is what the
# audit trail and the assessment report are built from.


def _evidence(parsed_data):
    return Evidence.from_tool_output(
        tool_name="airodump-ng",
        capability="wireless_observation",
        evidence_type=EvidenceType.ACCESS_POINT,
        raw_output="fixture",
        parsed_data=parsed_data,
        parameters={},
        confidence=ConfidenceLevel.HIGH,
    )


def test_an_unreadable_channel_is_recorded_and_the_previous_value_is_kept():
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", channel=6)
    ap.update_from_evidence(_evidence({"channel": "6a"}))

    assert ap.channel == 6, "a malformed value overwrote a good one"
    assert ap.parse_errors == ["channel: could not read '6a' as a whole number; kept 6"]


def test_an_unreadable_signal_is_recorded():
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", signal_strength=-45)
    ap.update_from_evidence(_evidence({"signal": "loud"}))

    assert ap.signal_strength == -45
    assert len(ap.parse_errors) == 1
    assert "signal" in ap.parse_errors[0] and "'loud'" in ap.parse_errors[0]


def test_a_client_signal_failure_is_recorded_too():
    client = WirelessClient(mac="11:22:33:44:55:66", signal_strength=-70)
    client.update_from_evidence(_evidence({"signal": "not a number"}))

    assert client.signal_strength == -70
    assert client.parse_errors, "the client entity dropped a malformed signal silently"


def test_repeated_identical_failures_are_recorded_once():
    """A world model is long-lived: an access point seen on every sweep of a long capture
    would otherwise accumulate one identical entry per sweep."""
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", channel=6)
    for _ in range(25):
        ap.update_from_evidence(_evidence({"channel": "6a"}))

    assert len(ap.parse_errors) == 1


def test_a_distinct_failure_is_still_recorded():
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", channel=6)
    ap.update_from_evidence(_evidence({"channel": "6a"}))
    ap.update_from_evidence(_evidence({"channel": "unknown"}))

    assert len(ap.parse_errors) == 2


def test_a_readable_value_still_updates_the_entity():
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", channel=6, signal_strength=-45)
    ap.update_from_evidence(_evidence({"channel": 11, "signal": -60}))

    assert ap.channel == 11
    assert ap.signal_strength == -60
    assert ap.parse_errors == []


def test_a_fractional_channel_is_refused_rather_than_rounded():
    """`int(6.5)` is 6, so a naive coercion would store a channel the access point is not
    on. The same rule the scope applies to a declared channel."""
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", channel=6)
    ap.update_from_evidence(_evidence({"channel": 6.5}))

    assert ap.channel == 6
    assert any("6.5" in error for error in ap.parse_errors)


def test_an_integral_string_from_a_tool_is_accepted():
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF")
    ap.update_from_evidence(_evidence({"channel": "11", "signal": "-45.0"}))

    assert ap.channel == 11
    assert ap.signal_strength == -45
    assert ap.parse_errors == []


def test_parse_errors_reach_the_world_model_dump():
    """The dump is what the audit trail and the report are built from, so a recorded
    failure that stops at the entity object is still invisible to an operator."""
    model = WorldModel()
    model.update(_evidence({"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "TestNetwork", "channel": "6a"}))

    dumped = model.to_dict()["access_points"]["AA:BB:CC:DD:EE:FF"]
    assert dumped["channel"] is None
    assert dumped["parse_errors"], "the world model dump does not carry the unreadable value"
    assert "channel" in dumped["parse_errors"][0]


def test_a_clean_entity_reports_no_parse_errors():
    model = WorldModel()
    model.update(_evidence({"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "signal": -50}))

    dumped = model.to_dict()["access_points"]["AA:BB:CC:DD:EE:FF"]
    assert dumped["parse_errors"] == []
    assert dumped["channel"] == 6


def test_the_world_model_and_the_scope_apply_the_same_rule():
    """One helper, so a declared channel in an authorization scope and an observed channel
    in the world model cannot disagree about what counts as a whole number."""
    from wifi_framework.core.models.scope import AssessmentScope

    for value in [6, "6", "6.0", -45.0, 6.5, "6.5", True, None, "abc"]:
        assert AssessmentScope._channel_number(value) == _observed_channel(value), (
            f"{value!r}: scope and world model disagree"
        )


def _observed_channel(value):
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF")
    ap.update_from_evidence(_evidence({"channel": value}))
    return ap.channel
