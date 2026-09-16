"""Tests for core models."""
import pytest
from datetime import datetime, timezone

from wifi_framework.core.models.evidence import Evidence, EvidenceType, EvidenceSource, ConfidenceLevel
from wifi_framework.core.models.finding import Finding, FindingStatus, FindingCategory, FindingSeverity
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.core.models.world_model import WorldModel, AccessPoint


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
