"""Tests for WPA3/SAE posture constants, RSN decoding, and honest unknown states."""
from __future__ import annotations

import pytest

from wifi_framework.core.models.wpa3 import (
    PweMethod,
    Wpa3Posture,
    Wpa3Profile,
    assess_dragonblood_exposure,
    brainpool_groups,
    classify_pwe,
    min_pwe_loop_iterations,
    parse_version,
    pwe_exposes_cache_side_channel,
    suitable_group,
    timing_precondition_groups,
)
from wifi_framework.parsers.iw import parse_iw_scan
from wifi_framework.parsers.rsn import RsnParseError, parse_iw_rsn_lines, parse_rsn_ie, parse_rsn_ie_hex, parse_rsnx_ie
from wifi_framework.parsers.wpa_config import parse_wpa_config, sanitize_wpa_config


def suite(t: int) -> bytes:
    return bytes((0, 0x0F, 0xAC, t))


def rsn(*, akms=(8,), caps=0x00C0) -> bytes:
    # version, group CCMP, one pairwise CCMP, AKMs, capabilities
    return b"\x01\x00" + suite(4) + b"\x01\x00" + suite(4) + len(akms).to_bytes(2, "little") + b"".join(suite(a) for a in akms) + caps.to_bytes(2, "little")


def test_group_table_matches_hostapd_rules() -> None:
    assert suitable_group(19)
    assert suitable_group(15)
    assert not suitable_group(14)
    assert not suitable_group(28)
    assert brainpool_groups() == {27, 28, 29, 30}
    assert timing_precondition_groups() == {22, 23, 24, 27, 28, 29, 30}
    assert min_pwe_loop_iterations(24) == 40
    assert min_pwe_loop_iterations(18) == 1
    assert min_pwe_loop_iterations(19) == 40


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, PweMethod.HUNTING_AND_PECKING), (0, PweMethod.HUNTING_AND_PECKING),
     (1, PweMethod.HASH_TO_ELEMENT), (2, PweMethod.BOTH), (99, PweMethod.UNRECOGNIZED)],
)
def test_pwe_classification(value, expected) -> None:
    assert classify_pwe(value) is expected


def test_pwe_side_channel_mapping_is_not_boolean_for_unknown() -> None:
    assert pwe_exposes_cache_side_channel(PweMethod.HASH_TO_ELEMENT) is False
    assert pwe_exposes_cache_side_channel(PweMethod.HUNTING_AND_PECKING) is True
    assert pwe_exposes_cache_side_channel(PweMethod.UNRECOGNIZED) is None


@pytest.mark.parametrize("text, expected", [("hostapd v2.10", (2, 10)), ("2.9-2.fc", (2, 9)), ("no version", None)])
def test_version_parser(text, expected) -> None:
    assert parse_version(text) == expected


def test_rsn_bytes_decode_akm_and_pmf_bits() -> None:
    result = parse_rsn_ie(rsn(akms=(2, 8), caps=0x00C0))
    assert result["akm_suites"] == [2, 8]
    assert result["akm_names"] == ["PSK", "SAE"]
    # hostapd: MFPR bit 6, MFPC bit 7
    assert result["mfpr"] is True
    assert result["mfpc"] is True


def test_rsn_optional_pmf_is_capable_only() -> None:
    result = parse_rsn_ie(rsn(akms=(2,), caps=0x0080))
    assert result["mfpr"] is False
    assert result["mfpc"] is True


def test_rsn_unknown_oui_is_not_mistaken_for_sae() -> None:
    body = rsn(akms=(8,)).replace(suite(8), bytes((0x50, 0x6F, 0x9A, 8)))
    result = parse_rsn_ie(body)
    assert result["akm_suites"] == []
    assert result["akm_suite_ouis"] == [(0x50, 0x6F, 0x9A)]


def test_rsn_hex_and_rsnx_decode() -> None:
    result = parse_rsn_ie_hex(rsn(akms=(8,)).hex(" "))
    assert result["akm_suites"] == [8]
    # H2E is RSNX bit 5; SAE-PK is bit 6.
    ext = parse_rsnx_ie(bytes([0b01100000]))
    assert ext["sae_h2e"] is True
    assert ext["sae_pk"] is True


@pytest.mark.parametrize("data", [b"", b"\x01", b"\x01\x00\x00", b"\x01\x00" + b"x" * 4])
def test_rsn_rejects_truncated_structures(data: bytes) -> None:
    with pytest.raises(RsnParseError):
        parse_rsn_ie(data)


def test_iw_text_decoder_reads_sae_psk_and_pmf() -> None:
    lines = [
        "\tRSN:",
        "\t\t* Version: 1",
        "\t\t* Group cipher: CCMP",
        "\t\t* Authentication suites: PSK SAE",
        "\t\t* Capabilities: MFP-capable",
        "\t\t* Capabilities: MFP-required",
        "\tRSNX:",
        "\t\t* Capabilities: SAE H2E",
    ]
    result = parse_iw_rsn_lines(lines)
    assert result["akm_suites"] == [2, 8]
    assert result["mfpc"] is True
    assert result["mfpr"] is True
    assert result["h2e_advertised"] is True


def test_transition_posture_is_supported_not_verified() -> None:
    posture = Wpa3Posture(bssid="00:11:22:33:44:55", akm_suites=[2, 8], source="iw scan")
    assert posture.profile() is Wpa3Profile.WPA3_PERSONAL_TRANSITION
    finding = assess_dragonblood_exposure(posture)[0]
    assert finding.exposed is True
    assert finding.status.value == "supported"
    assert finding.cert_id == "VU#871675"
    assert "does not perform" in finding.verify_requires


def test_passive_assessment_does_not_invent_sae_groups_or_pwe() -> None:
    posture = Wpa3Posture(bssid="00:11:22:33:44:55", akm_suites=[8], source="iw scan")
    findings = assess_dragonblood_exposure(posture)
    timing = next(f for f in findings if f.attack.startswith("SAE timing"))
    cache = next(f for f in findings if f.attack.startswith("SAE cache"))
    assert timing.exposed is None
    assert cache.exposed is None
    assert timing.status.value == "unresolved"
    assert cache.status.value == "unresolved"


def test_config_audit_can_prove_h2e_modern_posture_not_exposed() -> None:
    posture = Wpa3Posture(
        bssid="00:11:22:33:44:55", akm_suites=[8], sae_pwe=1,
        version="hostapd v2.10", source="config:hostapd.conf",
    )
    cache = next(f for f in assess_dragonblood_exposure(posture) if f.attack.startswith("SAE cache"))
    assert cache.exposed is False
    assert cache.severity.value == "info"


def test_old_hnp_config_is_exposed_and_group_findings_are_separate() -> None:
    posture = Wpa3Posture(
        bssid="00:11:22:33:44:55", akm_suites=[8], sae_pwe=0,
        sae_groups=[19, 28], version="2.9", source="config:hostapd.conf",
    )
    findings = assess_dragonblood_exposure(posture)
    timing = next(f for f in findings if f.attack.startswith("SAE timing"))
    group = next(f for f in findings if f.attack.startswith("SAE security"))
    cache = next(f for f in findings if f.attack.startswith("SAE cache"))
    assert timing.exposed is True
    assert group.exposed is True
    assert cache.exposed is True
    assert timing.cve.startswith("CVE-2019-9494")


def test_wpa3_without_psk_is_not_transition_exposed() -> None:
    posture = Wpa3Posture(bssid="00:11:22:33:44:55", akm_suites=[8], source="iw scan")
    first = assess_dragonblood_exposure(posture)[0]
    assert first.exposed is False


def test_no_rsn_is_unknown_not_open() -> None:
    finding = assess_dragonblood_exposure(Wpa3Posture(bssid="00:11:22:33:44:55"))[0]
    assert finding.exposed is None
    assert finding.status.value == "unresolved"



def test_iw_scan_parser_builds_passive_posture_without_inventing_groups() -> None:
    output = """BSS 00:11:22:33:44:55(on wlan0)
\tSSID: WPA3-lab
\tfreq: 2412
\tsignal: -42.00 dBm
\tDS Parameter set: channel 1
\tRSN:
\t\t* Version: 1
\t\t* Group cipher: CCMP
\t\t* Pairwise ciphers: CCMP
\t\t* Authentication suites: SAE
\t\t* Capabilities: MFP-capable, MFP-required
\tRSNX:
\t\t* Capabilities: SAE H2E
BSS aa:bb:cc:dd:ee:ff(on wlan0)
\tSSID:
\tfreq: 5180
\tRSN:
\t\t* Authentication suites: PSK SAE
\t\t* Capabilities: MFP-capable
"""
    aps = parse_iw_scan(output)
    assert len(aps) == 2
    assert aps[0]["bssid"] == "00:11:22:33:44:55"
    assert aps[0]["akm_suites"] == [8]
    assert aps[0]["mfpr"] is True
    assert aps[0]["h2e_advertised"] is True
    assert "sae_groups" not in aps[0]
    assert aps[1]["is_hidden"] is True
    assert aps[1]["akm_suites"] == [2, 8]
    assert aps[1]["mfpr"] is None


def test_iw_scan_parser_reports_invalid_bssid_and_empty_scan() -> None:
    issues = []
    assert parse_iw_scan("BSS :::::::::::::::::::::(on wlan0)\n", issues) == []
    assert issues and "invalid BSSID" in issues[0]
    issues = []
    assert parse_iw_scan("", issues) == []
    assert issues == ["iw scan output contained no BSS blocks"]


def test_wpa_config_audit_extracts_posture_without_secret_material() -> None:
    issues = []
    posture = parse_wpa_config(
        """wpa_key_mgmt=WPA-PSK SAE
sae_groups=19 28
sae_pwe=1
ieee80211w=2
anti_clogging_threshold=5
wpa_passphrase=do-not-return
sae_password=also-do-not-return
""",
        version="hostapd v2.10", issues=issues,
    )
    assert posture.akm_suites == [2, 8]
    assert posture.sae_groups == [19, 28]
    assert posture.sae_pwe == 1
    assert posture.mfpc is True and posture.mfpr is True
    assert posture.anti_clogging_threshold == 5
    assert "do-not-return" not in repr(posture)
    assert issues == []


def test_wpa_config_invalid_values_remain_unknown_and_are_reported() -> None:
    issues = []
    posture = parse_wpa_config(
        "wpa_key_mgmt=SAE UNKNOWN\nsae_pwe=seven\nsae_groups=19 nope\nieee80211w=7\n",
        issues=issues,
    )
    assert posture.akm_suites == [8]
    assert posture.sae_pwe is None
    assert posture.sae_groups == [19]
    assert posture.mfpr is None
    assert len(issues) == 4


def test_enterprise_akm_does_not_fabricate_eap_pwd_exposure() -> None:
    posture = Wpa3Posture(bssid="00:11:22:33:44:55", akm_suites=[5], source="iw scan")
    findings = assess_dragonblood_exposure(posture)
    assert len(findings) == 2
    assert all(f.exposed is None for f in findings)
    assert all(f.status.value == "unresolved" for f in findings)


def test_configured_old_eap_pwd_is_assessed_separately() -> None:
    posture = Wpa3Posture(
        bssid="00:11:22:33:44:55", akm_suites=[5], eap_pwd_configured=True,
        version="2.6", source="radius config",
    )
    findings = assess_dragonblood_exposure(posture)
    assert {f.cve for f in findings} == {
        "CVE-2019-9495, CVE-2022-23304",
        "CVE-2019-9497, CVE-2019-9498, CVE-2019-9499",
    }
    assert all(f.exposed is True for f in findings)


def test_world_model_preserves_rsn_posture_under_wpa3_namespace() -> None:
    from wifi_framework.core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
    from wifi_framework.core.models.world_model import WorldModel

    evidence = Evidence.from_tool_output(
        tool_name="iw", capability="wpa3_posture_scan", evidence_type=EvidenceType.ACCESS_POINT,
        raw_output="fixture", parsed_data={
            "bssid": "00:11:22:33:44:55", "ssid": "lab", "akm_suites": [8],
            "mfpc": True, "mfpr": True, "h2e_advertised": True,
            "source": "iw scan",
        }, parameters={}, confidence=ConfidenceLevel.HIGH,
    )
    world = WorldModel()
    world.update(evidence)
    assert world.access_points["00:11:22:33:44:55"].extra["wpa3"] == {
        "akm_suites": [8], "mfpc": True, "mfpr": True,
        "h2e_advertised": True, "source": "iw scan",
    }


def test_assessment_engine_projects_wpa3_posture_into_findings(tmp_path) -> None:
    from wifi_framework.core.engine.assessment_engine import AssessmentEngine
    from wifi_framework.core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
    from wifi_framework.core.models.scope import AssessmentScope
    from wifi_framework.core.audit.logger import AuditLogger

    engine = AssessmentEngine(
        AssessmentScope(authorized_bssids=["00:11:22:33:44:55"]),
        audit_logger=AuditLogger(log_dir=str(tmp_path / "audit")),
        artifact_dir=str(tmp_path / "artifacts"),
    )
    evidence = Evidence.from_tool_output(
        tool_name="iw", capability="wpa3_posture_scan", evidence_type=EvidenceType.ACCESS_POINT,
        raw_output="fixture", parsed_data={
            "bssid": "00:11:22:33:44:55", "ssid": "transition", "akm_suites": [2, 8],
            "mfpc": True, "mfpr": False, "source": "iw scan",
        }, parameters={}, confidence=ConfidenceLevel.HIGH,
    )
    engine.state.world_model.update(evidence)
    engine.update_findings_from_world_model()
    wpa_findings = [f for f in engine.state.findings if "wpa3" in f.tags]
    assert wpa_findings
    assert any("Transition downgrade" in f.title for f in wpa_findings)
    assert all(f.status.value != "verified" for f in wpa_findings)


def test_wpa_config_sanitizer_removes_secrets_before_evidence() -> None:
    safe = sanitize_wpa_config(
        "wpa_passphrase=secret\nsae_password=dragon\npsk=another\nsae_pwe=1\n"
    )
    assert "secret" not in safe and "dragon" not in safe and "another" not in safe
    assert "wpa_passphrase=<redacted>" in safe
    assert "sae_pwe=1" in safe


def test_control_client_audit_sanitizes_raw_evidence() -> None:
    from wifi_framework.tools.adapters.audit.wpa3 import (
        HOSTAPD_WPA3_AUDIT_METADATA,
        HostapdWpa3AuditAdapter,
    )

    adapter = HostapdWpa3AuditAdapter(HOSTAPD_WPA3_AUDIT_METADATA)
    output = "wpa_key_mgmt=SAE\nsae_pwe=1\nwpa_passphrase=top-secret\nsae_password=sae-secret\n"
    evidence = adapter.parse_output(output, "", 0, {}, "wlan0")[0]
    assert evidence.parsed_data["sae_pwe"] == 1
    assert "top-secret" not in (evidence.raw_output or "")
    assert "sae-secret" not in (evidence.raw_output or "")
    assert adapter.build_command("wlan0", {}) == ["hostapd_cli", "-i", "wlan0", "get_config"]


def test_control_client_audit_requires_interface() -> None:
    from wifi_framework.tools.adapters.audit.wpa3 import (
        HOSTAPD_WPA3_AUDIT_METADATA,
        HostapdWpa3AuditAdapter,
    )

    adapter = HostapdWpa3AuditAdapter(HOSTAPD_WPA3_AUDIT_METADATA)
    with pytest.raises(ValueError):
        adapter.build_command(None, {})


def test_sae_capture_parser_uses_explicit_tshark_group_fields_only() -> None:
    import json
    from wifi_framework.parsers.sae import parse_sae_tshark_json, parse_sae_tshark_fields

    packets = [{"_source": {"layers": {
        "wlan": {
            "wlan.fixed.auth_alg": "3",
            "wlan.fixed.auth_seq": "1",
            "wlan.sae.group": "19",
            "wlan.bssid": "00:11:22:33:44:55",
        }
    }}}, {"_source": {"layers": {
        "wlan": {
            "wlan.fixed.auth_alg": "3",
            "wlan.fixed.auth_seq": "2",
            "wlan.sae.group": "19",
        }
    }}}]
    result = parse_sae_tshark_json(json.dumps(packets))
    assert result[0]["sae_groups"] == [19]
    assert result[0]["bssid"] == "00:11:22:33:44:55"
    assert result[0]["sae_commit_count"] == 1
    assert result[0]["sae_confirm_count"] == 1

    fields = "3\t1\t28\t00:11:22:33:44:55\n3\t2\t28\t00:11:22:33:44:55\n"
    result = parse_sae_tshark_fields(
        fields, ["wlan.fixed.auth_alg", "wlan.fixed.auth_seq", "wlan.sae.group", "wlan.bssid"]
    )
    assert result[0]["sae_groups"] == [28]
    assert result[0]["bssid"] == "00:11:22:33:44:55"


def test_sae_capture_parser_does_not_infer_groups_from_unlabeled_bytes() -> None:
    import json
    from wifi_framework.parsers.sae import parse_sae_tshark_json

    issues = []
    packets = [{"_source": {"layers": {
        "wlan": {"wlan.fixed.auth_alg": "3", "wlan.fixed.auth_seq": "1", "wlan.fixed.raw": "1300"}
    }}}]
    result = parse_sae_tshark_json(json.dumps(packets), issues)
    assert result[0]["sae_groups"] == []
    assert result[0]["sae_observation_count"] == 1
    assert not issues


def test_offline_sae_adapter_never_opens_interface() -> None:
    from wifi_framework.tools.adapters.capture.sae import METADATA, SaeCaptureAnalysisAdapter

    adapter = SaeCaptureAnalysisAdapter(METADATA)
    assert adapter.build_command(None, {"read_file": "/tmp/authorized.pcapng"}) == [
        "tshark", "-r", "/tmp/authorized.pcapng", "-T", "json",
        "-Y", "wlan.fixed.auth_alg == 3",
    ]
    with pytest.raises(ValueError):
        adapter.build_command("wlan0", {"read_file": "-i"})


def test_offline_sae_handshake_fills_observed_groups_in_world_model() -> None:
    from wifi_framework.core.models.evidence import Evidence, EvidenceType
    from wifi_framework.core.models.world_model import WorldModel

    evidence = Evidence(
        evidence_type=EvidenceType.HANDSHAKE,
        parsed_data={
            "bssid": "00:11:22:33:44:55", "sae_groups": [19],
            "sae_observation_count": 2, "sae_commit_count": 1, "sae_confirm_count": 1,
        },
    )
    world = WorldModel()
    world.update(evidence)
    assert world.access_points["00:11:22:33:44:55"].extra["wpa3"]["sae_groups"] == [19]


def test_later_sae_capture_refines_an_unresolved_wpa3_finding(tmp_path) -> None:
    from wifi_framework.core.engine.assessment_engine import AssessmentEngine
    from wifi_framework.core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
    from wifi_framework.core.models.scope import AssessmentScope
    from wifi_framework.core.audit.logger import AuditLogger

    engine = AssessmentEngine(
        AssessmentScope(authorized_bssids=["00:11:22:33:44:55"]),
        audit_logger=AuditLogger(log_dir=str(tmp_path / "audit")),
        artifact_dir=str(tmp_path / "artifacts"),
    )
    scan = Evidence.from_tool_output(
        tool_name="iw", capability="wpa3_posture_scan", evidence_type=EvidenceType.ACCESS_POINT,
        raw_output="scan", parsed_data={
            "bssid": "00:11:22:33:44:55", "akm_suites": [8],
            "mfpc": True, "mfpr": True, "source": "iw scan",
        }, parameters={}, confidence=ConfidenceLevel.HIGH,
    )
    engine.state.world_model.update(scan)
    engine.update_findings_from_world_model()
    timing = next(f for f in engine.state.findings if f.title.startswith("WPA3 posture: SAE timing"))
    assert timing.status.value == "unresolved"

    capture = Evidence(
        evidence_type=EvidenceType.HANDSHAKE,
        parsed_data={
            "bssid": "00:11:22:33:44:55", "sae_groups": [19],
            "sae_observation_count": 2, "sae_commit_count": 1, "sae_confirm_count": 1,
        },
    )
    engine.state.world_model.update(capture)
    engine.update_findings_from_world_model()
    refined = next(f for f in engine.state.findings if f.id == timing.id)
    assert refined.status.value == "supported"
    assert refined.details["exposed"] is False
    assert capture.id in refined.evidence_ids


def test_offline_sae_adapter_rejects_missing_capture_before_execution(tmp_path) -> None:
    from wifi_framework.tools.adapters.capture.sae import METADATA, SaeCaptureAnalysisAdapter

    adapter = SaeCaptureAnalysisAdapter(METADATA)
    ok, errors = adapter.custom_parameter_validation({"read_file": str(tmp_path / "missing.pcapng")})
    assert ok is False
    assert "does not exist" in errors[0]
    capture = tmp_path / "authorized.pcapng"
    capture.write_bytes(b"fixture")
    assert adapter.custom_parameter_validation({"read_file": str(capture)}) == (True, [])


def test_sae_capture_parser_uses_canonical_mac_identity() -> None:
    import json
    from wifi_framework.parsers.sae import parse_sae_tshark_json

    packets = [{"_source": {"layers": {
        "wlan": {
            "wlan.fixed.auth_alg": "3",
            "wlan.sae.group": "19",
            "wlan.bssid": "aa-bb-cc-dd-ee-ff",
        }
    }}}]
    result = parse_sae_tshark_json(json.dumps(packets))
    assert result[0]["bssid"] == "AA:BB:CC:DD:EE:FF"


def test_wpa_config_recognizes_explicit_eap_pwd_only() -> None:
    explicit = parse_wpa_config("wpa_key_mgmt=WPA-EAP\neap=PWD\neap_pwd_groups=19\n")
    assert explicit.eap_pwd_configured is True
    external = parse_wpa_config("wpa_key_mgmt=WPA-EAP\neap_user_file=/etc/hostapd/hostapd.eap_users\n")
    assert external.eap_pwd_configured is None
