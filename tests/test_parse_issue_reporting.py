"""Extraction problems are declared, not hidden.

`contracts/evidence.py` states the rule: `parse_issues` records partial parses. Two
parsers broke it. `parse_nmap_xml` swallowed `ET.ParseError` and `parse_tshark_json`
swallowed `JSONDecodeError`, each returning an empty list - so a truncated document
was indistinguishable from "nmap found no hosts" or "no packets were captured".

That distinction is the whole basis of the evidence hierarchy. An empty result the
framework believes is an observation says something about the network; an empty result
caused by an unparseable document says nothing at all, and treating it as an
observation is how a truncated capture becomes a claim that a host is absent.

Truncation is not exotic here: tshark stopped by a timeout mid-write produces exactly
this, and the framework's own timeout path reports partial output.

These tests drive the whole channel - parser, adapter, gateway, Evidence Engine -
because a parser with nowhere to report is the defect, not the `except` clause.
"""
from __future__ import annotations

import pytest

from wifi_framework.contracts.common import InterfaceRef, ToolRef
from wifi_framework.contracts.execution import ExecutionResult, ExecutionStatus
from wifi_framework.contracts.envelope import EngineId
from wifi_framework.core.evidence import EvidenceEngine
from wifi_framework.core.models.assessment_state import AssessmentState
from wifi_framework.core.models.evidence import EvidenceType
from wifi_framework.core.execution.adapter_base import AdapterExecutionResult
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.parsers.nmap import nmap_to_evidences, parse_nmap_xml
from wifi_framework.parsers.tshark import parse_tshark_json, tshark_to_evidences

ASSESSMENT = "33333333-3333-4333-8333-333333333333"

#: Shaped like real `nmap -oX -` output, including the DOCTYPE and the
#: `<status state="up"/>` element the parser keys on.
NMAP_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX - 10.0.0.1" start="1700000000" version="7.94" xmloutputversion="1.05">
 <host starttime="1700000000" endtime="1700000003">
  <status state="up" reason="arp-response" reason_ttl="0"/>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <hostnames><hostname name="gateway.local" type="PTR"/></hostnames>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack" reason_ttl="64"/>
    <service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10"/>
   </port>
   <port protocol="tcp" portid="443">
    <state state="open" reason="syn-ack" reason_ttl="64"/>
    <service name="https" method="table" conf="3"/>
   </port>
  </ports>
 </host>
</nmaprun>
'''

#: What a capture stopped mid-write looks like: valid prefix, no closing bracket.
NMAP_XML_TRUNCATED = NMAP_XML[: NMAP_XML.index("<ports>")]

TSHARK_JSON = (
    '[{"_source": {"layers": {"frame": {"frame.number": "1"},'
    ' "wlan": {"wlan.bssid": "AA:BB:CC:DD:EE:FF", "wlan_mgt.ssid": "Office"}}}},'
    ' {"_source": {"layers": {"frame": {"frame.number": "2"}}}}]'
)
TSHARK_JSON_TRUNCATED = TSHARK_JSON[: TSHARK_JSON.rindex("}")]


# --------------------------------------------------------------------- nmap parser


def test_valid_nmap_xml_parses_and_reports_nothing():
    """Positive control: a clean parse must not produce noise, or the signal is
    worthless."""
    issues: list = []
    hosts = parse_nmap_xml(NMAP_XML, issues=issues)

    assert issues == []
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "10.0.0.1"
    assert hosts[0]["hostname"] == "gateway.local"
    assert [port["port"] for port in hosts[0]["ports"]] == [22, 443]


def test_truncated_nmap_xml_is_reported_rather_than_swallowed():
    issues: list = []
    hosts = parse_nmap_xml(NMAP_XML_TRUNCATED, issues=issues)

    assert hosts == []
    assert len(issues) == 1, "an unparseable document was reported as an empty result"
    assert "could not be parsed" in issues[0]
    # The message must say which of the two empty results this is.
    assert "not that no hosts were found" in issues[0]
    assert "line" in issues[0] and "column" in issues[0], "no position given to act on"


def test_nmap_to_evidences_passes_the_problem_through():
    issues: list = []
    evidences = nmap_to_evidences(NMAP_XML_TRUNCATED, target="10.0.0.1", issues=issues)
    assert evidences == []
    assert len(issues) == 1

    clean: list = []
    evidences = nmap_to_evidences(NMAP_XML, target="10.0.0.1", issues=clean)
    assert clean == []
    assert evidences, "valid XML produced no evidence - the fixture is wrong"
    assert any(evidence.evidence_type == EvidenceType.NETWORK_HOST for evidence in evidences)


def test_the_parsers_still_work_without_an_issues_argument():
    """Every existing caller passes no `issues`; the parameter is optional so the
    change is additive rather than a breaking signature edit."""
    assert parse_nmap_xml(NMAP_XML_TRUNCATED) == []
    assert len(parse_nmap_xml(NMAP_XML)) == 1
    assert parse_tshark_json(TSHARK_JSON_TRUNCATED) == []
    assert len(nmap_to_evidences(NMAP_XML)) == len(nmap_to_evidences(NMAP_XML, issues=[]))


# ------------------------------------------------------------------- tshark parser


def test_valid_tshark_json_parses_and_reports_nothing():
    issues: list = []
    packets = parse_tshark_json(TSHARK_JSON, issues=issues)

    assert issues == []
    assert len(packets) == 2
    assert packets[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert packets[0]["ssid"] == "Office"


def test_truncated_tshark_json_is_reported_rather_than_swallowed():
    issues: list = []
    packets = parse_tshark_json(TSHARK_JSON_TRUNCATED, issues=issues)

    assert packets == []
    assert len(issues) == 1
    assert "could not be parsed" in issues[0]
    assert "not that no" in issues[0]
    assert "position" in issues[0]


def test_tshark_to_evidences_passes_the_problem_through():
    issues: list = []
    evidences = tshark_to_evidences(TSHARK_JSON_TRUNCATED, interface="wlan0mon", issues=issues)
    assert len(issues) == 1

    clean: list = []
    evidences = tshark_to_evidences(TSHARK_JSON, interface="wlan0mon", issues=clean)
    assert clean == []
    assert len(evidences) == 2


# --------------------------------------------------------------- adapter -> result


def _registry():
    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.tools.registry_loader import load_all_adapters

    return load_all_adapters(CapabilityRegistry())


def test_the_nmap_adapter_records_the_parse_problem_on_the_result():
    """`parse_output` returns evidence and has no other way to say "this did not fully
    parse", so the adapter records it on itself and the base class carries it out."""
    adapter = _registry().get_adapter_instance("nmap")
    assert adapter is not None, "nmap capability missing - the test would be vacuous"

    evidences = adapter.parse_output(NMAP_XML_TRUNCATED, "", 0, {"target": "10.0.0.1"}, None)
    assert evidences == []
    assert adapter.parse_warnings, "the adapter noticed nothing"
    assert "could not be parsed" in adapter.parse_warnings[0]

    # A clean parse leaves nothing behind, including from a previous run.
    adapter.parse_warnings = []
    adapter.parse_output(NMAP_XML, "", 0, {"target": "10.0.0.1"}, None)
    assert adapter.parse_warnings == []


def test_the_tshark_adapter_records_the_parse_problem_on_the_result():
    adapter = _registry().get_adapter_instance("tshark")
    assert adapter is not None, "tshark capability missing - the test would be vacuous"

    adapter.parse_output(TSHARK_JSON_TRUNCATED, "", 0, {}, "wlan0mon")
    assert adapter.parse_warnings, "the adapter noticed nothing"

    adapter.parse_warnings = []
    adapter.parse_output(TSHARK_JSON, "", 0, {}, "wlan0mon")
    assert adapter.parse_warnings == []


def test_execute_resets_parse_warnings_between_runs():
    """A stale warning from a previous execution would be attributed to the wrong run."""
    adapter = _registry().get_adapter_instance("nmap")
    adapter.parse_warnings = ["leftover from a previous run"]
    adapter.parse_output(NMAP_XML, "", 0, {"target": "10.0.0.1"}, None)
    # parse_output itself does not reset; execute() does, immediately before parsing.
    result = adapter.execute(interface=None, parameters={"target": "10.0.0.1"}, timeout=5)
    assert "leftover from a previous run" not in result.parse_warnings


# --------------------------------------------------------------- result -> contract


def test_parse_warnings_stay_off_the_general_warning_list():
    from wifi_framework.core.execution.gateway import ExecutionGateway

    expected = ["nmap XML output could not be parsed (unclosed token)"]
    legacy = AdapterExecutionResult(
        success=True,
        raw_output=NMAP_XML_TRUNCATED,
        exit_code=0,
        raw_command="nmap 10.0.0.1",
        argv=["nmap", "10.0.0.1"],
        parse_warnings=list(expected),
    )

    _status, failure, warnings = ExecutionGateway._classify(legacy, [])
    assert failure is None, "a parse problem is not an execution failure - the tool ran"
    assert warnings == [], (
        "parse problems must not ride on general warnings: the Evidence Engine folds "
        "parse_warnings into parse_issues, and mixing them would make every advisory "
        "claim to be an extraction problem"
    )
    assert legacy.parse_warnings == expected


def test_a_legacy_result_without_parse_warnings_is_unaffected():
    """Adapters that report nothing must not gain an empty-warning artefact."""
    from wifi_framework.core.execution.gateway import ExecutionGateway

    legacy = AdapterExecutionResult(
        success=True, raw_output="hi", exit_code=0, raw_command="echo hi", argv=["echo", "hi"]
    )
    assert legacy.parse_warnings == []

    _status, _failure, warnings = ExecutionGateway._classify(legacy, [])
    assert warnings == []


# ------------------------------------------------------------- contract -> evidence


def _execution(parse_warnings: list, warnings: list | None = None) -> ExecutionResult:
    return ExecutionResult(
        assessment_id=ASSESSMENT,
        action_id="action-parse",
        execution_id="execution-parse",
        capability="network_discovery",
        implementation="nmap",
        status=ExecutionStatus.SUCCESS,
        exit_code=0,
        duration_ms=1200,
        tool=ToolRef(name="nmap", version="7.94"),
        interface=InterfaceRef(name="wlan0"),
        command=["nmap", "10.0.0.1"],
        parse_warnings=list(parse_warnings),
        warnings=list(warnings or []),
        correlation_id=ASSESSMENT,
    )


def test_a_successful_run_with_a_parse_problem_declares_it_in_parse_issues():
    """The status is SUCCESS - the tool ran and exited 0. Without this channel the
    evidence set would look clean and empty."""
    engine = EvidenceEngine(AssessmentScope(authorized_networks=["10.0.0.0/24"]))
    result = engine.process(_execution(["nmap XML output could not be parsed"]), [])

    assert result.evidence_set.parse_issues, "the problem did not reach parse_issues"
    assert any("could not be parsed" in issue for issue in result.evidence_set.parse_issues)
    assert result.evidence_set.observations == []


def test_a_clean_successful_run_declares_no_parse_issues():
    engine = EvidenceEngine(AssessmentScope(authorized_networks=["10.0.0.0/24"]))
    result = engine.process(_execution([]), [])
    assert result.evidence_set.parse_issues == []


def test_the_applier_carries_parse_issues_into_its_report_notes():
    """The end of the chain: the World Model's own record of applying the evidence set
    must still say the parse was incomplete."""
    from wifi_framework.core.world.applier import WorldModelApplier

    engine = EvidenceEngine(AssessmentScope(authorized_networks=["10.0.0.0/24"]))
    processed = engine.process(_execution(["nmap XML output could not be parsed"]), [])

    state = AssessmentState(scope=AssessmentScope(authorized_networks=["10.0.0.0/24"]))
    report = WorldModelApplier().apply_evidence(state, processed.evidence_set, processed.evidences)

    assert any(note.startswith("parse_issue:") for note in report.notes), (
        f"the applier dropped the parse issue; notes were {report.notes}"
    )


def test_parse_warnings_survive_the_whole_chain():
    """Parser -> adapter -> result -> contract -> evidence set, in one pass."""
    adapter = _registry().get_adapter_instance("nmap")
    adapter.parse_warnings = []
    evidences = adapter.parse_output(NMAP_XML_TRUNCATED, "", 0, {"target": "10.0.0.1"}, None)

    from wifi_framework.core.execution.gateway import ExecutionGateway

    legacy = AdapterExecutionResult(
        success=True,
        raw_output=NMAP_XML_TRUNCATED,
        exit_code=0,
        raw_command="nmap 10.0.0.1",
        argv=["nmap", "10.0.0.1"],
        parse_warnings=list(adapter.parse_warnings),
    )

    _status, _failure, general_warnings = ExecutionGateway._classify(legacy, [])
    assert general_warnings == []

    # What the gateway's `_invoke` does: the adapter's parse warnings go on the
    # contract's own field, not onto the general warning list.
    engine = EvidenceEngine(AssessmentScope(authorized_networks=["10.0.0.0/24"]))
    result = engine.process(_execution(legacy.parse_warnings), evidences)

    assert result.evidence_set.observations == []
    assert any("could not be parsed" in issue for issue in result.evidence_set.parse_issues), (
        "a truncated nmap document reached the World Model looking like a clean empty scan"
    )


# ------------------------------------------------------- airodump-ng adapter
#
# The screen-output fallback used to return nothing at all, so an adapter that failed to
# read a busy capture recorded an empty observation. These go through the real adapter.

#: Compact modern-layout screen capture; the full fixtures live in tests/test_parsers.py.
AIRODUMP_SCREEN = """ CH  11 ][ Elapsed: 1 min ][ 2026-09-17 10:23

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC   CIPHER  AUTH  ESSID

 00:11:22:33:44:55  -45 100      512       42    0  11  130   WPA2  CCMP    PSK   TestNetwork

 Station            PWR   Rate    Lost    Frames  Notes  Probes

 11:22:33:44:55:66  -60   24e-54e  0      128          TestNetwork
"""

#: MACs with no table header: unattributable, and definitely not an empty capture.
AIRODUMP_UNREADABLE = (
    "00:11:22:33:44:55 unexpected format\n"
    "AA:BB:CC:DD:EE:FF unexpected format\n"
)


def test_the_airodump_adapter_reports_a_screen_capture_it_could_not_read():
    adapter = _registry().get_adapter_instance("airodump-ng")
    adapter.parse_warnings = []

    evidences = adapter.parse_output(AIRODUMP_UNREADABLE, "", 0, {}, "wlan0mon")

    assert evidences == []
    assert any("was not empty" in warning for warning in adapter.parse_warnings), (
        "an unreadable capture reached the World Model looking like an empty observation"
    )


def test_the_airodump_adapter_parses_screen_output_when_no_csv_file_exists():
    """No `--write` file means `csv_content` stays None and the screen fallback is the
    only source; it must actually produce evidence rather than an empty list."""
    adapter = _registry().get_adapter_instance("airodump-ng")
    adapter.parse_warnings = []

    evidences = adapter.parse_output(AIRODUMP_SCREEN, "", 0, {}, "wlan0mon")

    assert len(evidences) == 2
    bssids = {e.parsed_data.get("bssid") or e.parsed_data.get("client_mac") for e in evidences}
    assert bssids == {"00:11:22:33:44:55", "11:22:33:44:55:66"}

    # The fallback worked, and says so: screen parsing cannot attribute probe requests,
    # and leaving that unstated would let a truncated client record look complete.
    assert any(
        "does not reliably attribute probe requests" in warning
        for warning in adapter.parse_warnings
    )


def test_the_authoritative_csv_path_reports_nothing():
    csv_content = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "00:11:22:33:44:55, 2026-09-17 10:00:00, 2026-09-17 10:01:00, 11, 130, WPA2, "
        "CCMP, PSK, -45, 512, 0, , 11, TestNetwork, \n"
    )
    from wifi_framework.parsers.airodump import airodump_to_evidences

    issues = []
    evidences = airodump_to_evidences(
        raw_output="", csv_content=csv_content, interface="wlan0mon", issues=issues
    )
    assert len(evidences) == 1
    assert issues == [], "the authoritative CSV path produced spurious warnings"
