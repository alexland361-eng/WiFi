"""An address has one meaning, and it is decided in one place.

`utils/validation.normalize_mac` is the framework's answer to "is this a MAC address". It
earned that role the hard way: an earlier version stripped non-hex characters, so
`AABBCCDDEEFFGG` became `AA:BB:CC:DD:EE:FF` - a *different* address - and an operator's
scope allowlist silently authorized a network nobody had named.

Three parser sites were not asking it. `parse_wash` took the 17 hex-or-colon characters its
row pattern captured as an address unchanged, so `:::::::::::::::::` was recorded as a BSSID;
its fallback branch used an unanchored `re.match`, so `AA:BB:CC:DD:EE:FFGG` was recorded with
the trailing garbage attached, while the dash form - which the canonical rule accepts - was
dropped without a word. `parsers/base.py` kept its own regexes, which accepted mixed
separators and extracted `00:11:22:33:44:55` out of an eight-group run.

A BSSID decides what may be attacked, so the parser and the scope cannot be allowed two
opinions about what one is. These tests hold both halves of that: a value the canonical rule
refuses must not become an observation, and one it accepts must not be lost. What is refused
is reported, through the same `parse_warnings` channel `test_parse_issue_reporting.py` pins
for nmap and tshark - wash was the parser left out of it.

The invariant asserted throughout is that every address a parser emits is a *fixed point* of
`normalize_mac`: feeding it back changes nothing, because it is already in the one canonical
form. An address that is not a fixed point is one some other component will disagree with.
"""
from __future__ import annotations

import pytest

from wifi_framework.core.models.scope import AssessmentScope, ScopeEnforcer
from wifi_framework.parsers import base as parser_base
from wifi_framework.parsers.wash import parse_wash, wash_to_evidences
from wifi_framework.utils.validation import normalize_mac, validate_ip, validate_mac

#: wash only parses rows it sees *after* a line carrying both of these.
HEADER = "BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID\n"

#: Shaped like a real run, including what wash prints around its rows and what the adapter
#: appends from stderr - `parse_output` hands the parser `raw_output + error_output` as one
#: document, so once the header has been seen, stderr is parsed as rows too.
REAL_WASH_OUTPUT = HEADER + """Scanning for WPS enabled access points...
00:11:22:33:44:55  6   -45  2.0  No   Broadcom  MyNetwork
AA:BB:CC:DD:EE:FFGG
aa:bb:cc:dd:ee:ff  11  -70  1.0  Yes  Atheros   WEPNet
:::::::::::::::::
[!] Found packet with bad FCS, skipping
202401011200
No more packets to read
"""


def _rows(*lines: str) -> str:
    return HEADER + "".join(line + "\n" for line in lines)


def _registry():
    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.tools.registry_loader import load_all_adapters

    return load_all_adapters(CapabilityRegistry())


# ------------------------------------------------------- wash: what becomes an observation


def test_a_well_formed_row_parses_as_it_always_did():
    """The fix must not change what a good row produces - this is the regression guard."""
    results = parse_wash(
        _rows("00:11:22:33:44:55  6   -45  2.0  No   Broadcom  MyNetwork")
    )
    assert len(results) == 1
    entry = results[0]
    assert entry["bssid"] == "00:11:22:33:44:55"
    assert entry["channel"] == 6
    assert entry["signal"] == -45
    assert entry["ssid"] == "MyNetwork"
    assert entry["wps_enabled"] is True
    assert entry["wps_locked"] is False


@pytest.mark.parametrize(
    "row",
    [
        # Seventeen characters of hex-or-colon, which the row pattern accepts and which is
        # not an address. Recorded as a BSSID before the fix.
        ":::::::::::::::::  6   -45  2.0  No   Broadcom  MyNetwork",
        "AABBCCDDEEFF00112  6   -45  2.0  No   Broadcom  MyNetwork",
        "1:23:45:67:89:AB:C  6   -45  2.0  No   Broadcom  MyNetwork",
        # The fallback branch: a colon-form address with trailing garbage, which an
        # unanchored re.match accepted along with the garbage.
        "AA:BB:CC:DD:EE:FFGG",
    ],
)
def test_a_bssid_the_canonical_rule_refuses_does_not_become_an_observation(row):
    results = parse_wash(_rows(row))
    assert results == [], f"a value normalize_mac rejects reached the world model: {results}"


@pytest.mark.parametrize(
    "row",
    [
        ":::::::::::::::::  6   -45  2.0  No   Broadcom  MyNetwork",
        "AABBCCDDEEFF00112  6   -45  2.0  No   Broadcom  MyNetwork",
        "AA:BB:CC:DD:EE:FFGG",
    ],
)
def test_a_refused_bssid_is_reported_naming_the_value(row):
    """Silently dropping is the failure this pass has been removing. The report names the
    offending token so an operator can find it in the raw output."""
    issues: list[str] = []
    results = parse_wash(_rows(row), issues)
    assert results == []
    assert issues, "the parser refused a row and said nothing about it"
    token = row.split()[0]
    assert token in issues[0], f"the report does not name {token!r}: {issues[0]}"


def test_the_two_kinds_of_refusal_are_distinguished():
    """"Not an address" and "an address, in a form this line does not establish" send an
    operator looking in different directions - one at a corrupt capture, one at a tool
    emitting a format the parser did not expect."""
    not_an_address: list[str] = []
    parse_wash(_rows("AA:BB:CC:DD:EE:FFGG"), not_an_address)
    assert "not a MAC address" in not_an_address[0]

    bare_form: list[str] = []
    parse_wash(_rows("AABBCCDDEEFF"), bare_form)
    assert "bare form" in bare_form[0]
    assert normalize_mac("AABBCCDDEEFF") is not None, (
        "the canonical rule does accept this value; the report must not claim otherwise"
    )


def test_a_dash_form_bssid_is_parsed_rather_than_silently_dropped():
    """The old fallback was colon-only, so an address the canonical rule accepts produced no
    entry and no report - an AP wash really did find, missing from the results."""
    results = parse_wash(_rows("AA-BB-CC-DD-EE-FF"))
    assert len(results) == 1
    assert results[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert results[0]["raw_line"] == "AA-BB-CC-DD-EE-FF"


def test_a_lowercase_bssid_is_normalized_to_the_canonical_form():
    results = parse_wash(_rows("aa:bb:cc:dd:ee:ff  11  -70  1.0  Yes  Atheros  WEPNet"))
    assert len(results) == 1
    assert results[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert results[0]["wps_locked"] is True


def test_every_bssid_the_parser_emits_is_a_fixed_point_of_the_canonical_rule():
    """The invariant that makes parser and scope agree: re-normalizing a parsed address
    changes nothing, because it is already in the one canonical form."""
    for entry in parse_wash(REAL_WASH_OUTPUT):
        assert normalize_mac(entry["bssid"]) == entry["bssid"]
        assert validate_mac(entry["bssid"])[0]


def test_prose_around_the_rows_is_not_reported_as_a_problem():
    """wash prints banner text and stderr between and around its rows. Reporting those would
    fill parse_warnings with prose and bury the malformed rows the list exists to surface."""
    issues: list[str] = []
    results = parse_wash(REAL_WASH_OUTPUT, issues)

    assert [entry["bssid"] for entry in results] == [
        "00:11:22:33:44:55",
        "AA:BB:CC:DD:EE:FF",
    ]
    assert [entry["channel"] for entry in results] == [6, 11]

    # Three malformed values, and nothing from the four prose lines.
    assert len(issues) == 3, issues
    assert not any("Scanning" in issue for issue in issues)
    assert not any("bad FCS" in issue for issue in issues)
    assert not any("No more packets" in issue for issue in issues)


def test_a_prose_only_run_produces_no_entries_and_no_issues():
    issues: list[str] = []
    results = parse_wash(
        _rows("Scanning for WPS enabled access points...", "[!] bad FCS", "No more packets"),
        issues,
    )
    assert results == []
    assert issues == []


def test_the_issues_argument_is_optional():
    """Callers that do not want the reports - the exercise script, existing callers - must
    not have to pass a list, and must not get an AttributeError for not doing so."""
    assert len(parse_wash(REAL_WASH_OUTPUT)) == 2
    assert len(parse_wash(HEADER)) == 0
    assert parse_wash("") == []


def test_rows_before_the_header_are_not_parsed():
    """Unchanged behaviour, pinned because the fix touched this loop."""
    assert parse_wash("AA:BB:CC:DD:EE:FF  6  -45  2.0  No  Vendor  Net") == []


def test_the_dashed_separator_wash_prints_under_its_header_is_skipped():
    """Real wash output separates the header from the rows with a rule of dashes, and the
    fallback branch would otherwise be handed a line whose first field is all punctuation."""
    output = HEADER + "-" * 70 + "\n" + "00:11:22:33:44:55  6   -45  2.0  No   Broadcom  MyNetwork\n"
    issues: list[str] = []
    results = parse_wash(output, issues)
    assert [entry["bssid"] for entry in results] == ["00:11:22:33:44:55"]
    assert issues == [], f"a separator line was reported as a parse problem: {issues}"


# ------------------------------------------------------------- wash: the reporting channel


def test_wash_to_evidences_forwards_the_issues_list():
    """Without the pass-through the evidence list is all a caller sees, and a row wash
    reported but the parser could not use is indistinguishable from a row wash never saw."""
    issues: list[str] = []
    evidences = wash_to_evidences(REAL_WASH_OUTPUT, interface="wlan0mon", issues=issues)

    assert len(evidences) == 2
    assert len(issues) == 3
    assert all(ev.parsed_data["bssid"] for ev in evidences)


def test_the_wash_adapter_records_the_parse_problem_on_the_result():
    """`parse_output` returns evidence and has no other way to say "this did not fully
    parse", so the adapter records it on itself - the wiring nmap and tshark already have."""
    adapter = _registry().get_adapter_instance("wash")
    assert adapter is not None, "wash capability missing - the test would be vacuous"

    evidences = adapter.parse_output(REAL_WASH_OUTPUT, "", 0, {}, "wlan0mon")
    assert len(evidences) == 2
    assert adapter.parse_warnings, "the adapter noticed nothing"
    assert "AA:BB:CC:DD:EE:FFGG" in adapter.parse_warnings[0]

    # A clean parse leaves nothing behind, including from a previous run.
    adapter.parse_warnings = []
    adapter.parse_output(
        _rows("00:11:22:33:44:55  6   -45  2.0  No   Broadcom  MyNetwork"), "", 0, {}, "wlan0mon"
    )
    assert adapter.parse_warnings == []


def test_a_parsed_bssid_can_match_an_authorized_scope_entry():
    """The consequence the change exists for: an address wash reports and an address the
    operator authorized are normalized by the same function, so they meet. A dash-form BSSID
    used to be dropped, so this AP would never have been seen at all - and had it been
    recorded with trailing garbage instead, every invasive action against it would have been
    refused against an operator who had authorized it by name."""
    scope = AssessmentScope(authorized_bssids=["AA:BB:CC:DD:EE:FF"])
    enforcer = ScopeEnforcer(scope)

    parsed = parse_wash(_rows("AA-BB-CC-DD-EE-FF"))
    assert len(parsed) == 1

    allowed, reason = enforcer.check_wireless_action_allowed(
        None, parsed[0]["bssid"], invasive=True
    )
    assert allowed, reason

    refused, _ = enforcer.check_wireless_action_allowed(None, "11:22:33:44:55:66", invasive=True)
    assert not refused


# ---------------------------------------------------- base helpers: finding addresses in text


@pytest.mark.parametrize(
    "spelling",
    ["aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "Aa:bB:Cc:dD:eE:fF", "AA-BB-CC-DD-EE-FF"],
)
def test_extract_macs_returns_the_canonical_form_for_every_spelling(spelling):
    assert parser_base.extract_macs(spelling) == ["AA:BB:CC:DD:EE:FF"]


def test_extract_macs_finds_addresses_inside_surrounding_text():
    text = "client aa:bb:cc:dd:ee:ff associated with 00:11:22:33:44:55 (mine)"
    assert parser_base.extract_macs(text) == [
        "AA:BB:CC:DD:EE:FF",
        "00:11:22:33:44:55",
    ]


def test_extract_macs_refuses_mixed_separators():
    """The old pattern allowed `[:-]` at each position independently, so this was returned as
    a MAC address while `normalize_mac` - and therefore every scope check - rejected it."""
    assert parser_base.extract_macs("AA:BB-CC:DD-EE:FF") == []
    assert normalize_mac("AA:BB-CC:DD-EE:FF") is None


@pytest.mark.parametrize(
    "text",
    [
        "00:11:22:33:44:55:66",  # eight groups is not an address plus a leftover
        "AA:BB:CC:DD:EE:FFGG",  # trailing garbage
        "xxAABBCCDDEEFFyy",  # embedded in a longer token
        "AABBCCDDEEFFGG",  # the value normalize_mac was written to refuse
    ],
)
def test_extract_macs_does_not_take_part_of_a_longer_run(text):
    """Extracting a substring and calling it an address reports one that is not in the text."""
    assert parser_base.extract_macs(text) == []


@pytest.mark.parametrize(
    "text", ["202401011200", "frame 112233445566 seen", "counter=999999999999"]
)
def test_extract_macs_does_not_invent_an_address_from_a_bare_number(text):
    """A bare twelve-digit run is a timestamp or a counter far more often than an address, and
    tool output is full of them. `normalize_mac` accepts the bare form because an operator
    writing a scope entry means an address; extracting from free text has no such evidence.
    `parse_wash` accepts it for the same reason it is refused here - see its fallback branch."""
    assert parser_base.extract_macs(text) == []


def test_extract_macs_keeps_duplicates_in_the_order_found():
    """The same address twice in a capture is two observations of it. Collapsing them is the
    caller's decision, not this function's."""
    assert parser_base.extract_macs("aa:bb:cc:dd:ee:ff then AA:BB:CC:DD:EE:FF") == [
        "AA:BB:CC:DD:EE:FF",
        "AA:BB:CC:DD:EE:FF",
    ]


def test_every_address_extract_macs_returns_is_one_the_canonical_rule_accepts():
    """The property that matters, checked over a corpus of near misses rather than asserted
    case by case: nothing leaves this function that a scope check would disagree with."""
    corpus = [
        "aa:bb:cc:dd:ee:ff and 00:11:22:33:44:55",
        "AA:BB-CC:DD-EE:FF 00:11:22:33:44:55:66 AABBCCDDEEFFGG",
        "202401011200 xxAABBCCDDEEFFyy FF:FF:FF:FF:FF:FF",
        "no addresses here at all",
        "",
    ]
    found = [mac for text in corpus for mac in parser_base.extract_macs(text)]
    assert found, "the corpus should still yield real addresses, or the test proves nothing"
    for mac in found:
        assert validate_mac(mac)[0], mac
        assert normalize_mac(mac) == mac


def test_extract_ips_finds_a_real_address_in_text():
    assert parser_base.extract_ips("host 192.168.1.1 is up") == ["192.168.1.1"]
    assert parser_base.extract_ips("10.0.0.1 and 10.0.0.254") == ["10.0.0.1", "10.0.0.254"]


def test_extract_ips_refuses_impossible_octets():
    """`\\d{1,3}` has the right shape and the wrong range; `validate_ip` is
    `ipaddress.ip_address`, which is the authority the scope checks also use."""
    assert parser_base.extract_ips("999.999.999.999") == []
    assert parser_base.extract_ips("256.1.1.1") == []
    assert validate_ip("999.999.999.999")[0] is False


def test_extract_ips_does_not_split_a_longer_dotted_run():
    """Unbounded, the pattern reported `1.2.3.4` and `5.6.7.8` from a token that is neither."""
    assert parser_base.extract_ips("1.2.3.4.5.6.7.8") == []


def test_extract_ips_leaves_the_octet_range_judgement_to_the_standard_library():
    """A leading zero is ambiguous - octal to some tools, decimal to others - and
    `ipaddress` refuses it. Delegating means this parser and a scope entry agree."""
    assert parser_base.extract_ips("192.168.001.1") == []
    assert validate_ip("192.168.001.1")[0] is False


def test_extract_ips_is_ipv4_only_and_says_so():
    """Pinned because the name promises more than the function does. An IPv6 address is not
    found and not reported as an error either, so a caller with a dual-stack scope must not
    read an empty result as "no addresses here". Extracting IPv6 from arbitrary text is not a
    regex problem - colon-separated hex collides with MAC addresses and frame numbers."""
    assert parser_base.extract_ips("fe80::1 and 2001:db8::ff") == []
    assert parser_base.extract_ips("fe80::1 and 192.168.1.1") == ["192.168.1.1"]
    assert "IPv4 only" in (parser_base.extract_ips.__doc__ or "")


# ------------------------------------------------------- base helpers: key/value extraction


def test_parse_key_value_output_keeps_a_key_whose_value_is_empty():
    """`if key and value` dropped it, discarding something the parser did see - and here the
    empty value is the interesting case: `ESSID:` with nothing after it is a hidden network,
    not a missing field."""
    parsed = parser_base.parse_key_value_output("ESSID:\nChannel: 6")
    assert parsed == {"essid": "", "channel": "6"}
    assert "essid" in parsed


def test_parse_key_value_output_normalizes_keys():
    parsed = parser_base.parse_key_value_output("Signal Level: -45\nWPS Version: 2.0")
    assert parsed == {"signal_level": "-45", "wps_version": "2.0"}


def test_parse_key_value_output_splits_on_the_first_delimiter_only():
    """A value may contain the delimiter; a key may not."""
    assert parser_base.parse_key_value_output("note: 1:2:3") == {"note": "1:2:3"}


def test_parse_key_value_output_skips_lines_that_are_not_pairs():
    parsed = parser_base.parse_key_value_output("malformed\n: orphan\na: 1\n\nb: 2")
    assert parsed == {"a": "1", "b": "2"}


def test_parse_key_value_output_honours_a_custom_delimiter():
    assert parser_base.parse_key_value_output("a=1\nb=2", delimiter="=") == {
        "a": "1",
        "b": "2",
    }


def test_parse_key_value_output_keeps_the_last_of_a_repeated_key():
    """Documented rather than left to be discovered: a dict cannot hold both, and which one
    wins is part of the contract."""
    assert parser_base.parse_key_value_output("a: 1\na: 2") == {"a": "2"}
