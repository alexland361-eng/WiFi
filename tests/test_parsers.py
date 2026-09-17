"""Tests for parsers."""
import pytest

from wifi_framework.parsers.iw import parse_iw_dev, parse_iw_list
from wifi_framework.parsers.airodump import (
    airodump_to_evidences,
    parse_airodump_csv,
    parse_airodump_text,
)
from wifi_framework.parsers.wash import parse_wash
from wifi_framework.parsers.nmap import parse_nmap_grepable, parse_nmap_normal


def test_parse_iw_dev():
    sample = """
phy#0
    Interface wlan0
        ifindex 3
        wdev 0x1
        addr 00:11:22:33:44:55
        ssid MyNetwork
        type managed
        channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
    Interface wlan0mon
        ifindex 4
        wdev 0x2
        addr 00:11:22:33:44:56
        type monitor
        channel 6 (2437 MHz)
"""

    interfaces = parse_iw_dev(sample)
    assert len(interfaces) == 2
    assert interfaces[0]["name"] == "wlan0"
    assert interfaces[0]["mac"] == "00:11:22:33:44:55"
    assert interfaces[0]["ssid"] == "MyNetwork"
    assert interfaces[0]["type"] == "managed"
    assert interfaces[0]["channel"] == 6
    assert interfaces[1]["name"] == "wlan0mon"
    assert interfaces[1]["type"] == "monitor"


def test_parse_iw_list():
    sample = """
Wiphy phy0
    max # scan SSIDs: 20
    Supported interface modes:
         * IBSS
         * managed
         * AP
         * AP/VLAN
         * monitor
         * mesh point
    Band 1:
        Capabilities: 0x11ef
"""

    caps = parse_iw_list(sample)
    assert caps["supports_monitor"] is True
    assert "monitor" in caps["interface_modes"]
    assert "managed" in caps["interface_modes"]


def test_parse_airodump_csv():
    csv_content = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
00:11:22:33:44:55, 2024-01-01 00:00:00, 2024-01-01 00:01:00,  6,  54, WPA2, CCMP, PSK, -45, 100, 0, 0.0.0.0, 9, MyNetwork,
AA:BB:CC:DD:EE:FF, 2024-01-01 00:00:00, 2024-01-01 00:01:00,  11,  54, WEP, WEP, , -70, 50, 10, 0.0.0.0, 7, WEPNet,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -50, 20, 00:11:22:33:44:55, MyNetwork
"""

    aps, clients = parse_airodump_csv(csv_content)
    assert len(aps) == 2
    assert aps[0]["bssid"] == "00:11:22:33:44:55"
    assert aps[0]["ssid"] == "MyNetwork"
    assert aps[0]["channel"] == 6
    assert "WPA2" in aps[0]["encryption"]

    assert len(clients) == 1
    assert clients[0]["client_mac"] == "11:22:33:44:55:66"
    assert clients[0]["ap_mac"] == "00:11:22:33:44:55"


def test_parse_wash():
    sample = """
BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
00:11:22:33:44:55  6   -45  2.0  No   Broadcom  MyNetwork
AA:BB:CC:DD:EE:FF  11  -70  1.0  Yes  Atheros   WEPNet
"""

    results = parse_wash(sample)
    assert len(results) == 2
    assert results[0]["bssid"] == "00:11:22:33:44:55"
    assert results[0]["channel"] == 6
    assert results[0]["wps_enabled"] is True
    assert results[0]["wps_locked"] is False
    assert results[1]["wps_locked"] is True


def test_parse_nmap_grepable():
    sample = """
# Nmap 7.80 scan initiated
Host: 192.168.1.1 () Status: Up
Host: 192.168.1.1 () Ports: 22/open/tcp//ssh//OpenSSH 7.9/, 80/open/tcp//http//Apache/
Host: 192.168.1.2 () Status: Up
Host: 192.168.1.2 () Ports: 443/open/tcp//https//nginx/
"""

    hosts = parse_nmap_grepable(sample)
    assert len(hosts) == 2
    assert hosts[0]["ip"] == "192.168.1.1"
    assert len(hosts[0]["ports"]) == 2
    assert hosts[0]["ports"][0]["port"] == 22
    assert hosts[0]["ports"][0]["service"] == "ssh"


def test_parse_nmap_normal():
    sample = """
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9
80/tcp open  http    Apache httpd 2.4.38

Nmap scan report for 192.168.1.2
Host is up.
PORT    STATE SERVICE VERSION
443/tcp open  https   nginx 1.14.2
"""

    hosts = parse_nmap_normal(sample)
    assert len(hosts) == 2
    assert hosts[0]["ip"] == "192.168.1.1"
    assert len(hosts[0]["ports"]) == 2


# ------------------------------------------------- airodump-ng screen output
#
# The CSV writer is authoritative, but when no --write file is found the adapter falls
# back to screen output. That fallback used to loop over every line computing a MAC
# regex and then `pass`, so it always returned two empty lists - and an assessment that
# failed to read a busy capture recorded "no access points observed".

#: Modern layout: `PWR RXQ`, the two-column signal field newer airodump-ng prints.
SCREEN_MODERN = """ CH  11 ][ Elapsed: 1 min ][ 2026-09-17 10:23 ][ Pseudo random frequency: 2.4.2

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC   CIPHER  AUTH  ESSID

 00:11:22:33:44:55  -45 100      512       42    0  11  130   WPA2  CCMP    PSK   TestNetwork
 AA:BB:CC:DD:EE:FF  -70   0       12        0    0   6   54e.  WPA   TKIP    PSK   <length:  0>
 12:34:56:78:9A:BC  -81  33       88        3    1  36  195   WPA2  CCMP    PSK   My Home WiFi 5G

 Station            PWR   Rate    Lost    Frames  Notes  Probes

 11:22:33:44:55:66  -60   24e-54e  0      128          TestNetwork
 77:88:99:AA:BB:CC  -72    0e- 1e  0        5          (not associated)
"""

#: Legacy layout: `PWR` only, and blank CIPHER/AUTH on an open network.
SCREEN_LEGACY = """ CH  6 ][ Elapsed: 12 s ][ 2026-09-17 10:24

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC   CIPHER  AUTH  ESSID

 CC:DD:EE:FF:00:11  -52      300       18    0   6  130   OPN                 OpenCafe

 Station            PWR   Rate    Lost    Frames  Probes

 99:88:77:66:55:44  -65    0e- 1      12         OpenCafe
"""


def test_screen_output_reads_every_ap_column_in_the_modern_layout():
    aps, clients = parse_airodump_text(SCREEN_MODERN)

    assert [ap["bssid"] for ap in aps] == [
        "00:11:22:33:44:55",
        "AA:BB:CC:DD:EE:FF",
        "12:34:56:78:9A:BC",
    ]
    first = aps[0]
    assert first["channel"] == 11, "CH was read as a span covering MB too, not as a channel"
    assert first["power"] == -45
    assert first["signal"] == -45
    assert first["encryption"] == ["WPA2"]
    assert first["cipher_list"] == ["CCMP"]
    assert first["auth_list"] == ["PSK"]
    assert first["ssid"] == "TestNetwork"
    assert first["is_hidden"] is False


def test_an_ssid_containing_spaces_survives_screen_parsing():
    """Splitting on whitespace would yield 'My'; slicing at the header offset yields
    the whole SSID. An SSID is what scope authorization matches on, so truncating it
    would misclassify an in-scope network."""
    aps, _clients = parse_airodump_text(SCREEN_MODERN)
    assert aps[2]["ssid"] == "My Home WiFi 5G"


def test_a_hidden_network_is_recognised_in_screen_output():
    aps, _clients = parse_airodump_text(SCREEN_MODERN)
    hidden = aps[1]
    assert hidden["is_hidden"] is True
    assert hidden["ssid"] == "", "the <length: 0> marker must not become the SSID"


def test_screen_output_reads_the_legacy_single_pwr_layout():
    """The layouts differ by a column, which is why offsets come from the header the
    tool printed rather than being assumed."""
    aps, clients = parse_airodump_text(SCREEN_LEGACY)

    assert len(aps) == 1
    ap = aps[0]
    assert ap["bssid"] == "CC:DD:EE:FF:00:11"
    assert ap["channel"] == 6
    assert ap["power"] == -52
    assert ap["encryption"] == ["OPN"]
    assert ap["cipher_list"] == []
    assert ap["auth_list"] == []
    assert ap["ssid"] == "OpenCafe"

    assert len(clients) == 1
    assert clients[0]["client_mac"] == "99:88:77:66:55:44"
    assert clients[0]["power"] == -65


def test_screen_output_does_not_guess_a_probe_ssid():
    """The station table's trailing text does not start under its header and `Rate`
    contains a space, so offset slicing returned 'stNetwork' for 'TestNetwork'. A
    truncated SSID attached to a client becomes fabricated evidence, so the field is
    left unset and the limitation is reported instead."""
    _aps, clients = parse_airodump_text(SCREEN_MODERN, issues=[])
    assert all(client["probed_ssid"] is None for client in clients)
    assert all(client["ap_mac"] is None for client in clients)

    issues = []
    parse_airodump_text(SCREEN_MODERN, issues=issues)
    assert any("does not reliably attribute probe requests" in issue for issue in issues)


def test_screen_output_becomes_evidence():
    issues = []
    evidences = airodump_to_evidences(raw_output=SCREEN_MODERN, issues=issues)
    assert len(evidences) == 5
    assert len([e for e in evidences if e.evidence_type.value == "access_point"]) == 3
    assert len([e for e in evidences if e.evidence_type.value == "client"]) == 2


def test_screen_output_with_macs_but_no_table_header_is_reported():
    """MACs present, nothing attributable: the capture was not empty, and saying so is
    the difference between 'we could not read it' and 'the radio saw nothing'."""
    issues = []
    aps, clients = parse_airodump_text(
        "00:11:22:33:44:55 unexpected format\nAA:BB:CC:DD:EE:FF unexpected format\n",
        issues=issues,
    )
    assert aps == [] and clients == []
    assert len(issues) == 1
    assert "2 MAC address line(s)" in issues[0]
    assert "was not empty" in issues[0]


def test_a_truncated_screen_capture_is_reported():
    issues = []
    aps, clients = parse_airodump_text(
        " BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC   CIPHER  AUTH  ESSID\n",
        issues=issues,
    )
    assert aps == [] and clients == []
    assert any("no MAC address lines" in issue for issue in issues)


def test_tool_error_output_is_reported_as_unparseable():
    issues = []
    aps, clients = parse_airodump_text(
        "ioctl(SIOCSIFFLAGS) failed: Device or resource busy\n", issues=issues
    )
    assert aps == [] and clients == []
    assert issues, "an interface error was silently reported as an empty observation"


def test_a_clean_screen_capture_reports_nothing():
    issues = []
    parse_airodump_text(SCREEN_MODERN, issues=issues)
    assert [issue for issue in issues if "MAC address" in issue] == []


# ------------------------------------------------------- airodump-ng CSV failures


def test_csv_parsing_is_unchanged_for_valid_input():
    csv_content = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "00:11:22:33:44:55, 2026-09-17 10:00:00, 2026-09-17 10:01:00, 11, 130, WPA2, "
        "CCMP, PSK, -45, 512, 0, , 11, TestNetwork, \n"
        "\n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
        "11:22:33:44:55:66, 2026-09-17 10:00:10, 2026-09-17 10:01:00, -60, 128, "
        "00:11:22:33:44:55, TestNetwork\n"
    )
    issues = []
    aps, clients = parse_airodump_csv(csv_content, issues=issues)
    assert len(aps) == 1 and aps[0]["ssid"] == "TestNetwork"
    assert len(clients) == 1 and clients[0]["client_mac"] == "11:22:33:44:55:66"
    assert issues == []


def test_an_unrecognizable_csv_section_is_reported():
    issues = []
    aps, clients = parse_airodump_csv(
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "00:11:22:33:44:55, 2026-09-17 10:00:00, 2026-09-17 10:01:00, 11, 130, WPA2, "
        "CCMP, PSK, -45, 512, 0, , 11, TestNetwork, \n"
        "\n"
        "some noise that is not a client table\n",
        issues=issues,
    )
    assert len(aps) == 1
    assert any("section 2 has no recognized header" in issue for issue in issues), issues


def test_output_with_no_csv_header_at_all_is_reported():
    issues = []
    aps, clients = parse_airodump_csv("nothing resembling csv\n", issues=issues)
    assert aps == [] and clients == []
    assert any("no airodump-ng CSV header" in issue for issue in issues)


def test_an_empty_csv_is_reported_as_empty():
    issues = []
    aps, clients = parse_airodump_csv("", issues=issues)
    assert aps == [] and clients == []
    assert any("was empty" in issue for issue in issues)


def test_a_declared_but_unreadable_csv_reports_the_fallback():
    """The adapter passes `csv_content=None` when no --write file exists, and a real
    file that parses to nothing otherwise. Only the second case should complain about
    the CSV, and both should say the screen fallback is best-effort."""
    issues = []
    evidences = airodump_to_evidences(
        raw_output=SCREEN_MODERN, csv_content="garbage, columns\nnot, a table\n", issues=issues
    )
    assert evidences, "the screen fallback did not run after the CSV failed"
    assert any("falling back to" in issue for issue in issues), issues


def test_an_undeclared_csv_does_not_produce_csv_complaints():
    """Callers may pass screen text positionally; offering it to the CSV parser is a
    guess, so its complaints must not be reported as a CSV failure."""
    issues = []
    evidences = airodump_to_evidences(raw_output=SCREEN_LEGACY, issues=issues)
    assert evidences
    assert not any("CSV header" in issue for issue in issues), issues


@pytest.mark.parametrize("parser", [parse_airodump_text, parse_airodump_csv])
def test_the_airodump_parsers_still_work_without_an_issues_argument(parser):
    """`issues` is optional so every existing caller is unaffected."""
    aps, clients = parser(SCREEN_MODERN)
    assert isinstance(aps, list) and isinstance(clients, list)
