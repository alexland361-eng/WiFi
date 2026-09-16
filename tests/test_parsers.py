"""Tests for parsers."""
from wifi_framework.parsers.iw import parse_iw_dev, parse_iw_list
from wifi_framework.parsers.airodump import parse_airodump_csv
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
