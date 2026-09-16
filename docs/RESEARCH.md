# Deep Research - Kali Wireless Toolchain & Fullest Potential Usage

This document demonstrates thorough, structured research conducted before implementing each capability, documenting sources, real usage, output formats, operational characteristics, and how the framework leverages each tool's fullest potential according to the adaptive philosophy.

**Research Methodology**: Official documentation, Kali Tools docs, Aircrack-ng docs, Wireshark docs, Scapy docs, tool --help output, man pages, GitHub repositories, and real execution testing where possible. All sources credited.

---

## 1. Wireless Interface and Radio Management

### 1.1 Aircrack-ng Suite - Research

**Source**: https://www.aircrack-ng.org/doku.php, https://www.kali.org/tools/aircrack-ng/

The Aircrack-ng suite is NOT monolithic - each binary has distinct purpose:

#### `airmon-ng` - Interface and Monitor-Mode Management
**Real usage**:
```bash
airmon-ng                    # List interfaces, drivers, chipsets
airmon-ng check              # List processes interfering with monitor mode (NetworkManager, wpa_supplicant)
airmon-ng check kill         # Kill interfering processes
airmon-ng start wlan0        # Create monitor interface wlan0mon (mac80211: creates vif)
airmon-ng start wlan0 6      # Start on channel 6
airmon-ng stop wlan0mon      # Remove monitor vif, restore managed
```

**Operational characteristics**:
- Requires root, uses `iw` under the hood for mac80211
- On old drivers: creates `mon0`, on new: `wlan0mon`
- Parses output: `(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)` → monitor interface name
- Failure modes: unsupported driver (e.g., no monitor), interface busy, NetworkManager interference

**Framework usage to fullest potential**:
- Adapter implements `check`, `start`, `stop`, `list` actions, not just start
- Parses interfering processes from `check` output for audit
- Extracts monitor interface name via regex `on\s+\[phy\d+\](\w+mon)` for state update
- Capability metadata: `interface_capabilities: [monitor_mode]`, `privileges: [root]`, `dependencies: [iw]`
- Planner: Only selects `start` when world model has no monitor interface but needs active_observation; selects `check` early in capability_discovery phase
- Experience: Tracks success rate of monitor creation per driver

#### `airodump-ng` - Wireless Discovery
**Real usage**:
```bash
airodump-ng wlan0mon
airodump-ng -c 6 wlan0mon                    # Fixed channel
airodump-ng --bssid 00:11:22:33:44:55 wlan0mon  # Filter BSSID
airodump-ng -w /tmp/cap --output-format csv,pcap --write-interval 1 wlan0mon
airodump-ng --berlin 60 -w /tmp/cap wlan0mon   # Time before AP removal
airodump-ng --wps --output-format csv wlan0mon # Include WPS info
```

**Output formats**:
- Screen: Real-time table with BSSID, PWR, Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, ESSID, STATION, etc.
- CSV: Two sections separated by blank line: APs (BSSID, channel, privacy, cipher, auth, power, beacons, IV, ESSID) and clients (Station MAC, Power, BSSID, Probed ESSIDs)
- pcap: Raw 802.11 frames
- kismet csv, netxml, etc.

**Framework fullest potential**:
- Adapter uses `-w <prefix> --output-format csv --write-interval 1` to get machine-parseable CSV while also showing screen
- Handles temp file lifecycle: creates prefix in /tmp, after execution searches for `-01.csv`, parses, then cleans all files with prefix (pcap, csv, kismet.csv)
- Parser `parse_airodump_csv`: Splits by blank lines, uses csv.DictReader, strips keys, handles AP section (ESSID distinct field) vs client section (Station MAC), extracts encryption list, cipher list, auth list, signal, hidden detection (empty ESSID)
- Evidence: Separate Evidence per AP and per client, with BSSID, SSID, channel, encryption, signal, is_hidden, confidence HIGH
- WorldModel: Updates APs and clients, maintains client_macs per AP, channels_observed, ssids_observed
- Planner: Scores high for `wireless_observation` uncertainty, prefers when no APs observed, can be re-selected if new evidence makes it useful (e.g., after channel change)
- Verification: AP observed by airodump and also by tshark or iw scan → promoted to verified

#### `aireplay-ng` - Frame Injection and Active Testing (NEW - Added after deep research)
**Real usage**:
```bash
aireplay-ng --test wlan0mon                  # Injection test
aireplay-ng -0 1 -a 00:11:22:33:44:55 wlan0mon  # Deauth 1 client (broadcast)
aireplay-ng -0 5 -a 00:11:22:33:44:55 -c 11:22:33:44:55:66 wlan0mon # Targeted deauth
aireplay-ng -1 0 -a 00:11:22:33:44:55 wlan0mon  # Fake auth
aireplay-ng -3 -b 00:11:22:33:44:55 wlan0mon    # ARP replay
aireplay-ng -9 wlan0mon                        # Injection test
```

**Operational**: Highly invasive, requires monitor + injection support, authorization critical, can disrupt network

**Framework fullest potential**:
- Adapter implements `test`, `deauth`, `fakeauth`, `arpreplay` actions with strict scope enforcement
- Parameters: `action`, `bssid`, `client_mac`, `count`, `delay`
- Only selected when in-scope AP and explicit authorization, planner penalizes invasive unless high priority
- Audit logs invasive flag
- Failure: unsupported_driver if injection test fails

#### `aircrack-ng` - Capture Analysis
**Real usage**:
```bash
aircrack-ng -w wordlist.txt capture.cap
aircrack-ng -w wordlist.txt -b 00:11:22:33:44:55 capture.cap
aircrack-ng -a 2 -w wordlist.txt capture.cap  # WPA
```

**Framework**: Offline analysis, treated as credential assessment, not run blindly

#### `airdecap-ng`, `airbase-ng`, etc.
**Research**: 
- `airdecap-ng`: Decrypts WEP/WPA capture when key known: `airdecap-ng -e MyNetwork -p password capture.cap`
- `airbase-ng`: Simulates AP for testing: `airbase-ng -e FakeAP -c 6 wlan0mon`
- `packetforge-ng`: Crafts packets: `packetforge-ng -0 -a 00:11:22:33:44:55 -h 11:22:33:44:55:66 -k 192.168.1.1 -l 192.168.1.100 -y fragment.xor -w custom.cap`
- `wpaclean`, `airdecloak-ng`, `ivstools`: Capture manipulation

**Framework**: Each registered with distinct capability, not treated as one monolithic tool

### 1.2 `iw` - Low-Level Wireless Configuration

**Source**: https://wireless.wiki.kernel.org/en/users/documentation/iw, `man iw`

**Real usage**:
```bash
iw dev                          # List interfaces, phy, addr, type, channel, ssid
iw dev wlan0 link               # Link status: SSID, BSSID, freq, signal, tx bitrate
iw dev wlan0 info               # Interface info
iw dev wlan0 scan               # Scan APs (detailed IE, signal, encryption)
iw dev wlan0 scan | grep SSID   # Quick SSID list
iw list                         # PHY capabilities: bands, frequencies, interface modes (managed, monitor, AP, etc.), HT, VHT
iw phy phy0 info                # Specific phy
iw dev wlan0 set type monitor   # Set monitor
iw dev wlan0 set channel 6      # Set channel
```

**Output parsing**:
- `iw dev`: `phy#0\n\tInterface wlan0\n\t\tifindex 3\n\t\twdev 0x1\n\t\taddr 00:11:22:33:44:55\n\t\tssid MyNetwork\n\t\ttype managed\n\t\tchannel 6 (2437 MHz)`
- `iw list`: `Supported interface modes:\n\t * managed\n\t * monitor\n\t * AP`

**Framework fullest potential**:
- Two adapters: `iw_dev` (interface discovery) and `iw_list` (capability discovery)
- `iw_dev` adapter supports subcommands `link`, `info`, `scan` via parameters
- Parser `parse_iw_dev`: Regex for phy, Interface, addr, ssid, type, channel, frequency
- Parser `parse_iw_list`: Detects monitor mode support via `* monitor` in Supported interface modes
- WorldModel: InterfaceInfo with supports_monitor flag from iw list
- Planner: Uses iw_dev early for interface_discovery, iw_list for capability_discovery
- Non-invasive, no root required for dev/list, quick (2-3 sec)

### 1.3 `iwconfig` - Legacy

**Source**: `man iwconfig`, https://www.kali.org/tools/wireless-tools/

**Real usage**:
```bash
iwconfig
iwconfig wlan0
iwconfig wlan0 essid MyNetwork
iwconfig wlan0 mode Monitor
iwconfig wlan0 channel 6
```

**Output**: `wlan0 IEEE 802.11 ESSID:"MyNetwork" Mode:Managed Frequency:2.437 GHz Access Point: 00:11:22:33:44:55`

**Framework**: Legacy fallback when iw not available, parser extracts ESSID, Mode, Frequency, Access Point, wireless flag (no wireless extensions)

### 1.4 `rfkill` - Radio Block

**Source**: `man rfkill`, https://wireless.wiki.kernel.org/en/users/documentation/rfkill

**Real usage**:
```bash
rfkill list
rfkill list wifi
rfkill unblock wifi
rfkill block wifi
```

**Output**:
```
0: phy0: Wireless LAN
    Soft blocked: no
    Hard blocked: no
```

**Framework**: Capability discovery phase, checks soft/hard blocked, can unblock with root, evidence type RADIO_BLOCK, non-invasive

### 1.5 `ethtool` - Driver Info

**Source**: `man ethtool`

**Real usage**:
```bash
ethtool wlan0
ethtool -i wlan0  # Driver: iwlwifi, version, firmware, bus-info
```

**Framework**: Diagnostics when execution fails (unsupported_driver), provides driver info for experience store

---

## 2. Wireless Discovery and Reconnaissance

### 2.1 Kismet - Passive Reconnaissance Platform

**Source**: https://www.kismetwireless.net/docs/, https://www.kali.org/tools/kismet/

**Real usage**:
- Long-running server: `kismet -c wlan0mon:type=linuxwifi --log-prefix /tmp/kismet`
- REST API: `http://localhost:2501/` for real-time devices
- Logs: pcapng, kismet log, gpsxml
- Not one-shot scanner, maintains continuously updated view

**Framework fullest potential**:
- Adapter treats as persistent observation source, not one-shot
- Supports modes: version (availability check), server (long-running with log-prefix), capture
- Planner: Scores high for wireless_observation when long observation needed, but penalizes persistent due to duration
- Audit: Notes long-running nature, suggests checking REST API or logs
- Future: Could integrate Kismet REST API polling for real-time world model updates

### 2.2 `wash` - WPS Discovery

**Source**: https://github.com/t6x/reaver-wps-fork-t6x/wiki/wash, `man wash`

**Real usage**:
```bash
wash -i wlan0mon
wash -i wlan0mon -c 6
wash -i wlan0mon -s  # Survey mode (passive, no probe)
wash -i wlan0mon -C  # Ignore FCS errors
wash -i wlan0mon -j  # JSON output (if compiled with json)
```

**Output**:
```
BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
00:11:22:33:44:55  6   -45  2.0  No   Broadcom  MyNetwork
```

**Parser**: Regex `([0-9A-F:]{17})\s+(\d+)\s+(-?\d+)\s+([\d\.]+|n/a)\s+(\w+)\s+(\S+)?\s*(.*)?` for BSSID, Ch, dBm, WPS version, Lck, Vendor, ESSID

**Framework fullest potential**:
- Adapter supports survey (passive), channel filter, json, ignore_fcs
- Evidence: WPS type with wps_enabled (version != n/a), wps_locked (Lck Yes), vendor, signal, channel
- WorldModel: Updates AP wps_enabled, wps_locked
- Planner: Only selected when WPS state unknown for >50% APs or explicit WPS assessment objective, correlates with observed WPS state rather than executing all WPS tools indiscriminately
- Example flow from spec: Observed WPS unavailable → determine whether WPS present → collect evidence via wash → select reaver/bully/pixiewps → verify → update

### 2.3 `horst`, `wavemon`

**Source**: https://github.com/br101/horst, https://github.com/uoaerg/wavemon

- `horst`: Lightweight, shows APs, clients, signal, channel, type; `horst -i wlan0mon -q -c 6`
- `wavemon`: Interactive signal monitor; `wavemon -i wlan0 -d` for dump

**Framework**: Both as lightweight alternatives when airodump not available, parser creates generic evidence with output snippet, confidence LOW, but still contributes to world model if possible

---

## 3. Wireless Packet Capture and Analysis

### 3.1 `tshark` - CLI Wireshark Engine

**Source**: https://www.wireshark.org/docs/man-pages/tshark.html, https://www.kali.org/tools/wireshark/

**Real usage**:
```bash
tshark -i wlan0mon
tshark -i wlan0mon -f "wlan"  # Capture filter (BPF)
tshark -i wlan0mon -Y "wlan.fc.type_subtype==8"  # Display filter (beacon)
tshark -r capture.pcap -T json  # JSON output
tshark -r capture.pcap -T fields -e frame.number -e wlan.sa -e wlan.da -e wlan_mgt.ssid
tshark -i wlan0mon -a duration:30 -c 100  # Duration and count
tshark -i wlan0mon -w /tmp/cap.pcap
```

**Why suitable for automation**: `-T json` or `-T fields` gives structured output without GUI

**Framework fullest potential**:
- Adapter supports capture_filter (BPF), display_filter (Wireshark), read_file, output_format (json, fields, text), fields list, count, duration
- Parser `tshark_to_evidences`: Tries JSON first (list of packets with _source.layers), then fields (tab-separated), fallback generic
- Evidence: CAPTURE type with layers, bssid, ssid extraction from wlan layer
- Planner: Useful for verification (e.g., verify AP existence via beacon filter), packet capture for handshake analysis
- Can be re-selected with different display filters based on uncertainty (e.g., filter for EAPOL for handshake)

### 3.2 `tcpdump`, `dumpcap`, `termshark`, Wireshark

**Source**: `man tcpdump`, https://www.wireshark.org/docs/man-pages/dumpcap.html

- `tcpdump`: `tcpdump -i wlan0mon -c 100 -n -v -w /tmp/cap.pcap "wlan"`
- `dumpcap`: Wireshark's capture engine, similar to tcpdump but Wireshark's backend: `dumpcap -i wlan0mon -c 100 -w /tmp/cap.pcapng -a duration:30`
- `termshark`: Terminal UI for tshark
- Wireshark: GUI, not suitable for automation but useful for manual analysis

**Framework**: 
- tcpdump adapter: Supports interface, count, filter (BPF), no_resolve, verbose, read_file, write_file
- dumpcap adapter: Similar, with duration via `-a duration:`
- Both produce CAPTURE evidence, confidence MEDIUM, can be used when tshark not available
- termshark/Wireshark not directly wrapped as they are interactive, but their capture engines are

---

## 4. Protocol and Packet Analysis

### 4.1 Scapy - Programmable Packet Manipulation

**Source**: https://scapy.net/, https://scapy.readthedocs.io/

**Real usage**:
```python
from scapy.all import *
# Sniff
pkts = sniff(iface="wlan0mon", count=10, filter="wlan")
# Send
sendp(Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")/Dot11Beacon(cap="ESS", info="Test"), iface="wlan0mon")
# Parse pcap
pkts = rdpcap("/tmp/cap.pcap")
```

**Framework fullest potential**:
- Unlike traditional CLI utilities, Scapy is programmatic component
- Adapter overrides `execute` to try `import scapy.all` directly, if available executes Python script in controlled context with stdout/stderr capture
- Supports `script` parameter: Python code using scapy
- Fallback to `python3 -c` subprocess if scapy not installed
- Evidence: GENERIC with script_output
- Planner: For specialized authorized testing when custom packet crafting needed, invasive True, requires_authorization True
- Security: Exec in restricted context, __builtins__ allowed but script should be reviewed; in production would be sandboxed

### 4.2 `macchanger` - MAC Address Configuration

**Source**: https://github.com/alobbs/macchanger, `man macchanger`

**Real usage**:
```bash
macchanger -s wlan0          # Show current and permanent
macchanger -r wlan0          # Random MAC
macchanger -m 00:11:22:33:44:55 wlan0  # Set specific
macchanger -p wlan0          # Reset to permanent
```

**Framework**:
- Adapter supports `show`, `random`, `set`, `reset` actions
- Parser: Regex `Current MAC:\s*([0-9A-F:]{17})`, `Permanent MAC`
- Evidence: INTERFACE type with current_mac, permanent_mac
- Use case: Authorized local-interface MAC testing, e.g., test MAC filtering, needs root, interface must be down for some drivers
- Planner: Only when interface testing objective, not blindly

### 4.3 `bettercap` - Broad Network Assessment Framework

**Source**: https://www.bettercap.org/, https://github.com/bettercap/bettercap

**Real usage**:
```bash
bettercap -iface wlan0mon
bettercap -caplet http-req-dump -eval "net.probe on; net.show"
bettercap --help
```

**Framework fullest potential**:
- Because it provides many overlapping functions, orchestrator exposes individual capabilities rather than opaque "run everything"
- Adapter supports `caplet` and `eval` parameters for specific modules
- If no eval, shows help for availability check
- Evidence: GENERIC with caplet/eval, confidence LOW (since bettercap output is complex)
- Planner: Penalizes due to invasive True and broad scope, only when specific bettercap capability needed and authorized
- Future: Could implement bettercap API client for more granular control

### 4.4 `mitmproxy` - HTTP/HTTPS Interception

**Source**: https://mitmproxy.org/, https://docs.mitmproxy.org/

**Real usage**: After wireless access, for HTTP analysis: `mitmproxy`, `mitmdump`

**Framework**: Belongs to broader network-security phase after wireless access established, not treated as dedicated Wi-Fi radio tool. Could be added as service enumeration capability with mitmproxy adapter that runs `mitmdump -w flow` etc.

---

## 5. WPS Assessment - Deep Research

### 5.1 `reaver` - WPS Assessment

**Source**: https://github.com/t6x/reaver-wps-fork-t6x/wiki, `man reaver`

**Real usage**:
```bash
reaver -i wlan0mon -b 00:11:22:33:44:55 -c 6 -e MyNetwork
reaver -i wlan0mon -b 00:11:22:33:44:55 -p 12345670  # Test specific PIN
reaver -i wlan0mon -b 00:11:22:33:44:55 -N  # No nacks
reaver -i wlan0mon -b 00:11:22:33:44:55 --pixie-dust  # Pixie dust attack
```

**Output**: `WPS PIN: '12345670'`, `WPA PSK: 'password'`, `AP SSID: 'MyNetwork'`, `WPS transaction failed`, `AP rate limiting`

**Framework fullest potential**:
- Adapter requires BSSID, interface, supports channel, ssid, pin, no_nacks, pixie dust via params
- Parser regex for PIN, PSK, SSID, locked detection (rate limiting)
- Evidence: WPS type with wps_pin, wpa_psk, wps_locked
- Scope: Highly invasive, requires explicit authorization, only when WPS enabled and in-scope, after wash discovery
- Verification: If PIN found, could verify via `wpa_supplicant` with PIN or via second tool (bully)
- Experience: Tracks success per vendor, locked detection

### 5.2 `bully` - WPS Assessment

**Source**: https://github.com/aanarchyy/bully, `man bully`

**Real usage**:
```bash
bully wlan0mon -b 00:11:22:33:44:55 -c 6 -e MyNetwork
```

**Framework**: Similar to reaver, alternative implementation, adapter supports bssid, channel, essid, parser for PIN and Key

### 5.3 `pixiewps` - WPS Protocol Analysis

**Source**: https://github.com/wiire-a/pixiewps, https://github.com/t6x/reaver-wps-fork-t6x/wiki/Pixie-Dust-Attack

**Real usage**:
```bash
pixiewps --pke <pke> --pkr <pkr> --e-nonce <enonce> --r-nonce <rnonce> --e-hash1 <h1> --e-hash2 <h2> --authkey <authkey>
# Often used with reaver output: reaver ... --pixie-dust saves params, then pixiewps calculates PIN
```

**Framework**:
- Adapter supports pke, pkr, e_nonce, r_nonce, e_hash1, e_hash2, authkey params
- Offline analysis, not requiring interface
- Parser for `WPS pin: <pin>`
- Evidence: WPS type with pin, success flag
- Planner: Used alongside reaver/bully when pixie dust data available, not executed indiscriminately

**Correlation**: Framework correlates these tools with WPS state already observed rather than executing all WPS tooling indiscriminately. Flow: wash discovers WPS enabled APs → if in scope, select reaver or bully → if pixie dust data, select pixiewps → verify → update

---

## 6. WPA/WPA2/WPA3 and Authentication Assessment

### 6.1 `hcxdumptool` - Capture and Auth Material Collection

**Source**: https://github.com/ZerBea/hcxdumptool, https://github.com/ZerBea/hcxdumptool/blob/master/docs/

**Real usage**:
```bash
hcxdumptool -i wlan0mon -o /tmp/cap.pcapng --enable_status=1 -c 6
hcxdumptool -i wlan0mon -o /tmp/cap.pcapng --filterlist=targets.txt --filtermode=2
```

**Output**: Status counters, PMKID, EAPOL captured, output pcapng

**Framework fullest potential**:
- Adapter supports output_file, channel, filterlist, filtermode, enable_status
- Evidence: CAPTURE with pmkid_captured, eapol_captured, output_file
- Produces pcapng for next stage (hcxpcapngtool)
- Planner: Selected when WPA APs observed but no handshake, with channel from world model, output file in /tmp
- Invasive False (passive observation), but persistent True

### 6.2 `hcxpcapngtool` - Conversion

**Source**: https://github.com/ZerBea/hcxtools, `man hcxpcapngtool`

**Real usage**:
```bash
hcxpcapngtool -o /tmp/hash.hc22000 /tmp/cap.pcapng
hcxpcapngtool -o /tmp/hash.hc22000 --essid=MyNetwork /tmp/cap.pcapng
```

**Output**: `X PMKID(s) written`, `Y EAPOL pair(s) written`, `Z handshake(s) written`

**Framework**:
- Adapter requires input_file, supports output_file, essid filter
- Parser regex for counts
- Evidence: HANDSHAKE with pmkid_count, eapol_count, handshake_count
- Distinguishes capture acquisition (hcxdumptool), material conversion (hcxpcapngtool), offline analysis (hashcat/john), verification

### 6.3 `hashcat` - Credential Strength Assessment

**Source**: https://hashcat.net/wiki/, https://hashcat.net/hashcat/

**Real usage**:
```bash
hashcat -m 22000 hash.hc22000 wordlist.txt
hashcat -m 22000 -a 3 hash.hc22000 ?d?d?d?d?d?d?d?d  # Mask
hashcat -m 22000 --session=mysession --potfile-disable hash.hc22000 wordlist.txt
```

**Modes**: 22000 for WPA PMKID/EAPOL, 2500 for old hccap, etc.

**Framework fullest potential**:
- Treated as controlled offline analysis component operating on legitimately obtained material
- Adapter requires hash_file, supports wordlist or mask (requires one for actual execution, otherwise raises), mode (default 22000), attack_mode (0 dict, 3 mask), session, potfile_disable
- Parser for cracked passwords (hash:password lines), cracked count `Cracked: X/Y`
- Evidence: CREDENTIAL with cracked list, cracked_count, success
- Planner: Only when handshake evidence exists and in scope, with wordlist from authorized scope
- Security: Requires wordlist, not running without scope

### 6.4 `john` - John the Ripper

**Source**: https://www.openwall.com/john/, `man john`

**Real usage**:
```bash
john --wordlist=wordlist.txt --format=wpapsk hash.txt
john --show hash.txt
```

**Framework**: Similar to hashcat, offline credential assessment, adapter supports wordlist, format, session, hash_file

---

## 7. Wireless/Network Discovery Beyond Radio Layer

**Philosophy**: Once authorized wireless assessment establishes access to relevant network, conventional network-assessment tools become relevant. Should NOT be launched merely because installed.

### 7.1 `nmap` - Host Discovery, Service Enumeration

**Source**: https://nmap.org/book/man.html, https://www.kali.org/tools/nmap/

**Real usage**:
```bash
nmap 192.168.1.0/24
nmap -sV 192.168.1.1  # Version detection
nmap -p 22,80,443 192.168.1.1
nmap -oG - 192.168.1.0/24  # Grepable for parsing
nmap -oX - 192.168.1.0/24  # XML
nmap --script vuln 192.168.1.1
```

**Output formats**: Normal (human), grepable (Host: ... Ports: ...), XML

**Framework fullest potential**:
- Adapter supports target, scan_type (default -sV), ports, timing, additional_args, output_format (xml, grepable)
- Uses `-oG -` for easy parsing by default
- Parser handles all 3 formats: parse_nmap_grepable (Host: IP Status: Up, Ports: 22/open/tcp//ssh//), parse_nmap_normal (Nmap scan report for, PORT STATE SERVICE VERSION), parse_nmap_xml (ET)
- Evidence: NETWORK_HOST (ip, hostname, status) and NETWORK_SERVICE (ip, port, protocol, service, version, state)
- WorldModel: NetworkHost with open_ports, services
- Scope enforcement: Checks IP against authorized_networks/hosts, blocks if out of scope and invasive
- Planner: Only when network discovery phase and authorized network scope defined, not merely because IP discovered

### 7.2 `arp-scan`, `netdiscover`, `fping`, `dig`, `dnsenum`, `dnsrecon`

**Research**:
- `arp-scan`: `arp-scan --interface=wlan0 --localnet`, `arp-scan 192.168.1.0/24`, output IP MAC Vendor, requires root
- `netdiscover`: `netdiscover -i wlan0 -r 192.168.1.0/24`, `-p` passive, output IP MAC
- `fping`: `fping -g 192.168.1.0/24`, `fping -c 3 192.168.1.1`, output `192.168.1.1 is alive`
- `dig`: `dig @8.8.8.8 example.com A +short`, `dig example.com ANY`, output ANSWER SECTION
- `dnsenum`: `dnsenum --dnsserver 8.8.8.8 example.com`, DNS enumeration, brute force
- `dnsrecon`: `dnsrecon -d example.com -t std`, DNS reconnaissance

**Framework**:
- Each adapter with real command building and parsing
- arp-scan parser: IP MAC Vendor regex
- netdiscover parser: IP MAC
- fping parser: is alive / unreachable
- dig parser: ANSWER SECTION, +short IPs
- dnsenum/dnsrecon: Could be added as DNS enumeration capabilities, with domain input, server, etc.
- Planner: Only when network discovery phase, authorized scope, and relevant (e.g., dig only when DNS assessment in scope)

---

## 8. Service and Network Enumeration

**Philosophy**: Not inherently Wi-Fi tools. Become relevant when wireless assessment transitions into authorized assessment of services reachable through wireless network.

**Tools**: smbclient, smbmap, enum4linux-ng, ldapsearch, snmpwalk, nbtscan, rpcclient, ftp, curl, wget, openssl s_client

**Real usage examples**:
```bash
smbclient //192.168.1.1/share -N -c ls
smbmap -H 192.168.1.1
enum4linux-ng 192.168.1.1
ldapsearch -x -h 192.168.1.1 -b "dc=example,dc=com"
snmpwalk -v2c -c public 192.168.1.1
nbtscan 192.168.1.0/24
rpcclient -U "" 192.168.1.1 -c enumdomusers
curl -s -i http://192.168.1.1
wget -qO- http://192.168.1.1
openssl s_client -connect 192.168.1.1:443 -servername example.com
```

**Framework fullest potential**:
- Implemented generic enumeration adapters: curl (HTTP), openssl s_client (TLS), smbclient (SMB)
- Each with real command building and parsing
- curl adapter: Supports url, method, headers, insecure, parses status code, headers, body
- openssl adapter: Supports target, port, servername, parses certificate, protocol, cipher
- smbclient adapter: Supports target, share, command, parses file listing, accessible flag
- Scope: Requires authorized network scope, invasive False but requires_authorization True
- Planner: Only when service enumeration phase and network hosts discovered with relevant open ports (e.g., curl only when port 80/443 open, smbclient only when 445 open)
- Future: Add smbmap, enum4linux-ng, etc. with similar pattern

---

## 9. Vulnerability Assessment

**Philosophy**: Useful for broader vulnerability assessment after network and hosts identified. Should NOT be launched merely because installed. Orchestrator selects only when world model indicates prerequisites and assessment purpose satisfied.

**Tools**: Greenbone/OpenVAS, Nuclei, Nikto

**Real usage**:
```bash
gvm-start  # Start OpenVAS
nuclei -u http://192.168.1.1 -t /path/to/templates/
nikto -h http://192.168.1.1
```

**Framework fullest potential**:
- Each would be adapter with target input, output vulnerability evidence
- Planner: Only when service enumeration found HTTP service and vulnerability assessment phase, with authorized scope
- Would produce VULNERABILITY evidence with severity, CVE, etc.
- Not yet implemented, but capability model defined in docs, and experience store would track info gain

---

## 10. Framework and Credential Utilities

**Philosophy**: Belong to broader network-security phase rather than initial wireless reconnaissance. Can be used for authorized vulnerability validation and exploitation testing after applicable vulnerability identified.

**Tools**: Metasploit Framework, Impacket, Responder

**Real usage**:
```bash
msfconsole -x "use exploit/...; set RHOSTS 192.168.1.1; run"
impacket-psexec user:pass@192.168.1.1
responder -I wlan0
```

**Framework**: Would be adapters with careful scope enforcement, only when vulnerability found and exploitation testing authorized

---

## Tool Selection Philosophy - Fullest Potential

**Core principle**: Framework must never interpret presence of tool as requirement to execute it.

**Example from spec**:
```
Observed: WPS information unavailable
Potential: wash, reaver, bully, pixiewps
Planner:
    determine whether WPS actually present
        ↓
    collect required evidence (wash)
        ↓
    select appropriate assessment capability (reaver if WPS enabled and in-scope)
        ↓
    execute
        ↓
    verify
        ↓
    update state
```

**Fullest potential means**:
- Use `iw` not just for interface list but also for link, scan, capability discovery
- Use `airodump-ng` not just for AP discovery but also client, WPS, channel, BSSID filtering, CSV parsing for machine consumption
- Use `tshark` not just capture but with BPF and display filters for specific evidence (EAPOL, beacon, deauth)
- Use `wash` for WPS discovery, then correlate with `reaver`/`bully`/`pixiewps` only if WPS present and authorized
- Use `hcxdumptool` for capture, `hcxpcapngtool` for conversion, `hashcat` for offline, each distinct phase
- Use `nmap` with appropriate scan type based on uncertainty (e.g., -sV for version when service unknown, -p for specific ports when port unknown)
- Use `curl` only when HTTP service discovered and in scope, with appropriate headers, method
- Use `bettercap` not as opaque "run everything" but with specific caplet/eval for needed capability

**Adaptive loop ensures**:
- Previously used tool may be selected again if new evidence makes it useful (e.g., airodump again after channel change)
- Tool may be skipped entirely when required information already established through another observation (e.g., if iw scan already gave APs, skip airodump)
- Tool selection determined by state of assessment rather than existence of tool

---

## Sources

- Kali Linux Tools: https://www.kali.org/tools/
- Aircrack-ng Suite: https://www.aircrack-ng.org/doku.php?id=main
- iw: https://wireless.wiki.kernel.org/en/users/documentation/iw
- Kismet: https://www.kismetwireless.net/docs/
- Wireshark/tshark: https://www.wireshark.org/docs/man-pages/tshark.html
- Scapy: https://scapy.net/ and https://scapy.readthedocs.io/
- Bettercap: https://www.bettercap.org/ and https://github.com/bettercap/bettercap
- Reaver: https://github.com/t6x/reaver-wps-fork-t6x/wiki
- Bully: https://github.com/aanarchyy/bully
- Pixiewps: https://github.com/wiire-a/pixiewps
- Hcxdumptool: https://github.com/ZerBea/hcxdumptool
- Hcxtools: https://github.com/ZerBea/hcxtools
- Hashcat: https://hashcat.net/wiki/
- John the Ripper: https://www.openwall.com/john/doc/
- Nmap: https://nmap.org/book/man.html
- rfkill: https://wireless.wiki.kernel.org/en/users/documentation/rfkill
- Macchanger: https://github.com/alobbs/macchanger
- Mitmproxy: https://docs.mitmproxy.org/
- Horst: https://github.com/br101/horst
- Wavemon: https://github.com/uoaerg/wavemon

All adapters credit sources in docstrings and metadata references.
