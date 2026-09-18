# WPA3 tool-command verification record

This record separates three states that must not be conflated:

1. **Source-verified**: the command or handler is present in primary documentation/source.
2. **Fixture-verified**: this repository's adapter/parser tests exercise the argv and parser,
   but the binary was not available in the development sandbox.
3. **Live-verified**: the command was successfully run against a real interface, control
   socket, or capture in an authorized environment.

As of this record, the WPA3 binaries are not installed in the development sandbox, so no
WPA3 command below is claimed as live-verified.

## Commands

| Capability | argv emitted | Source verification | Local/live status |
|---|---|---|---|
| `iw_scan` | `iw dev <interface> scan` | **Source-verified** by Linux Wireless' `About iw` documentation, which gives this exact example: [wireless.docs.kernel.org](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html) | Fixture-verified; `iw` absent locally |
| `hostapd_wpa3_audit` | `hostapd_cli -i <interface> get_config` | **Source-verified** by hostapd's `hostapd_ctrl_iface_get_config()` handler in [`hostapd/ctrl_iface.c`](https://github.com/zephyrproject-rtos/hostap/blob/master/hostapd/ctrl_iface.c) and its command dispatch | Fixture-verified; `hostapd_cli` and a control socket absent locally |
| `wpa_supplicant_wpa3_audit` | `wpa_cli -i <interface> get_config` | **Source-verified** through the wpa_supplicant control-interface implementation and the project's control-interface documentation: [w1.fi code structure](https://w1.fi/wpa_supplicant/devel/code_structure.html) | Fixture-verified; `wpa_cli` and a control socket absent locally |
| `wpa_supplicant_wpa3_status` | `wpa_cli -i <interface> status` | **Source-verified** by `wpa_supplicant_ctrl_iface_status()` in [`wpa_supplicant/ctrl_iface.c`](https://github.com/zephyrproject-rtos/hostap/blob/master/wpa_supplicant/ctrl_iface.c); the source explicitly emits `sae_group`, `sae_h2e`, and `sae_pk` for an accepted SAE connection | Fixture-verified; no live supplicant locally |
| `sae_capture_analysis` | `tshark -r <capture> -T json -Y 'wlan.fixed.auth_alg == 3'` | `-r`, `-T json`, and `-Y` are **source/documentation-verified** by the official [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html). The exact `wlan.fixed.auth_alg` field name is **not live-verified here** and must be checked with `tshark -G fields` on the deployed version. | Fixture-verified; `tshark` absent locally |

## What is verified about the protocol fields

The SAE authentication algorithm value and group/PWE semantics were checked against hostap's
source. The RSN/RSNX bit definitions, AKM selectors, SAE group mapping, and Transition
Disable constants came from hostap's common headers and SAE implementation, not from guessed
regular expressions.

The parser intentionally accepts only explicitly decoded tshark fields. If a deployed
Wireshark version uses a different field name, the capability must report no decoded SAE
observation until that field is configured and tested; it must not inspect arbitrary payload
bytes and infer a group or Transition Disable mask.

## What remains required for live verification

An authorized Linux test environment must provide:

- `iw` and a usable wireless interface for `iw_scan`;
- `hostapd_cli` or `wpa_cli` connected to a real control socket;
- `tshark` plus an authorized SAE/EAPOL capture;
- a deployed Wireshark field inventory from `tshark -G fields` to confirm the exact SAE and
  Transition Disable dissector names.

The framework should record missing binaries, missing sockets, invalid captures, and unsupported
fields as capability failures or unresolved evidence. It must never substitute fixture output
for any of those live observations.
