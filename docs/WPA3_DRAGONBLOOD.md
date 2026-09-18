# WPA3 / Dragonblood posture assessment

This document describes the WPA3-Personal assessment capability added to the framework. It
implements **posture detection and remediation verification**, not the Dragonblood attacks.
It never floods an AP, partitions a password, reflects EAP-pwd messages, creates a rogue AP,
or sends deauthentication frames.

## Research basis

The implementation was checked against:

- Mathy Vanhoef and Eyal Ronen, *Dragonblood: A Security Analysis of WPA3's SAE Handshake*
  and the authors' summary at [wpa3.mathyvanhoef.com](https://wpa3.mathyvanhoef.com/).
- CERT/CC VU#871675 and Debian DSA-4430-1 for the original CVE set.
- NVD for CVE-2022-23303/-23304, which describe incomplete fixes for the original SAE and
  EAP-pwd side-channel issues.
- The hostap source files `src/common/sae.c`, `src/common/dragonfly.c`,
  `src/common/wpa_common.h`, `src/common/ieee802_11_defs.h`,
  `src/crypto/crypto_openssl.c`, and `src/crypto/dh_groups.c` for group IDs, AKM selectors,
  PMF bits, RSNX bits, and hostap's suitability rules.

The supplied PDF URL was not reachable from the development sandbox. The code therefore does
not claim to have parsed that PDF; the primary sources above were used instead.

## What the passive scan can establish

`iw_scan` executes the real command `iw dev <interface> scan`, parses each BSS block, and
records:

- BSSID, SSID, frequency, channel, and signal when present;
- RSN AKM suites: PSK (2), SAE (8), FT-PSK (4), FT-SAE (9), and recognized enterprise suites;
- RSN capabilities: MFPR is bit 6 and MFPC is bit 7;
- the RSNX SAE-H2E bit (bit 5), and SAE-PK bit (bit 6).

A BSS advertising both PSK and SAE is WPA3-Transition posture. The framework reports the
transition-mode downgrade as **supported**, not verified: proving downgrade requires forcing
a WPA3-capable client onto a WPA2 handshake, which is an active attack against a third-party
client.

An SAE-only BSS has no PSK path visible in the beacon, but that does not prove that every SAE
side-channel mitigation is present. SAE groups are negotiated in SAE commit/confirm messages,
not advertised in the RSN element. Passive scanning therefore reports timing exposure and
group-downgrade exposure as **unresolved** unless an authorized configuration audit supplies
`sae_groups`.

The RSNX H2E bit means H2E is advertised as supported. It does not prove that H2E is the only
PWE method used; `sae_pwe` must come from a configuration audit.

## Configuration audit

`parse_wpa_config` accepts the WPA3-relevant subset of hostapd/wpa_supplicant configuration:

- `wpa_key_mgmt`
- `sae_groups`
- `sae_pwe` (`0` hunting-and-pecking, `1` H2E only, `2` both)
- `ieee80211w` / `sae_require_mfp`
- `anti_clogging_threshold`
- `transition_disable`

Passphrases and SAE passwords are deliberately discarded and never enter a posture or finding.
Malformed values are reported as issues and remain unknown; they are not coerced into a safe
value.

The version model records the original 2019 fixes, the 2.9 Brainpool/default-group changes,
and the complete side-channel fix boundary at 2.10. A hostapd/wpa_supplicant 2.7 or 2.9
installation is therefore not reported as fully fixed for the SAE cache side channel.

## Group risk model

The table in `wifi_framework.core.models.wpa3` uses hostap's authoritative identifiers:

- 19, 20, 21: NIST P-256, P-384, P-521; suitable default SAE groups;
- 22, 23, 24: MODP groups associated with password-dependent timing iterations;
- 27, 28, 29, 30: Brainpool P224/P256/P384/P512, associated with the Brainpool timing result;
- 25 and 26: older curves below the modern suitability floor.

`dragonfly_suitable_group` allows 19/20/21 and (for FFC) 15/16/17/18, mirroring hostap's
REVmd rule. This is a group suitability predicate, not a proof that an implementation is
secure. The framework reports the precondition and names the active verification required.

## Enterprise / EAP-pwd

The research also covers EAP-pwd (CVE-2019-9495, -9497, -9498, and -9499). The RSN parser
recognizes enterprise AKM suites, and the posture model distinguishes enterprise from personal
profiles. A complete EAP-pwd finding requires auditing the RADIUS server and EAP-pwd peer
configuration; a beacon alone cannot establish that EAP-pwd is enabled or patched. That
RADIUS-side adapter is intentionally kept separate from the SAE scan so an enterprise result
cannot be fabricated from an AKM label alone.

## World-model and finding integration

`iw_scan` access-point evidence is retained under the namespaced `wpa3` field in `AccessPoint.extra`, so the existing world-model contract remains backward-compatible while preserving RSN/PWE/group observations. The assessment engine projects the model assessment into ordinary findings tagged `wpa3` and `dragonblood`, carrying the source evidence IDs. Passive observations remain hypotheses, supported findings, or unresolved findings; they are never silently promoted to verified.

## Evidence and safety boundary

All passive results are observations or supported hypotheses. No Dragonblood result is marked
`verified` merely because a vulnerable precondition was observed. Verification would require
the attack itself, and the framework records that requirement in `verify_requires` instead.

The capabilities are passive unless an operator later adds a separately reviewed, explicitly
authorized negotiation capability. No active SAE probing or attack implementation is hidden in
this change, and no tool output is fabricated when the required binary or wireless interface
is unavailable.
