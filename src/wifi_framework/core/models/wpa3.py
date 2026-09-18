"""WPA3 / SAE posture: what an access point advertises, and what that exposes.

The Dragonblood research (Vanhoef & Ronen, IEEE S&P 2020) showed that WPA3's SAE
handshake leaks password information through timing and cache side channels, that
WPA3-Transition mode can be downgraded into a WPA2 handshake that *is* crackable offline,
and that a flood of forged commit frames denies service. The property that matters for an
assessment framework is that nearly every **precondition** for those attacks is readable -
out of a beacon's RSN information element, or out of the access point's own configuration -
so exposure can be established without transmitting anything at all.

Every constant in this module is taken from a primary source and the source is named. A
wrong bit position or group identifier in a security tool produces a confidently wrong
verdict, which is worse than no verdict, so where sources disagreed the disagreement and
its resolution are recorded rather than silently picking one.

Sources, in the order they were relied on:

* ``hostapd`` source (w1.fi, read directly): ``src/common/sae.c``,
  ``src/common/dragonfly.c``, ``src/common/ieee802_11_defs.h``,
  ``src/common/wpa_common.h``, ``src/crypto/dh_groups.c``,
  ``src/crypto/crypto_openssl.c``.
* CERT/CC VU#871675 and Debian DSA-4430-1 for the CVE set and its wording.
* NVD for severity, and for the fact that CVE-2022-23303 is an *incomplete fix* for
  CVE-2019-9494.
* ``wpa3.mathyvanhoef.com``, the authors' own summary, for which groups leak timing and
  for the Brainpool result added in August 2019.
* IANA's IKEv2 registry for the finite-cyclic-group identifiers; ``hostapd`` states in
  ``crypto_ec_group_2_nid`` that it maps "from IANA registry for IKE D-H groups", so the
  IEEE 802.11 SAE identifiers and the IKEv2 ones are the same numbering.

This module is pure data and logic. It performs no I/O, so it is testable anywhere - which
matters, because the sandbox that develops this framework has no wireless hardware and none
of the tools installed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .finding import FindingCategory, FindingSeverity, FindingStatus

# ---------------------------------------------------------------------------
# AKM suite selectors
# ---------------------------------------------------------------------------
#: The OUI that marks a standards-defined suite selector, from ``wpa_common.h``:
#: ``RSN_AUTH_KEY_MGMT_SAE RSN_SELECTOR(0x00, 0x0f, 0xac, 8)``.
AKM_OUI: Tuple[int, int, int] = (0x00, 0x0F, 0xAC)

#: Suite type -> name. Verified against ``RSN_AUTH_KEY_MGMT_*`` in ``wpa_common.h``.
AKM_SUITE_NAMES: Dict[int, str] = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    7: "TDLS",
    8: "SAE",
    9: "FT-SAE",
    11: "802.1X-SuiteB",
    12: "802.1X-SuiteB-192",
    13: "FT-802.1X-SHA384",
    14: "FILS-SHA256",
    15: "FILS-SHA384",
    16: "FT-FILS-SHA256",
    17: "FT-FILS-SHA384",
    18: "OWE",
    19: "FT-PSK-SHA384",
    20: "PSK-SHA384",
    21: "PASN",
    23: "802.1X-SHA384",
    24: "SAE-EXT-KEY",
    25: "FT-SAE-EXT-KEY",
}

#: SAE (WPA3-Personal) suites. 8 and 9 are the original pair; 24 and 25 are the Wi-Fi 7
#: ``SAE_EXT_KEY`` variants, whose hash follows the negotiated DH group.
SAE_AKM_SUITES: FrozenSet[int] = frozenset({8, 9, 24, 25})

#: Pre-shared-key suites - the ones a transition-mode downgrade lands on.
PSK_AKM_SUITES: FrozenSet[int] = frozenset({2, 4, 6, 19, 20})

#: 802.1X suites, i.e. WPA3-Enterprise / WPA2-Enterprise.
EAP_AKM_SUITES: FrozenSet[int] = frozenset({1, 3, 5, 11, 12, 13, 23})

# ---------------------------------------------------------------------------
# RSN capabilities (RSNE) and RSNX capabilities
# ---------------------------------------------------------------------------
#: Bit 6 of the RSNE capabilities field is Management Frame Protection **Required**.
#:
#: This is the reverse of what several secondary sources state, and it is worth being
#: explicit because transition-mode detection depends on it. ``hostapd`` defines
#: ``WPA_CAPABILITY_MFPR BIT(6)`` and ``WPA_CAPABILITY_MFPC BIT(7)`` in
#: ``wpa_common.h``, and Cisco's 802.11w document says the same. The arithmetic on real
#: beacons settles it beyond either authority: a WPA2 network with PMF *optional*
#: advertises RSN capabilities ``0x00a8`` (bit 7 set, bit 6 clear) while a WPA3 network
#: with PMF *required* advertises ``0x00e8`` (both set). Optional means capable-but-not-
#: required, so the set bit in ``0xa8`` is MFPC, which is bit 7.
RSN_CAPAB_MFPR: int = 6
RSN_CAPAB_MFPC: int = 7

#: RSNX (RSN Extension, element id 244) capability bits, from ``WLAN_RSNX_CAPAB_*`` in
#: ``ieee802_11_defs.h``. ``SAE_H2E`` is the beacon-visible signal that the AP supports
#: hash-to-element, the PWE derivation that removes the hunting-and-pecking loop the cache
#: side channel targets.
RSNX_CAPAB_SAE_H2E: int = 5
RSNX_CAPAB_SAE_PK: int = 6
RSNX_CAPAB_PROTECTED_TWT: int = 4

#: Element ids, from ``WLAN_EID_*``.
WLAN_EID_RSN: int = 48
WLAN_EID_RSNX: int = 244

#: Transition Disable is **not** an RSN capabilities bit. It is a WFA Key Data
#: encapsulation (``WFA_KEY_DATA_TRANSITION_DISABLE``, OUI ``50-6f-9a`` type ``0x20``)
#: that the AP sends inside the 4-way handshake, with the bits below. The consequence for
#: this framework is important and easy to get wrong: whether an AP has transition disable
#: configured cannot be read from a beacon. It is observable from the access point's
#: configuration, or from a completed handshake - never passively.
WFA_KEY_DATA_TRANSITION_DISABLE: Tuple[int, int, int, int] = (0x50, 0x6F, 0x9A, 0x20)
TRANSITION_DISABLE_WPA3_PERSONAL: int = 1 << 0
TRANSITION_DISABLE_SAE_PK: int = 1 << 1
TRANSITION_DISABLE_WPA3_ENTERPRISE: int = 1 << 2
TRANSITION_DISABLE_ENHANCED_OPEN: int = 1 << 3


# ---------------------------------------------------------------------------
# SAE finite cyclic groups
# ---------------------------------------------------------------------------
class GroupKind(str, Enum):
    """Whether a group is elliptic-curve or finite-field."""

    ECC = "ecc"
    FFC = "ffc"


@dataclass(frozen=True)
class SaeGroup:
    """One SAE finite cyclic group, with the properties that decide its risk.

    ``suitable`` mirrors ``dragonfly_suitable_group`` in ``hostapd``'s
    ``src/common/dragonfly.c``, which enforces the REVmd rules (FFC prime >= 3072 bits,
    ECC prime field >= 256 bits, no characteristic-2 curves, co-factor 1).

    ``timing_precondition`` means the group's prime is *not* close to a power of two, so
    the hunting-and-pecking loop can run a password-dependent number of iterations. That
    is a precondition for the timing attack, not a proof that an implementation leaks:
    ``hostapd`` both pads the loop (``dragonfly_min_pwe_loop_iter``) and, from 2.9,
    disables Brainpool groups outright for exactly this reason.

    ``h2e_supported`` mirrors the ``switch`` in ``sswu_curve_param``, which is what makes
    hash-to-element available for a group. Note it is absent for group 27: hostapd maps
    BrainpoolP224r1 in ``crypto_ec_group_2_nid`` but has no SSWU parameter for it, so that
    group cannot use the mitigation that removes the hunting-and-pecking loop.
    """

    identifier: int
    name: str
    kind: GroupKind
    prime_bits: int
    #: ``True``/``False`` from the ``DH_GROUP(id, safe_prime)`` table in ``dh_groups.c``;
    #: ``None`` for ECC groups, where the concept does not apply.
    safe_prime: Optional[bool]
    suitable: bool
    timing_precondition: bool
    h2e_supported: bool
    #: Compiled into a default ``hostapd`` build. Only group 5 among the FFC groups is:
    #: the rest of ``dh_groups[]`` is inside ``#ifdef ALL_DH_GROUPS``. This is why the
    #: authors note that most implementations do not enable the MODP groups by default.
    default_build: bool
    note: str = ""


def _ecc(identifier, name, prime_bits, suitable, timing, h2e, default, note=""):
    return SaeGroup(
        identifier=identifier, name=name, kind=GroupKind.ECC, prime_bits=prime_bits,
        safe_prime=None, suitable=suitable, timing_precondition=timing,
        h2e_supported=h2e, default_build=default, note=note,
    )


def _ffc(identifier, name, prime_bits, safe_prime, suitable, default, note=""):
    # FFC timing exposure follows directly from the safe-prime flag: dragonfly.c returns
    # 40 minimum PWE iterations for 22/23/24 ("pwd-value is likely to be >= p frequently")
    # and 1 for the safe-prime groups ("prime that is close to a power of two").
    return SaeGroup(
        identifier=identifier, name=name, kind=GroupKind.FFC, prime_bits=prime_bits,
        safe_prime=safe_prime, suitable=suitable, timing_precondition=not safe_prime,
        h2e_supported=False, default_build=default, note=note,
    )


#: The group table. Identifiers and names from the IANA IKEv2 registry and
#: ``crypto_ec_group_2_nid``; suitability from ``dragonfly_suitable_group``; timing
#: preconditions from ``dragonfly_min_pwe_loop_iter`` and the Brainpool comment beside it;
#: H2E availability from ``sswu_curve_param``; default-build membership from
#: ``dh_groups[]``.
SAE_GROUPS: Dict[int, SaeGroup] = {
    g.identifier: g
    for g in (
        _ffc(1, "768-bit MODP", 768, True, False, False, "far below the REVmd floor"),
        _ffc(2, "1024-bit MODP", 1024, True, False, False, "far below the REVmd floor"),
        _ffc(5, "1536-bit MODP", 1536, True, False, True, "below the REVmd floor"),
        _ffc(14, "2048-bit MODP", 2048, True, False, False, "below the 3072-bit REVmd floor"),
        _ffc(15, "3072-bit MODP", 3072, True, True, False),
        _ffc(16, "4096-bit MODP", 4096, True, True, False),
        _ffc(17, "6144-bit MODP", 6144, True, True, False),
        _ffc(18, "8192-bit MODP", 8192, True, True, False),
        _ffc(
            22, "1024-bit MODP with 160-bit prime-order subgroup", 1024, False, False, False,
            "not a safe prime; a target of the authors' dragontime tool",
        ),
        _ffc(
            23, "2048-bit MODP with 224-bit prime-order subgroup", 2048, False, False, False,
            "not a safe prime; a target of the authors' dragontime tool",
        ),
        _ffc(
            24, "2048-bit MODP with 256-bit prime-order subgroup", 2048, False, False, False,
            "not a safe prime; a target of the authors' dragontime tool",
        ),
        _ecc(19, "NIST P-256", 256, True, False, True, True,
             "hostapd's only default SAE group; the authors' own recommendation"),
        _ecc(20, "NIST P-384", 384, True, False, True, True),
        _ecc(21, "NIST P-521", 521, True, False, True, True),
        _ecc(25, "NIST P-192", 192, False, False, True, False, "prime below 256 bits"),
        _ecc(26, "secp224r1", 224, False, False, True, False, "prime below 256 bits"),
        _ecc(27, "BrainpoolP224r1", 224, False, True, False, False,
             "Brainpool leaks timing, and has no SSWU parameter so H2E cannot mitigate it"),
        _ecc(28, "BrainpoolP256r1", 256, False, True, True, False, "CVE-2019-13377"),
        _ecc(29, "BrainpoolP384r1", 384, False, True, True, False, "CVE-2019-13377"),
        _ecc(30, "BrainpoolP512r1", 512, False, True, True, False, "CVE-2019-13377"),
    )
}


def suitable_group(identifier: int, ecc_only: bool = False) -> bool:
    """Mirror of ``hostapd``'s ``dragonfly_suitable_group``.

    Kept as a function rather than only a table field so that the rule is executable and
    testable on identifiers the table does not list, including ones invented by a fuzzer.
    """
    if identifier in (19, 20, 21):
        return True
    return not ecc_only and identifier in (15, 16, 17, 18)


def min_pwe_loop_iterations(identifier: int) -> int:
    """Mirror of ``hostapd``'s ``dragonfly_min_pwe_loop_iter``.

    The number of hunting-and-pecking iterations the implementation runs at minimum. It is
    the mitigation for the timing leak: groups whose prime is close to a power of two need
    one, while the MODP-with-prime-order-subgroup groups would otherwise leak, so they are
    padded to forty.
    """
    if identifier in (22, 23, 24):
        return 40
    if identifier in (1, 2, 5, 14, 15, 16, 17, 18):
        return 1
    return 40


def brainpool_groups() -> Set[int]:
    """Groups whose curve is Brainpool - the August 2019 result, CVE-2019-13377."""
    return {gid for gid, group in SAE_GROUPS.items() if group.name.startswith("Brainpool")}


def timing_precondition_groups() -> Set[int]:
    """Groups whose prime is not close to a power of two, so iterations can depend on the
    password. The precondition for the timing attack, not a proof that one leaks."""
    return {gid for gid, group in SAE_GROUPS.items() if group.timing_precondition}


# ---------------------------------------------------------------------------
# Password-to-element derivation
# ---------------------------------------------------------------------------
class PweMethod(str, Enum):
    """How SAE turns a password into a curve element.

    This is the single most consequential configuration value for the cache side channel,
    because the channel is in the hunting-and-pecking loop and hash-to-element has no such
    loop. Values are ``hostapd``'s ``sae_pwe``: 0 hunting-and-pecking only (the default
    when no password identifier is used), 1 hash-to-element only, 2 both. A third value
    appears in ``wpa_supplicant`` beside the password-identifier handling; it is not
    documented in the configuration manual, so it is represented here as unrecognized
    rather than guessed at.
    """

    HUNTING_AND_PECKING = "hunting_and_pecking"
    HASH_TO_ELEMENT = "hash_to_element"
    BOTH = "both"
    UNRECOGNIZED = "unrecognized"


SAE_PWE_VALUES: Dict[int, PweMethod] = {
    0: PweMethod.HUNTING_AND_PECKING,
    1: PweMethod.HASH_TO_ELEMENT,
    2: PweMethod.BOTH,
}


def classify_pwe(value: Optional[int]) -> PweMethod:
    """Map a ``sae_pwe`` integer onto a method, refusing to invent one.

    ``None`` - the parameter absent from a configuration file - is hunting-and-pecking,
    because that is ``hostapd``'s documented default when no password identifier is
    configured. Any other unrecognized integer stays unrecognized: guessing would report a
    remediation status that was never observed.
    """
    if value is None:
        return PweMethod.HUNTING_AND_PECKING
    return SAE_PWE_VALUES.get(value, PweMethod.UNRECOGNIZED)


def pwe_exposes_cache_side_channel(method: PweMethod) -> Optional[bool]:
    """Whether the PWE method leaves the hunting-and-pecking loop reachable.

    ``None`` for an unrecognized value, which is the honest answer: the exposure cannot be
    determined from a setting this code does not understand.
    """
    if method is PweMethod.HASH_TO_ELEMENT:
        return False
    if method in (PweMethod.HUNTING_AND_PECKING, PweMethod.BOTH):
        return True
    return None


# ---------------------------------------------------------------------------
# hostapd / wpa_supplicant versions
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VersionFix:
    """A version at which something was fixed, and what it fixed."""

    version: Tuple[int, ...]
    cve: Optional[str]
    description: str


#: Ordered by version. 2.7 fixed the original Dragonblood set; 2.9 disabled Brainpool
#: groups and changed the default to groups 19/20/21; 2.10 is where CVE-2022-23303 and
#: CVE-2022-23304 were fixed - both recorded by NVD as *incomplete fixes* for the 2019
#: CVEs, which is why a version check that stops at 2.7 reports a patched system that is
#: not.
HOSTAPD_FIXES: Tuple[VersionFix, ...] = (
    VersionFix((2, 7), "CVE-2019-9494", "SAE timing and cache side-channel mitigations"),
    VersionFix((2, 7), "CVE-2019-9495", "EAP-pwd cache side-channel mitigations"),
    VersionFix((2, 7), "CVE-2019-9496", "SAE confirm state validation, the AP-side DoS"),
    VersionFix((2, 7), "CVE-2019-9497", "EAP-pwd reflection-attack validation"),
    VersionFix((2, 7), "CVE-2019-9498", "EAP-pwd server commit scalar/element validation"),
    VersionFix((2, 7), "CVE-2019-9499", "EAP-pwd peer commit scalar/element validation"),
    VersionFix((2, 9), "CVE-2019-13377", "Brainpool groups disabled; default groups 19/20/21"),
    VersionFix((2, 10), "CVE-2022-23303", "SAE side-channel, incomplete fix for CVE-2019-9494"),
    VersionFix((2, 10), "CVE-2022-23304", "EAP-pwd side-channel, incomplete fix for CVE-2019-9495"),
    VersionFix((2, 10), None, "hash-to-element support (sae_pwe=1 or 2)"),
    VersionFix((2, 10), None, "Transition Disable mechanism"),
)

#: The version at which the side-channel fixes are actually complete.
SIDE_CHANNEL_FIXED_IN: Tuple[int, ...] = (2, 10)


def parse_version(text: str) -> Optional[Tuple[int, ...]]:
    """Parse ``v2.10``, ``2.9-2.7``, ``hostapd v2.6`` into a comparable tuple.

    Returns ``None`` rather than guessing when the text holds no version, because a version
    check that cannot read its input must not report "not vulnerable".
    """
    match = re.search(r"(\d+)\.(\d+)", text or "")
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))


def unresolved_fixes(version: Optional[Tuple[int, ...]]) -> Optional[List[VersionFix]]:
    """Fixes this version predates, or ``None`` if the version is unknown.

    ``None`` is deliberately distinct from an empty list: "we could not read the version"
    must not be reported as "everything is fixed".
    """
    if version is None:
        return None
    return [fix for fix in HOSTAPD_FIXES if version < fix.version]


# ---------------------------------------------------------------------------
# Posture
# ---------------------------------------------------------------------------
class Wpa3Profile(str, Enum):
    """Which Wi-Fi Alliance security profile an advertisement describes."""

    NOT_RSN = "not_rsn"
    WPA3_PERSONAL = "wpa3_personal"
    WPA3_PERSONAL_TRANSITION = "wpa3_personal_transition"
    WPA3_ENTERPRISE = "wpa3_enterprise"
    WPA3_ENTERPRISE_TRANSITION = "wpa3_enterprise_transition"
    WPA3_ENTERPRISE_192 = "wpa3_enterprise_192"
    ENHANCED_OPEN = "enhanced_open"
    WPA2_PERSONAL = "wpa2_personal"
    WPA2_ENTERPRISE = "wpa2_enterprise"
    OTHER = "other"


@dataclass
class Wpa3Posture:
    """What is known about one BSS's WPA3 posture, and how it was learned.

    Every field is ``Optional`` except the AKM list, and ``None`` always means *not
    observed* rather than *absent*. That distinction carries the whole design: the SAE
    groups an AP supports are not in its beacon - they are negotiated in commit and confirm
    frames - so a passive assessment genuinely cannot know them, and must say so instead of
    inferring a default and reporting it as an observation.
    """

    bssid: str
    ssid: Optional[str] = None
    akm_suites: List[int] = field(default_factory=list)
    #: From the RSNE capabilities field. ``None`` when the field was not present, which
    #: happens on pre-802.11w beacons.
    mfpc: Optional[bool] = None
    mfpr: Optional[bool] = None
    #: From the RSNX element. ``None`` when no RSNX element was present - which is itself
    #: evidence, but weak: an AP may support H2E and simply not advertise it.
    h2e_advertised: Optional[bool] = None
    sae_pk_advertised: Optional[bool] = None
    #: Not observable from a beacon. Only a configuration audit or an authorized SAE
    #: negotiation can fill these in.
    sae_groups: Optional[List[int]] = None
    sae_pwe: Optional[int] = None
    anti_clogging_threshold: Optional[int] = None
    transition_disable_configured: Optional[bool] = None
    #: EAP-pwd is an EAP method, not an AKM selector. An enterprise AKM alone cannot prove
    #: that EAP-pwd is configured; a RADIUS/EAP audit must populate this field.
    eap_pwd_configured: Optional[bool] = None
    implementation: Optional[str] = None
    version: Optional[str] = None
    #: Where each field came from, so a finding can name its source.
    source: str = "unspecified"

    @property
    def parsed_version(self) -> Optional[Tuple[int, ...]]:
        return parse_version(self.version) if self.version else None

    def has_sae(self) -> bool:
        return any(suite in SAE_AKM_SUITES for suite in self.akm_suites)

    def has_psk(self) -> bool:
        return any(suite in PSK_AKM_SUITES for suite in self.akm_suites)

    def has_eap(self) -> bool:
        return any(suite in EAP_AKM_SUITES for suite in self.akm_suites)

    def transition_mode(self) -> bool:
        """Both SAE and PSK advertised on the same BSS.

        This is the precondition for the transition-mode downgrade, and it is the one
        Dragonblood exposure that is fully readable from a beacon.
        """
        return self.has_sae() and self.has_psk()

    def profile(self) -> Wpa3Profile:
        suites = set(self.akm_suites)
        if not suites:
            return Wpa3Profile.NOT_RSN
        if 12 in suites:
            return Wpa3Profile.WPA3_ENTERPRISE_192
        if 18 in suites:
            return Wpa3Profile.ENHANCED_OPEN
        if self.has_sae() and self.has_psk():
            return Wpa3Profile.WPA3_PERSONAL_TRANSITION
        if self.has_sae():
            return Wpa3Profile.WPA3_PERSONAL
        if self.has_eap() and suites & {5, 13, 23}:
            return Wpa3Profile.WPA3_ENTERPRISE
        if self.has_eap():
            return Wpa3Profile.WPA2_ENTERPRISE
        if self.has_psk():
            return Wpa3Profile.WPA2_PERSONAL
        return Wpa3Profile.OTHER

    def akm_names(self) -> List[str]:
        return [AKM_SUITE_NAMES.get(suite, f"unknown-{suite}") for suite in self.akm_suites]


# ---------------------------------------------------------------------------
# Exposure assessment
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DragonbloodExposure:
    """One Dragonblood attack class, and what the evidence says about it.

    ``status`` uses the framework's own :class:`FindingStatus`, and the mapping is
    deliberate: passive observation of a precondition can *support* an exposure but can
    never *verify* it, because verification means demonstrating the attack, and this
    framework does not perform the Dragonblood attacks. ``verify_requires`` therefore says
    what it would take, so a report can be honest about the distance between what was seen
    and what was proven.

    ``UNRESOLVED`` with ``exposed is None`` means the evidence needed was not available -
    which is a different claim from "not exposed", and the one most likely to be collapsed
    by a careless reader or a careless renderer.
    """

    attack: str
    status: FindingStatus
    exposed: Optional[bool]
    severity: FindingSeverity
    detail: str
    remediation: str
    verify_requires: str
    cve: Optional[str] = None
    cert_id: Optional[str] = None
    category: FindingCategory = FindingCategory.WIRELESS
    evidence: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, object]:
        return {
            "attack": self.attack,
            "status": self.status.value,
            "exposed": self.exposed,
            "severity": self.severity.value,
            "detail": self.detail,
            "remediation": self.remediation,
            "verify_requires": self.verify_requires,
            "cve": self.cve,
            "cert_id": self.cert_id,
            "category": self.category.value,
            "evidence": list(self.evidence),
        }


CERT_DRAGONBLOOD = "VU#871675"

_UNOBSERVABLE_GROUPS = (
    "the SAE groups an AP supports are negotiated in commit and confirm frames, not "
    "advertised in its beacon"
)


def assess_dragonblood_exposure(posture: Wpa3Posture) -> List[DragonbloodExposure]:
    """Assess every Dragonblood attack class against what is known about a BSS.

    The order of the returned list is the order of the attack classes, not of severity, so
    that a caller can compare two assessments position by position.
    """
    findings: List[DragonbloodExposure] = []
    profile = posture.profile()

    if profile is Wpa3Profile.NOT_RSN:
        return [
            DragonbloodExposure(
                attack="no RSN information element observed",
                status=FindingStatus.UNRESOLVED,
                exposed=None,
                severity=FindingSeverity.INFO,
                detail=(
                    "No AKM suites were observed, so no WPA3 property can be assessed. This "
                    "is not evidence of an open network - the RSN element may simply not "
                    "have been captured."
                ),
                remediation="capture a beacon or probe response carrying the RSN element",
                verify_requires="a beacon or probe response from this BSS",
            )
        ]

    # EAP-pwd is not encoded by the AKM selector. Keep the enterprise result separate from
    # SAE: an enterprise AKM proves 802.1X, not which EAP method the RADIUS server chose.
    if posture.has_eap() and not posture.has_sae():
        return _eap_pwd_exposures(posture)

    # 1. Transition-mode downgrade. Fully readable from the beacon.
    if posture.transition_mode():
        findings.append(
            DragonbloodExposure(
                attack="WPA3-Transition downgrade to a crackable WPA2 handshake",
                status=FindingStatus.SUPPORTED,
                exposed=True,
                severity=FindingSeverity.HIGH,
                detail=(
                    f"BSS advertises both SAE and PSK suites ({', '.join(posture.akm_names())}). "
                    "A client that supports WPA3 can be made to negotiate WPA2 instead, and "
                    "the resulting 4-way handshake is capturable and crackable offline - "
                    "which is exactly what SAE exists to prevent."
                    + (
                        " PMF is capable but not required, so nothing forces the client onto "
                        "the protected path."
                        if posture.mfpc and posture.mfpr is False
                        else ""
                    )
                ),
                remediation=(
                    "disable transition mode once the client inventory allows it, and "
                    "configure Transition Disable so clients stop offering WPA2; note that "
                    "Transition Disable is signalled inside the 4-way handshake, not in the "
                    "beacon, so it cannot be confirmed passively"
                ),
                verify_requires=(
                    "demonstrating that a WPA3-capable client negotiates PSK against a BSS "
                    "advertising only PSK. This framework does not perform that: it is an "
                    "active attack on third-party clients."
                ),
                cert_id=CERT_DRAGONBLOOD,
                evidence=(f"akm_suites={posture.akm_suites}", f"source={posture.source}"),
            )
        )
    elif posture.has_sae():
        findings.append(
            DragonbloodExposure(
                attack="WPA3-Transition downgrade to a crackable WPA2 handshake",
                status=FindingStatus.SUPPORTED,
                exposed=False,
                severity=FindingSeverity.INFO,
                detail=(
                    f"BSS advertises SAE with no PSK suite ({', '.join(posture.akm_names())}), "
                    "so there is no WPA2 path to downgrade to."
                ),
                remediation="none required for this class",
                verify_requires="n/a - the absence of a PSK suite is directly observable",
                cert_id=CERT_DRAGONBLOOD,
                evidence=(f"akm_suites={posture.akm_suites}",),
            )
        )

    # 2. PMF enforcement. WPA3 mandates it; without it the SAE guarantee is undermined.
    if posture.has_sae() and posture.mfpr is not True:
        findings.append(
            DragonbloodExposure(
                attack="management frame protection not required",
                status=FindingStatus.SUPPORTED,
                exposed=True,
                severity=(
                    FindingSeverity.MEDIUM
                    if posture.mfpc
                    else FindingSeverity.HIGH
                ),
                detail=(
                    "A WPA3 network must require management frame protection. MFPR is "
                    + (
                        "not set (MFPC is), so PMF is negotiable rather than enforced."
                        if posture.mfpc
                        else "not set and MFPC is not set either."
                    )
                    + " Unprotected deauthentication and disassociation remain available, "
                    "which is both a denial of service in its own right and the lever a "
                    "downgrade attack uses to push a client off the network."
                ),
                remediation="set ieee80211w=2 (required); WPA3-Personal requires it",
                verify_requires="n/a - MFPR is a beacon-visible bit",
                category=FindingCategory.CONFIGURATION,
                evidence=(f"mfpc={posture.mfpc}", f"mfpr={posture.mfpr}"),
            )
        )

    # 3. Timing side-channel. Precondition is group support, which is not in the beacon.
    findings.append(_timing_exposure(posture))

    # 4. Cache side-channel. Precondition is hunting-and-pecking plus an unfixed version.
    findings.append(_cache_exposure(posture))

    # 5. Security-group downgrade.
    findings.append(_group_downgrade_exposure(posture))

    # 6. Resource-consumption denial of service.
    findings.append(_dos_exposure(posture))

    return findings


def _eap_pwd_exposures(posture: Wpa3Posture) -> List[DragonbloodExposure]:
    """Assess EAP-pwd without mistaking an enterprise AKM for EAP-pwd itself."""
    if posture.eap_pwd_configured is not True:
        detail = (
            "An enterprise AKM was observed, but AKM selectors do not identify the EAP "
            "method. EAP-pwd configuration was not independently observed, so this cannot "
            "be called exposed or safe from a beacon alone."
        )
        return [
            DragonbloodExposure(
                attack="EAP-pwd cache side-channel",
                status=FindingStatus.UNRESOLVED,
                exposed=None,
                severity=FindingSeverity.MEDIUM,
                detail=detail,
                remediation="audit the RADIUS/EAP configuration and upgrade to 2.10 or later",
                verify_requires="RADIUS/EAP configuration identifying EAP-pwd and the implementation version",
                cve="CVE-2019-9495, CVE-2022-23304",
                category=FindingCategory.CONFIGURATION,
                evidence=(f"akm_suites={posture.akm_suites}", f"source={posture.source}"),
            ),
            DragonbloodExposure(
                attack="EAP-pwd reflection and invalid-commit validation",
                status=FindingStatus.UNRESOLVED,
                exposed=None,
                severity=FindingSeverity.HIGH,
                detail=detail,
                remediation="audit the RADIUS/EAP configuration and upgrade to 2.7 or later",
                verify_requires="RADIUS/EAP configuration identifying EAP-pwd and patched hostapd/wpa_supplicant versions",
                cve="CVE-2019-9497, CVE-2019-9498, CVE-2019-9499",
                category=FindingCategory.CONFIGURATION,
                evidence=(f"akm_suites={posture.akm_suites}", f"source={posture.source}"),
            ),
        ]

    version = posture.parsed_version
    if version is None:
        status = FindingStatus.UNRESOLVED
        exposed: Optional[bool] = None
    else:
        status = FindingStatus.SUPPORTED
        exposed = version < (2, 10)
    return [
        DragonbloodExposure(
            attack="EAP-pwd cache side-channel",
            status=status,
            exposed=exposed,
            severity=FindingSeverity.MEDIUM if exposed is not False else FindingSeverity.INFO,
            detail=(
                "EAP-pwd is configured. The cache side-channel fix is incomplete before 2.10."
                if version is not None
                else "EAP-pwd is configured, but the implementation version is unknown."
            ),
            remediation="upgrade to hostapd/wpa_supplicant 2.10 or later",
            verify_requires="cache-access measurement during EAP-pwd; this framework reports the precondition only",
            cve="CVE-2019-9495, CVE-2022-23304",
            category=FindingCategory.CONFIGURATION,
        ),
        DragonbloodExposure(
            attack="EAP-pwd reflection and invalid-commit validation",
            status=status,
            exposed=(version is None or version < (2, 7)) if version is not None else None,
            severity=FindingSeverity.HIGH if version is None or version < (2, 7) else FindingSeverity.INFO,
            detail=(
                "EAP-pwd is configured; versions before 2.7 require the reflection and "
                "scalar/element validation fixes."
                if version is not None
                else "EAP-pwd is configured, but the implementation version is unknown."
            ),
            remediation="upgrade to hostapd/wpa_supplicant 2.7 or later",
            verify_requires="an authorized EAP-pwd protocol test; this framework reports the configured precondition",
            cve="CVE-2019-9497, CVE-2019-9498, CVE-2019-9499",
            category=FindingCategory.CONFIGURATION,
        ),
    ]


def _timing_exposure(posture: Wpa3Posture) -> DragonbloodExposure:
    groups = posture.sae_groups
    if groups is None:
        return DragonbloodExposure(
            attack="SAE timing side-channel (password-dependent PWE iterations)",
            status=FindingStatus.UNRESOLVED,
            exposed=None,
            severity=FindingSeverity.MEDIUM,
            detail=(
                "Cannot be determined from what was observed: " + _UNOBSERVABLE_GROUPS + ". "
                "The leak requires a group whose prime is not close to a power of two - the "
                "MODP groups 22, 23 and 24, or any Brainpool curve. With NIST curves 19, 20 "
                "and 21 the authors report no timing leak."
            ),
            remediation=(
                "configure sae_groups=19 (hostapd's own default, and the authors' "
                "recommendation); Brainpool groups have been disabled by default since 2.9"
            ),
            verify_requires=(
                "the AP's sae_groups from its configuration, or an authorized SAE "
                "negotiation observing the groups it accepts"
            ),
            cve="CVE-2019-9494 (also CVE-2019-13377 for Brainpool)",
            cert_id=CERT_DRAGONBLOOD,
            evidence=(f"source={posture.source}",),
        )

    exposed_groups = sorted(set(groups) & timing_precondition_groups())
    weak = sorted(gid for gid in groups if not suitable_group(gid))
    if exposed_groups:
        names = ", ".join(
            f"{gid} ({SAE_GROUPS[gid].name})" if gid in SAE_GROUPS else str(gid)
            for gid in exposed_groups
        )
        return DragonbloodExposure(
            attack="SAE timing side-channel (password-dependent PWE iterations)",
            status=FindingStatus.SUPPORTED,
            exposed=True,
            severity=FindingSeverity.MEDIUM,
            detail=(
                f"Configured or negotiated groups include {names}, whose prime is not close "
                "to a power of two, so the hunting-and-pecking loop can run a "
                "password-dependent number of iterations. hostapd pads this loop to 40 "
                "iterations, which is a mitigation and not a proof of safety."
                + (f" Groups outside the REVmd suitability rule are also present: {weak}."
                   if weak else "")
            ),
            remediation="restrict sae_groups to 19, 20, 21; drop 22, 23, 24 and all Brainpool",
            verify_requires=(
                "measuring response-time distributions across many commit frames, which is "
                "the attack itself. This framework reports the precondition, not the leak."
            ),
            cve="CVE-2019-9494 (also CVE-2019-13377 for Brainpool)",
            cert_id=CERT_DRAGONBLOOD,
            evidence=(f"sae_groups={groups}", f"source={posture.source}"),
        )

    return DragonbloodExposure(
        attack="SAE timing side-channel (password-dependent PWE iterations)",
        status=FindingStatus.SUPPORTED,
        exposed=False,
        severity=FindingSeverity.INFO,
        detail=(
            f"Observed groups {sorted(groups)} contain none whose prime is far from a power "
            "of two."
            + (f" Note that {weak} are outside the REVmd suitability rule." if weak else "")
        ),
        remediation="none required for this class" + (
            f"; consider dropping the unsuitable groups {weak}" if weak else ""
        ),
        verify_requires="n/a given the observed group set",
        cve="CVE-2019-9494",
        evidence=(f"sae_groups={groups}",),
    )


def _cache_exposure(posture: Wpa3Posture) -> DragonbloodExposure:
    method = classify_pwe(posture.sae_pwe)
    exposes = pwe_exposes_cache_side_channel(method)
    version = posture.parsed_version
    version_unknown = version is None

    if exposes is None:
        return DragonbloodExposure(
            attack="SAE cache side-channel (hunting-and-pecking memory access pattern)",
            status=FindingStatus.UNRESOLVED,
            exposed=None,
            severity=FindingSeverity.MEDIUM,
            detail=(
                f"sae_pwe={posture.sae_pwe!r} is not a documented value, so the PWE "
                "derivation method cannot be determined and neither can this exposure."
            ),
            remediation="set sae_pwe explicitly to 1 (hash-to-element) or 2",
            verify_requires="a configuration value this framework recognizes",
            cve="CVE-2019-9494, CVE-2022-23303",
            category=FindingCategory.CONFIGURATION,
            evidence=(f"sae_pwe={posture.sae_pwe!r}",),
        )

    if posture.sae_pwe is None and "config" not in (posture.source or ""):
        # Nothing was observed at all: neither a beacon can show this, nor was a
        # configuration read. Report as unresolved rather than assuming the default.
        return DragonbloodExposure(
            attack="SAE cache side-channel (hunting-and-pecking memory access pattern)",
            status=FindingStatus.UNRESOLVED,
            exposed=None,
            severity=FindingSeverity.MEDIUM,
            detail=(
                "The PWE derivation method was not observed. It is not advertised in a "
                "beacon (the RSNX H2E bit indicates H2E *support*, not that it is the only "
                "method in use)"
                + (
                    f", though RSNX does advertise H2E support: {posture.h2e_advertised}."
                    if posture.h2e_advertised is not None
                    else ", and no RSNX element was observed."
                )
            ),
            remediation=(
                "read sae_pwe from the AP or supplicant configuration; set it to 1 to remove "
                "the hunting-and-pecking loop entirely"
            ),
            verify_requires="the sae_pwe setting, from configuration",
            cve="CVE-2019-9494, CVE-2022-23303",
            category=FindingCategory.CONFIGURATION,
            evidence=(f"h2e_advertised={posture.h2e_advertised}", f"source={posture.source}"),
        )

    detail_parts: List[str] = []
    if exposes:
        detail_parts.append(
            f"PWE derivation is {method.value}, so the hunting-and-pecking loop runs and its "
            "memory access pattern depends on the password."
        )
    else:
        detail_parts.append(
            "PWE derivation is hash-to-element only, so there is no hunting-and-pecking loop "
            "for a cache observer to measure."
        )

    if version_unknown:
        detail_parts.append(
            "The implementation version is unknown, so whether the side-channel mitigations "
            "are present cannot be determined."
        )
    else:
        assert version is not None
        if version < SIDE_CHANNEL_FIXED_IN:
            detail_parts.append(
                f"Version {'.'.join(str(part) for part in version)} predates "
                f"{'.'.join(str(p) for p in SIDE_CHANNEL_FIXED_IN)}, where CVE-2022-23303 was "
                "fixed. That CVE is recorded by NVD as an *incomplete fix* for CVE-2019-9494, so "
                "a system patched to 2.7 or 2.9 is still exposed."
            )
        else:
            detail_parts.append(
                f"Version {'.'.join(str(part) for part in version)} is at or past "
                f"{'.'.join(str(p) for p in SIDE_CHANNEL_FIXED_IN)}, where the incomplete-fix "
                "CVE-2022-23303 was addressed."
            )

    if version is None:
        version_vulnerable = True
    else:
        version_vulnerable = version < SIDE_CHANNEL_FIXED_IN
    exposed = bool(exposes) and version_vulnerable
    status = (
        FindingStatus.SUPPORTED
        if not version_unknown
        else FindingStatus.HYPOTHESIS
    )
    return DragonbloodExposure(
        attack="SAE cache side-channel (hunting-and-pecking memory access pattern)",
        status=status,
        exposed=exposed if not version_unknown else None,
        # INFO only when this class was positively ruled out. An unresolved version keeps
        # MEDIUM: "we could not tell" is not "we told you it is safe".
        severity=(
            FindingSeverity.INFO
            if exposed is False
            else FindingSeverity.MEDIUM
        ),
        detail=" ".join(detail_parts),
        remediation=(
            "none required for this class"
            if exposed is False
            else "set sae_pwe=1 and upgrade to hostapd/wpa_supplicant 2.10 or later"
        ),
        verify_requires=(
            "cache-access measurement on the victim device during a handshake - the attack "
            "itself, requiring unprivileged code execution on the target. This framework "
            "reports the precondition."
        ),
        cve="CVE-2019-9494, CVE-2022-23303",
        category=FindingCategory.CONFIGURATION,
        evidence=(
            f"sae_pwe={posture.sae_pwe!r}",
            f"version={posture.version!r}",
            f"source={posture.source}",
        ),
    )


def _group_downgrade_exposure(posture: Wpa3Posture) -> DragonbloodExposure:
    groups = posture.sae_groups
    if groups is None:
        return DragonbloodExposure(
            attack="SAE security-group downgrade",
            status=FindingStatus.UNRESOLVED,
            exposed=None,
            severity=FindingSeverity.MEDIUM,
            detail=(
                "Cannot be determined from what was observed: " + _UNOBSERVABLE_GROUPS + ". "
                "The attack forges decline messages carrying a rejected-groups element to "
                "push a peer onto a weaker group, so the exposure is whether the peer will "
                "accept one."
            ),
            remediation="restrict sae_groups to 19, 20, 21",
            verify_requires="the configured group list, or an authorized negotiation",
            cert_id=CERT_DRAGONBLOOD,
            evidence=(f"source={posture.source}",),
        )

    unsuitable = sorted(gid for gid in groups if not suitable_group(gid))
    if unsuitable:
        names = ", ".join(
            f"{gid} ({SAE_GROUPS[gid].name})" if gid in SAE_GROUPS else f"{gid} (unknown)"
            for gid in unsuitable
        )
        return DragonbloodExposure(
            attack="SAE security-group downgrade",
            status=FindingStatus.SUPPORTED,
            exposed=True,
            severity=FindingSeverity.MEDIUM,
            detail=(
                f"Groups outside hostapd's suitability rule are accepted: {names}. A "
                "downgrade has somewhere to land."
            ),
            remediation="restrict sae_groups to 19, 20, 21",
            verify_requires="forging decline frames, which is the attack itself",
            cert_id=CERT_DRAGONBLOOD,
            evidence=(f"sae_groups={groups}",),
        )

    return DragonbloodExposure(
        attack="SAE security-group downgrade",
        status=FindingStatus.SUPPORTED,
        exposed=False,
        severity=FindingSeverity.INFO,
        detail=f"Every accepted group {sorted(groups)} passes the suitability rule.",
        remediation="none required for this class",
        verify_requires="n/a given the observed group set",
        cert_id=CERT_DRAGONBLOOD,
        evidence=(f"sae_groups={groups}",),
    )


def _dos_exposure(posture: Wpa3Posture) -> DragonbloodExposure:
    threshold = posture.anti_clogging_threshold
    version = posture.parsed_version

    if threshold is None:
        detail = (
            "The anti-clogging token threshold was not observed. hostapd's cookie exchange is "
            "the mitigation for forged commit frames, and the authors found it trivial to "
            "bypass, so a high threshold is not by itself a defence - but its absence means "
            "the AP processes every commit frame at full cost."
        )
        status = FindingStatus.UNRESOLVED
        exposed: Optional[bool] = None
    else:
        detail = (
            f"anti_clogging_threshold={threshold}. The authors report that as few as 16 forged "
            "commit frames per second can overload an access point, and that the cookie "
            "exchange intended to prevent forged commits is trivial to bypass."
        )
        status = FindingStatus.SUPPORTED
        exposed = True

    if version is not None and version < (2, 7):
        detail += (
            f" Version {'.'.join(str(p) for p in version)} also predates the fix for "
            "CVE-2019-9496, where an invalid authentication sequence could terminate the "
            "hostapd process outright."
        )
    elif version is None:
        detail += " The version is unknown, so CVE-2019-9496 status cannot be determined."

    return DragonbloodExposure(
        attack="SAE resource-consumption denial of service",
        status=status,
        exposed=exposed,
        severity=FindingSeverity.MEDIUM if exposed else FindingSeverity.INFO,
        detail=detail,
        remediation=(
            "set anti_clogging_threshold, keep hostapd at 2.7 or later for CVE-2019-9496, and "
            "monitor for commit-frame floods rather than relying on the cookie exchange"
        ),
        verify_requires=(
            "sending forged commit frames at volume. This framework does not: it is a denial "
            "of service against a live network, and detection of the flood is the defensible "
            "capability."
        ),
        cve="CVE-2019-9496",
        cert_id=CERT_DRAGONBLOOD,
        category=FindingCategory.CONFIGURATION,
        evidence=(f"anti_clogging_threshold={threshold!r}", f"version={posture.version!r}"),
    )
