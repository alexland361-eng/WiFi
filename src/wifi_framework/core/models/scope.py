"""
Scope and authorization model.

The framework is intended for authorized security assessment. Operational controls
must preserve defined assessment scope and prevent decision engine from silently expanding it.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional, Set

from ...utils.validation import integral_int, normalize_mac


@dataclass
class AssessmentScope:
    """
    Defines authorized scope for assessment.

    Distinguishes assets inside authorized scope from unrelated wireless networks
    or devices observed in surrounding radio environment.
    """
    # Wireless scope
    authorized_ssids: List[str] = field(default_factory=list)  # Exact or regex patterns
    authorized_bssids: List[str] = field(default_factory=list)  # MACs, normalized upper
    authorized_channels: List[int] = field(default_factory=list)  # Empty = all channels allowed
    # Network scope (after wireless access)
    authorized_networks: List[str] = field(default_factory=list)  # CIDR notation
    authorized_hosts: List[str] = field(default_factory=list)  # IPs or hostnames
    # General
    description: str = ""
    allow_broadcast_discovery: bool = True  # Allow passive discovery of all, but only act on authorized
    strict_mode: bool = False  # If True, even passive observation limited to authorized

    # Internal compiled patterns
    _ssid_patterns: List[re.Pattern] = field(default_factory=list, init=False, repr=False)
    _network_objects: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list, init=False, repr=False)
    _bssid_set: Set[str] = field(default_factory=set, init=False, repr=False)

    #: Declared entries that could not be used and were dropped. An authorization entry
    #: that silently fails to parse narrows the scope without telling anyone: the
    #: operator believes 192.168.1.0/24 is authorized, it is not, and every action
    #: against it is refused for a reason that looks like a scope violation rather than
    #: a typo. The direction is fail-safe, but the silence is not. Reported by
    #: :meth:`validate` and carried in :meth:`to_dict`, which is what the audit trail
    #: records when the scope is defined.
    invalid_bssids: List[str] = field(default_factory=list, init=False, repr=False)
    invalid_networks: List[str] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self):
        # Compile SSID patterns
        self._ssid_patterns = []
        for ssid in self.authorized_ssids:
            try:
                # Treat as regex if contains regex chars, otherwise exact match
                if any(c in ssid for c in ".*+?^$[]()|\\"):
                    self._ssid_patterns.append(re.compile(ssid, re.IGNORECASE))
                else:
                    # Exact match pattern
                    self._ssid_patterns.append(re.compile(f"^{re.escape(ssid)}$", re.IGNORECASE))
            except re.error:
                # Fallback to literal
                self._ssid_patterns.append(re.compile(f"^{re.escape(ssid)}$", re.IGNORECASE))

        # Normalize BSSIDs
        self._bssid_set = set()
        self.invalid_bssids = []
        for bssid in self.authorized_bssids:
            normalized = self._normalize_mac(bssid)
            if normalized:
                self._bssid_set.add(normalized)
            else:
                self.invalid_bssids.append(str(bssid))

        # Parse networks
        self._network_objects = []
        self.invalid_networks = []
        for net in self.authorized_networks:
            try:
                self._network_objects.append(ipaddress.ip_network(net, strict=False))
            except ValueError:
                self.invalid_networks.append(str(net))

    @staticmethod
    def _normalize_mac(mac: str) -> Optional[str]:
        """
        Normalize a BSSID to upper colon format, or ``None`` if it is not a well-formed address.

        Delegates to :func:`wifi_framework.utils.validation.normalize_mac` rather than keeping a
        second implementation here. This copy sits in the authorisation path - it builds the
        allowlist that decides which access points may be attacked - and it had drifted into a
        security bug: it stripped *every* non-hex character, so a malformed entry such as
        ``AABBCCDDEEFFGG`` was silently normalised to ``AA:BB:CC:DD:EE:FF``. The scope then
        authorised a network the operator never named, and :meth:`validate` reported no error
        because the normalisation had "succeeded".

        One shared definition means the scope allowlist and the rest of the framework cannot
        disagree about what counts as a BSSID.
        """
        return normalize_mac(mac)

    def is_ssid_authorized(self, ssid: str) -> bool:
        """Check if SSID is within authorized scope."""
        if not self.authorized_ssids:
            # If no SSID restriction, all are authorized for observation,
            # but active testing still requires explicit scope if strict
            return not self.strict_mode
        if not ssid:
            return False
        for pattern in self._ssid_patterns:
            if pattern.match(ssid):
                return True
        return False

    def is_bssid_authorized(self, bssid: str) -> bool:
        """Check if BSSID is within authorized scope."""
        if not self.authorized_bssids:
            return not self.strict_mode
        normalized = self._normalize_mac(bssid)
        if not normalized:
            return False
        return normalized in self._bssid_set

    def is_channel_authorized(self, channel: int) -> bool:
        if not self.authorized_channels:
            return True
        return channel in self.authorized_channels

    def is_ip_authorized(self, ip_str: str) -> bool:
        """Check if IP is within authorized networks or hosts."""
        if not self.authorized_networks and not self.authorized_hosts:
            # No network restriction defined
            return not self.strict_mode

        # Check explicit hosts
        if ip_str in self.authorized_hosts:
            return True

        # Check networks
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in self._network_objects:
                if ip_obj in net:
                    return True
        except ValueError:
            # Hostname check
            if ip_str in self.authorized_hosts:
                return True
            return False

        return False

    def is_wireless_asset_authorized(self, ssid: Optional[str] = None, bssid: Optional[str] = None) -> bool:
        """
        Determine if wireless asset is authorized for active testing.

        In non-strict mode, if neither SSID nor BSSID restrictions exist, allow all for passive,
        but for active testing we require at least one identifier to be authorized if any restriction exists.
        """
        # If no restrictions at all, everything authorized (for initial discovery)
        if not self.authorized_ssids and not self.authorized_bssids:
            return True

        # If either matches, authorized.
        #
        # An identifier may only *grant* authorisation when the operator actually used that
        # identifier to define scope. An empty list means "this identifier did not define the
        # scope", not "anything goes": without this rule, an access point whose BSSID is
        # explicitly absent from an authorised-BSSID list would be waved through by a
        # vacuously true SSID check, and an invasive action against a neighbour's AP would be
        # permitted. ``is_ssid_authorized``/``is_bssid_authorized`` deliberately stay permissive
        # for callers that ask about a single identifier in isolation.
        ssid_ok = bool(ssid) and bool(self.authorized_ssids) and self.is_ssid_authorized(ssid)
        bssid_ok = bool(bssid) and bool(self.authorized_bssids) and self.is_bssid_authorized(bssid)

        # If both provided, either matching is enough
        # If only one provided, that one must match
        if ssid and bssid:
            return ssid_ok or bssid_ok
        elif ssid:
            return ssid_ok
        elif bssid:
            return bssid_ok
        else:
            # No identifier provided, cannot authorize if restrictions exist
            return False

    def validate(self) -> List[str]:
        """Validate scope definition, return list of errors.

        Never raises. This is the function that reports malformed scope, so a malformed
        entry crashing it is the one failure it must not have: ``1 <= ch <= 196`` raised
        ``TypeError`` on a channel declared as a string, which is exactly the input it
        exists to report.
        """
        errors = []
        # BSSIDs and networks were already parsed in __post_init__; report what was
        # dropped there rather than parsing a second time and risking a different answer.
        for bssid in self.invalid_bssids:
            errors.append(f"Invalid BSSID format: {bssid}")
        for net in self.invalid_networks:
            errors.append(f"Invalid network CIDR: {net}")
        # Validate channels
        for ch in self.authorized_channels:
            number = self._channel_number(ch)
            if number is None or not 1 <= number <= 196:  # Covers 2.4GHz, 5GHz, 6GHz
                errors.append(f"Invalid channel: {ch}")
        return errors

    @staticmethod
    def _channel_number(channel: Any) -> Optional[int]:
        """A channel as an int, or ``None`` if the value is not one.

        Delegates to :func:`utils.validation.integral_int`, which accepts the integral
        strings a configuration file produces and refuses anything that does not survive
        the round trip - ``6.5`` truncates to a valid channel, so it is refused rather
        than quietly rounded. One rule for every value being recorded, so a declared
        channel here and an observed channel in the world model cannot disagree.
        """
        return integral_int(channel)

    def to_dict(self):
        return {
            "authorized_ssids": self.authorized_ssids,
            "authorized_bssids": self.authorized_bssids,
            "authorized_channels": self.authorized_channels,
            "authorized_networks": self.authorized_networks,
            "authorized_hosts": self.authorized_hosts,
            "description": self.description,
            "allow_broadcast_discovery": self.allow_broadcast_discovery,
            "strict_mode": self.strict_mode,
            # Recorded so the audit trail shows which declared authorizations were
            # unusable, not only which were requested.
            "invalid_bssids": list(self.invalid_bssids),
            "invalid_networks": list(self.invalid_networks),
        }


class ScopeEnforcer:
    """Enforces scope during assessment."""

    def __init__(self, scope: AssessmentScope):
        self.scope = scope

    def check_wireless_action_allowed(self, ssid: Optional[str], bssid: Optional[str], invasive: bool) -> tuple[bool, str]:
        """
        Check if wireless action is allowed.

        Returns (allowed, reason).
        """
        if not invasive:
            # Passive observation always allowed if broadcast discovery allowed
            if self.scope.allow_broadcast_discovery:
                return True, "Passive observation allowed"
            # Otherwise check scope
            if self.scope.is_wireless_asset_authorized(ssid, bssid):
                return True, "Asset in authorized scope"
            else:
                return False, f"Asset SSID={ssid} BSSID={bssid} not in authorized scope (passive restricted)"

        # Invasive actions require authorization
        if self.scope.is_wireless_asset_authorized(ssid, bssid):
            return True, "Asset in authorized scope for active testing"
        else:
            return False, f"Invasive action denied: SSID={ssid} BSSID={bssid} not in authorized scope"

    def check_network_action_allowed(self, target_ip: str, invasive: bool) -> tuple[bool, str]:
        if not invasive:
            if self.scope.allow_broadcast_discovery:
                return True, "Passive network observation allowed"
        if self.scope.is_ip_authorized(target_ip):
            return True, "Target IP in authorized scope"
        else:
            return False, f"Action denied: IP {target_ip} not in authorized scope"

    def filter_evidence_by_scope(self, evidence_list):
        """Tag evidence as in-scope or out-of-scope for reporting."""
        # This doesn't filter out, but tags
        for ev in evidence_list:
            ssid = ev.parsed_data.get("ssid")
            bssid = ev.parsed_data.get("bssid") or ev.parsed_data.get("mac") or ev.parsed_data.get("ap_mac")
            ip = ev.parsed_data.get("ip") or ev.parsed_data.get("target_ip")
            in_scope = True
            if ssid or bssid:
                in_scope = self.scope.is_wireless_asset_authorized(ssid, bssid)
            elif ip:
                in_scope = self.scope.is_ip_authorized(ip)
            ev.tags.append("in_scope" if in_scope else "out_of_scope")
        return evidence_list
