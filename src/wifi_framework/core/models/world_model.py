"""
World model - continuously maintains internal model of observed wireless environment.

The framework treats Wi-Fi penetration testing as adaptive investigation rather than
fixed sequence. It maintains what is known, identifies uncertainties, evaluates actions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from ...utils.validation import integral_int
from .evidence import Evidence, EvidenceType


def _record_parse_error(errors: List[str], field: str, value: Any, kept: Any) -> None:
    """Note a value that could not be read, once per distinct message.

    Deduplicated because a world model is long-lived: an access point observed on every
    sweep of a long capture would otherwise accumulate one identical entry per sweep.
    """
    message = f"{field}: could not read {value!r} as a whole number; kept {kept!r}"
    if message not in errors:
        errors.append(message)


@dataclass
class AccessPoint:
    bssid: str
    ssid: Optional[str] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None
    signal_strength: Optional[int] = None
    encryption: List[str] = field(default_factory=list)
    cipher: List[str] = field(default_factory=list)
    authentication: List[str] = field(default_factory=list)
    wps_enabled: Optional[bool] = None
    wps_locked: Optional[bool] = None
    manufacturer: Optional[str] = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_ids: List[str] = field(default_factory=list)
    client_macs: Set[str] = field(default_factory=set)
    # Additional observed properties
    is_hidden: bool = False
    uptime: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    #: Evidence values that could not be read, so the field kept its previous value.
    #: A dropped value used to leave no trace at all: the entity silently retained a
    #: stale channel or signal, and nothing downstream could tell a field that was never
    #: observed from one whose latest observation was unreadable.
    parse_errors: List[str] = field(default_factory=list)

    def update_from_evidence(self, evidence: Evidence):
        data = evidence.parsed_data
        # Update fields if present in evidence
        if "ssid" in data and data["ssid"]:
            self.ssid = data["ssid"]
            if self.ssid == "" or data.get("is_hidden"):
                self.is_hidden = True
        if "channel" in data and data["channel"]:
            channel = integral_int(data["channel"])
            if channel is None:
                _record_parse_error(self.parse_errors, "channel", data["channel"], self.channel)
            else:
                self.channel = channel
        if "frequency" in data:
            self.frequency = data["frequency"]
        if "signal" in data or "power" in data:
            sig = data.get("signal") or data.get("power")
            signal = integral_int(sig)
            if signal is None:
                _record_parse_error(self.parse_errors, "signal", sig, self.signal_strength)
            else:
                self.signal_strength = signal
        if "encryption" in data:
            enc = data["encryption"]
            if isinstance(enc, str):
                enc = [enc]
            for e in enc:
                if e not in self.encryption:
                    self.encryption.append(e)
        if "cipher" in data:
            c = data["cipher"]
            if isinstance(c, str):
                c = [c]
            for item in c:
                if item not in self.cipher:
                    self.cipher.append(item)
        if "authentication" in data:
            auth = data["authentication"]
            if isinstance(auth, str):
                auth = [auth]
            for a in auth:
                if a not in self.authentication:
                    self.authentication.append(a)
        if "wps_enabled" in data:
            self.wps_enabled = bool(data["wps_enabled"])
        if "wps_locked" in data:
            self.wps_locked = bool(data["wps_locked"])
        if "manufacturer" in data:
            self.manufacturer = data["manufacturer"]

        # WPA3/RSN fields are deliberately kept under a namespaced extra payload. The
        # generic AP model predates RSN capabilities; placing these observations here keeps
        # older consumers compatible while preserving the exact posture for the assessment
        # engine. Missing keys are not converted into false values.
        wpa3_keys = {
            "akm_suites", "akm_names", "mfpc", "mfpr", "h2e_advertised",
            "sae_pk_advertised", "sae_groups", "sae_pwe", "anti_clogging_threshold",
            "transition_disable_configured", "version", "source", "eap_pwd_configured",
        }
        wpa3_observations = {key: data[key] for key in wpa3_keys if key in data}
        if wpa3_observations:
            current = self.extra.setdefault("wpa3", {})
            if isinstance(current, dict):
                current.update(wpa3_observations)

        self.last_seen = evidence.timestamp
        if evidence.id not in self.evidence_ids:
            self.evidence_ids.append(evidence.id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "frequency": self.frequency,
            "signal_strength": self.signal_strength,
            "encryption": self.encryption,
            "cipher": self.cipher,
            "authentication": self.authentication,
            "wps_enabled": self.wps_enabled,
            "wps_locked": self.wps_locked,
            "manufacturer": self.manufacturer,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "evidence_ids": self.evidence_ids,
            "client_macs": list(self.client_macs),
            "is_hidden": self.is_hidden,
            "extra": self.extra,
            "parse_errors": list(self.parse_errors),
        }


@dataclass
class WirelessClient:
    mac: str
    associated_bssid: Optional[str] = None
    ssid_probed: List[str] = field(default_factory=list)
    signal_strength: Optional[int] = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_ids: List[str] = field(default_factory=list)
    manufacturer: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    #: See ``AccessPoint.parse_errors``.
    parse_errors: List[str] = field(default_factory=list)

    def update_from_evidence(self, evidence: Evidence):
        data = evidence.parsed_data
        if "ap_mac" in data or "bssid" in data:
            self.associated_bssid = data.get("ap_mac") or data.get("bssid")
        if "probed_ssid" in data and data["probed_ssid"]:
            if data["probed_ssid"] not in self.ssid_probed:
                self.ssid_probed.append(data["probed_ssid"])
        if "signal" in data:
            signal = integral_int(data["signal"])
            if signal is None:
                _record_parse_error(
                    self.parse_errors, "signal", data["signal"], self.signal_strength
                )
            else:
                self.signal_strength = signal
        self.last_seen = evidence.timestamp
        if evidence.id not in self.evidence_ids:
            self.evidence_ids.append(evidence.id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac,
            "associated_bssid": self.associated_bssid,
            "ssid_probed": self.ssid_probed,
            "signal_strength": self.signal_strength,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "evidence_ids": self.evidence_ids,
            "manufacturer": self.manufacturer,
            "extra": self.extra,
            "parse_errors": list(self.parse_errors),
        }


@dataclass
class NetworkHost:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_ids: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "open_ports": self.open_ports,
            "services": self.services,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "evidence_ids": self.evidence_ids,
            "extra": self.extra,
        }


@dataclass
class WorldModel:
    """
    Internal model of observed wireless environment.

    Continuously updated with new evidence. Used by planner to identify uncertainties.
    """
    access_points: Dict[str, AccessPoint] = field(default_factory=dict)  # bssid -> AP
    clients: Dict[str, WirelessClient] = field(default_factory=dict)  # mac -> client
    network_hosts: Dict[str, NetworkHost] = field(default_factory=dict)  # ip -> host
    channels_observed: Set[int] = field(default_factory=set)
    ssids_observed: Set[str] = field(default_factory=set)
    evidence_count: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def update(self, evidence: Evidence):
        """Update world model from structured evidence."""
        self.evidence_count += 1
        self.last_updated = evidence.timestamp

        etype = evidence.evidence_type
        data = evidence.parsed_data

        if etype == EvidenceType.ACCESS_POINT:
            bssid = data.get("bssid") or data.get("mac")
            if not bssid:
                return
            bssid = bssid.upper()
            if bssid not in self.access_points:
                self.access_points[bssid] = AccessPoint(bssid=bssid, first_seen=evidence.timestamp)
            self.access_points[bssid].update_from_evidence(evidence)

            if data.get("ssid"):
                self.ssids_observed.add(data["ssid"])
            if data.get("channel"):
                try:
                    self.channels_observed.add(int(data["channel"]))
                except (ValueError, TypeError):
                    pass

            # Update client relationship if present
            if "client_mac" in data and data["client_mac"]:
                client_mac = data["client_mac"].upper()
                if client_mac in self.clients:
                    self.clients[client_mac].associated_bssid = bssid
                self.access_points[bssid].client_macs.add(client_mac)

        elif etype == EvidenceType.CLIENT:
            mac = data.get("client_mac") or data.get("mac") or data.get("client")
            if not mac:
                return
            mac = mac.upper()
            if mac not in self.clients:
                self.clients[mac] = WirelessClient(mac=mac, first_seen=evidence.timestamp)
            self.clients[mac].update_from_evidence(evidence)

            # Update AP client list
            ap_mac = data.get("ap_mac") or data.get("bssid")
            if ap_mac:
                ap_mac = ap_mac.upper()
                if ap_mac in self.access_points:
                    self.access_points[ap_mac].client_macs.add(mac)

        elif etype == EvidenceType.WPS:
            bssid = data.get("bssid") or data.get("mac")
            if bssid:
                bssid = bssid.upper()
                if bssid not in self.access_points:
                    self.access_points[bssid] = AccessPoint(bssid=bssid, first_seen=evidence.timestamp)
                self.access_points[bssid].update_from_evidence(evidence)

        elif etype == EvidenceType.NETWORK_HOST:
            ip = data.get("ip")
            if not ip:
                return
            if ip not in self.network_hosts:
                self.network_hosts[ip] = NetworkHost(ip=ip, first_seen=evidence.timestamp)
            host = self.network_hosts[ip]
            if "mac" in data and data["mac"]:
                host.mac = data["mac"]
            if "hostname" in data and data["hostname"]:
                host.hostname = data["hostname"]
            if "os" in data and data["os"]:
                host.os_guess = data["os"]
            if evidence.id not in host.evidence_ids:
                host.evidence_ids.append(evidence.id)
            host.last_seen = evidence.timestamp

        elif etype == EvidenceType.NETWORK_SERVICE:
            ip = data.get("ip")
            port = data.get("port")
            if not ip or not port:
                return
            try:
                port = int(port)
            except (ValueError, TypeError):
                return
            if ip not in self.network_hosts:
                self.network_hosts[ip] = NetworkHost(ip=ip, first_seen=evidence.timestamp)
            host = self.network_hosts[ip]
            if port not in host.open_ports:
                host.open_ports.append(port)
            host.services[port] = {
                "service": data.get("service"),
                "version": data.get("version"),
                "protocol": data.get("protocol", "tcp"),
                "state": data.get("state", "open"),
            }
            host.last_seen = evidence.timestamp

        # Generic channel observations
        if "channel" in data and data["channel"]:
            try:
                self.channels_observed.add(int(data["channel"]))
            except (ValueError, TypeError):
                pass

    def get_ap_by_ssid(self, ssid: str) -> List[AccessPoint]:
        return [ap for ap in self.access_points.values() if ap.ssid == ssid]

    def get_unidentified_aps(self) -> List[AccessPoint]:
        """APs with missing critical info."""
        result = []
        for ap in self.access_points.values():
            if not ap.ssid or ap.channel is None or not ap.encryption:
                result.append(ap)
        return result

    def get_wps_enabled_aps(self) -> List[AccessPoint]:
        return [ap for ap in self.access_points.values() if ap.wps_enabled]

    def get_clients_without_ap(self) -> List[WirelessClient]:
        return [c for c in self.clients.values() if not c.associated_bssid]

    def summary(self) -> Dict[str, Any]:
        return {
            "access_points_count": len(self.access_points),
            "clients_count": len(self.clients),
            "network_hosts_count": len(self.network_hosts),
            "channels_observed": sorted(list(self.channels_observed)),
            "ssids_observed": sorted(list(self.ssids_observed)),
            "evidence_count": self.evidence_count,
            "last_updated": self.last_updated.isoformat(),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_points": {bssid: ap.to_dict() for bssid, ap in self.access_points.items()},
            "clients": {mac: client.to_dict() for mac, client in self.clients.items()},
            "network_hosts": {ip: host.to_dict() for ip, host in self.network_hosts.items()},
            "channels_observed": sorted(list(self.channels_observed)),
            "ssids_observed": sorted(list(self.ssids_observed)),
            "evidence_count": self.evidence_count,
            "last_updated": self.last_updated.isoformat(),
        }
