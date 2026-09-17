"""
Parser for nmap output (normal, grepable, XML).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from ..core.models.evidence import ConfidenceLevel, Evidence, EvidenceType


def parse_nmap_grepable(output: str) -> List[Dict[str, Any]]:
    """
    Parse nmap grepable output (-oG).

    Example:
    Host: 192.168.1.1 () Status: Up
    Host: 192.168.1.1 () Ports: 22/open/tcp//ssh//OpenSSH 7.9/
    """
    hosts = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("Host:"):
            # Extract IP
            ip_match = re.search(r"Host:\s+(\S+)", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            if ip not in hosts:
                hosts[ip] = {"ip": ip, "ports": [], "status": "unknown"}

            if "Status:" in line:
                if "Up" in line:
                    hosts[ip]["status"] = "up"
                else:
                    hosts[ip]["status"] = "down"

            if "Ports:" in line:
                ports_part = line.split("Ports:")[1].strip()
                # Ports are like 22/open/tcp//ssh//OpenSSH 7.9/, 80/open/tcp//http//...
                port_entries = ports_part.split(",")
                for entry in port_entries:
                    entry = entry.strip()
                    if not entry:
                        continue
                    # Format: port/state/protocol/owner/service/version
                    parts = entry.split("/")
                    if len(parts) >= 5:
                        try:
                            port_num = int(parts[0])
                            state = parts[1]
                            protocol = parts[2]
                            service = parts[4]
                            version = parts[6] if len(parts) > 6 else ""
                            if state == "open":
                                hosts[ip]["ports"].append(
                                    {
                                        "port": port_num,
                                        "protocol": protocol,
                                        "service": service,
                                        "version": version,
                                        "state": state,
                                    }
                                )
                        except (ValueError, IndexError):
                            continue

    return list(hosts.values())


def parse_nmap_normal(output: str) -> List[Dict[str, Any]]:
    """Parse nmap normal output."""
    hosts = []
    current_host = None

    for line in output.splitlines():
        line = line.strip()
        # Nmap scan report for
        m = re.match(r"Nmap scan report for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)\)?", line)
        if m:
            hostname = m.group(1)
            ip = m.group(2)
            if not ip:
                ip = hostname
            else:
                if not hostname or re.match(r"\d+\.\d+\.\d+\.\d+", hostname):
                    hostname = None
            current_host = {"ip": ip, "hostname": hostname, "ports": [], "status": "up"}
            hosts.append(current_host)
            continue

        # Port line: 22/tcp open ssh OpenSSH 7.9
        port_match = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?", line)
        if port_match and current_host is not None:
            try:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5) or ""
                if state == "open":
                    current_host["ports"].append(
                        {
                            "port": port_num,
                            "protocol": protocol,
                            "service": service,
                            "version": version,
                            "state": state,
                        }
                    )
            except ValueError:
                continue

    return hosts


def parse_nmap_xml(xml_content: str, issues: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Parse nmap XML output.

    ``issues``, when given, receives a description of any extraction problem. A
    document that does not parse yields an empty list, which is indistinguishable
    from "nmap found no hosts" unless the failure is reported - and the difference
    matters, because one is an observation and the other is a missing one.
    ``contracts/evidence.py`` states the rule: extraction problems are declared, not
    hidden.
    """
    hosts = []
    try:
        root = ET.fromstring(xml_content)
        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            status = status_elem.get("state") if status_elem is not None else "unknown"
            if status != "up":
                continue

            address_elem = host_elem.find("address[@addrtype='ipv4']")
            if address_elem is None:
                address_elem = host_elem.find("address")
            if address_elem is None:
                continue
            ip = address_elem.get("addr")
            hostname_elem = host_elem.find("hostnames/hostname")
            hostname = hostname_elem.get("name") if hostname_elem is not None else None

            host_data = {"ip": ip, "hostname": hostname, "ports": [], "status": status}

            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue
                    port_id = port_elem.get("portid")
                    protocol = port_elem.get("protocol")
                    service_elem = port_elem.find("service")
                    service = service_elem.get("name") if service_elem is not None else ""
                    version = service_elem.get("product") if service_elem is not None else ""
                    if service_elem is not None and service_elem.get("version"):
                        version = f"{version} {service_elem.get('version')}".strip()

                    try:
                        host_data["ports"].append(
                            {
                                "port": int(port_id),
                                "protocol": protocol,
                                "service": service,
                                "version": version,
                                "state": "open",
                            }
                        )
                    except ValueError:
                        continue

            hosts.append(host_data)
    except ET.ParseError as exc:
        if issues is not None:
            issues.append(
                f"nmap XML output could not be parsed ({exc}); the empty result means the "
                "output was unusable, not that no hosts were found"
            )
        return hosts

    return hosts


def nmap_to_evidences(
    output: str,
    target: str = None,
    execution_id: str = None,
    issues: Optional[List[str]] = None,
) -> List[Evidence]:
    """Convert nmap output to evidences.

    ``issues`` collects extraction problems for the caller to report; see
    :func:`parse_nmap_xml`.
    """
    evidences = []

    # Try XML first
    if output.strip().startswith("<?xml") or "<nmaprun" in output:
        hosts = parse_nmap_xml(output, issues=issues)
    elif "Host:" in output and "Ports:" in output:
        hosts = parse_nmap_grepable(output)
    else:
        hosts = parse_nmap_normal(output)

    for host in hosts:
        # Host evidence
        ev_host = Evidence.from_tool_output(
            tool_name="nmap",
            capability="network_discovery",
            evidence_type=EvidenceType.NETWORK_HOST,
            raw_output=output,
            parsed_data={
                "ip": host["ip"],
                "hostname": host.get("hostname"),
                "status": host.get("status", "up"),
                "target": target,
            },
            parameters={"target": target} if target else {},
            confidence=ConfidenceLevel.HIGH,
            execution_id=execution_id,
            raw_command=f"nmap {target}" if target else "nmap",
        )
        evidences.append(ev_host)

        # Service evidences
        for port_info in host.get("ports", []):
            ev_service = Evidence.from_tool_output(
                tool_name="nmap",
                capability="service_enumeration",
                evidence_type=EvidenceType.NETWORK_SERVICE,
                raw_output=output,
                parsed_data={
                    "ip": host["ip"],
                    "port": port_info["port"],
                    "protocol": port_info.get("protocol", "tcp"),
                    "service": port_info.get("service"),
                    "version": port_info.get("version"),
                    "state": port_info.get("state", "open"),
                },
                parameters={"target": target} if target else {},
                confidence=ConfidenceLevel.HIGH,
                execution_id=execution_id,
                raw_command=f"nmap {target}" if target else "nmap",
            )
            evidences.append(ev_service)

    return evidences
