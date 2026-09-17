"""
CLI for WiFi Framework - real Wi-Fi penetration-testing and security-assessment framework.
"""
from __future__ import annotations

import argparse
import json
import sys

from ..core.models.scope import AssessmentScope
from ..core.engine.assessment_engine import AssessmentEngine
from ..core.execution.registry import get_global_registry
from ..core.execution.tool_manager import ToolManager
from ..core.execution.dependency_resolver import DependencyResolver
from ..tools.registry_loader import load_all_adapters
from ..core.audit.logger import AuditLogger
from ..core.experience.store import ExperienceStore
from typing import Optional


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifi-assess",
        description="Real Wi-Fi penetration-testing and security-assessment framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover interfaces and capabilities
  wifi-assess --discover-only

  # Assess with authorized SSIDs
  wifi-assess --ssid MyNetwork --ssid CorpWiFi --max-iterations 30

  # Assess with authorized BSSIDs and channels
  wifi-assess --bssid 00:11:22:33:44:55 --channel 6 --channel 11

  # Assess with network scope
  wifi-assess --ssid MyNetwork --network 192.168.1.0/24 --max-iterations 50

  # List available capabilities
  wifi-assess --list-capabilities

  # Run with specific interface
  wifi-assess --interface wlan0mon --ssid MyNetwork

Operational Philosophy:
  This framework is designed as a real Wi-Fi penetration-testing and security-assessment
  framework, not as a collection of simulated demonstrations. It performs genuine assessments
  against networks and wireless environments for which the operator has explicit authorization.

  Every reported observation can be traced back to an actual operation performed by a real
  supported tool.
        """,
    )

    parser.add_argument(
        "--ssid",
        action="append",
        default=[],
        help="Authorized SSID (can be specified multiple times, supports regex)",
    )
    parser.add_argument(
        "--bssid",
        action="append",
        default=[],
        help="Authorized BSSID (can be specified multiple times)",
    )
    parser.add_argument(
        "--channel",
        action="append",
        type=int,
        default=[],
        help="Authorized channel (can be specified multiple times)",
    )
    parser.add_argument(
        "--network",
        action="append",
        default=[],
        dest="networks",
        help="Authorized network CIDR (e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "--host",
        action="append",
        default=[],
        dest="hosts",
        help="Authorized host IP or hostname",
    )
    parser.add_argument(
        "--interface",
        "-i",
        help="Wireless interface to use (e.g., wlan0mon)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=30,
        help="Maximum assessment iterations (default: 30)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout per tool execution in seconds (default: 60)",
    )
    parser.add_argument(
        "--discover-only",
        action="store_true",
        help="Only discover interfaces and capabilities, don't run assessment",
    )
    parser.add_argument(
        "--list-capabilities",
        action="store_true",
        help="List all registered capabilities and their availability",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List discovered wireless interfaces",
    )
    parser.add_argument(
        "--scope-description",
        default="",
        help="Description of assessment scope for audit log",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict scope mode (even passive observation limited to authorized)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output directory for reports (default: /tmp/wifi_framework_audit)",
    )
    parser.add_argument(
        "--config",
        help="Path to YAML config file with scope definition",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )

    return parser


def load_scope_from_args(args) -> AssessmentScope:
    """Create scope from CLI args."""
    scope = AssessmentScope(
        authorized_ssids=args.ssid,
        authorized_bssids=args.bssid,
        authorized_channels=args.channel,
        authorized_networks=args.networks,
        authorized_hosts=args.hosts,
        description=args.scope_description,
        strict_mode=args.strict,
    )

    # Load from config file if provided
    if args.config:
        try:
            import yaml

            with open(args.config, "r") as f:
                config = yaml.safe_load(f)
                if config:
                    if "authorized_ssids" in config:
                        scope.authorized_ssids.extend(config["authorized_ssids"])
                    if "authorized_bssids" in config:
                        scope.authorized_bssids.extend(config["authorized_bssids"])
                    if "authorized_channels" in config:
                        scope.authorized_channels.extend(config["authorized_channels"])
                    if "authorized_networks" in config:
                        scope.authorized_networks.extend(config["authorized_networks"])
                    if "authorized_hosts" in config:
                        scope.authorized_hosts.extend(config["authorized_hosts"])
                    if "description" in config:
                        scope.description = config["description"]
        except Exception as e:
            print(f"[!] Failed to load config {args.config}: {e}", file=sys.stderr)
            sys.exit(1)

    # Validate scope
    errors = scope.validate()
    if errors:
        print("[!] Scope validation errors:", file=sys.stderr)
        for err in errors:
            print(f"    - {err}", file=sys.stderr)
        sys.exit(1)

    return scope


def cmd_list_capabilities(registry, interface: Optional[str] = None):
    """List capabilities with deep tool management."""
    print("=== Registered Capabilities (Deep Management) ===")

    tool_manager = ToolManager(registry)
    dependency_resolver = DependencyResolver(registry)

    # Show deep tool info
    deep_tools = tool_manager.discover_all_tools()
    print(f"\nDeep Tool Discovery: {len(deep_tools)} binaries")
    for binary, info in sorted(deep_tools.items()):
        if info.available:
            print(f"  AVAILABLE: {binary} at {info.path} version={info.version_raw[:50] if info.version_raw else 'unknown'} operational={info.operational}")
        else:
            print(f"  UNAVAILABLE: {binary} - {info.failure_reason}")

    # Show interface deep capabilities
    deep_ifaces = tool_manager.discover_all_interfaces()
    print(f"\nDeep Interface Discovery: {len(deep_ifaces)} interfaces")
    for iface_name, cap in deep_ifaces.items():
        print(f"  {iface_name}: exists={cap.exists} up={cap.is_up} driver={cap.driver} monitor={cap.supports_monitor} injection={cap.supports_injection} mac={cap.mac}")

    # Show tool chains
    print("\nTool Chains Feasibility:")
    for objective in ["handshake_capture", "wps_assessment", "wireless_discovery", "network_discovery", "service_enumeration", "vulnerability_assessment", "interface_setup"]:
        chain = tool_manager.get_tool_chain(objective)
        feasible, missing, reasons = dependency_resolver.check_tool_chain_feasibility(chain, interface)
        status = "FEASIBLE" if feasible else f"PARTIAL missing={missing}"
        print(f"  {objective}: {chain} -> {status}")

    print("\n=== Detailed Capability List ===")
    for name in sorted(registry.list_capabilities()):
        meta = registry.get_metadata(name)
        # Use deep check
        available, reason, details = tool_manager.get_capability_status(name, interface)
        status = "AVAILABLE" if available else f"UNAVAILABLE ({reason})"
        print(f"\n{name}:")
        print(f"  Display: {meta.display_name}")
        print(f"  Category: {meta.category.value}")
        print(f"  Tool: {meta.tool_binary}")
        print(f"  Status: {status}")
        print(f"  Description: {meta.description}")
        print(f"  Inputs: {meta.inputs}")
        print(f"  Outputs: {meta.outputs}")
        print(f"  Invasive: {meta.operational_properties.invasive}")
        print(f"  Persistent: {meta.operational_properties.persistent}")
        print(f"  Requires Auth: {meta.operational_properties.requires_authorization}")
        if meta.requirements.interface_capabilities:
            print(f"  Needs: {meta.requirements.interface_capabilities}")
        if meta.references:
            print(f"  References: {meta.references}")

        # Suggest alternatives if unavailable
        if not available:
            alternatives = dependency_resolver.suggest_alternatives(name, registry.get_available_capabilities(interface))
            if alternatives:
                print(f"  Alternatives: {alternatives[:3]}")


def cmd_discover_only(scope: AssessmentScope, output_dir: Optional[str] = None):
    """Run discovery only."""
    print("[*] Running discovery only mode")

    registry = get_global_registry()
    load_all_adapters(registry)

    audit_logger = AuditLogger(log_dir=output_dir or "/tmp/wifi_framework_audit")
    experience_store = ExperienceStore()

    engine = AssessmentEngine(
        scope=scope, registry=registry, audit_logger=audit_logger, experience_store=experience_store
    )

    engine.discover_interfaces()
    engine.discover_capabilities()

    print("\n=== Discovery Summary ===")
    print(f"Interfaces: {len(engine.state.interfaces)}")
    for name, info in engine.state.interfaces.items():
        print(f"  - {name}: type={info.type} driver={info.driver} monitor={info.supports_monitor}")

    print(f"\nAvailable Capabilities: {len(engine.state.available_capabilities)}")
    for name in sorted(engine.state.available_capabilities.keys()):
        print(f"  - {name}")

    print(f"\nUnavailable Capabilities: {len(engine.state.unavailable_capabilities)}")
    for name, reason in engine.state.unavailable_capabilities.items():
        print(f"  - {name}: {reason}")

    # Save discovery report
    report_path = audit_logger.save_report(engine.state)
    print(f"\nDiscovery report saved to: {report_path}")


def main():
    parser = create_parser()
    args = parser.parse_args()

    # Setup registry
    registry = get_global_registry()
    load_all_adapters(registry)

    if args.list_capabilities:
        cmd_list_capabilities(registry, args.interface)
        return

    if args.list_interfaces:
        from ..utils.system import get_interface_list

        print("=== System Interfaces ===")
        for iface in get_interface_list():
            print(f"  - {iface}")
        return

    # Load scope
    scope = load_scope_from_args(args)

    if args.discover_only:
        cmd_discover_only(scope, args.output)
        return

    # Run full assessment
    print(f"[*] Starting assessment with scope: {scope.to_dict()}")
    if not scope.authorized_ssids and not scope.authorized_bssids and not scope.authorized_networks:
        print("[!] WARNING: No authorized scope defined! Running in discovery-only mode with broadcast allowed.")
        print("    For authorized testing, specify --ssid, --bssid, or --network")
        print("    Use --strict to restrict even passive observation")

    audit_logger = AuditLogger(log_dir=args.output or "/tmp/wifi_framework_audit")
    experience_store = ExperienceStore()

    engine = AssessmentEngine(
        scope=scope, registry=registry, audit_logger=audit_logger, experience_store=experience_store
    )

    try:
        final_state = engine.run(
            max_iterations=args.max_iterations, timeout_per_action=args.timeout, auto_discover=True
        )

        print("\n=== Final Assessment Summary ===")
        summary = final_state.summary()
        print(json.dumps(summary, indent=2))

        print(f"\nFindings: {len(final_state.findings)}")
        for finding in final_state.findings:
            print(f"  [{finding.severity.value.upper()}] {finding.title} - {finding.status.value}")

        # Save final report
        report_path = audit_logger.save_report(final_state)
        print(f"\nFinal report saved to: {report_path}")

    except KeyboardInterrupt:
        print("\n[!] Assessment interrupted by user")
        # Save partial report
        try:
            report_path = audit_logger.save_report(engine.state)
            print(f"Partial report saved to: {report_path}")
        except Exception as e:
            print(f"Failed to save partial report: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Assessment failed: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
