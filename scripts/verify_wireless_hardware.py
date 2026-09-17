#!/usr/bin/env python3
"""
Verify InterfaceManager against a real wireless radio.

This is an integration check, not a unit test. It drives the actual
InterfaceManager against a real 802.11 interface -- a mac80211_hwsim virtual
radio in CI, or a physical adapter on a Kali box -- and confirms each claimed
result independently.

The independence is the point. InterfaceManager returns (success, message)
tuples built from exit codes and scraped stdout. Trusting those would only
prove that the module agrees with itself. So every check here re-reads the
outcome from a source the framework does not control: `iw dev <if> info`,
`ip link`, /sys/class/net/<if>/address, `rfkill list`. A method that reports
success without changing the radio is recorded as a failure.

Requires root (it changes MAC addresses, interface types and link state) and a
wireless interface. Restores the interface to its original state afterwards.

Usage:
    sudo python3 scripts/verify_wireless_hardware.py
    sudo python3 scripts/verify_wireless_hardware.py --interface wlan0
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import traceback
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

# Allow running from a source checkout without installation.
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

TIMEOUT = 15

# Job logs and artifacts live in blob storage that is not reachable from every
# environment reading CI results. When running under Actions, findings are also
# emitted as annotations, which the check-run API does return.
_IN_CI = bool(os.environ.get("GITHUB_ACTIONS"))


def annotate(level: str, title: str, message: str) -> None:
    """Emit a GitHub Actions annotation. No-op outside CI."""
    if not _IN_CI:
        return
    # Annotation values are single-line; newlines must be escaped.
    safe = str(message).replace("\n", " ").replace("\r", " ").replace("%", "%25")
    safe = safe.replace(":", "%3A").replace(",", "%2C")
    print(f"::{level} title={title}::{safe[:900]}")



# --------------------------------------------------------------------------
# Independent oracle. Deliberately does not use framework helpers.
# --------------------------------------------------------------------------


def sh(cmd: List[str], timeout: int = TIMEOUT) -> Tuple[int, str, str]:
    """Run a command list, never a shell string. Returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout if isinstance(exc.stdout, str) else ""
        return 124, partial or "", f"timed out after {timeout}s"


def wireless_interfaces() -> List[str]:
    """Enumerate wireless interfaces via `iw dev` (authoritative, nl80211)."""
    rc, out, _ = sh(["iw", "dev"])
    if rc != 0:
        return []
    return re.findall(r"^\s*Interface\s+(\S+)", out, re.MULTILINE)


def truth_type(iface: str) -> Optional[str]:
    rc, out, _ = sh(["iw", "dev", iface, "info"])
    if rc != 0:
        return None
    m = re.search(r"type\s+(\S+)", out)
    return m.group(1) if m else None


def truth_mac(iface: str) -> Optional[str]:
    path = f"/sys/class/net/{iface}/address"
    try:
        with open(path) as handle:
            return handle.read().strip().upper()
    except OSError:
        return None


def truth_is_up(iface: str) -> Optional[bool]:
    rc, out, _ = sh(["ip", "link", "show", iface])
    if rc != 0:
        return None
    m = re.search(r"<([^>]*)>", out)
    return bool(m and "UP" in m.group(1).split(","))


def truth_channel(iface: str) -> Optional[int]:
    rc, out, _ = sh(["iw", "dev", iface, "info"])
    if rc != 0:
        return None
    m = re.search(r"channel\s+(\d+)", out)
    return int(m.group(1)) if m else None


def truth_rfkill_blocked() -> Optional[bool]:
    """True if any wlan device is soft- or hard-blocked."""
    rc, out, _ = sh(["rfkill", "list"])
    if rc != 0:
        return None
    blocked = re.findall(r"(Soft|Hard) blocked:\s*(yes)", out, re.IGNORECASE)
    return bool(blocked)


def is_locally_administered(mac: str) -> bool:
    """The local bit (bit 1 of the first octet) must be set for a spoofed MAC."""
    try:
        first = int(mac.replace(":", "").replace("-", "")[:2], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02) and not (first & 0x01)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str
    claimed: str = ""
    observed: str = ""


@dataclass
class Report:
    results: List[CheckResult] = field(default_factory=list)

    def record(self, name: str, passed: bool, detail: str, claimed: str = "", observed: str = "") -> bool:
        self.results.append(CheckResult(name, passed, detail, claimed, observed))
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {name}")
        if detail:
            print(f"         {detail}")
        if not passed:
            if claimed:
                print(f"         framework claimed: {claimed}")
            if observed:
                print(f"         independently observed: {observed}")
            annotate(
                "error",
                name.replace(":", " -"),
                f"claimed=[{claimed}] observed=[{observed}] detail=[{detail}]",
            )
        return passed


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

TARGET_MAC = "02:00:00:00:00:AA"  # locally administered, unicast


def check_list_interfaces(im, iface: str, report: Report) -> None:
    found = im.list_interfaces()
    report.record(
        "list_interfaces includes the wireless interface",
        iface in found,
        f"returned {found}",
        claimed=str(found),
        observed=f"{iface} {'present' if iface in found else 'ABSENT'}",
    )


def check_get_interface_info(im, iface: str, report: Report) -> None:
    info = im.get_interface_info(iface)
    if info is None:
        report.record("get_interface_info returns data", False, "returned None for an existing interface")
        return

    report.record(
        "get_interface_info returns data",
        True,
        f"type={info.type!r} mac={info.mac!r} is_up={info.is_up} "
        f"supports_monitor={info.supports_monitor} supports_injection={info.supports_injection}",
    )

    # MAC must match what the kernel reports.
    real_mac = truth_mac(iface)
    reported_mac = (info.mac or "").upper()
    report.record(
        "get_interface_info MAC matches the kernel",
        real_mac is not None and reported_mac == real_mac,
        f"reported={reported_mac!r} kernel={real_mac!r}",
        claimed=reported_mac,
        observed=str(real_mac),
    )

    # Type must be a real 802.11 type, not the "unknown" default.
    real_type = truth_type(iface)
    report.record(
        "get_interface_info detects the interface type",
        info.type == real_type and real_type is not None,
        f"reported={info.type!r} kernel={real_type!r}",
        claimed=info.type,
        observed=str(real_type),
    )


def check_up_down(im, iface: str, report: Report) -> None:
    ok, msg = im.set_interface_down(iface)
    observed = truth_is_up(iface)
    report.record(
        "set_interface_down actually lowers the link",
        ok is True and observed is False,
        f"returned ({ok}, {msg!r})",
        claimed=f"success={ok}",
        observed=f"link up={observed}",
    )

    ok, msg = im.set_interface_up(iface)
    observed = truth_is_up(iface)
    report.record(
        "set_interface_up actually raises the link",
        ok is True and observed is True,
        f"returned ({ok}, {msg!r})",
        claimed=f"success={ok}",
        observed=f"link up={observed}",
    )


def check_change_mac(im, iface: str, report: Report) -> None:
    if shutil.which("macchanger") is None:
        report.record("change_mac to an explicit address", False, "macchanger not installed; cannot exercise this path")
        report.record("change_mac randomisation", False, "macchanger not installed; cannot exercise this path")
        return

    ok, msg, new_mac = im.change_mac(iface, mac=TARGET_MAC)
    observed = truth_mac(iface)
    report.record(
        "change_mac to an explicit address",
        ok is True and observed == TARGET_MAC,
        f"returned ({ok}, {msg!r}, {new_mac!r})",
        claimed=f"success={ok} new_mac={new_mac}",
        observed=f"kernel MAC={observed}",
    )
    if new_mac and observed and new_mac.upper() != observed:
        report.record(
            "change_mac reports the MAC it actually set",
            False,
            "the returned MAC does not match the address now on the interface",
            claimed=new_mac,
            observed=observed,
        )

    before = truth_mac(iface)
    ok, msg, new_mac = im.change_mac(iface, random=True)
    observed = truth_mac(iface)
    changed = observed is not None and before is not None and observed != before
    report.record(
        "change_mac randomisation",
        ok is True and changed and is_locally_administered(observed or ""),
        f"returned ({ok}, {msg!r}, {new_mac!r}); before={before} after={observed}",
        claimed=f"success={ok} new_mac={new_mac}",
        observed=f"kernel MAC={observed} locally_administered={is_locally_administered(observed or '')}",
    )


def check_channel(im, iface: str, report: Report) -> None:
    # Channel control is a monitor-mode operation: on a managed interface
    # cfg80211 ties the channel to the associated BSS and refuses to set it.
    # The interface must also be up, or `iw dev <if> info` reports no channel
    # and a genuine success would read back as None.
    im.set_interface_up(iface)
    mode = truth_type(iface)
    print(f"  (channel checks against {iface} in {mode!r} mode, up={truth_is_up(iface)})")

    supported = im.get_supported_channels(iface)
    report.record(
        "get_supported_channels returns channels",
        bool(supported),
        f"returned {supported[:12]}{'...' if len(supported) > 12 else ''} ({len(supported)} total)",
    )
    if not supported:
        # Distinguish "the parser missed them" from "iw list produced nothing".
        rc, out, err = sh(["iw", "list"])
        sample = " | ".join((out or err).splitlines()[:6])
        annotate(
            "error",
            "iw-list-diagnostic",
            f"get_supported_channels returned [] ; iw list rc={rc} first lines: {sample[:600]}",
        )

    # Channels 1, 6 and 11 are always valid 2.4 GHz; hwsim supports them.
    for channel in (1, 6, 11):
        ok, msg = im.set_channel(iface, channel)
        observed = truth_channel(iface)
        report.record(
            f"set_channel({channel}) takes effect",
            ok is True and observed == channel,
            f"returned ({ok}, {msg!r}) in mode {mode!r}",
            claimed=f"success={ok} message={msg!r}",
            observed=f"kernel channel={observed}",
        )


def check_monitor(im, iface: str, report: Report) -> str:
    """Enter monitor mode and verify it. Returns the monitor interface name."""
    ok, msg, mon_iface = im.create_monitor_interface(iface)

    # Monitor mode may land on a new interface (airmon-ng) or on the original (iw).
    candidates = [c for c in {mon_iface, iface} if c]
    monitor_found = None
    for candidate in candidates:
        if truth_type(candidate) == "monitor":
            monitor_found = candidate
            break

    report.record(
        "create_monitor_interface produces a real monitor interface",
        ok is True and monitor_found is not None,
        f"returned ({ok}, {msg!r}, {mon_iface!r})",
        claimed=f"success={ok} monitor_interface={mon_iface}",
        observed=(
            f"type({monitor_found})=monitor"
            if monitor_found
            else "; ".join(f"type({c})={truth_type(c)!r}" for c in candidates),
        ),
    )

    target = monitor_found or mon_iface or iface

    # A monitor interface must now be detectable as such by the framework.
    if monitor_found:
        info = im.get_interface_info(monitor_found)
        reported = info.type if info else None
        report.record(
            "framework recognises the monitor interface as monitor",
            reported == "monitor",
            f"get_interface_info({monitor_found}).type={reported!r}",
            claimed=str(reported),
            observed=f"kernel type={truth_type(monitor_found)!r}",
        )

    return target


def check_monitor_teardown(im, target: str, iface: str, report: Report) -> None:
    ok, msg = im.remove_monitor_interface(target, iface)
    still_monitor = truth_type(target) == "monitor"
    report.record(
        "remove_monitor_interface tears monitor mode down",
        ok is True and not still_monitor,
        f"returned ({ok}, {msg!r})",
        claimed=f"success={ok}",
        observed=f"type({target})={truth_type(target)!r}",
    )


def check_rfkill(im, report: Report) -> None:
    if shutil.which("rfkill") is None:
        report.record("unblock_rfkill clears blocks", False, "rfkill not installed; cannot exercise this path")
        return
    ok, msg = im.unblock_rfkill()
    blocked = truth_rfkill_blocked()
    report.record(
        "unblock_rfkill clears blocks",
        ok is True and blocked is False,
        f"returned ({ok}, {msg!r})",
        claimed=f"success={ok}",
        observed=f"any wlan blocked={blocked}",
    )


def check_rejects_absent_interface(im, report: Report) -> None:
    """Negative control: a nonexistent interface must not be reported as usable."""
    ghost = "wlan_does_not_exist_99"
    info = im.get_interface_info(ghost)
    ok_up, _ = im.set_interface_up(ghost)
    ok_mon, _, _ = im.create_monitor_interface(ghost)
    report.record(
        "nonexistent interface is refused",
        info is None and ok_up is False and ok_mon is False,
        f"get_interface_info={info!r} set_interface_up={ok_up} create_monitor_interface={ok_mon}",
    )


# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------


def describe_environment() -> bool:
    print("=" * 72)
    print("WIRELESS HARDWARE VERIFICATION -- InterfaceManager")
    print("=" * 72)

    if os.geteuid() != 0:
        print("\nFATAL: must run as root -- MAC, type and link-state changes need CAP_NET_ADMIN.")
        return False

    for binary in ("iw", "ip"):
        if shutil.which(binary) is None:
            print(f"\nFATAL: required tool {binary!r} is not installed.")
            return False

    rc, out, err = sh(["uname", "-r"])
    out_kernel = out.strip()
    print(f"\nkernel: {out_kernel}")

    rc, out, _ = sh(["lsmod"])
    hwsim = "mac80211_hwsim" in out
    print(f"mac80211_hwsim loaded: {hwsim}")

    rc, out, _ = sh(["iw", "list"])
    phys = re.findall(r"^phy#(\d+)", out, re.MULTILINE)
    print(f"physical devices (phy): {phys or 'none'}")

    ifaces = wireless_interfaces()
    print(f"wireless interfaces: {ifaces or 'none'}")
    annotate("notice", "radios", f"kernel={out_kernel} hwsim={hwsim} phys={phys} interfaces={ifaces}")

    for iface in ifaces:
        detail = (
            f"type={truth_type(iface)} mac={truth_mac(iface)} "
            f"up={truth_is_up(iface)} channel={truth_channel(iface)}"
        )
        print(f"  {iface}: {detail}")
        annotate("notice", f"iface-{iface}", detail)

    if not ifaces:
        print(
            "\nFATAL: no wireless interface exists. The kernel has no usable 802.11 radio,\n"
            "so InterfaceManager cannot be verified. Diagnostics follow.\n"
        )
        for cmd in (["lsmod"], ["dmesg"], ["iw", "list"]):
            rc, out, err = sh(cmd, timeout=10)
            tail = (out + err).strip().splitlines()[-15:]
            print(f"--- {' '.join(cmd)} (rc={rc}) ---")
            for line in tail:
                print(f"    {line}")
        return False
    return True


def restore(iface: str, original: dict) -> None:
    print("\n--- restoring original interface state ---")
    if original.get("mon_created") and original["mon_created"] != iface:
        sh(["iw", "dev", original["mon_created"], "del"])
        print(f"  deleted {original['mon_created']}")

    if original.get("type") and truth_type(iface) != original["type"]:
        sh(["ip", "link", "set", iface, "down"])
        sh(["iw", "dev", iface, "set", "type", original["type"]])
        print(f"  type -> {original['type']}")

    if original.get("mac") and truth_mac(iface) != original["mac"]:
        if shutil.which("macchanger"):
            sh(["ip", "link", "set", iface, "down"])
            sh(["macchanger", "-m", original["mac"].lower(), iface])
        else:
            sh(["ip", "link", "set", iface, "down"])
            sh(["ip", "link", "set", iface, "address", original["mac"].lower()])
        print(f"  mac -> {original['mac']}")

    if original.get("up"):
        sh(["ip", "link", "set", iface, "up"])
        print("  link -> up")
    print(f"  final: type={truth_type(iface)} mac={truth_mac(iface)} up={truth_is_up(iface)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--interface", help="wireless interface to exercise (default: first found)")
    args = parser.parse_args()

    if not describe_environment():
        return 2

    ifaces = wireless_interfaces()
    iface = args.interface or next((i for i in ifaces if i != "hwsim0"), ifaces[0])
    if iface not in ifaces:
        print(f"\nFATAL: {iface!r} is not a wireless interface. Available: {ifaces}")
        return 2

    from wifi_framework.core.execution.interface_manager import InterfaceManager
    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.core.execution.tool_manager import ToolManager

    registry = CapabilityRegistry()
    tool_manager = ToolManager(registry)
    im = InterfaceManager(tool_manager)

    original = {
        "mac": truth_mac(iface),
        "type": truth_type(iface),
        "up": truth_is_up(iface),
        "mon_created": None,
    }
    print(f"\nexercising InterfaceManager against {iface!r}")
    print(f"original state: {original}\n")

    report = Report()

    def run_check(name: str, fn: Callable[[], None]) -> None:
        """Run one check, recording a crash as a failure instead of aborting.

        A harness that stops at the first exception reports only the checks that
        happened to come before it, which hides both later defects and the crash
        itself.
        """
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - isolation is the point
            tb = traceback.format_exc(limit=8)
            print(f"  [ERROR] {name} raised {type(exc).__name__}: {exc}")
            print(tb)
            annotate("error", f"check crashed - {name}", f"{type(exc).__name__}: {exc}")
            report.record(f"{name} raised {type(exc).__name__}", False, str(exc)[:300])

    def note_monitor_interface() -> None:
        # Record which interface monitor mode landed on, for teardown.
        for candidate in [c for c in os.listdir("/sys/class/net") if c.endswith("mon")]:
            original["mon_created"] = candidate
            break
        if original["mon_created"] is None and truth_type(iface) == "monitor":
            original["mon_created"] = iface

    monitor_target = {"iface": iface}

    def do_monitor() -> None:
        monitor_target["iface"] = check_monitor(im, iface, report)

    def do_channel() -> None:
        # Runs while still in monitor mode: channel control is rejected on a
        # managed interface, so testing it after teardown measures nothing.
        check_channel(im, monitor_target["iface"], report)

    def do_teardown() -> None:
        note_monitor_interface()
        check_monitor_teardown(im, monitor_target["iface"], iface, report)

    try:
        run_check("list_interfaces", lambda: check_list_interfaces(im, iface, report))
        run_check("get_interface_info", lambda: check_get_interface_info(im, iface, report))
        run_check("rejects_absent_interface", lambda: check_rejects_absent_interface(im, report))
        run_check("up_down", lambda: check_up_down(im, iface, report))
        run_check("rfkill", lambda: check_rfkill(im, report))
        run_check("change_mac", lambda: check_change_mac(im, iface, report))
        run_check("monitor", do_monitor)
        run_check("channel", do_channel)
        run_check("monitor_teardown", do_teardown)
    finally:
        try:
            restore(iface, original)
        except Exception as exc:  # noqa: BLE001
            print(f"  [ERROR] restore failed: {type(exc).__name__}: {exc}")
            annotate("error", "state restoration failed", f"{type(exc).__name__}: {exc}")

    passed = sum(1 for r in report.results if r.passed)
    failed = [r for r in report.results if not r.passed]

    print("\n" + "=" * 72)
    print(f"RESULT: {passed}/{len(report.results)} checks passed against a real radio")
    print("=" * 72)
    tally = " ".join(("P" if r.passed else "F") + ":" + r.name for r in report.results)
    print(f"\ncheck tally:\n  {tally}")
    annotate("notice", "checks-run", tally)
    annotate(
        "notice" if not failed else "error",
        "verification-result",
        f"{passed}/{len(report.results)} checks passed on {iface}"
        + ("" if not failed else "; failed: " + ", ".join(r.name for r in failed)),
    )
    if failed:
        print("\nFailures:")
        for result in failed:
            print(f"  - {result.name}")
            print(f"      claimed:  {result.claimed or result.detail}")
            if result.observed:
                print(f"      observed: {result.observed}")
        print(
            "\nThese are mismatches between what InterfaceManager reported and what the\n"
            "kernel actually did. They are real defects, not environment noise."
        )
        return 1
    print("\nEvery claim InterfaceManager made was confirmed by the kernel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
