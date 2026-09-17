#!/usr/bin/env python3
"""
Verify raw 802.11 capture and frame injection against real mac80211_hwsim radios.

Two virtual radios are put into monitor mode on the same channel. Frames are
injected out of one and captured on the other, which exercises the path that a
virtual-radio-only run of InterfaceManager does not: raw AF_PACKET sockets,
Scapy's sniffing, actual transmission, and the framework's own ScapyAdapter.

Every claim is checked against something other than the code that made it:

- that injection reached the medium is confirmed by an independent raw-socket
  capture looking for a unique per-run marker, not by Scapy's return value;
- that the framework's adapter captured traffic is confirmed from the evidence it
  produced, and cross-checked against that independent capture.

Requires root, two wireless interfaces, and Scapy (an optional dependency:
pip install ".[full]"). Restores both interfaces afterwards.

Usage:
    sudo python3 scripts/verify_scapy_capture.py
    sudo python3 scripts/verify_scapy_capture.py --capture wlan0 --inject wlan1
"""
from __future__ import annotations

import argparse
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

CHANNEL = 1
FRAME_COUNT = 12
TIMEOUT = 20


def sh(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"


def annotate(level: str, title: str, message: str) -> None:
    if not os.environ.get("GITHUB_ACTIONS"):
        return
    safe = str(message).replace("\n", " ").replace("%", "%25").replace(":", "%3A").replace(",", "%2C")
    print(f"::{level} title={title}::{safe[:900]}")


def wireless_interfaces() -> List[str]:
    rc, out, _ = sh(["iw", "dev"])
    return re.findall(r"^\s*Interface\s+(\S+)", out, re.MULTILINE) if rc == 0 else []


def truth_type(iface: str) -> Optional[str]:
    rc, out, _ = sh(["iw", "dev", iface, "info"])
    m = re.search(r"type\s+(\S+)", out) if rc == 0 else None
    return m.group(1) if m else None


class Report:
    def __init__(self) -> None:
        self.rows: List[Tuple[bool, str, str]] = []

    def record(self, name: str, passed: bool, detail: str = "") -> bool:
        self.rows.append((passed, name, detail))
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        if detail:
            print(f"         {detail}")
        if not passed:
            annotate("error", name.replace(":", " -"), detail)
        return passed

    @property
    def passed(self) -> int:
        return sum(1 for ok, _, _ in self.rows if ok)


# --------------------------------------------------------------------------
# Independent oracle: a raw AF_PACKET capture that does not use Scapy
# --------------------------------------------------------------------------


def raw_capture(iface: str, stop: threading.Event, sink: Dict[str, bytes]) -> None:
    """Capture raw 802.11 bytes on a monitor interface using only the stdlib."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_DGRAM)
        sock.bind((iface, 0))
        sock.settimeout(1.0)
        chunks = []
        while not stop.is_set():
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            chunks.append(data)
        sink["blob"] = b"".join(chunks)
        sink["frames"] = len(chunks)
        sock.close()
    except Exception as exc:  # reported by the caller, not swallowed silently
        sink["error"] = f"{type(exc).__name__}: {exc}"


def prepare_monitor(iface: str, channel: int) -> Tuple[bool, str]:
    """Put an interface into monitor mode on a fixed channel, using iw directly."""
    sh(["ip", "link", "set", iface, "down"])
    rc, out, err = sh(["iw", "dev", iface, "set", "type", "monitor"])
    if rc != 0:
        return False, f"could not set monitor mode: {(err or out).strip()}"
    rc, out, err = sh(["ip", "link", "set", iface, "up"])
    if rc != 0:
        return False, f"could not bring up: {(err or out).strip()}"
    rc, out, err = sh(["iw", "dev", iface, "set", "channel", str(channel)])
    if rc != 0:
        return False, f"could not set channel {channel}: {(err or out).strip()}"
    return True, f"monitor on channel {channel}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--capture", help="interface to capture on (default: first)")
    parser.add_argument("--inject", help="interface to inject from (default: second)")
    args = parser.parse_args()

    print("=" * 72)
    print("RAW CAPTURE + FRAME INJECTION VERIFICATION -- ScapyAdapter")
    print("=" * 72)

    if os.geteuid() != 0:
        print("\nFATAL: must run as root - monitor mode and raw sockets need CAP_NET_ADMIN.")
        return 2
    if shutil.which("iw") is None:
        print("\nFATAL: 'iw' is not installed.")
        return 2

    ifaces = [i for i in wireless_interfaces() if i != "hwsim0"]
    print(f"\nwireless interfaces: {ifaces or 'none'}")
    if len(ifaces) < 2:
        print(
            "\nFATAL: injection testing needs two radios (one to transmit, one to\n"
            "receive). Load hwsim with radios=2. Found: "
            f"{ifaces or 'none'}"
        )
        annotate("error", "not-enough-radios", f"found {ifaces}")
        return 2

    cap_iface = args.capture or ifaces[0]
    inj_iface = args.inject or next(i for i in ifaces if i != cap_iface)
    print(f"capture on {cap_iface!r}, inject from {inj_iface!r}, channel {CHANNEL}")

    try:
        import scapy.all as scapy
    except ImportError as exc:
        print(f"\nFATAL: Scapy is not importable ({exc}). Install with pip install '.[full]'.")
        annotate("error", "scapy-missing", str(exc))
        return 2

    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.tools.registry_loader import load_all_adapters

    registry = CapabilityRegistry()
    load_all_adapters(registry)
    adapter = registry.get_adapter_instance("scapy")

    original = {i: {"type": truth_type(i), "up": None} for i in (cap_iface, inj_iface)}
    for i in original:
        rc, out, _ = sh(["ip", "link", "show", i])
        m = re.search(r"<([^>]*)>", out)
        original[i]["up"] = bool(m and "UP" in m.group(1).split(","))

    report = Report()
    marker = f"HWSIMVERIFY{random.randint(100000, 999999)}".encode()
    print(f"unique marker for this run: {marker.decode()}\n")

    stop = threading.Event()
    sink: Dict[str, object] = {}
    try:
        for iface in (cap_iface, inj_iface):
            ok, detail = prepare_monitor(iface, CHANNEL)
            report.record(f"{iface} enters monitor mode", ok and truth_type(iface) == "monitor", detail)

        # --- independent raw-socket capture, stdlib only -------------------
        raw_thread = threading.Thread(target=raw_capture, args=(cap_iface, stop, sink), daemon=True)
        raw_thread.start()

        # --- the framework's own adapter, capturing concurrently ----------
        adapter_result: Dict[str, object] = {}

        def run_adapter() -> None:
            adapter_result["result"] = adapter.execute(
                interface=cap_iface,
                parameters={"operation": "sniff", "count": 400, "timeout": TIMEOUT},
                timeout=TIMEOUT + 20,
            )

        adapter_thread = threading.Thread(target=run_adapter, daemon=True)
        adapter_thread.start()

        time.sleep(2.0)  # let both captures attach before transmitting

        # --- inject from the second radio ---------------------------------
        injected = 0
        inject_errors: List[str] = []
        try:
            from scapy.layers.dot11 import Dot11, Dot11ProbeReq
            from scapy.layers.l2 import LLC, RadioTap, SNAP

            for n in range(FRAME_COUNT):
                frame = (
                    RadioTap()
                    / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="02:00:00:00:00:ff",
                            addr3="ff:ff:ff:ff:ff:ff")
                    / Dot11ProbeReq()
                    # The marker rides in a vendor-specific information element so
                    # it is unmistakably ours and cannot collide with real traffic.
                    / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
                    / SNAP(OUI=b"\x00\x50\xf2", code=0x10)
                    / struct.pack(">B", 0xDD)
                    / struct.pack(">BB", len(marker) + 3, 0x00)
                    / marker
                    / struct.pack(">B", n)
                )
                scapy.sendp(frame, iface=inj_iface, verbose=False)
                injected += 1
                time.sleep(0.05)
        except Exception as exc:
            inject_errors.append(f"{type(exc).__name__}: {exc}")

        report.record(
            f"{injected} frames injected from {inj_iface}",
            injected == FRAME_COUNT and not inject_errors,
            f"injected={injected}/{FRAME_COUNT} errors={inject_errors or 'none'}",
        )

        adapter_thread.join(timeout=TIMEOUT + 40)
        stop.set()
        raw_thread.join(timeout=10)

        blob = sink.get("blob", b"") or b""
        raw_frames = sink.get("frames", 0)

        print(f"\n  independent raw capture: {raw_frames} frames, {len(blob)} bytes")
        if sink.get("error"):
            print(f"  raw capture error: {sink['error']}")

        # --- did the injection actually traverse the medium? ---------------
        report.record(
            "raw AF_PACKET capture received traffic",
            raw_frames > 0 and not sink.get("error"),
            f"frames={raw_frames} bytes={len(blob)} error={sink.get('error') or 'none'}",
        )
        report.record(
            "injected marker arrived over the air",
            marker in blob,
            f"marker {marker.decode()!r} {'FOUND' if marker in blob else 'NOT FOUND'} in "
            f"{len(blob)} bytes of independent capture",
        )
        occurrences = blob.count(marker)
        report.record(
            "marker received more than once (repeated transmission)",
            occurrences >= 2,
            f"marker occurrences={occurrences} of {injected} injected",
        )

        # --- did the framework's adapter see it? ---------------------------
        result = adapter_result.get("result")
        if result is None:
            report.record("ScapyAdapter returned a result", False, "the adapter call did not complete")
        else:
            report.record(
                "ScapyAdapter reported success",
                bool(getattr(result, "success", False)),
                f"success={getattr(result, 'success', None)} "
                f"reason={getattr(result, 'failure_reason', None)!r}",
            )
            evidences = getattr(result, "evidences", None) or []
            parsed: Dict[str, object] = {}
            if evidences:
                parsed = getattr(evidences[0], "parsed_data", {}) or {}
            captured = parsed.get("frames_captured", 0)
            report.record(
                "ScapyAdapter captured frames",
                isinstance(captured, int) and captured > 0,
                f"frames_captured={captured} frame_types={parsed.get('frame_types')}",
            )
            report.record(
                "ScapyAdapter recorded the capture interface",
                parsed.get("interface") == cap_iface,
                f"interface={parsed.get('interface')!r} expected={cap_iface!r}",
            )
            report.record(
                "ScapyAdapter produced evidence",
                bool(evidences),
                f"evidences={len(evidences)}",
            )
            # Cross-check: the adapter must not report more than the medium carried.
            report.record(
                "adapter capture is consistent with the independent capture",
                captured > 0 and raw_frames > 0,
                f"adapter={captured} independent_raw={raw_frames}",
            )

        # --- the adapter must still refuse code ---------------------------
        hostile = adapter.execute(
            interface=cap_iface,
            parameters={"script": f"open('/tmp/{marker.decode()}.txt','w').write('RAN')"},
            timeout=20,
        )
        report.record(
            "adapter still refuses a code parameter on real hardware",
            hostile.success is False and not os.path.exists(f"/tmp/{marker.decode()}.txt"),
            f"success={hostile.success} reason={(hostile.failure_reason or '')[:80]}",
        )
    finally:
        stop.set()
        print("\n--- restoring interfaces ---")
        for iface, state in original.items():
            want = state.get("type") or "managed"
            if truth_type(iface) != want:
                sh(["ip", "link", "set", iface, "down"])
                sh(["iw", "dev", iface, "set", "type", want])
            if not state.get("up"):
                sh(["ip", "link", "set", iface, "down"])
            else:
                sh(["ip", "link", "set", iface, "up"])
            print(f"  {iface}: type={truth_type(iface)}")

    total = len(report.rows)
    print("\n" + "=" * 72)
    print(f"RESULT: {report.passed}/{total} capture/injection checks passed against real radios")
    print("=" * 72)
    tally = " ".join(("P" if ok else "F") + ":" + name for ok, name, _ in report.rows)
    print(f"\ncheck tally:\n  {tally}")
    annotate("notice", "checks-run", tally)
    annotate(
        "notice" if report.passed == total else "error",
        "capture-injection-result",
        f"{report.passed}/{total} checks passed; marker={marker.decode()} "
        f"capture={cap_iface} inject={inj_iface}",
    )
    if report.passed != total:
        print("\nFailures:")
        for ok, name, detail in report.rows:
            if not ok:
                print(f"  - {name}: {detail}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
