#!/usr/bin/env python3
"""
Drive scripts on the remote mac80211_hwsim host.

The dev sandbox cannot load mac80211_hwsim (its kernel is built with
CONFIG_MODULES unset), so wireless verification needs a machine that can. This
wrapper posts a script to the remote host's execution API and prints what came
back.

The endpoint is read from the HWSIM_ENDPOINT environment variable rather than
hardcoded: a tunnel URL is ephemeral and private, and committing one guarantees
a stale secret in git history.

    export HWSIM_ENDPOINT="https://<your-tunnel>.ngrok-free.app"
    python3 scripts/remote_hwsim.py probe
    python3 scripts/remote_hwsim.py run scripts/verify_wireless_hardware.py
    python3 scripts/remote_hwsim.py bootstrap

Commands:
    probe      report the remote kernel, radios and tooling
    run FILE   ship a local file and execute it there
    bootstrap  install this branch on the remote host, then run the
               wireless verification against its virtual radios
"""
from __future__ import annotations

import argparse
import json
import os
import sys

try:
    import requests
except ImportError:  # pragma: no cover
    sys.exit("requests is required: pip install requests")

REPO = "https://github.com/alexland361-eng/WiFi.git"
BRANCH = "arena/01a0ab79-wifi"
TIMEOUT = 300


def endpoint() -> str:
    url = os.environ.get("HWSIM_ENDPOINT", "").strip().rstrip("/")
    if not url:
        sys.exit(
            "HWSIM_ENDPOINT is not set.\n"
            '  export HWSIM_ENDPOINT="https://<your-tunnel>.ngrok-free.app"\n'
            "A bare 'ngrok-free.dev' is a placeholder and will not route."
        )
    return url


def test_code(filename: str, code_string: str) -> int:
    """POST a script to the remote host and print its output. Returns exit code."""
    url = endpoint()
    print(f"--> POST {url}  ({filename}, {len(code_string)} bytes)")
    try:
        response = requests.post(
            url,
            json={"filename": filename, "code": code_string},
            timeout=TIMEOUT,
            headers={"ngrok-skip-browser-warning": "1"},
        )
    except Exception as exc:
        print(f"Connection Error: {type(exc).__name__}: {exc}")
        return 99

    if response.status_code != 200:
        print(f"HTTP {response.status_code}: {response.text[:500]}")
        return 98

    try:
        result = response.json()
    except json.JSONDecodeError:
        print(f"non-JSON response: {response.text[:500]}")
        return 97

    print(f"--- STDOUT ---\n{result.get('stdout', '')}")
    stderr = result.get("stderr", "")
    if stderr:
        print(f"--- STDERR ---\n{stderr}")
    code = result.get("exit_code")
    print(f"Exit Code: {code}")
    return int(code) if code is not None else 96


PROBE = r'''
import os, shutil, subprocess

def sh(c, t=20):
    try:
        p = subprocess.run(c, shell=False, capture_output=True, text=True, timeout=t)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}"

print("uid:", os.geteuid(), "(0 = root)")
print("kernel:", sh(["uname", "-r"])[1])
print("hwsim loaded:", "mac80211_hwsim" in sh(["lsmod"])[1])
rc, out = sh(["iw", "dev"])
print("iw dev (rc=%d):\n%s" % (rc, out or "  (no wireless interfaces)"))
rc, out = sh(["iw", "list"])
print("phys:", [l for l in out.splitlines() if l.startswith("phy#")] or "none")
for b in ("iw", "ip", "airmon-ng", "macchanger", "rfkill", "ethtool", "aireplay-ng", "python3"):
    print(f"  {b:14s} {shutil.which(b) or 'MISSING'}")
print("python:", sh(["python3", "-V"])[1])
print("scapy:", sh(["python3", "-c", "import scapy; print(scapy.__version__)"])[1])
for p in ("/sys/class/ieee80211", "/sys/class/net"):
    rc, out = sh(["ls", p])
    print(f"{p}: {out}")
'''


def bootstrap_script() -> str:
    return f'''
import subprocess, sys, os

def sh(cmd, **kw):
    print("$", " ".join(cmd))
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=900, **kw)
    if p.stdout.strip():
        print(p.stdout.strip()[-4000:])
    if p.stderr.strip():
        print("STDERR:", p.stderr.strip()[-2000:])
    return p.returncode

work = "/root/wifi-verify"
sh(["rm", "-rf", work])
sh(["mkdir", "-p", work])
rc = sh(["git", "clone", "--depth", "1", "--branch", "{BRANCH}", "{REPO}", work])
if rc != 0:
    print("FATAL: could not clone the branch; is the repo reachable and the branch pushed?")
    sys.exit(1)

py = sys.executable
sh([py, "-m", "pip", "install", "--quiet", "pyyaml"], cwd=work)
print("=== radio state before verification ===")
sh(["iw", "dev"])
print("=== running the verification against real virtual radios ===")
rc = sh([py, os.path.join(work, "scripts", "verify_wireless_hardware.py")], cwd=work)
print("VERIFICATION EXIT:", rc)
sys.exit(rc)
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("probe", help="report the remote environment")
    run_p = sub.add_parser("run", help="ship and execute a local file")
    run_p.add_argument("path")
    sub.add_parser("bootstrap", help="install this branch remotely and verify")
    args = parser.parse_args()

    if args.command == "probe":
        return test_code("probe.py", PROBE)
    if args.command == "bootstrap":
        return test_code("bootstrap.py", bootstrap_script())
    with open(args.path) as handle:
        return test_code(os.path.basename(args.path), handle.read())


if __name__ == "__main__":
    sys.exit(main())
