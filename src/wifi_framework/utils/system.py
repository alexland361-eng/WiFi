"""
System utilities - OS, privilege, tool version checks.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from typing import Dict, Optional, Tuple

from .validation import validate_interface


def get_os_info() -> Dict[str, str]:
    """Get OS information."""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "platform": platform.platform(),
    }


def is_root() -> bool:
    """Check if running as root."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows fallback
        return False


def check_tool_available(tool_binary: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if tool binary is available in PATH.

    Returns (available, path, version_or_error).
    """
    path = shutil.which(tool_binary)
    if not path:
        return False, None, f"Tool '{tool_binary}' not found in PATH"

    # Try to get version
    version = None
    try:
        # Common version flags
        for flag in ["--version", "-v", "version", "-V"]:
            try:
                result = subprocess.run(
                    [tool_binary, flag],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                output = result.stdout + result.stderr
                if output and len(output.strip()) > 0 and "not" not in output.lower()[:100]:
                    # Take first line
                    version = output.strip().split("\n")[0][:200]
                    break
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                continue
    except Exception:
        pass

    return True, path, version


def check_interface_exists(interface: str) -> bool:
    """
    Check whether a network interface exists.

    The name is validated *before* it is interpolated into ``/sys/class/net/{interface}``. Without
    that, ``""``, ``"."`` and ``".."`` all reported a present interface, because the directory
    itself and its parent satisfy ``os.path.exists``. Fourteen call sites gate on this answer -
    including ``InterfaceManager.change_mac``, ``ExecutionAdapter`` preparation and the capability
    checker - so a false positive means an operation proceeds against a path that is not an
    interface, and the caller's "interface does not exist" branch never runs.

    Validating also removes any traversal possibility: a name matching
    ``[a-zA-Z0-9._-]+`` with no empty dot-segment cannot escape ``/sys/class/net``.
    """
    if not validate_interface(interface)[0]:
        return False
    try:
        return os.path.exists(f"/sys/class/net/{interface}")
    except Exception:
        return False


def get_interface_list() -> list[str]:
    """Get list of network interfaces."""
    try:
        net_path = "/sys/class/net"
        if os.path.exists(net_path):
            return os.listdir(net_path)
    except Exception:
        pass
    return []


#: Seconds to wait between SIGTERM and SIGKILL when tearing down a timed-out tool.
TERMINATE_GRACE_SECONDS = 3.0


def terminate_process_group(proc: "subprocess.Popen", grace_seconds: float = TERMINATE_GRACE_SECONDS) -> bool:
    """Signal a process *and its children*, escalating SIGTERM to SIGKILL.

    ``subprocess.run(timeout=...)`` kills only the direct child. A wireless tool
    that spawns helpers - a capture utility, a monitor-mode daemon - therefore
    survives a timeout and keeps holding the radio, which blocks every later
    operation on that interface and can leave it stuck in monitor mode after the
    assessment ends. Starting the child in its own session makes the whole tree
    signalable as one group.

    Returns True if the process was reaped, False if it could not be signalled.
    """
    import os
    import signal

    if proc.poll() is not None:
        return True

    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        return False

    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            # Already gone, or not ours to signal. Nothing further to do.
            return proc.poll() is not None
        try:
            proc.wait(timeout=grace_seconds)
            return True
        except subprocess.TimeoutExpired:
            continue
    return proc.poll() is not None


def run_command(
    cmd: list[str],
    timeout: int = 30,
    check_privileges: bool = False,
    terminate_grace_seconds: float = TERMINATE_GRACE_SECONDS,
) -> Tuple[int, str, str, float]:
    """
    Execute a command and return results.

    The child is started in its own session so that a timeout tears down the whole
    process tree rather than leaving grandchildren running.

    Returns (exit_code, stdout, stderr, duration_seconds). Exit code 124 means the
    timeout elapsed, 127 that the executable was not found.
    """
    import os
    import time

    start = time.time()
    # start_new_session is POSIX-only; the framework targets Linux, but a Windows
    # import must not explode at call time.
    session_kwargs = {"start_new_session": True} if os.name == "posix" else {}
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **session_kwargs,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            terminate_process_group(proc, terminate_grace_seconds)
            # Grandchildren may still hold the pipes open, so bound this too.
            try:
                stdout, stderr = proc.communicate(timeout=terminate_grace_seconds)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
            duration = time.time() - start
            detail = (stderr or "").strip()
            message = f"Command timed out after {timeout}s"
            return 124, stdout or "", f"{message}: {detail}" if detail else message, duration
        duration = time.time() - start
        return proc.returncode, stdout or "", stderr or "", duration
    except FileNotFoundError as e:
        duration = time.time() - start
        return 127, "", f"Command not found: {e}", duration
    except Exception as e:
        if proc is not None:
            terminate_process_group(proc, terminate_grace_seconds)
        duration = time.time() - start
        return 1, "", f"Execution failed: {e}", duration


def parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
    """Parse version string into tuple of ints for comparison."""
    import re

    if not version_str:
        return None
    # Extract numbers
    match = re.search(r"(\d+(?:\.\d+)+)", version_str)
    if not match:
        return None
    try:
        return tuple(int(x) for x in match.group(1).split("."))
    except ValueError:
        return None


def is_version_sufficient(current: str, required: str) -> bool:
    """Check if current version meets required version."""
    curr_tuple = parse_version(current)
    req_tuple = parse_version(required)
    if curr_tuple is None or req_tuple is None:
        # If we can't parse, assume sufficient to avoid false negatives
        return True
    return curr_tuple >= req_tuple
