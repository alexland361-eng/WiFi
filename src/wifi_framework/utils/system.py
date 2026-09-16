"""
System utilities - OS, privilege, tool version checks.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from typing import Dict, Optional, Tuple


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
    """Check if network interface exists."""
    try:
        # Check /sys/class/net
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


def run_command(
    cmd: list[str],
    timeout: int = 30,
    check_privileges: bool = False,
) -> Tuple[int, str, str, float]:
    """
    Execute a command and return results.

    Returns (exit_code, stdout, stderr, duration_seconds)
    """
    import time

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = time.time() - start
        return result.returncode, result.stdout, result.stderr, duration
    except subprocess.TimeoutExpired as e:
        duration = time.time() - start
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return 124, stdout, f"Command timed out after {timeout}s: {stderr}", duration
    except FileNotFoundError as e:
        duration = time.time() - start
        return 127, "", f"Command not found: {e}", duration
    except Exception as e:
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
