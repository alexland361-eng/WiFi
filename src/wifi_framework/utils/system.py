"""
System utilities - OS, privilege, tool version checks.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from typing import Dict, List, Optional, Sequence, Set, Tuple

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


#: Linux capability bit numbers, from ``include/uapi/linux/capability.h``. Verified
#: against the header installed on the development machine rather than recalled:
#: CAP_NET_ADMIN=12, CAP_NET_RAW=13, CAP_SETFCAP=31, CAP_PERFMON=38.
#:
#: These are an ABI, not an implementation detail - the kernel exposes them as bit
#: positions in ``/proc/<pid>/status`` and they have never been renumbered, because
#: renumbering would break every setuid binary on Linux.
CAPABILITY_BITS: Dict[str, int] = {
    "cap_chown": 0,
    "cap_dac_override": 1,
    "cap_dac_read_search": 2,
    "cap_fowner": 3,
    "cap_fsetid": 4,
    "cap_kill": 5,
    "cap_setgid": 6,
    "cap_setuid": 7,
    "cap_setpcap": 8,
    "cap_linux_immutable": 9,
    "cap_net_bind_service": 10,
    "cap_net_broadcast": 11,
    "cap_net_admin": 12,
    "cap_net_raw": 13,
    "cap_ipc_lock": 14,
    "cap_ipc_owner": 15,
    "cap_sys_module": 16,
    "cap_sys_rawio": 17,
    "cap_sys_chroot": 18,
    "cap_sys_ptrace": 19,
    "cap_sys_pacct": 20,
    "cap_sys_admin": 21,
    "cap_sys_boot": 22,
    "cap_sys_nice": 23,
    "cap_sys_resource": 24,
    "cap_sys_time": 25,
    "cap_sys_tty_config": 26,
    "cap_mknod": 27,
    "cap_lease": 28,
    "cap_audit_write": 29,
    "cap_audit_control": 30,
    "cap_setfcap": 31,
    "cap_mac_override": 32,
    "cap_mac_admin": 33,
    "cap_syslog": 34,
    "cap_wake_alarm": 35,
    "cap_block_suspend": 36,
    "cap_audit_read": 37,
    "cap_perfmon": 38,
    "cap_bpf": 39,
    "cap_checkpoint_restore": 40,
}

#: ``privileges`` in capability metadata means "root", which the framework has
#: always honoured. Fine-grained tokens let a capability say what it actually
#: needs: ``iw dev wlan0 set type monitor`` requires CAP_NET_ADMIN, not full root,
#: and a raw-socket injection test requires CAP_NET_RAW.
ROOT_PRIVILEGE = "root"


def normalize_privilege_token(token: str) -> Optional[str]:
    """Canonical ``cap_*`` spelling of a privilege token, or ``None`` if unknown.

    ``core/models/capability.py`` documents the ``privileges`` list as
    "e.g. root, net_admin" - the bare spelling. Both ``net_admin`` and
    ``cap_net_admin`` are accepted so a capability declaration written to the
    documented example works; anything else is unknown and must fail closed.
    """
    if not isinstance(token, str):
        return None
    name = token.strip().lower()
    if not name:
        return None
    if name == ROOT_PRIVILEGE:
        return ROOT_PRIVILEGE
    if name in CAPABILITY_BITS:
        return name
    prefixed = f"cap_{name}"
    if prefixed in CAPABILITY_BITS:
        return prefixed
    return None


def decode_capability_mask(mask: int) -> Set[str]:
    """Decode a ``Cap*`` hex mask from ``/proc/<pid>/status`` into capability names.

    Separated from :func:`effective_capabilities` so the bit arithmetic can be
    tested directly: an unprivileged test process has ``CapEff`` 0, which decodes
    correctly but exercises none of the table.
    """
    if not isinstance(mask, int) or mask < 0:
        return set()
    return {name for name, bit in CAPABILITY_BITS.items() if mask & (1 << bit)}


def effective_capabilities() -> Set[str]:
    """The Linux capabilities this process actually holds, lower-cased names.

    Reads the ``CapEff`` mask from ``/proc/self/status``. Returns an empty set on
    platforms without that file - an empty set is the honest answer, and every
    consumer treats "capability not held" as a refusal rather than an exception.

    A root process holds the full set, so callers need not special-case root when
    they ask about a capability; they must still special-case it when the metadata
    demands ``root`` specifically, which :func:`satisfies_privileges` does.
    """
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    return decode_capability_mask(int(line.split(":", 1)[1].strip(), 16))
    except (OSError, ValueError, IndexError):
        return set()
    return set()


def has_capability(name: str) -> bool:
    """Whether this process holds a single capability.

    An unknown capability name is never held. Guessing would turn a typo in a
    capability declaration into a silently satisfied requirement.
    """
    if not isinstance(name, str):
        return False
    canonical = normalize_privilege_token(name)
    if canonical is None or canonical == ROOT_PRIVILEGE:
        return False
    return canonical in effective_capabilities()


def satisfies_privileges(required: Sequence[str]) -> Tuple[bool, str]:
    """Whether the current process satisfies a capability's ``privileges`` list.

    ``root`` keeps its strict meaning - the uid must be 0. Loosening it to "root or
    the relevant capabilities" would weaken a control on 19 capabilities at once,
    on the strength of an assumption about what each tool needs; a tool declared as
    needing root may need it for reasons beyond network administration.
    Fine-grained tokens are the way to express a narrower requirement.

    An unrecognised token fails closed. A privilege requirement the framework
    cannot evaluate must refuse, because passing it would mean executing a
    privileged action on the strength of a declaration nobody checked.

    Returns (satisfied, reason). ``reason`` is empty when satisfied.

    A shortfall is prefixed with the literal token ``insufficient_privileges``,
    which both :mod:`core.execution.gateway` and ``ToolAdapterBase`` already map to
    ``FailureCategory.INSUFFICIENT_PRIVILEGES``. The rest of the message states what
    is required *and* what the process actually holds, so an operator running with
    CAP_NET_ADMIN but not root sees the real state instead of a bare "not root".
    An unrecognised token deliberately carries no such prefix: a broken declaration
    is a tool error, not a privilege shortfall, and must not be reported as
    something the operator can fix by elevating.
    """
    if not required:
        return True, ""

    held = effective_capabilities()
    missing: List[str] = []
    for token in required:
        if not isinstance(token, str) or not token.strip():
            missing.append(repr(token))
            continue
        canonical = normalize_privilege_token(token)
        if canonical == ROOT_PRIVILEGE:
            if not is_root():
                missing.append(ROOT_PRIVILEGE)
        elif canonical is not None:
            if canonical not in held:
                missing.append(canonical)
        else:
            # Unknown requirement: refuse, and say so explicitly rather than
            # folding it into "missing" as though it were a real capability.
            return False, (
                f"unrecognised privilege requirement '{token}'; refusing rather than "
                "assuming it is satisfied"
            )

    if not missing:
        return True, ""
    summary = ", ".join(sorted(held)) if held else "none"
    return False, (
        f"insufficient_privileges: requires {', '.join(missing)}; "
        f"this process holds: {summary}"
    )


def check_tool_available(tool_binary: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if tool binary is available in PATH.

    Returns (available, path, version_or_error).
    """
    path = resolve_binary(tool_binary)
    if not path:
        return False, None, describe_unresolved(tool_binary)

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


def resolve_binary(
    tool_binary: str,
    *,
    allowed_dirs: Optional[Tuple[str, ...]] = None,
) -> Optional[str]:
    """Resolve a tool name to the absolute path that will actually be executed.

    Checking with :func:`shutil.which` and then executing the bare *name* leaves a
    gap between the two: ``PATH`` can change, or a writable directory earlier in it
    can gain an executable of the same name, so the binary that runs is not the one
    that was checked. Resolution and execution must name the same file, so callers
    resolve once and hand the returned path to :mod:`subprocess`.

    Resolution rules:

    * an absolute path is honoured if it exists and is executable - the caller
      deliberately named a file, as the process-supervision tests do with a
      temporary script;
    * a name containing a path separator that is *not* absolute is refused.
      :func:`shutil.which` treats such a name as relative to the working
      directory, so a capability declaration or a tool parameter (the Impacket
      adapter derives its command name from ``parameters["impacket_tool"]``)
      could select a file planted in the cwd instead of an installed binary.
      Every ``tool_binary`` declared in the source tree is a bare name;
    * a bare name is resolved against ``PATH``, and the result must be executable.

    ``allowed_dirs``, when given, restricts the search to those directories: a
    caller that wants to pin the framework to a known toolchain says so here, and
    a same-named binary in an unpinned directory earlier on ``PATH`` is not found
    rather than found and then rejected. The default is unrestricted, matching the
    previous behaviour.

    Returns the absolute path, or ``None`` if the name is unusable. Callers that
    need to explain a ``None`` should use :func:`describe_unresolved`.
    """
    if not isinstance(tool_binary, str):
        return None
    name = tool_binary.strip()
    if not name or "\x00" in name or any(char.isspace() for char in name):
        return None

    separators = {os.sep} | ({os.altsep} if os.altsep else set())
    has_separator = any(sep in name for sep in separators)

    if has_separator:
        if not os.path.isabs(name):
            return None
        candidate = os.path.abspath(name)
        if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
            return None
    else:
        search_path = os.pathsep.join(allowed_dirs) if allowed_dirs else None
        candidate = shutil.which(name, path=search_path)
        if not candidate:
            return None

    if allowed_dirs:
        # Covers the absolute-path branch too: naming a file directly must not
        # bypass a pin the caller asked for.
        resolved_dir = os.path.dirname(os.path.realpath(candidate))
        permitted = {os.path.realpath(directory) for directory in allowed_dirs}
        if resolved_dir not in permitted:
            return None
    return candidate


def describe_unresolved(tool_binary: str) -> str:
    """Why :func:`resolve_binary` returned ``None`` for this name.

    Reporting "not installed or not on PATH" for a name the resolver refused on
    shape grounds would send an operator looking for a missing package when the
    real problem is a malformed declaration.
    """
    if not isinstance(tool_binary, str) or not tool_binary.strip():
        return "tool binary name is empty"
    separators = {os.sep} | ({os.altsep} if os.altsep else set())
    if any(sep in tool_binary for sep in separators) and not os.path.isabs(tool_binary):
        return (
            f"tool name '{tool_binary}' contains a path separator but is not absolute; "
            "relative paths are refused so a declaration or parameter cannot select a "
            "file planted in the working directory"
        )
    if os.path.isabs(tool_binary) and not (os.path.isfile(tool_binary) and os.access(tool_binary, os.X_OK)):
        return f"Tool path '{tool_binary}' is not an executable file"
    # Wording is load-bearing: the gateway classifies failure reasons by substring,
    # and "not found in PATH" is the token that maps to TOOL_NOT_FOUND. Rephrasing
    # this would silently downgrade a missing-tool refusal to a generic tool error.
    return f"Tool '{tool_binary}' not found in PATH"


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

    ``cmd[0]`` is resolved to an absolute path *here*, immediately before the
    spawn, and that path is what is executed - see :func:`resolve_binary`. Passing
    a bare name to ``Popen`` would re-resolve it against ``PATH`` inside the
    kernel's search, so a binary swapped in after the availability check could run
    instead of the one that was checked.

    Returns (exit_code, stdout, stderr, duration_seconds). Exit code 124 means the
    timeout elapsed, 127 that the executable was not found or was refused.
    """
    import os
    import time

    start = time.time()
    if not cmd:
        return 127, "", "Command not found: empty command", time.time() - start
    resolved = resolve_binary(str(cmd[0]))
    if resolved is None:
        return 127, "", describe_unresolved(str(cmd[0])), time.time() - start
    argv = [resolved, *cmd[1:]]
    # start_new_session is POSIX-only; the framework targets Linux, but a Windows
    # import must not explode at call time.
    session_kwargs = {"start_new_session": True} if os.name == "posix" else {}
    proc = None
    try:
        proc = subprocess.Popen(
            argv,
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


#: Artifacts can hold captured traffic and enumeration output; audit logs hold the
#: commands run, the targets touched and the findings reached. Both describe an
#: assessment that may be under authorization constraints, so neither is created
#: readable by other local users. The umask default (0644 files, 0755 dirs) would
#: leave them world-readable.
OWNER_ONLY_DIR_MODE = 0o700
OWNER_ONLY_FILE_MODE = 0o600


def ensure_private_dir(path: str, mode: int = OWNER_ONLY_DIR_MODE) -> None:
    """Create a directory only the current user can read, write or traverse.

    The default audit location sits under ``/tmp``, which is world-writable and
    predictable. ``os.makedirs(exist_ok=True)`` would happily reuse a directory
    another local user created there first, so an existing directory that is not
    owned by us is treated as hostile rather than written into. An existing
    directory that *is* ours but group- or other-accessible is tightened.

    Raises:
        RuntimeError: the path exists and is owned by a different uid.
    """
    if os.path.isdir(path):
        info = os.stat(path)
        if info.st_uid != os.getuid():
            raise RuntimeError(
                f"refusing to use {path!r}: owned by uid {info.st_uid}, not the "
                f"current uid {os.getuid()}; a predictable path under /tmp must not "
                "be reused from another account"
            )
        if info.st_mode & 0o077:
            os.chmod(path, mode)
        return

    existed_before = os.path.exists(path)
    os.makedirs(path, mode=mode, exist_ok=True)
    if not existed_before:
        # makedirs applies `mode` inconsistently across intermediate directories and
        # is masked by the umask, so state the leaf mode explicitly.
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def tighten_file_mode(path: str, mode: int = OWNER_ONLY_FILE_MODE) -> None:
    """Restrict a file this process just wrote. Best effort; never raises."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


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
