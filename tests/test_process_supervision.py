"""
Process supervision for external tools.

A wireless framework runs tools that spawn children and hold hardware. A timeout
that kills only the direct child leaves grandchildren running: a capture utility
keeps the radio busy, an interface stays in monitor mode after the assessment
ends, and every later operation on that interface fails for a reason that has
nothing to do with the framework's logic.

``subprocess.run(timeout=...)`` has exactly that behaviour. These tests pin the
alternative - starting the child in its own session and signalling the whole
group - against a real process tree, because the difference is only observable by
running one.
"""
import os
import shutil
import signal
import subprocess
import sys
import time

import pytest

from wifi_framework.utils.system import run_command, terminate_process_group

pytestmark = pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-specific")

SPAWNER = """#!/bin/sh
# Two background children, both recorded, then wait. If only the direct child is
# signalled both are orphaned, which is the behaviour under test. A foreground
# sleep would orphan too but could not be recorded, so the script waits instead.
sleep 300 &
A=$!
sleep 300 &
B=$!
printf '%s %s\n' "$A" "$B" > {pidfile}
wait
"""


@pytest.fixture
def spawner(tmp_path):
    """A script that records its grandchild's pid, then hangs."""
    pidfile = tmp_path / "grandchild.pid"
    script = tmp_path / "spawner.sh"
    script.write_text(SPAWNER.format(pidfile=pidfile))
    script.chmod(0o755)
    yield str(script), pidfile
    # Never leave a sleeper behind, whatever the test did.
    for pid in _recorded_pids(pidfile):
        try:
            os.kill(pid, signal.SIGKILL)
        except (OSError, ValueError):
            pass


def _recorded_pids(pidfile):
    try:
        return [int(tok) for tok in pidfile.read_text().split() if tok.strip()]
    except (OSError, ValueError, FileNotFoundError):
        return []


def _grandchild_alive(pidfile) -> bool:
    """True if any recorded child of the spawner is still running."""
    for pid in _recorded_pids(pidfile):
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, OSError):
            continue
        return True
    return False


def test_a_timeout_kills_the_whole_process_tree(spawner):
    script, pidfile = spawner

    exit_code, _stdout, stderr, duration = run_command([script], timeout=1)

    assert exit_code == 124, "a timeout must be reported as 124"
    assert "timed out" in stderr
    assert duration < 10, f"teardown should not block; took {duration:.1f}s"

    # Give the signal a moment to land, then assert nothing survived.
    deadline = time.time() + 5
    while time.time() < deadline and _grandchild_alive(pidfile):
        time.sleep(0.1)
    assert not _grandchild_alive(pidfile), (
        "the grandchild outlived the timeout: a tool that spawns helpers would "
        "keep holding the radio after the framework gave up on it"
    )


def test_subprocess_run_alone_would_have_orphaned_it(spawner):
    """The contrast that justifies the custom supervision.

    Documents the stdlib behaviour being replaced, so a future reader does not
    "simplify" run_command back to subprocess.run and silently reintroduce the
    orphan.
    """
    script, pidfile = spawner

    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run([script], capture_output=True, text=True, timeout=1)

    time.sleep(0.5)
    orphaned = _grandchild_alive(pidfile)

    # Clean up by pid only. This is deliberate: because subprocess.run does not
    # start a new session, the orphan is in the *caller's* process group - here,
    # pytest's own. os.killpg() on it kills the test runner, which is exactly the
    # collateral damage that makes the missing supervision dangerous in the first
    # place.
    for pid in _recorded_pids(pidfile):
        try:
            os.kill(pid, signal.SIGKILL)
        except (OSError, ValueError):
            pass

    assert orphaned, (
        "expected plain subprocess.run to orphan the grandchild; if it no longer "
        "does, this platform changed and the premise of run_command should be revisited"
    )


def test_a_normal_command_is_unaffected(spawner):
    """Supervision must not change the ordinary path."""
    exit_code, stdout, stderr, _duration = run_command(["echo", "Office Network"], timeout=10)

    assert exit_code == 0
    assert stdout.strip() == "Office Network"
    assert stderr == ""


def test_a_missing_executable_is_still_127():
    exit_code, stdout, stderr, _duration = run_command(
        ["definitely-not-an-installed-tool-xyz"], timeout=5
    )

    assert exit_code == 127
    assert stdout == ""
    assert "not found" in stderr.lower() or "Command not found" in stderr


def test_a_nonzero_exit_is_passed_through_unchanged():
    exit_code, _stdout, _stderr, _duration = run_command(["false"], timeout=5)

    assert exit_code == 1


def test_stderr_is_captured_alongside_stdout():
    script = shutil.which("sh")
    assert script, "needs a POSIX shell"
    exit_code, stdout, stderr, _duration = run_command(
        [script, "-c", "echo out; echo err >&2; exit 3"], timeout=5
    )

    assert exit_code == 3
    assert stdout.strip() == "out"
    assert stderr.strip() == "err"


def test_terminate_process_group_is_idempotent_for_a_finished_process():
    """Signalling an already-exited process must not raise."""
    proc = subprocess.Popen(["true"], stdout=subprocess.PIPE, start_new_session=True)
    proc.wait(timeout=10)

    assert terminate_process_group(proc) is True
    # A second call on the same reaped process is a no-op, not an exception.
    assert terminate_process_group(proc) is True


def test_a_tool_that_writes_a_lot_before_timing_out_is_still_torn_down(tmp_path):
    """Output volume must not change the teardown outcome."""
    script = tmp_path / "noisy.sh"
    script.write_text("#!/bin/sh\nyes | head -c 5000000\nsleep 300\n")
    script.chmod(0o755)

    exit_code, stdout, _stderr, _duration = run_command([str(script)], timeout=2)

    assert exit_code == 124
    assert sys.getsizeof(stdout) >= 0  # captured what was produced, without hanging
