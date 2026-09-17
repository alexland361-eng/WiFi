"""Tool-binary resolution: the binary that runs is the binary that was checked.

`check_tool_available` resolved a name with `shutil.which`, the gateway resolved
it again to decide whether to refuse, and `run_command` handed the bare *name* to
`Popen` - which re-resolves it against PATH inside the kernel's search. Three
resolutions of the same name, any of which could disagree with the others if PATH
changed or a writable directory earlier in it gained an executable.

These tests pin the property that matters: resolution happens once, immediately
before the spawn, and the resolved absolute path is what is executed.
"""
from __future__ import annotations

import os
import stat
import subprocess

import pytest

from wifi_framework.utils.system import (
    describe_unresolved,
    resolve_binary,
    run_command,
)


def _make_executable(path, body="#!/bin/sh\necho ran\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


# --------------------------------------------------------------- resolution rules


def test_a_bare_name_resolves_to_an_absolute_executable_path():
    resolved = resolve_binary("echo")
    assert resolved is not None
    assert os.path.isabs(resolved), f"{resolved!r} is not absolute"
    assert os.access(resolved, os.X_OK)


def test_an_absolute_path_is_honoured():
    """Callers that deliberately name a file must keep working - the process
    supervision tests execute a temporary script by absolute path."""
    assert resolve_binary("/bin/sh") == "/bin/sh"


def test_a_relative_path_is_refused(tmp_path, monkeypatch):
    """The planted-binary shape: `shutil.which('./evil')` resolves against cwd, so a
    capability declaration or a tool parameter could select a file an attacker
    dropped in the working directory instead of an installed binary."""
    planted = _make_executable(tmp_path / "evil", "#!/bin/sh\ntouch pwned\n")
    monkeypatch.chdir(tmp_path)

    assert resolve_binary("./evil") is None
    assert resolve_binary(f"./{planted.name}") is None

    exit_code, _out, err, _dur = run_command(["./evil"], timeout=5)
    assert exit_code == 127
    assert "path separator" in err
    assert not (tmp_path / "pwned").exists(), "the planted binary was executed"


def test_unusable_names_are_refused():
    for name in ["", "   ", "a b", "echo; rm -rf /", "x\x00y", None, 42]:
        assert resolve_binary(name) is None, f"{name!r} was resolved"


def test_a_missing_tool_is_refused_with_the_classifier_token():
    assert resolve_binary("definitely-not-an-installed-tool-xyz") is None
    message = describe_unresolved("definitely-not-an-installed-tool-xyz")
    # The gateway maps failure reasons to categories by substring; "not found in
    # PATH" is the token that yields TOOL_NOT_FOUND rather than a generic error.
    assert "not found in PATH" in message


def test_every_declared_tool_binary_is_resolvable_or_cleanly_refused():
    """No capability in the source tree may declare a name the resolver refuses on
    shape grounds - that would be a declaration that can never execute."""
    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.tools.registry_loader import load_all_adapters

    registry = load_all_adapters(CapabilityRegistry())
    names = set()
    for name in registry.list_capabilities():
        metadata = registry.get_metadata(name)
        binary = getattr(metadata, "tool_binary", None)
        if binary:
            names.add(binary)
    assert names, "no capabilities discovered - the test would be vacuous"

    malformed = sorted(
        name for name in names
        if os.sep in name or (not name.strip()) or any(c.isspace() for c in name)
    )
    assert malformed == [], f"capability declarations the resolver refuses: {malformed}"


# ------------------------------------------------------- resolution is not repeated


def test_run_command_executes_the_resolved_path_not_the_bare_name(monkeypatch):
    """The core of the fix. Handing `Popen` a bare name makes the kernel re-search
    PATH, so the executed binary is chosen a second time, after the check."""
    captured = {}
    real_popen = subprocess.Popen

    def spy(argv, *args, **kwargs):
        captured["argv"] = list(argv)
        return real_popen(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spy)
    exit_code, stdout, _err, _dur = run_command(["echo", "Office Network"], timeout=10)

    assert exit_code == 0
    assert stdout.strip() == "Office Network"
    assert captured["argv"][0] == resolve_binary("echo")
    assert os.path.isabs(captured["argv"][0]), (
        f"Popen received the bare name {captured['argv'][0]!r}; PATH would be "
        "searched a second time at exec"
    )
    assert captured["argv"][1:] == ["Office Network"], "argument boundaries were altered"


def test_the_executed_binary_survives_a_path_change_mid_flight(tmp_path, monkeypatch):
    """Two same-named binaries, hostile one first on PATH. An absolute path selected
    before the change must still be what runs."""
    trusted = tmp_path / "trusted"
    hostile = tmp_path / "hostile"
    _make_executable(trusted / "probe", "#!/bin/sh\necho trusted\n")
    _make_executable(hostile / "probe", "#!/bin/sh\necho hostile\n")

    monkeypatch.setenv("PATH", str(trusted))
    resolved = resolve_binary("probe")
    assert resolved == str(trusted / "probe")

    # PATH now prefers the hostile directory; executing the resolved path is unaffected.
    monkeypatch.setenv("PATH", f"{hostile}{os.pathsep}{trusted}")
    exit_code, stdout, _err, _dur = run_command([resolved], timeout=5)
    assert exit_code == 0
    assert stdout.strip() == "trusted"
    assert resolve_binary("probe") == str(hostile / "probe"), (
        "the bare name would have resolved to the hostile binary - which is exactly "
        "why the resolved path is what gets executed"
    )


def test_allowed_dirs_pins_the_toolchain(tmp_path, monkeypatch):
    """Optional restriction: callers that want a known toolchain can refuse
    everything outside it, including a same-named binary earlier on PATH."""
    pinned = tmp_path / "pinned"
    loose = tmp_path / "loose"
    _make_executable(pinned / "probe")
    _make_executable(loose / "probe")
    monkeypatch.setenv("PATH", f"{loose}{os.pathsep}{pinned}")

    assert resolve_binary("probe") == str(loose / "probe")
    assert resolve_binary("probe", allowed_dirs=(str(pinned),)) == str(pinned / "probe")
    assert resolve_binary("probe", allowed_dirs=(str(tmp_path / "absent"),)) is None


# -------------------------------------------------------------------- availability


def test_check_tool_available_reports_the_refusal_reason(tmp_path, monkeypatch):
    from wifi_framework.utils.system import check_tool_available

    available, path, _version = check_tool_available("echo")
    assert available and os.path.isabs(path)

    available, path, error = check_tool_available("../evil")
    assert not available and path is None
    assert "path separator" in error, (
        "a shape refusal reported as a missing package would send an operator "
        "looking for the wrong problem"
    )

    available, path, error = check_tool_available("definitely-not-an-installed-tool-xyz")
    assert not available and path is None and "not found in PATH" in error


def test_an_empty_command_is_refused_without_spawning():
    exit_code, stdout, stderr, _dur = run_command([], timeout=5)
    assert exit_code == 127
    assert stdout == ""
    assert "empty command" in stderr
