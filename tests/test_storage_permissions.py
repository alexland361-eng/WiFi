"""
Storage permissions for artifacts and the audit trail.

Artifacts hold captured traffic and enumeration output; audit logs hold the
commands run, the targets touched and the findings reached. Together they describe
an assessment that may be under authorization constraints, so neither should be
readable by other local users. Both were previously created with umask defaults -
0755 directories and 0644 files - which is world-readable.

The default audit location also sits under ``/tmp``, which is world-writable and
predictable, so a directory another account created there first must not be
silently reused.
"""
import os
import stat
import tempfile
from unittest import mock

import pytest

from wifi_framework.core.audit.logger import AuditLogger
from wifi_framework.core.execution.artifacts import ArtifactStore
from wifi_framework.utils.system import (
    OWNER_ONLY_DIR_MODE,
    OWNER_ONLY_FILE_MODE,
    ensure_private_dir,
    require_private,
    tighten_file_mode,
)


def _mode(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_artifacts_are_created_owner_only(tmp_path):
    store = ArtifactStore(base_dir=str(tmp_path / "artifacts"))

    ref = store.store_text("stdout", "captured traffic metadata and enumeration output")

    assert ref is not None
    assert _mode(str(tmp_path / "artifacts")) == OWNER_ONLY_DIR_MODE
    assert _mode(ref.path) == OWNER_ONLY_FILE_MODE
    assert not _mode(ref.path) & stat.S_IROTH, "artifact is world-readable"
    assert not _mode(ref.path) & stat.S_IRGRP, "artifact is group-readable"


def test_artifact_bytes_are_owner_only(tmp_path):
    store = ArtifactStore(base_dir=str(tmp_path / "artifacts"))

    ref = store.store_bytes("stdout", b"\x00\x01raw capture bytes")

    assert ref is not None
    assert _mode(ref.path) == OWNER_ONLY_FILE_MODE


def test_the_audit_trail_is_created_owner_only(tmp_path):
    logger = AuditLogger(log_dir=str(tmp_path / "audit"))

    logger.log_event("action_executed", {"target": "AA:BB:CC:DD:EE:FF"})

    entries = os.listdir(tmp_path / "audit")
    assert entries, "no audit log was written"
    log_path = str(tmp_path / "audit" / entries[0])
    assert _mode(str(tmp_path / "audit")) == OWNER_ONLY_DIR_MODE
    assert _mode(log_path) == OWNER_ONLY_FILE_MODE
    assert logger.write_failures == []


def test_an_existing_directory_with_loose_permissions_is_tightened(tmp_path):
    loose = tmp_path / "loose"
    loose.mkdir(mode=0o755)
    os.chmod(loose, 0o755)
    assert _mode(str(loose)) == 0o755

    ensure_private_dir(str(loose))

    assert _mode(str(loose)) == OWNER_ONLY_DIR_MODE


def test_a_directory_owned_by_another_uid_is_refused(tmp_path):
    """/tmp is world-writable and the default audit path is predictable.

    ``os.makedirs(exist_ok=True)`` would reuse a directory another account created
    there first, writing the assessment into a location that account controls.
    """
    foreign = tmp_path / "foreign"
    foreign.mkdir()

    with mock.patch("os.getuid", return_value=os.getuid() + 12345):
        with pytest.raises(RuntimeError, match="owned by uid"):
            ensure_private_dir(str(foreign))


def test_a_fresh_directory_is_created_with_the_right_mode(tmp_path):
    target = tmp_path / "nested" / "deeper"

    ensure_private_dir(str(target))

    assert target.is_dir()
    assert _mode(str(target)) == OWNER_ONLY_DIR_MODE


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses directory permissions")
def test_an_audit_write_failure_is_recorded_not_swallowed(tmp_path):
    """An assessment whose trail silently stopped being recorded is not auditable.

    This was ``except OSError: pass``, so a full disk or a permissions problem left
    the run looking auditable while recording nothing.
    """
    audit_dir = tmp_path / "audit"
    logger = AuditLogger(log_dir=str(audit_dir))
    os.chmod(audit_dir, 0o500)  # readable and traversable, not writable
    try:
        logger.log_event("should_not_be_written", {"n": 1})
    finally:
        os.chmod(audit_dir, 0o700)

    assert logger.write_failures, "the failed write was swallowed"
    assert "Permission" in logger.write_failures[0] or "Errno 13" in logger.write_failures[0]
    # The event is still in memory, so the in-process view and the persisted trail
    # are allowed to diverge - but the divergence is now visible.
    assert len(logger.events) == 1


def test_a_repeated_audit_write_failure_is_counted_every_time(tmp_path):
    audit_dir = tmp_path / "audit"
    logger = AuditLogger(log_dir=str(audit_dir))
    os.chmod(audit_dir, 0o500)
    try:
        for i in range(3):
            logger.log_event(f"event_{i}", {})
    finally:
        os.chmod(audit_dir, 0o700)

    assert len(logger.write_failures) == 3, "only the first failure was recorded"


# ------------------------------------------------------- files a tool wrote itself


def test_a_capture_the_tool_wrote_is_restricted_when_adopted(tmp_path):
    """`register_file` adopts a file the tool created with its own umask - typically
    0644. A pcap holds whole conversations rather than a summary of them, so
    restricting only the files the framework writes would leave the most sensitive
    artifacts of all world-readable."""
    capture = tmp_path / "airodump-01.cap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1 captured frames")
    os.chmod(capture, 0o644)
    assert _mode(str(capture)) & stat.S_IROTH, "fixture should start world-readable"

    store = ArtifactStore(base_dir=str(tmp_path / "artifacts"))
    ref = store.register_file(str(capture), kind="pcap")

    assert ref is not None
    assert _mode(str(capture)) == OWNER_ONLY_FILE_MODE
    assert not _mode(str(capture)) & stat.S_IROTH
    assert store.permission_failures == []


def test_an_adopted_file_that_cannot_be_restricted_is_recorded_not_raised(tmp_path, monkeypatch):
    """The file may belong to another uid when the tool ran elevated. The artifact is
    still worth keeping, so the failure is recorded rather than fatal - but it must be
    recorded, because a world-readable capture nobody knows about is the worst outcome."""
    artifacts = tmp_path / "artifacts"
    store = ArtifactStore(base_dir=str(artifacts))
    store.store_bytes("stdout", b"prime the directory while chmod still works")

    capture = tmp_path / "handshake.cap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1 four-way handshake")

    def refuse_chmod(path, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", refuse_chmod)
    ref = store.register_file(str(capture), kind="pcap")

    assert ref is not None, "an unrestrictable file should still be registered"
    assert store.permission_failures == [str(capture)]
    assert store.stats().permission_failure_count >= 1
    assert store.stats().to_dict()["permission_failure_count"] >= 1


def test_a_stored_artifact_created_owner_only_needs_no_chmod(tmp_path, monkeypatch):
    """`store_bytes` creates with `os.open(..., 0600)`, so the tighten step is
    belt-and-braces: a chmod failure there changes nothing and must not be reported as
    a permission problem."""
    store = ArtifactStore(base_dir=str(tmp_path / "artifacts"))
    assert store.store_bytes("stdout", b"captured bytes") is not None
    assert store.permission_failures == []

    def refuse_chmod(path, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", refuse_chmod)
    second = store.store_bytes("stdout", b"more captured bytes")

    assert second is not None
    assert _mode(second.path) == OWNER_ONLY_FILE_MODE
    assert store.permission_failures == [], (
        "the file was created owner-only, so a failed chmod left it correct"
    )


# ---------------------------------------------------------- the restriction itself


def test_tighten_file_mode_reports_whether_it_worked(tmp_path, monkeypatch):
    """Returning nothing meant a file left at 0644 with no signal anywhere, which
    silently undoes the reason it was created owner-only."""
    target = tmp_path / "loose.txt"
    target.write_text("captured traffic")
    os.chmod(target, 0o644)

    assert tighten_file_mode(str(target)) is True
    assert _mode(str(target)) == OWNER_ONLY_FILE_MODE

    stuck = tmp_path / "stuck.txt"
    stuck.write_text("captured traffic")
    os.chmod(stuck, 0o644)

    def refuse_chmod(path, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", refuse_chmod)
    assert tighten_file_mode(str(stuck)) is False, "a failed restriction reported success"
    assert _mode(str(stuck)) & stat.S_IROTH, "the file is still world-readable"
    assert tighten_file_mode(str(tmp_path / "absent.txt")) is False


def test_a_directory_that_cannot_be_tightened_raises_with_context(tmp_path, monkeypatch):
    directory = tmp_path / "audit"
    directory.mkdir()
    os.chmod(directory, 0o755)

    def refuse_chmod(path, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", refuse_chmod)

    with pytest.raises(RuntimeError) as caught:
        ensure_private_dir(str(directory))
    message = str(caught.value)
    assert "0o755" in message, "the mode an operator needs to see is missing"
    assert str(directory) in message


def test_a_new_directory_that_cannot_be_tightened_raises_too(tmp_path, monkeypatch):
    """The inconsistency this closes: tightening an *existing* directory raised, while
    the same failure on a newly created one was swallowed - so the path that runs on
    every fresh assessment was the silent one."""
    real_makedirs = os.makedirs

    def loose_makedirs(path, mode=0o777, exist_ok=False):
        real_makedirs(path, mode=0o777, exist_ok=exist_ok)

    def refuse_chmod(path, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "makedirs", loose_makedirs)
    monkeypatch.setattr(os, "chmod", refuse_chmod)

    with pytest.raises(RuntimeError) as caught:
        ensure_private_dir(str(tmp_path / "fresh" / "audit"))
    assert "group/other accessible" in str(caught.value)


def test_require_private_accepts_a_directory_that_is_already_correct(tmp_path, monkeypatch):
    """Verifying the outcome rather than the syscall means a filesystem that ignores
    chmod is not an error when the mode is already right."""
    directory = tmp_path / "already"
    directory.mkdir()
    os.chmod(directory, OWNER_ONLY_DIR_MODE)

    def refuse_chmod(path, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", refuse_chmod)
    require_private(str(directory))  # must not raise


def test_an_audit_trail_that_cannot_be_restricted_is_recorded(tmp_path, monkeypatch):
    """The trail is appended to with a plain `open`, so a fresh file arrives at 0644
    under the usual umask and depends entirely on the tighten step. If that step fails
    the event is still written - abandoning the trail would lose more than the
    permission problem costs - but the problem must not be invisible."""
    logger = AuditLogger(log_dir=str(tmp_path / "audit"))
    assert logger.write_failures == []

    def refuse_chmod(path, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", refuse_chmod)
    logger.log_event("test_event", {"detail": "value"})

    trail = os.path.join(logger.log_dir, logger.assessment_id + ".jsonl")
    assert os.path.exists(trail), "the event was not written at all"
    assert any("owner-only" in failure for failure in logger.write_failures), (
        f"a world-readable audit trail was not reported; failures were {logger.write_failures}"
    )


def test_a_storage_permission_failure_reaches_the_execution_result(tmp_path, monkeypatch):
    """The store recording a failure is only half of it: the gateway has to carry it onto
    `ExecutionResult.warnings`, or it stays in a statistics dict nobody reads."""
    from wifi_framework.core.execution.gateway import ExecutionGateway

    gateway = ExecutionGateway.__new__(ExecutionGateway)
    gateway.artifact_store = ArtifactStore(base_dir=str(tmp_path / "artifacts"))

    legacy = type("Legacy", (), {"raw_output": "tool output", "error_output": ""})()

    clean = tmp_path / "clean.pcap"
    clean.write_bytes(b"\xd4\xc3\xb2\xa1 frames")
    prepared = type("Prepared", (), {"parameters": {"capture_file": str(clean)}})()

    _artifacts, _stdout, _stderr, warnings = gateway._store_artifacts(
        legacy, prepared, execution_id="execution-clean"
    )
    assert warnings == [], "a normally restricted artifact produced a warning"

    def refuse_chmod(path, mode, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    loose = tmp_path / "loose.pcap"
    loose.write_bytes(b"\xd4\xc3\xb2\xa1 four-way handshake")
    prepared_loose = type("Prepared", (), {"parameters": {"capture_file": str(loose)}})()

    monkeypatch.setattr(os, "chmod", refuse_chmod)
    artifacts, _stdout, _stderr, warnings = gateway._store_artifacts(
        legacy, prepared_loose, execution_id="execution-loose"
    )

    assert artifacts, "the artifact was dropped because its permissions could not be tightened"
    assert any("owner-only" in warning for warning in warnings), (
        f"a world-readable capture produced no warning; got {warnings}"
    )
    assert any(str(loose) in warning for warning in warnings), "the warning does not name the file"
