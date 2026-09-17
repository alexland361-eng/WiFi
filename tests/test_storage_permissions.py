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
