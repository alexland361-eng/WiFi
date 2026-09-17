"""
Artifact store.

Execution output is stored on disk and referenced from the ``execution-result`` contract by
identifier, instead of being truncated into the assessment state. Two requirements drive this:

1. Specification section 5 gives ``stdout_artifact`` / ``stderr_artifact`` / ``artifacts`` as
   references, not inline payloads. The previous behaviour (``raw_output[:10000]``) discarded
   evidence the Evidence Engine might still need.
2. Auditability requires that a reported observation can be traced to the real bytes a real
   tool produced. Each artifact therefore carries a SHA-256 digest and a byte count, and the
   store keeps an append-only manifest so artifacts can be reconciled after an assessment.

Security notes:
* Filenames are generated from the artifact identifier only. Caller-supplied text never forms
  part of a path, so a malicious SSID or tool error message cannot cause path traversal.
* Content larger than ``max_bytes`` is truncated **and the truncation is recorded** on the
  artifact. A silently truncated artifact would misrepresent what the tool said.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ...contracts.common import ArtifactRef
from ...contracts.envelope import format_timestamp

#: Default per-artifact cap. 32 MiB comfortably holds verbose tool output and text captures
#: while preventing a runaway ``airodump-ng``/``tshark`` run from filling the disk.
DEFAULT_MAX_BYTES = 32 * 1024 * 1024

#: Artifact kinds used across the framework.
KIND_STDOUT = "stdout"
KIND_STDERR = "stderr"
KIND_PCAP = "pcap"
KIND_PCAPNG = "pcapng"
KIND_CSV = "csv"
KIND_JSON = "json"
KIND_LOG = "log"
KIND_FILE = "file"

_MEDIA_TYPES = {
    KIND_STDOUT: "text/plain",
    KIND_STDERR: "text/plain",
    KIND_LOG: "text/plain",
    KIND_CSV: "text/csv",
    KIND_JSON: "application/json",
    KIND_PCAP: "application/vnd.tcpdump.pcap",
    KIND_PCAPNG: "application/x-pcapng",
    KIND_FILE: "application/octet-stream",
}


@dataclass(frozen=True)
class ArtifactStoreStats:
    """Summary of what a store holds, for audit reports."""

    base_dir: str
    artifact_count: int
    total_bytes: int
    truncated_count: int
    missing_count: int
    #: Paths whose owner-only restriction could not be applied.
    permission_failure_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_dir": self.base_dir,
            "artifact_count": self.artifact_count,
            "total_bytes": self.total_bytes,
            "truncated_count": self.truncated_count,
            "permission_failure_count": self.permission_failure_count,
            "missing_count": self.missing_count,
        }


from ...utils.system import OWNER_ONLY_FILE_MODE, ensure_private_dir, tighten_file_mode


class ArtifactStore:
    """Stores and indexes the bytes produced or consumed by executions."""

    def __init__(
        self,
        base_dir: str,
        max_bytes: int = DEFAULT_MAX_BYTES,
        assessment_id: Optional[str] = None,
        write_manifest: bool = True,
    ) -> None:
        if max_bytes <= 0:
            raise ValueError(f"max_bytes must be positive, got {max_bytes}")
        self.base_dir = os.path.abspath(base_dir)
        self.max_bytes = max_bytes
        self.assessment_id = assessment_id
        self.write_manifest = write_manifest
        self._artifacts: Dict[str, ArtifactRef] = {}
        self._manifest_path = os.path.join(self.base_dir, "artifacts.jsonl")
        self._created_dirs = False
        #: Files whose permissions could not be restricted to the owner. Artifacts
        #: hold captured traffic, so a file left group- or other-readable is worth
        #: reporting even though the artifact itself was written successfully.
        self.permission_failures: List[str] = []

    # ------------------------------------------------------------------ layout

    def _ensure_dir(self) -> None:
        if not self._created_dirs:
            ensure_private_dir(self.base_dir)
            self._created_dirs = True

    def _path_for(self, artifact_id: str, kind: str) -> str:
        # ``kind`` is validated against a closed set before it reaches the filesystem.
        safe_kind = kind if kind in _MEDIA_TYPES else KIND_FILE
        return os.path.join(self.base_dir, f"{artifact_id}.{safe_kind}")

    # ----------------------------------------------------------------- storing

    def store_text(
        self,
        kind: str,
        text: Optional[str],
        *,
        description: Optional[str] = None,
        execution_id: Optional[str] = None,
    ) -> Optional[ArtifactRef]:
        """
        Store text output. Returns ``None`` when there is nothing to store.

        An empty stream produces no artifact rather than an empty file: ``stdout_artifact``
        being null is the honest representation of "the tool wrote nothing to stdout".
        """
        if text is None or text == "":
            return None
        data = text.encode("utf-8", errors="replace")
        return self.store_bytes(kind, data, description=description, execution_id=execution_id)

    def store_bytes(
        self,
        kind: str,
        data: bytes,
        *,
        description: Optional[str] = None,
        execution_id: Optional[str] = None,
    ) -> Optional[ArtifactRef]:
        """Store raw bytes, applying and recording the size cap."""
        if not data:
            return None
        self._ensure_dir()
        artifact_id = f"artifact-{uuid.uuid4().hex[:12]}"
        truncated = len(data) > self.max_bytes
        stored = data[: self.max_bytes] if truncated else data
        path = self._path_for(artifact_id, kind)
        # Created with the owner-only mode rather than chmod'd afterwards, so the
        # bytes are never briefly world-readable.
        handle_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, OWNER_ONLY_FILE_MODE)
        with os.fdopen(handle_fd, "wb") as handle:
            handle.write(stored)
        if not tighten_file_mode(path):
            self.permission_failures.append(path)

        artifact = ArtifactRef(
            id=artifact_id,
            kind=kind if kind in _MEDIA_TYPES else KIND_FILE,
            path=path,
            sha256=hashlib.sha256(stored).hexdigest(),
            bytes=len(stored),
            created_at=format_timestamp(datetime.now(timezone.utc)),
            truncated=truncated,
            media_type=_MEDIA_TYPES.get(kind, _MEDIA_TYPES[KIND_FILE]),
            description=description,
        )
        self._artifacts[artifact_id] = artifact
        self._record(artifact, execution_id=execution_id, original_bytes=len(data))
        return artifact

    def register_file(
        self,
        path: str,
        kind: str = KIND_FILE,
        *,
        description: Optional[str] = None,
        execution_id: Optional[str] = None,
        copy_into_store: bool = False,
    ) -> Optional[ArtifactRef]:
        """
        Register a file a tool wrote itself (pcap, csv, kismet log).

        With ``copy_into_store`` the bytes are copied under the store so the artifact survives
        cleanup of the tool's temporary directory. Without it the artifact references the
        original path, which is correct when the caller manages that file's lifetime.
        """
        if not path or not os.path.exists(path):
            return None
        if not os.path.isfile(path):
            return None
        size = os.path.getsize(path)
        if copy_into_store:
            with open(path, "rb") as handle:
                data = handle.read(self.max_bytes)
            return self.store_bytes(
                kind,
                data,
                description=description or os.path.basename(path),
                execution_id=execution_id,
            )

        self._ensure_dir()
        # The tool wrote this file with its own umask, so a capture is typically 0644 -
        # world-readable, and a pcap holds whole conversations rather than a summary of
        # them. Restricting files the framework writes but not the ones it adopts would
        # leave the most sensitive artifacts of all unprotected. Best effort: the file
        # may belong to another uid if the tool ran elevated, in which case the failure
        # is recorded rather than raised, because the artifact is still worth keeping.
        if not tighten_file_mode(path):
            self.permission_failures.append(os.path.abspath(path))
        artifact_id = f"artifact-{uuid.uuid4().hex[:12]}"
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        artifact = ArtifactRef(
            id=artifact_id,
            kind=kind if kind in _MEDIA_TYPES else KIND_FILE,
            path=os.path.abspath(path),
            sha256=digest.hexdigest(),
            bytes=size,
            created_at=format_timestamp(datetime.now(timezone.utc)),
            truncated=False,
            media_type=_MEDIA_TYPES.get(kind, _MEDIA_TYPES[KIND_FILE]),
            description=description or os.path.basename(path),
        )
        self._artifacts[artifact_id] = artifact
        self._record(artifact, execution_id=execution_id, original_bytes=size)
        return artifact

    # ----------------------------------------------------------------- reading

    def get(self, artifact_id: str) -> Optional[ArtifactRef]:
        return self._artifacts.get(artifact_id)

    def read_text(self, artifact_id: str) -> Optional[str]:
        """Read an artifact back as text, or ``None`` when it is unknown or unreadable."""
        artifact = self._artifacts.get(artifact_id)
        if artifact is None or not artifact.path or not os.path.exists(artifact.path):
            return None
        try:
            with open(artifact.path, "rb") as handle:
                return handle.read().decode("utf-8", errors="replace")
        except OSError:
            return None

    def verify(self, artifact_id: str) -> bool:
        """Re-hash a stored artifact and compare against the recorded digest."""
        artifact = self._artifacts.get(artifact_id)
        if artifact is None or not artifact.path or not os.path.exists(artifact.path):
            return False
        digest = hashlib.sha256()
        try:
            with open(artifact.path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return False
        return digest.hexdigest() == artifact.sha256

    def list_artifacts(self) -> List[ArtifactRef]:
        return list(self._artifacts.values())

    def stats(self) -> ArtifactStoreStats:
        missing = sum(
            1 for item in self._artifacts.values() if not item.path or not os.path.exists(item.path)
        )
        return ArtifactStoreStats(
            base_dir=self.base_dir,
            artifact_count=len(self._artifacts),
            total_bytes=sum(item.bytes for item in self._artifacts.values()),
            truncated_count=sum(1 for item in self._artifacts.values() if item.truncated),
            missing_count=missing,
            permission_failure_count=len(self.permission_failures),
        )

    # --------------------------------------------------------------- lifecycle

    def _record(self, artifact: ArtifactRef, *, execution_id: Optional[str], original_bytes: int) -> None:
        if not self.write_manifest:
            return
        entry = {
            "artifact": artifact.to_dict(),
            "execution_id": execution_id,
            "assessment_id": self.assessment_id,
            "original_bytes": original_bytes,
            "recorded_at": format_timestamp(datetime.now(timezone.utc)),
        }
        try:
            with open(self._manifest_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError:
            # A manifest write failure must not abort an assessment; the artifact itself is
            # already on disk and still referenced by the execution result.
            self.write_manifest = False

    def cleanup(self) -> None:
        """Remove the store directory. Only for temporary stores owned by this process."""
        shutil.rmtree(self.base_dir, ignore_errors=True)
        self._artifacts.clear()
        self._created_dirs = False
