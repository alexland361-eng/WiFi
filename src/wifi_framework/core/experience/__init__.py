"""
Experience layer.

Two things live here and they are deliberately distinct:

* :class:`ExperienceStore` / :class:`ExperienceRecord` - the pre-existing (v0.1.0) heuristic
  store the action selector consults for capability scoring.
* :class:`ExperienceEngine` - the v0.4.0 producer of the ``experience-record`` *contract*, which
  adds state digests, verification outcome and normalized information gain, and mirrors each
  record into the store so existing scoring behaviour is unchanged.

The contract class is exported as ``ExperienceRecordContract`` to keep the two records
unambiguous at import sites.
"""
from __future__ import annotations

from ...contracts.experience import ExperienceRecord as ExperienceRecordContract
from .engine import STATUS_FACTORS, VERIFICATION_FACTORS, ExperienceEngine, ExperienceOutcome, saturation
from .store import ExperienceRecord, ExperienceStore

__all__ = [
    "ExperienceStore",
    "ExperienceRecord",
    "ExperienceRecordContract",
    "ExperienceEngine",
    "ExperienceOutcome",
    "saturation",
    "STATUS_FACTORS",
    "VERIFICATION_FACTORS",
]
