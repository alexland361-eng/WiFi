"""
Policy and capability validation layer.

Sits between the Decision Engine and the Execution Engine
(specification section 11):

    ActionRequest -> scope validation -> capability validation -> parameter validation -> execution

A rejected action always carries a structured reason, and the layer distinguishes two kinds of
"no":

* ``rejected`` - the action must not run (out of scope, incompatible capability, unsafe
  parameter). The Decision Engine should choose a different action.
* ``deferred`` - the action is legitimate but cannot run in this environment right now
  (tool missing, monitor mode unavailable, not root). The capability stays recorded as
  unavailable rather than being silently skipped.

This module imports no execution machinery beyond the capability registry: it judges requests,
it does not run them.
"""
from __future__ import annotations

from .validator import PARAMETER_RULES, ActionPolicy, ParameterRule, PolicyDecision

__all__ = ["ActionPolicy", "PolicyDecision", "ParameterRule", "PARAMETER_RULES"]
