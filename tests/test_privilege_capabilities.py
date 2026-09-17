"""Privilege checks against what the process actually holds.

The framework gated every privileged action on ``is_root()``. On Linux, wireless
administration needs CAP_NET_ADMIN and raw capture needs CAP_NET_RAW - not a root
uid - so an unprivileged process holding exactly those capabilities was told it
could do nothing, and the world model recorded injection support as unknown because
the probe was skipped.

``core/models/capability.py`` already documented the ``privileges`` list as
"e.g. root, net_admin"; nothing implemented the second form. These tests pin the
implementation, and pin that ``root`` was *not* loosened while adding it.
"""
from __future__ import annotations

import os
import re

import pytest

import wifi_framework.utils.system as system
from wifi_framework.core.models.capability import (
    CapabilityCategory,
    CapabilityRequirements,
    OperatingSystem,
    ToolCapabilityMetadata,
)
from wifi_framework.core.models.evidence import Evidence, EvidenceType
from wifi_framework.core.execution.adapter_base import ToolAdapterBase
from wifi_framework.utils.system import (
    CAPABILITY_BITS,
    decode_capability_mask,
    effective_capabilities,
    has_capability,
    normalize_privilege_token,
    satisfies_privileges,
)

HEADER = "/usr/include/linux/capability.h"


# ------------------------------------------------- the bit table is ground-truthed


@pytest.mark.skipif(not os.path.isfile(HEADER), reason=f"{HEADER} not installed")
def test_the_bit_table_matches_the_kernel_header():
    """Bit numbers are an ABI, but a typo in the table would silently decode the
    wrong capability. Checked against the installed header where one exists."""
    declared = {}
    pattern = re.compile(r"^#define\s+(CAP_[A-Z0-9_]+)\s+(\d+)\s*$")
    with open(HEADER, "r", encoding="utf-8") as handle:
        for line in handle:
            match = pattern.match(line)
            if match:
                declared[match.group(1).lower()] = int(match.group(2))

    relevant = {name: bit for name, bit in declared.items() if name in CAPABILITY_BITS}
    assert relevant, "no capabilities parsed from the header - the check is vacuous"
    mismatched = {
        name: (CAPABILITY_BITS[name], relevant[name])
        for name in relevant
        if CAPABILITY_BITS[name] != relevant[name]
    }
    assert mismatched == {}, f"bit numbers disagree with the kernel header: {mismatched}"

    for name in ("cap_net_admin", "cap_net_raw", "cap_net_bind_service"):
        assert name in CAPABILITY_BITS, f"{name} missing from the table"


def test_decoding_a_known_mask():
    assert decode_capability_mask(1 << 12) == {"cap_net_admin"}
    assert decode_capability_mask((1 << 12) | (1 << 13)) == {"cap_net_admin", "cap_net_raw"}
    assert decode_capability_mask(0) == set()
    # A root process reports a full mask; every table entry must decode from it.
    full = decode_capability_mask((1 << (max(CAPABILITY_BITS.values()) + 1)) - 1)
    assert full == set(CAPABILITY_BITS), (
        f"{len(full)} of {len(CAPABILITY_BITS)} decoded; a wrong bit number would "
        "drop a capability silently"
    )


def test_decoding_garbage_is_empty_not_an_exception():
    for bad in (-1, "0000", None, [], 1.5):
        assert decode_capability_mask(bad) == set(), f"{bad!r} decoded to something"


def test_effective_capabilities_reads_the_live_process():
    """Smoke test of the /proc read. Unprivileged here, so the honest answer is the
    empty set; the decoder itself is covered above against known masks."""
    held = effective_capabilities()
    assert isinstance(held, set)
    assert held <= set(CAPABILITY_BITS)
    if os.path.exists("/proc/self/status") and os.geteuid() != 0:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            mask = next(
                int(line.split(":", 1)[1].strip(), 16)
                for line in handle
                if line.startswith("CapEff:")
            )
        assert held == decode_capability_mask(mask)


# --------------------------------------------------------------- token normalising


def test_both_documented_spellings_are_accepted():
    assert normalize_privilege_token("root") == "root"
    assert normalize_privilege_token("net_admin") == "cap_net_admin"
    assert normalize_privilege_token("cap_net_admin") == "cap_net_admin"
    assert normalize_privilege_token("NET_RAW") == "cap_net_raw"
    assert normalize_privilege_token("  cap_sys_admin ") == "cap_sys_admin"


def test_unknown_tokens_normalise_to_none():
    for token in ["net_teleport", "", "   ", None, 42, "cap_", "rootish"]:
        assert normalize_privilege_token(token) is None, f"{token!r} was accepted"


def test_has_capability_refuses_unknown_names():
    assert has_capability("cap_teleport") is False
    assert has_capability("root") is False, "root is a uid state, not a capability"
    assert has_capability(None) is False


# --------------------------------------------------------------- privilege checks


def test_no_requirement_is_satisfied():
    assert satisfies_privileges([]) == (True, "")
    assert satisfies_privileges(None) == (True, "")


def test_root_stays_strict(monkeypatch):
    """Adding fine-grained tokens must not weaken the existing requirement: 19
    capabilities declare ``root`` and it must still mean uid 0."""
    monkeypatch.setattr(system, "is_root", lambda: False)
    monkeypatch.setattr(system, "effective_capabilities", lambda: {"cap_net_admin", "cap_net_raw", "cap_sys_admin"})

    ok, reason = satisfies_privileges(["root"])
    assert not ok, "a non-root process satisfied a root requirement"
    assert "root" in reason

    monkeypatch.setattr(system, "is_root", lambda: True)
    assert satisfies_privileges(["root"]) == (True, "")


def test_a_held_capability_satisfies_a_capability_requirement(monkeypatch):
    monkeypatch.setattr(system, "is_root", lambda: False)
    monkeypatch.setattr(system, "effective_capabilities", lambda: {"cap_net_admin"})

    assert satisfies_privileges(["cap_net_admin"]) == (True, "")
    assert satisfies_privileges(["net_admin"]) == (True, "")

    ok, reason = satisfies_privileges(["cap_net_admin", "cap_net_raw"])
    assert not ok and "cap_net_raw" in reason, "a partially satisfied set passed"


def test_an_unknown_requirement_fails_closed(monkeypatch):
    """A typo in a capability declaration must refuse, not pass. Passing would mean
    executing a privileged action on the strength of a requirement nobody checked."""
    monkeypatch.setattr(system, "is_root", lambda: True)
    monkeypatch.setattr(system, "effective_capabilities", lambda: set(CAPABILITY_BITS))

    ok, reason = satisfies_privileges(["cap_teleport"])
    assert not ok, "an unrecognised privilege requirement was treated as satisfied"
    assert "unrecognised privilege requirement" in reason


# --------------------------------------- refusals classify as privilege failures


def test_the_refusal_message_carries_the_classified_token(monkeypatch):
    """The gateway maps free-text failure reasons to categories by substring. A
    privilege refusal that does not carry the token is reported as a generic tool
    error, which tells the operator to fix the tool instead of their privileges."""
    from wifi_framework.core.execution.gateway import classify_failure
    from wifi_framework.contracts.execution import FailureCategory

    monkeypatch.setattr(system, "is_root", lambda: False)
    monkeypatch.setattr(system, "effective_capabilities", lambda: {"cap_net_raw"})

    for required in (["root"], ["cap_net_admin"], ["net_admin"]):
        ok, reason = satisfies_privileges(required)
        assert not ok
        assert classify_failure(reason) == FailureCategory.INSUFFICIENT_PRIVILEGES, (
            f"{required} refusal {reason!r} classified as "
            f"{classify_failure(reason)}"
        )
        # The operator needs to know what they hold, not just what is missing.
        assert "this process holds" in reason


def test_a_broken_declaration_is_not_reported_as_a_privilege_shortfall(monkeypatch):
    """Elevating cannot fix a malformed declaration, so it must not be classified as
    insufficient privileges."""
    from wifi_framework.core.execution.gateway import classify_failure
    from wifi_framework.contracts.execution import FailureCategory

    monkeypatch.setattr(system, "is_root", lambda: True)
    ok, reason = satisfies_privileges(["cap_teleport"])
    assert not ok
    assert classify_failure(reason) != FailureCategory.INSUFFICIENT_PRIVILEGES


# ------------------------------------------------------------------- consumers


def test_tool_manager_holds_capabilities():
    from wifi_framework.core.execution.tool_manager import ToolManager

    class Stub:
        is_root = False
        capabilities: list = []

    manager = ToolManager.__new__(ToolManager)
    manager.is_root = False
    manager.capabilities = []
    assert manager.holds_capabilities("cap_net_admin") is False

    manager.capabilities = ["cap_net_admin", "cap_net_raw"]
    assert manager.holds_capabilities("cap_net_admin") is True
    assert manager.holds_capabilities("cap_net_admin", "cap_net_raw") is True
    assert manager.holds_capabilities("cap_net_admin", "cap_sys_admin") is False
    assert manager.holds_capabilities() is True

    # A root process holds the full effective set. ``capabilities`` is read once at
    # construction, so a manager marked root afterwards must still answer yes.
    manager.is_root = True
    manager.capabilities = []
    assert manager.holds_capabilities("cap_net_admin", "cap_net_raw") is True


def test_the_tool_manager_audit_record_states_held_capabilities():
    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.tools.registry_loader import load_all_adapters
    from wifi_framework.core.execution.tool_manager import ToolManager

    manager = ToolManager(load_all_adapters(CapabilityRegistry()))
    record = manager.to_dict()
    assert "capabilities" in record, "the audit snapshot reports is_root but not what is held"
    assert isinstance(record["capabilities"], list)
    assert set(record["capabilities"]) <= set(CAPABILITY_BITS)


def test_interface_administration_is_gated_on_cap_net_admin():
    from wifi_framework.core.execution.interface_manager import _can_admin_interfaces

    class Stub:
        def __init__(self, is_root, capabilities):
            self.is_root = is_root
            self.capabilities = capabilities

    assert _can_admin_interfaces(Stub(True, [])) is True
    assert _can_admin_interfaces(Stub(False, ["cap_net_admin"])) is True, (
        "CAP_NET_ADMIN is sufficient to bring an interface up and switch its type"
    )
    assert _can_admin_interfaces(Stub(False, ["cap_net_raw"])) is False
    assert _can_admin_interfaces(Stub(False, [])) is False


def test_the_capability_checker_reports_held_capabilities():
    from wifi_framework.core.execution.capability_checker import CapabilityChecker

    metadata = ToolCapabilityMetadata(
        name="echo_probe",
        display_name="Echo",
        category=CapabilityCategory.WIRELESS_INTERFACE,
        description="test",
        tool_binary="echo",
        requirements=CapabilityRequirements(operating_systems=[OperatingSystem.LINUX]),
    )
    available, reason, details = CapabilityChecker().check(metadata)
    assert available, reason
    assert "capabilities" in details, "details reported is_root but not the capability set"
    assert details["capabilities"] == sorted(effective_capabilities())


# ------------------------------------------------------------------- end to end


class _ProbeAdapter(ToolAdapterBase):
    def build_command(self, interface, parameters):
        return ["echo", "probe"]

    def parse_output(self, raw_output, error_output, exit_code, parameters, interface):
        return [
            Evidence.from_tool_output(
                tool_name="echo",
                capability="probe",
                evidence_type=EvidenceType.GENERIC,
                raw_output=raw_output,
                parsed_data={},
                parameters=parameters,
            )
        ]


def _metadata(privileges):
    return ToolCapabilityMetadata(
        name="probe_capability",
        display_name="Probe",
        category=CapabilityCategory.WIRELESS_INTERFACE,
        description="test",
        tool_binary="echo",
        requirements=CapabilityRequirements(
            operating_systems=[OperatingSystem.LINUX], privileges=list(privileges)
        ),
    )


def test_an_adapter_refuses_root_when_not_root(monkeypatch):
    """Regression guard: the base-class requirement check still refuses."""
    monkeypatch.setattr(system, "is_root", lambda: False)
    monkeypatch.setattr(system, "effective_capabilities", lambda: {"cap_net_admin", "cap_net_raw"})

    adapter = _ProbeAdapter(_metadata(["root"]))
    ok, reason = adapter.check_requirements(interface=None, parameters={})
    assert not ok and "root" in reason


def test_an_adapter_accepts_a_held_capability(monkeypatch):
    monkeypatch.setattr(system, "is_root", lambda: False)
    monkeypatch.setattr(system, "effective_capabilities", lambda: {"cap_net_admin"})

    adapter = _ProbeAdapter(_metadata(["net_admin"]))
    ok, reason = adapter.check_requirements(interface=None, parameters={})
    assert ok, f"a process holding CAP_NET_ADMIN was refused: {reason}"


def test_an_adapter_refuses_a_capability_it_lacks(monkeypatch):
    monkeypatch.setattr(system, "is_root", lambda: False)
    monkeypatch.setattr(system, "effective_capabilities", lambda: set())

    adapter = _ProbeAdapter(_metadata(["cap_net_admin"]))
    ok, reason = adapter.check_requirements(interface=None, parameters={})
    assert not ok
    assert "insufficient_privileges" in reason


def test_an_adapter_refuses_a_broken_privilege_declaration(monkeypatch):
    monkeypatch.setattr(system, "is_root", lambda: True)
    monkeypatch.setattr(system, "effective_capabilities", lambda: set(CAPABILITY_BITS))

    adapter = _ProbeAdapter(_metadata(["cap_teleport"]))
    ok, reason = adapter.check_requirements(interface=None, parameters={})
    assert not ok, "an unrecognised requirement passed on a root process"
    assert "unrecognised" in reason


def test_no_declared_privilege_in_the_tree_is_unrecognised():
    """Every ``privileges`` value the 38 adapters declare must be evaluable. A token
    this code does not know would now fail closed and make that capability
    permanently unusable - better found here than at runtime."""
    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.tools.registry_loader import load_all_adapters

    registry = load_all_adapters(CapabilityRegistry())
    declared = set()
    for name in registry.list_capabilities():
        metadata = registry.get_metadata(name)
        declared.update(metadata.requirements.privileges or [])
    assert declared, "no privileges declared anywhere - the check is vacuous"

    unknown = sorted(token for token in declared if normalize_privilege_token(token) is None)
    assert unknown == [], f"declared privileges the framework cannot evaluate: {unknown}"
