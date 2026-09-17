"""
Tests for the Scapy adapter's security boundary.

The adapter previously accepted a ``script`` parameter and ran it through
``exec()`` with full ``__builtins__``. That was reachable through the normal
capability path, and no existing control caught it:

- the policy layer rejects shell metacharacters, but pure Python needs none, so
  ``open('/tmp/x','w').write('...')`` sailed through;
- the no-``shell=True`` AST sweep could not see it, because no shell was involved;
- ``custom_parameter_validation`` returned ``(True, [])``, validating nothing.

Worse, the success path was unreachable: a wrong relative-import depth raised
``ModuleNotFoundError`` (a subclass of ``ImportError``), which the broad handler
misreported as a missing dependency - so the adapter ran the code and then
claimed it had not.

These tests pin the boundary. The rejection tests deliberately do not need Scapy
installed, because validation must happen before the library is touched.
"""
import pytest

from wifi_framework.core.execution.registry import CapabilityRegistry
from wifi_framework.tools.adapters.protocol.scapy_adapter import (
    ALLOWED_OPERATIONS,
    FORBIDDEN_PARAMETERS,
    MAX_COUNT,
    MAX_FILTER_LENGTH,
    MAX_TIMEOUT,
    ScapyAdapter,
)
from wifi_framework.tools.registry_loader import load_all_adapters

try:
    import scapy  # noqa: F401

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@pytest.fixture
def adapter():
    registry = CapabilityRegistry()
    load_all_adapters(registry)
    return registry.get_adapter_instance("scapy")


# --------------------------------------------------------------------------
# Arbitrary code execution is refused
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "param",
    ["script", "code", "source", "expr", "lambda"],
)
def test_code_carrying_parameters_are_rejected(adapter, param):
    ok, errors = adapter.custom_parameter_validation({param: "open('/tmp/x','w').write('hi')"})

    assert ok is False
    assert any(param in e for e in errors), errors


def test_forbidden_parameter_list_covers_the_declared_set():
    assert "script" in FORBIDDEN_PARAMETERS
    assert "code" in FORBIDDEN_PARAMETERS


def test_rejection_happens_before_any_side_effect(adapter, tmp_path):
    """The old adapter executed the payload and then reported failure."""
    marker = tmp_path / "pwned.txt"
    payload = f"open({str(marker)!r},'w').write('RAN')"

    result = adapter.execute(interface=None, parameters={"script": payload}, timeout=20)

    assert result.success is False
    assert "invalid_parameters" in (result.failure_reason or "")
    assert not marker.exists(), "the payload ran despite being rejected"


def test_payload_without_shell_metacharacters_is_still_rejected(adapter, tmp_path):
    """The policy layer's metacharacter rule cannot catch this; the adapter must."""
    from wifi_framework.utils.validation import SHELL_METACHARACTERS

    marker = tmp_path / "quiet.txt"
    payload = f"open({str(marker)!r},'w').write('no metacharacters here')"
    assert not any(token in payload for token in SHELL_METACHARACTERS), "test payload changed shape"

    result = adapter.execute(interface=None, parameters={"script": payload}, timeout=20)

    assert result.success is False
    assert not marker.exists()


def test_rejected_execution_reports_what_it_refused(adapter):
    result = adapter.execute(interface=None, parameters={"script": "print(1)"}, timeout=20)

    assert result.success is False
    assert result.raw_command, "the refusal should still record what was attempted"
    assert "rejected" in result.raw_command


def test_multiple_bad_parameters_are_all_reported(adapter):
    ok, errors = adapter.custom_parameter_validation(
        {"script": "x", "operation": "detonate", "count": -5}
    )

    assert ok is False
    assert len(errors) >= 3, errors


# --------------------------------------------------------------------------
# build_command never becomes an execution vector
# --------------------------------------------------------------------------


def test_build_command_never_embeds_caller_data(adapter):
    """It used to return ['python3', '-c', <caller code>] as a fallback path."""
    cmd = adapter.build_command(None, {"script": "ARBITRARY; rm -rf /"})

    assert cmd == ["python3", "-c", "import scapy; print(scapy.__version__)"]
    assert not any("ARBITRARY" in part for part in cmd)


@pytest.mark.parametrize("params", [{}, {"operation": "sniff"}, {"filter": "type mgt"}])
def test_build_command_is_constant_regardless_of_parameters(adapter, params):
    assert adapter.build_command("wlan0", params) == adapter.build_command(None, {})


# --------------------------------------------------------------------------
# The declarative parameter set is actually validated
# --------------------------------------------------------------------------


def test_allowed_operations_are_a_closed_set():
    assert ALLOWED_OPERATIONS == ("version", "sniff")


@pytest.mark.parametrize("operation", ["inject_deauth", "run", "", "SNIFF", None, 123])
def test_unknown_operation_rejected(adapter, operation):
    ok, errors = adapter.custom_parameter_validation({"operation": operation})

    assert ok is False
    assert any("operation" in e for e in errors)


@pytest.mark.parametrize("count", [0, -1, MAX_COUNT + 1, "100", 1.5, None, True])
def test_count_bounds_enforced(adapter, count):
    ok, errors = adapter.custom_parameter_validation({"operation": "sniff", "count": count})

    assert ok is False, f"count={count!r} should be rejected"
    assert any("count" in e for e in errors)


def test_count_at_both_bounds_is_accepted(adapter):
    for count in (1, MAX_COUNT):
        ok, errors = adapter.custom_parameter_validation({"operation": "sniff", "count": count})
        assert ok is True, errors


@pytest.mark.parametrize("timeout", [0, -1, MAX_TIMEOUT + 1, "10", None, False])
def test_timeout_bounds_enforced(adapter, timeout):
    ok, errors = adapter.custom_parameter_validation({"operation": "sniff", "timeout": timeout})

    assert ok is False
    assert any("timeout" in e for e in errors)


def test_non_string_filter_rejected(adapter):
    ok, errors = adapter.custom_parameter_validation({"operation": "sniff", "filter": ["type", "mgt"]})

    assert ok is False
    assert any("filter" in e for e in errors)


def test_overlong_filter_rejected(adapter):
    ok, errors = adapter.custom_parameter_validation(
        {"operation": "sniff", "filter": "a" * (MAX_FILTER_LENGTH + 1)}
    )

    assert ok is False
    assert any("200" in e or "at most" in e for e in errors)


@pytest.mark.parametrize("bad", ["type mgt\n", "wlan\r0", "a\x00b"])
def test_filter_with_control_characters_rejected(adapter, bad):
    ok, errors = adapter.custom_parameter_validation({"operation": "sniff", "filter": bad})

    assert ok is False
    assert any("control" in e for e in errors)


def test_a_plain_bpf_filter_is_accepted(adapter):
    ok, errors = adapter.custom_parameter_validation(
        {"operation": "sniff", "filter": "type mgt and subtype deauth", "count": 50, "timeout": 5}
    )

    assert ok is True, errors


def test_empty_parameters_are_valid_and_default_to_version(adapter):
    ok, errors = adapter.custom_parameter_validation({})

    assert ok is True, errors


# --------------------------------------------------------------------------
# Scapy is a library, so requirements must be modelled as one
# --------------------------------------------------------------------------


def test_metadata_does_not_list_scapy_as_a_binary_dependency(adapter):
    """`dependencies` is checked by looking for an executable, which never matched."""
    assert "scapy" not in adapter.metadata.requirements.dependencies


def test_metadata_declares_the_declarative_inputs(adapter):
    assert "optional_script" not in adapter.metadata.inputs
    assert "optional_operation" in adapter.metadata.inputs


def test_requirement_check_verifies_importability(adapter):
    ok, reason = adapter.custom_requirement_check(None, {"operation": "version"})

    if SCAPY_AVAILABLE:
        assert ok is True, reason
    else:
        assert ok is False and "not importable" in reason


def test_sniff_requires_an_interface(adapter):
    ok, reason = adapter.custom_requirement_check(None, {"operation": "sniff"})

    assert ok is False
    assert "interface" in reason


def test_sniff_without_interface_fails_through_execute(adapter):
    result = adapter.execute(interface=None, parameters={"operation": "sniff"}, timeout=20)

    assert result.success is False
    assert "interface" in (result.failure_reason or "")


# --------------------------------------------------------------------------
# Legitimate use still works
# --------------------------------------------------------------------------


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy is an optional dependency")
def test_version_operation_reports_a_real_version(adapter):
    result = adapter.execute(interface=None, parameters={"operation": "version"}, timeout=20)

    assert result.success is True
    assert result.raw_output and result.raw_output != "unknown"
    assert result.evidences, "a successful run must produce evidence"


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy is an optional dependency")
def test_default_operation_is_version(adapter):
    result = adapter.execute(interface=None, parameters={}, timeout=20)

    assert result.success is True
    assert result.raw_output != "unknown"


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy is an optional dependency")
def test_a_capture_failure_is_reported_not_swallowed(adapter):
    """An interface that does not exist must surface as a failure."""
    result = adapter.execute(
        interface="wlan_absent_99",
        parameters={"operation": "sniff", "count": 1, "timeout": 1},
        timeout=20,
    )

    assert result.success is False
    assert result.failure_reason


def test_the_adapter_is_registered_and_reachable(adapter):
    assert isinstance(adapter, ScapyAdapter)
    assert ALLOWED_OPERATIONS


# --------------------------------------------------------------------------
# Validation order: the error contract must not depend on the environment
# --------------------------------------------------------------------------


def test_the_input_contract_is_checked_before_the_environment_probe(adapter, monkeypatch):
    """With Scapy absent *and* no interface, the interface error must win.

    Otherwise the failure reason depends on whether an optional extra happens to
    be installed. That is how two tests in this file came to fail under a plain
    ``pip install -e .`` while passing wherever scapy was present: the request was
    malformed, but the reported reason was the missing library.
    """
    import wifi_framework.tools.adapters.protocol.scapy_adapter as mod

    monkeypatch.setattr(mod, "find_spec", lambda _name: None)

    ok, reason = adapter.custom_requirement_check(None, {"operation": "sniff"})

    assert ok is False
    assert "interface" in reason
    assert "not importable" not in reason


def test_a_missing_library_is_still_reported_for_a_well_formed_request(adapter, monkeypatch):
    """Reordering must not hide a genuinely absent dependency."""
    import wifi_framework.tools.adapters.protocol.scapy_adapter as mod

    monkeypatch.setattr(mod, "find_spec", lambda _name: None)

    ok, reason = adapter.custom_requirement_check("wlan0", {"operation": "sniff"})

    assert ok is False
    assert "not importable" in reason


def test_execute_reports_the_interface_error_without_scapy_installed(adapter, monkeypatch):
    """The end-to-end path, in the environment where this used to fail."""
    import wifi_framework.tools.adapters.protocol.scapy_adapter as mod

    monkeypatch.setattr(mod, "find_spec", lambda _name: None)

    result = adapter.execute(interface=None, parameters={"operation": "sniff"}, timeout=20)

    assert result.success is False
    assert "interface" in (result.failure_reason or "")
