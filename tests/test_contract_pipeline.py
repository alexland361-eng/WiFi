"""
End-to-end tests of the contract pipeline with real subprocess execution.

The sandbox has no wireless hardware and no Kali toolchain, so these tests put a **stub binary**
on ``PATH`` and drive the *production* adapter, *production* parser, *production* execution
gateway and *production* policy through a real ``subprocess`` call. What is stubbed is the
external tool only - the framework code under test is the same code that runs on Kali.

Each stub records its own invocations, which lets these tests prove a negative: that a refused
action never reached the tool at all. Stubs answer version probes immediately and only do work
for the real subcommand, so the framework's availability checks stay fast.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from wifi_framework.contracts import (
    ActionObjective,
    ActionOrigin,
    ActionRequest,
    EntityRef,
    ExecutionStatus,
    FailureCategory,
    TargetType,
)
from wifi_framework.core.audit.logger import AuditLogger
from wifi_framework.core.engine.assessment_engine import BLOCK_COOLDOWN_ITERATIONS, AssessmentEngine
from wifi_framework.core.execution.gateway import ExecutionGateway
from wifi_framework.core.models.evidence import EvidenceType
from wifi_framework.core.models.scope import AssessmentScope

IN_SCOPE_BSSID = "AA:BB:CC:DD:EE:FF"
OUT_OF_SCOPE_BSSID = "11:22:33:44:55:66"
WLAN0_MAC = "00:11:22:33:44:55"
WLAN1_MAC = "66:77:88:99:AA:BB"

# Realistic `iw dev` output: this is what the production parser is written against.
IW_DEV_OUTPUT = """phy#0
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\taddr 00:11:22:33:44:55
\t\tssid TestNet
\t\ttype managed
\t\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
phy#1
\tInterface wlan1
\t\tifindex 5
\t\twdev 0x2
\t\taddr 66:77:88:99:aa:bb
\t\ttype monitor
\t\tchannel 11 (2462 MHz), width: 20 MHz, center1: 2462 MHz
"""


@pytest.fixture
def bin_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A directory on PATH for stub tools; created before the engine probes availability."""
    directory = tmp_path / "bin"
    directory.mkdir()
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ['PATH']}")
    return directory


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "run"
    (root / "audit").mkdir(parents=True)
    (root / "artifacts").mkdir(parents=True)
    return root


def write_stub(
    directory: Path,
    name: str,
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    delay: float = 0.0,
    subcommand: str | None = None,
) -> Path:
    """
    Create an executable stub tool that records every invocation.

    Version probes (``--version``, ``-v``, ``-V``, ``version``) exit immediately without doing
    any work: the framework probes several flags per tool, and a stub that slept on each would
    dominate the test runtime.
    """
    marker = directory / f"{name}.invoked"
    body: list[str] = []
    if stdout:
        # The heredoc terminator must start on its own line, so normalise the trailing newline.
        body.append(f"cat <<'STUB_EOF'\n{stdout.rstrip(chr(10))}\nSTUB_EOF")
    if stderr:
        body.append(f"cat <<'STUB_ERR' >&2\n{stderr.rstrip(chr(10))}\nSTUB_ERR")
    if delay:
        body.append(f"sleep {delay}")
    body.append(f"exit {exit_code}")
    work = "\n".join(body)
    guard = f'if [ "$1" = "{subcommand}" ]; then' if subcommand else "if true; then"
    script = f"""#!/bin/sh
printf '%s\\n' "invoked: $*" >> {marker}
case "$1" in
    --version|-v|-V|version) exit 0 ;;
esac
{guard}
{work}
fi
exit 0
"""
    path = directory / name
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def make_engine(workspace: Path, scope: AssessmentScope | None = None) -> AssessmentEngine:
    logger = AuditLogger(log_dir=str(workspace / "audit"))
    return AssessmentEngine(
        scope or AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID]),
        audit_logger=logger,
        artifact_dir=str(workspace / "artifacts"),
    )


def audit_events(workspace: Path) -> list[dict]:
    events: list[dict] = []
    for path in sorted((workspace / "audit").glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def event_types(workspace: Path) -> set[str]:
    return {event["event_type"] for event in audit_events(workspace)}


def invasive_request(engine: AssessmentEngine, action_id: str, bssid: str) -> ActionRequest:
    return ActionRequest(
        assessment_id=engine.state.id,
        action_id=action_id,
        capability="wireless_observation",
        implementation="aireplay-ng",
        interface="wlan0mon",
        parameters={"bssid": bssid, "action": "deauth"},
        objective=ActionObjective.RESOLVE_INFORMATION_GAP,
        target=EntityRef(type=TargetType.ACCESS_POINT.value, id=bssid),
        prepared=True,
        origin=ActionOrigin.PLANNER,
    )


# ------------------------------------------------------------------- happy path


def test_real_tool_execution_produces_a_complete_contract_chain(bin_dir, workspace, capsys):
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace)

    outcome = engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()

    result = outcome.result
    assert result.status == ExecutionStatus.SUCCESS
    assert result.succeeded is True
    assert result.exit_code == 0
    assert result.command == ["iw", "dev"]
    assert result.tool.name == "iw"
    assert result.action_id
    assert result.validate().ok, result.validate().error_messages

    # The real parser produced real observations from real tool output.
    assert outcome.evidences
    assert all(item.evidence_type == EvidenceType.INTERFACE for item in outcome.evidences)
    assert {item.parsed_data["name"] for item in outcome.evidences} == {"wlan0", "wlan1"}
    monitor = next(item for item in outcome.evidences if item.parsed_data["name"] == "wlan1")
    assert monitor.parsed_data["type"] == "monitor"
    assert monitor.parsed_data["mac"] == WLAN1_MAC
    assert monitor.parsed_data["channel"] == 11

    # Evidence reached the World Model, bound to the action that produced it.
    assert engine.state.evidences
    assert all(item.action_id == result.action_id for item in engine.state.evidences)
    assert engine.state.execution_history[-1].action_id == result.action_id
    assert engine.state.execution_history[-1].status == ExecutionStatus.SUCCESS


def test_artifacts_are_written_to_disk_and_hashed(bin_dir, workspace, capsys):
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace)

    outcome = engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()
    result = outcome.result

    assert result.artifacts
    stdout_artifact = next(item for item in result.artifacts if item.kind == "stdout")
    assert Path(stdout_artifact.path).is_file()
    content = Path(stdout_artifact.path).read_text()
    assert "Interface wlan0" in content
    assert stdout_artifact.bytes == len(content.encode("utf-8"))
    assert stdout_artifact.sha256 == hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert stdout_artifact.truncated is False
    assert result.stdout_artifact == stdout_artifact.id


def test_stub_tool_was_actually_invoked(bin_dir, workspace, capsys):
    """Guards the test itself: the pipeline must reach a real subprocess."""
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace)
    engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()

    marker = bin_dir / "iw.invoked"
    assert marker.is_file()
    assert "dev" in marker.read_text()


def test_pipeline_emits_every_contract_into_the_audit_trail(bin_dir, workspace, capsys):
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace)
    engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()

    types = event_types(workspace)
    assert "contract:action-request" in types
    assert "contract:action-validation-result" in types
    assert "contract:execution-result" in types
    assert "contract:evidence-set" in types
    assert "contract:experience-record" in types
    assert "contract:world-state" in types
    assert "execution" in types


def test_experience_record_scores_a_successful_observation(bin_dir, workspace, capsys):
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace)
    engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()

    records = [
        event for event in audit_events(workspace) if event["event_type"] == "contract:experience-record"
    ]
    assert records
    summary = records[-1]["data"].get("summary", {})
    # Two new interface observations: gain = saturation(2) * the success status factor.
    assert summary["new_observations"] == 2
    assert summary["information_gain"] > 0.0
    assert summary["useful"] is True


def test_published_world_state_reflects_the_real_observation(bin_dir, workspace, capsys):
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace)
    engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()

    published = engine.publish_world_state(force=True)
    assert published.validate().ok
    assert published.observations
    # An interface observation is identified by its hardware address; the name travels in
    # provenance, which is what makes the observation traceable back to the interface.
    assert {obs.subject_id for obs in published.observations} == {
        WLAN0_MAC.upper(),
        WLAN1_MAC,
    }
    assert {obs.provenance.interface for obs in published.observations} == {"wlan0", "wlan1"}
    assert published.channels_observed == [6, 11]


def test_correlation_chain_links_action_to_execution_to_evidence(bin_dir, workspace, capsys):
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace)
    outcome = engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()

    chains = AuditLogger.correlation_chains(engine.state)
    assert chains
    chain = next(item for item in chains if item["execution_id"] == outcome.result.execution_id)
    assert chain["action_id"] == outcome.result.action_id
    assert chain["assessment_id"] == engine.state.id
    assert chain["status"] == ExecutionStatus.SUCCESS
    assert len(chain["evidence_ids"]) == 2
    assert chain["artifact_ids"]


# ------------------------------------------------------------------ failure paths


def test_nonzero_exit_is_reported_as_failure_never_success(bin_dir, workspace, capsys):
    write_stub(
        bin_dir,
        "iw",
        stderr="iw: unknown option -- bogus",
        exit_code=3,
        subcommand="dev",
    )
    engine = make_engine(workspace)

    outcome = engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()
    result = outcome.result

    assert result.status == ExecutionStatus.FAILED
    assert result.succeeded is False
    assert result.exit_code == 3
    assert result.failure is not None
    assert result.failure.category == FailureCategory.TOOL_ERROR
    assert result.failure.details["exit_code"] == 3
    # A failed run yields no observations: nothing is invented to fill the gap.
    assert outcome.evidences == []


def test_permission_failure_is_attributed_to_privileges(bin_dir, workspace, capsys):
    """A real `iw` failing with EPERM is a privileges problem, and must be reported as one."""
    write_stub(
        bin_dir,
        "iw",
        stderr="command failed: Operation not permitted",
        exit_code=1,
        subcommand="dev",
    )
    engine = make_engine(workspace)

    outcome = engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()

    assert outcome.result.status == ExecutionStatus.FAILED
    assert outcome.result.failure.category == FailureCategory.INSUFFICIENT_PRIVILEGES


def test_timeout_is_reported_as_a_timeout(bin_dir, workspace, capsys):
    write_stub(bin_dir, "iw", delay=10, subcommand="dev")
    engine = make_engine(workspace)

    outcome = engine.run_discovery_action("iw_dev", timeout=1)
    capsys.readouterr()
    result = outcome.result

    assert result.status == ExecutionStatus.TIMEOUT
    assert result.exit_code == 124
    assert result.failure.category == FailureCategory.TIMEOUT
    assert result.failure.retriable is True
    assert outcome.evidences == []
    assert result.duration_ms >= 1000


def test_partial_output_survives_a_timeout_at_the_subprocess_level():
    """
    ``subprocess`` *does* return output written before a timeout kill, so a stopped run is not
    automatically output-free. Whether that output reaches the World Model is the adapter's
    decision (see the next test), and capture tools that write to files - ``airodump-ng --write``,
    ``hcxdumptool`` - are how partial output reaches the pipeline in practice.
    """
    from wifi_framework.utils.system import run_command

    exit_code, stdout, stderr, _duration = run_command(["sh", "-c", "echo partial; sleep 5"], timeout=1)
    assert exit_code == 124
    assert stdout.strip() == "partial"
    assert "timed out" in stderr


def test_timed_out_iw_reports_timeout_because_the_adapter_will_not_parse_a_failed_run(
    bin_dir, workspace, capsys
):
    """
    The tool emitted real interface data before being stopped, yet the result is ``timeout``,
    not ``partial``: ``IwDevAdapter.parse_output`` returns nothing when the exit code is
    non-zero. Reporting observations from a run the adapter itself refused to interpret would
    be presenting unvalidated output as evidence.
    """
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, delay=10, subcommand="dev")
    engine = make_engine(workspace)

    outcome = engine.run_discovery_action("iw_dev", timeout=1)
    capsys.readouterr()

    assert outcome.result.status == ExecutionStatus.TIMEOUT
    assert outcome.result.exit_code == 124
    assert outcome.evidences == []
    assert engine.state.evidences == []


@dataclass
class _LegacyExecution:
    """Stand-in for the executor's result record, used to pin the classification rule."""

    raw_command: str = "airodump-ng -i wlan0mon"
    success: bool = False
    exit_code: int | None = 124
    evidences: list = field(default_factory=list)
    failure_reason: str | None = "Command timed out after 30s"
    duration: float = 30.0


def test_classification_rule_separates_partial_from_timeout():
    """A stopped run that produced real observations is partial; one that produced none is a timeout."""
    classify = ExecutionGateway._classify

    status, failure, warnings = classify(_LegacyExecution(evidences=["obs-1"]), [])
    assert status == ExecutionStatus.PARTIAL
    assert failure.category == FailureCategory.TIMEOUT
    assert failure.retriable is True
    assert any("stopped by the timeout" in warning for warning in warnings)

    status, failure, _ = classify(_LegacyExecution(evidences=[]), [])
    assert status == ExecutionStatus.TIMEOUT
    assert failure.category == FailureCategory.TIMEOUT

    status, failure, _ = classify(_LegacyExecution(raw_command=""), [])
    assert status == ExecutionStatus.UNSUPPORTED
    assert failure.retriable is bool(failure.category in FailureCategory.RETRIABLE)


def test_malformed_output_produces_no_invented_observations(bin_dir, workspace, capsys):
    write_stub(bin_dir, "iw", stdout="this is not iw output at all\n", subcommand="dev")
    engine = make_engine(workspace)

    outcome = engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()

    assert outcome.result.status == ExecutionStatus.SUCCESS
    # The run succeeded but the parser found nothing to report: that is the honest result.
    assert outcome.evidences == []
    assert engine.state.evidences == []


# ------------------------------------------------------------------- refusals


def test_missing_tool_is_unsupported_and_reports_no_exit_code(bin_dir, workspace, capsys):
    engine = make_engine(workspace)

    outcome = engine.run_discovery_action("airodump-ng", timeout=10)
    capsys.readouterr()
    result = outcome.result

    assert result.status == ExecutionStatus.UNSUPPORTED
    assert result.exit_code is None
    # The missing binary is the fundamental blocker, not the absent interface.
    assert result.failure.category == FailureCategory.TOOL_NOT_FOUND
    # The wording is load-bearing, not cosmetic: the gateway classifies failure
    # reasons by substring, and "not found in PATH" is the token that maps to
    # TOOL_NOT_FOUND. Asserting the token keeps this test coupled to the contract
    # between resolve_binary's message and the classifier.
    assert "not found in PATH" in result.failure.message
    assert "airodump-ng" in result.failure.message
    assert outcome.evidences == []


def test_missing_tool_blocks_the_capability_permanently(bin_dir, workspace, capsys):
    engine = make_engine(workspace)
    engine.run_discovery_action("airodump-ng", timeout=10)
    capsys.readouterr()

    blocked = engine.state.extra["blocked_capabilities"]["airodump-ng"]
    assert blocked["permanent"] is True
    # The refusal came from preparation (the gateway would not resolve an invocation).
    assert blocked["stage"] == "prepare"
    assert blocked["action_id"]


def test_blocked_capability_is_projected_out_of_the_planning_view(bin_dir, workspace, capsys):
    """
    A refusal is environmental information: the Decision Engine plans from a view in which the
    refused capability is unavailable, while the published record of the environment is unchanged.
    """
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace)
    engine.discover_capabilities()
    engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()

    published = engine.publish_world_state(force=True)
    assert "iw_dev" in [item.name for item in published.available_capabilities()]

    engine.block_capability(
        ActionRequest(
            assessment_id=engine.state.id,
            action_id="action-block",
            capability="wireless_interface",
            implementation="iw_dev",
        ),
        stage="scope",
        reason="interface is outside the authorised scope",
        permanent=True,
    )

    planning_view = engine.world_state_for_planning(published)
    assert "iw_dev" not in [item.name for item in planning_view.available_capabilities()]
    projected = planning_view.capability("iw_dev")
    assert projected is not None
    assert projected.available is False
    assert "blocked by policy (scope)" in projected.reason
    # The projection is a view: the underlying published record still says the tool exists.
    assert published.capability("iw_dev").available is True


def test_transient_block_expires_after_the_cooldown(bin_dir, workspace, capsys):
    """A retriable refusal is suppressed briefly, then offered again in case circumstances changed."""
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace)
    engine.discover_capabilities()
    engine.run_discovery_action("iw_dev", timeout=15)
    capsys.readouterr()
    published = engine.publish_world_state(force=True)
    assert "iw_dev" in [item.name for item in published.available_capabilities()]

    engine.block_capability(
        ActionRequest(
            assessment_id=engine.state.id,
            action_id="action-cooldown",
            capability="wireless_interface",
            implementation="iw_dev",
        ),
        stage="capability",
        reason="interface is down",
        permanent=False,
    )

    names = lambda view: [item.name for item in view.available_capabilities()]  # noqa: E731
    assert "iw_dev" not in names(engine.world_state_for_planning(published, iteration=1))
    assert "iw_dev" not in names(engine.world_state_for_planning(published, iteration=BLOCK_COOLDOWN_ITERATIONS))
    # Past the cooldown the capability is offered to the Decision Engine again.
    assert "iw_dev" in names(engine.world_state_for_planning(published, iteration=BLOCK_COOLDOWN_ITERATIONS + 2))


def test_out_of_scope_invasive_action_never_reaches_the_tool(bin_dir, workspace, capsys):
    """
    The strongest scope guarantee: the tool exists and would run, but policy refuses first.

    The stub records every invocation, so the absence of its marker proves non-execution rather
    than relying on a status string.
    """
    write_stub(bin_dir, "aireplay-ng", stdout="deauth sent\n")
    engine = make_engine(workspace, AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID]))

    outcome = engine.execute_action_request(invasive_request(engine, "action-scope-test", OUT_OF_SCOPE_BSSID))
    capsys.readouterr()

    assert outcome.result.status == ExecutionStatus.REJECTED
    assert outcome.result.exit_code is None
    assert outcome.result.scope_authorised is False
    assert not (bin_dir / "aireplay-ng.invoked").exists()
    assert outcome.evidences == []


def test_scope_refusal_blocks_the_capability_without_retry(bin_dir, workspace, capsys):
    write_stub(bin_dir, "aireplay-ng")
    engine = make_engine(workspace, AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID]))

    engine.execute_action_request(invasive_request(engine, "action-scope-block", OUT_OF_SCOPE_BSSID))
    capsys.readouterr()

    blocked = engine.state.extra["blocked_capabilities"]["aireplay-ng"]
    assert blocked["permanent"] is True
    assert blocked["stage"] == "scope"


def test_in_scope_invasive_action_passes_the_scope_gate(bin_dir, workspace, capsys):
    """The same request against an authorised target clears scope and is then judged on
    capability and privileges - which here fails honestly rather than silently."""
    write_stub(bin_dir, "aireplay-ng")
    engine = make_engine(workspace, AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID]))

    outcome = engine.execute_action_request(invasive_request(engine, "action-in-scope", IN_SCOPE_BSSID))
    capsys.readouterr()

    assert outcome.validation is not None
    scope_check = next(check for check in outcome.validation.checks if check.type == "scope")
    assert scope_check.status == "passed"
    assert outcome.result.status != ExecutionStatus.REJECTED


def test_unsafe_parameter_is_refused_before_execution(bin_dir, workspace, capsys):
    write_stub(bin_dir, "airodump-ng")
    engine = make_engine(workspace)
    engine.state.available_capabilities["airodump-ng"] = engine.registry.get_metadata("airodump-ng")

    request = ActionRequest(
        assessment_id=engine.state.id,
        action_id="action-injection",
        capability="wireless_observation",
        implementation="airodump-ng",
        interface="wlan0mon",
        parameters={"bssid": IN_SCOPE_BSSID, "ssid": "-e TestNet --write /etc/passwd"},
        objective=ActionObjective.RESOLVE_INFORMATION_GAP,
        target=EntityRef(type=TargetType.ACCESS_POINT.value, id=IN_SCOPE_BSSID),
        prepared=True,
    )
    outcome = engine.execute_action_request(request, timeout=10)
    capsys.readouterr()

    assert outcome.result.status == ExecutionStatus.REJECTED
    assert outcome.result.exit_code is None
    assert outcome.validation.rejection["code"] == "argument_injection_risk"
    assert not (bin_dir / "airodump-ng.invoked").exists()


def test_refusal_is_audited_with_its_reason(bin_dir, workspace, capsys):
    write_stub(bin_dir, "aireplay-ng")
    engine = make_engine(workspace, AssessmentScope(authorized_bssids=[IN_SCOPE_BSSID]))

    engine.execute_action_request(invasive_request(engine, "action-audit-refusal", OUT_OF_SCOPE_BSSID))
    capsys.readouterr()

    refusals = [event for event in audit_events(workspace) if event["event_type"] == "action_rejected"]
    assert refusals
    assert refusals[-1]["data"]["stage"] == "scope"
    assert refusals[-1]["data"]["reason"]["code"] == "scope_denied_wireless"


# ------------------------------------------------------------------- whole loop


def test_full_assessment_loop_runs_on_a_stubbed_toolchain(bin_dir, workspace, capsys):
    """
    The complete adaptive loop against a stubbed tool: observe, model, plan, execute, gather
    evidence, verify, re-evaluate, report - with every execution traceable to an action.
    """
    write_stub(bin_dir, "iw", stdout=IW_DEV_OUTPUT, subcommand="dev")
    engine = make_engine(workspace, AssessmentScope(authorized_ssids=["TestNet"]))

    engine.run(max_iterations=3)
    capsys.readouterr()

    report = engine.audit_logger.generate_report(engine.state)
    assert report["contracts"]
    assert report["contracts"]["world-state"]["producer"] == "world_model"

    chains = report["correlation_chains"]
    assert chains
    # Every recorded execution is attributable to the action that caused it.
    assert all(chain["action_id"] for chain in chains)
    assert any(record.status == ExecutionStatus.SUCCESS for record in engine.state.execution_history)
    assert engine.state.evidences

    published = engine.publish_world_state(force=True)
    assert published.validate().ok


def test_loop_without_any_tool_completes_without_fabricating(bin_dir, workspace, capsys):
    """No wireless tooling at all: the loop must complete and report an empty world, not invent one."""
    engine = make_engine(workspace)
    engine.run(max_iterations=3)
    capsys.readouterr()

    assert engine.state.world_model.access_points == {}
    assert engine.state.evidences == []
    assert engine.state.findings == []
    assert engine.state.unavailable_capabilities
    assert engine.state.phase.value in ("completed", "reporting", "failed")


# ------------------------------------------------------- recorded command fidelity
#
# contracts/execution.py promises the recorded command "is exactly what was passed
# to subprocess.run and can be re-run by an auditor without reinterpretation".
# These pin that promise; the pre-existing `assert result.command == ["iw", "dev"]`
# passed with the bug present because no argument contained whitespace.


def test_a_recorded_command_preserves_an_ssid_containing_a_space():
    from wifi_framework.core.execution.adapter_base import AdapterExecutionResult
    from wifi_framework.core.execution.gateway import recorded_command
    from wifi_framework.tools.adapters.capture.termshark import AIRBASE_METADATA, AirbaseNgAdapter

    adapter = AirbaseNgAdapter(AIRBASE_METADATA)
    cmd = adapter.build_command("wlan0", {"essid": "Office Network"})

    # SSIDs with spaces are ordinary; airbase-ng takes one as an argument.
    assert cmd == ["airbase-ng", "-e", "Office Network", "wlan0"]

    result = AdapterExecutionResult(success=True, raw_command=" ".join(cmd), argv=cmd)
    assert recorded_command(result) == cmd

    # The lossy reconstruction this replaces: the recorded command would have been
    # ['airbase-ng', '-e', 'Office', 'Network', 'wlan0'], which cannot be re-run.
    assert result.raw_command.split() == ["airbase-ng", "-e", "Office", "Network", "wlan0"]
    assert result.raw_command.split() != cmd


def test_recorded_command_does_not_fabricate_an_argv_for_a_library_adapter():
    """An empty argv means no subprocess ran; a description is not a command.

    The Scapy adapter calls a library and stores prose such as
    "scapy sniff iface=wlan0 count=10" in `raw_command`. Splitting that would put
    an invocation in the audit trail that was never executed.
    """
    from wifi_framework.core.execution.adapter_base import AdapterExecutionResult
    from wifi_framework.core.execution.gateway import recorded_command

    result = AdapterExecutionResult(
        success=True, raw_command="scapy sniff iface=wlan0 count=10 timeout=5", argv=[]
    )

    assert recorded_command(result) == []


def test_recorded_command_falls_back_for_results_predating_argv():
    from wifi_framework.core.execution.gateway import recorded_command

    class _LegacyResult:
        raw_command = "iw dev"

    assert recorded_command(_LegacyResult()) == ["iw", "dev"]


def test_execute_populates_argv_with_the_vector_it_actually_ran():
    """`argv` must be the list handed to subprocess, not a reconstruction."""
    from wifi_framework.core.execution.adapter_base import AdapterExecutionResult, ToolAdapterBase
    from wifi_framework.core.models.capability import (
        CapabilityRequirements,
        OperatingSystem,
        ToolCapabilityMetadata,
    )

    class _EchoSpaceAdapter(ToolAdapterBase):
        def build_command(self, interface, parameters):
            return ["echo", parameters["message"]]

        def parse_output(self, raw_output, error_output, exit_code, parameters, interface):
            return []

    adapter = _EchoSpaceAdapter(
        ToolCapabilityMetadata(
            name="echo_space_probe",
            display_name="Echo space probe",
            category=None,
            description="test stub",
            tool_binary="echo",
            requirements=CapabilityRequirements(operating_systems=[OperatingSystem.LINUX]),
        )
    )

    result = adapter.execute(parameters={"message": "Office Network"}, timeout=10)

    assert result.success is True, result.failure_reason
    assert result.argv == ["echo", "Office Network"]
    assert result.raw_output.strip() == "Office Network"
    assert result.raw_command.split() != result.argv


def test_a_failure_path_still_records_the_command_it_attempted():
    """argv must be populated on failure too, or an auditor cannot see what ran."""
    from wifi_framework.core.execution.adapter_base import ToolAdapterBase
    from wifi_framework.core.models.capability import (
        CapabilityRequirements,
        OperatingSystem,
        ToolCapabilityMetadata,
    )

    class _FailingAdapter(ToolAdapterBase):
        def build_command(self, interface, parameters):
            return ["false", "Office Network"]

        def parse_output(self, raw_output, error_output, exit_code, parameters, interface):
            return []

    adapter = _FailingAdapter(
        ToolCapabilityMetadata(
            name="false_space_probe",
            display_name="Failing probe",
            category=None,
            description="test stub",
            tool_binary="false",
            requirements=CapabilityRequirements(operating_systems=[OperatingSystem.LINUX]),
        )
    )

    result = adapter.execute(parameters={}, timeout=10)

    assert result.success is False
    assert result.argv == ["false", "Office Network"]
