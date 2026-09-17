"""
Tests for the CLI's scope construction: the path from operator input to authorization.

This module was entirely untested, and it is where a human's intent becomes the scope the
framework enforces. The defect that lived here - a `--config` file whose entries never
reached the compiled matchers - made the framework refuse invasive actions against assets
the operator had explicitly authorized, while passive discovery still appeared to work.
"""
from __future__ import annotations

import importlib
import sys

import pytest

from wifi_framework.core.models.scope import ScopeEnforcer

#: `from wifi_framework.cli import main` binds the *function* the package re-exports, not
#: the module, so the module is fetched explicitly.
cli = importlib.import_module("wifi_framework.cli.main")

CONFIG = """\
authorized_ssids:
  - MyNetwork
authorized_bssids:
  - AA:BB:CC:DD:EE:FF
authorized_networks:
  - 10.0.0.0/24
description: config-driven scope
"""


def _write(tmp_path, text, name="scope.yaml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# ------------------------------------------------------- parser <-> loader coupling


def test_parser_defaults_supply_every_attribute_the_scope_loader_reads():
    """`load_scope_from_args` reads eight attributes off the namespace. Nothing connects
    them to the parser but matching names, and `--network`/`--host` are stored under
    different dests, so a renamed flag would surface as an AttributeError at run time
    rather than at parse time."""
    args = cli.create_parser().parse_args([])

    for name in (
        "ssid",
        "bssid",
        "channel",
        "networks",
        "hosts",
        "scope_description",
        "strict",
        "config",
    ):
        assert hasattr(args, name), f"load_scope_from_args reads args.{name}, which the parser does not define"


def test_the_list_flags_default_to_empty_rather_than_none():
    """The loader concatenates these, so a None default would be a TypeError."""
    args = cli.create_parser().parse_args([])
    assert args.ssid == [] and args.bssid == [] and args.channel == []
    assert args.networks == [] and args.hosts == []


# ------------------------------------------------------------------ scope from args


def test_a_scope_from_arguments_compiles_its_matchers():
    args = cli.create_parser().parse_args(
        ["--ssid", "MyNetwork", "--bssid", "AA:BB:CC:DD:EE:FF", "--network", "10.0.0.0/24"]
    )
    scope = cli.load_scope_from_args(args)

    assert scope._ssid_patterns, "SSID patterns were not compiled"
    assert scope._bssid_set == {"AA:BB:CC:DD:EE:FF"}
    assert [str(network) for network in scope._network_objects] == ["10.0.0.0/24"]


def test_a_scope_from_arguments_authorizes_what_the_operator_listed():
    args = cli.create_parser().parse_args(
        ["--ssid", "MyNetwork", "--bssid", "AA:BB:CC:DD:EE:FF", "--network", "10.0.0.0/24"]
    )
    scope = cli.load_scope_from_args(args)
    enforcer = ScopeEnforcer(scope)

    allowed, _ = enforcer.check_wireless_action_allowed(
        "MyNetwork", "AA:BB:CC:DD:EE:FF", invasive=True
    )
    assert allowed

    refused, _ = enforcer.check_wireless_action_allowed(
        "Neighbour", "11:22:33:44:55:66", invasive=True
    )
    assert not refused

    assert scope.is_ip_authorized("10.0.0.5") is True
    assert scope.is_ip_authorized("11.0.0.5") is False


def test_repeated_arguments_accumulate():
    args = cli.create_parser().parse_args(
        ["--ssid", "One", "--ssid", "Two", "--channel", "1", "--channel", "6"]
    )
    scope = cli.load_scope_from_args(args)

    assert scope.authorized_ssids == ["One", "Two"]
    assert scope.authorized_channels == [1, 6]


def test_the_strict_flag_reaches_the_scope():
    args = cli.create_parser().parse_args(["--ssid", "MyNetwork", "--strict"])
    assert cli.load_scope_from_args(args).strict_mode is True

    args = cli.create_parser().parse_args(["--ssid", "MyNetwork"])
    assert cli.load_scope_from_args(args).strict_mode is False


# --------------------------------------------------------------- scope from config


def test_a_scope_from_a_config_file_authorizes_what_the_operator_wrote(tmp_path):
    """The regression this file exists for. The scope used to be constructed empty and
    then extended from the config, but `AssessmentScope` compiles its matchers in
    `__post_init__`, so config entries landed in the public lists and never in the
    matchers the authorization checks read."""
    args = cli.create_parser().parse_args(["--config", _write(tmp_path, CONFIG)])
    scope = cli.load_scope_from_args(args)

    assert scope._ssid_patterns, "config SSIDs were never compiled into matchers"
    assert scope._bssid_set == {"AA:BB:CC:DD:EE:FF"}
    assert [str(network) for network in scope._network_objects] == ["10.0.0.0/24"]

    enforcer = ScopeEnforcer(scope)
    allowed, reason = enforcer.check_wireless_action_allowed(
        "MyNetwork", "AA:BB:CC:DD:EE:FF", invasive=True
    )
    assert allowed, f"an asset the operator authorized in the config was refused: {reason}"

    assert scope.is_ip_authorized("10.0.0.5") is True, (
        "a network the operator authorized in the config refused every action against it"
    )
    assert scope.is_ip_authorized("11.0.0.5") is False


def test_arguments_and_config_are_merged(tmp_path):
    args = cli.create_parser().parse_args(
        ["--ssid", "FromArgs", "--network", "192.168.0.0/24", "--config", _write(tmp_path, CONFIG)]
    )
    scope = cli.load_scope_from_args(args)

    assert scope.authorized_ssids == ["FromArgs", "MyNetwork"]
    assert scope.authorized_networks == ["192.168.0.0/24", "10.0.0.0/24"]
    # Both sources are compiled, not just the arguments.
    assert len(scope._ssid_patterns) == 2
    assert len(scope._network_objects) == 2
    assert scope.is_ip_authorized("192.168.0.9") is True
    assert scope.is_ip_authorized("10.0.0.9") is True


def test_the_config_description_wins_over_the_argument(tmp_path):
    args = cli.create_parser().parse_args(
        ["--scope-description", "from args", "--config", _write(tmp_path, CONFIG)]
    )
    assert cli.load_scope_from_args(args).description == "config-driven scope"


def test_the_argument_description_is_kept_when_the_config_has_none(tmp_path):
    args = cli.create_parser().parse_args(
        [
            "--scope-description",
            "from args",
            "--config",
            _write(tmp_path, "authorized_ssids:\n  - MyNetwork\n"),
        ]
    )
    assert cli.load_scope_from_args(args).description == "from args"


def test_an_empty_config_file_yields_an_empty_scope(tmp_path):
    args = cli.create_parser().parse_args(["--config", _write(tmp_path, "")])
    scope = cli.load_scope_from_args(args)

    assert scope.authorized_ssids == []
    assert scope.validate() == []


def test_a_config_that_is_not_a_mapping_is_refused(tmp_path):
    args = cli.create_parser().parse_args(["--config", _write(tmp_path, "- just\n- a\n- list\n")])

    with pytest.raises(SystemExit):
        cli.load_scope_from_args(args)


def test_a_config_key_holding_a_string_is_refused_rather_than_split(tmp_path, capsys):
    """`list.extend` on a string iterates its characters, so
    `authorized_ssids: MyNetwork` would have authorized 'M', 'y', 'N' ... - a scope that
    matches nothing while looking like it parsed correctly."""
    args = cli.create_parser().parse_args(
        ["--config", _write(tmp_path, "authorized_ssids: MyNetwork\n")]
    )

    with pytest.raises(SystemExit):
        cli.load_scope_from_args(args)

    error = capsys.readouterr().err
    assert "must be a list" in error
    assert "MyNetwork" in error


def test_a_malformed_config_entry_is_reported_by_validation(tmp_path, capsys):
    """`validate()` reports what was dropped at construction. Because the config is now
    merged before construction, a malformed entry in it is caught - which it was not when
    the entries were appended afterwards."""
    args = cli.create_parser().parse_args(
        ["--config", _write(tmp_path, "authorized_networks:\n  - not-a-network\n")]
    )

    with pytest.raises(SystemExit):
        cli.load_scope_from_args(args)

    error = capsys.readouterr().err
    assert "Invalid network CIDR: not-a-network" in error


def test_an_unrecognized_config_key_is_reported_but_not_fatal(tmp_path, capsys):
    """A typo like `authorized_ssid` silently narrows the authorization the operator
    believes they granted, so it is reported - but a combined config file carrying other
    sections is legitimate, so it is not refused."""
    args = cli.create_parser().parse_args(
        ["--config", _write(tmp_path, "authorized_ssid:\n  - MyNetwork\n")]
    )
    scope = cli.load_scope_from_args(args)

    assert scope.authorized_ssids == [], "an unrecognized key was silently treated as a known one"
    error = capsys.readouterr().err
    assert "Ignoring unrecognized scope config keys: authorized_ssid" in error


def test_a_missing_config_file_exits_with_the_reason(tmp_path, capsys):
    args = cli.create_parser().parse_args(["--config", str(tmp_path / "absent.yaml")])

    with pytest.raises(SystemExit):
        cli.load_scope_from_args(args)
    assert "Failed to load config" in capsys.readouterr().err


# ----------------------------------------------------------------------- main() dispatch


def test_list_interfaces_returns_without_loading_a_scope(monkeypatch, capsys):
    """A read-only listing must not require a scope, and must not exit non-zero."""
    monkeypatch.setattr(sys, "argv", ["wifi-framework", "--list-interfaces"])
    cli.main()

    assert "System Interfaces" in capsys.readouterr().out


def test_main_warns_the_operator_when_no_scope_is_defined(tmp_path, monkeypatch, capsys):
    """Running with no authorized scope permits broadcast discovery of everything, so the
    operator is told rather than silently given the widest possible reading."""
    from wifi_framework.core.models.assessment_state import AssessmentState

    monkeypatch.setattr(sys, "argv", ["wifi-framework", "--output", str(tmp_path)])

    seen = {}

    class StubEngine:
        def __init__(self, scope=None, registry=None, audit_logger=None, experience_store=None):
            seen["scope"] = scope

        def run(self, **kwargs):
            seen["run"] = kwargs
            return AssessmentState()

    monkeypatch.setattr(cli, "AssessmentEngine", StubEngine)
    cli.main()

    output = capsys.readouterr().out
    assert "No authorized scope defined" in output
    assert seen["scope"].authorized_ssids == []
    assert seen["run"]["max_iterations"] == 30, "the parser default did not reach the engine"


def test_main_passes_the_loaded_scope_to_the_engine(tmp_path, monkeypatch):
    from wifi_framework.core.models.assessment_state import AssessmentState

    monkeypatch.setattr(
        sys,
        "argv",
        ["wifi-framework", "--ssid", "MyNetwork", "--network", "10.0.0.0/24", "--output", str(tmp_path)],
    )

    seen = {}

    class StubEngine:
        def __init__(self, scope=None, registry=None, audit_logger=None, experience_store=None):
            seen["scope"] = scope

        def run(self, **kwargs):
            return AssessmentState()

    monkeypatch.setattr(cli, "AssessmentEngine", StubEngine)
    cli.main()

    scope = seen["scope"]
    assert scope.authorized_ssids == ["MyNetwork"]
    assert scope._ssid_patterns, "the engine received a scope whose matchers were never compiled"
    assert scope.is_ip_authorized("10.0.0.5") is True
