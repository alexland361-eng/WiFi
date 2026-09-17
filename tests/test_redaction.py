"""Redaction of operator secrets on the persistence boundary.

The adapters put secrets directly into command lines - `aircrack-ng` a passphrase,
`reaver` a WPS PIN, Impacket `user:pass@host`, `smbclient` `user%password`,
`snmpwalk` a community string. Persisted verbatim, the audit trail becomes a
credential file. These tests pin what is masked, what is deliberately not, and that
the trail still says what ran.
"""
from __future__ import annotations

import json
import re

import pytest

from wifi_framework.utils.redaction import (
    MIN_SUBSTITUTE_LENGTH,
    NOT_SENSITIVE,
    REDACTED,
    is_sensitive_name,
    normalize_name,
    redact,
    redact_with_report,
)

SECRET = "Sup3rSecret!"


# ------------------------------------------------------------------ name matching


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "passwd",
        "passphrase",
        "psk",
        "key",
        "wpa_key",
        "session_key",
        "private_key",
        "user_password",
        "pin",
        "wps_pin",
        "authkey",
        "community",
        "snmp_community",
        "secret",
        "token",
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "hash",
        "PASSWORD",
        "  Passphrase  ",
        "pass-key",
    ],
)
def test_secret_bearing_names_are_recognised(name):
    assert is_sensitive_name(name), f"{name!r} was not treated as sensitive"


@pytest.mark.parametrize(
    "name",
    [
        # Real parameter names used by the adapters that must survive intact.
        "passive",          # netdiscover: listen instead of probe - a boolean
        "hash_file",        # john/hashcat: a path, not a hash
        "wordlist",         # a path
        "potfile_disable",  # a hashcat flag
        "input_file",
        "capture_file",
        "fragment_file",
        "keyspace",
        "e_nonce",          # pixiewps: captured from a frame sent in the clear
        "r_nonce",
        "e_hash1",
        "e_hash2",
        "pke",
        "pkr",
        # Ordinary parameters.
        "ssid",
        "bssid",
        "essid",
        "interface",
        "channel",
        "target",
        "target_ip",
        "user",
        "username",
        "monkey",
        "keyboard",
        "passenger",
        "duration",
        "timeout",
    ],
)
def test_non_secret_names_are_left_alone(name):
    """Over-masking is a real failure mode: it destroys the auditability the
    framework exists to provide. `passive` contains `pass`; `keyspace` and `monkey`
    contain `key`. Matching is on whole tokens precisely so these survive."""
    assert not is_sensitive_name(name), f"{name!r} was masked and should not be"


def test_unusable_names_are_not_sensitive():
    for name in [None, 42, "", "   ", [], {}]:
        assert is_sensitive_name(name) is False


def test_normalize_name_strips_separators():
    assert normalize_name("WPA-Key") == "wpakey"
    assert normalize_name("  pass_word ") == "password"
    assert normalize_name(None) == ""


def test_the_documented_exclusions_are_the_exclusions_in_code():
    """`NOT_SENSITIVE` is the reviewable statement of what was deliberately left
    unmasked. If it drifts from the names above, one of the two is wrong."""
    for name in ("passive", "hash_file", "wordlist", "keyspace"):
        assert name in NOT_SENSITIVE


# ------------------------------------------------------------------- value masking


def test_a_secret_field_is_masked():
    out = redact({"parameters": {"password": SECRET, "target": "10.0.0.1"}})
    assert out["parameters"]["password"] == REDACTED
    assert out["parameters"]["target"] == "10.0.0.1"


def test_a_secret_is_masked_inside_a_command_line_and_an_argv():
    structure = {
        "parameters": {"password": SECRET},
        "raw_command": f"aircrack-ng -w /usr/share/wordlist.txt -e Office {SECRET} capture.pcap",
        "command": ["aircrack-ng", "-w", "/usr/share/wordlist.txt", "-e", "Office", SECRET],
    }
    out = redact(structure)
    assert SECRET not in out["raw_command"]
    assert SECRET not in out["command"]
    assert out["command"][-1] == REDACTED
    # The shape of the invocation must survive - an auditor still needs to know what ran.
    assert out["command"][:5] == ["aircrack-ng", "-w", "/usr/share/wordlist.txt", "-e", "Office"]
    assert out["raw_command"].startswith("aircrack-ng -w /usr/share/wordlist.txt")


def test_composite_credential_forms_are_masked():
    """Impacket builds `user:pass@host`; smbclient builds `user%password`. The secret
    is a substring of a larger argument, so whole-element equality would miss it."""
    structure = {
        "parameters": {"password": SECRET, "username": "admin"},
        "raw_command": f"impacket-psexec admin:{SECRET}@10.0.0.1",
        "command": ["smbclient", "//host/share", "-U", f"admin%{SECRET}"],
    }
    out = redact(structure)
    assert out["raw_command"] == f"impacket-psexec admin:{REDACTED}@10.0.0.1"
    assert out["command"][-1] == f"admin%{REDACTED}"
    # The username is not a secret and is needed to make the record meaningful.
    assert "admin" in out["raw_command"]
    assert out["parameters"]["username"] == "admin"


def test_a_numeric_secret_is_masked():
    """A WPS PIN arrives as a string or an int depending on the caller."""
    assert redact({"parameters": {"pin": 12345670}})["parameters"]["pin"] == REDACTED
    out = redact({"parameters": {"pin": 12345670}, "raw_command": "reaver -i wlan0mon -p 12345670"})
    assert "12345670" not in out["raw_command"]


def test_the_longest_secret_is_substituted_first():
    """A secret that is a prefix of another must not leave a fragment of the longer
    one behind."""
    out = redact(
        {
            "parameters": {"password": "hunter2", "psk": "hunter2extended"},
            "raw_command": "tool --psk hunter2extended --pass hunter2",
        }
    )
    assert "hunter2extended" not in out["raw_command"]
    assert "hunter2" not in out["raw_command"]


def test_the_input_is_never_modified():
    """Contracts in this framework are immutable, and the caller still needs the real
    values in memory to run the assessment."""
    original = {
        "parameters": {"password": SECRET},
        "command": ["smbclient", f"admin%{SECRET}"],
        "nested": [{"password": SECRET}],
    }
    snapshot = json.dumps(original, sort_keys=True)
    redact(original)
    assert json.dumps(original, sort_keys=True) == snapshot, "redaction mutated its input"


def test_a_short_secret_masks_its_field_but_is_not_substituted():
    """A one- or two-character value occurs inside unrelated tokens often enough that
    replacing it would wreck the surrounding record. The field that carries it is
    still masked, so the secret is not disclosed where it lives."""
    out, report = redact_with_report({"parameters": {"pin": "12"}, "raw_command": "reaver -p 12 on 12 channels"})
    assert out["parameters"]["pin"] == REDACTED
    assert out["raw_command"] == "reaver -p 12 on 12 channels"
    assert report.substitutions == 0
    assert "pin" in report.skipped_substitutions
    assert MIN_SUBSTITUTE_LENGTH == 3


def test_empty_secret_fields_are_left_empty():
    """`password: null` means no passphrase was supplied. Masking it would claim a
    secret existed."""
    for empty in (None, "", [], {}):
        out = redact({"parameters": {"password": empty}})
        assert out["parameters"]["password"] == empty


# ------------------------------------------------------------------ reporting


def test_the_report_states_what_was_masked():
    out, report = redact_with_report(
        {"parameters": {"password": SECRET, "community": "s3cr3t"}, "raw_command": f"-c s3cr3t {SECRET}"}
    )
    assert report.applied
    assert set(report.masked_fields) == {"password", "community"}
    assert report.substitutions == 2
    assert report.to_dict()["applied"] is True


def test_a_structure_with_no_secrets_reports_no_redaction():
    out, report = redact_with_report({"parameters": {"ssid": "Office", "channel": 6}, "raw_command": "iw dev wlan0 scan"})
    assert not report.applied
    assert report.to_dict() == {
        "applied": False,
        "masked_fields": [],
        "substitutions": 0,
        "skipped_substitutions": [],
    }
    assert out["parameters"]["ssid"] == "Office"


def test_secrets_accumulate_across_a_sequence_of_records():
    """The load-bearing case. A passphrase is supplied when an action is
    parameterised and appears in a command line when execution is reported, so
    masking one record independently of the next leaks it."""
    known: dict = {}

    first = redact({"parameters": {"password": SECRET}}, known_secrets=known)
    assert first["parameters"]["password"] == REDACTED

    # A later record that never mentions the parameter, only the command line.
    second = redact({"raw_command": f"aircrack-ng -e Office {SECRET} cap.pcap"}, known_secrets=known)
    assert SECRET not in second["raw_command"], (
        "a secret collected from an earlier record was written verbatim into a later one"
    )
    assert second["raw_command"] == f"aircrack-ng -e Office {REDACTED} cap.pcap"


# ------------------------------------------------------------- documented boundary


def test_captured_wps_values_are_deliberately_not_masked():
    """`pixiewps` takes `pke`, `pkr`, `e_nonce`, `r_nonce`, `e_hash1`, `e_hash2`.
    These are captured from frames transmitted in the clear - they are evidence, not
    secrets held by anyone - and masking them would break reproducibility of the
    invocation while protecting nothing. `authkey` is derived key material and *is*
    masked. This test exists so the distinction stays a decision rather than drift."""
    values = {
        "pke": "AABBCCDD",
        "pkr": "11223344",
        "e_nonce": "0F0E0D0C",
        "r_nonce": "9A8B7C6D",
        "e_hash1": "DEADBEEF",
        "e_hash2": "CAFEBABE",
        "authkey": "0011223344556677",
    }
    out = redact({"parameters": dict(values), "raw_command": "pixiewps " + " ".join(values.values())})

    for name in ("pke", "pkr", "e_nonce", "r_nonce", "e_hash1", "e_hash2"):
        assert out["parameters"][name] == values[name], f"{name} was masked but is captured evidence"
    assert out["parameters"]["authkey"] == REDACTED
    assert values["authkey"] not in out["raw_command"]


def test_a_recovered_credential_is_not_mistaken_for_a_supplied_one():
    """The hardest case, and the reason harvesting and field masking are scoped.

    ``john.py`` and ``hashcat.py`` both build
    ``parsed_data["cracked"] = [{"password": ..., "user": ..., "raw": ...}]`` and
    ``aircrack.py`` parses ``KEY FOUND! [ ... ]``. A sensitive-named field inside an
    evidence container holds the passphrase this assessment *recovered*, not one an
    operator supplied. Masking it would delete the finding - the one thing the
    assessment exists to produce - so field masking stops at the container boundary.

    Substitution does not stop: a tool that echoes its own arguments into stdout
    must not leak the supplied passphrase through the output.
    """
    supplied = "hunter2wrong"
    structure = {
        "raw_output": f"KEY FOUND! [ Office123 ] (attempted {supplied})",
        "parsed_data": {
            "cracked": [{"password": "Office123", "user": "admin", "raw": "line"}],
            "cracked_count": 1,
            "ssid": "Office",
        },
        "parameters": {"password": supplied, "wordlist": "/usr/share/wl.txt"},
        "raw_command": f"aircrack-ng -w /usr/share/wl.txt {supplied} capture.pcap",
    }
    out = redact(structure)

    # The finding survives, in the output and in the parsed evidence.
    assert out["parsed_data"]["cracked"][0]["password"] == "Office123"
    assert out["parsed_data"]["cracked"][0]["user"] == "admin"
    assert "Office123" in out["raw_output"]
    assert out["parsed_data"]["cracked_count"] == 1

    # The operator secret is gone everywhere, including where the tool echoed it.
    assert supplied not in json.dumps(out)
    assert out["parameters"]["password"] == REDACTED
    assert out["raw_command"] == f"aircrack-ng -w /usr/share/wl.txt {REDACTED} capture.pcap"
    assert out["parameters"]["wordlist"] == "/usr/share/wl.txt"


def test_a_finding_with_no_supplied_secret_is_untouched():
    """A pure evidence record - no parameters at all - must come through verbatim."""
    structure = {
        "raw_output": "KEY FOUND! [ Office123 ]",
        "parsed_data": {"cracked": [{"password": "Office123"}]},
        "raw_command": "aircrack-ng -w /usr/share/wl.txt capture.pcap",
    }
    out, report = redact_with_report(structure)
    assert out == structure
    assert not report.applied


# ------------------------------------------------------------------- audit logger


def _logger(tmp_path):
    from wifi_framework.core.audit.logger import AuditLogger

    return AuditLogger(log_dir=str(tmp_path / "audit"))


def test_the_audit_trail_on_disk_does_not_contain_the_secret(tmp_path):
    logger = _logger(tmp_path)
    logger.log_action_selection(
        {
            "capability_name": "wpa_assessment",
            "interface": "wlan0",
            "parameters": {"password": SECRET, "user": "admin", "wordlist": "/usr/share/wl.txt"},
        }
    )
    logger.log_event(
        "execution",
        {
            "raw_command": f"impacket-psexec admin:{SECRET}@10.0.0.1",
            "parameters": {"pin": "12345670"},
            "passive": True,
            "hash_file": "/tmp/h.hash",
        },
    )
    logger.log_event("evidence", {"raw_command": f"aircrack-ng -w /usr/share/wl.txt {SECRET} cap.pcap"})

    assert logger.write_failures == []
    trail = (tmp_path / "audit" / f"{logger.assessment_id}.jsonl").read_text()

    assert SECRET not in trail, "the passphrase reached the audit file"
    assert "12345670" not in trail, "the WPS PIN reached the audit file"
    # Auditability survives: what ran, against what, with which non-secret inputs.
    assert "admin" in trail
    assert "/usr/share/wl.txt" in trail
    assert "/tmp/h.hash" in trail
    assert "wlan0" in trail


def test_the_audit_trail_declares_that_it_was_filtered(tmp_path):
    """A masked value must not look like the value that was used."""
    logger = _logger(tmp_path)
    logger.log_action_selection({"capability_name": "wpa_assessment", "parameters": {"password": SECRET}})
    logger.log_event("capability_discovery", {"available_count": 3})

    trail = (tmp_path / "audit" / f"{logger.assessment_id}.jsonl").read_text().strip().splitlines()
    filtered = json.loads(trail[0])
    assert filtered["redaction"]["applied"] is True
    assert filtered["redaction"]["masked_fields"] == ["password"]

    clean = json.loads(trail[1])
    assert "redaction" not in clean, "an event with nothing to mask claimed to be filtered"


def test_a_contract_payload_is_filtered_when_it_is_recorded(tmp_path):
    """`execution-result` payloads are inlined in full and carry both `command` and
    `parameters`, so they go through the same filter."""
    from wifi_framework.contracts.action import ActionRequest
    from wifi_framework.contracts.envelope import EngineId

    logger = _logger(tmp_path)
    request = ActionRequest(
        assessment_id="assessment-1",
        source_engine=EngineId.DECISION.value,
        action_id="action-1",
        capability="wpa_assessment",
        interface="wlan0",
        parameters={"password": SECRET, "wordlist": "/usr/share/wl.txt"},
    )
    logger.log_contract(request)

    trail = (tmp_path / "audit" / f"{logger.assessment_id}.jsonl").read_text()
    assert SECRET not in trail
    assert REDACTED in trail
    assert "/usr/share/wl.txt" in trail


def test_the_saved_report_is_filtered(tmp_path):
    """The report inlines `raw_command` for every evidence item and every finding
    trace, and is the artefact most likely to leave the machine it was made on."""

    from wifi_framework.core.models.assessment_state import AssessmentState, ExecutionRecord
    from wifi_framework.core.models.scope import AssessmentScope

    logger = _logger(tmp_path)
    state = AssessmentState(scope=AssessmentScope())
    state.execution_history.append(
        ExecutionRecord(
            capability_name="wpa_assessment",
            tool_binary="aircrack-ng",
            interface="wlan0",
            parameters={"password": SECRET, "wordlist": "/usr/share/wl.txt"},
            raw_command=f"aircrack-ng -w /usr/share/wl.txt -e Office {SECRET} capture.pcap",
            exit_code=0,
            success=True,
        )
    )

    path = logger.save_report(state, output_path=str(tmp_path / "report.json"))
    written = json.loads(open(path, "r", encoding="utf-8").read())

    assert SECRET not in json.dumps(written), "the passphrase reached the report file"
    record = written["execution_history"][0]
    assert record["parameters"]["password"] == REDACTED
    assert record["raw_command"] == f"aircrack-ng -w /usr/share/wl.txt -e Office {REDACTED} capture.pcap"
    assert record["parameters"]["wordlist"] == "/usr/share/wl.txt"
    assert written["redaction"]["applied"] is True


def test_a_report_with_no_secrets_claims_no_redaction(tmp_path):
    from wifi_framework.core.models.assessment_state import AssessmentState, ExecutionRecord
    from wifi_framework.core.models.scope import AssessmentScope

    logger = _logger(tmp_path)
    state = AssessmentState(scope=AssessmentScope())
    state.execution_history.append(
        ExecutionRecord(
            capability_name="discovery",
            tool_binary="iw",
            interface="wlan0",
            parameters={"channel": 6},
            raw_command="iw dev wlan0 scan",
            success=True,
        )
    )
    path = logger.save_report(state, output_path=str(tmp_path / "clean.json"))
    written = json.loads(open(path, "r", encoding="utf-8").read())
    assert "redaction" not in written
    assert written["execution_history"][0]["raw_command"] == "iw dev wlan0 scan"


# ------------------------------------------------------------------ future-proofing

#: Names the redactor leaves alone although they look secret-shaped. Each is a
#: deliberate decision, documented in the module docstring.
KNOWN_NON_SECRET_PARAMETERS = {
    "passive",     # boolean: listen instead of probe
    "hash_file",   # a path
    "e_hash1",     # captured from an M1 frame sent in the clear
    "e_hash2",     # captured from an M2 frame sent in the clear
    "e_nonce",     # captured, transmitted in the clear
    "r_nonce",     # captured, transmitted in the clear
    "pke",         # captured public value
    "pkr",         # captured public value
}

_SECRET_SHAPED = ("pass", "psk", "key", "secret", "token", "pin", "cred", "hash", "auth", "community", "nonce", "pw", "pwd")


def test_every_secret_shaped_adapter_parameter_is_handled():
    """Redaction is name-driven, so a new adapter that reads a secret from a
    parameter name this module does not know would leak it silently. This scans the
    adapter sources and fails when a secret-shaped name is neither masked nor
    explicitly accounted for - the leak is caught at review time, not in production.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent / "src" / "wifi_framework" / "tools" / "adapters"
    assert root.is_dir(), f"{root} missing - the scan would silently cover nothing"

    pattern = re.compile(r"""parameters(?:\.get\()?\[?\(?\s*["']([A-Za-z0-9_]+)["']""")
    names = set()
    for path in root.rglob("*.py"):
        names.update(pattern.findall(path.read_text(encoding="utf-8")))
    assert names, "no adapter parameters found - the scan is vacuous"

    shaped = {name for name in names if any(hint in name.lower() for hint in _SECRET_SHAPED)}
    assert shaped, "no secret-shaped parameters found - the scan is vacuous"

    unhandled = sorted(
        name for name in shaped
        if not is_sensitive_name(name) and name not in KNOWN_NON_SECRET_PARAMETERS
    )
    assert unhandled == [], (
        f"adapter parameters that look like secrets but are neither masked nor "
        f"documented as safe: {unhandled}. Add the name to SENSITIVE_NAMES / "
        "SENSITIVE_TOKENS in utils/redaction.py, or to KNOWN_NON_SECRET_PARAMETERS "
        "here with a reason."
    )
