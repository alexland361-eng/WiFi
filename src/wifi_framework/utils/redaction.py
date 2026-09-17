"""
Redaction of operator secrets on the persistence boundary.

The framework records what it ran: the argument vector, the parameters that produced
it, and the joined command line, in the audit trail and in the final report. Several
adapters put a secret directly into that command line - ``aircrack-ng`` takes a
passphrase from ``parameters["password"]`` or ``parameters["key"]``, ``reaver`` a WPS
PIN from ``parameters["pin"]``, the Impacket adapter interpolates ``user:pass@host``,
``smbclient`` builds ``user%password``, and ``snmpwalk`` takes a community string.
Persisted verbatim, the audit trail becomes a credential file: readable by anyone who
can read it, and shipped wherever the report goes.

Redaction is applied at the point where data is written down, not where it is
executed. In-memory contracts stay exact - the Decision Engine generated those
parameters and needs them, and the ``execution-result`` contract promises its
recorded command is what actually ran. Only the persisted copy is masked, and the
mask is declared in the record so the trail states that it is incomplete rather than
looking whole.

Two boundaries are deliberate and worth stating, because both look like omissions:

* **Tool output is not redacted.** ``raw_output``, artifacts and evidence payloads
  may contain recovered credential material - a cracked passphrase, a dumped hash.
  That material *is* the finding. Masking it would destroy the thing the assessment
  exists to produce, and the evidence hierarchy already handles it by requiring
  independent confirmation of a ``credential_observation`` rather than by hiding it.
  Only operator-supplied secrets entering a command line are masked.
* **WPS nonces and Diffie-Hellman values are not redacted.** ``pixiewps`` takes
  ``pke``, ``pkr``, ``e_nonce`` and ``r_nonce``. These are captured from frames
  transmitted in the clear, not secrets held by anyone; they are evidence, and
  masking them would break reproducibility of the invocation while protecting
  nothing. ``authkey`` is masked, because it is derived key material rather than an
  observed transmission.

Redaction is name-driven: a capability that stored a secret under a parameter name
this module does not recognise would not be masked. ``tests/test_redaction.py``
cross-checks every secret-shaped parameter name used by the adapters against the
tables below, so adding one without teaching the redactor fails the suite.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

#: The marker left in place of a masked value. Deliberately loud: a reader of the
#: audit trail must be able to tell "this was removed" from "this was empty".
REDACTED = "***REDACTED***"

#: Parameter names whose value is a secret, matched exactly after normalisation.
#: ``e_nonce``/``r_nonce``/``pke``/``pkr`` are absent on purpose - see the module
#: docstring. ``hash`` is here as an exact name only, so that a supplied hash value
#: is masked while ``hash_file`` (a path) is not.
SENSITIVE_NAMES: FrozenSet[str] = frozenset(
    {
        "hash",
        "passkey",
        "passphrase",
        "passcode",
        "password",
        "passwd",
        "psk",
        "pin",
        "authkey",
        "community",
        "secret",
        "token",
        "credential",
        "credentials",
        "apikey",
        "privatekey",
    }
)

#: Word tokens that make a compound name sensitive: ``wpa_key`` and ``session_key``
#: are caught by ``key``, ``user_password`` by ``password``.
#:
#: Matching is on whole tokens, never substrings. A substring rule would mask
#: ``passive`` - a boolean that makes netdiscover listen instead of probe - and
#: ``keyspace``, and would quietly corrupt unrelated audit records.
SENSITIVE_TOKENS: FrozenSet[str] = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "passkey",
        "passcode",
        "psk",
        "pin",
        "authkey",
        "community",
        "secret",
        "token",
        "key",
        "credential",
        "credentials",
        "apikey",
    }
)

#: Names that are *not* sensitive despite containing a sensitive word. Recorded so
#: the exclusions are explicit and reviewable rather than accidental.
NOT_SENSITIVE: FrozenSet[str] = frozenset(
    {
        "passive",
        "hash_file",
        "hashfile",
        "wordlist",
        "potfile_disable",
        "input_file",
        "fragment_file",
        "capture_file",
        "keyspace",
    }
)

#: Keys whose contents are *findings* rather than operator input, and are therefore
#: not harvested for secrets.
#:
#: The parsers put cracked credentials under sensitive-looking names inside these
#: containers: ``john.py`` and ``hashcat.py`` both build
#: ``parsed_data["cracked"] = [{"password": ..., "user": ..., "raw": ...}]``, and
#: ``aircrack.py`` parses ``KEY FOUND! [ ... ]`` out of the output. Harvesting by
#: name alone would collect a recovered passphrase as though it were an operator
#: secret and then mask it everywhere it appears - destroying the finding, which is
#: the one thing the assessment exists to produce.
#:
#: Only *harvesting* is skipped here. Masking still applies inside these containers,
#: so an operator secret that a tool echoes back into its own output is still
#: masked.
EVIDENCE_CONTAINERS: FrozenSet[str] = frozenset(
    {
        "parsed_data",
        "parsed",
        "raw_output",
        "error_output",
        "stdout",
        "stderr",
        "output",
        "cracked",
        "findings",
        "evidences",
        "evidence",
        "observations",
        "recovered",
    }
)

#: Shortest value substituted inside a larger string. A one- or two-character secret
#: occurs as a substring of unrelated tokens often enough that replacing it would
#: wreck the surrounding record; the parameter itself is still masked exactly, so the
#: secret is not disclosed in the field that carries it.
MIN_SUBSTITUTE_LENGTH = 3

_NAME_SEPARATOR = re.compile(r"[^0-9a-z]+")


def normalize_name(name: Any) -> str:
    """Lower-case a parameter name and strip the separators used in tool flags."""
    if not isinstance(name, str):
        return ""
    lowered = name.strip().lower()
    return _NAME_SEPARATOR.sub("", lowered)


def is_sensitive_name(name: Any) -> bool:
    """Whether a parameter name denotes an operator secret."""
    if not isinstance(name, str):
        return False
    lowered = name.strip().lower()
    if lowered in NOT_SENSITIVE or normalize_name(lowered) in NOT_SENSITIVE:
        return False
    compact = normalize_name(lowered)
    if not compact:
        return False
    if compact in SENSITIVE_NAMES or lowered in SENSITIVE_NAMES:
        return True
    tokens = [token for token in _NAME_SEPARATOR.split(lowered) if token]
    return any(token in SENSITIVE_TOKENS for token in tokens)


@dataclass
class RedactionReport:
    """What redaction did to one structure.

    Recorded alongside the redacted data so an audit trail states that it was
    filtered and which fields were affected, instead of silently presenting masked
    values as the values that were used.
    """

    masked_fields: List[str] = field(default_factory=list)
    substitutions: int = 0
    #: Secret values too short to substitute inside a larger string. The field that
    #: carries them is still masked; only the substring pass skipped them.
    skipped_substitutions: List[str] = field(default_factory=list)

    @property
    def applied(self) -> bool:
        return bool(self.masked_fields) or self.substitutions > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "applied": self.applied,
            "masked_fields": sorted(set(self.masked_fields)),
            "substitutions": self.substitutions,
            "skipped_substitutions": sorted(set(self.skipped_substitutions)),
        }


def _collect(node: Any, secrets: Dict[str, Set[str]], *, harvest: bool = True) -> None:
    """Gather every secret value in the structure, keyed by the field that held it.

    Collected across the whole structure before anything is masked, because the same
    value appears in more than one place: ``parameters["password"]`` holds it
    directly, while ``raw_command`` and ``command`` hold it interpolated into
    ``user:pass@host`` or ``-p pass``. Masking only the field would leave the
    command line disclosing it.

    ``harvest`` is switched off below an :data:`EVIDENCE_CONTAINERS` key so that a
    cracked credential is not mistaken for a supplied one. See that constant.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            sensitive = is_sensitive_name(key)
            if harvest and sensitive:
                if isinstance(value, str) and value:
                    secrets.setdefault(normalize_name(key), set()).add(value)
                elif isinstance(value, (int, float)) and not isinstance(value, bool):
                    secrets.setdefault(normalize_name(key), set()).add(str(value))
            below = harvest and normalize_name(key) not in EVIDENCE_CONTAINERS
            _collect(value, secrets, harvest=below)
    elif isinstance(node, (list, tuple, set, frozenset)):
        for item in node:
            _collect(item, secrets, harvest=harvest)


def _substitute(text: str, ordered: List[Tuple[str, str]], report: RedactionReport) -> str:
    """Replace every occurrence of a collected secret inside one string."""
    result = text
    for value, field_name in ordered:
        if value in result:
            result = result.replace(value, REDACTED)
            report.substitutions += 1
            if field_name not in report.masked_fields:
                report.masked_fields.append(field_name)
    return result


def redact_with_report(
    structure: Any,
    *,
    known_secrets: Optional[Dict[str, Set[str]]] = None,
) -> Tuple[Any, RedactionReport]:
    """A copy of ``structure`` with operator secrets masked, plus what was masked.

    The input is never modified: contracts in this framework are immutable, and a
    caller that persists a redacted copy still needs the original in memory to run
    the assessment.

    ``known_secrets`` is an accumulator for callers redacting a *sequence* of
    records. Secrets are disclosed at planning time and appear in a command line at
    execution time, so a value collected from one record must still be masked in the
    next one: without it, ``log_action_selection`` masks ``parameters["password"]``
    while the later execution event writes the same password into ``raw_command``
    unmasked. Secrets found in ``structure`` are added to the accumulator in place.
    """
    report = RedactionReport()
    secrets: Dict[str, Set[str]] = {} if known_secrets is None else known_secrets
    _collect(structure, secrets)

    # Longest first, so a secret that is a prefix of another is not replaced inside
    # the mask left by the shorter one.
    ordered: List[Tuple[str, str]] = []
    for field_name, values in secrets.items():
        for value in values:
            if len(value) >= MIN_SUBSTITUTE_LENGTH:
                ordered.append((value, field_name))
            else:
                report.skipped_substitutions.append(field_name)
    ordered.sort(key=lambda pair: len(pair[0]), reverse=True)

    def walk(node: Any, *, mask_fields: bool = True) -> Any:
        """Rebuild ``node``, masking as it goes.

        Two different operations with two different scopes:

        * *field masking* - a sensitive-named field is assumed to hold an operator
          secret. That assumption holds for input parameters but not inside an
          evidence container, where ``parsed_data["cracked"][0]["password"]`` is the
          passphrase this assessment recovered. Masking it would delete the finding,
          so field masking stops at an :data:`EVIDENCE_CONTAINERS` key.
        * *substitution* - replacing a value that was demonstrably supplied as a
          secret somewhere in the same record. That applies everywhere, including
          inside evidence containers, so a tool that echoes its own arguments back
          into stdout does not leak the passphrase through the output.
        """
        if isinstance(node, dict):
            out: Dict[Any, Any] = {}
            for key, value in node.items():
                if mask_fields and is_sensitive_name(key):
                    # Masked whether or not the value was long enough to substitute
                    # elsewhere: this field is the secret's home.
                    if value not in (None, "", [], {}):
                        out[key] = REDACTED
                        name = normalize_name(key)
                        if name not in report.masked_fields:
                            report.masked_fields.append(name)
                    else:
                        out[key] = value
                    continue
                below = mask_fields and normalize_name(key) not in EVIDENCE_CONTAINERS
                out[key] = walk(value, mask_fields=below)
            return out
        if isinstance(node, list):
            return [walk(item, mask_fields=mask_fields) for item in node]
        if isinstance(node, tuple):
            return tuple(walk(item, mask_fields=mask_fields) for item in node)
        if isinstance(node, str):
            return _substitute(node, ordered, report) if ordered else node
        return node

    return walk(structure), report


def redact(structure: Any, *, known_secrets: Optional[Dict[str, Set[str]]] = None) -> Any:
    """A copy of ``structure`` with operator secrets masked."""
    redacted, _report = redact_with_report(structure, known_secrets=known_secrets)
    return redacted
