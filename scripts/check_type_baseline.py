#!/usr/bin/env python3
"""
Fail when mypy findings grow past the recorded baseline.

The codebase has 34 known mypy findings, described in ``pyproject.toml``. Clearing them
is per-site judgement work rather than a sweep, so it has not been done - but leaving the
checker ungated means the number only ever rises, and a gate that fails on day one is a
gate nobody runs. This is the middle position: the count is recorded, CI fails when it
increases, and CI says so when it falls so the baseline can be lowered.

Usage::

    python scripts/check_type_baseline.py            # compare against .mypy-baseline
    python scripts/check_type_baseline.py --update   # rewrite the baseline to the current count

Exit codes: 0 at or below baseline, 1 above it, 2 if the check could not run.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE_FILE = REPO_ROOT / ".mypy-baseline"
TARGET = "src/wifi_framework"

#: ``Found 34 errors in 15 files (checked 121 source files)``, and the singular form
#: mypy prints for one finding.
COUNT_RE = re.compile(r"Found (\d+) errors? in (\d+) files?")
SUCCESS_RE = re.compile(r"Success: no issues found in (\d+) source files")


def abort(message: str) -> None:
    """Report a gate that could not run, distinct from a gate that failed.

    ``SystemExit`` with a string message exits 1, which would be indistinguishable from
    "the codebase has too many findings" - the two need different responses, so this
    prints and exits with the documented code.
    """
    print(message, file=sys.stderr)
    raise SystemExit(2)


def run_mypy() -> tuple[int, str]:
    """The current finding count, and mypy's output for the report."""
    executable = sys.executable
    command = [executable, "-m", "mypy", TARGET]
    try:
        completed = subprocess.run(
            command, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=900
        )
    except FileNotFoundError:
        abort(f"could not run {command}; install mypy (pip install mypy) to use this gate")
    except subprocess.TimeoutExpired:
        abort("mypy did not finish within 900s")

    output = completed.stdout + completed.stderr
    match = COUNT_RE.search(output)
    if match:
        return int(match.group(1)), output
    if SUCCESS_RE.search(output):
        return 0, output
    # No recognizable summary means the run itself failed - a configuration error or a
    # crash must not be reported as a clean tree.
    abort(f"mypy produced no recognizable summary (rc={completed.returncode}):\n{output}")


def read_baseline() -> int:
    if not BASELINE_FILE.exists():
        abort(f"no baseline at {BASELINE_FILE}; run with --update to create one")
    text = BASELINE_FILE.read_text().strip()
    digits = re.sub(r"[^0-9]", "", text.split("\n")[0])
    if not digits:
        abort(f"{BASELINE_FILE} does not start with a number: {text[:80]!r}")
    return int(digits)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument(
        "--update",
        action="store_true",
        help="rewrite .mypy-baseline to the current count instead of comparing",
    )
    args = parser.parse_args()

    current, output = run_mypy()

    if args.update:
        BASELINE_FILE.write_text(f"{current}\n")
        print(f"mypy findings: {current} - baseline written to {BASELINE_FILE.name}")
        return 0

    baseline = read_baseline()
    print(f"mypy findings: {current} (baseline {baseline})")

    if current > baseline:
        print(
            f"\nFAIL: {current - baseline} new type finding(s) above the baseline of {baseline}.\n"
            "Fix them, or - if the growth is deliberate and justified - lower the bar\n"
            "explicitly with `python scripts/check_type_baseline.py --update` in a commit\n"
            "that says why.\n"
        )
        findings = [line for line in output.splitlines() if ": error:" in line]
        print("\n".join(findings[-40:]))
        return 1

    if current < baseline:
        print(
            f"\nbelow baseline by {baseline - current}: lower it with "
            "`python scripts/check_type_baseline.py --update` so the improvement is kept."
        )
    else:
        print("at baseline; no new findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
