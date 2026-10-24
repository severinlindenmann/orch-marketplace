#!/usr/bin/env python3
"""Scope gate (M#2): a pull request may change the gate or the index, never both.

The gate is everything that decides whether an index is valid: the validator, the schema, the workflows and the CI
requirements. CI runs this script from the BASE branch (so the PR cannot change it) on the PR's file list.

    check_scope.py --base SHA --head SHA [--only PATH | --promotion]

``--only PATH`` is for the re-sign branch: it may change that one file and nothing else.
``--promotion`` is for the develop -> main PR (the workflow decides: same repository, base main, head develop): every
develop PR was checked on its own, so the combined change set is not refused.
Exit 0 = fine, 1 = refused (reasons on stdout).
"""

from __future__ import annotations

import argparse
import subprocess
import sys

INDEX = "marketplace.json"
GATE_PREFIXES = ("scripts/", "schema/", ".github/")
GATE_FILES = ("requirements-ci.txt", "requirements-sign.txt")


def is_gate(path: str) -> bool:
    return path.startswith(GATE_PREFIXES) or path in GATE_FILES


def judge(changed: list[str], only: str | None = None, promotion: bool = False) -> list[str]:
    """The reasons to refuse a change set (empty = allowed)."""
    if promotion and only is None:
        return []
    if only is not None:
        extra = sorted(p for p in changed if p != only)
        return [f"this branch may change only {only}, but also changes: {', '.join(extra)}"] if extra else []
    gate = sorted(p for p in changed if is_gate(p))
    if INDEX in changed and gate:
        return [f"{INDEX} and the gate are changed in one pull request; gate files: {', '.join(gate)}. "
                "Land the validator/schema/workflow change first, the index change in a later PR"]  # fmt: skip
    return []


def changed_files(base: str, head: str, cwd: str = ".") -> list[str]:
    """Paths changed on the head side since the merge base. No rename detection: a rename counts as delete + add."""
    out = subprocess.run(["git", "diff", "--name-only", "--no-renames", "-z", f"{base}...{head}"], cwd=cwd,
                         check=True, capture_output=True).stdout  # fmt: skip
    return [p for p in out.decode().split("\0") if p]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--only")
    ap.add_argument("--promotion", action="store_true")
    a = ap.parse_args(argv)
    try:
        files = changed_files(a.base, a.head)
    except subprocess.CalledProcessError as e:
        print(f"FAIL cannot list the changed files: {e}")
        return 1
    problems = judge(files, a.only, a.promotion)
    for p in problems:
        print(f"FAIL scope: {p}")
    if not problems:
        print(f"scope ok: {len(files)} file(s) changed")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
