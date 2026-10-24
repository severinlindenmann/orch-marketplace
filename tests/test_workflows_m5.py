"""CI workflow rules of M#5 (the workflows are the gate: they must install pinned, hashed requirements and hold a PR into
develop to main's published history as well)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"


def test_pip_installs_with_hashes_in_every_workflow():
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        for line in wf.read_text().splitlines():
            if "pip install" in line:
                assert "--require-hashes" in line, f"{wf.name}: {line.strip()}"


def test_the_gate_checks_main_history_as_a_second_ref():
    ci = (WORKFLOWS / "ci.yml").read_text()
    assert '--history-ref "$BASE"' in ci and "--history-ref refs/remotes/origin/main" in ci
