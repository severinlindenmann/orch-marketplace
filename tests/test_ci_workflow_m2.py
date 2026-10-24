"""M2-1/M2-4/M2-5/M2-3: structural invariants of ci.yml added in the review round (text checks)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
LIVE = "\n".join(line for line in CI.splitlines() if not line.lstrip().startswith("#"))



def test_promotion_is_decided_by_the_workflow_for_same_repo_main_from_develop_only():
    assert re.search(r'\[ "\$PR_HEAD_REPO" = "\$THIS_REPO" \]', LIVE)
    assert re.search(r'\[ "\$PR_BASE_REF" = "main" \] && \[ "\$PR_HEAD_REF" = "develop" \]', LIVE)
    assert LIVE.index('"$PR_HEAD_REPO" = "$THIS_REPO"') < LIVE.index("--promotion")  # a fork's `develop` branch never counts



def test_resign_branch_is_scoped_signed_and_single_commit():
    assert re.search(r"grep -Eq '\^index-resign-\[0-9\]\+\$'", LIVE)
    assert "--only marketplace.json" in LIVE
    step = LIVE.split("Re-sign PR - ")[1].split("- name:")[0]
    assert "rev-list --count" in step and "github-actions[bot]" in step
    assert "sign-index --verify-only" in step and "vars.ORCH_MARKET_INDEX_PUBS" in LIVE
    assert '[ -n "$PUBS" ]' in step, "fail closed without the pinned keys"



def test_only_ci_yml_defines_a_job_named_index():
    """The required check is the NAME `index`; a PR-added workflow with such a job would satisfy it (see README)."""
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        text = "\n".join(line for line in wf.read_text().splitlines() if not line.lstrip().startswith("#"))
        defines = bool(re.search(r"^  index:", text, re.M)) or bool(re.search(r"^    name: ['\"]?index['\"]?\s*$", text, re.M))
        assert defines == (wf.name == "ci.yml"), wf.name



def test_requirements_ci_is_hash_pinned():
    req = (ROOT / "requirements-ci.txt").read_text()
    pins = [line for line in req.splitlines() if re.match(r"[A-Za-z]", line)]
    assert pins and all("==" in p for p in pins)
    assert req.count("--hash=sha256:") >= len(pins)

