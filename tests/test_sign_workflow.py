"""M#3: structural invariants of the signing workflow (text checks; no YAML parser is available to every runner)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = (ROOT / ".github" / "workflows" / "sign-index.yml").read_text()
WF = "\n".join(line for line in RAW.splitlines() if not line.lstrip().startswith("#"))


def test_runs_on_main_only_in_the_signing_environment():
    assert re.search(r"^    if: github.ref == 'refs/heads/main'$", WF, re.M)
    assert re.search(r"^    environment: index-signing$", WF, re.M)
    assert re.search(r"^    branches: \[main\]$", WF, re.M)


def test_triggers_are_index_change_schedule_and_manual():
    on_block = re.search(r"^on:\n((?:  .*\n|\n)+)", WF, re.M).group(1)
    assert sorted(re.findall(r"^  ([a-z_]+):", on_block, re.M)) == ["push", "schedule", "workflow_dispatch"]
    assert "pull_request" not in on_block


def test_the_key_is_only_in_the_signing_step():
    assert WF.count("secrets.ORCH_MARKET_INDEX_KEY") == 1
    assert "secrets." not in WF.replace("secrets.ORCH_MARKET_INDEX_KEY", "")
    step = WF.split("- name: Sign (only this step sees the key)")[1].split("- name:")[0]
    assert "secrets.ORCH_MARKET_INDEX_KEY" in step
    assert "echo" not in step.replace('echo "ORCH_MARKET_INDEX_PUBS', "")  # nothing prints around the key


def test_signing_fails_closed_without_pinned_public_keys():
    assert re.search(r'\[ -n "\$ORCH_MARKET_INDEX_PUBS" \] \|\|', WF)
    assert '--expect-pub "$ORCH_MARKET_INDEX_PUBS"' in WF


def test_result_goes_to_a_pull_request_never_to_main():
    assert "gh pr create --base main" in WF
    assert not re.search(r"git push[^\n]* (origin )?main\b", WF)
    assert not re.search(r"git -c ", WF), "the token must not appear in argv"
    assert "--force" not in WF and " -f " not in WF
    assert 'branch="index-resign-${RUN_ID}"' in WF  # a fresh branch per run: no force needed


def test_refuses_a_run_that_is_not_mains_tip_or_definition():
    assert "github.workflow_sha" in WF and "origin/main" in WF
    assert re.search(r'\[ "\$WORKFLOW_SHA" = "\$tip" \]', WF)


def test_dependencies_are_hash_pinned_and_actions_are_sha_pinned():
    assert "pip install --require-hashes -r requirements-sign.txt" in WF
    assert all(re.search(r"@[0-9a-f]{40}\b", u) for u in re.findall(r"uses: (\S+)", WF))
    req = (ROOT / "requirements-sign.txt").read_text()
    assert "cryptography==" in req and req.count("--hash=sha256:") > 20


def test_permissions_are_least_privilege_and_credentials_not_persisted():
    assert re.search(r"^permissions:\n  contents: read\n", WF, re.M)
    assert re.search(r"persist-credentials: false", WF)
    assert "contents: write" in WF and "pull-requests: write" in WF
    assert "actions: write" not in WF  # no workflow dispatches: the gate has no manual trigger


def test_changes_other_than_the_index_stop_the_job():
    assert "unexpected changes" in WF and "git diff --name-only" in WF


def test_no_event_text_is_interpolated_into_scripts():
    for block in re.findall(r"^\s+run: \|\n((?:\s{10,}.*\n)+)", WF, re.M):
        assert "${{" not in block


def test_only_prs_made_by_this_workflow_block_a_re_sign():
    """A title match would let anyone (a fork PR too) block re-signing until the index expires."""
    step = WF.split("- name: Open the pull request when the file changed")[1]
    assert "in:title" not in step and "--search" not in step
    assert "--json number,headRefName,author,isCrossRepository" in step
    assert '.author.login == "app/github-actions"' in step
    assert 'startswith("index-resign-")' in step
    assert "(.isCrossRepository | not)" in step


def test_skipping_because_a_pr_is_open_fails_visibly_when_the_signature_is_running_out():
    step = WF.split("- name: Open the pull request when the file changed")[1]
    assert "--verify-only" in step and "--min-days 10" in step
    assert "::error::" in step and "::notice::" in step
    assert re.search(r"::error::[^\n]*\n\s+exit 1", step)
    assert "git show HEAD:marketplace.json" in step  # the signature on main, not the one just made


def test_token_reaches_git_through_environment_config_not_argv():
    assert "GIT_CONFIG_COUNT=1" in WF and "GIT_CONFIG_VALUE_0=" in WF
    assert "unset GIT_CONFIG_COUNT" in WF
    assert "git -c" not in WF


def test_re_sign_pr_body_carries_the_merge_back_command():
    assert "gh pr create --repo severinlindenmann/orch-marketplace --base develop --head main" in WF
    assert "merge main (re-sign) back into develop" in WF


def test_no_other_workflow_names_the_signing_environment_or_uses_privileged_triggers_with_it():
    """L3: for pull_request_target / workflow_run `github.ref` is the base/default branch, which an Environment limited to
    main would allow. Only sign-index.yml may name index-signing, and it has neither trigger."""
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        text = "\n".join(line for line in wf.read_text().splitlines() if not line.lstrip().startswith("#"))
        if wf.name != "sign-index.yml":
            assert "index-signing" not in text and "ORCH_MARKET_INDEX_KEY" not in text, wf.name
    assert "pull_request_target" not in WF and "workflow_run" not in WF and "workflow_call" not in WF
