"""M#2: the gate runs the BASE branch's validator and refuses a PR that changes the gate and the index together."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import re

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import check_scope as cs  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]


@pytest.mark.parametrize("path", ["scripts/validate_index.py", "schema/market.v1.json", ".github/workflows/ci.yml",
                                  ".github/CODEOWNERS", "requirements-ci.txt", "scripts/new_tool.py"])  # fmt: skip
def test_gate_plus_index_is_refused(path):
    assert cs.judge(["marketplace.json", path])


@pytest.mark.parametrize("changed", [["marketplace.json"], ["marketplace.json", "packages/x/main.py", "README.md"],
                                     ["scripts/validate_index.py", "tests/test_x.py"], [".github/workflows/ci.yml"], []])  # fmt: skip
def test_one_side_alone_is_fine(changed):
    assert cs.judge(changed) == []


def test_only_mode_allows_exactly_one_file():
    assert cs.judge(["marketplace.json"], only="marketplace.json") == []
    assert cs.judge([], only="marketplace.json") == []
    assert cs.judge(["marketplace.json", ".github/workflows/ci.yml"], only="marketplace.json")
    assert cs.judge(["scripts/sign-index"], only="marketplace.json")


def _repo(tmp_path):
    def run(*a):
        return subprocess.run([*GIT, *a], cwd=tmp_path, check=True, capture_output=True, text=True).stdout.strip()
    run("init", "-q", "-b", "main")
    (tmp_path / "marketplace.json").write_text("{}")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "validate_index.py").write_text("v1")
    run("add", "-A"); run("commit", "-qm", "base")  # noqa: E702
    return run, run("rev-parse", "HEAD")


def test_cli_refuses_a_real_pr_that_touches_both(tmp_path):
    run, base = _repo(tmp_path)
    run("checkout", "-qb", "pr")
    (tmp_path / "scripts" / "validate_index.py").write_text("weaker")
    (tmp_path / "marketplace.json").write_text('{"x":1}')
    run("add", "-A"); run("commit", "-qm", "both")  # noqa: E702
    head = run("rev-parse", "HEAD")
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_scope.py"), "--base", base, "--head", head],
                       cwd=tmp_path, capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 1 and "FAIL scope" in r.stdout


def test_cli_counts_a_deleted_or_renamed_gate_file(tmp_path):
    run, base = _repo(tmp_path)
    run("checkout", "-qb", "pr")
    run("mv", "scripts/validate_index.py", "scripts/other.py")
    (tmp_path / "marketplace.json").write_text('{"x":1}')
    run("add", "-A"); run("commit", "-qm", "rename")  # noqa: E702
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_scope.py"), "--base", base, "--head", run("rev-parse", "HEAD")],
                       cwd=tmp_path, capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 1


def test_cli_allows_an_index_only_pr(tmp_path):
    run, base = _repo(tmp_path)
    run("checkout", "-qb", "pr")
    (tmp_path / "marketplace.json").write_text('{"x":1}')
    run("add", "-A"); run("commit", "-qm", "idx")  # noqa: E702
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_scope.py"), "--base", base, "--head", run("rev-parse", "HEAD")],
                       cwd=tmp_path, capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout


# -- the workflow itself: structural invariants of the gate (text checks; the prepush env has no YAML parser) ------------

CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
TESTS = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
LIVE = "\n".join(line for line in CI.splitlines() if not line.lstrip().startswith("#"))


def test_gate_workflow_is_pull_request_target_not_pull_request():
    assert re.search(r"^  pull_request_target:", LIVE, re.M)
    assert not re.search(r"^  pull_request:", LIVE, re.M)


def test_gate_job_is_named_index_and_has_read_only_token():
    assert re.search(r"^  index:", LIVE, re.M)
    assert re.search(r"^permissions:\n  contents: read\n", LIVE, re.M)
    assert "write" not in LIVE.replace("workflow_dispatch", "")


def test_gate_checks_out_the_base_never_the_pr_head():
    assert LIVE.count("actions/checkout@") == 1
    ref = re.search(r"^\s+ref: (.+)$", LIVE, re.M).group(1)
    assert "pull_request.base.sha" in ref and "head" not in ref
    assert "repository:" not in LIVE  # never a fork's repository


def test_gate_runs_the_validator_from_the_checked_out_base_tree_on_extracted_data():
    assert "python -I scripts/validate_index.py" in LIVE and "python -I scripts/check_scope.py" in LIVE
    assert 'git show "$HEAD_SHA:marketplace.json"' in LIVE  # the PR contributes data only
    assert "pip install -r requirements-ci.txt" in LIVE  # from the base tree


def test_gate_never_interpolates_event_text_into_a_script():
    for block in re.findall(r"^\s+run: \|\n((?:\s{10,}.*\n)+)", LIVE, re.M):
        assert "${{" not in block


def test_self_tests_live_in_an_unprivileged_pull_request_workflow():
    assert re.search(r"^  pull_request:", TESTS, re.M) and "pull_request_target" not in TESTS
    assert re.search(r"^permissions:\n  contents: read\n", TESTS, re.M)


def test_gate_has_no_manual_or_other_trigger():
    """A manual run would use the file of whatever branch it is started from, so the gate has exactly these events."""
    on_block = re.search(r"^on:\n((?:  .*\n|\n)+)", LIVE, re.M).group(1)
    events = re.findall(r"^  ([a-z_]+):", on_block, re.M)
    assert sorted(events) == ["pull_request_target", "push"]
    assert "workflow_dispatch" not in LIVE and "workflow_call" not in LIVE and "workflow_run" not in LIVE


def test_pull_request_target_job_never_runs_pr_code():
    """The only checkout is the base sha; the PR head is fetched as a ref and read with `git show`, never checked out,
    built, installed or executed."""
    assert "git checkout" not in LIVE and "git switch" not in LIVE and "git merge" not in LIVE and "git worktree" not in LIVE
    assert "FETCH_HEAD" in LIVE and "git show" in LIVE
    runs = "\n".join(re.findall(r"^\s+run: (?:\|\n)?(.*(?:\n\s{10,}.*)*)", LIVE, re.M))
    for line in runs.splitlines():
        if line.strip().startswith(("python", "pip")):
            assert "$HEAD_SHA" not in line and "head-index" not in line.replace("$RUNNER_TEMP/head-index.json", "")


def test_codeowners_cover_the_gate():
    owners = (ROOT / ".github" / "CODEOWNERS").read_text()
    for path in ("/.github/", "/scripts/", "/schema/", "/requirements-ci.txt"):
        assert re.search(rf"^{re.escape(path)}\s+@\S+", owners, re.M), path
