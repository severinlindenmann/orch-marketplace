"""git tree -> package digest vectors (``vectors_tree_digest.json``): each case is built as a real git tree with
plumbing, read back with the validator's ``export_package`` and must give the recorded file list and digest. The file
is written to be adopted by orch-core's fetch tests (the missing git-tree -> digest vector of the Opus review)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import validate_index as v  # noqa: E402

CASES = json.loads(Path(__file__).with_name("vectors_tree_digest.json").read_text())["cases"]
ENV = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
       "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
       "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}  # fmt: skip


def git(repo, *args, stdin=None):
    return subprocess.run(["git", *args], cwd=repo, env={**ENV, "HOME": str(repo)}, input=stdin, check=True,
                          capture_output=True).stdout.decode().strip()  # fmt: skip


def build(repo, case):
    git(repo, "init", "-q", "--template=", "-b", "main")
    # an unrelated top-level file: with a "dir" it is outside the package, without one the case has no such file
    entries = list(case["files"])
    if case["dir"]:
        entries.append({"path": "README", "mode": "100644", "text": "not part of the package"})
    for f in entries:
        path = f["path"] if not case["dir"] or f["path"] == "README" else f"{case['dir']}/{f['path']}"
        oid = git(repo, "hash-object", "-w", "--stdin", stdin=f["text"].encode())
        git(repo, "update-index", "--add", "--cacheinfo", f"{f['mode']},{oid},{path}")
    tree = git(repo, "write-tree")
    return git(repo, "commit-tree", tree, "-m", "x")


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_git_tree_gives_the_recorded_digest(tmp_path, case):
    commit = build(tmp_path, case)
    files = v.export_package(str(tmp_path), commit, case["dir"], ENV)
    assert files == {f["path"]: f["text"].encode() for f in case["files"] if f["path"] != "README"}
    assert v.package_digest(files) == case["digest"]
