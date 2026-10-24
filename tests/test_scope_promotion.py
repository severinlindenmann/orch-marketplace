"""M2-1: the develop -> main promotion PR may carry gate and index changes; plus path tricks against check_scope (review)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import check_scope as cs  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]


def _repo(tmp_path):
    def run(*a):
        return subprocess.run([*GIT, *a], cwd=tmp_path, check=True, capture_output=True, text=True,
                              env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}).stdout.strip()  # fmt: skip
    run("init", "-q", "-b", "main")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "validate_index.py").write_text("x\n")
    (tmp_path / "marketplace.json").write_text("{}\n")
    run("add", "-A")
    run("commit", "-qm", "base")
    return run, run("rev-parse", "HEAD")


@pytest.mark.parametrize("trick", ["rename_dir", "symlink_scripts", "mode_only", "delete_gate"])
def test_scope_tricks(tmp_path, trick):
    run, base = _repo(tmp_path)
    (tmp_path / "marketplace.json").write_text('{"a":1}\n')
    if trick == "rename_dir":
        run("mv", "scripts", "scripts2")
    elif trick == "symlink_scripts":
        run("rm", "-rq", "scripts")
        os.symlink("other", tmp_path / "scripts")
    elif trick == "mode_only":
        os.chmod(tmp_path / "scripts/validate_index.py", 0o755)
    elif trick == "delete_gate":
        run("rm", "-q", "scripts/validate_index.py")
    run("add", "-A")
    run("commit", "-qm", "head")
    out = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "check_scope.py"), "--base", base, "--head", run("rev-parse", "HEAD")],
                         cwd=tmp_path, capture_output=True, text=True)  # fmt: skip
    assert out.returncode == 1, out.stdout


def test_promotion_pr_may_carry_gate_and_index_changes():
    both = ["marketplace.json", "scripts/validate_index.py", ".github/workflows/ci.yml"]
    assert cs.judge(both)
    assert cs.judge(both, promotion=True) == []
    assert cs.judge(both, only="marketplace.json", promotion=True), "promotion never relaxes --only"



def test_cli_promotion_flag(tmp_path):
    run, base = _repo(tmp_path)
    run("checkout", "-qb", "develop")
    (tmp_path / "scripts" / "validate_index.py").write_text("v2")
    (tmp_path / "marketplace.json").write_text('{"x":1}')
    run("add", "-A"); run("commit", "-qm", "both")  # noqa: E702
    head = run("rev-parse", "HEAD")
    cmd = [sys.executable, str(ROOT / "scripts" / "check_scope.py"), "--base", base, "--head", head]
    assert subprocess.run(cmd, cwd=tmp_path, capture_output=True).returncode == 1
    assert subprocess.run([*cmd, "--promotion"], cwd=tmp_path, capture_output=True).returncode == 0

