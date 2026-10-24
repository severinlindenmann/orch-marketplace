"""M#4 / M#5 hardening: entry count with directories, address pin before fetch, pack size cap; history refuses a
shallow repo, reads a second ref, keeps revocations, fails cleanly on a bad historic file."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import validate_index as v  # noqa: E402
from test_validate_index import M, entry, git, index  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


# ----- M#4: files and directories count toward the 256 limit


def test_files_alone_at_the_limit_pass_but_directories_push_it_over():
    flat = [M] + [("100644", f"f{i}", 1) for i in range(255)]  # 256 entries, no directory
    v.judge_listing(flat)
    nested = [M] + [("100644", f"d/f{i}", 1) for i in range(254)]  # 255 files + the directory d = 256
    v.judge_listing(nested)
    with pytest.raises(v.Invalid, match="files and directories"):
        v.judge_listing([M] + [("100644", f"d/f{i}", 1) for i in range(255)])  # 256 files + d = 257
    with pytest.raises(v.Invalid, match="files and directories"):
        v.judge_listing([M] + [("100644", f"d{i}/f", 1) for i in range(130)])  # 131 files + 130 directories


def test_a_directory_shared_by_many_files_counts_once():
    v.judge_listing([M] + [("100644", f"a/b/c/f{i}", 1) for i in range(200)])  # 201 files + a, a/b, a/b/c


# ----- M#4: the address is checked, and git is told to use it


def test_pin_address_pins_the_first_judged_address(monkeypatch):
    monkeypatch.setattr(v, "resolve_host", lambda host, timeout=0: ["140.82.112.3", "140.82.112.4"])
    env = v.pin_address("https://github.com/acme/x")
    assert env == {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.curloptResolve",
                   "GIT_CONFIG_VALUE_0": "github.com:443:140.82.112.3"}  # fmt: skip
    monkeypatch.setattr(v, "resolve_host", lambda host, timeout=0: ["2606:4700:4700::1111"])
    assert v.pin_address("https://github.com/acme/x")["GIT_CONFIG_VALUE_0"] == "github.com:443:[2606:4700:4700::1111]"


@pytest.mark.parametrize("url", ["http://github.com/a/b", "/tmp/repo", "file:///tmp/x", "ssh://github.com/a/b"])
def test_pin_address_refuses_a_non_https_url(url):
    with pytest.raises(v.Invalid, match="address_refused"):
        v.pin_address(url)


def test_one_private_address_among_public_ones_refuses_the_host(monkeypatch):
    import socket

    def fake(host, port, type=0):
        return [(2, 1, 6, "", ("140.82.112.3", 443)), (2, 1, 6, "", ("169.254.169.254", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(v.Invalid, match="address_refused"):
        v.resolve_host("evil.example")


def test_a_host_that_does_not_resolve_is_a_fetch_failure(monkeypatch):
    import socket

    def fail(host, port, type=0):
        raise socket.gaierror("no")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(v.Invalid, match="fetch_failed"):
        v.resolve_host("nope.example")


def test_check_entry_refuses_a_private_host_before_any_fetch(monkeypatch):
    called = []
    monkeypatch.setattr(v, "resolve_host", lambda host, timeout=0: [v.check_address("10.0.0.1")])
    e = entry(source={"git": "https://github.com/acme/x"})
    with pytest.raises(v.Invalid, match="address_refused"):
        v.check_entry(e, fetch=lambda *a: called.append("fetch"), reach=lambda *a: called.append("reach"))
    assert called == []


def test_check_entry_hands_the_pin_to_fetch_and_reach(monkeypatch):
    seen = []
    monkeypatch.setattr(v, "resolve_host", lambda host, timeout=0: ["140.82.112.3"])

    def fetch(url, commit, repo, env):
        seen.append(env["GIT_CONFIG_VALUE_0"])
        raise v.Invalid("market.fetch_failed: stop here")

    with pytest.raises(v.Invalid, match="stop here"):
        v.check_entry(entry(source={"git": "https://github.com/acme/x"}), fetch=fetch)
    assert seen == ["github.com:443:140.82.112.3"]


# ----- M#4: a pack larger than the cap kills git


def test_git_with_a_file_size_cap_fails_when_a_write_passes_it(tmp_path):
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}  # fmt: skip
    repo = tmp_path / "r"
    repo.mkdir()
    v._git(["init", "-q", "--template="], str(repo), env)
    (repo / "big").write_bytes(os.urandom(3 << 20))
    ident = ["-c", "user.name=t", "-c", "user.email=t@t"]
    v._git([*ident, "add", "big"], str(repo), env)
    v._git([*ident, "commit", "-qm", "big"], str(repo), env)
    assert v._git(["rev-parse", "HEAD"], str(repo), env, max_file=8 << 20)  # under the cap: works
    v._git(["repack", "-a", "-d", "-q"], str(repo), env, max_file=8 << 20)  # a 3 MB pack under an 8 MB cap
    with pytest.raises(v.Invalid, match="fetch_failed"):
        v._git(["repack", "-a", "-d", "-q", "-f"], str(repo), env, max_file=1 << 20)  # the pack would be 3 MB


def test_the_caps_are_the_core_ones():
    assert v.PACK_CAP_COMMIT == (16 << 20) + (8 << 20)  # core gitsafe.MARKET_PACKAGE_PACK
    assert v.PACK_CAP_HISTORY > v.PACK_CAP_COMMIT


# ----- M#5: history


def commit_index(repo, doc_or_text, msg="i"):
    text = doc_or_text if isinstance(doc_or_text, str) else json.dumps(doc_or_text)
    (repo / "marketplace.json").write_text(text)
    git(repo, "add", "marketplace.json")
    git(repo, "commit", "-qm", msg)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "market"
    r.mkdir()
    git(r, "init", "-q", "-b", "develop")
    return r


def test_a_shallow_repository_is_refused(tmp_path, repo):
    commit_index(repo, index([entry(version="1.0.0")], version=1))
    commit_index(repo, index([entry(version="1.1.0")], version=2))
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "-c", "protocol.file.allow=always", "clone", "-q", "--depth", "1", f"file://{repo}",
                    str(shallow)], check=True, capture_output=True, env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"})  # fmt: skip
    with pytest.raises(v.Invalid, match="shallow"):
        v.history_from_git("HEAD", cwd=str(shallow))
    assert len(v.history_from_git("develop", cwd=str(repo))) == 2


@pytest.mark.parametrize("text", ["[]", '{"addons": 5}', '{"addons": [5]}', '{"addons": [{"id": "x"}]}',
                                  '{"addons": [], "revoked": [1]}', '"x"',
                                  '{"addons": [{"id": "x", "version": "v1", "commit": "c", "package_sha256": "s", "source": {}}]}'])  # fmt: skip
def test_a_historic_file_that_parses_but_is_no_index_is_a_clean_error(repo, text):
    commit_index(repo, index([entry()], version=1))
    commit_index(repo, text)
    with pytest.raises(v.Invalid, match="market.malformed: history"):
        v.history_from_git("develop", cwd=str(repo))


def test_main_prints_fail_not_a_traceback_for_a_bad_historic_file(repo, tmp_path, capsys):
    commit_index(repo, '{"addons": [{"id": "x"}]}')
    p = tmp_path / "new.json"
    p.write_text(json.dumps(index(version=2)))
    old = Path.cwd()
    os.chdir(repo)
    try:
        assert v.main([str(p), "--history-ref", "develop"]) == 1
    finally:
        os.chdir(old)
    out = capsys.readouterr().out
    assert out.startswith("FAIL market.malformed: history") and "Traceback" not in out


def test_only_a_deletion_is_skipped(repo):
    commit_index(repo, index([entry(version="1.0.0")], version=1))
    git(repo, "rm", "-q", "marketplace.json")
    git(repo, "commit", "-qm", "delete")
    commit_index(repo, index([entry(version="1.1.0")], version=2))
    assert [d["version"] for d in v.history_from_git("develop", cwd=str(repo))] == [1, 2]


def test_an_unreadable_historic_blob_is_an_error_not_a_skip(repo):
    commit_index(repo, index([entry(version="1.0.0")], version=1))
    commit_index(repo, index([entry(version="1.1.0")], version=2))
    sha = git(repo, "rev-parse", "HEAD~1:marketplace.json")
    obj = repo / ".git" / "objects" / sha[:2] / sha[2:]
    obj.chmod(0o644)
    obj.write_bytes(b"garbage")  # a corrupt object: git show fails, which is not a deletion
    with pytest.raises(v.Invalid, match="fetch_failed"):
        v.history_from_git("develop", cwd=str(repo))


def test_a_non_utf8_historic_file_is_a_clean_error(repo):
    (repo / "marketplace.json").write_bytes(b'{"addons": [], "x": "\xff"}')
    git(repo, "add", "marketplace.json")
    git(repo, "commit", "-qm", "bad")
    with pytest.raises(v.Invalid, match="market.malformed: history"):
        v.history_from_git("develop", cwd=str(repo))


def test_history_keeps_revocations():
    h = [index([entry(version="1.0.0")], version=1), index([], version=2, revoked=["demo@1.0.0"])]
    assert v.check_index(index([], version=3, revoked=["demo@1.0.0"]), history=h) == []
    dropped = v.check_index(index([], version=3), history=h)
    assert any("revocation dropped" in p for p in dropped)
    relisted = v.check_index(index([entry(version="1.0.0")], version=3), history=h)
    assert any("market.revoked" in p for p in relisted)


def test_two_history_refs_both_count(repo, tmp_path):
    commit_index(repo, index([entry(version="1.0.0")], version=1))
    git(repo, "branch", "main")
    git(repo, "checkout", "-q", "main")
    commit_index(repo, index([entry(version="1.2.0")], version=2))  # main got a release develop does not have
    git(repo, "checkout", "-q", "develop")
    p = tmp_path / "new.json"
    p.write_text(json.dumps(index([entry(version="1.1.0")], version=2)))
    old = Path.cwd()
    os.chdir(repo)
    try:
        assert v.main([str(p), "--history-ref", "develop"]) == 0
        assert v.main([str(p), "--history-ref", "develop", "--history-ref", "main"]) == 1  # below 1.2.0 of main
    finally:
        os.chdir(old)


def test_a_pin_that_differs_from_any_ref_is_a_rollback():
    a = index([entry(version="1.0.0", commit="a" * 40)], version=1)
    b = index([entry(version="1.0.0", commit="b" * 40)], version=1)  # two refs disagree
    assert any("another pin" in p for p in v.check_index(index([entry(version="1.0.0", commit="a" * 40)], version=2), history=[a, b]))
    assert any("another pin" in p for p in v.check_index(index([entry(version="1.0.0", commit="b" * 40)], version=2), history=[a, b]))
