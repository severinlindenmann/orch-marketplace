"""Tests for scripts/validate_index.py. Entries are fetched from local repositories (file paths), never the network."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import validate_index as v  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = {
    "schema": "orch.addon/3", "name": "demo", "version": "1.0.0", "title": "Demo",
    "entry": {"cmd": ["demo"]}, "capabilities": ["network"], "min_core": "2.0.0",
}  # fmt: skip
URL = "https://github.com/severinlindenmann/orch-marketplace"
GIT_ENV = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}


def index(addons=None, **kw):
    doc = {"format": "orch.market/1", "name": "orch-marketplace", "version": 1, "source": {"git": URL},
           "addons": addons or []}  # fmt: skip
    doc.update(kw)
    return doc


def entry(**kw):
    e = {"id": "demo", "version": "1.0.0", "source": {"git": "https://github.com/acme/orch-addon-demo"},
         "commit": "a" * 40, "package_sha256": "sha256:" + "0" * 64, "capabilities": ["network"],
         "min_orch": "2.0.0"}  # fmt: skip
    e.update(kw)
    return e


def git(repo, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=repo,
                          env={**GIT_ENV, "HOME": str(repo)}, check=True, capture_output=True, text=True).stdout.strip()  # fmt: skip


def make_repo(tmp_path, files, *, sub="pkg"):
    repo = tmp_path / "addon"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    for name, data in files.items():
        p = repo / sub / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode())
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "x")
    return repo, git(repo, "rev-parse", "HEAD")


def local_fetch(repo):
    def fetch(url, commit, dest, env):
        v._git(["init", "-q", "--template=", dest], dest, env)
        v._git(["-c", "protocol.file.allow=always", "fetch", "-q", "--no-tags", str(repo), commit], dest, env)
        assert v._git(["rev-parse", "FETCH_HEAD"], dest, env).decode().strip() == commit

    return fetch


def src():
    return {"git": "https://github.com/acme/x", "subdir": "pkg"}


def good(tmp_path, manifest=MANIFEST):
    files = {"orch-addon.json": json.dumps(manifest), "main.py": "print('hi')\n"}
    repo, commit = make_repo(tmp_path, files)
    digest = v.package_digest({k: x.encode() for k, x in files.items()})
    return repo, entry(commit=commit, package_sha256=digest, source=src())


# ----- the committed files


def test_committed_index_is_valid():
    doc = v.strict_loads((ROOT / "marketplace.json").read_text())
    assert v.check_index(doc) == []


def test_committed_schema_is_the_spec_schema():
    assert json.loads((ROOT / "schema" / "market.v1.json").read_text())["$id"] == "https://schemas.orch.dev/market/1"


# ----- strict JSON


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":1.5}', '{"a":NaN}', '{"\\u00e4":1}', "[" * 20 + "]" * 20, "{"])
def test_strict_json_refuses(text):
    with pytest.raises(v.Invalid):
        v.strict_loads(text)


# ----- offline index checks


def test_empty_index_valid():
    assert v.check_index(index()) == []


def test_unknown_key_refused():
    assert v.check_index(index(extra=1))[0].startswith("market.malformed")


def test_branch_instead_of_commit_refused():
    assert any("commit" in p for p in v.check_index(index([entry(commit="main")])))


def test_bad_digest_refused():
    assert v.check_index(index([entry(package_sha256="sha256:abc")]))


def test_duplicate_id():
    assert any(p.startswith("market.duplicate_id") for p in v.check_index(index([entry(), entry()])))


def test_unsorted_capabilities():
    assert any("not sorted" in p for p in v.check_index(index([entry(capabilities=["pty", "network"])])))


@pytest.mark.parametrize(
    "url",
    ["https://github.com/a/b.git", "https://127.0.0.1/a/b", "http://github.com/a/b", "https://github.com:8443/a/b",
     "https://github.com/Acme/Repo"],
)
def test_bad_source_url_refused(url):
    assert v.check_index(index([entry(source={"git": url})])), url


def test_foreign_host_refused_unless_allowed():
    e = entry(source={"git": "https://git.example.org/a/b"})
    assert any(p.startswith("market.host_not_allowed") for p in v.check_index(index([e])))
    assert v.check_index(index([e]), extra_hosts=("git.example.org",)) == []


def test_same_host_as_marketplace_allowed():
    e = entry(source={"git": "https://git.example.org/a/b"})
    assert v.check_index(index([e], source={"git": "https://git.example.org/m/market"})) == []


def test_revoked_and_listed_conflict():
    assert any(p.startswith("market.revoked") for p in v.check_index(index([entry()], revoked=["demo@1.0.0"])))


def test_official_needs_expiry_and_signature():
    probs = v.check_index(index(), official=True, now=1000)
    assert len(probs) == 2 and all(p.startswith("market.index_unsigned") for p in probs)
    sig = {"key": "A" * 86 + "A", "sig": "A" * 85 + "A"}
    assert v.check_index(index(expires_at=2000, signature=sig), official=True, now=1000) == []
    assert v.check_index(index(expires_at=500, signature=sig), official=True, now=1000)


def test_rollback():
    prev = index([entry()], version=5)
    assert any("lower" in p for p in v.check_index(index([entry()], version=4), previous=prev))
    assert any("not raised" in p for p in v.check_index(index([], version=5), previous=prev))
    assert v.check_index(index([entry()], version=5), previous=prev) == []
    assert v.check_index(index([entry(version="1.1.0")], version=6), previous=prev) == []
    assert any("demo 0.9.0" in p for p in v.check_index(index([entry(version="0.9.0")], version=6), previous=prev))


# ----- listing and digest


def test_digest_is_sha256sum_of_sorted_lines():
    d = v.package_digest({"b": b"2", "a": b"1"})
    lines = f"{hashlib.sha256(b'1').hexdigest()}  a\n{hashlib.sha256(b'2').hexdigest()}  b\n"
    assert d == "sha256:" + hashlib.sha256(lines.encode()).hexdigest()


M = ("100644", "orch-addon.json", 3)


@pytest.mark.parametrize(
    "listing",
    [
        [("120000", "orch-addon.json", 3)],
        [("160000", "orch-addon.json", 0)],
        [M, ("100644", "../x", 1)],
        [M, ("100644", ".git/config", 1)],
        [M, ("100644", "A", 1), ("100644", "a", 1)],
        [M, ("100644", "x.so", 1)],
        [M, ("100644", "a", 1), ("100644", "a/b", 1)],
        [("100644", "orch-addon.json", 5 << 20)],
        [("100644", "main.py", 3)],
        [M] + [("100644", f"f{i}", 1) for i in range(300)],
    ],
)
def test_bad_listing_refused(listing):
    with pytest.raises(v.Invalid, match="package_invalid"):
        v.judge_listing(listing)


def test_good_listing_accepted():
    v.judge_listing([M, ("100755", "bin/run", 9)])


# ----- fetch + digest against a real local repository


def test_entry_matches(tmp_path):
    repo, e = good(tmp_path)
    v.check_entry(e, local_fetch(repo))


def test_digest_mismatch(tmp_path):
    repo, e = good(tmp_path)
    e["package_sha256"] = "sha256:" + "1" * 64
    with pytest.raises(v.Invalid, match="digest_mismatch"):
        v.check_entry(e, local_fetch(repo))


def test_missing_commit(tmp_path):
    repo, e = good(tmp_path)
    e["commit"] = "b" * 40
    with pytest.raises(v.Invalid, match="fetch_failed"):
        v.check_entry(e, local_fetch(repo))


@pytest.mark.parametrize(
    "field,value",
    [("name", "other"), ("version", "9.9.9"), ("min_core", "3.0.0"), ("capabilities", ["pty"]),
     ("schema", "orch.addon/2"), ("runtime", {"kind": "python-requirements", "lock": "r.txt"})],
)
def test_manifest_mismatch(tmp_path, field, value):
    repo, e = good(tmp_path, {**MANIFEST, field: value})
    with pytest.raises(v.Invalid, match="manifest_mismatch"):
        v.check_entry(e, local_fetch(repo))


def test_symlink_in_tree_refused(tmp_path):
    repo, _ = make_repo(tmp_path, {"orch-addon.json": json.dumps(MANIFEST)})
    (repo / "pkg" / "link").symlink_to("orch-addon.json")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "link")
    e = entry(commit=git(repo, "rev-parse", "HEAD"), source=src())
    with pytest.raises(v.Invalid, match="package_invalid"):
        v.check_entry(e, local_fetch(repo))


def test_attributes_cannot_change_bytes(tmp_path):
    repo, _ = make_repo(tmp_path, {"orch-addon.json": json.dumps(MANIFEST), "a.txt": "x\r\ny\n"})
    (repo / ".gitattributes").write_text("* text eol=lf\n")  # outside pkg/, as a hostile repo would have it
    git(repo, "add", ".gitattributes")
    git(repo, "commit", "-qm", "attrs")
    commit = git(repo, "rev-parse", "HEAD")
    files = v.export_package(str(repo), commit, "pkg", {**v.git_env(str(tmp_path)), "GIT_DIR": str(repo / ".git")})
    assert files["a.txt"] == b"x\r\ny\n"


# ----- CLI


def test_cli_valid_and_invalid(tmp_path, capsys):
    p = tmp_path / "m.json"
    p.write_text(json.dumps(index()))
    assert v.main([str(p)]) == 0
    p.write_text(json.dumps(index(version=0)))
    assert v.main([str(p)]) == 1
    assert "FAIL" in capsys.readouterr().out
