#!/usr/bin/env python3
"""Validate an orch add-on marketplace index (``marketplace.json``, format ``orch.market/1``).

Spec: orch-core ``docs/architecture/orch-v2-marketplace.md`` (sections 3, 4.1, 5.1.1). Two stages:

* offline (always): strict JSON, the schema, unique ids, sorted capabilities, canonical URLs, git host rule, rollback
  against ``--previous``, and for ``--official`` the presence of ``expires_at`` and ``signature``;
* network (``--fetch``): for every entry, fetch ``commit`` (it must exist and be the commit named), read the package
  from git plumbing in memory (no checkout), judge the tree like ticket-format 8.1, recompute ``package_sha256`` and
  compare it, and check the manifest agrees with the entry.

The index is attacker-controlled text: git runs with an isolated environment and closed settings. Signature
*verification* is not done here (the official key is pinned in core, not in this repo): the signing step is a later
release step and the installer verifies. Exit code 0 = valid, 1 = invalid, 2 = usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "market.v1.json"
DEFAULT_GIT_HOSTS = ("github.com", "gitlab.com")
CASE_INSENSITIVE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")

# Package rules, ticket-format 8.1 (mirror of orch.addons.package).
MANIFEST_FILE = "orch-addon.json"
MAX_DEPTH, MAX_FILES = 6, 256
MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_MANIFEST_BYTES = 4 << 20, 16 << 20, 64 << 10
REFUSED_SUFFIXES = (".pyc", ".pyo", ".so", ".dylib", ".dll", ".pyd")
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?![\s\S])")
_FETCH_TIMEOUT = 120


class Invalid(Exception):
    """One refusal; the message starts with the stable code (``market.*``)."""


# ----------------------------------------------------------------------------------------------- strict JSON


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise Invalid(f"market.malformed: duplicate key {k!r}")
        if not k.isascii():
            raise Invalid("market.malformed: non-ASCII key")
        out[k] = v
    return out


def _no_float(s: str) -> Any:
    raise Invalid(f"market.malformed: number {s} is not an integer")


def _no_const(s: str) -> Any:
    raise Invalid(f"market.malformed: {s} is not allowed")


def _depth(v: Any, n: int = 1) -> None:
    if n > 16:
        raise Invalid("market.malformed: nesting over 16")
    for c in v.values() if isinstance(v, dict) else v if isinstance(v, list) else ():
        _depth(c, n + 1)


def strict_loads(text: str) -> Any:
    try:
        doc = json.loads(text, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_const)
    except json.JSONDecodeError as e:
        raise Invalid(f"market.malformed: not JSON ({e.msg})") from None
    except RecursionError:
        raise Invalid("market.malformed: nesting over 16") from None
    _depth(doc)
    return doc


# ----------------------------------------------------------------------------------------------- the index


def canonical_url_ok(url: str) -> bool:
    """The schema forbids ``.git``, ports, credentials, query. This adds the lower-case rule (spec 4.1)."""
    parts = urlsplit(url)
    if (parts.hostname or "") in CASE_INSENSITIVE_HOSTS:
        return parts.path == parts.path.lower()
    return True


def check_index(doc: Any, *, previous: Any = None, official: bool = False, now: float | None = None,
                extra_hosts: tuple[str, ...] = ()) -> list[str]:
    """Offline checks; returns a list of ``market.*`` problems (empty = valid)."""
    schema = json.loads(SCHEMA_PATH.read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.absolute_path))
    problems = [
        f"market.malformed: {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message[:200]}" for e in errors
    ]
    if problems:
        return problems  # the rest assumes the shape
    own = doc["source"]["git"]
    if not canonical_url_ok(own):
        problems.append("market.malformed: source.git is not lower-case on a case-insensitive host")
    host = urlsplit(own).hostname
    seen: set[str] = set()
    for i, e in enumerate(doc["addons"]):
        where = f"addons[{i}] ({e['id']})"
        if e["id"] in seen:
            problems.append(f"market.duplicate_id: {where}")
        seen.add(e["id"])
        if e["capabilities"] != sorted(e["capabilities"]):
            problems.append(f"market.malformed: {where}: capabilities are not sorted")
        if not canonical_url_ok(e["source"]["git"]):
            problems.append(f"market.malformed: {where}: source.git is not lower-case on a case-insensitive host")
        h = urlsplit(e["source"]["git"]).hostname
        if h != host and h not in DEFAULT_GIT_HOSTS and h not in extra_hosts:
            problems.append(f"market.host_not_allowed: {where}: {h}")
    revoked = set(doc.get("revoked", []))
    for r in revoked:
        if r in {f"{e['id']}@{e['version']}" for e in doc["addons"]}:
            problems.append(f"market.revoked: {r} is both listed and revoked")
    if official:
        if "expires_at" not in doc:
            problems.append("market.index_unsigned: official index needs expires_at")
        elif doc["expires_at"] < (time.time() if now is None else now):
            problems.append("market.index_unsigned: expires_at is in the past")
        if "signature" not in doc:
            problems.append("market.index_unsigned: official index needs a signature")
    if previous is not None:
        problems += _rollback(doc, previous)
    return problems


def _rollback(doc: dict[str, Any], prev: dict[str, Any]) -> list[str]:
    out = []
    if doc["version"] < prev["version"]:
        out.append(f"market.rollback: version {doc['version']} is lower than {prev['version']}")
    elif doc["version"] == prev["version"] and _content(doc) != _content(prev):
        out.append("market.rollback: the index changed but its version was not raised")
    old = {e["id"]: e for e in prev.get("addons", [])}
    prev_revoked = set(prev.get("revoked", []))
    now_revoked = set(doc.get("revoked", []))
    if not prev_revoked <= now_revoked:
        out.append(f"market.rollback: revocation dropped: {', '.join(sorted(prev_revoked - now_revoked))}")
    ids_now = {e["id"] for e in doc["addons"]}
    for i, o in old.items():
        if i not in ids_now and f"{i}@{o['version']}" not in now_revoked:
            out.append(f"market.rollback: {i} was dropped; list {i}@{o['version']} in revoked (a pin cannot be re-added)")
    for e in doc["addons"]:
        o = old.get(e["id"])
        if f"{e['id']}@{e['version']}" in prev_revoked:
            out.append(f"market.revoked: {e['id']}@{e['version']} was revoked and cannot be listed again")
        if o is None:
            continue
        if _semver(e["version"]) < _semver(o["version"]):
            out.append(f"market.rollback: {e['id']} {e['version']} is lower than {o['version']}")
        elif e["version"] == o["version"]:
            for k in ("commit", "package_sha256", "source"):
                if e[k] != o[k]:
                    out.append(f"market.rollback: {e['id']} {e['version']}: {k} changed without a higher version")
    return out


def _content(doc: dict[str, Any]) -> Any:
    return {k: v for k, v in doc.items() if k not in ("title",)}


def _semver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


# ----------------------------------------------------------------------------------------------- package digest


def package_digest(files: dict[str, bytes]) -> str:
    """``sha256:`` + SHA-256 of ``<sha256 hex>  <path>\\n`` lines in byte order of the path (ticket-format 8.1)."""
    if not files:
        raise Invalid("market.package_invalid: an empty package")
    lines = [f"{hashlib.sha256(files[p]).hexdigest()}  {p}\n" for p in sorted(files, key=lambda p: p.encode())]
    return "sha256:" + hashlib.sha256("".join(lines).encode()).hexdigest()


def check_path(rel: str) -> None:
    parts = rel.split("/")
    if len(parts) > MAX_DEPTH:
        raise Invalid(f"market.package_invalid: {ascii(rel)}: more than {MAX_DEPTH} levels")
    for part in parts:
        if part == "__pycache__" or not _SEGMENT.fullmatch(part):
            raise Invalid(f"market.package_invalid: {ascii(rel)}: bad file name")
    if parts[-1].lower().endswith(REFUSED_SUFFIXES):
        raise Invalid(f"market.package_invalid: {ascii(rel)}: compiled files are not allowed")


def judge_listing(listing: list[tuple[str, str, int]]) -> None:
    """``listing`` = (mode, path, size) from ``git ls-tree -r -l``. Judged before any blob is read (spec 5.1.1)."""
    if len(listing) > MAX_FILES:
        raise Invalid("market.package_invalid: too many files")
    names: set[str] = set()
    dirs: set[str] = set()
    total = 0
    for mode, path, size in listing:
        if mode not in ("100644", "100755"):
            raise Invalid(f"market.package_invalid: {ascii(path)}: mode {mode} (link, submodule or odd entry)")
        check_path(path)
        folded = unicodedata.normalize("NFC", path).casefold()
        if folded in names:
            raise Invalid(f"market.package_invalid: {ascii(path)}: duplicate name after case folding")
        names.add(folded)
        for i in range(1, len(path.split("/"))):
            dirs.add(unicodedata.normalize("NFC", "/".join(path.split("/")[:i])).casefold())
        if size > MAX_FILE_BYTES:
            raise Invalid(f"market.package_invalid: {ascii(path)}: larger than {MAX_FILE_BYTES} bytes")
        total += size
    if names & dirs:
        raise Invalid("market.package_invalid: a name is both a file and a directory")
    if total > MAX_TOTAL_BYTES:
        raise Invalid("market.package_invalid: too many bytes in all")
    if MANIFEST_FILE not in {p for _, p, _ in listing}:
        raise Invalid(f"market.package_invalid: no {MANIFEST_FILE} at the top of the package")


# ----------------------------------------------------------------------------------------------- git


def git_env(home: str) -> dict[str, str]:
    empty = os.path.join(home, "empty-gitconfig")
    Path(empty).write_text("")
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "GIT_CONFIG_GLOBAL": empty,
        "GIT_CONFIG_SYSTEM": empty,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
    }


def _git(args: list[str], cwd: str, env: dict[str, str], *, timeout: int = _FETCH_TIMEOUT) -> bytes:
    try:
        r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Invalid("market.fetch_failed: git timed out") from None
    if r.returncode != 0:
        raise Invalid(f"market.fetch_failed: git {args[0]} failed: {r.stderr.decode(errors='replace')[:200].strip()}")
    return r.stdout


FETCH_SETTINGS = [
    "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "http.followRedirects=false",
    "-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true", "-c", "core.hooksPath=/dev/null",
    "-c", "core.symlinks=false", "-c", "submodule.recurse=false",
]  # fmt: skip


def fetch_commit(url: str, commit: str, repo: str, env: dict[str, str]) -> None:
    """Fetch exactly ``commit`` into the fresh repo at ``repo`` and check that it is the commit named."""
    fmt = "sha1" if len(commit) == 40 else "sha256"
    _git(["init", "-q", "--template=", f"--object-format={fmt}", repo], repo, env)
    _git([*FETCH_SETTINGS, "fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules", url, commit],
         repo, env)  # fmt: skip
    if _git(["rev-parse", "FETCH_HEAD"], repo, env).decode().strip() != commit:
        raise Invalid("market.commit_mismatch: the fetched object is not the pinned commit")


def ensure_reachable(url: str, commit: str, repo: str, env: dict[str, str], extra: tuple[str, ...] = ()) -> None:
    """GitHub serves a commit that exists only in a fork under the parent's URL. Require the commit to be reachable
    from a branch or tag of the named repo: fetch its heads and tags and ask which of them contain the commit."""
    settings = [x for kv in extra for x in ("-c", kv)]
    _git([*FETCH_SETTINGS, *settings, "fetch", "-q", "--no-tags", "--no-recurse-submodules", url,
          "+refs/heads/*:refs/remotes/origin/*", "+refs/tags/*:refs/tags/*"], repo, env, timeout=600)  # fmt: skip
    refs = _git(["for-each-ref", "--contains", commit, "--count=1", "--format=%(refname)",
                 "refs/remotes/origin", "refs/tags"], repo, env).strip()  # fmt: skip
    if not refs:
        raise Invalid("market.commit_unreachable: the commit is on no branch or tag of the named repo (fork commit?)")


def export_package(repo: str, commit: str, subdir: str | None, env: dict[str, str]) -> dict[str, bytes]:
    """Read the package in memory with git plumbing (no checkout, so no attribute filter touches a byte)."""
    tree = f"{commit}:{subdir}" if subdir else f"{commit}:"
    raw = _git(["ls-tree", "-r", "-z", "-l", tree], repo, env)
    listing, ids = [], {}
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, kind, oid, size = meta.decode().split()
        try:
            p = path.decode("ascii")
        except UnicodeDecodeError:
            raise Invalid("market.package_invalid: non-ASCII path") from None
        listing.append((mode, p, int(size) if size != "-" else 0))
        ids[p] = oid
    judge_listing(listing)
    files = {}
    for _, p, size in listing:
        blob = _git(["cat-file", "blob", ids[p]], repo, env)
        if len(blob) != size:
            raise Invalid(f"market.package_invalid: {ascii(p)}: size differs from the listing")
        files[p] = blob
    if len(files[MANIFEST_FILE]) > MAX_MANIFEST_BYTES:
        raise Invalid("market.package_invalid: manifest too large")
    return files


def check_manifest(entry: dict[str, Any], manifest_bytes: bytes) -> None:
    try:
        m = strict_loads(manifest_bytes.decode())
    except (Invalid, UnicodeDecodeError) as e:
        raise Invalid(f"market.manifest_mismatch: manifest is not strict JSON ({e})") from None
    if not isinstance(m, dict):
        raise Invalid("market.manifest_mismatch: manifest is not an object")
    caps = m.get("capabilities", [])
    checks = {
        "schema": m.get("schema") == "orch.addon/3",
        "name": m.get("name") == entry["id"],
        "version": m.get("version") == entry["version"],
        "capabilities": isinstance(caps, list) and sorted(caps) == entry["capabilities"],
        "min_core": m.get("min_core") == entry["min_orch"],
    }
    for k, ok in checks.items():
        if not ok:
            raise Invalid(f"market.manifest_mismatch: manifest {k} differs from the entry")
    if m.get("runtime") != entry.get("runtime"):
        raise Invalid("market.manifest_mismatch: manifest runtime differs from the entry")


def check_entry(entry: dict[str, Any], fetch=fetch_commit, reach=ensure_reachable) -> None:
    """Fetch, export, digest, manifest. Raises :class:`Invalid`. ``fetch`` is replaceable for tests."""
    home = tempfile.mkdtemp(prefix="mk-validate-")
    try:
        env = git_env(home)
        repo = os.path.join(home, "repo")
        os.mkdir(repo)
        fetch(entry["source"]["git"], entry["commit"], repo, env)
        reach(entry["source"]["git"], entry["commit"], repo, env)
        files = export_package(repo, entry["commit"], entry["source"].get("subdir"), env)
        if package_digest(files) != entry["package_sha256"]:
            raise Invalid(f"market.digest_mismatch: computed {package_digest(files)}")
        check_manifest(entry, files[MANIFEST_FILE])
    finally:
        _rmtree(home)


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


# ----------------------------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("index", nargs="?", default="marketplace.json")
    ap.add_argument("--previous", help="the index on the base branch (rollback check)")
    ap.add_argument("--official", action="store_true", help="require expires_at and signature")
    ap.add_argument("--fetch", action="store_true", help="fetch every entry at its commit and compare the digest")
    ap.add_argument("--allow-host", action="append", default=[], help="extra git host (the core allow list)")
    a = ap.parse_args(argv)
    try:
        doc = strict_loads(Path(a.index).read_text())
        prev = strict_loads(Path(a.previous).read_text()) if a.previous and Path(a.previous).exists() else None
    except (Invalid, OSError) as e:
        print(f"FAIL {e}")
        return 1
    problems = check_index(doc, previous=prev, official=a.official, extra_hosts=tuple(a.allow_host))
    if not problems and a.fetch:
        for e in doc["addons"]:
            try:
                check_entry(e)
                print(f"ok   {e['id']} {e['version']} {e['commit'][:12]} {e['package_sha256'][:19]}")
            except Invalid as ex:
                problems.append(f"{e['id']}: {ex}")
    for p in problems:
        print(f"FAIL {p}")
    if not problems:
        print(f"valid: {len(doc['addons'])} add-on(s), index version {doc['version']}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
