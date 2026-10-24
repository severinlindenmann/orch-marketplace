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
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "market.v1.json"
# core's manifest schema and the shared definitions it references, vendored byte-identical (orch/schema/schemas/)
MANIFEST_SCHEMA_PATH = SCHEMA_PATH.with_name("addon-manifest.json")
COMMON_SCHEMA_PATH = SCHEMA_PATH.with_name("common.json")
ADDON_API = (1, 1)  # the add-on API of the core this copy of the schemas comes from; a package must run on it
DEFAULT_GIT_HOSTS = ("github.com", "gitlab.com")
CASE_INSENSITIVE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")

# Package rules, ticket-format 8.1 (mirror of orch.addons.package).
MANIFEST_FILE = "orch-addon.json"
ADDON_API_1_1_CAPS = ("choose_model", "credential")  # addon-api 1.1; the index lists them like any other capability
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
                extra_hosts: tuple[str, ...] = (), history: list[Any] | None = None) -> list[str]:
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
    if history:
        problems += _history(doc, history)
    return problems


def _history(doc: dict[str, Any], docs: list[dict[str, Any]]) -> list[str]:
    """Append-only history: every (id, version) ever listed keeps its pin, an id never goes below the highest version
    ever listed, and every revocation ever published stays, so dropping an id and re-adding it cannot change a
    published pin, roll it back or lift a revocation. ``docs`` may come from several refs; a pin counts as changed if
    it differs from ANY historic pin of that (id, version)."""
    pins: dict[tuple[str, str], list[tuple[Any, Any, Any]]] = {}
    floor: dict[str, str] = {}
    revoked: set[str] = set()
    for old in docs:
        revoked.update(old.get("revoked", []))
        for e in old.get("addons", []):
            pin = (e["commit"], e["package_sha256"], e["source"])
            known = pins.setdefault((e["id"], e["version"]), [])
            if pin not in known:
                known.append(pin)
            if e["id"] not in floor or _semver(e["version"]) > _semver(floor[e["id"]]):
                floor[e["id"]] = e["version"]
    out = []
    dropped = sorted(revoked - set(doc.get("revoked", [])))
    if dropped:
        out.append(f"market.rollback: revocation dropped from the history: {', '.join(dropped)}")
    for e in doc["addons"]:
        if f"{e['id']}@{e['version']}" in revoked:
            out.append(f"market.revoked: {e['id']}@{e['version']} was revoked in the history and cannot be listed")
        if any(p != (e["commit"], e["package_sha256"], e["source"]) for p in pins.get((e["id"], e["version"]), [])):
            out.append(f"market.rollback: {e['id']} {e['version']} was published with another pin in the history")
        if e["id"] in floor and _semver(e["version"]) < _semver(floor[e["id"]]):
            out.append(f"market.rollback: {e['id']} {e['version']} is below {floor[e['id']]}, listed before")
    return out


_HISTORY_ENTRY = {"id": str, "version": str, "commit": str, "package_sha256": str, "source": dict}


def _history_shape(doc: Any) -> None:
    """The history code reads these fields of every historic entry; a historic file that parses as JSON but lacks
    them is a clean :class:`Invalid`, never a traceback."""
    ok = isinstance(doc, dict) and isinstance(doc.get("addons"), list)
    revoked = doc.get("revoked", []) if ok else []
    ok = ok and isinstance(revoked, list) and all(isinstance(r, str) for r in revoked)
    for e in doc["addons"] if ok else []:
        ok = ok and isinstance(e, dict) and all(isinstance(e.get(k), t) for k, t in _HISTORY_ENTRY.items())
        ok = ok and re.fullmatch(r"[0-9]+(\.[0-9]+)*", e["version"]) is not None
        if not ok:
            break
    if not ok:
        raise Invalid("not a valid index (addons, revoked or an entry has the wrong shape)")


def history_from_git(ref: str, path: str = "marketplace.json", cwd: str = ".") -> list[dict[str, Any]]:
    """Every version of ``path`` on the first-parent history of ``ref`` (oldest first), parsed strictly. A shallow
    repository is refused (its history is cut, so the record would silently be incomplete). Only a commit that DELETED
    the file is skipped; any other failure to read it is an error."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}  # fmt: skip
    if _git(["rev-parse", "--is-shallow-repository"], cwd, env).decode().strip() != "false":
        raise Invalid("market.history_incomplete: the repository is shallow; fetch the full history (fetch-depth: 0)")
    shas = _git(["log", "--first-parent", "--reverse", "--format=%H", ref, "--", path], cwd, env).decode().split()
    docs = []
    for sha in shas:
        if not _git(["ls-tree", "--name-only", sha, "--", path], cwd, env).strip():
            continue  # the commit deleted the file
        try:
            doc = strict_loads(_git(["show", f"{sha}:{path}"], cwd, env).decode())
            _history_shape(doc)
        except (Invalid, UnicodeDecodeError) as e:
            raise Invalid(f"market.malformed: history {sha[:12]}: {e}") from None
        docs.append(doc)
    return docs


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
    """``listing`` = (mode, path, size) from ``git ls-tree -r -l``. Judged before any blob is read (spec 5.1.1).
    Like core (``orch.addons.package.check_listing``) the 256-entry limit counts files AND directories."""
    if len(listing) > MAX_FILES:
        raise Invalid("market.package_invalid: too many files")
    names: set[str] = set()
    dirs: set[str] = set()  # the same directories core counts: every proper prefix of a path, case as written
    folded_dirs: set[str] = set()
    total = 0
    for mode, path, size in listing:
        if mode not in ("100644", "100755"):
            raise Invalid(f"market.package_invalid: {ascii(path)}: mode {mode} (link, submodule or odd entry)")
        check_path(path)
        folded = unicodedata.normalize("NFC", path).casefold()
        if folded in names:
            raise Invalid(f"market.package_invalid: {ascii(path)}: duplicate name after case folding")
        names.add(folded)
        parts = path.split("/")
        for i in range(1, len(parts)):
            prefix = "/".join(parts[:i])
            dirs.add(prefix)
            folded_dirs.add(unicodedata.normalize("NFC", prefix).casefold())
        if size < 0:
            raise Invalid(f"market.package_invalid: {ascii(path)}: negative size")
        if size > MAX_FILE_BYTES:
            raise Invalid(f"market.package_invalid: {ascii(path)}: larger than {MAX_FILE_BYTES} bytes")
        total += size
    if len(listing) + len(dirs) > MAX_FILES:
        raise Invalid(f"market.package_invalid: more than {MAX_FILES} files and directories")
    if names & folded_dirs:
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


# Re-executes git with RLIMIT_FSIZE and no core dump (same fixed program text as core's gitsafe): a write past the limit
# kills git, so a pack larger than the cap cannot fill the runner's disk. No operand is interpolated into the text.
_TRAMPOLINE = (
    "import os,resource,sys;n=int(sys.argv[1]);resource.setrlimit(resource.RLIMIT_FSIZE,(n,n));"
    "resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.execvp(sys.argv[2],sys.argv[2:])"
)
# an add-on's whole commit must fit: the package total of 8.1 plus a margin for tree objects and pack overhead (core:
# gitsafe.MARKET_PACKAGE_PACK). The reachability fetch brings the branch and tag history of the named repo, so its cap
# is larger; it still bounds what a hostile repo can make the runner download.
PACK_CAP_COMMIT = MAX_TOTAL_BYTES + (8 << 20)
PACK_CAP_HISTORY = 256 << 20


def _git(args: list[str], cwd: str, env: dict[str, str], *, timeout: int = _FETCH_TIMEOUT,
         max_file: int | None = None) -> bytes:  # fmt: skip
    argv = ["git", *args]
    if max_file is not None:
        argv = [sys.executable, "-I", "-c", _TRAMPOLINE, str(max_file), *argv]
    try:
        r = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Invalid("market.fetch_failed: git timed out") from None
    if r.returncode != 0:
        raise Invalid(f"market.fetch_failed: git {args[0]} failed: {r.stderr.decode(errors='replace')[:200].strip()}")
    return r.stdout


# ----------------------------------------------------------------------------------------------- address check
# Mirror of orch-core ``orch.market.address`` (vectors ``address_*``): IPv4 must be global unicast; IPv6 is an allow
# list (2000::/3 minus 2001::/23, documentation, 6to4); IPv4-mapped is judged as the IPv4 address it carries. Every
# address a name resolves to must pass, and git is told to connect to the first one (no second lookup).

_V6_OK = ipaddress.ip_network("2000::/3")
_V6_NO = tuple(ipaddress.ip_network(n) for n in ("2001::/23", "2001:db8::/32", "3fff::/20", "2002::/16"))
_RESOLVE_SECONDS = 15.0


def check_address(text: object) -> str:
    """The address to connect to, or :class:`Invalid` (``market.address_refused``)."""
    refused = Invalid("market.address_refused: the host resolves to an address that is not public")
    if not isinstance(text, str) or "%" in text:
        raise refused
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise refused from None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address):
        bad = ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip.is_loopback or ip.is_link_local
        if bad or not ip.is_global or ip == ipaddress.IPv4Address("255.255.255.255"):
            raise refused
        return str(ip)
    if ip not in _V6_OK or any(ip in n for n in _V6_NO):
        raise refused
    return str(ip)


def resolve_host(host: str, timeout: float = _RESOLVE_SECONDS) -> list[str]:
    """Every address of ``host`` (port 443), sorted, each judged. No result, a timeout or one bad address is refused."""
    box: list[list[str]] = []

    def work() -> None:
        try:
            box.append(sorted({i[4][0] for i in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}))
        except OSError:
            box.append([])

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    found = box[0] if box and not t.is_alive() else []
    if not found:
        raise Invalid("market.fetch_failed: the host does not resolve")
    return [check_address(a) for a in found]


def pin_address(url: str) -> dict[str, str]:
    """Environment entries that make git connect to the first judged address of the URL's host and nowhere else
    (``http.curloptResolve``; the config goes in through ``GIT_CONFIG_COUNT`` so every git call of the entry has it)."""
    host = urlsplit(url).hostname
    if urlsplit(url).scheme != "https" or not host:
        raise Invalid("market.address_refused: not an https URL with a host name")
    addr = resolve_host(host)[0]
    shown = f"[{addr}]" if ":" in addr else addr
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.curloptResolve",
            "GIT_CONFIG_VALUE_0": f"{host}:443:{shown}"}  # fmt: skip


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
         repo, env, max_file=PACK_CAP_COMMIT)  # fmt: skip
    if _git(["rev-parse", "FETCH_HEAD"], repo, env).decode().strip() != commit:
        raise Invalid("market.commit_mismatch: the fetched object is not the pinned commit")


def ensure_reachable(url: str, commit: str, repo: str, env: dict[str, str], extra: tuple[str, ...] = ()) -> None:
    """GitHub serves a commit that exists only in a fork under the parent's URL. Require the commit to be reachable
    from a branch or tag of the named repo: fetch its heads and tags and ask which of them contain the commit."""
    settings = [x for kv in extra for x in ("-c", kv)]
    _git([*FETCH_SETTINGS, *settings, "fetch", "-q", "--no-tags", "--no-recurse-submodules", url,
          "+refs/heads/*:refs/remotes/origin/*", "+refs/tags/*:refs/tags/*"], repo, env, timeout=600,
         max_file=PACK_CAP_HISTORY)  # fmt: skip
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


# ----------------------------------------------------------------------------------------------- addon-api 1.1
# Mirror of orch-core (addon-api.md section 8): ``orch.schema._check_manifest_api_1_1``, ``orch.addons.settings_schema``
# and the ``credential`` -> ``network`` rule of the manifest schema. Stdlib only; keep in step with core.

_SETTINGS_MAX_DEPTH = 4
_SETTINGS_MAX_ENTRIES = 64
_SETTINGS_KEY = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}(?![\s\S])")
_SETTINGS_TYPES = ("object", "string", "integer", "boolean", "array")
_SETTINGS_COMMON = {"type", "title"}
_SETTINGS_KEYS = {
    "object": _SETTINGS_COMMON | {"properties", "additionalProperties", "required", "maxProperties"},
    "string": _SETTINGS_COMMON | {"enum", "maxLength"},
    "integer": _SETTINGS_COMMON | {"minimum", "maximum"},
    "boolean": _SETTINGS_COMMON,
    "array": _SETTINGS_COMMON | {"items", "maxItems"},
}
_SAFE_INT = 2**53 - 1
_BIDI = frozenset([0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])
_EXTRA_INVISIBLE = frozenset(
    [0x034F, 0x115F, 0x1160, 0x2028, 0x2029, 0x2800, 0x3164, 0xFFA0, *range(0x17B4, 0x17B6),
     *range(0x180B, 0x1810), *range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)]
)  # fmt: skip
_API_CLAUSE = re.compile(r"(>=|<=|==|>|<)([0-9]{1,4})(?:\.([0-9]{1,4}))?(?![\s\S])")
_LEGACY_API = ">=1.0,<2"


def _int_ok(v: Any, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _suspicious(s: str) -> bool:
    """Mirror of core's ``suspicious()``: bidi controls, invisible and look-alike characters, every Cf, private use,
    and a leading mark."""
    for i, c in enumerate(s):
        cp = ord(c)
        cat = unicodedata.category(c)
        if (cp in _BIDI or cp in _EXTRA_INVISIBLE or cat in ("Cf", "Co") or (i == 0 and cat in ("Mn", "Mc", "Me"))):
            return True
    return False


def _text_ok(s: str) -> bool:
    """Printable, not only blank, nothing ``_suspicious``, no control, surrogate, unassigned or line-separator
    character, no space but U+0020. Core's Unicode tables are pinned; this uses the CI interpreter's, so a character
    newer than CI's tables is refused here (over-refusal only, never the dangerous direction)."""
    if not s.strip() or _suspicious(s):
        return False
    return all(unicodedata.category(c) not in ("Cc", "Cs", "Cn", "Zl", "Zp") and (c == " " or not c.isspace())
               for c in s)  # fmt: skip


def check_settings_schema(node: Any) -> None:
    """Raise :class:`Invalid` unless ``node`` is a schema of the closed subset with an object at the root."""
    if not isinstance(node, dict) or node.get("type") != "object":
        raise Invalid("market.manifest_invalid: the settings schema is an object")
    _settings_node(node, "settings.schema", 1)


def _settings_node(node: Any, path: str, depth: int) -> None:
    def bad(where: str, why: str) -> Invalid:
        return Invalid(f"market.manifest_invalid: {where}: {why}")

    if not isinstance(node, dict):
        raise bad(path, "a schema is an object")
    if depth > _SETTINGS_MAX_DEPTH:
        raise bad(path, f"nested deeper than {_SETTINGS_MAX_DEPTH}")
    typ = node.get("type")
    if typ not in _SETTINGS_TYPES:
        raise bad(f"{path}.type", "type is one of object, string, integer, boolean, array")
    for k in node:
        if k not in _SETTINGS_KEYS[typ]:
            raise bad(f"{path}.{k}", f"{k!r} is not allowed here")
    t = node.get("title")
    if t is not None and not (isinstance(t, str) and 1 <= len(t) <= 60 and _text_ok(t)):
        raise bad(f"{path}.title", "title is 1 to 60 printable characters")
    if typ == "object":
        if node.get("additionalProperties") is not False:
            raise bad(f"{path}.additionalProperties", "an object sets additionalProperties to false")
        props = node.get("properties", {})
        if not isinstance(props, dict) or len(props) > _SETTINGS_MAX_ENTRIES:
            raise bad(f"{path}.properties", f"properties is an object of at most {_SETTINGS_MAX_ENTRIES}")
        for k, sub in props.items():
            if not _SETTINGS_KEY.fullmatch(k):
                raise bad(f"{path}.properties.{k}", "a property name is lower-case letters, digits . _ -")
            _settings_node(sub, f"{path}.properties.{k}", depth + 1)
        req = node.get("required", [])
        if (not isinstance(req, list) or not all(isinstance(r, str) and r in props for r in req)
                or len(set(req)) != len(req)):  # fmt: skip
            raise bad(f"{path}.required", "required lists distinct names of properties")
        if "maxProperties" in node and not _int_ok(node["maxProperties"], 0, _SETTINGS_MAX_ENTRIES):
            raise bad(f"{path}.maxProperties", f"maxProperties is 0 to {_SETTINGS_MAX_ENTRIES}")
    elif typ == "string":
        if "enum" not in node and "maxLength" not in node:
            raise bad(path, "a string sets enum or maxLength")
        if "maxLength" in node and not _int_ok(node["maxLength"], 1, 200):
            raise bad(f"{path}.maxLength", "maxLength is 1 to 200")
        if "enum" in node:
            e = node["enum"]
            if (not isinstance(e, list) or not 1 <= len(e) <= _SETTINGS_MAX_ENTRIES
                    or not all(isinstance(v, str) and 1 <= len(v) <= 64 and _text_ok(v) for v in e)
                    or len(set(e)) != len(e)):  # fmt: skip
                raise bad(f"{path}.enum", "enum is 1 to 64 distinct printable strings of at most 64 characters")
    elif typ == "integer":
        if "minimum" not in node or "maximum" not in node:
            raise bad(path, "an integer sets minimum and maximum")
        for k in ("minimum", "maximum"):
            if not _int_ok(node[k], -_SAFE_INT, _SAFE_INT):
                raise bad(f"{path}.{k}", f"{k} is a whole number")
        if node["minimum"] > node["maximum"]:
            raise bad(f"{path}.minimum", "minimum is greater than maximum")
    elif typ == "array":
        if "items" not in node:
            raise bad(f"{path}.items", "an array names its items")
        _settings_node(node["items"], f"{path}.items", depth + 1)
        if not _int_ok(node.get("maxItems"), 0, _SETTINGS_MAX_ENTRIES):
            raise bad(f"{path}.maxItems", f"an array sets maxItems, 0 to {_SETTINGS_MAX_ENTRIES}")


def api_range_includes(api: tuple[int, int], rng: str) -> bool | None:
    """True/False, or ``None`` when ``rng`` is not a valid range (fail closed). Mirror of core ``_api_in_range``."""
    clauses = rng.split(",")
    if not 1 <= len(clauses) <= 4:
        return None
    ok = True
    for c in clauses:
        m = _API_CLAUSE.fullmatch(c)
        if m is None:
            return None
        bound = (int(m[2]), int(m[3] or 0))
        ok = ok and {">=": api >= bound, "<=": api <= bound, "==": api == bound, ">": api > bound, "<": api < bound}[m[1]]
    return ok


def _manifest_validator() -> Draft202012Validator:
    reg: Registry = Registry()
    for path in (COMMON_SCHEMA_PATH, MANIFEST_SCHEMA_PATH):
        doc = json.loads(path.read_text())
        reg = reg.with_resource(doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012))
    manifest = json.loads(MANIFEST_SCHEMA_PATH.read_text())
    return Draft202012Validator({"$ref": manifest["$id"]}, registry=reg)


def check_manifest_schema(m: dict[str, Any]) -> None:
    """Core's own manifest schema (orch.addon/3), then the checks core's ``validate()`` adds beyond it that matter
    here: no invisible character in the title, and the api range must include the add-on API this core speaks."""
    errs = sorted(_manifest_validator().iter_errors(m), key=lambda e: list(e.absolute_path))
    if errs:
        e = errs[0]
        raise Invalid(f"market.manifest_invalid: {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message[:200]}")
    if _suspicious(m["title"]):
        raise Invalid("market.manifest_invalid: title contains an invisible character")
    if api_range_includes(ADDON_API, m.get("api", _LEGACY_API)) is not True:
        raise Invalid(f"market.manifest_invalid: api {m.get('api')!r} does not include add-on API 1.1")


def check_api_1_1(m: dict[str, Any]) -> None:
    """The add-on API 1.1 rules of a manifest: the new features need an api range that excludes 1.0, ``{python}`` is
    the whole of ``cmd[0]`` only, ``credential`` needs ``network``, ``settings.schema`` is in the closed subset."""
    caps = m.get("capabilities", [])
    cmd = m.get("entry", {}).get("cmd") if isinstance(m.get("entry"), dict) else None
    if not isinstance(cmd, list) or not cmd or not all(isinstance(a, str) for a in cmd):
        raise Invalid("market.manifest_invalid: entry.cmd is a list of strings")
    uses = ([c for c in caps if c in ADDON_API_1_1_CAPS] + (["settings"] if "settings" in m else [])
            + (["{python}"] if cmd[0] == "{python}" else []))  # fmt: skip
    api = m.get("api", _LEGACY_API)
    if uses and (not isinstance(api, str) or api_range_includes((1, 0), api) is not False):
        raise Invalid(f"market.manifest_invalid: {uses[0]} needs add-on API 1.1: set api to a range that excludes 1.0")
    for i, arg in enumerate(cmd):
        if "{python}" in arg and (i != 0 or arg != "{python}"):
            raise Invalid(f"market.manifest_invalid: entry.cmd[{i}]: {{python}} is only allowed as the whole of cmd[0]")
    if "credential" in caps and "network" not in caps:
        raise Invalid("market.manifest_invalid: credential needs network")
    if "settings" in m:
        st = m["settings"]
        if (not isinstance(st, dict) or set(st) != {"title", "schema"} or not isinstance(st["title"], str)
                or not 1 <= len(st["title"]) <= 60 or not _text_ok(st["title"])):  # fmt: skip
            raise Invalid("market.manifest_invalid: settings is {title (1 to 60 printable characters), schema}")
        check_settings_schema(st["schema"])


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
    check_manifest_schema(m)
    check_api_1_1(m)


def check_entry(entry: dict[str, Any], fetch=fetch_commit, reach=ensure_reachable, pin=pin_address) -> None:
    """Address check, fetch, export, digest, manifest. Raises :class:`Invalid`. ``fetch``, ``reach`` and ``pin`` are
    replaceable for tests."""
    home = tempfile.mkdtemp(prefix="mk-validate-")
    try:
        env = {**git_env(home), **pin(entry["source"]["git"])}
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
    ap.add_argument("--history-ref", action="append", default=[],
                    help="git ref whose first-parent history of the index is the append-only record (repeatable)")
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
    try:
        hist = [d for r in a.history_ref for d in history_from_git(r)] if a.history_ref else None
    except Invalid as e:
        print(f"FAIL {e}")
        return 1
    problems = check_index(doc, previous=prev, official=a.official, extra_hosts=tuple(a.allow_host), history=hist)
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
