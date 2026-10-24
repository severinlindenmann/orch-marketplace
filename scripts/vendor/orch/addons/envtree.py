"""The dependency environment of an add-on on disk: its tree rules, its stamp, and the check before every run
(spec 8.2; design ``state/design-g4.md``, conditions C1 and C4).

An environment is ``<state>/addon-env/<workspace id>/<name>/<package digest hex[:16]>/`` plus a stamp next to it,
``<digest dir>.stamp.json``. The host builds it (``orch.host.addonenv``) and writes the stamp; this module holds what
both the host and the runner need and nothing that installs: the path rules (:func:`check_paths`), a walk that opens
every component without following a link (:func:`walk`), the stamp (:func:`read_stamp`, :func:`stamp_body`) and
:func:`verify`, which the runner calls INSIDE every call: the stamp is the one for this workspace, add-on, package
digest and kind, the ABI is this computer's, and the tree on disk hashes to the stamp. Anything else is
``market.env_changed``; nothing is ever rebuilt at run time.

Pure of network and of host code (the runner imports this).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import re
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orch.market import MarketError

__all__ = [
    "ADDON_ENV",
    "ENV_FILE_MODE",
    "MAX_BYTES",
    "MAX_ENTRIES",
    "Budget",
    "EnvLocation",
    "Tree",
    "TreeError",
    "abi",
    "check_paths",
    "env_dir",
    "read_stamp",
    "rmtree_at",
    "stamp_body",
    "stamp_path",
    "target_dir",
    "tree_hashes",
    "verify",
    "walk",
]

ADDON_ENV = "addon-env"
MAX_ENTRIES = 20_000
MAX_BYTES = 256 << 20
MAX_DEPTH = 64
MAX_PATH = 240
_AUTO_RUN = re.compile(r"(?:sitecustomize|usercustomize)(?:\..*)?|.*\.pth", re.I)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}(?![\s\S])")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,39}(?![\s\S])")
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_DIR = _FLAGS | os.O_DIRECTORY
_STAMP_KEYS = {"v", "ws", "name", "digest", "kind", "tree", "dirs", "files", "bytes", "abi", "built_at"}
ENV_FILE_MODE = 0o644  # normalized: 0644, or 0755 when any execute bit was set


HEADER_ALLOWANCE = 2048  # per archive member: its header block, padding and an extension header


class TreeError(Exception):
    """The tree breaks a rule. ``reason`` is one of ``auto_run_file``, ``path_escape``, ``link``, ``too_large``,
    ``package`` (the words of ``market.env_failed``)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class Budget:
    """THE way a parser consumes bytes or entries. The invariant of the dependency code: **what orch judged is exactly
    what gets written, and every written byte comes out of a Budget.** Whatever a hostile artifact makes a consumer
    (pip's ``zipfile``, ``tarfile``) write must have been listed and drawn from here first, or the artifact is refused;
    when orch and the consumer parse a format, the two views must be identical (``addonenv.scan_zip`` checks it).
    Every input-driven loop and
    buffer draws from one of these BEFORE it allocates, and the object is shared by everything one operation reads (all
    tarballs and wheels of one environment, every file of one walk), so N archives together cannot exceed what one may.
    ``bytes`` counts what comes out of a decompressor (headers included) or the bytes a file or download delivers;
    ``entries`` counts members, rows and directory entries. Exhausted: :class:`TreeError` ``too_large``."""

    bytes: int = MAX_BYTES + MAX_ENTRIES * HEADER_ALLOWANCE
    entries: int = MAX_ENTRIES

    def take(self, n_bytes: int = 0, n_entries: int = 0) -> None:
        self.bytes -= n_bytes
        self.entries -= n_entries
        if self.bytes < 0 or self.entries < 0:
            raise TreeError("too_large")

    def room(self, cap: int) -> int:
        """The most one item may take now: ``cap`` or what is left, whichever is smaller."""
        return max(min(cap, self.bytes), 0)


@dataclass(frozen=True)
class EnvLocation:
    """Where the host keeps environments: the state directory and the workspace id. The runner needs nothing else:
    the add-on's name, digest and kind come from the grant it is asked to run."""

    state: str
    ws: str


@dataclass(frozen=True)
class Tree:
    entries: tuple[tuple[str, str, int], ...]  # (path, sha256 hex, mode) of every file
    dirs: tuple[tuple[str, int], ...]  # (path, mode) of every directory below the root
    bytes: int


# ------------------------------------------------------------------------------------------------ paths
def env_dir(state: str | os.PathLike[str], ws: str, name: str) -> Path:
    return Path(state) / ADDON_ENV / ws / name


def target_dir(state: str | os.PathLike[str], ws: str, name: str, digest: str) -> Path:
    """The environment of one package digest: ``<name>/<hex[:16]>``."""
    return env_dir(state, ws, name) / digest.removeprefix("sha256:")[:16]


def stamp_path(target: Path) -> Path:
    return target.with_name(target.name + ".stamp.json")


def check_paths(paths: list[str]) -> None:
    """The files a dependency install would put into the environment (vectors ``env_paths_*``): nothing may leave the
    root (absolute, ``..``, empty or ``.`` segment, backslash, control character) and nothing at the root may run when
    an interpreter starts (``*.pth``, ``sitecustomize*``, ``usercustomize*``, any case). Raises :class:`TreeError`."""
    for p in paths:
        parts = p.split("/")
        if (
            not p
            or p.startswith("/")
            or "" in parts
            or "." in parts
            or ".." in parts
            or "\\" in p
            or _CONTROL.search(p)
            or len(p) > MAX_PATH
            or len(parts) > MAX_DEPTH
        ):
            raise TreeError("path_escape")
        try:
            p.encode("utf-8")
        except UnicodeEncodeError:
            raise TreeError("path_escape") from None
        if _AUTO_RUN.fullmatch(parts[0]):
            raise TreeError("auto_run_file")


def _norm_mode(st: int, is_dir: bool) -> int:
    if is_dir:
        return 0o755
    return 0o755 if st & 0o111 else 0o644


# ------------------------------------------------------------------------------------------------ the walk
def walk(root: str | os.PathLike[str] | int, budget: Budget | None = None) -> Tree:
    """Hash the tree below ``root`` (a path, or an open directory descriptor) without following any link: every
    component is opened ``O_NOFOLLOW``; only regular files with one link and directories are allowed; entries, depth and
    bytes are drawn from the ``budget`` (default: the environment limits). Depth first: only the chain of parent
    directories is open at any time (at most ``MAX_DEPTH + 1`` descriptors), never one per sibling. Raises
    :class:`TreeError`; ``OSError`` is ``link`` (a swap, or a non-file where we looked)."""
    own = not isinstance(root, int)
    fd = os.open(root, _DIR) if own else root
    entries: list[tuple[str, str, int]] = []
    dirs: list[tuple[str, int]] = []
    budget = budget if budget is not None else Budget(bytes=MAX_BYTES, entries=MAX_ENTRIES)
    total = [0]

    def visit(dfd: int, prefix: str, depth: int) -> None:
        names = os.listdir(dfd)
        if len({n.casefold() for n in names}) != len(names):
            raise TreeError("package")  # two names that differ only in case
        for name in sorted(names):
            rel = prefix + name
            budget.take(n_entries=1)  # before the entry is looked at
            check_paths([rel]) if not prefix else _check_name(rel)
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                if depth + 1 > MAX_DEPTH:
                    raise TreeError("path_escape")
                dirs.append((rel, _norm_mode(st.st_mode, True)))
                child = os.open(name, _DIR, dir_fd=dfd)
                try:
                    visit(child, rel + "/", depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode):
                f = os.open(name, _FLAGS | getattr(os, "O_NONBLOCK", 0), dir_fd=dfd)
                try:
                    info = os.fstat(f)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise TreeError("link")
                    h = hashlib.sha256()
                    while chunk := os.read(f, 1 << 16):
                        total[0] += len(chunk)
                        budget.take(len(chunk))
                        h.update(chunk)
                finally:
                    os.close(f)
                entries.append((rel, h.hexdigest(), _norm_mode(info.st_mode, False)))
            else:
                raise TreeError("link")  # a symbolic link, device, pipe or socket

    try:
        visit(fd, "", 0)
    except OSError:
        raise TreeError("link") from None
    finally:
        if own:
            os.close(fd)
    return Tree(
        tuple(sorted(entries, key=lambda e: e[0].encode())), tuple(sorted(dirs, key=lambda d: d[0].encode())), total[0]
    )


def _check_name(rel: str) -> None:
    last = rel.rsplit("/", 1)[-1]
    if not last or last in (".", "..") or "\\" in last or _CONTROL.search(last) or len(rel) > MAX_PATH:
        raise TreeError("path_escape")
    try:
        rel.encode("utf-8")
    except UnicodeEncodeError:
        raise TreeError("path_escape") from None


def tree_hashes(tree: Tree) -> tuple[str, str]:
    """``(tree, dirs)``: ``tree`` is ``tests/addons/market_ref.tree_hash``: sha256 over ``<sha256>  <mode 4 octal
    digits>  <path>\\n`` lines of the files in byte order of the path; ``dirs`` is the same over
    ``<mode>  <path>\\n`` lines of the directories, so an added empty directory or a mode change shows."""
    files = sorted(tree.entries, key=lambda e: e[0].encode())
    lines = "".join(f"{sha}  {mode:04o}  {path}\n" for path, sha, mode in files)
    dl = "".join(f"{mode:04o}  {path}\n" for path, mode in sorted(tree.dirs, key=lambda d: d[0].encode()))
    return "sha256:" + hashlib.sha256(lines.encode()).hexdigest(), "sha256:" + hashlib.sha256(dl.encode()).hexdigest()


# ------------------------------------------------------------------------------------------------ the stamp
def abi(kind: str) -> str:
    """What the built environment is valid for: the interpreter's cache tag and best wheel tag, or the Node platform."""
    if kind == "python-requirements":
        from packaging.tags import sys_tags

        best = next(iter(sys_tags()), None)
        return f"{sys.implementation.cache_tag}|{best}"
    return f"node|{sys.platform}|{platform.machine().lower()}"


def stamp_body(ws: str, name: str, digest: str, kind: str, tree: Tree, built_at: float | None = None) -> dict[str, Any]:
    t, d = tree_hashes(tree)
    return {
        "v": 1, "ws": ws, "name": name, "digest": digest, "kind": kind, "tree": t, "dirs": d,
        "files": len(tree.entries), "bytes": tree.bytes, "abi": abi(kind),
        "built_at": int(time.time() if built_at is None else built_at),
    }  # fmt: skip


def read_stamp(path: Path | str, uid: int, dir_fd: int | None = None) -> dict[str, Any] | None:
    """The stamp at ``path`` (relative to ``dir_fd`` when given) if it is the host's own plain file and strictly well
    formed, else ``None``."""
    try:
        fd = os.open(path, _FLAGS, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_size > 4096:
            return None
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    ints = ("v", "files", "bytes", "built_at")
    strs = ("ws", "name", "digest", "kind", "tree", "dirs", "abi")
    if (
        not isinstance(doc, dict)
        or set(doc) != _STAMP_KEYS
        or any(type(doc[k]) is not int or doc[k] < 0 for k in ints)
        or any(not isinstance(doc[k], str) for k in strs)
        or doc["v"] != 1
        or not _DIGEST.fullmatch(doc["digest"])
        or not _DIGEST.fullmatch(doc["tree"])
        or not _DIGEST.fullmatch(doc["dirs"])
        or not _NAME.fullmatch(doc["name"])
    ):
        return None
    return doc


# ------------------------------------------------------------------------------------------------ the check
def _open_chain(state: str, parts: list[str]) -> int:
    """Open ``state`` then each part below it, every one ``O_NOFOLLOW`` and a directory."""
    fd = os.open(state, _DIR)
    try:
        for part in parts:
            nxt = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def verify(state: str, ws: str, name: str, digest: str, kind: str) -> Path:
    """The environment of this add-on at this package digest, or ``market.env_changed`` (reason ``missing``,
    ``changed``, ``digest`` or ``abi``). Opens every component without following a link, reads the stamp, compares
    workspace, name, digest and kind, the ABI, and hashes the whole tree against the stamp. Nothing is built, and
    nothing leaves the machine. Returns the directory to put on the path."""

    def changed(reason: str) -> MarketError:
        return MarketError("market.env_changed", reason)

    short = digest.removeprefix("sha256:")[:16]
    uid = os.getuid()
    try:
        parent = _open_chain(state, [ADDON_ENV, ws, name])
    except OSError:
        raise changed("missing") from None
    try:
        try:
            tfd = os.open(short, _DIR, dir_fd=parent)
        except OSError:
            raise changed("missing") from None
        try:
            info = os.fstat(tfd)
            if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o022:
                raise changed("changed")
            stamp = read_stamp(short + ".stamp.json", uid, parent)
            if stamp is None:
                raise changed("missing")
            if stamp["digest"] != digest:
                raise changed("digest")
            if (stamp["ws"], stamp["name"], stamp["kind"]) != (ws, name, kind):
                raise changed("changed")
            if stamp["abi"] != abi(kind):
                raise changed("abi")
            try:
                tree = walk(tfd)
            except TreeError:
                raise changed("changed") from None
            if (*tree_hashes(tree), len(tree.entries), tree.bytes) != (
                stamp["tree"], stamp["dirs"], stamp["files"], stamp["bytes"],
            ):  # fmt: skip
                raise changed("changed")
        finally:
            os.close(tfd)
    finally:
        os.close(parent)
    return Path(state) / ADDON_ENV / ws / name / short


# ------------------------------------------------------------------------------------------------ removal
def rmtree_at(dir_fd: int, name: str) -> None:
    """Remove ``name`` below the directory ``dir_fd``: a link or file is unlinked, never followed; a directory with its
    tree, making what it must writable first."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return
    if not stat.S_ISDIR(st.st_mode):
        with contextlib.suppress(OSError):
            os.unlink(name, dir_fd=dir_fd)
        return
    try:
        sub = os.open(name, _DIR, dir_fd=dir_fd)
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fchmod(sub, 0o700)
        for child in os.listdir(sub):
            rmtree_at(sub, child)
    finally:
        os.close(sub)
    with contextlib.suppress(OSError):
        os.rmdir(name, dir_fd=dir_fd)
