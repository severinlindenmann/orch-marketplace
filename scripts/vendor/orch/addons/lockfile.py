"""Lockfiles of an add-on's dependencies (spec 8.1; design ``state/design-g4.md``, condition C2).

The one parser. :func:`check` is the verdict ``tests/addons/market_ref.check_lock`` gives on every ``lock`` vector, on
the bytes of the lockfile of a package that was read once; its :class:`Lock` rows are the ONLY source of what the
review shows, what the diff compares, what is downloaded and what is installed. Nothing the author wrote reaches an
installer as text: ``pip`` gets a requirements file orch writes from these rows, ``npm`` is never run.
:func:`plan` decides which rows this computer installs (Python markers for the host interpreter; Node ``dev``,
``optional``, ``os`` and ``cpu``). Pure: no disk, no network, no clock.

Install scripts are not judged here: lock metadata is the publisher's claim, and no dependency script ever runs.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from orch.addons.envtree import Budget, TreeError
from orch.market import MarketError

__all__ = [
    "KINDS",
    "MAX_LOCK_BYTES",
    "MAX_ROWS",
    "Host",
    "Lock",
    "Planned",
    "Row",
    "check",
    "current_host",
    "plan",
]

KINDS = ("python-requirements", "node-package-lock")
MAX_LOCK_BYTES = 1 << 20
MAX_ROWS = 1000
NODE_HOSTS = ("registry.npmjs.org",)  # the one registry a node lockfile may name (constants.DEP_HOSTS repeats it)

_PY_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")  # one whole token; matched with fullmatch, never searched
MAX_LINE = 64 << 10  # one logical requirement line (a name, a marker and its hashes)
_NPM_NAME = r"(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*"
_NODE_KEY = re.compile(rf"node_modules/{_NPM_NAME}(?:/node_modules/{_NPM_NAME})*")
_NODE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]{1,40})?(?:\+[0-9A-Za-z.-]{1,40})?")
_SHA512 = re.compile(r"sha512-([A-Za-z0-9+/]{86}==)")
_PLATFORM_WORD = re.compile(r"!?[a-z0-9_]{1,20}")
_BAD_TEXT = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  ]")


@dataclass(frozen=True)
class Row:
    """One locked package, as the lockfile states it (already checked).

    Python: ``name`` is the normalized project name, ``hashes`` the accepted sha256 values, ``marker`` the marker text.
    Node: ``key`` is the ``node_modules/...`` path, ``hashes`` has the one sha512 as lower-case hex, ``resolved`` the
    registry URL; ``flags`` are ``dev``/``optional`` and ``os``/``cpu`` lists as the lock claims them."""

    name: str
    version: str
    hashes: tuple[str, ...]
    marker: str | None = None
    key: str | None = None
    resolved: str | None = None
    dev: bool = False
    optional: bool = False
    os: tuple[str, ...] = ()
    cpu: tuple[str, ...] = ()


@dataclass(frozen=True)
class Lock:
    kind: str
    rows: tuple[Row, ...]


@dataclass(frozen=True)
class Host:
    """What the plan needs to know about this computer."""

    python_env: Mapping[str, str]  # the PEP 508 environment of the interpreter that runs add-ons
    node_os: str  # process.platform words: darwin, linux, win32
    node_cpu: str  # process.arch words: arm64, x64


@dataclass(frozen=True)
class Planned:
    row: Row
    install: bool
    note: str | None  # None | "other_platform" | "dev"


def _invalid() -> MarketError:
    return MarketError("market.lock_invalid")


def check(kind: str, data: bytes, budget: Budget | None = None) -> Lock:
    """The checked :class:`Lock` of ``data``, or ``market.lock_invalid`` (``market.malformed`` for an unknown kind).
    The bytes and the rows are drawn from ``budget`` (default: the lockfile limits) before anything is parsed."""
    if kind not in KINDS:
        raise MarketError("market.malformed")
    if not isinstance(data, bytes):
        raise _invalid()
    try:
        (budget or Budget(bytes=MAX_LOCK_BYTES, entries=MAX_ROWS)).take(len(data))
    except TreeError:
        raise _invalid() from None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _invalid() from None
    rows = _python(text) if kind == KINDS[0] else _node(text)
    if not 1 <= len(rows) <= MAX_ROWS:
        raise _invalid()
    return Lock(kind, tuple(rows))


# ------------------------------------------------------------------------------------------------ python


def _logical_lines(text: str) -> list[str]:
    """The requirement lines of a requirements file: ``\\``-newline continues a line (spaces next to it collapse to
    one), blank lines and ``#`` comments are dropped. One pass, no regular expression over the whole text (a long run of
    spaces cannot make it quadratic); a lone carriage return is refused."""
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise _invalid()
    lines: list[str] = []
    pieces: list[str] = []
    for raw in text.split("\n"):
        body = raw.rstrip(" ")
        cont = body.endswith("\\")
        pieces.append((body[:-1] if cont else raw).strip(" "))
        if not cont:
            line = " ".join(p for p in pieces if p)
            pieces = []
            if line and not line.startswith("#"):
                lines.append(line)
    tail = " ".join(p for p in pieces if p)
    if tail and not tail.startswith("#"):
        lines.append(tail)
    return lines


def _python(text: str) -> list[Row]:
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import canonicalize_name
    from packaging.version import InvalidVersion, Version

    if _BAD_TEXT.search(text):
        raise _invalid()
    lines = _logical_lines(text)
    if len(lines) > MAX_ROWS:  # a count cap before any line is parsed
        raise _invalid()
    rows = []
    for ln in lines:
        # linear: split at the FIRST " --hash=", then every remaining token must be exactly one hash option
        at = ln.find(" --hash=")
        tokens = [t for t in ln[at:].split(" ") if t] if at > 0 else []
        if at <= 0 or len(ln) > MAX_LINE or not tokens or not all(_PY_HASH.fullmatch(t) for t in tokens):
            raise _invalid()
        try:
            r = Requirement(ln[:at])
            specs = list(r.specifier)
            if r.url is not None or len(specs) != 1 or specs[0].operator != "==" or "*" in specs[0].version:
                raise _invalid()
            version = str(Version(specs[0].version))
        except (InvalidRequirement, InvalidVersion):
            raise _invalid() from None
        hashes = tuple(sorted({t[len("--hash=sha256:") :] for t in tokens}))
        rows.append(Row(canonicalize_name(r.name), version, hashes, None if r.marker is None else str(r.marker)))
    return rows


# ------------------------------------------------------------------------------------------------ node


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _refuse_value(_: str) -> Any:
    raise ValueError("not allowed")


def _words(v: Any) -> tuple[str, ...]:
    if not isinstance(v, list) or len(v) > 20 or not all(isinstance(x, str) and _PLATFORM_WORD.fullmatch(x) for x in v):
        raise ValueError("platform list")
    return tuple(v)


def _node(text: str) -> list[Row]:
    try:
        lock = json.loads(
            text, object_pairs_hook=_strict_pairs, parse_float=_refuse_value, parse_constant=_refuse_value
        )
        pkgs = lock["packages"]
        if not isinstance(pkgs, dict) or len(pkgs) > MAX_ROWS + 1:  # a count cap before any entry is judged
            raise _invalid()
        root = pkgs[""]
        if not (
            type(lock["lockfileVersion"]) is int
            and lock["lockfileVersion"] == 3
            and isinstance(pkgs, dict)
            and len(pkgs) > 1
            and isinstance(root, dict)
        ):
            raise _invalid()
        # the root entry is the add-on itself: it is not fetched, so it must not claim a source or a link,
        # and everything it depends on must be a locked entry
        if {"resolved", "integrity", "link", "inBundle"} & set(root):
            raise _invalid()
        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            deps = root.get(field, {})
            if not isinstance(deps, dict):
                raise _invalid()
            for dep in deps:
                if f"node_modules/{dep}" not in pkgs:
                    raise _invalid()
        rows = []
        for key, p in pkgs.items():
            if key != "":
                rows.append(_node_row(key, p))
        return rows
    except MarketError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise _invalid() from None


def _node_row(key: str, p: Any) -> Row:
    """A locked package: the key is a plain ``node_modules/...`` chain of package names, ``version`` is a version, the
    tarball URL is exactly the registry's URL for that name and version (so what the review shows is what installs),
    and ``integrity`` is exactly one full sha512 digest."""
    if not isinstance(p, dict) or p.get("link") or _NODE_KEY.fullmatch(key) is None:
        raise _invalid()
    name = key.rsplit("node_modules/", 1)[1]
    version, resolved, integrity = p.get("version"), p.get("resolved"), p.get("integrity")
    if not isinstance(version, str) or not _NODE_VERSION.fullmatch(version):
        raise _invalid()
    base = name.rsplit("/", 1)[-1]
    m = _SHA512.fullmatch(integrity) if isinstance(integrity, str) else None
    if resolved not in [f"https://{h}/{name}/-/{base}-{version}.tgz" for h in NODE_HOSTS] or m is None:
        raise _invalid()
    try:
        digest = base64.b64decode(m[1], validate=True)
    except (binascii.Error, ValueError):
        raise _invalid() from None
    if len(digest) != 64:
        raise _invalid()
    for flag in ("dev", "optional", "devOptional"):
        if flag in p and type(p[flag]) is not bool:
            raise _invalid()
    return Row(
        name, version, (digest.hex(),), key=key, resolved=resolved,
        dev=bool(p.get("dev")) or bool(p.get("devOptional")), optional=bool(p.get("optional")),
        os=_words(p.get("os", [])), cpu=_words(p.get("cpu", [])),
    )  # fmt: skip


# ------------------------------------------------------------------------------------------------ plan


def current_host() -> Host:
    from packaging.markers import default_environment

    return Host(
        {**default_environment()},
        {"darwin": "darwin", "linux": "linux", "win32": "win32"}.get(sys.platform, sys.platform),
        _node_cpu(),
    )


def _node_cpu() -> str:
    import platform

    return {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(
        platform.machine().lower(), "other"
    )


def _listed(words: tuple[str, ...], value: str) -> bool:
    """npm's ``os``/``cpu`` rule: ``!x`` blocks x; otherwise the value must be listed. An empty list allows all."""
    if not words:
        return True
    blocked = {w[1:] for w in words if w.startswith("!")}
    allowed = {w for w in words if not w.startswith("!")}
    return value not in blocked and (not allowed or value in allowed)


def plan(lock: Lock, host: Host) -> tuple[Planned, ...]:
    """Which rows this computer installs. Python: the marker is evaluated for the host interpreter; two applicable
    lines of one name are ``market.env_failed`` (reason ``lock``). Node: ``dev`` rows are not installed, ``optional``
    rows whose ``os``/``cpu`` miss are skipped, any other miss is ``market.env_failed`` (reason ``platform``)."""
    from packaging.markers import InvalidMarker, Marker, UndefinedComparison, UndefinedEnvironmentName

    out: list[Planned] = []
    if lock.kind == KINDS[0]:
        seen: set[str] = set()
        for row in lock.rows:
            try:
                applies = row.marker is None or Marker(row.marker).evaluate({**host.python_env, "extra": ""})
            except (InvalidMarker, UndefinedComparison, UndefinedEnvironmentName):
                raise MarketError("market.env_failed", "lock") from None
            if applies and row.name in seen:
                raise MarketError("market.env_failed", "lock")
            if applies:
                seen.add(row.name)
            out.append(Planned(row, applies, None if applies else "other_platform"))
        return tuple(out)
    for row in lock.rows:
        if row.dev:
            out.append(Planned(row, False, "dev"))
        elif _listed(row.os, host.node_os) and _listed(row.cpu, host.node_cpu):
            out.append(Planned(row, True, None))
        elif row.optional:
            out.append(Planned(row, False, "other_platform"))
        else:
            raise MarketError("market.env_failed", "platform")
    return tuple(out)
