"""GitHub checks for orch: have the checks of a pull request finished? Answers the host's ``events.poll`` (addon API 1.2).

One process per call. orch writes one JSON-RPC 2.0 request line on stdin::

    {"jsonrpc":"2.0","id":1,"method":"events.poll","params":{"kind":"checks.finished","ref":"acme:api:412","settings":null,"credential":"..."}}

and reads exactly one line back. The result is exactly ``{"state":"pending"}``, ``{"state":"failed"}`` or
``{"state":"done","status":"passed"|"failed"}``; anything else is an error with a fixed message.
The key arrives only as ``params.credential``: it is never printed, logged or put in an error, and neither is any text
of a response. Standard library only; GETs to ``https://api.github.com`` only, no redirects, 8 s in total.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

KIND = "checks.finished"
HOST = "api.github.com"
OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")
NUMBER = re.compile(r"[1-9][0-9]{0,8}")
SHA = re.compile(r"[0-9a-f]{40}")
PASSING = ("success", "neutral", "skipped")
PAGE = 100
MAX_PAGES = 3
MAX_BODY = 1 << 20
BUDGET_S = 8.0

E_JSON, E_METHOD, E_PARAMS, E_LOGIN, E_NET, E_BAD = -32700, -32601, -32602, -32001, -32002, -32003
MESSAGES = {
    E_JSON: "not JSON",
    E_METHOD: "unknown method",
    E_PARAMS: "bad parameters",
    E_LOGIN: "login needed",
    E_NET: "github not reachable",
    E_BAD: "bad answer from github",
}


class Fail(Exception):
    """A coded failure; the message of the answer is the fixed text of the code, never anything else."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class Gone(Exception):
    """GitHub answered 404: the pull request or its checks do not exist (for orch: the event failed)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None  # the 3xx then surfaces as an HTTPError, which is a failed call


def real_opener() -> Callable[..., Any]:
    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler).open


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _no_const(_: str) -> Any:
    raise ValueError("NaN or Infinity")


def strict_loads(text: str | bytes) -> Any:
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_const)


def parse_ref(ref: Any) -> tuple[str, str, int]:
    """``owner:repo:number`` -> its parts, or Fail. No part can hold a slash, dots-only name or other path trick."""
    if not isinstance(ref, str) or len(ref) > 64 or ref.count(":") != 2:
        raise Fail(E_PARAMS)
    owner, repo, number = ref.split(":")
    if (not OWNER.fullmatch(owner) or not REPO.fullmatch(repo) or repo in (".", "..") or repo.endswith(".git")
            or not NUMBER.fullmatch(number)):  # fmt: skip
        raise Fail(E_PARAMS)
    return owner, repo, int(number)


def check_params(params: Any) -> tuple[str, str, int, str]:
    """(owner, repo, number, credential) of an ``events.poll`` call, or Fail."""
    if not isinstance(params, dict) or not {"kind", "ref", "settings"} <= set(params) <= {"kind", "ref", "settings", "credential"}:
        raise Fail(E_PARAMS)
    if params["kind"] != KIND or params["settings"] is not None:  # this add-on has no settings
        raise Fail(E_PARAMS)
    owner, repo, number = parse_ref(params["ref"])
    cred = params.get("credential")
    if not isinstance(cred, str) or not cred or len(cred) > 4096 or not cred.isprintable():
        raise Fail(E_LOGIN)
    return owner, repo, number, cred


class Client:
    """GETs under https://api.github.com with one total time budget; every failure is a coded Fail or Gone."""

    def __init__(self, cred: str, opener: Callable[..., Any] | None, now: Callable[[], float]) -> None:
        self._cred, self._opener, self._now = cred, opener, now
        self._deadline = now() + BUDGET_S

    def get(self, path: str) -> Any:
        left = self._deadline - self._now()
        if left <= 0:
            raise Fail(E_NET)
        req = urllib.request.Request(
            "https://" + HOST + path,
            headers={
                "Authorization": "Bearer " + self._cred,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "orch-github-reviews/1",
            },
            method="GET",
        )
        try:
            resp = (self._opener or real_opener())(req, timeout=max(0.5, left))
            try:
                status = getattr(resp, "status", 200)
                body = resp.read(MAX_BODY + 1)
            finally:
                close = getattr(resp, "close", None)
                if close:
                    close()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise Fail(E_LOGIN) from None
            if e.code == 404:
                raise Gone from None
            raise Fail(E_NET) from None
        except Fail:
            raise
        except Exception:  # noqa: BLE001 - timeouts, DNS, TLS, refused redirects: one coded failure, no text kept
            raise Fail(E_NET) from None
        if status != 200:
            raise Fail(E_NET)
        if len(body) > MAX_BODY:
            raise Fail(E_BAD)
        try:
            return strict_loads(body.decode("utf-8"))
        except (ValueError, RecursionError):  # includes UnicodeDecodeError and JSONDecodeError
            raise Fail(E_BAD) from None


def head_sha(doc: Any) -> str:
    head = doc.get("head") if isinstance(doc, dict) else None
    sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise Fail(E_BAD)
    return sha


def judge(runs: list[Any], total: Any) -> dict[str, str]:
    """pending unless there is at least one check run, all are complete and we saw all of them."""
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise Fail(E_BAD)
    if not runs:
        return {"state": "pending"}
    verdict = "passed"
    for r in runs:
        if not isinstance(r, dict) or not isinstance(r.get("status"), str):
            raise Fail(E_BAD)
        if r["status"] != "completed":
            return {"state": "pending"}
        c = r.get("conclusion")
        if not isinstance(c, str):
            raise Fail(E_BAD)
        if c not in PASSING:
            verdict = "failed"
    if len(runs) < total:  # more checks exist than the pages we read: do not claim they are all done
        return {"state": "pending"}
    return {"state": "done", "status": verdict}


def poll(params: Any, opener: Callable[..., Any] | None = None, now: Callable[[], float] = time.monotonic) -> dict[str, str]:
    owner, repo, number, cred = check_params(params)
    client = Client(cred, opener, now)
    base = f"/repos/{owner}/{repo}"
    try:
        sha = head_sha(client.get(f"{base}/pulls/{number}"))
        runs: list[Any] = []
        total: Any = None
        for page in range(1, MAX_PAGES + 1):
            doc = client.get(f"{base}/commits/{sha}/check-runs?per_page={PAGE}&page={page}")
            got = doc.get("check_runs") if isinstance(doc, dict) else None
            total = doc.get("total_count") if isinstance(doc, dict) else None
            if not isinstance(got, list) or len(got) > PAGE:
                raise Fail(E_BAD)
            runs.extend(got)
            if len(got) < PAGE:
                break
    except Gone:
        return {"state": "failed"}
    return judge(runs, total)


def answer(line: str, opener: Callable[..., Any] | None = None) -> dict[str, Any]:
    try:
        req = strict_loads(line)
    except (ValueError, RecursionError):
        return _error(1, E_JSON)
    rid = req.get("id") if isinstance(req, dict) and type(req.get("id")) is int else 1
    if not isinstance(req, dict) or req.get("method") != "events.poll":
        return _error(rid, E_METHOD)
    try:
        return {"jsonrpc": "2.0", "id": rid, "result": poll(req.get("params"), opener)}
    except Fail as f:
        return _error(rid, f.code)
    except Exception:  # noqa: BLE001 - never let an exception text (it could hold the key) reach the output
        return _error(rid, E_BAD)


def _error(rid: int, code: int) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": MESSAGES[code]}}


def main() -> int:
    line = sys.stdin.readline(64 << 10)
    sys.stdout.write(json.dumps(answer(line), separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
