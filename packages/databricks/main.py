"""Databricks for orch: has a job run finished? Answers the host's ``events.poll`` (add-on API 1.2, section 8.6).

One process per call. orch writes one JSON-RPC 2.0 request line on stdin::

    {"jsonrpc":"2.0","id":1,"method":"events.poll","params":{"kind":"run.finished","ref":"8812","settings":{...},"credential":"..."}}

and reads exactly one line back. The result is exactly ``{"state":"pending"}``, ``{"state":"failed"}`` or
``{"state":"done","status":"succeeded"|"failed"|"cancelled"}``; anything else is an error with a fixed message.
The key arrives only as ``params.credential``: it is never printed, logged or put in an error, and neither is the
address or any text of a response. Standard library only; one GET with a bearer token, no redirects, 8 s in total.
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

KIND = "run.finished"
HOST_SUFFIXES = (".cloud.databricks.com", ".azuredatabricks.net", ".gcp.databricks.com")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
REF = re.compile(r"[0-9]{1,19}")
TERMINAL = ("TERMINATED", "SKIPPED", "INTERNAL_ERROR")
MAX_BODY = 1 << 20
CHUNK = 64 << 10
BUDGET_S = 8.0

# fixed codes and messages: this add-on's own choice (login / unreachable / bad answer); the host counts any error as a failed poll
E_JSON, E_METHOD, E_PARAMS, E_LOGIN, E_NET, E_BAD = -32700, -32601, -32602, -32001, -32002, -32003
MESSAGES = {
    E_JSON: "not JSON",
    E_METHOD: "unknown method",
    E_PARAMS: "bad parameters",
    E_LOGIN: "login needed",
    E_NET: "databricks not reachable",
    E_BAD: "bad answer from databricks",
}


class Fail(Exception):
    """A coded failure; the message of the answer is the fixed text of the code, never anything else."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None  # the 3xx then surfaces as an HTTPError, which is a failed call


def real_opener() -> Callable[..., Any]:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),  # no system or environment proxy: the key goes only to the API host
        _NoRedirect,
        urllib.request.HTTPSHandler,
    ).open


def read_capped(resp: Any, deadline: float, now: Callable[[], float]) -> bytes:
    """The body in 64 KiB chunks: more than MAX_BODY is refused and the total deadline is checked between chunks."""
    parts: list[bytes] = []
    size = 0
    while size <= MAX_BODY:
        if now() > deadline:
            raise Fail(E_NET)
        chunk = resp.read(min(CHUNK, MAX_BODY + 1 - size))
        if not chunk:
            break
        parts.append(chunk)
        size += len(chunk)
    return b"".join(parts)


def workspace_host(value: Any) -> str:
    """The host of a workspace address: https only, nothing but the host, one of the Databricks domains."""
    if not isinstance(value, str) or not value.isascii() or not 8 < len(value) <= 200:
        raise Fail(E_PARAMS)
    m = re.fullmatch(r"https://([A-Za-z0-9.-]+)/?", value)
    if m is None:
        raise Fail(E_PARAMS)
    host = m.group(1).lower()
    suffix = next((s for s in HOST_SUFFIXES if host.endswith(s)), None)
    if suffix is None or not host[: -len(suffix)]:
        raise Fail(E_PARAMS)
    if not all(LABEL.fullmatch(label) for label in host.split(".")):
        raise Fail(E_PARAMS)
    return host


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


def check_params(params: Any) -> tuple[str, str, str]:
    """(host, ref, credential) of an ``events.poll`` call, or Fail."""
    if not isinstance(params, dict) or not {"kind", "ref", "settings"} <= set(params) <= {"kind", "ref", "settings", "credential"}:
        raise Fail(E_PARAMS)
    ref, settings = params["ref"], params["settings"]
    if params["kind"] != KIND or not isinstance(ref, str) or not REF.fullmatch(ref):
        raise Fail(E_PARAMS)
    if not isinstance(settings, dict) or set(settings) != {"workspace_url"}:
        raise Fail(E_PARAMS)
    host = workspace_host(settings["workspace_url"])
    cred = params.get("credential")
    if not isinstance(cred, str) or not cred or len(cred) > 4096 or not cred.isprintable():
        raise Fail(E_LOGIN)
    return host, ref, cred


def poll(params: Any, opener: Callable[..., Any] | None = None, now: Callable[[], float] = time.monotonic) -> dict[str, str]:
    host, ref, cred = check_params(params)
    deadline = now() + BUDGET_S
    req = urllib.request.Request(
        f"https://{host}/api/2.1/jobs/runs/get?run_id={int(ref)}",
        headers={"Authorization": "Bearer " + cred, "Accept": "application/json", "User-Agent": "orch-databricks/1"},
        method="GET",
    )
    try:
        resp = (opener or real_opener())(req, timeout=max(0.5, deadline - now()))
        try:
            status = getattr(resp, "status", 200)
            body = read_capped(resp, deadline, now)
        finally:
            close = getattr(resp, "close", None)
            if close:
                close()
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise Fail(E_LOGIN) from None
        if e.code == 404:
            return {"state": "failed"}
        raise Fail(E_NET) from None
    except Fail:
        raise
    except Exception:  # noqa: BLE001 - timeouts, DNS, TLS, refused redirects: all one coded failure, no text kept
        raise Fail(E_NET) from None
    if status != 200:
        raise Fail(E_NET)
    if len(body) > MAX_BODY:
        raise Fail(E_BAD)
    return summarise(body)


def summarise(body: bytes) -> dict[str, str]:
    try:
        doc = strict_loads(body.decode("utf-8"))
    except (ValueError, RecursionError):  # includes UnicodeDecodeError and JSONDecodeError
        raise Fail(E_BAD) from None
    state = doc.get("state") if isinstance(doc, dict) else None
    if not isinstance(state, dict):
        raise Fail(E_BAD)
    life = state.get("life_cycle_state")
    if not isinstance(life, str):
        raise Fail(E_BAD)
    if life not in TERMINAL:
        return {"state": "pending"}
    result = state.get("result_state")
    if result is not None and not isinstance(result, str):
        raise Fail(E_BAD)
    status = {"SUCCESS": "succeeded", "CANCELED": "cancelled"}.get(result or "", "failed")
    return {"state": "done", "status": status}


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
