"""Model routing for orch: answers "which model for this agent start" from the settings the owner signed.

One process per call (addon-api 1.1, section 8.3). orch writes one JSON-RPC 2.0 request line on stdin::

    {"jsonrpc":"2.0","id":1,"method":"launch.model","params":{"harness":"claude-code","mode":"work","settings":{...}|null}}

and reads exactly one line back, ``{"result": {"model": <string or null>}}``. ``null`` means "the harness default".
The input holds nothing a ticket or an agent wrote: only the harness, the Start agent mode and the owner's settings.
Standard library only (the entry is ``{python}``: no site-packages). orch checks the answer against its own closed
list before it is used, so this file is a convenience, not the gate.
"""

from __future__ import annotations

import json
import sys

# The same closed lists as orch core (modelchoices.MODEL_CHOICES); core refuses anything else, so a value outside them
# is never returned from here either.
MODELS = {
    "claude-code": ("fable", "opus", "sonnet", "haiku"),
    "codex": ("gpt-5.4", "gpt-5-codex", "gpt-5", "o3"),
}
MODES = ("work", "refine", "fix", "continue", "context")


def choose(params: object) -> dict[str, str | None]:
    """The model for ``params`` = ``{harness, mode, settings}``; ``None`` when nothing is set for that mode."""
    if not isinstance(params, dict) or set(params) != {"harness", "mode", "settings"}:
        raise ValueError("params are exactly harness, mode and settings")
    harness, mode, settings = params["harness"], params["mode"], params["settings"]
    if not isinstance(harness, str) or not isinstance(mode, str):
        raise ValueError("harness and mode are strings")
    if settings is None or harness not in MODELS or mode not in MODES:
        return {"model": None}
    if not isinstance(settings, dict):
        raise ValueError("settings is an object or null")
    if harness not in settings:
        return {"model": None}
    per = settings[harness]
    if not isinstance(per, dict):
        raise ValueError("settings for this harness are not an object")
    if mode not in per or per[mode] is None:
        return {"model": None}
    value = per[mode]
    if not isinstance(value, str) or value not in MODELS[harness]:
        raise ValueError("the model set for this mode is not one orch offers")  # fail closed, never a guess
    return {"model": value}


def answer(line: str) -> dict[str, object]:
    try:
        req = json.loads(line)
    except ValueError:
        return {"jsonrpc": "2.0", "id": 1, "error": {"code": -32700, "message": "not JSON"}}
    rid = req.get("id") if isinstance(req, dict) and type(req.get("id")) is int else 1
    if not isinstance(req, dict) or req.get("method") != "launch.model":
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "unknown method"}}
    try:
        return {"jsonrpc": "2.0", "id": rid, "result": choose(req.get("params"))}
    except ValueError as e:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": str(e)}}


def main() -> int:
    line = sys.stdin.readline(64 << 10)
    sys.stdout.write(json.dumps(answer(line), separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
