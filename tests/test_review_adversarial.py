"""Adversarial tests from the Opus review of M#2/M#3 (state/review-m3-adversarial_test.py), adapted to the fixed
behaviour and to the repo layout. Tests that need orch-core run when ORCH_CORE_SRC points at plugins/orch-core/src."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import market_sign as ms  # noqa: E402
import validate_index as vi  # noqa: E402

URL = "https://github.com/severinlindenmann/orch-marketplace"
NOW = 1_800_000_000
DAY = 86400


def _core():
    src = os.environ.get("ORCH_CORE_SRC")
    if not src:
        return None
    sys.path.insert(0, src)
    try:
        from orch.canon.jcs import dumps
        from orch.market import MarketError, index
    except Exception:
        return None
    return index, MarketError, dumps


needs_core = pytest.mark.skipif(_core() is None, reason="set ORCH_CORE_SRC=<orch-core>/plugins/orch-core/src")


def entry(id_, ver="1.0.0", **kw):
    e = {"id": id_, "version": ver, "source": {"git": URL, "subdir": f"packages/{id_}"}, "commit": "a" * 40,
         "package_sha256": "sha256:" + hashlib.sha256(id_.encode()).hexdigest(), "capabilities": ["network"],
         "min_orch": "2.0.0", "summary": "x"}  # fmt: skip
    e.update(kw)
    return e


def index(**kw):
    doc = {"format": "orch.market/1", "name": "orch-marketplace", "version": 3, "source": {"git": URL},
           "addons": [entry("zeta"), entry("alpha", "2.1.0")]}  # fmt: skip
    doc.update(kw)
    return doc


def sign_cli(tmp_path, key, doc, now=NOW):
    p = tmp_path / "marketplace.json"
    p.write_text(json.dumps(doc, indent=2) + "\n")
    env = {k: v for k, v in os.environ.items() if k != "ORCH_MARKET_INDEX_KEY"}
    env["ORCH_MARKET_INDEX_KEY"] = ms.private_text(key)
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "sign-index"), "--index", str(p), "--now", str(now)],
                       env=env, capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stderr
    return json.loads(p.read_text())


def evaluate(index_mod, doc, keys, now):
    return index_mod.evaluate(json.dumps(doc).encode(), URL, official=True, now=now, keys=keys)


@needs_core
def test_first_signing_and_content_change_pass_the_gate_and_core_floor(tmp_path):
    index_mod, _, _ = _core()
    key = ms.new_private_key()
    keys = (ms.public_text(key),)
    base = index(version=7)
    first = sign_cli(tmp_path, key, base)
    assert vi._rollback(first, base) == []
    main = copy.deepcopy(first)
    main["version"] += 1
    main["addons"].append(entry("beta"))
    out = sign_cli(tmp_path, key, main, NOW + 1)
    assert vi._rollback(out, main) == []
    v1 = evaluate(index_mod, first, keys, NOW)
    v2 = evaluate(index_mod, out, keys, NOW + 1)
    index_mod.check_floor(v1.doc["version"], v1.payload_sha256, v2)  # market.rollback would raise


@needs_core
def test_key_switch_passes_core_floor(tmp_path):
    index_mod, _, _ = _core()
    cur, nxt = ms.new_private_key(), ms.new_private_key()
    pubs = (ms.public_text(cur), ms.public_text(nxt))
    first = sign_cli(tmp_path, cur, index())
    v1 = evaluate(index_mod, first, pubs, NOW)
    doc = copy.deepcopy(first)
    for e in doc["addons"]:
        e.pop("publisher")  # what a future --rekey would do; sign-index itself refuses foreign publishers
    second = sign_cli(tmp_path, nxt, doc, NOW + DAY)
    assert second["version"] == first["version"] + 1
    v2 = evaluate(index_mod, second, pubs, NOW + DAY)
    index_mod.check_floor(v1.doc["version"], v1.payload_sha256, v2)


ALPHABET = ['"', "\\", "\b", "\f", "\n", "\r", "\t", "\x00", "\x1f", "\x7f", " ", "é", "\U0001f600", "/",
            "<", "a", " ", "\u0085", "﻿"]  # fmt: skip


@needs_core
def test_messages_equal_core_on_random_strings():
    index_mod, _, core_dumps = _core()
    rnd = random.Random(1)
    for _ in range(3000):
        s = "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(0, 12)))
        e = entry("alpha", summary=s, title=s, publisher={"key": "k", "sig": "s"})
        e["x" + "".join(rnd.choice("abc\t\n\x01") for _ in range(3))] = s
        assert ms.entry_message(e, URL) == index_mod.entry_message(e, URL)
        doc = index(revoked=[s, "z" + s], expires_at=rnd.randint(0, 2**53 - 1))
        doc["addons"][0]["id"] = s or "q"
        assert ms.signed_message(doc) == index_mod.signed_message(doc)
        assert ms.cj({"a": [s, {"b": s}]}) == core_dumps({"a": [s, {"b": s}]})
