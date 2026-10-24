"""M#3: key generation, signing and refresh of the official index, checked with a throwaway key against an independent
copy of core's verifier logic (``core_verify`` / ``core_message`` below, transcribed from orch-core
plugins/orch-core/src/orch/market/index.py) and, when orch-core is importable, against core itself.

Only throwaway keys made inside the tests are used; no real key is read, printed or stored."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import market_sign as ms  # noqa: E402
import validate_index as vi  # noqa: E402

URL = "https://github.com/severinlindenmann/orch-marketplace"
NOW = 1_800_000_000
DAY = 86400
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# -- core's logic, transcribed (independent of market_sign) -------------------------------------------------------------

def _unb64u(s, n):
    assert re.fullmatch(r"[A-Za-z0-9_-]*", s) and len(s) % 4 != 1
    data = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    assert base64.urlsafe_b64encode(data).rstrip(b"=").decode() == s and len(data) == n
    return data


def core_verify(key_b64, sig_b64, message):
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _unb64u(key_b64, 65))
        raw = _unb64u(sig_b64, 64)
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        if not (1 <= r < N and 1 <= s < N):
            return False
        key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, AssertionError, ValueError):
        return False


def cj(o):  # core: byte-identical to this json.dumps on the subset
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def core_index_message(doc):
    body = {"market": doc["source"]["git"], "version": doc["version"], "expires_at": doc.get("expires_at"),
            "entries": [[e["id"], e["version"], e["package_sha256"]] for e in sorted(doc["addons"], key=lambda e: e["id"])],
            "revoked": sorted(doc.get("revoked", []))}  # fmt: skip
    return b"orch/market/1/index|" + cj(body)


def core_entry_message(entry, market):
    reduced = {**entry, "publisher": {"key": entry["publisher"]["key"]}}
    return b"orch/market/1/entry|" + cj({"entry": reduced, "market": market})


def core_accepts(doc, keys, now=NOW):
    """core's ``verify(official=True)`` plus the official-entry rule of spec 5.1, plus not stale."""
    sig = doc.get("signature")
    if sig is None or "expires_at" not in doc or sig["key"] not in keys:
        return False
    if not core_verify(sig["key"], sig["sig"], core_index_message(doc)):
        return False
    if now > doc["expires_at"]:
        return False
    return all(
        e.get("publisher") and e["publisher"]["key"] in keys
        and core_verify(e["publisher"]["key"], e["publisher"]["sig"], core_entry_message(e, doc["source"]["git"]))
        for e in doc["addons"]
    )  # fmt: skip


# -- helpers --------------------------------------------------------------------------------------------------------------

def entry(id_, ver="1.0.0", **kw):
    e = {"id": id_, "version": ver, "source": {"git": URL, "subdir": f"packages/{id_}"}, "commit": "a" * 40,
         "package_sha256": "sha256:" + hashlib.sha256(id_.encode()).hexdigest(), "capabilities": ["network"],
         "min_orch": "2.0.0", "summary": "x"}  # fmt: skip
    e.update(kw)
    return e


def index(addons=None, **kw):
    doc = {"format": "orch.market/1", "name": "orch-marketplace", "version": 3, "source": {"git": URL},
           "addons": addons if addons is not None else [entry("zeta"), entry("alpha", "2.1.0")]}  # fmt: skip
    doc.update(kw)
    return doc


@pytest.fixture
def key():
    return ms.new_private_key()


def run(script, *args, env=None, stdin=None, cwd=None):
    e = {k: v for k, v in os.environ.items() if k != "ORCH_MARKET_INDEX_KEY"}
    e.update(env or {})
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], env=e, input=stdin, capture_output=True,
                          text=True, cwd=cwd)  # fmt: skip


def write(tmp_path, doc, name="marketplace.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc, indent=2) + "\n")
    return p


def sign_cli(tmp_path, key, *args, doc=None, now=NOW):
    p = tmp_path / "marketplace.json"
    if doc is not None:
        write(tmp_path, doc)
    r = run("sign-index", "--index", str(p), "--now", str(now), *args, env={"ORCH_MARKET_INDEX_KEY": ms.private_text(key)})
    return r, json.loads(p.read_text())


# -- gen-index-keys ---------------------------------------------------------------------------------------------------------

def mkdir(tmp_path, mode=0o700, name="keys"):
    d = tmp_path / name
    d.mkdir()
    d.chmod(mode)
    return d


def test_gen_index_keys_writes_two_private_files_and_prints_only_public_halves(tmp_path):
    d = mkdir(tmp_path)
    r = run("gen-index-keys", "--out", str(d))
    assert r.returncode == 0, r.stderr
    files = sorted(p.name for p in d.iterdir())
    assert files == ["current.key", "next.key"]
    pubs = []
    for name in files:
        p = d / name
        assert (p.stat().st_mode & 0o777) == 0o600
        text = p.read_text()
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", text), "exactly the one-line scalar: no label, no newline"
        assert text not in r.stdout and text not in r.stderr
        pubs.append(ms.public_text(ms.load_private(text)))
    assert pubs[0] != pubs[1]
    found = re.findall(r'^\s+"([A-Za-z0-9_-]{87})",\s+# (current|next)$', r.stdout, re.M)
    assert found == [(pubs[0], "current"), (pubs[1], "next")] or found == [(pubs[1], "next"), (pubs[0], "current")] or \
        sorted(found) == sorted([(pubs[0], "current"), (pubs[1], "next")])  # fmt: skip
    assert "OFFICIAL_KEYS" in r.stdout and "move" in r.stdout.lower() and "delete" in r.stdout.lower()
    # the printed public keys are the canonical form the schema (and core) accept
    schema = json.loads((ROOT / "schema" / "market.v1.json").read_text())["$defs"]["b64uKey"]["pattern"]
    assert all(re.match(schema, k) for k, _ in found)


def test_gen_index_keys_refuses_unsafe_directories(tmp_path):
    assert run("gen-index-keys", "--out", str(tmp_path / "missing")).returncode == 1
    assert run("gen-index-keys", "--out", str(mkdir(tmp_path, 0o755, "open"))).returncode == 1
    full = mkdir(tmp_path, 0o700, "full")
    (full / "x").write_text("x")
    assert run("gen-index-keys", "--out", str(full)).returncode == 1
    real = mkdir(tmp_path, 0o700, "real")
    link = tmp_path / "link"
    link.symlink_to(real)
    assert run("gen-index-keys", "--out", str(link)).returncode == 1
    assert list(real.iterdir()) == []


def test_public_of_prints_only_the_public_half_of_a_key_on_stdin(tmp_path):
    d = mkdir(tmp_path)
    r = run("gen-index-keys", "--out", str(d))
    pub = re.search(r'"([A-Za-z0-9_-]{87})",\s+# next', r.stdout).group(1)
    secret = (d / "next.key").read_text()
    r = run("gen-index-keys", "--public-of", stdin=secret)
    assert r.returncode == 0 and r.stdout.strip() == pub and secret not in r.stdout + r.stderr
    r = run("gen-index-keys", "--public-of", stdin="not-a-key-1234")
    assert r.returncode == 1 and "not-a-key-1234" not in r.stdout + r.stderr
    assert run("gen-index-keys").returncode == 1
    assert run("gen-index-keys", "--public-of", "--out", str(d)).returncode == 1


def test_public_of_with_non_utf8_input_fails_with_a_fixed_message(tmp_path):
    """L5: a raw key or DER piped from a vault must not leak a byte through an exception text."""
    raw = bytes([0xFF, 0xFE, 0x80, 0xC3, 0x28]) + os.urandom(27)
    r = subprocess.run([sys.executable, str(SCRIPTS / "gen-index-keys"), "--public-of"], input=raw, capture_output=True)
    assert r.returncode == 1
    err = r.stderr.decode("ascii")  # pure ASCII: the fixed message only
    assert err.strip() == "gen-index-keys: not a key file written by gen-index-keys"
    assert r.stdout == b"" and b"Traceback" not in r.stderr and b"0xff" not in r.stderr.lower()


def test_gen_index_keys_never_overwrites(tmp_path):
    d = mkdir(tmp_path)
    assert run("gen-index-keys", "--out", str(d)).returncode == 0
    before = (d / "current.key").read_text()
    assert run("gen-index-keys", "--out", str(d)).returncode == 1
    assert (d / "current.key").read_text() == before


def test_a_key_file_pipes_straight_into_sign_index(tmp_path):
    d = mkdir(tmp_path)
    r = run("gen-index-keys", "--out", str(d))
    pub = re.search(r'"([A-Za-z0-9_-]{87})",\s+# current', r.stdout).group(1)
    p = write(tmp_path, index())
    r = run("sign-index", "--index", str(p), "--now", str(NOW), stdin=(d / "current.key").read_text())
    assert r.returncode == 0, r.stderr
    assert core_accepts(json.loads(p.read_text()), (pub,))


# -- signing: what core verifies ----------------------------------------------------------------------------------------------

def test_message_builders_equal_the_transcribed_core_logic(key):
    doc = index(revoked=["zeta@0.9.0", "alpha@0.1.0"], expires_at=NOW + 5)
    assert ms.signed_message(doc) == core_index_message(doc)
    e = {**entry("alpha"), "publisher": {"key": ms.public_text(key), "sig": "x"}}
    assert ms.entry_message(e, URL) == core_entry_message(e, URL)


def test_signed_index_verifies_with_core_logic(tmp_path, key):
    r, out = sign_cli(tmp_path, key, doc=index(revoked=["old@1.0.0"], title="T"))
    assert r.returncode == 0, r.stderr
    pub = ms.public_text(key)
    assert core_accepts(out, (pub,))
    assert out["expires_at"] == NOW + 30 * DAY and isinstance(out["expires_at"], int)
    assert out["signature"].keys() == {"key", "sig"} and out["signature"]["key"] == pub
    assert all(e["publisher"]["key"] == pub for e in out["addons"])
    assert vi.check_index(out, official=True, now=NOW) == []  # the repo's own validator accepts the file


def test_keys_list_current_and_next_both_accepted(tmp_path, key):
    nxt = ms.new_private_key()
    r, out = sign_cli(tmp_path, nxt, doc=index())
    assert r.returncode == 0
    assert core_accepts(out, (ms.public_text(key), ms.public_text(nxt)))
    assert not core_accepts(out, (ms.public_text(key),))


@pytest.mark.parametrize("tamper", [
    lambda d: d.update(version=d["version"] + 1),
    lambda d: d.update(expires_at=d["expires_at"] + 1),
    lambda d: d.update(revoked=["alpha@2.1.0"]),
    lambda d: d["addons"][0].update(package_sha256="sha256:" + "0" * 64),
    lambda d: d["addons"][0].update(version="9.9.9"),
    lambda d: d["addons"].pop(),
    lambda d: d["addons"][0].update(summary="changed"),  # covered by the entry signature, not the index one
    lambda d: d.__setitem__("source", {"git": "https://github.com/evil/market"}),
])  # fmt: skip
def test_any_tampering_is_refused_by_core_logic(tmp_path, key, tamper):
    _, out = sign_cli(tmp_path, key, doc=index())
    pub = (ms.public_text(key),)
    assert core_accepts(out, pub)
    t = copy.deepcopy(out)
    tamper(t)
    assert not core_accepts(t, pub)


def test_display_text_is_not_covered_by_the_index_signature(tmp_path, key):
    _, out = sign_cli(tmp_path, key, doc=index())
    out["title"] = "A new title"
    assert core_verify(out["signature"]["key"], out["signature"]["sig"], core_index_message(out))


def test_another_markets_entry_does_not_verify_here(tmp_path, key):
    _, out = sign_cli(tmp_path, key, doc=index())
    e = out["addons"][0]
    assert not core_verify(e["publisher"]["key"], e["publisher"]["sig"], core_entry_message(e, "https://github.com/x/y"))


def test_missing_expires_at_or_foreign_key_is_not_accepted(tmp_path, key):
    _, out = sign_cli(tmp_path, key, doc=index())
    t = copy.deepcopy(out)
    t.pop("expires_at")
    assert not core_accepts(t, (ms.public_text(key),))
    assert not core_accepts(out, (ms.public_text(ms.new_private_key()),))
    assert not core_accepts(out, (ms.public_text(key),), now=out["expires_at"] + 1)  # stale


def test_signature_encoding_is_canonical_and_fixed_length(tmp_path, key):
    _, out = sign_cli(tmp_path, key, doc=index())
    sig = out["signature"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{85}[AQgw]", sig["sig"]) and re.fullmatch(r"[A-Za-z0-9_-]{86}[AEIMQUYcgkosw048]", sig["key"])


# -- refresh and rollback ---------------------------------------------------------------------------------------------------

def test_refresh_raises_the_version_so_hosts_do_not_see_a_rollback(tmp_path, key):
    _, first = sign_cli(tmp_path, key, doc=index())
    later = NOW + 25 * DAY
    r, second = sign_cli(tmp_path, key, now=later)
    assert r.returncode == 0
    assert second["version"] == first["version"] + 1, "same version + new expires_at would be market.rollback in core"
    assert second["expires_at"] == later + 30 * DAY
    assert core_accepts(second, (ms.public_text(key),), now=later)
    # the payload hash core records differs between the two, which is why the version must differ
    assert hashlib.sha256(core_index_message(first)).digest() != hashlib.sha256(core_index_message(second)).digest()
    assert [e["publisher"] for e in second["addons"]] == [e["publisher"] for e in first["addons"]], "entries untouched"
    assert vi._rollback(second, first) == [] and vi.check_index(second, previous=first, official=True, now=later) == []


def test_every_file_written_has_the_input_version_plus_one(tmp_path, key):
    """H1: first signing, content change after a signed version, key switch and refresh all raise the version by one, so
    the gate's rollback check (previous = main's index) and core's floor accept the re-sign PR."""
    main = index(version=7)  # main, unsigned
    _, first = sign_cli(tmp_path, key, doc=main)
    assert first["version"] == 8 and vi._rollback(first, main) == []
    changed = copy.deepcopy(first)  # develop -> main merged new content with a raised version
    changed["version"] += 1
    changed["addons"].append(entry("beta"))
    _, second = sign_cli(tmp_path, key, doc=changed, now=NOW + 1)
    assert second["version"] == changed["version"] + 1 and vi._rollback(second, changed) == []
    other = ms.new_private_key()  # key switch: entries were made by the old key, so the publishers are re-made by the new
    stripped = copy.deepcopy(second)
    for e in stripped["addons"]:
        e.pop("publisher")
    _, third = sign_cli(tmp_path, other, doc=stripped, now=NOW + 2)
    assert third["version"] == second["version"] + 1 and vi._rollback(third, second) == []


def test_index_changed_after_signing_gets_one_more_version(tmp_path, key):
    _, first = sign_cli(tmp_path, key, doc=index())
    changed = copy.deepcopy(first)
    changed["version"] += 1
    changed["addons"].append(entry("beta"))
    r, out = sign_cli(tmp_path, key, doc=changed, now=NOW + 1)
    assert r.returncode == 0 and out["version"] == first["version"] + 2  # the author's raise, plus the signing raise
    assert core_accepts(out, (ms.public_text(key),), now=NOW + 1)
    assert [e["id"] for e in out["addons"]] == ["zeta", "alpha", "beta"]


def test_if_needed_leaves_a_fresh_signed_index_alone(tmp_path, key):
    sign_cli(tmp_path, key, doc=index())
    before = (tmp_path / "marketplace.json").read_bytes()
    r, _ = sign_cli(tmp_path, key, "--if-needed", now=NOW + 10 * DAY)
    assert r.returncode == 0 and "unchanged" in r.stdout
    assert (tmp_path / "marketplace.json").read_bytes() == before
    r, out = sign_cli(tmp_path, key, "--if-needed", now=NOW + 21 * DAY)  # 9 days left
    assert "signed:" in r.stdout and out["expires_at"] == NOW + 51 * DAY


def test_if_needed_resigns_when_unsigned_or_signed_by_another_key(tmp_path, key):
    r, out = sign_cli(tmp_path, key, "--if-needed", doc=index())
    assert "signed:" in r.stdout and out["signature"]["key"] == ms.public_text(key)
    other = ms.new_private_key()
    r, _ = sign_cli(tmp_path, other, "--if-needed")  # a different key must not silently take over signed entries
    assert r.returncode == 1 and "publisher" in r.stderr


def test_signing_changes_nothing_but_the_allowed_fields(tmp_path, key):
    src = index(revoked=["a@1.0.0"], title="Hello")
    _, out = sign_cli(tmp_path, key, doc=src)
    assert ({k: v for k, v in out.items() if k not in ("expires_at", "signature", "version")}
            | {"addons": [{k: v for k, v in e.items() if k != "publisher"} for e in out["addons"]]}) == {
                k: v for k, v in src.items() if k != "version"}  # fmt: skip
    assert out["version"] == src["version"] + 1


# -- refusals -----------------------------------------------------------------------------------------------------------------

def test_no_key_is_an_error_and_nothing_is_written(tmp_path):
    p = write(tmp_path, index())
    before = p.read_bytes()
    r = run("sign-index", "--index", str(p), stdin="")
    assert r.returncode == 1 and p.read_bytes() == before


def test_a_bad_key_is_refused_without_echoing_it(tmp_path):
    p = write(tmp_path, index())
    secret = "not-a-key-but-looks-like-a-secret-1234567890"
    r = run("sign-index", "--index", str(p), env={"ORCH_MARKET_INDEX_KEY": secret})
    assert r.returncode == 1 and secret not in r.stdout + r.stderr


def test_env_key_wins_over_stdin_and_stdin_works_alone(tmp_path, key):
    p = write(tmp_path, index())
    other = ms.new_private_key()
    r = run("sign-index", "--index", str(p), "--now", str(NOW), env={"ORCH_MARKET_INDEX_KEY": ms.private_text(key)},
            stdin=ms.private_text(other))  # fmt: skip
    assert r.returncode == 0 and json.loads(p.read_text())["signature"]["key"] == ms.public_text(key)


def test_expect_pub_refuses_the_wrong_secret(tmp_path, key):
    p = write(tmp_path, index())
    before = p.read_bytes()
    other = ms.public_text(ms.new_private_key())
    r, _ = sign_cli(tmp_path, key, "--expect-pub", other)
    assert r.returncode == 1 and p.read_bytes() == before
    r, out = sign_cli(tmp_path, key, "--expect-pub", f"{other},{ms.public_text(key)}")
    assert r.returncode == 0
    r = run("sign-index", "--index", str(p), "--expect-pub", " , ", env={"ORCH_MARKET_INDEX_KEY": ms.private_text(key)})
    assert r.returncode == 1, "an empty expect list is not 'no check'"


def test_an_invalid_index_is_never_signed(tmp_path, key):
    bad = index()
    bad["addons"][0]["commit"] = "main"
    p = write(tmp_path, bad)
    before = p.read_bytes()
    r, _ = sign_cli(tmp_path, key)
    assert r.returncode == 1 and p.read_bytes() == before and "signature" not in json.loads(before)


def test_an_entry_published_by_another_key_is_not_overwritten(tmp_path, key):
    doc = index()
    doc["addons"][0]["publisher"] = {"key": ms.public_text(ms.new_private_key()), "sig": "A" * 85 + "A"}
    r, _ = sign_cli(tmp_path, key, doc=doc)
    assert r.returncode == 1 and "publisher" in r.stderr


# -- rotation (--rekey, orch-core #1191) -----------------------------------------------------------------------------------

def test_rekey_moves_every_entry_and_the_index_to_the_next_key(tmp_path, key):
    cur, newnext = ms.public_text(key), ms.public_text(ms.new_private_key())
    _, first = sign_cli(tmp_path, key, doc=index())
    nkey = ms.new_private_key()
    nxt = ms.public_text(nkey)
    r, out = sign_cli(tmp_path, nkey, "--rekey", "--expect-pub", f"{cur},{nxt}")
    assert r.returncode == 0, r.stderr
    assert out["signature"]["key"] == nxt and {e["publisher"]["key"] for e in out["addons"]} == {nxt}
    assert out["version"] == first["version"] + 1  # a host that saw the old payload sees a newer version, no rollback
    assert core_accepts(out, (cur, nxt)) and core_accepts(out, (nxt, newnext))  # the old release and the next one
    assert not core_accepts(out, (cur,)) and not core_accepts(first, (nxt, newnext))  # the retired key is gone
    strip = lambda d: [{k: v for k, v in e.items() if k != "publisher"} for e in d["addons"]]  # noqa: E731
    assert strip(out) == strip(first)  # nothing but the publishers changed in the entries


def test_without_rekey_a_rotation_is_refused_and_nothing_is_written(tmp_path, key):
    sign_cli(tmp_path, key, doc=index())
    before = (tmp_path / "marketplace.json").read_bytes()
    nkey = ms.new_private_key()
    r, _ = sign_cli(tmp_path, nkey, "--expect-pub", f"{ms.public_text(key)},{ms.public_text(nkey)}")
    assert r.returncode == 1 and "--rekey" in r.stderr and (tmp_path / "marketplace.json").read_bytes() == before


def test_rekey_needs_the_pinned_keys(tmp_path, key):
    sign_cli(tmp_path, key, doc=index())
    before = (tmp_path / "marketplace.json").read_bytes()
    r, _ = sign_cli(tmp_path, ms.new_private_key(), "--rekey", "--expect-pub", "")
    assert r.returncode == 1 and "--expect-pub" in r.stderr and (tmp_path / "marketplace.json").read_bytes() == before
    nkey = ms.new_private_key()
    r, _ = sign_cli(tmp_path, nkey, "--rekey", "--expect-pub", ms.public_text(key))  # the signing key is not pinned
    assert r.returncode == 1 and (tmp_path / "marketplace.json").read_bytes() == before


def test_rekey_never_overwrites_a_publisher_made_by_an_unpinned_key(tmp_path, key):
    doc = index()
    stranger = ms.new_private_key()
    e = doc["addons"][0]
    e["publisher"] = {"key": ms.public_text(stranger), "sig": ""}
    e["publisher"]["sig"] = ms.sign(stranger, ms.entry_message(e, URL))
    p = write(tmp_path, doc)
    before = p.read_bytes()
    nkey = ms.new_private_key()
    r, _ = sign_cli(tmp_path, nkey, "--rekey", "--expect-pub", f"{ms.public_text(key)},{ms.public_text(nkey)}")
    assert r.returncode == 1 and "publisher" in r.stderr and p.read_bytes() == before


def test_rekey_and_verify_only_exclude_each_other(tmp_path, key):
    sign_cli(tmp_path, key, doc=index())
    r = run("sign-index", "--index", str(tmp_path / "marketplace.json"), "--verify-only", "--rekey",
            "--pub", ms.public_text(key))  # fmt: skip
    assert r.returncode == 1 and "exclude" in r.stderr


def test_days_out_of_range_refused(tmp_path, key):
    assert sign_cli(tmp_path, key, "--days", "0", doc=index())[0].returncode == 1
    assert sign_cli(tmp_path, key, "--days", "91")[0].returncode == 1


def test_empty_official_index_can_be_signed(tmp_path, key):
    r, out = sign_cli(tmp_path, key, doc=index(addons=[]))
    assert r.returncode == 0 and core_accepts(out, (ms.public_text(key),))


# -- verify-only ----------------------------------------------------------------------------------------------------------------

def test_verify_only(tmp_path, key):
    sign_cli(tmp_path, key, doc=index())
    p = tmp_path / "marketplace.json"
    pub = ms.public_text(key)
    base = ["--index", str(p), "--verify-only", "--now", str(NOW)]
    assert run("sign-index", *base, "--pub", pub).returncode == 0
    assert run("sign-index", *base, "--pub", ms.public_text(ms.new_private_key())).returncode == 1
    assert run("sign-index", *base, "--pub", pub, "--min-days", "31").returncode == 1
    assert run("sign-index", *base).returncode == 1  # no --pub
    d = json.loads(p.read_text())
    d["version"] += 1
    p.write_text(json.dumps(d))
    assert run("sign-index", *base, "--pub", pub).returncode == 1


# -- against the real core, when it is importable ------------------------------------------------------------------------------

def _core():
    src = os.environ.get("ORCH_CORE_SRC")
    if not src:
        return None
    sys.path.insert(0, src)
    try:
        from orch.market import MarketError, index as core_index
    except Exception:  # not importable here: the transcribed logic above is the check
        return None
    return core_index, MarketError


@pytest.mark.skipif(_core() is None, reason="set ORCH_CORE_SRC to orch-core plugins/orch-core/src to run against core")
def test_core_itself_accepts_our_signature_and_refuses_tampering(tmp_path, key):
    core_index, MarketError = _core()
    _, out = sign_cli(tmp_path, key, doc=index())
    keys = (ms.public_text(key),)
    raw = json.dumps(out).encode()
    v = core_index.evaluate(raw, URL, official=True, now=NOW, keys=keys)
    assert v.verified and not v.stale
    assert core_index.signed_message(out) == ms.signed_message(out)
    for e in out["addons"]:
        assert core_index.entry_message(e, URL) == ms.entry_message(e, URL)
        assert core_index.verify_entry(e, URL)
    out["version"] += 1
    with pytest.raises(MarketError) as ei:
        core_index.evaluate(json.dumps(out).encode(), URL, official=True, now=NOW, keys=keys)
    assert str(ei.value).endswith("index_unsigned") or "index_unsigned" in str(ei.value.args)
    # a refresh at the same version is a rollback for a host that recorded the first payload; ours raises the version
    _, first = sign_cli(tmp_path, key, doc=index())
    _, second = sign_cli(tmp_path, key, now=NOW + 25 * DAY)
    v1 = core_index.evaluate(json.dumps(first).encode(), URL, official=True, now=NOW, keys=keys)
    v2 = core_index.evaluate(json.dumps(second).encode(), URL, official=True, now=NOW + 25 * DAY, keys=keys)
    core_index.check_floor(v1.doc["version"], v1.payload_sha256, v2)  # must not raise market.rollback
