"""orch-marketplace#17: adversarial cases of the independent Opus review (orch-dev state/review-1224.md, I2)."""
from tests.test_market_sign import URL, core_accepts, index, ms, sign_cli, write  # noqa: F401
from tests.test_market_sign import key  # noqa: F401


def test_rekey_reverse_direction_is_allowed(tmp_path, key):
    """Signing key = the CURRENT pin, entries by NEXT: --rekey moves them back (documents behaviour)."""
    nkey = ms.new_private_key()
    sign_cli(tmp_path, nkey, doc=index())
    cur, nxt = ms.public_text(key), ms.public_text(nkey)
    r, out = sign_cli(tmp_path, key, "--rekey", "--expect-pub", f"{cur},{nxt}")
    assert r.returncode == 0 and {e["publisher"]["key"] for e in out["addons"]} == {cur}


def test_rekey_resigns_an_entry_that_only_claims_a_pinned_key(tmp_path, key):
    """An entry with publisher.key = a pinned key but a garbage sig is re-signed (as the non-rekey path does for the
    signing key itself): the content review of marketplace.json, not the old signature, is the control."""
    nkey = ms.new_private_key()
    doc = index()
    doc["addons"][0]["publisher"] = {"key": ms.public_text(key), "sig": "A" * 86}
    write(tmp_path, doc)
    r, out = sign_cli(tmp_path, nkey, "--rekey", "--expect-pub", f"{ms.public_text(key)},{ms.public_text(nkey)}")
    assert r.returncode == 0 and core_accepts(out, (ms.public_text(nkey),))
    # the baseline without rekey: the same forged claim of the SIGNING key is also re-signed
    doc = index()
    doc["addons"][0]["publisher"] = {"key": ms.public_text(nkey), "sig": "A" * 86}
    write(tmp_path, doc)
    r, out = sign_cli(tmp_path, nkey)
    assert r.returncode == 0


def test_if_needed_without_rekey_after_the_secret_switch_fails_closed(tmp_path, key):
    """The scheduled job after the secret moved to next.key, before a --rekey run: it dies, writes nothing."""
    sign_cli(tmp_path, key, doc=index())
    before = (tmp_path / "marketplace.json").read_bytes()
    nkey = ms.new_private_key()
    r, _ = sign_cli(tmp_path, nkey, "--if-needed", "--expect-pub", f"{ms.public_text(key)},{ms.public_text(nkey)}")
    assert r.returncode == 1 and (tmp_path / "marketplace.json").read_bytes() == before
