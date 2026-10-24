"""Signing and verification of the official ``orch.market/1`` index (spec 3.1) and its entries (spec 4.3).

This is the signing side of orch-core ``orch.market.index`` (``signed_message``, ``entry_message``, ``_verify``). The two
must stay byte-identical: tests/test_market_sign.py checks this module against a vendored copy of core's verifier logic
and, when orch-core is importable (``ORCH_CORE_SRC``), against core itself.

Formats (all canonical unpadded base64url):
* public key  = the 65-byte uncompressed P-256 point (87 characters);
* signature   = 64 bytes r || s (86 characters);
* private key = the 32-byte scalar (43 characters), one line, nothing else in the file. It exists only in the key
  files the operator moves into a secret store; it is never written by anything but ``gen-index-keys``.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

INDEX_LABEL = b"orch/market/1/index|"
ENTRY_LABEL = b"orch/market/1/entry|"
ORDER_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_B64U = re.compile(r"[A-Za-z0-9_-]*")
MAX_SAFE_INT = 2**53 - 1


class SignError(Exception):
    pass


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(s: object, n: int) -> bytes:
    """Canonical unpadded base64url of exactly ``n`` bytes (the same strictness as core's ``unb64u``)."""
    if type(s) is not str or not _B64U.fullmatch(s) or len(s) % 4 == 1:
        raise SignError("not canonical base64url")
    data = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u(data) != s or len(data) != n:
        raise SignError(f"not canonical base64url of {n} bytes")
    return data


# -- canonical JSON (cj, orch-relay protocol 2.3): the signed bodies hold only ASCII keys, strings, safe integers ----

def cj(value: Any, _depth: int = 1) -> bytes:
    if _depth > 16:
        raise SignError("nesting too deep")
    return _cj(value, _depth).encode("utf-8")


def _cj(v: Any, depth: int) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if type(v) is int:
        if abs(v) > MAX_SAFE_INT:
            raise SignError("integer outside the safe range")
        return str(v)
    if type(v) is str:
        v.encode("utf-8")  # a lone surrogate raises
        return json.dumps(v, ensure_ascii=False)
    if type(v) is list:
        return "[" + ",".join(_cj(x, depth + 1) for x in v) + "]"
    if type(v) is dict:
        for k in v:
            if type(k) is not str or not k or not k.isascii():
                raise SignError("keys must be non-empty ASCII strings")
        if depth > 16:
            raise SignError("nesting too deep")
        return "{" + ",".join(json.dumps(k) + ":" + _cj(v[k], depth + 1) for k in sorted(v)) + "}"
    raise SignError(f"type {type(v).__name__} is not canonical JSON")


# -- messages -----------------------------------------------------------------------------------------------------------

def signed_message(doc: dict[str, Any]) -> bytes:
    """What the official key signs over the index (3.1). Titles, summaries and other display fields are not covered."""
    body = {
        "market": doc["source"]["git"],
        "version": doc["version"],
        "expires_at": doc.get("expires_at"),
        "entries": [[e["id"], e["version"], e["package_sha256"]] for e in sorted(doc["addons"], key=lambda e: e["id"])],
        "revoked": sorted(doc.get("revoked", [])),
    }
    return INDEX_LABEL + cj(body)


def entry_message(entry: dict[str, Any], market: str) -> bytes:
    """What a publisher signs over an entry (4.3): the entry with ``publisher`` reduced to its key, and the market URL."""
    reduced = {**entry, "publisher": {"key": entry["publisher"]["key"]}}
    return ENTRY_LABEL + cj({"entry": reduced, "market": market})


# -- keys ---------------------------------------------------------------------------------------------------------------

def new_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def private_text(key: ec.EllipticCurvePrivateKey) -> str:
    return b64u(key.private_numbers().private_value.to_bytes(32, "big"))


def load_private(text: str) -> ec.EllipticCurvePrivateKey:
    """The one-line private key format. Surrounding whitespace (a trailing newline) is ignored; anything else is not."""
    raw = unb64u(text.strip(), 32)
    d = int.from_bytes(raw, "big")
    if not 1 <= d < ORDER_N:
        raise SignError("private key out of range")
    return ec.derive_private_key(d, ec.SECP256R1())


def public_text(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> str:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return b64u(pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))


# -- sign / verify ------------------------------------------------------------------------------------------------------

def sign(key: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify(key_b64: str, sig_b64: str, message: bytes) -> bool:
    """Core's ``_verify``: strict encodings, r and s in [1, n), ECDSA P-256 over SHA-256."""
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64u(key_b64, 65))
        raw = unb64u(sig_b64, 64)
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        if not (1 <= r < ORDER_N and 1 <= s < ORDER_N):
            return False
        key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, SignError, ValueError):
        return False


def verify_index(doc: dict[str, Any], keys: tuple[str, ...]) -> bool:
    """The index check of ``orch.market.index.verify`` for an official index: expires_at present, signature by one of
    ``keys``, valid. (The URL check is the caller's.)"""
    sig = doc.get("signature")
    return bool(
        sig is not None
        and "expires_at" in doc
        and sig["key"] in keys
        and verify(sig["key"], sig["sig"], signed_message(doc))
    )


def verify_entries(doc: dict[str, Any], keys: tuple[str, ...]) -> bool:
    """Every entry carries a publisher by one of ``keys`` that verifies for this market (market.official_unsigned)."""
    market = doc["source"]["git"]
    for e in doc["addons"]:
        p = e.get("publisher")
        if p is None or p["key"] not in keys or not verify(p["key"], p["sig"], entry_message(e, market)):
            return False
    return True
