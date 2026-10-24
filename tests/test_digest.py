"""Known-answer package digest (ticket-format 8.1). The same bytes and the same answer are fixed in orch-core's
``tests/market/test_core.py`` (``KNOWN_DIGEST``), which cites this file: the two implementations cannot drift apart
without one of the two suites failing in CI."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import validate_index as v  # noqa: E402

KNOWN_DIGEST = "sha256:3f8e89e323846e8e54e539550c34b536d78eb959ee4db7d925211a4931d7e897"
FILES = {"orch-addon.json": b"{}", "a/b.txt": b"x"}


def test_the_package_digest_has_a_fixed_known_answer():
    assert v.package_digest(FILES) == KNOWN_DIGEST


def test_the_known_answer_is_the_sha256sum_listing_by_hand():
    lines = (f"{hashlib.sha256(b'x').hexdigest()}  a/b.txt\n" f"{hashlib.sha256(b'{}').hexdigest()}  orch-addon.json\n")
    assert KNOWN_DIGEST == "sha256:" + hashlib.sha256(lines.encode()).hexdigest()


def test_the_order_of_the_input_does_not_matter_but_a_path_or_a_byte_does():
    assert v.package_digest(dict(reversed(list(FILES.items())))) == KNOWN_DIGEST
    assert v.package_digest({**FILES, "a/b.txt": b"y"}) != KNOWN_DIGEST
    assert v.package_digest({"orch-addon.json": b"{}", "a/c.txt": b"x"}) != KNOWN_DIGEST


def test_paths_sort_by_bytes_not_by_locale_or_case():
    files = {"orch-addon.json": b"{}", "B": b"1", "a": b"2", "a/b": b"3", "a.b": b"4"}
    order = sorted(files, key=lambda p: p.encode())
    assert order == ["B", "a", "a.b", "a/b", "orch-addon.json"]
    lines = "".join(f"{hashlib.sha256(files[p]).hexdigest()}  {p}\n" for p in order)
    assert v.package_digest(files) == "sha256:" + hashlib.sha256(lines.encode()).hexdigest()


def test_an_empty_package_has_no_digest():
    with pytest.raises(v.Invalid, match="empty package"):
        v.package_digest({})
