"""The vendored core files (manifest schema, common definitions, market vectors) have a pinned source: the core commit
and the SHA-256 in ``schema/vendored-sources.json``. Offline this checks that the copies are unedited; with
``ORCH_CORE_DIR`` pointing at an orch-core clone it also checks that the record is true (the file at that commit)."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import check_vendored as cv  # noqa: E402


def test_the_vendored_files_match_the_record():
    assert cv.check() == []


def test_an_edited_copy_is_reported(tmp_path):
    for f in json.loads(cv.RECORD.read_text())["files"]:
        dst = tmp_path / f["local"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / f["local"], dst)
    assert cv.check(root=tmp_path) == []
    (tmp_path / "schema" / "common.json").write_text("{}")
    problems = cv.check(root=tmp_path)
    assert len(problems) == 1 and problems[0].startswith("schema/common.json: sha256")
    (tmp_path / "schema" / "common.json").unlink()
    assert cv.check(root=tmp_path) == ["schema/common.json: missing"]


def test_the_record_names_a_full_commit_and_a_sha256_for_every_file():
    rec = json.loads(cv.RECORD.read_text())
    assert {f["local"] for f in rec["files"]} == {"schema/addon-manifest.json", "schema/common.json",
                                                  "tests/vectors_market.json",
                                                  "scripts/vendor/orch/addons/lockfile.py",
                                                  "scripts/vendor/orch/addons/envtree.py"}  # fmt: skip
    for f in rec["files"]:
        assert len(f["commit"]) == 40 and len(f["sha256"]) == 64 and (ROOT / f["local"]).exists()


@pytest.mark.skipif(not os.environ.get("ORCH_CORE_DIR"), reason="ORCH_CORE_DIR (an orch-core clone) is not set")
def test_the_record_is_the_file_at_the_pinned_core_commit():
    assert cv.check(core=os.environ["ORCH_CORE_DIR"]) == []
