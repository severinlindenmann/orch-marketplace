#!/usr/bin/env python3
"""Check the vendored copies of orch-core files against schema/vendored-sources.json (pinned core commit + SHA-256).

    check_vendored.py                      every local file still has the recorded SHA-256 (offline; also a unit test)
    check_vendored.py --core DIR           and the recorded SHA-256 is really the file at the recorded commit in the
                                           orch-core clone DIR (proves the record, not just the copy)
    check_vendored.py --core DIR --head    and the file at core's HEAD still equals the vendored copy (fails when core
                                           moved on: re-vendor in a pull request that updates the record)

Exit 0 = fine, 1 = a mismatch (reasons on stdout), 2 = usage. Stdlib only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "schema" / "vendored-sources.json"


def _blob(core: str, rev: str, path: str) -> bytes | None:
    r = subprocess.run(["git", "-C", core, "cat-file", "blob", f"{rev}:{path}"], capture_output=True, check=False)
    return r.stdout if r.returncode == 0 else None


def check(core: str | None = None, head: bool = False, root: Path = ROOT, record: Path = RECORD) -> list[str]:
    rec = json.loads(record.read_text())
    out = []
    for f in rec["files"]:
        want = f["sha256"]
        try:
            have = hashlib.sha256((root / f["local"]).read_bytes()).hexdigest()
        except OSError:
            out.append(f"{f['local']}: missing")
            continue
        if have != want:
            out.append(f"{f['local']}: sha256 {have[:12]} differs from the recorded {want[:12]} (edited, or re-vendored "
                       f"without updating {record.name})")  # fmt: skip
        if core is None:
            continue
        pinned = _blob(core, f["commit"], f["source"])
        if pinned is None:
            out.append(f"{f['local']}: {f['source']} not found at {f['commit'][:12]} in {core}")
        elif hashlib.sha256(pinned).hexdigest() != want:
            out.append(f"{f['local']}: the recorded sha256 is not the file at {f['commit'][:12]} in orch-core")
        if head:
            now = _blob(core, "HEAD", f["source"])
            if now is None or hashlib.sha256(now).hexdigest() != want:
                out.append(f"{f['local']}: orch-core HEAD has a different {f['source']}; re-vendor it")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--core", help="an orch-core clone")
    ap.add_argument("--head", action="store_true", help="also compare with core's HEAD (needs --core)")
    a = ap.parse_args(argv)
    if a.head and not a.core:
        ap.error("--head needs --core")
    problems = check(a.core, a.head)
    for p in problems:
        print(f"FAIL {p}")
    if not problems:
        print("vendored files match the record")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
