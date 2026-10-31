"""The add-on API 1.2 rules (addon-api.md section 8.6) that mirror core's manifest check for declared wake events
(orch-core ``schema._check_manifest_events``), and the vendored core schema that knows ``events``."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import validate_index as v  # noqa: E402

EVENT = {"kind": "run.finished", "title": "Run finished", "statuses": ["succeeded", "failed"],
         "ref": {"format": "int"}, "poll": {"interval_s": 300}}  # fmt: skip


def manifest(**kw):
    m = {"schema": "orch.addon/3", "name": "eventer", "version": "1.0.0", "title": "Eventer",
         "entry": {"cmd": ["{python}", "{pkg}/main.py"]}, "capabilities": ["network"], "min_core": "2.0.0",
         "api": ">=1.2,<2", "events": [EVENT]}  # fmt: skip
    m.update(kw)
    return m


def test_the_validator_speaks_add_on_api_1_2():
    assert v.ADDON_API == (1, 2)


def test_a_manifest_with_events_passes_the_vendored_schema_and_the_1_2_rules():
    v.check_manifest_schema(manifest())
    v.check_api_1_2(manifest())
    v.check_api_1_2(manifest(events=None) | {"api": ">=1.0,<2"})  # no events: nothing to check


@pytest.mark.parametrize("api", [">=1.1,<2", ">=1.0,<2"])
def test_events_need_a_range_that_excludes_1_1(api):
    with pytest.raises(v.Invalid, match="events needs add-on API 1.2"):
        v.check_api_1_2(manifest(api=api))


def test_events_need_the_network_capability():
    with pytest.raises(v.Invalid, match="events needs the network capability"):
        v.check_api_1_2(manifest(capabilities=[]))


def test_a_kind_declared_twice_is_refused():
    with pytest.raises(v.Invalid, match="declared twice"):
        v.check_api_1_2(manifest(events=[EVENT, dict(EVENT, title="Again")]))


@pytest.mark.parametrize("title", ["Run‮finished", " Run finished", "Run\nfinished", ""])
def test_a_title_that_is_not_plain_text_is_refused(title):
    with pytest.raises(v.Invalid, match="plain printable text"):
        v.check_api_1_2(manifest(events=[dict(EVENT, title=title)]))
