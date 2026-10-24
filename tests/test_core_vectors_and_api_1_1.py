"""Core's ``orch.market/1`` index vectors (a pinned copy of orch-core ``tests/addons/vectors_market.json``) run through
this validator, and the add-on API 1.1 rules (addon-api.md section 8) that mirror core's manifest checks."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import validate_index as v  # noqa: E402

CASES = [c for c in json.loads((Path(__file__).with_name("vectors_market.json")).read_text())["cases"]
         if c["check"] == "index"]  # fmt: skip
SCHEMA = json.loads((Path(__file__).resolve().parent.parent / "schema" / "market.v1.json").read_text())

# core refuses these in its installer with a more specific code; here the offline checker reports them as malformed
SAME_FAMILY = {"market.bad_digest_format", "market.unpinned"}


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_core_index_vector(case):
    idx = case["args"]["index"]
    try:
        doc = v.strict_loads(idx) if isinstance(idx, str) else idx
        problems = v.check_index(doc, extra_hosts=("example.com",))
    except v.Invalid as e:
        problems = [str(e)]
    expect = case["expect"]
    if "ok" in expect:
        assert problems == []
    else:
        assert problems, f"{case['name']} should be refused with {expect['refuse']}"
        code = expect["refuse"]
        if code == "market.duplicate_id":
            assert problems[0].startswith(code)
        elif code not in SAME_FAMILY:
            assert problems[0].startswith(code), problems


def test_schema_lists_the_seven_capabilities_sorted_like_core():
    caps = SCHEMA["$defs"]["entry"]["properties"]["capabilities"]
    assert caps["maxItems"] == 7
    assert caps["items"]["enum"] == ["choose_model", "credential", "git_push", "network", "pty", "serve_http",
                                     "spawn_agent"]  # fmt: skip


def _entry(caps):
    return {"id": "demo", "version": "1.0.0", "source": {"git": "https://github.com/severinlindenmann/orch-marketplace"},
            "commit": "a" * 40, "package_sha256": "sha256:" + "0" * 64, "capabilities": caps, "min_orch": "2.0.0"}  # fmt: skip


def _index(entry):
    return {"format": "orch.market/1", "name": "m", "version": 1,
            "source": {"git": "https://github.com/severinlindenmann/orch-marketplace"}, "addons": [entry]}  # fmt: skip


def test_an_entry_may_list_choose_model_and_credential():
    assert v.check_index(_index(_entry(["choose_model"]))) == []
    assert v.check_index(_index(_entry(["credential", "network"]))) == []


def test_unknown_capability_and_unsorted_new_capabilities_are_refused():
    assert v.check_index(_index(_entry(["teleport"])))
    assert any("not sorted" in p for p in v.check_index(_index(_entry(["network", "credential"]))))


def manifest(**kw):
    m = {"schema": "orch.addon/3", "name": "model-routing", "version": "1.0.0", "title": "Model routing",
         "entry": {"cmd": ["{python}", "{pkg}/main.py"]}, "capabilities": ["choose_model"], "min_core": "2.0.0",
         "api": ">=1.1,<2"}  # fmt: skip
    m.update(kw)
    return m


SETTINGS = {"title": "Models", "schema": {"type": "object", "additionalProperties": False, "properties": {
    "claude": {"type": "object", "additionalProperties": False, "properties": {
        "plan": {"type": "string", "enum": ["opus", "sonnet"]}}}}}}  # fmt: skip


def test_a_valid_1_1_manifest_passes():
    v.check_api_1_1(manifest(settings=SETTINGS))


@pytest.mark.parametrize("kw", [
    {"api": ">=1.0,<2"}, {"api": ">=1.0"}, {"api": ">=0.9,<2"}, {"api": "garbage"}, {"api": "<=1.1"},
], ids=["1_0_range", "open_1_0", "0_9", "unparsable", "includes_1_0"])
def test_1_1_features_need_an_api_range_that_excludes_1_0(kw):
    with pytest.raises(v.Invalid, match="needs add-on API 1.1"):
        v.check_api_1_1(manifest(**kw))


def test_each_1_1_feature_alone_needs_the_api_range():
    legacy = {"api": ">=1.0,<2"}
    for kw in ({"capabilities": ["choose_model"], "entry": {"cmd": ["x"]}},
               {"capabilities": ["credential", "network"], "entry": {"cmd": ["x"]}},
               {"capabilities": [], "entry": {"cmd": ["x"]}, "settings": SETTINGS},
               {"capabilities": [], "entry": {"cmd": ["{python}"]}}):  # fmt: skip
        with pytest.raises(v.Invalid, match="needs add-on API 1.1"):
            v.check_api_1_1(manifest(**kw, **legacy))
    # a 1.0 manifest without any of them is untouched, with or without the api key
    v.check_api_1_1(manifest(capabilities=["network"], entry={"cmd": ["x"]}, api=">=1.0,<2"))
    m = manifest(capabilities=["network"], entry={"cmd": ["x"]})
    del m["api"]
    v.check_api_1_1(m)


@pytest.mark.parametrize("cmd", [["python", "{python}"], ["{python}x"], ["x{python}"], ["{python}", "{python}"],
                                 ["{python}", "--p={python}"]])  # fmt: skip
def test_python_placeholder_only_as_the_whole_of_cmd0(cmd):
    with pytest.raises(v.Invalid):
        v.check_api_1_1(manifest(entry={"cmd": cmd}))


def test_credential_needs_network():
    with pytest.raises(v.Invalid, match="credential needs network"):
        v.check_api_1_1(manifest(capabilities=["credential"]))
    v.check_api_1_1(manifest(capabilities=["credential", "network"]))


def _schema(**node):
    return manifest(settings={"title": "S", "schema": {"type": "object", "additionalProperties": False, **node}})


@pytest.mark.parametrize("bad", [
    {"properties": {"a": {"type": "string", "pattern": "^a$", "maxLength": 5}}},
    {"properties": {"a": {"$ref": "#/x"}}},
    {"properties": {"a": {"type": "string", "format": "email", "maxLength": 5}}},
    {"properties": {"a": {"type": "string"}}},  # bare string
    {"properties": {"a": {"type": "integer", "minimum": 0}}},  # one-sided
    {"properties": {"a": {"type": "integer", "minimum": 0, "maximum": 2**53}}},
    {"properties": {"a": {"type": "integer", "minimum": 5, "maximum": 1}}},
    {"properties": {"a": {"type": "number"}}},
    {"properties": {"a": {"type": "array", "items": {"type": "boolean"}}}},  # no maxItems
    {"properties": {"a": {"type": "string", "enum": ["x" * 65]}}},
    {"properties": {"a": {"type": "string", "enum": ["a", "a"]}}},
    {"properties": {"a": {"type": "string", "enum": ["a​b"]}}},
    {"properties": {"a": {"type": "string", "enum": ["a\nb"]}}},
    {"properties": {"a": {"type": "string", "enum": [" "]}}},
    {"properties": {"a": {"type": "string", "maxLength": 201}}},
    {"properties": {"A": {"type": "boolean"}}},
    {"required": ["missing"]},
    {"properties": {"a": {"type": "boolean", "default": True}}},
    {"properties": {"a": {"type": "object", "properties": {}}}},  # additionalProperties not false
], ids=lambda b: json.dumps(b)[:60])
def test_settings_schema_outside_the_subset_is_refused(bad):
    with pytest.raises(v.Invalid):
        v.check_api_1_1(_schema(**bad))


def test_settings_schema_depth_and_root():
    deep = {"type": "boolean"}
    for _ in range(4):
        deep = {"type": "object", "additionalProperties": False, "properties": {"a": deep}}
    with pytest.raises(v.Invalid, match="deeper"):
        v.check_api_1_1(manifest(settings={"title": "S", "schema": deep}))
    with pytest.raises(v.Invalid):
        v.check_api_1_1(manifest(settings={"title": "S", "schema": {"type": "string", "maxLength": 3}}))
    with pytest.raises(v.Invalid):
        v.check_api_1_1(manifest(settings={"title": "S", "schema": {"type": "object", "additionalProperties": False},
                                           "extra": 1}))  # fmt: skip
    with pytest.raises(v.Invalid):
        v.check_api_1_1(manifest(settings={"title": "x" * 61, "schema": {"type": "object",
                                                                         "additionalProperties": False}}))  # fmt: skip


def test_check_manifest_runs_the_1_1_rules():
    e = {**_entry(["choose_model"]), "id": "model-routing"}
    good = manifest(settings=SETTINGS)
    v.check_manifest(e, json.dumps(good).encode())
    with pytest.raises(v.Invalid, match="needs add-on API 1.1"):
        v.check_manifest(e, json.dumps(manifest(api=">=1.0,<2")).encode())


# ---- D8-1: manifests are validated against core's vendored manifest schema in --fetch (parity probes of the Opus review)


def _routing_entry():
    return {**_entry(["choose_model"]), "id": "model-routing"}


def _bad(**kw):
    m = manifest(**kw)
    for k in [k for k, val in kw.items() if val is _DROP]:
        del m[k]
    return m


_DROP = object()


@pytest.mark.parametrize("m", [
    _bad(unknown_key=1),
    _bad(title=_DROP),
    _bad(entry={"cmd": ["{python}", "{pkg}/main.py"], "extra": 1}),
    _bad(entry={"cmd": [""]}),
    _bad(title="Model‮routing"),
    _bad(version="1"),
    _bad(api=">=1.2,<2"),
    _bad(api=">=2.0"),
], ids=["unknown_top_key", "missing_title", "extra_entry_key", "empty_cmd0", "bidi_title", "version_1", "api_1_2", "api_2"])
def test_manifest_that_core_refuses_is_refused_here_too(m):
    with pytest.raises(v.Invalid):
        v.check_manifest(_routing_entry(), json.dumps(m).encode())


def test_the_manifest_schema_files_are_vendored():
    for p in (v.MANIFEST_SCHEMA_PATH, v.COMMON_SCHEMA_PATH):
        doc = json.loads(p.read_text())
        assert doc["$id"].startswith("https://schemas.orch.dev/v2/")
