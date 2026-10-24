"""packages/model-routing: the manifest passes the 1.1 rules, settings validate, main.py answers like core's routing."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packages" / "model-routing"
sys.path.insert(0, str(ROOT / "scripts"))
import validate_index as v  # noqa: E402

MANIFEST = json.loads((PKG / "orch-addon.json").read_text())
SCHEMA = MANIFEST["settings"]["schema"]


def run(params, *, raw=None):
    req = raw if raw is not None else json.dumps({"jsonrpc": "2.0", "id": 1, "method": "launch.model", "params": params})
    r = subprocess.run([sys.executable, "-B", "-E", "-s", "-S", str(PKG / "main.py")], input=req + "\n",
                       capture_output=True, text=True, timeout=10, check=True)  # fmt: skip
    assert r.stdout.count("\n") == 1 and r.stdout.endswith("\n") and r.stderr == ""
    return json.loads(r.stdout)


def test_manifest_follows_the_1_1_rules_and_the_design():
    v.check_api_1_1(MANIFEST)
    assert MANIFEST["entry"]["cmd"] == ["{python}", "{pkg}/main.py"]
    assert MANIFEST["capabilities"] == ["choose_model"] and MANIFEST["name"] == "model-routing"
    assert MANIFEST["api"] == ">=1.1,<2"
    assert sorted(p.name for p in PKG.iterdir()) == ["main.py", "orch-addon.json"]


def test_the_package_is_stdlib_only():
    import ast

    stdlib = sys.stdlib_module_names
    for node in ast.walk(ast.parse((PKG / "main.py").read_text())):
        names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
            [node.module] if isinstance(node, ast.ImportFrom) else []  # fmt: skip
        assert all(n.split(".")[0] in stdlib for n in names), names


def test_settings_schema_accepts_the_documented_shape_and_null_works():
    val = Draft202012Validator(SCHEMA)
    assert not list(val.iter_errors({"claude-code": {"work": "opus"}, "codex": {"fix": "o3"}}))
    assert not list(val.iter_errors({}))
    for bad in ({"claude-code": {"work": "gpt-5"}}, {"claude-code": {"nope": "opus"}}, {"x": {}}, {"codex": {"work": 1}}):
        assert list(val.iter_errors(bad)), bad


def test_every_mode_maps_to_its_setting():
    for h, model in (("claude-code", "haiku"), ("codex", "gpt-5-codex")):
        for mode in ("work", "refine", "fix", "continue", "context"):
            out = run({"harness": h, "mode": mode, "settings": {h: {mode: model}}})
            assert out == {"jsonrpc": "2.0", "id": 1, "result": {"model": model}}


@pytest.mark.parametrize("settings", [None, {}, {"claude-code": {}}, {"codex": {"work": "o3"}}, {"claude-code": None}])
def test_nothing_set_is_the_harness_default(settings):
    assert run({"harness": "claude-code", "mode": "work", "settings": settings})["result"] == {"model": None}


def test_unknown_harness_or_mode_is_null_never_a_guess():
    assert run({"harness": "shell", "mode": "work", "settings": {"shell": {"work": "opus"}}})["result"] == {"model": None}
    assert run({"harness": "claude-code", "mode": "x", "settings": {"claude-code": {"x": "opus"}}})["result"] == {"model": None}


@pytest.mark.parametrize("params", [
    {"harness": "claude-code", "mode": "work"},
    {"harness": "claude-code", "mode": "work", "settings": None, "key": "ORCH-1"},
    {"harness": 1, "mode": "work", "settings": None},
    {"harness": "claude-code", "mode": "work", "settings": []},
    [], None,
])  # fmt: skip
def test_malformed_params_answer_an_error_not_a_model(params):
    out = run(params)
    assert set(out) == {"jsonrpc", "id", "error"} and out["error"]["code"] == -32602


def test_unknown_method_and_garbage():
    assert run(None, raw=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "propose", "params": {}}))["error"]["code"] == -32601
    assert run(None, raw="not json")["error"]["code"] == -32700
    assert run(None, raw="")["error"]["code"] == -32700


def test_the_package_passes_the_listing_digest_and_manifest_checks_an_index_entry_would_run():
    files = {p.name: p.read_bytes() for p in PKG.iterdir()}
    v.judge_listing([("100644", n, len(b)) for n, b in files.items()])
    entry = {"id": "model-routing", "version": "1.0.0", "capabilities": ["choose_model"], "min_orch": "2.0.0.dev0"}
    assert v.package_digest(files).startswith("sha256:")
    v.check_manifest(entry, files["orch-addon.json"])


@pytest.mark.parametrize("settings", [
    {"claude-code": {"work": "gpt-5"}}, {"claude-code": {"work": "--flag"}}, {"claude-code": {"work": 1}},
    {"claude-code": "opus"}, {"claude-code": ["opus"]},
])
def test_a_set_but_invalid_value_is_an_error_answer_not_null(settings):
    out = run({"harness": "claude-code", "mode": "work", "settings": settings})
    assert set(out) == {"jsonrpc", "id", "error"} and out["error"]["code"] == -32602
