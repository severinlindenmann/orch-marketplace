"""packages/databricks: the manifest, the events.poll mapping with recorded HTTP answers (no network), the refusals."""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import re
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packages" / "databricks"
sys.path.insert(0, str(ROOT / "scripts"))
import validate_index as v  # noqa: E402

sys.dont_write_bytecode = True  # never leave a __pycache__ in the package directory
spec = importlib.util.spec_from_file_location("databricks_main", PKG / "main.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

MANIFEST = json.loads((PKG / "orch-addon.json").read_text())
SENTINEL = "dapi-SENTINEL-0123456789abcdef"
WS = "https://adb-123.4.azuredatabricks.net"


@pytest.fixture(autouse=True)
def key_never_printed(capfd):
    """Every test of the state and error matrix: the key never reaches stdout or stderr of this process."""
    yield
    out, err = capfd.readouterr()
    assert SENTINEL not in out and SENTINEL not in err


class Drip:
    """A response that hands out one byte per read and moves a fake clock: a slow-dripping server."""

    status = 200

    def __init__(self, clock):
        self.clock = clock

    def read(self, n=-1):
        self.clock[0] += 3.0
        return b"x"

    def close(self):
        pass


def test_a_slow_dripping_body_ends_in_a_failed_poll_before_the_runner_limit():
    clock = [100.0]
    op = lambda req, timeout=None: Drip(clock)  # noqa: E731
    with pytest.raises(m.Fail) as e:
        m.poll(params(), op, now=lambda: clock[0])
    assert e.value.code == m.E_NET and clock[0] - 100.0 < 10


def test_the_real_opener_has_an_empty_proxy_handler_and_ignores_system_proxies(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"https": "http://127.0.0.1:9"})
    handlers = m.real_opener().__self__.handlers
    # an empty ProxyHandler replaces the default one, which would read the environment / macOS proxies, and registers nothing
    assert not [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert urllib.request.ProxyHandler().proxies != {}  # the default would have used the proxy set above


def params(**kw):
    p = {"kind": "run.finished", "ref": "8812", "settings": {"workspace_url": WS}, "credential": SENTINEL}
    p.update(kw)
    return p


class Resp:
    def __init__(self, body: bytes, status: int = 200):
        self.status, self._b = status, io.BytesIO(body)

    def read(self, n=-1):
        return self._b.read(n)

    def close(self):
        pass


class Opener:
    """A recorded answer: a body (200), or an HTTP error code, or an exception to raise."""

    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def __call__(self, req, timeout=None):
        self.calls.append((req, timeout))
        a = self.answer
        if isinstance(a, BaseException):
            raise a
        if isinstance(a, int):
            raise urllib.error.HTTPError(req.full_url, a, "x", {}, io.BytesIO(b"secret body text"))
        return Resp(a if isinstance(a, bytes) else json.dumps(a).encode())


def run_state(life, result=None):
    st = {"life_cycle_state": life}
    if result is not None:
        st["result_state"] = result
    return {"state": st}


def code_of(p, answer=None):
    out = m.answer(json.dumps({"jsonrpc": "2.0", "id": 7, "method": "events.poll", "params": p}), Opener(answer or {}))
    assert set(out) == {"jsonrpc", "id", "error"} and out["id"] == 7
    assert out["error"]["message"] == m.MESSAGES[out["error"]["code"]]
    return out["error"]["code"]


def result_of(answer):
    out = m.answer(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "events.poll", "params": params()}), Opener(answer))
    assert set(out) == {"jsonrpc", "id", "result"}, out
    return out["result"]


def test_manifest_and_package_shape():
    assert MANIFEST["name"] == "databricks" and MANIFEST["api"] == ">=1.2,<2"
    assert MANIFEST["capabilities"] == ["network", "credential"]
    assert MANIFEST["entry"]["cmd"] == ["{python}", "{pkg}/main.py"]
    assert MANIFEST["events"] == [{
        "kind": "run.finished", "title": "Databricks run finished", "statuses": ["succeeded", "failed", "cancelled"],
        "ref": {"format": "int"}, "poll": {"interval_s": 300},
    }]  # fmt: skip
    assert sorted(p.name for p in PKG.iterdir()) == ["README.md", "main.py", "orch-addon.json"]


def check_events(events):
    """The strict rules of addon-api 8.6 (mirror of core's manifest checks)."""
    assert isinstance(events, list) and len(events) <= 8
    kinds = set()
    for e in events:
        assert set(e) == {"kind", "title", "statuses", "ref", "poll"}
        assert re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,2}", e["kind"]) and e["kind"] not in kinds
        kinds.add(e["kind"])
        assert 1 <= len(e["title"]) <= 40 and e["title"].isprintable()
        assert 1 <= len(e["statuses"]) <= 4 and len(set(e["statuses"])) == len(e["statuses"])
        assert all(re.fullmatch(r"[a-z][a-z0-9_]*", s) for s in e["statuses"])
        assert set(e["ref"]) == {"format"} and e["ref"]["format"] in ("int", "slug", "owner_repo_number", "hex40")
        assert set(e["poll"]) == {"interval_s"} and 60 <= e["poll"]["interval_s"] <= 3600


def test_events_follow_addon_api_1_2_and_need_network():
    check_events(MANIFEST["events"])
    assert "network" in MANIFEST["capabilities"] and "credential" in MANIFEST["capabilities"]


def test_settings_schema_and_listing_checks():
    v.check_settings_schema(MANIFEST["settings"]["schema"])
    files = {p.name: p.read_bytes() for p in PKG.iterdir()}
    v.judge_listing([("100644", n, len(b)) for n, b in files.items()])
    assert v.package_digest(files).startswith("sha256:")


def test_vendored_core_schema_accepts_the_manifest_once_it_knows_1_2():
    try:
        v.check_manifest_schema(MANIFEST)
    except v.Invalid as e:
        pytest.skip(f"vendored core schema predates addon-api 1.2 (needs orch-core #1733): {str(e)[:80]}")


def test_stdlib_only():
    for node in ast.walk(ast.parse((PKG / "main.py").read_text())):
        names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
            [node.module] if isinstance(node, ast.ImportFrom) else []  # fmt: skip
        assert all(n.split(".")[0] in sys.stdlib_module_names for n in names), names


@pytest.mark.parametrize("life,result,want", [
    ("PENDING", None, {"state": "pending"}), ("RUNNING", None, {"state": "pending"}),
    ("QUEUED", None, {"state": "pending"}), ("TERMINATING", "SUCCESS", {"state": "pending"}),
    ("BLOCKED", None, {"state": "pending"}), ("WAITING_FOR_RETRY", None, {"state": "pending"}),
    ("TERMINATED", "SUCCESS", {"state": "done", "status": "succeeded"}),
    ("TERMINATED", "FAILED", {"state": "done", "status": "failed"}),
    ("TERMINATED", "CANCELED", {"state": "done", "status": "cancelled"}),
    ("TERMINATED", "TIMEDOUT", {"state": "done", "status": "failed"}),
    ("TERMINATED", None, {"state": "done", "status": "failed"}),
    ("SKIPPED", None, {"state": "done", "status": "failed"}),
    ("SKIPPED", "CANCELED", {"state": "done", "status": "cancelled"}),
    ("INTERNAL_ERROR", None, {"state": "done", "status": "failed"}),
    ("INTERNAL_ERROR", "FAILED", {"state": "done", "status": "failed"}),
])  # fmt: skip
def test_state_mapping(life, result, want):
    assert result_of(run_state(life, result)) == want


def test_the_request_is_one_https_get_with_a_bearer_token():
    op = Opener(run_state("RUNNING"))
    m.poll(params(ref="000812"), op)
    (req, timeout), = op.calls
    assert req.full_url == "https://adb-123.4.azuredatabricks.net/api/2.1/jobs/runs/get?run_id=812"
    assert req.get_method() == "GET" and req.data is None
    assert req.get_header("Authorization") == "Bearer " + SENTINEL
    assert 0 < timeout <= 8


@pytest.mark.parametrize("url,host", [
    ("https://dbc-1.cloud.databricks.com", "dbc-1.cloud.databricks.com"),
    ("https://ADB-1.AzureDatabricks.net/", "adb-1.azuredatabricks.net"),
    ("https://a.b.gcp.databricks.com", "a.b.gcp.databricks.com"),
])
def test_accepted_workspace_addresses(url, host):
    assert m.workspace_host(url) == host


@pytest.mark.parametrize("url", [
    "http://dbc-1.cloud.databricks.com", "https://evil.com", "https://x.cloud.databricks.com.evil.com",
    "https://cloud.databricks.com", "https://.cloud.databricks.com", "https://u:p@dbc-1.cloud.databricks.com",
    "https://dbc-1.cloud.databricks.com:8443", "https://dbc-1.cloud.databricks.com/path", "https://dbc-1.cloud.databricks.com/?x=1",
    "https://dbc-1.cloud.databricks.com#f", "https://127.0.0.1", "https://dbc-1.cloud.databricks.com.", "https://-a.cloud.databricks.com",
    "https://dbc-1.cloud.databricks.com\\@evil.com", "https://dbcé.cloud.databricks.com", "https://a..cloud.databricks.com",
    "ftp://dbc-1.cloud.databricks.com", "", "https://", 5, None, ["https://dbc-1.cloud.databricks.com"],
    "https://dbc-1.cloud.databricks.com\n", "https://evil.com/.cloud.databricks.com", "https://evil.com?.cloud.databricks.com",
])  # fmt: skip
def test_other_hosts_are_refused_before_any_call(url):
    op = Opener(run_state("RUNNING"))
    with pytest.raises(m.Fail) as e:
        m.poll(params(settings={"workspace_url": url}), op)
    assert e.value.code == m.E_PARAMS and op.calls == []


@pytest.mark.parametrize("bad", [
    {"extra": 1}, {"kind": "other.kind"}, {"ref": "0x1"}, {"ref": "-1"}, {"ref": "1.5"}, {"ref": "1" * 20}, {"ref": 5},
    {"ref": ""}, {"settings": None}, {"settings": {}}, {"settings": {"workspace_url": WS, "x": 1}}, {"settings": []},
])  # fmt: skip
def test_bad_params_are_refused_with_no_call(bad):
    op = Opener(run_state("RUNNING"))
    with pytest.raises(m.Fail) as e:
        m.poll(params(**bad), op)
    assert e.value.code == m.E_PARAMS and op.calls == []


def test_missing_keys_and_non_dict_params():
    for p in (None, [], {"kind": "run.finished"}):
        assert code_of(p) == m.E_PARAMS
    p = params()
    del p["settings"]
    assert code_of(p) == m.E_PARAMS


@pytest.mark.parametrize("cred", [None, "", 5, "a\nb", "x" * 5000])
def test_missing_or_odd_credential_is_a_login_error_with_no_call(cred):
    p = params()
    p["credential"] = cred
    assert code_of(p) == m.E_LOGIN
    del p["credential"]
    assert code_of(p) == m.E_LOGIN


@pytest.mark.parametrize("answer,code", [
    (401, m.E_LOGIN), (403, m.E_LOGIN), (500, m.E_NET), (429, m.E_NET), (302, m.E_NET), (301, m.E_NET),
    (OSError("boom " + SENTINEL), m.E_NET), (TimeoutError(SENTINEL), m.E_NET),
    (urllib.error.URLError(SENTINEL), m.E_NET),
    (b"not json", m.E_BAD), (b"", m.E_BAD), (b"\xff\xfe", m.E_BAD), (b"[]", m.E_BAD), (b'"x"', m.E_BAD),
    (b'{"state":{"life_cycle_state":"RUNNING","life_cycle_state":"TERMINATED"}}', m.E_BAD),
    (b'{"state":{"life_cycle_state":NaN}}', m.E_BAD), (b'{"state":{"life_cycle_state":Infinity}}', m.E_BAD),
    ({"state": "RUNNING"}, m.E_BAD), ({}, m.E_BAD), ({"state": {}}, m.E_BAD), ({"state": {"life_cycle_state": 3}}, m.E_BAD),
    ({"state": {"life_cycle_state": "TERMINATED", "result_state": 5}}, m.E_BAD),
    (b"[" * 100000, m.E_BAD),
])  # fmt: skip
def test_errors_are_coded_with_fixed_messages(answer, code):
    assert code_of(params(), answer) == code


def test_404_is_a_failed_run():
    assert result_of(404) == {"state": "failed"}


def test_oversize_body_is_refused():
    big = b'{"state":{"life_cycle_state":"RUNNING"},"pad":"' + b"a" * (m.MAX_BODY + 10) + b'"}'
    assert code_of(params(), big) == m.E_BAD
    at_limit = json.dumps({"state": {"life_cycle_state": "RUNNING"}, "pad": ""}).encode()
    pad = b"a" * (m.MAX_BODY - len(at_limit))
    assert result_of(at_limit.replace(b'""', b'"' + pad + b'"')) == {"state": "pending"}


def test_a_non_200_success_status_is_refused():
    class Odd(Opener):
        def __call__(self, req, timeout=None):
            return Resp(b"{}", status=204)

    out = m.answer(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "events.poll", "params": params()}), Odd({}))
    assert out["error"]["code"] == m.E_NET


def test_the_real_opener_refuses_redirects():
    h = m._NoRedirect()
    req = urllib.request.Request(WS)
    assert h.redirect_request(req, None, 302, "Found", {}, "https://evil.example/") is None
    handlers = [type(x) for x in m.real_opener().__self__.handlers]
    assert m._NoRedirect in handlers and urllib.request.HTTPRedirectHandler not in handlers


def test_a_deadline_shorter_than_the_budget_is_passed_on():
    op = Opener(run_state("RUNNING"))
    clock = iter([100.0, 107.9] + [107.9] * 20)
    m.poll(params(), op, now=lambda: next(clock))
    assert op.calls[0][1] == 0.5  # floor for an almost used up budget; the 8 s total is the runner's 10 s minus slack


# ------------------------------------------------------------------------------------------- the process itself
def run_proc(raw: str):
    r = subprocess.run([sys.executable, "-B", "-E", "-s", "-S", str(PKG / "main.py")], input=raw + "\n",
                       capture_output=True, text=True, timeout=10, check=True)  # fmt: skip
    assert r.stdout.count("\n") == 1 and r.stderr == ""
    assert SENTINEL not in r.stdout and SENTINEL not in r.stderr
    return json.loads(r.stdout)


def test_process_refuses_a_bad_host_without_echoing_anything():
    p = params(settings={"workspace_url": "https://evil.com/" + SENTINEL})
    out = run_proc(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "events.poll", "params": p}))
    assert out == {"jsonrpc": "2.0", "id": 4, "error": {"code": m.E_PARAMS, "message": "bad parameters"}}


def test_process_missing_credential_unknown_method_garbage():
    p = params()
    del p["credential"]
    out = run_proc(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "events.poll", "params": p}))
    assert out["error"]["code"] == m.E_LOGIN
    out = run_proc(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "propose", "params": {}}))
    assert out["error"]["code"] == m.E_METHOD
    assert run_proc("not json")["error"]["code"] == m.E_JSON
    assert run_proc("")["error"]["code"] == m.E_JSON
    assert run_proc("[" * 60000)["error"]["code"] == m.E_JSON
