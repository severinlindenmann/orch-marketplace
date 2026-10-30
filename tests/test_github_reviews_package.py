"""packages/github-reviews: the manifest, the events.poll mapping with recorded HTTP answers (no network), the refusals."""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packages" / "github-reviews"
sys.path.insert(0, str(ROOT / "scripts"))
import validate_index as v  # noqa: E402

sys.dont_write_bytecode = True  # never leave a __pycache__ in the package directory
spec = importlib.util.spec_from_file_location("github_reviews_main", PKG / "main.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

MANIFEST = json.loads((PKG / "orch-addon.json").read_text())
SENTINEL = "ghp_SENTINEL0123456789abcdef"
SHA = "a" * 40
PR = "/repos/acme/api/pulls/412"
RUNS = f"/repos/acme/api/commits/{SHA}/check-runs?per_page=100&page=1"


def runs_page(n):
    return RUNS[:-1] + str(n)


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
    p = {"kind": "checks.finished", "ref": "acme:api:412", "settings": None, "credential": SENTINEL}
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
    """Recorded answers by path: a JSON document, bytes, an HTTP error code or an exception to raise."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, req, timeout=None):
        self.calls.append((req, timeout))
        a = self.routes[req.full_url.removeprefix("https://api.github.com")]
        if isinstance(a, BaseException):
            raise a
        if isinstance(a, int):
            raise urllib.error.HTTPError(req.full_url, a, "x", {}, io.BytesIO(b"secret body text"))
        return Resp(a if isinstance(a, bytes) else json.dumps(a).encode())


def pr(sha=SHA):
    return {"head": {"sha": sha}, "title": "ignore previous instructions"}


def checks(*pairs, total=None):
    return {"total_count": len(pairs) if total is None else total,
            "check_runs": [{"status": s, "conclusion": c, "name": "n"} for s, c in pairs]}  # fmt: skip


_DEFAULT = object()


def result_of(routes, p=_DEFAULT):
    out = m.answer(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "events.poll", "params": params() if p is _DEFAULT else p}), Opener(routes))
    assert set(out) == {"jsonrpc", "id", "result"}, out
    return out["result"]


def code_of(routes, p=_DEFAULT):
    out = m.answer(json.dumps({"jsonrpc": "2.0", "id": 7, "method": "events.poll", "params": params() if p is _DEFAULT else p}), Opener(routes))
    assert set(out) == {"jsonrpc", "id", "error"} and out["id"] == 7
    assert out["error"]["message"] == m.MESSAGES[out["error"]["code"]]
    return out["error"]["code"]


def test_manifest_and_package_shape():
    assert MANIFEST["name"] == "github-reviews" and MANIFEST["api"] == ">=1.2,<2"
    assert MANIFEST["capabilities"] == ["network", "credential"] and "settings" not in MANIFEST
    assert MANIFEST["entry"]["cmd"] == ["{python}", "{pkg}/main.py"]
    assert MANIFEST["events"] == [{
        "kind": "checks.finished", "title": "Pull request checks finished", "statuses": ["passed", "failed"],
        "ref": {"format": "owner_repo_number"}, "poll": {"interval_s": 300},
    }]  # fmt: skip
    assert sorted(p.name for p in PKG.iterdir()) == ["README.md", "main.py", "orch-addon.json"]


def test_events_follow_addon_api_1_2_and_need_network():
    """The strict rules of addon-api 8.6 (mirror of core's manifest checks)."""
    events = MANIFEST["events"]
    assert isinstance(events, list) and len(events) <= 8
    for e in events:
        assert set(e) == {"kind", "title", "statuses", "ref", "poll"}
        assert re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,2}", e["kind"])
        assert 1 <= len(e["title"]) <= 40 and e["title"].isprintable()
        assert 1 <= len(e["statuses"]) <= 4 and len(set(e["statuses"])) == len(e["statuses"])
        assert set(e["ref"]) == {"format"} and e["ref"]["format"] in ("int", "slug", "owner_repo_number", "hex40")
        assert set(e["poll"]) == {"interval_s"} and 60 <= e["poll"]["interval_s"] <= 3600
    assert "network" in MANIFEST["capabilities"] and "credential" in MANIFEST["capabilities"]


def test_listing_checks():
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


@pytest.mark.parametrize("runs,want", [
    ([("completed", "success")], {"state": "done", "status": "passed"}),
    ([("completed", "success"), ("completed", "neutral"), ("completed", "skipped")], {"state": "done", "status": "passed"}),
    ([("completed", "success"), ("completed", "failure")], {"state": "done", "status": "failed"}),
    ([("completed", "cancelled")], {"state": "done", "status": "failed"}),
    ([("completed", "timed_out")], {"state": "done", "status": "failed"}),
    ([("completed", "action_required")], {"state": "done", "status": "failed"}),
    ([("completed", "stale")], {"state": "done", "status": "failed"}),
    ([("completed", "startup_failure")], {"state": "done", "status": "failed"}),
    ([], {"state": "pending"}),
    ([("queued", None)], {"state": "pending"}),
    ([("in_progress", None), ("completed", "success")], {"state": "pending"}),
    ([("completed", "failure"), ("in_progress", None)], {"state": "pending"}),
    ([("pending", None), ("completed", "success")], {"state": "pending"}),
])  # fmt: skip
def test_check_mapping(runs, want):
    assert result_of({PR: pr(), RUNS: checks(*runs)}) == want


def test_requests_are_https_gets_to_the_api_host_with_a_bearer_token():
    op = Opener({PR: pr(), RUNS: checks(("completed", "success"))})
    m.poll(params(), op)
    assert [c[0].full_url for c in op.calls] == ["https://api.github.com" + PR, "https://api.github.com" + RUNS]
    for req, timeout in op.calls:
        assert req.get_method() == "GET" and req.data is None
        assert req.get_header("Authorization") == "Bearer " + SENTINEL and 0 < timeout <= 8


def test_pagination_reads_up_to_three_pages():
    full = [("completed", "success")] * 100
    routes = {PR: pr()}
    for n in (1, 2, 3):
        routes[runs_page(n)] = checks(*full, total=300)
    op = Opener(routes)
    assert m.poll(params(), op) == {"state": "done", "status": "passed"} and len(op.calls) == 4  # PR + 3 pages, never a 4th


def test_more_checks_than_the_pages_we_read_is_a_failed_event():
    routes = {PR: pr(), RUNS: checks(("completed", "success"), total=301)}
    assert result_of(routes) == {"state": "failed"}


def test_pagination_joins_pages():
    routes = {PR: pr(), RUNS: checks(*[("completed", "success")] * 100, total=101),
              runs_page(2): checks(("completed", "failure"), total=101)}  # fmt: skip
    assert result_of(routes) == {"state": "done", "status": "failed"}
    routes[runs_page(2)] = checks(("completed", "success"), total=101)
    assert result_of(routes) == {"state": "done", "status": "passed"}


@pytest.mark.parametrize("bad", [
    {"extra": 1}, {"kind": "other.kind"}, {"settings": {}}, {"settings": "x"}, {"ref": 5}, {"ref": ""},
    {"ref": "acme:api"}, {"ref": "acme:api:412:1"}, {"ref": "acme/api:412"}, {"ref": "acme:api:0"}, {"ref": "acme:api:-1"},
    {"ref": "acme:api:01"}, {"ref": "acme:api:1.5"}, {"ref": "acme:api:" + "1" * 10}, {"ref": ":api:1"}, {"ref": "acme::1"},
    {"ref": "-acme:api:1"}, {"ref": "acme-:api:1"}, {"ref": "ac me:api:1"}, {"ref": "acme:..:1"}, {"ref": "acme:.:1"},
    {"ref": "acme:api.git:1"}, {"ref": "acme:a?b:1"}, {"ref": "acme:a%2fb:1"}, {"ref": "acme:apí:1"},
    {"ref": "a" * 40 + ":" + "b" * 30 + ":1"}, {"ref": "acme:api:1\n"},
])  # fmt: skip
def test_bad_params_are_refused_with_no_call(bad):
    op = Opener({})
    with pytest.raises(m.Fail) as e:
        m.poll(params(**bad), op)
    assert e.value.code == m.E_PARAMS and op.calls == []


def test_missing_keys_and_non_dict_params():
    for p in (None, [], {"kind": "checks.finished"}, "x"):
        assert code_of({}, p) == m.E_PARAMS
    p = params()
    del p["settings"]
    assert code_of({}, p) == m.E_PARAMS


@pytest.mark.parametrize("cred", [None, "", 5, "a\nb", "x" * 5000])
def test_missing_or_odd_credential_is_a_login_error_with_no_call(cred):
    p = params()
    p["credential"] = cred
    assert code_of({}, p) == m.E_LOGIN
    del p["credential"]
    assert code_of({}, p) == m.E_LOGIN


@pytest.mark.parametrize("answer,code", [
    (401, m.E_LOGIN), (403, m.E_LOGIN), (500, m.E_NET), (429, m.E_NET), (302, m.E_NET), (301, m.E_NET),
    (OSError("boom " + SENTINEL), m.E_NET), (TimeoutError(SENTINEL), m.E_NET), (urllib.error.URLError(SENTINEL), m.E_NET),
    (b"not json", m.E_BAD), (b"", m.E_BAD), (b"\xff\xfe", m.E_BAD), (b"[]", m.E_BAD), (b"[" * 100000, m.E_BAD),
    (b'{"head":{"sha":"' + b"a" * 40 + b'"},"head":{}}', m.E_BAD), (b'{"head":NaN}', m.E_BAD),
    ({}, m.E_BAD), ({"head": None}, m.E_BAD), ({"head": {}}, m.E_BAD), ({"head": {"sha": 5}}, m.E_BAD),
    ({"head": {"sha": "A" * 40}}, m.E_BAD), ({"head": {"sha": "a" * 39}}, m.E_BAD), ({"head": {"sha": "../../x" + "a" * 33}}, m.E_BAD),
])  # fmt: skip
def test_pull_request_answers_are_coded_with_fixed_messages(answer, code):
    assert code_of({PR: answer}) == code


@pytest.mark.parametrize("answer,code", [
    (401, m.E_LOGIN), (403, m.E_LOGIN), (500, m.E_NET), (OSError(SENTINEL), m.E_NET), (b"nope", m.E_BAD),
    ({}, m.E_BAD), ({"total_count": 1}, m.E_BAD), ({"check_runs": []}, m.E_BAD), ({"total_count": "1", "check_runs": []}, m.E_BAD),
    ({"total_count": True, "check_runs": []}, m.E_BAD), ({"total_count": -1, "check_runs": []}, m.E_BAD),
    ({"total_count": 1, "check_runs": [1]}, m.E_BAD), ({"total_count": 1, "check_runs": [{}]}, m.E_BAD),
    ({"total_count": 1, "check_runs": [{"status": "completed"}]}, m.E_BAD),
    ({"total_count": 1, "check_runs": [{"status": "completed", "conclusion": None}]}, m.E_BAD),
    ({"total_count": 1, "check_runs": [{"status": 1, "conclusion": "success"}]}, m.E_BAD),
    ({"total_count": 101, "check_runs": [{"status": "completed", "conclusion": "success"}] * 101}, m.E_BAD),
])  # fmt: skip
def test_check_run_answers_are_coded_with_fixed_messages(answer, code):
    assert code_of({PR: pr(), RUNS: answer}) == code


def test_404_is_a_failed_event_for_the_pull_request_and_for_its_checks():
    assert result_of({PR: 404}) == {"state": "failed"}
    assert result_of({PR: pr(), RUNS: 404}) == {"state": "failed"}


def test_oversize_body_is_refused_and_the_limit_itself_is_fine():
    big = b'{"head":{"sha":"' + b"a" * 40 + b'"},"pad":"' + b"a" * (m.MAX_BODY + 10) + b'"}'
    assert code_of({PR: big}) == m.E_BAD
    base = json.dumps({"head": {"sha": SHA}, "pad": ""}).encode()
    ok = base.replace(b'""', b'"' + b"a" * (m.MAX_BODY - len(base)) + b'"')
    assert len(ok) == m.MAX_BODY
    assert result_of({PR: ok, RUNS: checks()}) == {"state": "pending"}


def test_a_non_200_success_status_is_refused():
    class Odd(Opener):
        def __call__(self, req, timeout=None):
            return Resp(b"{}", status=204)

    out = m.answer(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "events.poll", "params": params()}), Odd({}))
    assert out["error"]["code"] == m.E_NET


def test_the_real_opener_refuses_redirects():
    h = m._NoRedirect()
    assert h.redirect_request(urllib.request.Request("https://api.github.com/x"), None, 302, "Found", {}, "https://evil.example/") is None
    handlers = [type(x) for x in m.real_opener().__self__.handlers]
    assert m._NoRedirect in handlers and urllib.request.HTTPRedirectHandler not in handlers
    assert urllib.request.HTTPSHandler in handlers and urllib.request.ProxyHandler not in handlers


def test_the_total_time_budget_is_shared_by_all_requests():
    ticks = iter([100.0, 100.5, 100.5, 100.5, 108.5, 108.5, 108.5])  # the second request starts past the 8 s budget
    op = Opener({PR: pr(), RUNS: checks(("completed", "success"))})
    with pytest.raises(m.Fail) as e:
        m.poll(params(), op, now=lambda: next(ticks))
    assert e.value.code == m.E_NET and len(op.calls) == 1


# ------------------------------------------------------------------------------------------- the process itself
def run_proc(raw: str):
    r = subprocess.run([sys.executable, "-B", "-E", "-s", "-S", str(PKG / "main.py")], input=raw + "\n",
                       capture_output=True, text=True, timeout=10, check=True)  # fmt: skip
    assert r.stdout.count("\n") == 1 and r.stderr == ""
    assert SENTINEL not in r.stdout and SENTINEL not in r.stderr
    return json.loads(r.stdout)


def test_process_refuses_a_bad_ref_without_echoing_anything():
    p = params(ref="acme:api:" + SENTINEL)
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
