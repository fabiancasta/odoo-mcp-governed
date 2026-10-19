"""HTTP hardening found missing in the October 2026 audit.

- M1: one JSON-RPC batch of 300 calls went through as a single request, so
  the rate limit counted it once.
- M2: the limit was keyed by IP, and every local client — including every
  container behind the Docker bridge — shared one IP and one bucket.
- M4: MCP_HOST defaulted to 0.0.0.0, exposing the server to the LAN when run
  outside Docker.
- M6: the Origin header was not validated, which the MCP specification
  requires against DNS rebinding.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from odoo_mcp_governed.config import Settings
from odoo_mcp_governed.runtime import Runtime
from odoo_mcp_governed.web.app import create_app

from .test_http import bearer, make_settings, rpc


def app_with(tmp_path, **overrides) -> tuple[Runtime, TestClient]:
    runtime = Runtime(make_settings(tmp_path, **overrides))
    return runtime, TestClient(create_app(runtime))


def tool_events(runtime: Runtime) -> int:
    return sum(1 for e in runtime.audit.store.iter_all() if not e.tool.startswith(("mcp.", "self")))


class TestBatches:
    def test_an_oversized_batch_is_refused_before_anything_runs(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path, mcp_max_batch=10)
        batch = [rpc("tools/call", {"name": "search_count", "arguments": {"model": "res.partner"}},
                     id_=i) for i in range(300)]
        response = client.post("/mcp", json=batch, headers=bearer(runtime))
        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32600
        assert tool_events(runtime) == 0

    def test_every_message_in_a_batch_counts_against_the_limit(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path, rate_limit_mcp="5/minute")
        headers = bearer(runtime)
        batch = [rpc("ping", id_=i) for i in range(4)]
        assert client.post("/mcp", json=batch, headers=headers).status_code == 200
        assert client.post("/mcp", json=rpc("ping"), headers=headers).status_code == 200
        assert client.post("/mcp", json=rpc("ping"), headers=headers).status_code == 429

    def test_a_batch_bigger_than_what_is_left_is_refused_whole(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path, rate_limit_mcp="5/minute")
        headers = bearer(runtime)
        assert client.post("/mcp", json=[rpc("ping", id_=i) for i in range(3)],
                           headers=headers).status_code == 200
        assert client.post("/mcp", json=[rpc("ping", id_=i) for i in range(3)],
                           headers=headers).status_code == 429


class TestPerActorLimits:
    def test_one_busy_agent_does_not_starve_another_on_the_same_ip(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path, rate_limit_mcp="3/minute")
        busy, quiet = bearer(runtime, "busy"), bearer(runtime, "quiet")
        codes = [client.post("/mcp", json=rpc("ping"), headers=busy).status_code
                 for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        assert client.post("/mcp", json=rpc("ping"), headers=quiet).status_code == 200

    def test_the_ip_still_has_an_overall_ceiling(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path, rate_limit_mcp="100/minute",
                                   rate_limit_mcp_ip="4/minute")
        codes = [client.post("/mcp", json=rpc("ping"), headers=bearer(runtime, f"a{i}"))
                 .status_code for i in range(5)]
        assert codes == [200, 200, 200, 200, 429]

    def test_failed_authentication_is_limited_separately(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path, rate_limit_auth_fail="3/minute")
        bad = {"Authorization": "Bearer not-a-token"}
        codes = [client.post("/mcp", json=rpc("ping"), headers=bad).status_code
                 for _ in range(5)]
        assert codes == [401, 401, 401, 429, 429]


class TestOrigin:
    def test_a_foreign_origin_is_refused(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path)
        response = client.post("/mcp", json=rpc("ping"),
                               headers={**bearer(runtime), "Origin": "https://evil.example"})
        assert response.status_code == 403
        assert tool_events(runtime) == 0

    def test_no_origin_is_fine(self, tmp_path) -> None:
        """Non-browser clients such as Claude Code send no Origin at all."""
        runtime, client = app_with(tmp_path)
        assert client.post("/mcp", json=rpc("ping"), headers=bearer(runtime)).status_code == 200

    def test_local_and_configured_origins_are_accepted(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path, mcp_allowed_origins="https://app.example.com")
        for origin in ("http://localhost:6274", "http://127.0.0.1:8020",
                       "https://app.example.com"):
            response = client.post("/mcp", json=rpc("ping"),
                                   headers={**bearer(runtime), "Origin": origin})
            assert response.status_code == 200, origin

    def test_the_public_url_origin_is_accepted(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path, mcp_public_url="https://mcp.example.com")
        response = client.post("/mcp", json=rpc("ping"),
                               headers={**bearer(runtime), "Origin": "https://mcp.example.com"})
        assert response.status_code == 200


def test_the_default_bind_address_is_loopback(tmp_path) -> None:
    assert Settings(_env_file=None, data_dir=tmp_path).mcp_host == "127.0.0.1"


class TestMalformedInput:
    def test_deeply_nested_json_is_a_parse_error_not_a_500(self, tmp_path) -> None:
        """L1: 100k levels of nesting made json.loads raise RecursionError,
        which surfaced as a 500 with a traceback in the log."""
        runtime, client = app_with(tmp_path)
        body = b"[" * 100_000 + b"]" * 100_000
        response = client.post("/mcp", content=body,
                               headers={**bearer(runtime), "Content-Type": "application/json"})
        assert response.status_code == 400

    def test_moderately_nested_json_is_refused_before_dispatch(self, tmp_path) -> None:
        """Shallow enough to parse, deep enough to exhaust the recursion in
        domain handling later on."""
        runtime, client = app_with(tmp_path)
        domain: list = []
        for _ in range(500):
            domain = [domain]
        message = rpc("tools/call", {"name": "search_count",
                                     "arguments": {"model": "res.partner", "domain": domain}})
        response = client.post("/mcp", json=message, headers=bearer(runtime))
        assert response.status_code == 400
        assert tool_events(runtime) == 0

    def test_oversized_headers_are_refused(self, tmp_path) -> None:
        """L5: a 1 MB header was accepted."""
        runtime, client = app_with(tmp_path)
        response = client.post("/mcp", json=rpc("ping"),
                               headers={**bearer(runtime), "X-Junk": "a" * 64_000})
        assert response.status_code == 431

    def test_ordinary_headers_are_fine(self, tmp_path) -> None:
        runtime, client = app_with(tmp_path)
        response = client.post("/mcp", json=rpc("ping"),
                               headers={**bearer(runtime), "X-Trace": "a" * 2_000})
        assert response.status_code == 200


def test_a_flood_of_bad_tokens_does_not_lock_out_valid_agents(tmp_path) -> None:
    """Found by the red-team harness: the failed-auth limit was checked before
    verifying, so once an IP was exhausted every request from it got 429 —
    including valid agents sharing that IP (every container behind a Docker
    bridge). Ten bad tokens a minute were a denial of service."""
    runtime, client = app_with(tmp_path, rate_limit_auth_fail="3/minute")
    bad = {"Authorization": "Bearer not-a-token"}
    for _ in range(5):
        client.post("/mcp", json=rpc("ping"), headers=bad)
    assert client.post("/mcp", json=rpc("ping"), headers=bad).status_code == 429
    assert client.post("/mcp", json=rpc("ping"), headers=bearer(runtime)).status_code == 200
