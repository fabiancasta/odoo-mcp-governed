"""HTTP transport tests: authentication, admin panel, hardening.

These run the real FastAPI application in-process. No Odoo is needed: the
profile points at a closed port, which is itself a useful case — the server
must stay up, answer health checks and report the failure cleanly.
"""

from __future__ import annotations

import re
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from odoo_mcp_governed.config import ConfigError, Settings
from odoo_mcp_governed.governance import Decision
from odoo_mcp_governed.runtime import Runtime
from odoo_mcp_governed.web.app import create_app
from odoo_mcp_governed.web.auth import issue_token

SECRET = "x" * 48
ADMIN = "correct-horse-battery"


def make_settings(tmp_path, **overrides) -> Settings:
    values = dict(
        data_dir=tmp_path,
        jwt_secret=SECRET,
        admin_password=ADMIN,
        odoo_url="http://127.0.0.1:9",
        odoo_db="db",
        odoo_username="bot",
        odoo_api_key="key-123",
        allowed_models="res.partner",
        business_timezone="UTC",
        business_hours="00:00-23:59",
        business_days="mon,tue,wed,thu,fri,sat,sun",
        rate_limit_login="5/minute",
        rate_limit_mcp="1000/minute",
        rate_limit_health="1000/minute",
        risk_throttle_seconds=0,
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
def runtime(tmp_path) -> Runtime:
    return Runtime(make_settings(tmp_path))


@pytest.fixture
def client(runtime: Runtime) -> TestClient:
    return TestClient(create_app(runtime))


def bearer(runtime: Runtime, actor: str = "agent-x") -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(runtime.settings, actor)['token']}"}


def rpc(method: str, params: dict | None = None, id_: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


def last_auth_reason(runtime: Runtime) -> str:
    """Why the last authentication failed — kept in the audit log, never sent
    to the caller (CodeQL py/stack-trace-exposure, CWE-209)."""
    [event] = [e for e in runtime.audit.store.tail(5) if e.tool == "mcp.auth"][:1]
    return event.reasons[0]


def login(client: TestClient) -> str:
    response = client.post("/admin", data={"password": ADMIN}, follow_redirects=False)
    assert response.status_code == 303
    page = client.get("/admin").text
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


# --- fail closed -------------------------------------------------------------


class TestFailClosed:
    def test_refuses_to_start_without_a_jwt_secret(self, tmp_path) -> None:
        with pytest.raises(ConfigError, match="JWT_SECRET"):
            create_app(Runtime(make_settings(tmp_path, jwt_secret="")))

    def test_refuses_a_short_jwt_secret(self, tmp_path) -> None:
        with pytest.raises(ConfigError, match="at least 32"):
            create_app(Runtime(make_settings(tmp_path, jwt_secret="short-secret")))

    def test_refuses_to_start_without_an_admin_password(self, tmp_path) -> None:
        with pytest.raises(ConfigError, match="ADMIN_PASSWORD"):
            create_app(Runtime(make_settings(tmp_path, admin_password="")))


# --- MCP authentication ------------------------------------------------------


class TestMcpAuth:
    def test_valid_token_reaches_the_dispatcher(self, client, runtime) -> None:
        response = client.post("/mcp", json=rpc("initialize"), headers=bearer(runtime))
        assert response.status_code == 200
        assert response.json()["result"]["serverInfo"]["name"] == "odoo-mcp-governed"
        assert re.match(r"^[A-Za-z0-9_-]{16,128}$", response.headers["mcp-session-id"])

    def test_missing_token_is_401(self, client) -> None:
        response = client.post("/mcp", json=rpc("tools/list"))
        assert response.status_code == 401
        assert "Bearer" in response.headers["www-authenticate"]

    def test_malformed_token_is_a_clean_401_not_a_500(self, client) -> None:
        response = client.post("/mcp", json=rpc("tools/list"),
                               headers={"Authorization": "Bearer not.a.jwt"})
        assert response.status_code == 401

    def test_wrong_signature_is_rejected(self, client) -> None:
        forged = jwt.encode({"sub": "x", "iss": "odoo-mcp-governed", "iat": int(time.time()),
                             "exp": int(time.time()) + 60}, "y" * 48, algorithm="HS256")
        response = client.post("/mcp", json=rpc("tools/list"),
                               headers={"Authorization": f"Bearer {forged}"})
        assert response.status_code == 401

    def test_alg_none_is_rejected(self, client, runtime) -> None:
        """The classic: a token that declares no signature at all."""
        unsigned = jwt.encode({"sub": "x", "iss": "odoo-mcp-governed", "iat": int(time.time()),
                               "exp": int(time.time()) + 60}, None, algorithm="none")
        response = client.post("/mcp", json=rpc("tools/list"),
                               headers={"Authorization": f"Bearer {unsigned}"})
        assert response.status_code == 401
        assert response.json() == {"error": "invalid or expired token"}
        assert "algorithm" in last_auth_reason(runtime)

    def test_expired_token_is_rejected(self, client, runtime) -> None:
        old = jwt.encode({"sub": "x", "iss": "odoo-mcp-governed", "iat": 1, "exp": 2},
                         SECRET, algorithm="HS256")
        response = client.post("/mcp", json=rpc("tools/list"),
                               headers={"Authorization": f"Bearer {old}"})
        assert response.status_code == 401
        assert response.json() == {"error": "invalid or expired token"}
        assert "expired" in last_auth_reason(runtime)

    def test_wrong_issuer_is_rejected(self, client) -> None:
        other = jwt.encode({"sub": "x", "iss": "someone-else", "iat": int(time.time()),
                            "exp": int(time.time()) + 60}, SECRET, algorithm="HS256")
        response = client.post("/mcp", json=rpc("tools/list"),
                               headers={"Authorization": f"Bearer {other}"})
        assert response.status_code == 401

    def test_token_without_expiry_is_rejected(self, client) -> None:
        forever = jwt.encode({"sub": "x", "iss": "odoo-mcp-governed", "iat": int(time.time())},
                             SECRET, algorithm="HS256")
        response = client.post("/mcp", json=rpc("tools/list"),
                               headers={"Authorization": f"Bearer {forever}"})
        assert response.status_code == 401

    def test_failed_auth_is_audited(self, client, runtime) -> None:
        client.post("/mcp", json=rpc("tools/list"), headers={"Authorization": "Bearer junk"})
        events = runtime.audit.store.search(tool_prefix="mcp.auth")
        assert events and events[0].decision is Decision.DENY
        assert events[0].actor.startswith("anonymous@")

    def test_token_subject_becomes_the_audited_actor(self, client, runtime) -> None:
        client.post(
            "/mcp",
            json=rpc("tools/call", {"name": "search_count", "arguments": {"model": "res.users"}}),
            headers=bearer(runtime, "invoice-bot"),
        )
        assert runtime.audit.tail(1)[0].actor == "invoice-bot"


# --- MCP protocol over HTTP --------------------------------------------------


class TestMcpProtocol:
    def test_lists_18_tools(self, client, runtime) -> None:
        tools = client.post("/mcp", json=rpc("tools/list"), headers=bearer(runtime)).json()
        assert len(tools["result"]["tools"]) == 18

    def test_policy_denial_is_a_tool_error_with_a_reason(self, client, runtime) -> None:
        response = client.post(
            "/mcp",
            json=rpc("tools/call", {"name": "search_records", "arguments": {"model": "res.users"}}),
            headers=bearer(runtime),
        ).json()
        assert response["result"]["isError"] is True
        assert "res.users" in response["result"]["content"][0]["text"]

    def test_unreachable_odoo_is_reported_without_internals(self, client, runtime) -> None:
        response = client.post(
            "/mcp",
            json=rpc("tools/call", {"name": "search_count", "arguments": {"model": "res.partner"}}),
            headers=bearer(runtime),
        ).json()
        text = response["result"]["content"][0]["text"]
        assert response["result"]["isError"] is True
        assert "Could not reach Odoo" in text
        assert "127.0.0.1" not in text and "Traceback" not in text

    def test_notification_returns_202(self, client, runtime) -> None:
        response = client.post(
            "/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=bearer(runtime),
        )
        assert response.status_code == 202

    def test_unknown_method_is_a_jsonrpc_error(self, client, runtime) -> None:
        body = client.post("/mcp", json=rpc("resources/list"), headers=bearer(runtime)).json()
        assert body["error"]["code"] == -32601

    def test_batch_requests(self, client, runtime) -> None:
        body = client.post("/mcp", json=[rpc("ping", id_=1), rpc("ping", id_=2)],
                           headers=bearer(runtime)).json()
        assert [r["id"] for r in body] == [1, 2]

    def test_invalid_json_is_a_parse_error(self, client, runtime) -> None:
        response = client.post("/mcp", content=b"{nope",
                               headers={**bearer(runtime), "Content-Type": "application/json"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32700

    def test_malformed_session_id_is_rejected_not_reflected(self, client, runtime) -> None:
        evil = "<script>alert(1)</script>"
        response = client.post("/mcp", json=rpc("ping"),
                               headers={**bearer(runtime), "Mcp-Session-Id": evil})
        assert response.status_code == 400
        assert evil not in response.text

    def test_get_on_mcp_is_405(self, client) -> None:
        assert client.get("/mcp").status_code == 405

    def test_root_post_is_an_alias_for_mcp(self, client, runtime) -> None:
        response = client.post("/", json=rpc("ping"), headers=bearer(runtime))
        assert response.status_code == 200 and response.json()["result"] == {}

    def test_disabled_tool_disappears_and_is_refused(self, client, runtime) -> None:
        runtime.update_policy({"disabled_tools": ["delete_record"]}, actor="test")
        tools = client.post("/mcp", json=rpc("tools/list"), headers=bearer(runtime)).json()
        assert "delete_record" not in {t["name"] for t in tools["result"]["tools"]}
        called = client.post(
            "/mcp",
            json=rpc("tools/call", {"name": "delete_record",
                                    "arguments": {"model": "res.partner", "record_id": 1}}),
            headers=bearer(runtime),
        ).json()
        assert called["result"]["isError"] is True
        assert "disabled" in called["result"]["content"][0]["text"]


# --- hardening ---------------------------------------------------------------


class TestHardening:
    def test_api_docs_are_not_published(self, client) -> None:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404, path

    def test_security_headers(self, client) -> None:
        headers = client.get("/health").headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["cache-control"] == "no-store"
        assert "content-security-policy" in headers

    def test_admin_pages_allow_only_their_own_script(self, client) -> None:
        csp = client.get("/admin").headers["content-security-policy"]
        assert "script-src 'self';" in csp and "default-src 'none'" in csp
        assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]

    def test_hsts_only_in_https_mode(self, tmp_path) -> None:
        plain = TestClient(create_app(Runtime(make_settings(tmp_path / "a"))))
        assert "strict-transport-security" not in plain.get("/health").headers
        https = TestClient(create_app(Runtime(make_settings(tmp_path / "b", https_mode=True))))
        assert "max-age" in https.get("/health").headers["strict-transport-security"]

    def test_oversized_body_is_413(self, tmp_path) -> None:
        client = TestClient(create_app(Runtime(make_settings(tmp_path, max_body_mb=0.01))))
        response = client.post("/mcp", content=b"x" * 20_000,
                               headers={"Content-Type": "application/json"})
        assert response.status_code == 413

    def test_chunked_oversized_body_is_413(self, tmp_path) -> None:
        """No Content-Length: the limit must come from counting bytes."""
        client = TestClient(create_app(Runtime(make_settings(tmp_path, max_body_mb=0.01))))

        def chunks():
            for _ in range(10):
                yield b"x" * 4096

        response = client.post("/mcp", content=chunks(),
                               headers={"Content-Type": "application/json"})
        assert response.status_code == 413

    def test_health_hides_connection_errors(self, client) -> None:
        body = client.get("/health").json()
        assert body == {"status": "ok", "odoo": "unreachable"}

    def test_mcp_rate_limit(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path, rate_limit_mcp="3/minute"))
        client = TestClient(create_app(runtime))
        codes = [client.post("/mcp", json=rpc("ping"), headers=bearer(runtime)).status_code
                 for _ in range(5)]
        assert codes == [200, 200, 200, 429, 429]


# --- admin panel -------------------------------------------------------------


class TestAdmin:
    def test_panel_requires_login(self, client) -> None:
        assert "Administrator login" in client.get("/admin").text
        assert client.get("/token", follow_redirects=False).status_code == 303
        assert client.get("/admin/logs", follow_redirects=False).status_code == 303

    def test_wrong_password(self, client, runtime) -> None:
        response = client.post("/admin", data={"password": "nope"})
        assert response.status_code == 401
        event = runtime.audit.store.search(tool_prefix="admin.login")[0]
        assert event.decision is Decision.DENY

    def test_login_is_rate_limited(self, client) -> None:
        codes = [client.post("/admin", data={"password": "bad"}).status_code for _ in range(6)]
        assert codes[-1] == 429

    def test_session_cookie_is_random_and_hardened(self, client) -> None:
        response = client.post("/admin", data={"password": ADMIN}, follow_redirects=False)
        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie and "SameSite=strict" in cookie
        value = re.search(r"gov_admin=([^;]+)", cookie).group(1)
        assert len(value) >= 43  # 32 random bytes, urlsafe base64
        assert ADMIN not in cookie
        import hashlib

        assert hashlib.sha256(ADMIN.encode()).hexdigest() not in cookie

    def test_logout_invalidates_the_session(self, client) -> None:
        login(client)
        client.post("/admin/logout")
        assert "Administrator login" in client.get("/admin").text

    def test_api_keys_never_reach_the_browser(self, client) -> None:
        login(client)
        for page in (client.get("/admin").text, client.get("/admin?edit=default").text):
            assert "key-123" not in page

    def test_posts_without_csrf_are_refused(self, client, runtime) -> None:
        login(client)
        before = runtime.profiles.active_name
        response = client.post("/admin/profile/save", data={
            "name": "evil", "url": "http://evil.example", "database": "x", "username": "x",
            "api_key": "k",
        }, follow_redirects=False)
        assert response.status_code == 303 and "m=csrf" in response.headers["location"]
        assert runtime.profiles.get("evil") is None
        assert runtime.profiles.active_name == before

    def test_profile_name_charset_is_enforced(self, client) -> None:
        csrf = login(client)
        response = client.post("/admin/profile/save", data={
            "csrf": csrf, "name": "../../etc", "url": "http://x.example", "database": "d",
            "username": "u", "api_key": "k",
        })
        assert response.status_code == 400
        assert "may only contain" in response.text

    def test_edit_with_empty_key_keeps_the_stored_key(self, client, runtime) -> None:
        csrf = login(client)
        client.post("/admin/profile/save", data={
            "csrf": csrf, "name": "default", "url": "http://127.0.0.1:9", "database": "db2",
            "username": "bot", "api_key": "", "timeout": "30", "ssl_verify": "1",
        })
        profile = runtime.profiles.get("default")
        assert profile.database == "db2"
        assert profile.api_key == "key-123"

    def test_hot_swap_changes_the_next_call(self, client, runtime) -> None:
        csrf = login(client)
        client.post("/admin/profile/save", data={
            "csrf": csrf, "name": "second", "url": "http://127.0.0.1:10", "database": "other",
            "username": "bot", "api_key": "k2", "timeout": "30", "ssl_verify": "1",
        })
        assert runtime.snapshot().profile.name == "default"
        client.post("/admin/profile/activate", data={"csrf": csrf, "name": "second"})
        assert runtime.snapshot().profile.name == "second"
        assert runtime.snapshot().client.database == "other"
        # The switch itself is in the audit chain.
        assert runtime.audit.store.search(tool_prefix="admin.profile.activate")

    def test_cannot_delete_the_active_profile(self, client) -> None:
        csrf = login(client)
        response = client.post("/admin/profile/delete",
                               data={"csrf": csrf, "name": "default", "confirm": "yes"})
        assert response.status_code == 400

    def test_policy_change_applies_live_and_persists(self, client, runtime, tmp_path) -> None:
        csrf = login(client)
        form = {
            "csrf": csrf, "enabled_tools": [t for t in runtime.policy_store.as_dict()
                                            ["disabled_tools"]] or None,
            "allowed_models": "res.partner\nsale.order", "writable_models": "",
            "deletable_models": "", "denied_models": "ir.cron", "execute_method_allowlist": "",
            "forbidden_methods": "", "max_records_per_call": "100",
        }
        form.pop("enabled_tools")
        client.post("/admin/policy", data={**form, "enabled_tools": ["search_records"]})
        config = runtime.engine.policy.config
        assert config.allowed_models == {"res.partner", "sale.order"}
        assert config.max_records_per_call == 100
        assert "search_records" not in config.disabled_tools
        assert "delete_record" in config.disabled_tools
        assert (tmp_path / "policy.json").stat().st_mode & 0o777 == 0o600
        event = runtime.audit.store.search(tool_prefix="admin.policy.update")[0]
        assert "allowed_models" in event.fields_touched

    def test_audit_page_renders_and_filters(self, client, runtime) -> None:
        login(client)
        client.post("/mcp", json=rpc("tools/call", {"name": "search_records",
                                                    "arguments": {"model": "res.users"}}),
                    headers=bearer(runtime, "probe-bot"))
        page = client.get("/admin/logs?decision=deny").text
        assert "probe-bot" in page and "res.users" in page

    def test_injected_markup_in_audit_data_is_escaped(self, client, runtime) -> None:
        login(client)
        client.post("/mcp", json=rpc("tools/call", {
            "name": "search_records", "arguments": {"model": "<img src=x onerror=alert(1)>"}}),
            headers=bearer(runtime))
        page = client.get("/admin/logs").text
        assert "<img src=x" not in page
        assert "&lt;img src=x" in page

    def test_token_page_and_regeneration(self, client, runtime) -> None:
        csrf = login(client)
        client.post("/admin/token/regenerate",
                    data={"csrf": csrf, "actor": "claude-desktop", "confirm": "yes"})
        page = client.get("/token").text
        token = re.search(r'readonly class="mono">([^<]+)<', page).group(1)
        assert client.post("/mcp", json=rpc("ping"),
                           headers={"Authorization": f"Bearer {token}"}).status_code == 200
        assert (runtime.settings.token_file.stat().st_mode & 0o777) == 0o600

    def test_secret_files_are_0600(self, client, runtime) -> None:
        for path in (runtime.settings.profiles_file,):
            assert path.stat().st_mode & 0o777 == 0o600, path


def test_audit_database_and_its_wal_files_are_private(tmp_path) -> None:
    runtime = Runtime(make_settings(tmp_path / "data"))
    runtime.audit.write_anchor(runtime.settings.anchors_file)
    data = tmp_path / "data"
    assert data.stat().st_mode & 0o777 == 0o700
    for name in ("audit.db", "audit.db-wal", "audit.db-shm", "anchors.log", "profiles.json"):
        path = data / name
        if path.exists():
            assert path.stat().st_mode & 0o777 == 0o600, name
