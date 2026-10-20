"""Phases 2 and 3: the agent registry and record-level scope.

Phase 2 — every token can be revoked on its own, and an agent can be held to
fewer models and tools, read-only, a daily quota and one profile. A rule only
ever narrows the server policy.

Phase 3 — a scoped agent (a WhatsApp bot answering one customer) sees and
changes only the records its scope matches, with the customer taken from the
token's signed variables.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from odoo_mcp_governed.__main__ import main as cli
from odoo_mcp_governed.config import Settings
from odoo_mcp_governed.governance import Operation, PolicyConfig, PolicyEngine
from odoo_mcp_governed.governance.agents import (
    AgentError,
    AgentRule,
    AgentStore,
    parse_vars,
    resolve,
)
from odoo_mcp_governed.protocol import Dispatcher
from odoo_mcp_governed.runtime import Runtime, Snapshot
from odoo_mcp_governed.tools import ToolInputError, normalize_domain
from odoo_mcp_governed.web.app import create_app
from odoo_mcp_governed.web.auth import issue_token

from .conftest import FakeClock, make_call
from .test_http import ADMIN, login, make_settings, rpc
from .test_tools import FakeOdoo

WIDE = PolicyConfig(allowed_models=frozenset({"*"}), writable_models=frozenset({"*"}),
                    deletable_models=frozenset({"*"}), allow_execute_method=True)


def engine_with(**rule) -> PolicyEngine:
    return PolicyEngine(replace(WIDE, agent_rules={"bot": AgentRule(name="bot", **rule)}))


class TestRulesNarrow:
    def test_tools(self, clock: FakeClock) -> None:
        engine = engine_with(tools=frozenset({"search_records"}))
        assert engine.evaluate(make_call(clock, actor="bot")).allowed
        verdict = engine.evaluate(make_call(clock, actor="bot", tool="get_record"))
        assert "agent_tool" in verdict.codes
        admin = make_call(clock, actor="bot", tool="server_status", operation=Operation.ADMIN,
                          model=None)
        assert "agent_tool" in engine.evaluate(admin).codes

    def test_models(self, clock: FakeClock) -> None:
        engine = engine_with(models=frozenset({"sale.order"}))
        assert engine.evaluate(make_call(clock, actor="bot", model="sale.order")).allowed
        assert "agent_model" in engine.evaluate(make_call(clock, actor="bot")).codes

    def test_a_rule_never_widens_the_policy(self, clock: FakeClock) -> None:
        config = replace(WIDE, allowed_models=frozenset({"res.partner"}), agent_rules={
            "bot": AgentRule(name="bot", models=frozenset({"*", "res.users"}))})
        verdict = PolicyEngine(config).evaluate(make_call(clock, actor="bot", model="res.users"))
        assert not verdict.allowed

    def test_read_only(self, clock: FakeClock) -> None:
        engine = engine_with(read_only=True)
        assert engine.evaluate(make_call(clock, actor="bot")).allowed
        for op in (Operation.WRITE, Operation.CREATE, Operation.DELETE, Operation.EXECUTE):
            verdict = engine.evaluate(make_call(clock, actor="bot", operation=op,
                                                method="x" if op is Operation.EXECUTE else None))
            assert "agent_read_only" in verdict.codes, op

    def test_pinned_profile(self, clock: FakeClock) -> None:
        engine = engine_with(profile="client-a")
        assert engine.evaluate(make_call(clock, actor="bot", profile="client-a")).allowed
        assert "agent_profile" in engine.evaluate(
            make_call(clock, actor="bot", profile="client-b")).codes

    def test_other_agents_are_untouched(self, clock: FakeClock) -> None:
        engine = engine_with(read_only=True, tools=frozenset({"search_records"}))
        assert engine.evaluate(make_call(clock, actor="other", operation=Operation.WRITE,
                                         tool="update_record")).allowed

    def test_scope_limits_the_models(self, clock: FakeClock) -> None:
        engine = engine_with(scope={"sale.order": (["partner_id", "=", 1],)})
        assert engine.evaluate(make_call(clock, actor="bot", model="sale.order")).allowed
        assert "agent_scope" in engine.evaluate(make_call(clock, actor="bot")).codes


class TestRuleParsing:
    def test_from_form_values(self) -> None:
        rule = AgentRule.from_dict("bot", {
            "models": "res.partner, sale.order", "tools": ["search_records"],
            "daily_quota": "50", "scope": '{"res.partner": [["id", "=", "{partner}"]]}'})
        assert rule.models == {"res.partner", "sale.order"} and rule.daily_quota == 50
        assert rule.scope["res.partner"] == (["id", "=", "{partner}"],)

    @pytest.mark.parametrize("scope", [
        "not json", '["x"]', '{"res.partner": "id = 1"}', '{"res.partner": [["id", "~", 1]]}',
        '{"res.partner": [["id", "="]]}',
    ])
    def test_bad_scopes_are_refused(self, scope) -> None:
        with pytest.raises(AgentError):
            AgentRule.from_dict("bot", {"scope": scope})

    def test_negative_quota_is_refused(self) -> None:
        with pytest.raises(AgentError):
            AgentRule.from_dict("bot", {"daily_quota": "-1"})

    def test_vars(self) -> None:
        assert parse_vars(["partner=42", "city=Cali"]) == {"partner": 42, "city": "Cali"}
        with pytest.raises(AgentError):
            parse_vars(["Bad-Name=1"])

    def test_resolve_fails_closed(self) -> None:
        from odoo_mcp_governed.governance.agents import ScopeUnresolved
        assert resolve([["id", "=", "{p}"]], {"p": 7}) == [["id", "=", 7]]
        with pytest.raises(ScopeUnresolved):
            resolve([["id", "=", "{p}"]], {})

    def test_a_damaged_stored_rule_holds_the_agent_to_nothing(self, tmp_path) -> None:
        path = tmp_path / "agents.json"
        path.write_text(json.dumps({"agents": {"bot": {"scope": {"x": "broken"}}}}))
        rule = AgentStore(path).rule("bot")
        assert rule is not None and rule.tools == {"-"}


class TestDomainNormalisation:
    def test_implicit_and_made_explicit(self) -> None:
        assert normalize_domain([["a", "=", 1], ["b", "=", 2]]) == [
            "&", ["a", "=", 1], ["b", "=", 2]]

    def test_unbalanced_operators_are_refused(self) -> None:
        with pytest.raises(ToolInputError):
            normalize_domain(["|", ["a", "=", 1]])
        with pytest.raises(ToolInputError):
            normalize_domain(["^", ["a", "=", 1]])


# --- registry and tokens over HTTP ----------------------------------------------


@pytest.fixture
def web(tmp_path):
    def build(**overrides):
        runtime = Runtime(make_settings(tmp_path, **overrides))
        return runtime, TestClient(create_app(runtime))
    return build


def post(client, token: str, method: str = "tools/list"):
    return client.post("/mcp", json=rpc(method),
                       headers={"Authorization": f"Bearer {token}"})


class TestRevocation:
    def test_one_token_is_revoked_alone(self, web) -> None:
        runtime, client = web()
        first = runtime.issue_agent_token("bot", actor="admin")
        second = runtime.issue_agent_token("bot", actor="admin")
        assert runtime.revoke_token(first["jti"], actor="admin")
        assert post(client, first["token"]).status_code == 401
        assert post(client, second["token"]).status_code == 200

    def test_revoke_all_reaches_unregistered_tokens(self, web) -> None:
        runtime, client = web()
        old = issue_token(runtime.settings, "bot")["token"]  # minted before the registry
        other = issue_token(runtime.settings, "other")["token"]
        assert post(client, old).status_code == 200
        runtime.revoke_agent_tokens("bot", actor="admin")
        assert post(client, old).status_code == 401
        assert post(client, other).status_code == 200

    def test_registered_only_mode(self, web) -> None:
        runtime, client = web(require_registered_tokens=True)
        loose = issue_token(runtime.settings, "bot")["token"]
        assert post(client, loose).status_code == 401
        assert post(client, runtime.issue_agent_token("bot", actor="a")["token"]).status_code == 200

    def test_the_reason_stays_in_the_audit_log(self, web) -> None:
        runtime, client = web()
        issued = runtime.issue_agent_token("bot", actor="admin")
        runtime.revoke_token(issued["jti"], actor="admin")
        response = post(client, issued["token"])
        assert response.json() == {"error": "invalid or expired token"}
        [event] = [e for e in runtime.audit.store.tail(5) if e.tool == "mcp.auth"][:1]
        assert "revoked" in event.reasons[0]

    def test_cli_revoke_applies_without_a_restart(self, web, tmp_path, monkeypatch) -> None:
        runtime, client = web()
        issued = runtime.issue_agent_token("bot", actor="admin")
        assert post(client, issued["token"]).status_code == 200
        for key, value in {"DATA_DIR": str(tmp_path), "JWT_SECRET": "x" * 48,
                           "ADMIN_PASSWORD": ADMIN}.items():
            monkeypatch.setenv(key, value)
        assert cli(["revoke", "--actor", "bot"]) == 0
        assert post(client, issued["token"]).status_code == 401

    def test_cli_token_is_registered_with_its_variables(self, tmp_path, monkeypatch,
                                                         capsys) -> None:
        for key, value in {"DATA_DIR": str(tmp_path), "JWT_SECRET": "x" * 48,
                           "ADMIN_PASSWORD": ADMIN}.items():
            monkeypatch.setenv(key, value)
        assert cli(["token", "--actor", "bot", "--var", "partner=42"]) == 0
        [token] = AgentStore(tmp_path / "agents.json").tokens("bot")
        assert token["vars"] == {"partner": 42}
        assert cli(["token", "--actor", "bot", "--var", "x-y=1"]) == 2


class TestAgentsPanel:
    def test_save_issue_and_revoke_from_the_panel(self, web) -> None:
        runtime, client = web()
        csrf = login(client)
        saved = client.post("/admin/agents/save", data={
            "csrf": csrf, "name": "wabot", "models": "res.partner", "tools": "search_records",
            "daily_quota": "100", "read_only": "yes",
            "scope": '{"res.partner": [["id", "=", "{partner}"]]}'}, follow_redirects=False)
        assert saved.status_code == 303
        rule = runtime.engine.policy.config.agent_rules["wabot"]
        assert rule.read_only and rule.daily_quota == 100
        page = client.post("/admin/agents/token", data={
            "csrf": csrf, "name": "wabot", "vars": "partner=42", "label": "customer 42"}).text
        token = re.search(r'<textarea readonly class="mono">([^<]+)</textarea>', page).group(1)
        listed = post(client, token).json()["result"]["tools"]
        assert [t["name"] for t in listed] == ["search_records"]
        [row] = runtime.agents.tokens("wabot")
        assert client.post("/admin/agents/revoke", data={"csrf": csrf, "jti": row["jti"]},
                           follow_redirects=False).status_code == 303
        assert post(client, token).status_code == 401

    def test_a_bad_scope_is_explained(self, web) -> None:
        _, client = web()
        csrf = login(client)
        page = client.post("/admin/agents/save", data={
            "csrf": csrf, "name": "wabot", "scope": "{nope"}).text
        assert "Agent not saved" in page

    def test_the_page_needs_a_login(self, web) -> None:
        _, client = web()
        assert client.get("/admin/agents", follow_redirects=False).status_code == 303


class TestQuota:
    def test_daily_quota(self, web) -> None:
        runtime, client = web()
        runtime.save_agent(AgentRule(name="bot", daily_quota=2), actor="admin")
        token = runtime.issue_agent_token("bot", actor="admin")["token"]

        def search():
            return client.post("/mcp", headers={"Authorization": f"Bearer {token}"}, json=rpc(
                "tools/call", {"name": "search_count", "arguments": {"model": "res.partner"}}
            )).json()["result"]

        search(), search()  # Odoo is unreachable here: errors still count as calls
        third = search()
        assert third["isError"] and "calls for today" in third["content"][0]["text"]


# --- record scope at the tools ---------------------------------------------------


PARTNERS = {7: {"id": 7, "name": "Mine"}, 8: {"id": 8, "name": "Someone else"}}


class ScopedOdoo(FakeOdoo):
    """Answers search_count on res.partner and sale.order by evaluating the
    scope's equality conditions, so the tests do not trust the tool layer."""

    orders = {1: {"id": 1, "partner_id": 7}, 2: {"id": 2, "partner_id": 8}}

    def execute(self, model, method, args=None, kwargs=None):
        if method == "search_count" and model in ("res.partner", "sale.order"):
            self.calls.append((model, method, args or [], kwargs or {}))
            rows = PARTNERS if model == "res.partner" else self.orders
            return sum(1 for r in rows.values() if _matches(r, args[0]))
        return super().execute(model, method, args, kwargs)


def _matches(row: dict, domain: list) -> bool:
    for item in domain:
        if isinstance(item, list):
            name, op, value = item
            have = row.get(name)
            if op == "=" and have != value:
                return False
            if op == "in" and have not in value:
                return False
    return True


SCOPE = {"res.partner": (["id", "=", "{partner}"],),
         "sale.order": (["partner_id", "=", "{partner}"],)}


@pytest.fixture
def scoped(tmp_path):
    runtime = Runtime(Settings(
        _env_file=None, data_dir=tmp_path, odoo_url="http://fake.invalid", odoo_db="d",
        odoo_username="u", odoo_api_key="k", allowed_models="*", writable_models="*",
        deletable_models="*", allow_execute_method=True, business_timezone="UTC",
        business_hours="00:00-23:59", business_days="mon,tue,wed,thu,fri,sat,sun",
        risk_throttle_seconds=0, odoo_environment="development",
    ))
    runtime.save_agent(AgentRule(name="wabot", scope=SCOPE), actor="admin")
    fake = ScopedOdoo()
    runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
    dispatcher = Dispatcher(runtime)

    def call(tool, variables=None, **arguments):
        response = dispatcher.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": tool, "arguments": arguments}},
            "wabot", None, {"partner": 7} if variables is None else variables)["result"]
        text = response["content"][0]["text"]
        try:
            return response["isError"], json.loads(text)
        except ValueError:
            return response["isError"], text
    return call, fake


def _writes(fake, method):
    return [c for c in fake.calls if c[1] == method and c[0] != "ir.model"]


class TestRecordScope:
    def test_search_is_limited_to_own_records(self, scoped) -> None:
        call, fake = scoped
        assert not call("search_records", model="sale.order", domain=[["state", "=", "sale"]],
                        fields=["name"])[0]
        [(_, _, args, _)] = [c for c in fake.calls if c[:2] == ("sale.order", "search_read")]
        assert args[0] == ["&", ["partner_id", "=", 7], ["state", "=", "sale"]]

    def test_an_or_from_the_agent_cannot_swallow_the_scope(self, scoped) -> None:
        call, fake = scoped
        call("search_count", model="sale.order",
             domain=["|", ["id", "=", 2], ["id", "=", 1]])
        [(_, _, args, _)] = [c for c in fake.calls if c[1] == "search_count" and
                             "|" in c[2][0]]
        assert args[0][:2] == ["&", ["partner_id", "=", 7]]
        assert call("search_count", model="sale.order", domain=["|", ["id", "=", 2]])[0]

    def test_name_search_too(self, scoped) -> None:
        call, fake = scoped
        call("name_search", model="res.partner", name="a")
        [(_, _, args, _)] = [c for c in fake.calls if c[1] == "name_search"]
        assert args[1] == [["id", "=", 7]]

    def test_reading_another_customer_is_refused(self, scoped) -> None:
        call, fake = scoped
        fake.responses[("res.partner", "read")] = [PARTNERS[7]]
        assert not call("get_record", model="res.partner", record_id=7)[0]
        is_error, body = call("get_record", model="res.partner", ids=[7, 8])
        assert is_error and "own records" in body

    def test_models_outside_the_scope_are_refused(self, scoped) -> None:
        call, fake = scoped
        is_error, body = call("search_records", model="account.move")
        assert is_error and "scope" in body
        assert not [c for c in fake.calls if c[0] == "account.move"]

    def test_a_token_without_the_variable_sees_nothing(self, scoped) -> None:
        call, fake = scoped
        call("search_records", model="sale.order", variables={}, fields=["name"])
        [(_, _, args, _)] = [c for c in fake.calls if c[:2] == ("sale.order", "search_read")]
        assert args[0] == ["partner_id", "=", 0] or ["id", "=", 0] in args[0]

    def test_create_fills_the_scope_and_refuses_another_owner(self, scoped) -> None:
        call, fake = scoped
        fake.responses[("sale.order", "create")] = 5
        assert not call("create_record", model="sale.order", values={"note": "x"})[0]
        [(_, _, args, _)] = _writes(fake, "create")
        assert args[0]["partner_id"] == 7
        is_error, _ = call("create_record", model="sale.order", values={"partner_id": 8})
        assert is_error and len(_writes(fake, "create")) == 1

    def test_creating_a_customer_is_refused(self, scoped) -> None:
        call, fake = scoped
        assert call("create_record", model="res.partner", values={"name": "x"})[0]
        assert not _writes(fake, "create")

    def test_update_cannot_move_a_record_out(self, scoped) -> None:
        call, fake = scoped
        assert not call("update_record", model="sale.order", record_id=1,
                        values={"note": "ok"})[0]
        assert call("update_record", model="sale.order", record_id=1,
                    values={"partner_id": 8})[0]
        assert call("update_record", model="sale.order", record_id=2, values={"note": "x"})[0]
        assert len(_writes(fake, "write")) == 1

    def test_delete_and_methods_only_on_own_records(self, scoped) -> None:
        call, fake = scoped
        assert call("delete_record", model="sale.order", record_id=2)[0]
        assert call("execute_method", model="sale.order", method="action_confirm",
                    args=[[2]])[0]
        assert call("execute_method", model="sale.order", method="search_read",
                    args=[[]])[0]
        assert not call("execute_method", model="sale.order", method="action_confirm",
                        args=[[1]])[0]
        assert not _writes(fake, "unlink") and not _writes(fake, "search_read")

    def test_onchange_is_refused(self, scoped) -> None:
        call, fake = scoped
        assert call("call_onchange", model="sale.order", values={"partner_id": 8})[0]

    def test_files_only_of_own_records(self, scoped) -> None:
        call, fake = scoped
        assert call("list_attachments", model="res.partner", record_id=8)[0]
        fake.responses[("ir.attachment", "read")] = [
            {"id": 3, "name": "a.pdf", "mimetype": "application/pdf", "file_size": 3,
             "res_model": "res.partner", "res_id": 8, "res_field": False}]
        assert call("get_attachment", attachment_id=3)[0]
        assert call("upload_attachment", model="res.partner", record_id=8, filename="x.txt",
                    data_base64="eA==")[0]
        assert not _writes(fake, "create")

    def test_list_models_shows_only_the_scope(self, scoped) -> None:
        call, fake = scoped
        fake.responses[("ir.model", "search_read")] = [
            {"model": m, "name": m, "transient": False}
            for m in ("res.partner", "sale.order", "account.move")]
        _, body = call("list_models")
        assert {m["model"] for m in body["models"]} == {"res.partner", "sale.order"}
