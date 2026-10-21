"""Permissions per profile: one server, several Odoo instances.

A company with an Odoo in Spain and another in Colombia runs one server with
two profiles. Each profile can have its own model lists; a profile without
them uses the default lists. The floor — denylist, system models,
credentials — and each profile's environment (a production profile without
``allow_writes`` stays read-only) apply whatever the lists say.
"""

from __future__ import annotations

import re
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from odoo_mcp_governed.governance import Operation, PolicyConfig, PolicyEngine
from odoo_mcp_governed.policy_store import PolicyStore
from odoo_mcp_governed.profiles import Profile
from odoo_mcp_governed.protocol import Dispatcher
from odoo_mcp_governed.runtime import Runtime, Snapshot
from odoo_mcp_governed.web.app import create_app

from .conftest import FakeClock, make_call
from .test_http import login, make_settings
from .test_tools import FakeOdoo, call

BASE = PolicyConfig(
    allowed_models=frozenset({"res.partner"}), writable_models=frozenset({"res.partner"}),
    profile_lists={"colombia": {
        "allowed_models": frozenset({"pos.order", "account.move"}),
        "writable_models": frozenset({"pos.order"}),
        "deletable_models": frozenset(),
    }},
)


class TestEvaluation:
    def test_a_profile_with_its_own_lists_uses_them(self, clock: FakeClock) -> None:
        engine = PolicyEngine(BASE)
        assert engine.evaluate(make_call(clock, model="pos.order", profile="colombia")).allowed
        assert "model_not_allowed" in engine.evaluate(
            make_call(clock, model="res.partner", profile="colombia")).codes

    def test_other_profiles_use_the_default(self, clock: FakeClock) -> None:
        engine = PolicyEngine(BASE)
        assert engine.evaluate(make_call(clock, model="res.partner", profile="spain")).allowed
        assert "model_not_allowed" in engine.evaluate(
            make_call(clock, model="pos.order", profile="spain")).codes

    def test_writes_follow_the_profile_lists(self, clock: FakeClock) -> None:
        engine = PolicyEngine(BASE)
        write = dict(operation=Operation.WRITE, tool="update_record", profile="colombia")
        assert engine.evaluate(make_call(clock, model="pos.order", **write)).allowed
        assert "model_not_writable" in engine.evaluate(
            make_call(clock, model="account.move", **write)).codes

    def test_a_read_only_production_profile_stays_read_only(self, clock: FakeClock) -> None:
        engine = PolicyEngine(replace(BASE, read_only_profiles=frozenset({"colombia"})))
        verdict = engine.evaluate(make_call(clock, model="pos.order", operation=Operation.WRITE,
                                            tool="update_record", profile="colombia"))
        assert "profile_read_only" in verdict.codes

    def test_the_floor_is_the_same_for_every_profile(self, clock: FakeClock) -> None:
        config = replace(BASE, profile_lists={"colombia": {
            "allowed_models": frozenset({"*"}), "writable_models": frozenset(),
            "deletable_models": frozenset()}})
        engine = PolicyEngine(config)
        for model, code in (("res.users", "system_model"), ("ir.attachment", "model_denied"),
                            ("ir.config_parameter", "model_denied")):
            assert code in engine.evaluate(
                make_call(clock, model=model, profile="colombia")).codes, model


@pytest.fixture
def two_odoos(tmp_path):
    runtime = Runtime(make_settings(tmp_path, odoo_environment="development"))
    for name, env in (("spain", "development"), ("colombia", "production")):
        runtime.save_profile(Profile(name=name, url=f"http://{name}.invalid", database=name,
                                     username="u", api_key="k", environment=env),
                             actor="admin")
    return runtime


class TestStore:
    def test_set_reset_and_persist(self, two_odoos: Runtime, tmp_path) -> None:
        two_odoos.set_profile_lists("colombia", {"allowed_models": ["pos.order"]},
                                    actor="admin")
        engine_cfg = two_odoos.engine.policy.config
        assert engine_cfg.for_profile("colombia").allowed_models == {"pos.order"}
        assert engine_cfg.for_profile("spain").allowed_models == {"res.partner"}
        reloaded = PolicyStore(two_odoos.settings.policy_file, PolicyConfig())
        assert reloaded.config.profile_lists["colombia"]["allowed_models"] == {"pos.order"}
        two_odoos.set_profile_lists("colombia", None, actor="admin")
        assert "colombia" not in two_odoos.engine.policy.config.profile_lists

    def test_an_unknown_profile_is_refused(self, two_odoos: Runtime) -> None:
        with pytest.raises(ValueError):
            two_odoos.set_profile_lists("mars", {"allowed_models": ["x.y"]}, actor="admin")

    def test_the_change_is_audited(self, two_odoos: Runtime) -> None:
        two_odoos.set_profile_lists("colombia", {"allowed_models": ["pos.order"]},
                                    actor="admin")
        assert any(e.tool == "admin.policy.update" for e in two_odoos.audit.store.tail(3))


class TestAtTheTools:
    def test_each_odoo_answers_with_its_own_permissions(self, two_odoos: Runtime) -> None:
        two_odoos.set_profile_lists("colombia", {"allowed_models": ["pos.order"]},
                                    actor="admin")
        fakes = {"spain": FakeOdoo(), "colombia": FakeOdoo()}
        two_odoos._snapshot_factory = lambda profile: Snapshot(profile, fakes[profile.name])
        two_odoos._pinned.clear()
        d = Dispatcher(two_odoos)

        def ask(profile: str, model: str):
            reply = d.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "search_count", "arguments": {"model": model}}}, "agent", profile)
            return reply["result"]["isError"]

        assert not ask("spain", "res.partner") and ask("spain", "pos.order")
        assert not ask("colombia", "pos.order") and ask("colombia", "res.partner")
        assert [c[0] for c in fakes["colombia"].calls if c[1] == "search_count"] == ["pos.order"]

    def test_server_status_reports_the_profile_lists(self, two_odoos: Runtime) -> None:
        two_odoos.set_profile_lists("spain", {"allowed_models": ["sale.order"]}, actor="admin")
        two_odoos.activate_profile("spain", actor="admin")
        two_odoos._snapshot = Snapshot(two_odoos.profiles.active(), FakeOdoo())
        _, body = call(Dispatcher(two_odoos), "server_status")
        assert "sale.order" in str(body)


class TestPanel:
    def test_tabs_quick_add_and_back_to_default(self, two_odoos: Runtime) -> None:
        client = TestClient(create_app(two_odoos))
        csrf = login(client)
        page = client.get("/admin/permissions?profile=colombia").text
        assert "🏭 colombia" in page and "uses the default permissions" in page
        response = client.post("/admin/permissions/chip", data={
            "csrf": csrf, "profile": "colombia", "gate": "w", "model": "pos.order",
            "action": "add"}, follow_redirects=False)
        assert response.status_code == 303 and "profile=colombia" in response.headers["location"]
        lists = two_odoos.engine.policy.config.profile_lists["colombia"]
        # Started from the defaults, plus pos.order for change (and so for read).
        assert lists["writable_models"] == {"pos.order"}
        assert lists["allowed_models"] == {"res.partner", "pos.order"}
        assert "pos.order" not in two_odoos.engine.policy.config.allowed_models  # default kept
        assert "has its own permissions" in client.get("/admin/permissions?profile=colombia").text
        client.post("/admin/permissions/chip", data={
            "csrf": csrf, "profile": "colombia", "gate": "r", "model": "pos.order",
            "action": "remove"})
        lists = two_odoos.engine.policy.config.profile_lists["colombia"]
        assert "pos.order" not in lists["allowed_models"] | lists["writable_models"]
        client.post("/admin/permissions/reset", data={"csrf": csrf, "profile": "colombia"})
        assert "colombia" not in two_odoos.engine.policy.config.profile_lists

    def test_bad_model_names_are_refused(self, two_odoos: Runtime) -> None:
        client = TestClient(create_app(two_odoos))
        csrf = login(client)
        response = client.post("/admin/permissions/chip", data={
            "csrf": csrf, "gate": "r", "model": "<script>", "action": "add"},
            follow_redirects=False)
        assert "permissions_error" in response.headers["location"]

    def test_the_default_tab_edits_the_default_lists(self, two_odoos: Runtime) -> None:
        client = TestClient(create_app(two_odoos))
        csrf = login(client)
        client.post("/admin/permissions/chip", data={
            "csrf": csrf, "profile": "", "gate": "r", "model": "sale.order", "action": "add"})
        assert "sale.order" in two_odoos.engine.policy.config.allowed_models
        assert not two_odoos.engine.policy.config.profile_lists

    def test_agent_cards_with_a_drawing_and_plus(self, two_odoos: Runtime) -> None:
        from odoo_mcp_governed.governance.agents import AgentRule
        two_odoos.save_agent(AgentRule(name="bot-co", profile="colombia"), actor="admin")
        client = TestClient(create_app(two_odoos))
        csrf = login(client)
        page = client.get("/admin/agents").text
        assert "<svg" in page and "📌 colombia" in page
        assert "read-only (production)" in page  # colombia is production, writes off
        assert "agents can only read it" in client.get("/admin/permissions?profile=colombia").text
        client.post("/admin/agents/model", data={"csrf": csrf, "name": "bot-co",
                                                 "model": "pos.order", "action": "add"})
        assert two_odoos.agents.rule("bot-co").models == {"pos.order"}
        assert "bot-co" not in client.get("/admin/agents?tab=-").text.split("Issue a token")[0]
        assert re.search(r"bot-co", client.get("/admin/agents?tab=colombia").text)
