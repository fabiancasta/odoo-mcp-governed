"""The panic switch and per-agent blocking.

Both are operator controls for the moment something is going wrong: they act
on the very next call, survive a restart, are sealed into the audit chain, and
never depend on JavaScript or on the risk engine.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from odoo_mcp_governed.governance import Operation, PolicyConfig, PolicyEngine
from odoo_mcp_governed.runtime import Runtime
from odoo_mcp_governed.web.app import create_app

from .conftest import FakeClock, make_call
from .test_http import bearer, login, make_settings, rpc


def tool_call(name: str, **arguments) -> dict:
    return rpc("tools/call", {"name": name, "arguments": arguments})


def is_refused(response) -> bool:
    return response.json()["result"]["isError"]


class TestPolicy:
    def test_panic_refuses_everything_even_introspection(self, clock: FakeClock) -> None:
        engine = PolicyEngine(PolicyConfig(allowed_models=frozenset({"*"}), panic=True))
        for operation in (Operation.READ, Operation.ADMIN, Operation.META):
            verdict = engine.evaluate(make_call(clock, operation=operation))
            assert verdict.codes == ("panic_stop",)

    def test_a_blocked_actor_is_refused_and_others_are_not(self, clock: FakeClock) -> None:
        engine = PolicyEngine(PolicyConfig(allowed_models=frozenset({"*"}),
                                           blocked_actors=frozenset({"rogue"})))
        assert engine.evaluate(make_call(clock, actor="rogue")).codes == ("actor_blocked",)
        assert engine.evaluate(make_call(clock, actor="good")).allowed


class TestRuntime:
    def test_panic_applies_to_the_next_call_and_survives_a_restart(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        runtime.set_panic(True, actor="admin@test")
        assert runtime.engine.policy.config.panic
        restarted = Runtime(make_settings(tmp_path))
        assert restarted.engine.policy.config.panic
        restarted.set_panic(False, actor="admin@test")
        assert not Runtime(make_settings(tmp_path)).engine.policy.config.panic

    def test_blocking_is_audited_under_its_own_name(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        runtime.set_actor_blocked("rogue", True, actor="admin@test")
        runtime.set_panic(True, actor="admin@test")
        tools = [e.tool for e in runtime.audit.store.iter_all()]
        assert "admin.actor.block" in tools and "admin.panic" in tools
        assert "rogue" in runtime.engine.policy.config.blocked_actors


class TestPanel:
    def test_panic_button_stops_agents_and_resume_needs_confirmation(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        client = TestClient(create_app(runtime))
        csrf = login(client)
        headers = bearer(runtime, "claude")
        assert not is_refused(client.post("/mcp", json=tool_call("server_status"),
                                          headers=headers))

        assert client.post("/admin/panic", data={"csrf": csrf},
                           follow_redirects=False).status_code == 303
        refused = client.post("/mcp", json=tool_call("server_status"), headers=headers)
        assert is_refused(refused)
        assert "stopped" in refused.json()["result"]["content"][0]["text"]
        assert "Resume" in client.get("/admin").text

        client.post("/admin/resume", data={"csrf": csrf}, follow_redirects=False)
        assert runtime.engine.policy.config.panic, "resume without confirm must do nothing"
        client.post("/admin/resume", data={"csrf": csrf, "confirm": "yes"},
                    follow_redirects=False)
        assert not runtime.engine.policy.config.panic

    def test_panic_needs_a_session_and_csrf(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        client = TestClient(create_app(runtime))
        client.post("/admin/panic", data={}, follow_redirects=False)
        assert not runtime.engine.policy.config.panic
        login(client)
        client.post("/admin/panic", data={"csrf": "wrong"}, follow_redirects=False)
        assert not runtime.engine.policy.config.panic

    def test_block_and_unblock_one_agent_from_the_panel(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        client = TestClient(create_app(runtime))
        csrf = login(client)
        rogue, good = bearer(runtime, "rogue"), bearer(runtime, "good")
        client.post("/mcp", json=tool_call("server_status"), headers=rogue)

        assert "rogue" in client.get("/admin").text
        client.post("/admin/actor/block", data={"csrf": csrf, "actor": "rogue"},
                    follow_redirects=False)
        assert is_refused(client.post("/mcp", json=tool_call("server_status"), headers=rogue))
        assert not is_refused(client.post("/mcp", json=tool_call("server_status"),
                                          headers=good))

        client.post("/admin/actor/unblock", data={"csrf": csrf, "actor": "rogue"},
                    follow_redirects=False)
        assert not is_refused(client.post("/mcp", json=tool_call("server_status"),
                                          headers=rogue))
